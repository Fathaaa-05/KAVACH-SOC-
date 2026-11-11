"""Reporting & compliance: KPIs, daily/weekly fraud reports, RBI-modelled compliance checks, auditor export."""
import csv
import hashlib
import io
import json
import time
import zipfile
from collections import Counter

from . import db
from .config import ALERT_THRESHOLD
from .security import verify_audit_chain

COMPLIANCE_NOTE = ("Checks are modelled on RBI guidance (Master Directions on Fraud Risk Management, customer "
                   "protection / limited liability circular for unauthorised electronic banking transactions, "
                   "IT governance & cyber security directions). They are a prototype and must be validated by "
                   "the bank's compliance team before use.")


def _avg(xs):
    xs = [x for x in xs if x is not None]
    return round(sum(xs) / len(xs), 1) if xs else None


def kpis(hours=24):
    since = time.time() - hours * 3600
    tx = db.q("""SELECT id, ts, channel, amount, status, risk_score, priority, truth, label, alert_id
                 FROM transactions WHERE ts>=? AND source!='HISTORY'""", (since,))
    alerts = db.q("SELECT * FROM alerts WHERE created>=?", (since,))
    fraud = [t for t in tx if t["truth"] or t["label"] == "FRAUD"]
    detected = [t for t in fraud if (t["risk_score"] or 0) >= ALERT_THRESHOLD]
    stopped = [t for t in fraud if t["status"] in ("HELD", "BLOCKED")]
    closed = [a for a in alerts if a["status"].startswith("CLOSED")]
    fp = [a for a in closed if a["disposition"] == "FALSE_POSITIVE"]
    truth_by_txn = {t["id"]: bool(t["truth"]) for t in tx}
    alerts_true = sum(1 for a in alerts if truth_by_txn.get(a["txn_id"]))
    flagged_legit = sum(1 for t in tx if (t["risk_score"] or 0) >= ALERT_THRESHOLD and not t["truth"])
    legit = len(tx) - len(fraud)
    cases = db.q("SELECT * FROM cases WHERE created>=?", (since,))
    open_cases = db.q("SELECT * FROM cases WHERE status!='CLOSED'")
    now = time.time()

    def bucket_series():
        size = 3600 if hours > 6 else 300
        n = int(hours * 3600 // size)
        start = now - n * size
        txc, alc, frc = [0] * n, [0] * n, [0] * n
        for t in tx:
            i = int((t["ts"] - start) // size)
            if 0 <= i < n:
                txc[i] += 1
                frc[i] += 1 if t["truth"] else 0
        for a in alerts:
            i = int((a["created"] - start) // size)
            if 0 <= i < n:
                alc[i] += 1
        return {"bucket_seconds": size, "start": start, "transactions": txc, "alerts": alc, "fraud": frc}

    by_channel = {}
    for ch in ("UPI", "CARD", "MOBILE"):
        ct = [t for t in tx if t["channel"] == ch]
        by_channel[ch] = {"transactions": len(ct), "volume": round(sum(t["amount"] for t in ct), 2),
                          "alerts": sum(1 for t in ct if t["alert_id"]),
                          "fraud": sum(1 for t in ct if t["truth"]),
                          "fraud_detected": sum(1 for t in ct if t["truth"] and (t["risk_score"] or 0) >= ALERT_THRESHOLD)}
    by_scenario = {}
    for t in fraud:
        k = t["truth"] or "ANALYST_CONFIRMED"
        d = by_scenario.setdefault(k, {"transactions": 0, "detected": 0, "amount": 0.0})
        d["transactions"] += 1
        d["detected"] += 1 if (t["risk_score"] or 0) >= ALERT_THRESHOLD else 0
        d["amount"] = round(d["amount"] + t["amount"], 2)

    return {
        "window_hours": hours,
        "transactions": len(tx), "volume": round(sum(t["amount"] for t in tx), 2),
        "alerts": len(alerts), "alerts_by_priority": dict(Counter(a["priority"] for a in alerts)),
        "alerts_open": sum(1 for a in alerts if a["status"] == "OPEN"),
        "fraud_transactions": len(fraud), "fraud_amount": round(sum(t["amount"] for t in fraud), 2),
        "detection_rate": round(len(detected) / len(fraud) * 100, 1) if fraud else None,
        "prevention_rate": round(len(stopped) / len(fraud) * 100, 1) if fraud else None,
        "loss_prevented": round(sum(t["amount"] for t in stopped), 2),
        "loss_exposed": round(sum(t["amount"] for t in fraud if t["status"] == "APPROVED"), 2),
        "alert_precision": round(alerts_true / len(alerts) * 100, 1) if alerts else None,
        "false_positive_rate_txn": round(flagged_legit / legit * 100, 2) if legit else None,
        "false_positive_rate_closed_alerts": round(len(fp) / len(closed) * 100, 1) if closed else None,
        "mean_time_to_acknowledge_min": _avg([(a["acked"] - a["created"]) / 60 for a in alerts if a["acked"]]),
        "mean_time_to_close_alert_min": _avg([(a["closed"] - a["created"]) / 60 for a in alerts if a["closed"]]),
        "mean_case_resolution_hours": _avg([(c["closed"] - c["created"]) / 3600 for c in cases if c["closed"]]),
        "cases_opened": len(cases), "cases_open_total": len(open_cases),
        "sla_breaches": sum(1 for c in open_cases if c["sla_due"] and c["sla_due"] < now),
        "auto_actions": db.scalar("SELECT COUNT(*) FROM actions WHERE automated=1 AND ts>=?", (since,)),
        "manual_actions": db.scalar("SELECT COUNT(*) FROM actions WHERE automated=0 AND ts>=?", (since,)),
        "by_channel": by_channel, "by_scenario": by_scenario, "series": bucket_series(),
    }


def fraud_report(period="daily"):
    hours = 24 if period == "daily" else 168
    since = time.time() - hours * 3600
    k = kpis(hours)
    top_rules = db.q("SELECT id, name, hits FROM rules ORDER BY hits DESC LIMIT 6")
    risky = db.q("""SELECT t.customer_id, c.name, c.status, COUNT(*) alerts, MAX(t.risk_score) max_risk,
                    SUM(t.amount) amount FROM transactions t JOIN customers c ON c.id=t.customer_id
                    WHERE t.ts>=? AND t.alert_id IS NOT NULL GROUP BY t.customer_id
                    ORDER BY max_risk DESC, alerts DESC LIMIT 10""", (since,))
    actions = db.q("SELECT type, COUNT(*) n FROM actions WHERE ts>=? GROUP BY type ORDER BY n DESC", (since,))
    closed = db.q("SELECT resolution, COUNT(*) n FROM cases WHERE closed>=? GROUP BY resolution", (since,))
    return {"period": period, "generated_at": time.time(), "from": since, "kpis": k, "top_rules": top_rules,
            "top_risky_customers": risky, "actions": actions, "cases_closed": closed}


def compliance():
    checks = []
    held = db.q("""SELECT t.id, t.alert_id FROM transactions t WHERE t.status IN ('HELD','BLOCKED')
                   AND t.alert_id IS NOT NULL AND t.source!='HISTORY'""")
    notified = {r["alert_id"] for r in db.q("SELECT DISTINCT alert_id FROM actions WHERE type='NOTIFY_CUSTOMER'")}
    ok = sum(1 for t in held if t["alert_id"] in notified)
    checks.append({"id": "CUST_NOTIFY", "title": "Customer notified for every held/blocked transaction",
                   "reference": "RBI customer protection – SMS alerts for electronic banking transactions",
                   "status": "PASS" if ok == len(held) else "FAIL", "detail": f"{ok}/{len(held)} notified"})
    fraud_cases = db.q("SELECT id FROM cases WHERE resolution='CONFIRMED_FRAUD'")
    filed = {r["case_id"] for r in db.q("SELECT DISTINCT case_id FROM actions WHERE type='FMR_DRAFTED'")}
    pending = [c["id"] for c in fraud_cases if c["id"] not in filed]
    checks.append({"id": "FMR", "title": "Confirmed fraud cases have a fraud monitoring return (FMR) drafted",
                   "reference": "RBI Master Directions on Fraud Risk Management – reporting of frauds",
                   "status": "PASS" if not pending else "ACTION", "detail":
                       f"{len(fraud_cases) - len(pending)}/{len(fraud_cases)} drafted" +
                       (f"; pending cases {pending[:10]}" if pending else "")})
    old = db.scalar("SELECT COUNT(*) FROM cases WHERE status!='CLOSED' AND created<?", (time.time() - 90 * 86400,))
    checks.append({"id": "RESOLUTION_90D", "title": "No customer fraud complaint open beyond 90 days",
                   "reference": "RBI limited liability circular – resolution timeline",
                   "status": "PASS" if not old else "FAIL", "detail": f"{old} cases older than 90 days"})
    sla = db.scalar("SELECT COUNT(*) FROM cases WHERE status!='CLOSED' AND sla_due<?", (time.time(),))
    checks.append({"id": "SLA", "title": "Cases within internal response SLA", "reference": "Internal SOC policy",
                   "status": "PASS" if not sla else "WARN", "detail": f"{sla} open cases past SLA"})
    chain = verify_audit_chain()
    checks.append({"id": "AUDIT_INTEGRITY", "title": "Audit trail is complete and tamper-evident",
                   "reference": "RBI IT governance / cyber security – audit logs",
                   "status": "PASS" if chain["valid"] else "FAIL",
                   "detail": f"{chain['checked']} entries verified" if chain["valid"]
                   else f"chain broken at entry {chain['broken_at_id']}"})
    no_mfa = [u["username"] for u in db.q("SELECT username FROM users WHERE active=1 AND role IN ('ADMIN','MANAGER') "
                                          "AND mfa_enabled=0")]
    checks.append({"id": "MFA", "title": "Privileged users protected by multi-factor authentication",
                   "reference": "RBI cyber security framework – access control",
                   "status": "PASS" if not no_mfa else "WARN",
                   "detail": "all privileged users enrolled" if not no_mfa else f"not enrolled: {', '.join(no_mfa)}"})
    plain = db.scalar("SELECT COUNT(*) FROM customers WHERE phone_enc NOT LIKE 'gAAAA%' OR email_enc NOT LIKE 'gAAAA%'")
    checks.append({"id": "ENCRYPTION", "title": "Customer PII encrypted at rest", "reference": "Data protection",
                   "status": "PASS" if not plain else "FAIL", "detail": f"{plain} records with plaintext PII"})
    return {"note": COMPLIANCE_NOTE, "generated_at": time.time(), "checks": checks}


def fmr_draft(case_id):
    c = db.q1("SELECT * FROM cases WHERE id=?", (case_id,))
    if not c:
        return None
    tx = db.q("""SELECT t.* FROM transactions t JOIN alerts a ON a.txn_id=t.id WHERE a.case_id=?""", (case_id,))
    cust = db.q1("SELECT id, name, account_no, home_city FROM customers WHERE id=?", (c["customer_id"],))
    acts = db.q("SELECT ts, type, actor FROM actions WHERE case_id=? OR target=? ORDER BY ts",
                (case_id, c["customer_id"]))
    return {
        "form": "FMR draft (prototype layout – map to the bank's actual RBI reporting format)",
        "case_id": case_id, "bank_reference": f"KAVACH-{case_id:06d}",
        "customer": {"id": cust["id"], "name": cust["name"], "account": "XXXXXXXX" + cust["account_no"][-4:],
                     "branch_city": cust["home_city"]},
        "date_of_occurrence": min((t["ts"] for t in tx), default=c["created"]),
        "date_of_detection": c["created"], "date_of_classification": c["closed"],
        "channels": sorted({t["channel"] for t in tx}),
        "amount_involved": round(sum(t["amount"] for t in tx), 2),
        "amount_recovered_or_prevented": round(sum(t["amount"] for t in tx if t["status"] in ("HELD", "BLOCKED")), 2),
        "modus_operandi": c["title"], "transactions": [t["id"] for t in tx],
        "actions_taken": [{"ts": a["ts"], "type": a["type"], "by": a["actor"]} for a in acts],
    }


def _csv(rows):
    buf = io.StringIO()
    if rows:
        w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    return buf.getvalue()


def to_csv(rows):
    return _csv(rows)


def auditor_export(days=30):
    since = time.time() - days * 86400
    files = {
        "audit_log.csv": _csv(db.q("SELECT * FROM audit_log WHERE ts>=? ORDER BY id", (since,))),
        "actions.csv": _csv(db.q("SELECT * FROM actions WHERE ts>=? ORDER BY id", (since,))),
        "alerts.csv": _csv(db.q("SELECT * FROM alerts WHERE created>=? ORDER BY id", (since,))),
        "cases.csv": _csv(db.q("SELECT * FROM cases WHERE created>=? ORDER BY id", (since,))),
        "case_notes.csv": _csv(db.q("SELECT * FROM case_notes WHERE ts>=? ORDER BY id", (since,))),
        "notifications.csv": _csv(db.q("SELECT * FROM notifications WHERE ts>=? ORDER BY id", (since,))),
        "flagged_transactions.csv": _csv(db.q(
            """SELECT id, ts, customer_id, channel, amount, payee, city, status, risk_score, rule_score, ml_score,
               profile_score, priority, label, reasons FROM transactions WHERE ts>=? AND risk_score>=?
               ORDER BY ts""", (since, ALERT_THRESHOLD))),
        "model_versions.csv": _csv(db.q("SELECT * FROM model_versions ORDER BY id")),
        "rules.csv": _csv(db.q("SELECT * FROM rules ORDER BY id")),
        "compliance.json": json.dumps(compliance(), indent=2, default=str),
        "kpis.json": json.dumps(kpis(days * 24), indent=2, default=str),
    }
    manifest = {"generated_at": time.time(), "period_days": days, "audit_chain": verify_audit_chain(),
                "files": {n: hashlib.sha256(c.encode()).hexdigest() for n, c in files.items()}}
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for n, c in files.items():
            z.writestr(n, c)
        z.writestr("MANIFEST.json", json.dumps(manifest, indent=2, default=str))
    return out.getvalue()

"""Real-time scoring pipeline: every transaction gets rules + behavioral profile + ML -> one risk score,
then alerting and automated response."""
import json
import time

from . import db, response, rules
from .config import (ALERT_THRESHOLD, AUTO_BLOCK_THRESHOLD, AUTO_HOLD_THRESHOLD, HIGH_THRESHOLD, MEDIUM_THRESHOLD,
                     W_ML, W_PROFILE, W_RULES)
from .ml import model, vectorize
from .profiles import ProfileStore

profiles = ProfileStore()
_watchlist = {"data": {}, "at": 0}
_homes = {}
stats = {"processed": 0, "alerts": 0, "last_latency_ms": 0.0, "avg_latency_ms": 0.0}


def watchlist():
    if time.time() - _watchlist["at"] > 5:
        _watchlist["data"] = {r["value"]: r["reason"] for r in db.q("SELECT value, reason FROM watchlist")}
        _watchlist["at"] = time.time()
    return _watchlist["data"]


def home(cid):
    if cid not in _homes:
        r = db.q1("SELECT home_lat, home_lon FROM customers WHERE id=?", (cid,))
        _homes[cid] = (r["home_lat"], r["home_lon"]) if r else None
    return _homes[cid]


def priority_for(score):
    if score >= HIGH_THRESHOLD:
        return "HIGH"
    if score >= MEDIUM_THRESHOLD:
        return "MEDIUM"
    if score >= ALERT_THRESHOLD:
        return "LOW"
    return None


def context(t):
    fan_window = rules.all_rules().get("R09", {}).get("params", {}).get("window_sec", 1800)
    recent = db.q("""SELECT ts, amount, channel FROM transactions WHERE customer_id=? AND ts>=? AND ts<=?
                     AND id != ?""", (t["customer_id"], t["ts"] - 3600, t["ts"], t["id"]))
    senders = {r["customer_id"] for r in db.q(
        "SELECT DISTINCT customer_id FROM transactions WHERE payee=? AND ts>=? AND ts<=? AND payee_type='P2P'",
        (t["payee"], t["ts"] - fan_window, t["ts"]))} if t["payee_type"] == "P2P" else set()
    logs = db.q("SELECT event_type FROM siem_logs WHERE customer_id=? AND ts>=? AND ts<=?",
                (t["customer_id"], t["ts"] - 3600, t["ts"]))
    return {"recent": recent, "payee_senders": senders, "logs": logs, "watchlist": watchlist()}


def ingest_log(e):
    lid = db.insert("siem_logs", {k: e.get(k) for k in ("ts", "source", "event_type", "customer_id", "ip",
                                                       "device_id", "severity", "message")})
    response.publish("log", {"id": lid, **{k: e.get(k) for k in ("ts", "source", "event_type", "customer_id",
                                                               "severity", "message")}})
    return lid


def score(t):
    """Pure scoring step; returns the enriched transaction (no side effects)."""
    ctx = context(t)
    f = profiles.features(t, home(t["customer_id"]))
    rule_score, hits = rules.evaluate(t, f, ctx)
    prof_score, prof_why = ProfileStore.score(f, t["amount"])
    vec = vectorize(t, f, ctx)
    ml_score, ml_detail = model.score(vec)
    if model.ready:
        risk = W_RULES * rule_score + W_ML * ml_score + W_PROFILE * prof_score
    else:  # before the first model is trained
        risk = 0.6 * rule_score + 0.4 * prof_score
    # strong signals are never diluted by the blend
    risk = max(risk, 0.9 * rule_score if rule_score >= 80 else 0, 0.85 * ml_score if ml_score >= 90 else 0)
    if hits and prof_score >= 40 and ml_score >= 60:
        risk = max(risk, 70 + 0.1 * rule_score)
    reasons = {"rules": hits, "profile": prof_why, "ml": ml_detail, "model_version": model.version,
               "components": {"rules": round(rule_score, 1), "ml": round(ml_score, 1),
                              "profile": round(prof_score, 1)}}
    return {**t, "risk_score": round(min(risk, 100.0), 1), "rule_score": round(rule_score, 1),
            "ml_score": round(ml_score, 1), "profile_score": round(prof_score, 1), "reasons": reasons,
            "features": vec, "_f": f}


def process(e, source="API", replay=False):
    if e.get("kind") == "log":
        return ingest_log(e)
    t0 = time.perf_counter()
    t = {k: e.get(k) for k in ("id", "ts", "customer_id", "channel", "amount", "payee", "payee_type", "category",
                               "device_id", "ip", "city", "lat", "lon")}
    cust = db.q1("SELECT status FROM customers WHERE id=?", (t["customer_id"],))
    if not cust:
        raise ValueError(f"unknown customer {t['customer_id']}")
    s = score(t)
    risk = s["risk_score"]
    prio = priority_for(risk)
    status = "APPROVED"
    if not replay:
        if cust["status"] == "BLOCKED":
            status = "BLOCKED"
            s["reasons"]["profile"].insert(0, "Account is blocked — debit refused")
        elif risk >= AUTO_HOLD_THRESHOLD and db.get_setting("auto_response", True):
            status = "HELD"
    label = None
    if replay:  # historical data arrives with its dispute outcome already known
        label = "FRAUD" if e.get("truth") else "LEGIT"
    row = {"id": t["id"], "ts": t["ts"], "customer_id": t["customer_id"], "channel": t["channel"],
           "amount": t["amount"], "payee": t["payee"], "payee_type": t["payee_type"], "category": t["category"],
           "device_id": t["device_id"], "ip": t["ip"], "city": t["city"], "lat": t["lat"], "lon": t["lon"],
           "status": status, "risk_score": risk, "rule_score": s["rule_score"], "ml_score": s["ml_score"],
           "profile_score": s["profile_score"], "priority": prio, "reasons": json.dumps(s["reasons"]),
           "label": label, "truth": e.get("truth"), "source": "HISTORY" if replay else source,
           "features": json.dumps(s["features"])}
    db.insert("transactions", row)
    for h in s["reasons"]["rules"]:
        db.x("UPDATE rules SET hits=hits+1 WHERE id=?", (h["rule"],))
    if replay or risk < ALERT_THRESHOLD:
        if status == "APPROVED" and (not replay or not e.get("truth")):
            profiles.learn(t)
    alert_id = None
    if not replay and prio:
        alert_id = raise_alert(row, s)
    lat = (time.perf_counter() - t0) * 1000
    if not replay:
        stats["processed"] += 1
        stats["last_latency_ms"] = round(lat, 2)
        stats["avg_latency_ms"] = round(stats["avg_latency_ms"] * 0.98 + lat * 0.02, 2)
        response.publish("txn", {k: row[k] for k in ("id", "ts", "customer_id", "channel", "amount", "payee",
                                                       "city", "status", "risk_score", "priority")}
                         | {"alert_id": alert_id})
    return {**{k: v for k, v in row.items() if k not in ("features", "truth")}, "reasons": s["reasons"],
            "alert_id": alert_id}


def raise_alert(row, s):
    open_case = db.q1("""SELECT id FROM cases WHERE customer_id=? AND status NOT IN ('CLOSED') ORDER BY id DESC
                         LIMIT 1""", (row["customer_id"],))
    summary = "; ".join([h["name"] for h in s["reasons"]["rules"]] + s["reasons"]["profile"][:2]) or \
        "ML anomaly"
    aid = db.insert("alerts", {"txn_id": row["id"], "customer_id": row["customer_id"], "created": row["ts"],
                               "priority": row["priority"], "score": row["risk_score"], "reasons": summary,
                               "status": "IN_CASE" if open_case else "OPEN",
                               "case_id": open_case["id"] if open_case else None})
    db.x("UPDATE transactions SET alert_id=? WHERE id=?", (aid, row["id"]))
    if open_case:
        db.x("UPDATE cases SET updated=? WHERE id=?", (db.now(), open_case["id"]))
    stats["alerts"] += 1
    payload = {"id": aid, "txn_id": row["id"], "customer_id": row["customer_id"], "priority": row["priority"],
               "score": row["risk_score"], "amount": row["amount"], "channel": row["channel"], "reasons": summary,
               "case_id": open_case["id"] if open_case else None}
    response.publish("alert", payload)
    if row["priority"] == "HIGH":
        response.fire_webhooks("alert.high", payload)
    auto_respond(row, aid)
    return aid


def auto_respond(row, alert_id):
    if not db.get_setting("auto_response", True):
        return
    risk, cid = row["risk_score"], row["customer_id"]
    kw = {"alert_id": alert_id, "automated": True}
    if row["status"] == "HELD":
        response._record("HOLD_TRANSACTION", cid, "kavach-auto", {"txn_id": row["id"], "amount": row["amount"],
                                                                 "risk": risk}, **kw)
        response.notify_customer(cid, f"A {row['channel']} payment of Rs {row['amount']:,.2f} to {row['payee']} is "
                                      f"on hold for verification. Reply YES if this was you, NO if not.",
                                 channels=("SMS",), actor="kavach-auto", **kw)
    elif row["status"] == "BLOCKED":
        response.notify_customer(cid, f"A {row['channel']} payment of Rs {row['amount']:,.2f} to {row['payee']} was "
                                      f"declined because debits on your account are blocked for your safety.",
                                 channels=("SMS",), actor="kavach-auto", **kw)
    if risk >= AUTO_BLOCK_THRESHOLD and db.get_setting("auto_block", True):
        cust = db.q1("SELECT status FROM customers WHERE id=?", (cid,))
        if cust and cust["status"] != "BLOCKED":
            response.block_account(cid, f"Auto-block: risk {risk} on {row['id']}", actor="kavach-auto", **kw)
            response.trigger_fraud_team(cid, f"Auto-blocked customer {cid} after transaction {row['id']} "
                                             f"(₹{row['amount']:,.0f}, risk {risk}). Please call the customer.",
                                        actor="kavach-auto", **kw)


def replay_history(events):
    """Bootstraps profiles and training features by streaming history through the same pipeline."""
    with db.lock():
        c = db.conn()
        c.execute("BEGIN")
        try:
            for e in events:
                process(e, replay=True)
            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise

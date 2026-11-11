"""Response & action module: blocking, customer notification, fraud-team escalation, NPCI requests,
webhooks and the real-time event bus. External gateways (SMS, email, NPCI, bank fraud desk) are mocked:
messages land in the notifications outbox instead of leaving the system."""
import hashlib
import hmac
import json
import queue
import threading
import urllib.request

from . import db
from .security import audit, dec, mask_email, mask_phone

# ------------------------------------------------------------ real-time event bus (SSE)
_subscribers = []
_sub_lock = threading.Lock()


def subscribe():
    qu = queue.Queue(maxsize=500)
    with _sub_lock:
        _subscribers.append(qu)
    return qu


def unsubscribe(qu):
    with _sub_lock:
        if qu in _subscribers:
            _subscribers.remove(qu)


def publish(kind, data):
    msg = {"type": kind, "data": data}
    with _sub_lock:
        for qu in list(_subscribers):
            try:
                qu.put_nowait(msg)
            except queue.Full:
                pass


# ------------------------------------------------------------ outbound channels (mocked)
def _notify(channel, recipient, subject, message, ref=""):
    nid = db.insert("notifications", {"ts": db.now(), "channel": channel, "recipient": recipient,
                                      "subject": subject, "message": message, "status": "DELIVERED (mock)",
                                      "ref": ref})
    publish("notification", {"id": nid, "channel": channel, "recipient": recipient, "subject": subject})
    return nid


def _record(type_, target, actor, details, case_id=None, alert_id=None, automated=False, role="SYSTEM", ip=None):
    aid = db.insert("actions", {"ts": db.now(), "type": type_, "target": target, "case_id": case_id,
                                "alert_id": alert_id, "actor": actor, "automated": int(automated),
                                "details": json.dumps(details, default=str)})
    audit(actor, role, f"RESPONSE.{type_}", "customer" if target.startswith("C") else "target", target,
          {**details, "case_id": case_id, "alert_id": alert_id, "automated": automated}, ip)
    publish("action", {"id": aid, "type": type_, "target": target, "actor": actor, "automated": automated})
    return aid


def notify_customer(cid, message, channels=("SMS", "EMAIL"), actor="system", **kw):
    c = db.q1("SELECT * FROM customers WHERE id=?", (cid,))
    if not c:
        return None
    out = []
    if "SMS" in channels:
        out.append(_notify("SMS", mask_phone(dec(c["phone_enc"])), "KAVACH alert", message, cid))
    if "EMAIL" in channels:
        out.append(_notify("EMAIL", mask_email(dec(c["email_enc"])), "Important: activity on your account",
                           f"Dear {c['name']},\n\n{message}\n\nIf this was not you, call 1800-XXX-XXXX "
                           f"(24x7) or reply BLOCK.\n\n— Fraud Risk Team", cid))
    _record("NOTIFY_CUSTOMER", cid, actor, {"channels": list(channels), "message": message}, **kw)
    return out


def block_account(cid, reason, actor="system", notify=True, **kw):
    db.x("UPDATE customers SET status='BLOCKED' WHERE id=?", (cid,))
    _record("BLOCK_ACCOUNT", cid, actor, {"reason": reason}, **kw)
    if notify:
        notify_customer(cid, "For your safety we have temporarily blocked debits on your account after "
                             "detecting suspicious activity.", actor=actor, **kw)
    publish("customer", {"id": cid, "status": "BLOCKED"})


def unblock_account(cid, reason, actor, **kw):
    db.x("UPDATE customers SET status='ACTIVE' WHERE id=?", (cid,))
    _record("UNBLOCK_ACCOUNT", cid, actor, {"reason": reason}, **kw)
    publish("customer", {"id": cid, "status": "ACTIVE"})


def set_txn_status(txn_id, status, reason, actor="system", **kw):
    t = db.q1("SELECT * FROM transactions WHERE id=?", (txn_id,))
    if not t:
        return None
    db.x("UPDATE transactions SET status=? WHERE id=?", (status, txn_id))
    type_ = {"BLOCKED": "BLOCK_TRANSACTION", "HELD": "HOLD_TRANSACTION", "APPROVED": "RELEASE_TRANSACTION"}[status]
    _record(type_, t["customer_id"], actor, {"txn_id": txn_id, "amount": t["amount"], "reason": reason}, **kw)
    return t


def trigger_fraud_team(cid, summary, actor="system", **kw):
    _notify("FRAUD_TEAM", "fraud-ops@bank.example (mock)", f"[KAVACH] Escalation for customer {cid}", summary, cid)
    _record("TRIGGER_FRAUD_TEAM", cid, actor, {"summary": summary}, **kw)
    fire_webhooks("fraud_team.triggered", {"customer_id": cid, "summary": summary, **kw})


def npci_report(vpa, reason, actor, cid="", **kw):
    """Mock NPCI request: report a VPA as fraudulent / request freeze on beneficiary."""
    ref = "NPCI" + hashlib.sha1(f"{vpa}{db.now()}".encode()).hexdigest()[:10].upper()
    _notify("NPCI", "NPCI UPI fraud reporting (mock)", f"Report VPA {vpa}",
            f"Request ref {ref}: report VPA {vpa} as suspected mule. Reason: {reason}", ref)
    db.x("INSERT OR IGNORE INTO watchlist VALUES (?,?,?,?,?)", (vpa, "VPA", f"Reported to NPCI ({ref})", db.now(),
                                                               actor))
    _record("NPCI_REPORT_VPA", cid or vpa, actor, {"vpa": vpa, "reason": reason, "npci_ref": ref}, **kw)
    return ref


def add_watchlist(value, kind, reason, actor, **kw):
    db.x("INSERT OR REPLACE INTO watchlist VALUES (?,?,?,?,?)", (value, kind, reason, db.now(), actor))
    _record("ADD_WATCHLIST", value, actor, {"kind": kind, "reason": reason}, **kw)


# ------------------------------------------------------------ webhooks
def fire_webhooks(event, payload):
    hooks = [h for h in db.q("SELECT * FROM webhooks WHERE active=1")
             if event in json.loads(h["events"] or "[]") or "*" in json.loads(h["events"] or "[]")]
    for h in hooks:
        threading.Thread(target=_deliver, args=(h, event, payload), daemon=True).start()


def _deliver(h, event, payload):
    body = json.dumps({"event": event, "ts": db.now(), "data": payload}, default=str).encode()
    sig = hmac.new((h["secret"] or "").encode(), body, hashlib.sha256).hexdigest()
    status = "ok"
    try:
        req = urllib.request.Request(h["url"], data=body, method="POST",
                                     headers={"Content-Type": "application/json", "X-Kavach-Event": event,
                                              "X-Kavach-Signature": f"sha256={sig}"})
        with urllib.request.urlopen(req, timeout=5) as r:
            status = f"HTTP {r.status}"
    except Exception as e:
        status = f"failed: {type(e).__name__}"
    db.x("UPDATE webhooks SET last_status=? WHERE id=?", (f"{event} → {status}", h["id"]))
    _notify("WEBHOOK", h["url"], event, body.decode()[:500], status)

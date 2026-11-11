"""KAVACH — AI-SOC Fraud Detection Platform. FastAPI application entry point."""
import json
import queue
import secrets
import threading
import time
from collections import defaultdict, deque

from fastapi import Body, Depends, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import db, engine, reports, response, rules, security
from .config import (AUTO_RETRAIN_MINUTES, BASE_DIR, CASE_SLA_HOURS, DATA_DIR, DEFAULT_INGEST_API_KEY, DEMO_PASSWORD,
                     SIM_ENABLED)
from .ml import FEATURE_NAMES, model
from .simulator import CITIES, FRAUD_SCENARIOS, Bank, LiveFeed

app = FastAPI(title="KAVACH AI-SOC Fraud Detection Platform", version="1.0.0",
              description="Real-time fraud detection, alerting, case management and response for UPI, card and "
                          "mobile banking.")
STATE = {"bank": None, "feed": None, "ready": False, "boot": "starting"}
WEBHOOK_SINK = deque(maxlen=50)


# ====================================================================== bootstrap
def bootstrap():
    db.conn()
    rules.seed()
    if not db.scalar("SELECT COUNT(*) FROM users"):
        creds = ["KAVACH demo credentials (change these!)", ""]
        for username, name, role, mfa in [("admin", "Asha Admin", "ADMIN", True),
                                          ("manager", "Mohan Manager", "MANAGER", False),
                                          ("analyst1", "Anita Analyst", "ANALYST", False),
                                          ("analyst2", "Ravi Analyst", "ANALYST", False),
                                          ("auditor", "Ira Auditor", "READONLY", False)]:
            secret = security.new_mfa_secret() if mfa else None
            db.insert("users", {"username": username, "full_name": name, "role": role,
                                "pw_hash": security.hash_password(DEMO_PASSWORD), "mfa_secret": secret,
                                "mfa_enabled": int(mfa), "active": 1, "created": db.now()})
            creds.append(f"{username:10s} {role:9s} password={DEMO_PASSWORD}" +
                         (f"  MFA secret={secret}" if secret else ""))
        creds += ["", "Get the admin's current MFA code with:  python -m app.totp admin"]
        (DATA_DIR / "DEMO_CREDENTIALS.txt").write_text("\n".join(creds) + "\n")
        print("\n".join(creds))
    if not db.scalar("SELECT COUNT(*) FROM settings WHERE key='ingest_api_key'"):
        db.set_setting("ingest_api_key", DEFAULT_INGEST_API_KEY)
    bank = Bank()
    bank.persist()
    STATE["bank"] = bank
    if not db.scalar("SELECT COUNT(*) FROM transactions"):
        STATE["boot"] = "generating transaction history"
        hist = bank.history()
        print(f"[kavach] replaying {len(hist)} historical events through the pipeline…")
        STATE["boot"] = f"learning behavioral profiles from {len(hist)} historical events"
        engine.replay_history(hist)
        STATE["boot"] = "training models"
        res = model.train(trigger="bootstrap")
        print("[kavach] initial model:", res)
        security.audit("system", "SYSTEM", "MODEL.TRAIN", "model", res.get("version"), res)
    else:
        STATE["boot"] = "loading profiles and model"
        engine.profiles.rebuild()
        if not model.load_active():
            model.train(trigger="bootstrap")
    engine.profiles.snapshot()
    security.audit("system", "SYSTEM", "SYSTEM.START", "platform", "kavach", {"version": app.version})
    STATE["ready"], STATE["boot"] = True, "ready"
    feed = LiveFeed(bank, lambda e, src: engine.process(e, src))
    feed.running = SIM_ENABLED and db.get_setting("sim_running", True)
    STATE["feed"] = feed
    feed.start()
    threading.Thread(target=background_jobs, daemon=True, name="kavach-jobs").start()


def background_jobs():
    last_retrain = time.time()
    while True:
        time.sleep(30)
        try:
            # escalation workflow: cases breaching SLA climb a level automatically
            for c in db.q("SELECT * FROM cases WHERE status!='CLOSED' AND sla_due<? AND escalation_level<2",
                          (time.time(),)):
                escalate_case(c, "SLA breached — auto-escalated", "kavach-sla", "SYSTEM")
            if time.time() - last_retrain > AUTO_RETRAIN_MINUTES * 60:
                res = model.train(trigger="scheduled")
                security.audit("system", "SYSTEM", "MODEL.RETRAIN", "model", res.get("version"), res)
                engine.profiles.snapshot()
                last_retrain = time.time()
        except Exception as e:
            print("background job error:", e)


@app.on_event("startup")
def _startup():
    threading.Thread(target=bootstrap, daemon=True, name="kavach-boot").start()


# ====================================================================== middleware & auth
@app.middleware("http")
async def headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    if request.url.scheme == "https":
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.url.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


_failed = defaultdict(list)


def client_ip(req: Request):
    return req.client.host if req.client else ""


def need(perm):
    def dep(request: Request, authorization: str = Header(None)):
        token = (authorization or "").replace("Bearer ", "") or request.query_params.get("token")
        u = security.session_user(token)
        if not u:
            raise HTTPException(401, "Not authenticated")
        if not security.can(u["role"], perm):
            security.audit(u["username"], u["role"], "ACCESS.DENIED", "endpoint", request.url.path,
                           {"permission": perm}, client_ip(request))
            raise HTTPException(403, f"Role {u['role']} lacks permission '{perm}'")
        u["ip"] = client_ip(request)
        return u
    return dep


def A(u, action, entity="", eid="", details=None):
    security.audit(u["username"], u["role"], action, entity, eid, details, u.get("ip"))


def kw(u, **extra):
    return {"role": u["role"], "ip": u.get("ip"), **extra}


def need_ready():
    if not STATE["ready"]:
        raise HTTPException(503, f"KAVACH is starting up: {STATE['boot']}")


@app.get("/api/health")
def health():
    return {"ready": STATE["ready"], "boot": STATE["boot"], "model": model.version, "time": time.time()}


@app.post("/api/auth/login")
def login(request: Request, body: dict = Body(...)):
    username, pw, otp = body.get("username", ""), body.get("password", ""), body.get("otp")
    ip = client_ip(request)
    recent = [t for t in _failed[username] if t > time.time() - 900]
    _failed[username] = recent
    if len(recent) >= 5:
        security.audit(username, "-", "AUTH.LOCKED", "user", username, {}, ip)
        raise HTTPException(429, "Too many failed attempts. Try again in 15 minutes.")
    u = db.q1("SELECT * FROM users WHERE username=?", (username,))
    if not u or not u["active"] or not security.verify_password(pw, u["pw_hash"]):
        _failed[username].append(time.time())
        security.audit(username, "-", "AUTH.LOGIN_FAILED", "user", username, {"reason": "bad credentials"}, ip)
        raise HTTPException(401, "Invalid username or password")
    if u["mfa_enabled"]:
        if not otp:
            return JSONResponse({"mfa_required": True}, status_code=401)
        if not security.verify_totp(u["mfa_secret"], otp):
            _failed[username].append(time.time())
            security.audit(username, u["role"], "AUTH.MFA_FAILED", "user", username, {}, ip)
            raise HTTPException(401, "Invalid authentication code")
    _failed.pop(username, None)
    token = security.create_session(u["id"], ip)
    db.x("UPDATE users SET last_login=? WHERE id=?", (db.now(), u["id"]))
    security.audit(username, u["role"], "AUTH.LOGIN", "user", username, {"mfa": bool(u["mfa_enabled"])}, ip)
    return {"token": token, "user": public_user(u)}


def public_user(u):
    return {"id": u["id"], "username": u["username"], "full_name": u["full_name"], "role": u["role"],
            "mfa_enabled": bool(u["mfa_enabled"]), "permissions": security.permissions_for(u["role"])}


@app.post("/api/auth/logout")
def logout(authorization: str = Header(None), u=Depends(need("view"))):
    security.end_session((authorization or "").replace("Bearer ", ""))
    A(u, "AUTH.LOGOUT", "user", u["username"])
    return {"ok": True}


@app.get("/api/me")
def me(u=Depends(need("view"))):
    return public_user(u)


@app.post("/api/me/mfa/setup")
def mfa_setup(u=Depends(need("view"))):
    secret = security.new_mfa_secret()
    db.x("UPDATE users SET mfa_secret=?, mfa_enabled=0 WHERE id=?", (secret, u["id"]))
    A(u, "MFA.SETUP_STARTED", "user", u["username"])
    return {"secret": secret, "otpauth_uri": security.provisioning_uri(secret, u["username"])}


@app.post("/api/me/mfa/enable")
def mfa_enable(body: dict = Body(...), u=Depends(need("view"))):
    row = db.q1("SELECT mfa_secret FROM users WHERE id=?", (u["id"],))
    if not security.verify_totp(row["mfa_secret"], body.get("otp")):
        raise HTTPException(400, "Code did not match — check your authenticator app's clock")
    db.x("UPDATE users SET mfa_enabled=1 WHERE id=?", (u["id"],))
    A(u, "MFA.ENABLED", "user", u["username"])
    return {"ok": True}


@app.post("/api/me/password")
def change_password(body: dict = Body(...), u=Depends(need("view"))):
    if not security.verify_password(body.get("old", ""), u["pw_hash"]):
        raise HTTPException(400, "Current password is wrong")
    new = body.get("new", "")
    if len(new) < 10 or new.isalpha() or new.isdigit():
        raise HTTPException(400, "Use at least 10 characters mixing letters and digits/symbols")
    db.x("UPDATE users SET pw_hash=? WHERE id=?", (security.hash_password(new), u["id"]))
    A(u, "USER.PASSWORD_CHANGED", "user", u["username"])
    return {"ok": True}


# ====================================================================== dashboard & live stream
@app.get("/api/overview")
def overview(hours: int = 24, u=Depends(need("view"))):
    need_ready()
    k = reports.kpis(hours)
    return {"kpis": k, "engine": engine.stats, "feed": STATE["feed"].status() if STATE["feed"] else None,
            "model": model.version, "auto_response": db.get_setting("auto_response", True),
            "auto_block": db.get_setting("auto_block", True)}


@app.get("/api/stream")
def stream(u=Depends(need("view"))):
    qu = response.subscribe()

    def gen():
        try:
            yield "retry: 3000\n\n"
            while True:
                try:
                    msg = qu.get(timeout=15)
                    yield f"event: {msg['type']}\ndata: {json.dumps(msg['data'], default=str)}\n\n"
                except queue.Empty:
                    yield ": keepalive\n\n"
        finally:
            response.unsubscribe(qu)
    return StreamingResponse(gen(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"})


@app.get("/api/transactions")
def transactions(limit: int = 100, min_risk: float = 0, channel: str = "", status: str = "", customer_id: str = "",
                 q: str = "", u=Depends(need("view"))):
    sql = """SELECT id, ts, customer_id, channel, amount, payee, payee_type, category, device_id, ip, city, status,
             risk_score, rule_score, ml_score, profile_score, priority, label, alert_id, source
             FROM transactions WHERE source!='HISTORY' AND risk_score>=?"""
    p = [min_risk]
    for col, val in (("channel", channel), ("status", status), ("customer_id", customer_id)):
        if val:
            sql += f" AND {col}=?"
            p.append(val)
    if q:
        sql += " AND (id LIKE ? OR payee LIKE ? OR customer_id LIKE ?)"
        p += [f"%{q}%"] * 3
    return db.q(sql + " ORDER BY ts DESC LIMIT ?", (*p, min(limit, 1000)))


@app.get("/api/transactions/{tid}")
def transaction(tid: str, u=Depends(need("view"))):
    t = db.q1("SELECT * FROM transactions WHERE id=?", (tid,))
    if not t:
        raise HTTPException(404)
    t.pop("truth", None)
    t["reasons"] = json.loads(t["reasons"] or "{}")
    t["features"] = dict(zip(FEATURE_NAMES, json.loads(t["features"] or "[]")))
    t["alert"] = db.q1("SELECT * FROM alerts WHERE txn_id=?", (tid,))
    return t


# ====================================================================== alerts
def users_map():
    return {u["id"]: u["full_name"] for u in db.q("SELECT id, full_name FROM users")}


@app.get("/api/alerts")
def alerts(status: str = "OPEN", priority: str = "", limit: int = 200, u=Depends(need("view"))):
    sql = """SELECT a.*, t.amount, t.channel, t.payee, t.city, t.status AS txn_status, c.name AS customer_name
             FROM alerts a JOIN transactions t ON t.id=a.txn_id JOIN customers c ON c.id=a.customer_id WHERE 1=1"""
    p = []
    if status == "OPEN":
        sql += " AND a.status IN ('OPEN','ACKED')"
    elif status and status != "ALL":
        sql += " AND a.status=?"
        p.append(status)
    if priority:
        sql += " AND a.priority=?"
        p.append(priority)
    sql += " ORDER BY CASE a.priority WHEN 'HIGH' THEN 0 WHEN 'MEDIUM' THEN 1 ELSE 2 END, a.created DESC LIMIT ?"
    rows = db.q(sql, (*p, min(limit, 1000)))
    um = users_map()
    for r in rows:
        r["assignee"] = um.get(r["assignee_id"])
    return rows


def get_alert(aid):
    a = db.q1("SELECT * FROM alerts WHERE id=?", (aid,))
    if not a:
        raise HTTPException(404, "alert not found")
    return a


@app.post("/api/alerts/{aid}/ack")
def ack_alert(aid: int, u=Depends(need("triage"))):
    a = get_alert(aid)
    db.x("UPDATE alerts SET status=CASE WHEN status='OPEN' THEN 'ACKED' ELSE status END, acked=COALESCE(acked,?),"
         " assignee_id=COALESCE(assignee_id,?) WHERE id=?", (db.now(), u["id"], aid))
    A(u, "ALERT.ACK", "alert", aid, {"priority": a["priority"]})
    return get_alert(aid)


@app.post("/api/alerts/{aid}/assign")
def assign_alert(aid: int, body: dict = Body(...), u=Depends(need("triage"))):
    get_alert(aid)
    uid = body.get("user_id") or u["id"]
    if uid != u["id"] and not security.can(u["role"], "case_assign"):
        raise HTTPException(403, "Only managers can assign to others")
    db.x("UPDATE alerts SET assignee_id=?, acked=COALESCE(acked,?) WHERE id=?", (uid, db.now(), aid))
    A(u, "ALERT.ASSIGN", "alert", aid, {"assignee_id": uid})
    return get_alert(aid)


def label_txn(txn_id, label):
    db.x("UPDATE transactions SET label=? WHERE id=?", (label, txn_id))


@app.post("/api/alerts/{aid}/close")
def close_alert(aid: int, body: dict = Body(...), u=Depends(need("triage"))):
    """Analyst disposition = the false-positive feedback loop: it labels the transaction for retraining."""
    a = get_alert(aid)
    disp = body.get("disposition")
    if disp not in ("FALSE_POSITIVE", "CONFIRMED_FRAUD", "BENIGN"):
        raise HTTPException(400, "disposition must be FALSE_POSITIVE, CONFIRMED_FRAUD or BENIGN")
    db.x("UPDATE alerts SET status=?, disposition=?, closed=?, acked=COALESCE(acked,?), "
         "assignee_id=COALESCE(assignee_id,?) WHERE id=?",
         ("CLOSED_FRAUD" if disp == "CONFIRMED_FRAUD" else "CLOSED_FP" if disp == "FALSE_POSITIVE" else
          "CLOSED", disp, db.now(), db.now(), u["id"], aid))
    label_txn(a["txn_id"], "FRAUD" if disp == "CONFIRMED_FRAUD" else "LEGIT")
    t = db.q1("SELECT status FROM transactions WHERE id=?", (a["txn_id"],))
    if disp != "CONFIRMED_FRAUD" and t["status"] == "HELD" and body.get("release", True):
        response.set_txn_status(a["txn_id"], "APPROVED", "Released after analyst review", u["username"],
                                alert_id=aid, **kw(u))
    if disp == "CONFIRMED_FRAUD" and t["status"] == "HELD":
        response.set_txn_status(a["txn_id"], "BLOCKED", "Confirmed fraud", u["username"], alert_id=aid, **kw(u))
    if body.get("note"):
        A(u, "ALERT.NOTE", "alert", aid, {"note": body["note"]})
    A(u, "ALERT.CLOSE", "alert", aid, {"disposition": disp, "txn_id": a["txn_id"]})
    return get_alert(aid)


@app.post("/api/alerts/{aid}/case")
def alert_to_case(aid: int, body: dict = Body(default={}), u=Depends(need("case_work"))):
    a = get_alert(aid)
    if a["case_id"]:
        return {"case_id": a["case_id"], "existing": True}
    existing = db.q1("SELECT id FROM cases WHERE customer_id=? AND status!='CLOSED' ORDER BY id DESC LIMIT 1",
                     (a["customer_id"],))
    if existing:
        cid = existing["id"]
    else:
        cid = create_case_row(u, a["customer_id"], body.get("title") or f"{a['priority'].title()} risk: {a['reasons']}"[:140],
                              a["priority"], body.get("assignee_id") or u["id"])
    # pull every open alert of this customer into the case
    db.x("UPDATE alerts SET case_id=?, status='IN_CASE', acked=COALESCE(acked,?) WHERE customer_id=? "
         "AND status IN ('OPEN','ACKED')", (cid, db.now(), a["customer_id"]))
    A(u, "CASE.LINK_ALERT", "case", cid, {"alert_id": aid})
    return {"case_id": cid, "existing": bool(existing)}


# ====================================================================== cases
def create_case_row(u, customer_id, title, priority, assignee_id):
    now = db.now()
    cid = db.insert("cases", {"title": title, "customer_id": customer_id, "priority": priority, "status": "OPEN",
                              "assignee_id": assignee_id, "created_by": u["id"], "created": now, "updated": now,
                              "sla_due": now + CASE_SLA_HOURS.get(priority, 24) * 3600})
    A(u, "CASE.CREATE", "case", cid, {"customer_id": customer_id, "priority": priority, "assignee_id": assignee_id})
    response.publish("case", {"id": cid, "title": title, "priority": priority})
    return cid


@app.post("/api/cases")
def create_case(body: dict = Body(...), u=Depends(need("case_work"))):
    if not db.q1("SELECT id FROM customers WHERE id=?", (body.get("customer_id"),)):
        raise HTTPException(400, "unknown customer")
    cid = create_case_row(u, body["customer_id"], body.get("title") or "Manual investigation",
                          body.get("priority", "MEDIUM"), body.get("assignee_id") or u["id"])
    for aid in body.get("alert_ids", []):
        db.x("UPDATE alerts SET case_id=?, status='IN_CASE' WHERE id=?", (cid, aid))
    return get_case(cid, u)


@app.get("/api/cases")
def list_cases(status: str = "", mine: bool = False, u=Depends(need("view"))):
    sql = """SELECT k.*, c.name AS customer_name, c.status AS customer_status,
             (SELECT COUNT(*) FROM alerts a WHERE a.case_id=k.id) AS alert_count
             FROM cases k JOIN customers c ON c.id=k.customer_id WHERE 1=1"""
    p = []
    if status == "ACTIVE":
        sql += " AND k.status!='CLOSED'"
    elif status:
        sql += " AND k.status=?"
        p.append(status)
    if mine:
        sql += " AND k.assignee_id=?"
        p.append(u["id"])
    rows = db.q(sql + " ORDER BY CASE k.status WHEN 'CLOSED' THEN 1 ELSE 0 END, k.updated DESC LIMIT 300", p)
    um = users_map()
    for r in rows:
        r["assignee"] = um.get(r["assignee_id"])
        r["sla_breached"] = r["status"] != "CLOSED" and r["sla_due"] and r["sla_due"] < time.time()
    return rows


@app.get("/api/cases/{cid}")
def get_case(cid: int, u=Depends(need("view"))):
    c = db.q1("SELECT * FROM cases WHERE id=?", (cid,))
    if not c:
        raise HTTPException(404)
    um = users_map()
    c["assignee"] = um.get(c["assignee_id"])
    c["sla_breached"] = c["status"] != "CLOSED" and c["sla_due"] < time.time()
    c["customer"] = customer_public(c["customer_id"])
    c["alerts"] = db.q("""SELECT a.*, t.amount, t.channel, t.payee, t.city, t.status AS txn_status, t.ts AS txn_ts,
                          t.device_id, t.ip FROM alerts a JOIN transactions t ON t.id=a.txn_id WHERE a.case_id=?
                          ORDER BY a.created""", (cid,))
    c["notes"] = db.q("SELECT * FROM case_notes WHERE case_id=? ORDER BY ts", (cid,))
    for n in c["notes"]:
        n["author"] = um.get(n["user_id"])
    c["actions"] = db.q("""SELECT * FROM actions WHERE case_id=? OR (target=? AND ts>=?) ORDER BY ts""",
                        (cid, c["customer_id"], c["created"] - 3600))
    c["history"] = db.q("SELECT ts, actor, action, details FROM audit_log WHERE entity='case' AND entity_id=? "
                        "ORDER BY id", (str(cid),))
    return c


@app.post("/api/cases/{cid}/assign")
def assign_case(cid: int, body: dict = Body(...), u=Depends(need("case_work"))):
    uid = body.get("user_id") or u["id"]
    if uid != u["id"] and not security.can(u["role"], "case_assign"):
        raise HTTPException(403, "Only managers can assign cases to others")
    db.x("UPDATE cases SET assignee_id=?, updated=? WHERE id=?", (uid, db.now(), cid))
    A(u, "CASE.ASSIGN", "case", cid, {"assignee_id": uid})
    return get_case(cid, u)


@app.post("/api/cases/{cid}/note")
def case_note(cid: int, body: dict = Body(...), u=Depends(need("case_work"))):
    note = (body.get("note") or "").strip()
    if not note:
        raise HTTPException(400, "empty note")
    db.insert("case_notes", {"case_id": cid, "user_id": u["id"], "ts": db.now(), "note": note})
    db.x("UPDATE cases SET updated=? WHERE id=?", (db.now(), cid))
    A(u, "CASE.NOTE", "case", cid, {"note": note[:200]})
    return get_case(cid, u)


@app.post("/api/cases/{cid}/status")
def case_status(cid: int, body: dict = Body(...), u=Depends(need("case_work"))):
    st = body.get("status")
    if st not in ("OPEN", "INVESTIGATING", "PENDING_CUSTOMER"):
        raise HTTPException(400, "use /close to close, /escalate to escalate")
    db.x("UPDATE cases SET status=?, updated=? WHERE id=?", (st, db.now(), cid))
    A(u, "CASE.STATUS", "case", cid, {"status": st})
    return get_case(cid, u)


def escalate_case(c, reason, actor, role, ip=None):
    level = c["escalation_level"] + 1
    managers = db.q("SELECT id FROM users WHERE role='MANAGER' AND active=1 LIMIT 1")
    assignee = managers[0]["id"] if (level == 1 and managers) else c["assignee_id"]
    db.x("UPDATE cases SET escalation_level=?, status='ESCALATED', assignee_id=?, updated=?, sla_due=? WHERE id=?",
         (level, assignee, db.now(), db.now() + CASE_SLA_HOURS.get(c["priority"], 24) * 3600, c["id"]))
    security.audit(actor, role, "CASE.ESCALATE", "case", c["id"], {"level": level, "reason": reason}, ip)
    if level >= 2:
        response.trigger_fraud_team(c["customer_id"], f"Case #{c['id']} escalated to L{level}: {reason}",
                                    actor=actor, case_id=c["id"], role=role, ip=ip)
    response.publish("case", {"id": c["id"], "escalation_level": level})


@app.post("/api/cases/{cid}/escalate")
def escalate(cid: int, body: dict = Body(default={}), u=Depends(need("case_work"))):
    c = db.q1("SELECT * FROM cases WHERE id=?", (cid,))
    if not c or c["status"] == "CLOSED":
        raise HTTPException(400, "case not open")
    escalate_case(c, body.get("reason") or "Escalated by analyst", u["username"], u["role"], u.get("ip"))
    return get_case(cid, u)


@app.post("/api/cases/{cid}/close")
def close_case(cid: int, body: dict = Body(...), u=Depends(need("case_work"))):
    res = body.get("resolution")
    if res not in ("CONFIRMED_FRAUD", "FALSE_POSITIVE", "INCONCLUSIVE"):
        raise HTTPException(400, "resolution must be CONFIRMED_FRAUD, FALSE_POSITIVE or INCONCLUSIVE")
    c = db.q1("SELECT * FROM cases WHERE id=?", (cid,))
    alerts_ = db.q("SELECT a.id, a.txn_id, t.amount, t.status FROM alerts a JOIN transactions t ON t.id=a.txn_id "
                   "WHERE a.case_id=?", (cid,))
    for a in alerts_:
        if res != "INCONCLUSIVE":
            label_txn(a["txn_id"], "FRAUD" if res == "CONFIRMED_FRAUD" else "LEGIT")
        if res == "FALSE_POSITIVE" and a["status"] == "HELD":
            response.set_txn_status(a["txn_id"], "APPROVED", "Case closed as false positive", u["username"],
                                    case_id=cid, **kw(u))
        if res == "CONFIRMED_FRAUD" and a["status"] == "HELD":
            response.set_txn_status(a["txn_id"], "BLOCKED", "Case confirmed fraud", u["username"], case_id=cid,
                                    **kw(u))
    db.x("UPDATE alerts SET status=?, disposition=?, closed=COALESCE(closed,?) WHERE case_id=? AND status NOT LIKE "
         "'CLOSED%'", ("CLOSED_FRAUD" if res == "CONFIRMED_FRAUD" else "CLOSED_FP" if res == "FALSE_POSITIVE"
                       else "CLOSED", res, db.now(), cid))
    amt = sum(a["amount"] for a in alerts_) if res == "CONFIRMED_FRAUD" else 0
    db.x("UPDATE cases SET status='CLOSED', resolution=?, closed=?, updated=?, fraud_amount=? WHERE id=?",
         (res, db.now(), db.now(), amt, cid))
    if body.get("note"):
        db.insert("case_notes", {"case_id": cid, "user_id": u["id"], "ts": db.now(),
                                 "note": f"[Closed: {res}] {body['note']}"})
    A(u, "CASE.CLOSE", "case", cid, {"resolution": res, "alerts": len(alerts_)})
    if res == "FALSE_POSITIVE" and c and body.get("unblock", True):
        cust = db.q1("SELECT status FROM customers WHERE id=?", (c["customer_id"],))
        if cust["status"] == "BLOCKED" and security.can(u["role"], "unblock"):
            response.unblock_account(c["customer_id"], "Case closed as false positive", u["username"], case_id=cid,
                                     **kw(u))
    return get_case(cid, u)


@app.post("/api/cases/{cid}/fmr")
def case_fmr(cid: int, u=Depends(need("case_work"))):
    d = reports.fmr_draft(cid)
    if not d:
        raise HTTPException(404)
    response._record("FMR_DRAFTED", d["customer"]["id"], u["username"], {"bank_reference": d["bank_reference"]},
                     case_id=cid, **kw(u))
    return d


# ====================================================================== investigation
def customer_public(cid):
    c = db.q1("SELECT id, name, account_no, vpa, card_last4, home_city, home_lat, home_lon, segment, status, "
              "phone_enc, email_enc FROM customers WHERE id=?", (cid,))
    if not c:
        return None
    c["phone"] = security.mask_phone(security.dec(c.pop("phone_enc")))
    c["email"] = security.mask_email(security.dec(c.pop("email_enc")))
    c["account_no"] = "XXXXXXXX" + c["account_no"][-4:]
    return c


@app.get("/api/customers")
def customers(q: str = "", risky: bool = False, u=Depends(need("view"))):
    if risky:
        return db.q("""SELECT c.id, c.name, c.vpa, c.home_city, c.segment, c.status, COUNT(a.id) alerts,
                       MAX(a.score) max_score FROM customers c JOIN alerts a ON a.customer_id=c.id
                       WHERE a.created>=? GROUP BY c.id ORDER BY max_score DESC LIMIT 50""",
                    (time.time() - 86400,))
    return db.q("""SELECT id, name, vpa, home_city, segment, status FROM customers
                   WHERE id LIKE ? OR name LIKE ? OR vpa LIKE ? ORDER BY id LIMIT 50""", (f"%{q}%",) * 3)


@app.get("/api/customers/{cid}")
def customer(cid: str, u=Depends(need("view"))):
    c = customer_public(cid)
    if not c:
        raise HTTPException(404)
    p = engine.profiles.get(cid).to_dict()
    c["profile"] = p
    c["stats"] = db.q1("""SELECT COUNT(*) n, SUM(amount) volume, MAX(risk_score) max_risk,
                          SUM(CASE WHEN alert_id IS NOT NULL THEN 1 ELSE 0 END) alerts
                          FROM transactions WHERE customer_id=?""", (cid,))
    c["cases"] = db.q("SELECT id, title, status, priority, created, resolution FROM cases WHERE customer_id=? "
                      "ORDER BY id DESC", (cid,))
    A(u, "CUSTOMER.VIEW", "customer", cid)
    return c


@app.get("/api/customers/{cid}/pii")
def customer_pii(cid: str, u=Depends(need("respond"))):
    c = db.q1("SELECT phone_enc, email_enc, account_no FROM customers WHERE id=?", (cid,))
    if not c:
        raise HTTPException(404)
    A(u, "PII.REVEAL", "customer", cid, {"fields": ["phone", "email", "account_no"]})
    return {"phone": security.dec(c["phone_enc"]), "email": security.dec(c["email_enc"]), "account_no": c["account_no"]}


@app.get("/api/customers/{cid}/timeline")
def timeline(cid: str, days: int = 7, u=Depends(need("view"))):
    since = time.time() - days * 86400
    tx = db.q("""SELECT id, ts, channel, amount, payee, payee_type, category, device_id, ip, city, lat, lon, status,
                 risk_score, priority, alert_id, label, source FROM transactions WHERE customer_id=? AND ts>=?
                 ORDER BY ts DESC LIMIT 500""", (cid, since))
    logs = db.q("SELECT * FROM siem_logs WHERE customer_id=? AND ts>=? ORDER BY ts DESC LIMIT 200", (cid, since))
    acts = db.q("SELECT * FROM actions WHERE target=? AND ts>=? ORDER BY ts DESC", (cid, since))
    events = [{"ts": t["ts"], "kind": "txn", **t} for t in tx] + \
             [{"ts": l["ts"], "kind": "log", **l} for l in logs] + \
             [{"ts": a["ts"], "kind": "action", **a} for a in acts]
    return sorted(events, key=lambda e: -e["ts"])


@app.get("/api/customers/{cid}/devices")
def devices(cid: str, u=Depends(need("view"))):
    """Device & IP fingerprinting: what this customer used, and who else used the same fingerprint."""
    out = {}
    for col in ("device_id", "ip"):
        rows = db.q(f"""SELECT {col} AS value, COUNT(*) n, MIN(ts) first_seen, MAX(ts) last_seen,
                        MAX(risk_score) max_risk, GROUP_CONCAT(DISTINCT city) cities
                        FROM transactions WHERE customer_id=? GROUP BY {col} ORDER BY last_seen DESC LIMIT 30""",
                    (cid,))
        for r in rows:
            r["shared_with"] = [x["customer_id"] for x in db.q(
                f"SELECT DISTINCT customer_id FROM transactions WHERE {col}=? AND customer_id!=? LIMIT 20",
                (r["value"], cid))]
            r["watchlisted"] = bool(db.q1("SELECT 1 FROM watchlist WHERE value=?", (r["value"],)))
        out["devices" if col == "device_id" else "ips"] = rows
    return out


@app.get("/api/customers/{cid}/geo")
def geo(cid: str, days: int = 30, u=Depends(need("view"))):
    c = db.q1("SELECT home_city, home_lat, home_lon FROM customers WHERE id=?", (cid,))
    pts = db.q("""SELECT id, ts, lat, lon, city, amount, risk_score, channel FROM transactions WHERE customer_id=?
                  AND ts>=? ORDER BY ts""", (cid, time.time() - days * 86400))
    return {"home": c, "points": pts, "cities": CITIES}


def _graph(seed_customers=(), seed_payees=(), hours=72, max_nodes=150):
    since = time.time() - hours * 3600
    nodes, edges, seen = {}, {}, set()
    wl = engine.watchlist()

    def add(nid, kind, label, **extra):
        if nid not in nodes:
            nodes[nid] = {"id": nid, "kind": kind, "label": label, "watchlisted": label in wl, **extra}

    def link(a, b, kind, w=1, amount=0):
        k = (a, b, kind)
        e = edges.setdefault(k, {"source": a, "target": b, "kind": kind, "count": 0, "amount": 0.0})
        e["count"] += w
        e["amount"] += amount

    frontier = [("C", c) for c in seed_customers] + [("P", p) for p in seed_payees]
    for _ in range(3):  # hops
        nxt = []
        for kind, val in frontier:
            if (kind, val) in seen or len(nodes) > max_nodes:
                continue
            seen.add((kind, val))
            if kind == "C":
                rows = db.q("""SELECT payee, payee_type, device_id, ip, amount, risk_score FROM transactions
                               WHERE customer_id=? AND ts>=?""", (val, since))
                cust = db.q1("SELECT name, status FROM customers WHERE id=?", (val,))
                risk = max([r["risk_score"] or 0 for r in rows] or [0])
                add("C:" + val, "customer", val, name=cust["name"] if cust else val,
                    status=cust["status"] if cust else "", risk=risk)
                for r in rows:
                    if r["payee_type"] in ("P2P", "BENEFICIARY"):
                        add("P:" + r["payee"], "payee", r["payee"])
                        link("C:" + val, "P:" + r["payee"], "paid", 1, r["amount"])
                        nxt.append(("P", r["payee"]))
                    add("D:" + r["device_id"], "device", r["device_id"])
                    link("C:" + val, "D:" + r["device_id"], "used_device")
                    nxt.append(("D", r["device_id"]))
                    add("I:" + r["ip"], "ip", r["ip"])
                    link("C:" + val, "I:" + r["ip"], "used_ip")
                    nxt.append(("I", r["ip"]))
            else:
                col = {"P": "payee", "D": "device_id", "I": "ip"}[kind]
                for r in db.q(f"SELECT DISTINCT customer_id FROM transactions WHERE {col}=? AND ts>=? LIMIT 25",
                              (val, since)):
                    nxt.append(("C", r["customer_id"]))
                    if kind == "P":
                        add("P:" + val, "payee", val)
        frontier = nxt
    # prune leaf device/ip nodes that only connect to one customer (noise)
    deg = defaultdict(int)
    for (a, b, _) in edges:
        deg[a] += 1
        deg[b] += 1
    keep = {n for n, v in nodes.items() if v["kind"] in ("customer", "payee") or deg[n] > 1 or v["watchlisted"]}
    return {"nodes": [nodes[n] for n in keep],
            "edges": [e for (a, b, _), e in edges.items() if a in keep and b in keep]}


@app.get("/api/graph")
def graph(customer_id: str = "", payee: str = "", hours: int = 72, u=Depends(need("view"))):
    if not customer_id and not payee:
        raise HTTPException(400, "customer_id or payee required")
    return _graph([customer_id] if customer_id else [], [payee] if payee else [], hours)


@app.get("/api/graph/rings")
def rings(hours: int = 24, u=Depends(need("view"))):
    """Fraud network detection: clusters of customers tied together through a shared payee, device or IP."""
    since = time.time() - hours * 3600
    rows = db.q("""SELECT customer_id, payee, payee_type, device_id, ip FROM transactions WHERE ts>=?
                   AND source!='HISTORY'""", (since,))
    by_key = defaultdict(set)
    for r in rows:
        if r["payee_type"] == "P2P":
            by_key[("payee", r["payee"])].add(r["customer_id"])
        by_key[("device", r["device_id"])].add(r["customer_id"])
        by_key[("ip", r["ip"])].add(r["customer_id"])
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    links = defaultdict(list)
    customer_vpas = {r["vpa"] for r in db.q("SELECT vpa FROM customers")}
    for key, custs in by_key.items():
        if len(custs) < 2 or (key[0] == "payee" and key[1] in customer_vpas and len(custs) < 3):
            continue
        cs = sorted(custs)
        for c in cs[1:]:
            parent[find(c)] = find(cs[0])
        links[cs[0]].append(key)
    groups = defaultdict(set)
    for c in parent:
        groups[find(c)].add(c)
    wl = engine.watchlist()
    out = []
    for root, members in groups.items():
        if len(members) < 3:
            continue
        shared = [{"type": k[0], "value": k[1], "customers": len(by_key[k]), "watchlisted": k[1] in wl}
                  for k in by_key if len(by_key[k]) >= 2 and by_key[k] <= members and k[1] not in customer_vpas]
        if not shared:
            continue
        ph = ",".join("?" * len(members))
        stat = db.q1(f"""SELECT COUNT(*) alerts, MAX(score) max_score FROM alerts WHERE customer_id IN ({ph})
                        AND created>=?""", (*members, since))
        out.append({"members": sorted(members), "size": len(members), "shared": shared[:15],
                    "alerts": stat["alerts"], "max_score": stat["max_score"]})
    return sorted(out, key=lambda r: (-(r["max_score"] or 0), -r["size"]))[:20]


# ====================================================================== response actions
def _cust_or_404(cid):
    if not db.q1("SELECT id FROM customers WHERE id=?", (cid,)):
        raise HTTPException(404, "unknown customer")


@app.post("/api/respond/block-account")
def r_block(body: dict = Body(...), u=Depends(need("respond"))):
    _cust_or_404(body.get("customer_id"))
    response.block_account(body["customer_id"], body.get("reason", "Blocked by analyst"), u["username"],
                           notify=body.get("notify", True), case_id=body.get("case_id"), **kw(u))
    return {"ok": True}


@app.post("/api/respond/unblock-account")
def r_unblock(body: dict = Body(...), u=Depends(need("unblock"))):
    _cust_or_404(body.get("customer_id"))
    response.unblock_account(body["customer_id"], body.get("reason", "Unblocked after verification"), u["username"],
                             case_id=body.get("case_id"), **kw(u))
    return {"ok": True}


@app.post("/api/respond/transaction")
def r_txn(body: dict = Body(...), u=Depends(need("respond"))):
    st = body.get("status")
    if st not in ("BLOCKED", "HELD", "APPROVED"):
        raise HTTPException(400, "status must be BLOCKED, HELD or APPROVED")
    if not response.set_txn_status(body.get("txn_id"), st, body.get("reason", ""), u["username"],
                                   case_id=body.get("case_id"), **kw(u)):
        raise HTTPException(404, "unknown transaction")
    return {"ok": True}


@app.post("/api/respond/notify")
def r_notify(body: dict = Body(...), u=Depends(need("respond"))):
    _cust_or_404(body.get("customer_id"))
    out = response.notify_customer(body["customer_id"], body.get("message") or
                                   "We noticed unusual activity on your account. Please call us to verify.",
                                   tuple(body.get("channels") or ("SMS", "EMAIL")), u["username"],
                                   case_id=body.get("case_id"), **kw(u))
    return {"ok": True, "notifications": out}


@app.post("/api/respond/fraud-team")
def r_fraud_team(body: dict = Body(...), u=Depends(need("respond"))):
    _cust_or_404(body.get("customer_id"))
    response.trigger_fraud_team(body["customer_id"], body.get("summary") or "Analyst escalation", u["username"],
                                case_id=body.get("case_id"), **kw(u))
    return {"ok": True}


@app.post("/api/respond/npci")
def r_npci(body: dict = Body(...), u=Depends(need("respond"))):
    if not body.get("vpa"):
        raise HTTPException(400, "vpa required")
    ref = response.npci_report(body["vpa"], body.get("reason", "Suspected mule"), u["username"],
                               body.get("customer_id", ""), case_id=body.get("case_id"), **kw(u))
    return {"ok": True, "npci_ref": ref}


@app.get("/api/watchlist")
def get_watchlist(u=Depends(need("view"))):
    return db.q("SELECT * FROM watchlist ORDER BY added DESC")


@app.post("/api/watchlist")
def add_watch(body: dict = Body(...), u=Depends(need("respond"))):
    if not body.get("value"):
        raise HTTPException(400, "value required")
    response.add_watchlist(body["value"], body.get("kind", "OTHER"), body.get("reason", ""), u["username"], **kw(u))
    return {"ok": True}


@app.delete("/api/watchlist/{value}")
def del_watch(value: str, u=Depends(need("rules"))):
    db.x("DELETE FROM watchlist WHERE value=?", (value,))
    A(u, "WATCHLIST.REMOVE", "watchlist", value)
    return {"ok": True}


@app.get("/api/actions")
def actions(limit: int = 100, u=Depends(need("view"))):
    return db.q("SELECT * FROM actions ORDER BY id DESC LIMIT ?", (min(limit, 1000),))


@app.get("/api/notifications")
def notifications(limit: int = 100, channel: str = "", u=Depends(need("view"))):
    if channel:
        return db.q("SELECT * FROM notifications WHERE channel=? ORDER BY id DESC LIMIT ?", (channel, limit))
    return db.q("SELECT * FROM notifications ORDER BY id DESC LIMIT ?", (min(limit, 1000),))


# ====================================================================== rules, model, settings
@app.get("/api/rules")
def get_rules(u=Depends(need("view"))):
    hits = {r["id"]: r["hits"] for r in db.q("SELECT id, hits FROM rules")}
    return [{**r, "hits": hits.get(r["id"], 0)} for r in rules.all_rules().values()]


@app.put("/api/rules/{rid}")
def put_rule(rid: str, body: dict = Body(...), u=Depends(need("rules"))):
    r = rules.all_rules().get(rid)
    if not r:
        raise HTTPException(404)
    enabled = int(body.get("enabled", r["enabled"]))
    weight = float(body.get("weight", r["weight"]))
    params = {**r["params"], **{k: type(r["params"][k])(v) for k, v in (body.get("params") or {}).items()
                                 if k in r["params"]}}
    db.x("UPDATE rules SET enabled=?, weight=?, params=? WHERE id=?", (enabled, weight, json.dumps(params), rid))
    rules.reload()
    A(u, "RULE.UPDATE", "rule", rid, {"before": {k: r[k] for k in ("enabled", "weight", "params")},
                                      "after": {"enabled": enabled, "weight": weight, "params": params}})
    return rules.all_rules()[rid]


@app.get("/api/model")
def get_model(u=Depends(need("view"))):
    versions = db.q("SELECT * FROM model_versions ORDER BY id DESC")
    for v in versions:
        v["metrics"] = json.loads(v["metrics"] or "{}")
    labels = db.q1("""SELECT SUM(CASE WHEN label='FRAUD' AND source!='HISTORY' THEN 1 ELSE 0 END) fraud_feedback,
                      SUM(CASE WHEN label='LEGIT' AND source!='HISTORY' THEN 1 ELSE 0 END) legit_feedback
                      FROM transactions""")
    return {"active": model.version, "features": FEATURE_NAMES, "versions": versions, "feedback": labels,
            "auto_retrain_minutes": AUTO_RETRAIN_MINUTES}


@app.post("/api/model/retrain")
def retrain(u=Depends(need("model"))):
    res = model.train(trigger=f"manual:{u['username']}")
    A(u, "MODEL.RETRAIN", "model", res.get("version"), res)
    return res


@app.post("/api/model/activate")
def activate(body: dict = Body(...), u=Depends(need("model"))):
    if not model.activate(body.get("version")):
        raise HTTPException(404, "version not found")
    A(u, "MODEL.ACTIVATE", "model", body.get("version"))
    return {"ok": True, "active": model.version}


@app.get("/api/settings")
def get_settings(u=Depends(need("view"))):
    return {"auto_response": db.get_setting("auto_response", True), "auto_block": db.get_setting("auto_block", True)}


@app.put("/api/settings")
def put_settings(body: dict = Body(...), u=Depends(need("rules"))):
    for k in ("auto_response", "auto_block"):
        if k in body:
            db.set_setting(k, bool(body[k]))
    A(u, "SETTINGS.UPDATE", "settings", "", body)
    return get_settings(u)


# ====================================================================== reports & audit
@app.get("/api/reports/kpis")
def r_kpis(hours: int = 24, u=Depends(need("reports"))):
    return reports.kpis(hours)


@app.get("/api/reports/{period}")
def r_report(period: str, format: str = "json", u=Depends(need("reports"))):
    if period not in ("daily", "weekly"):
        raise HTTPException(404)
    rep = reports.fraud_report(period)
    A(u, "REPORT.GENERATE", "report", period, {"format": format})
    if format == "csv":
        rows = db.q("""SELECT a.id alert_id, datetime(a.created,'unixepoch','+330 minutes') created_ist, a.priority,
                       a.score, a.status, a.disposition, a.customer_id, t.channel, t.amount, t.payee, t.city,
                       t.status txn_status, a.reasons FROM alerts a JOIN transactions t ON t.id=a.txn_id
                       WHERE a.created>=? ORDER BY a.created""", (rep["from"],))
        return Response(reports.to_csv(rows), media_type="text/csv",
                        headers={"Content-Disposition": f"attachment; filename=kavach_{period}_alerts.csv"})
    return rep


@app.get("/api/compliance")
def r_compliance(u=Depends(need("reports"))):
    return reports.compliance()


@app.get("/api/export/auditor")
def export_auditor(days: int = 30, u=Depends(need("export"))):
    data = reports.auditor_export(days)
    A(u, "EXPORT.AUDITOR_PACK", "export", f"{days}d", {"bytes": len(data)})
    return Response(data, media_type="application/zip",
                    headers={"Content-Disposition": f"attachment; filename=kavach_audit_pack_{int(time.time())}.zip"})


@app.get("/api/audit")
def audit_log(limit: int = 200, actor: str = "", action: str = "", u=Depends(need("audit"))):
    sql, p = "SELECT * FROM audit_log WHERE 1=1", []
    if actor:
        sql += " AND actor=?"
        p.append(actor)
    if action:
        sql += " AND action LIKE ?"
        p.append(f"%{action}%")
    return db.q(sql + " ORDER BY id DESC LIMIT ?", (*p, min(limit, 2000)))


@app.get("/api/audit/verify")
def audit_verify(u=Depends(need("audit"))):
    return security.verify_audit_chain()


@app.get("/api/siem")
def siem(limit: int = 100, u=Depends(need("view"))):
    return db.q("SELECT * FROM siem_logs ORDER BY id DESC LIMIT ?", (min(limit, 1000),))


# ====================================================================== admin
@app.get("/api/users")
def list_users(u=Depends(need("view"))):
    rows = db.q("SELECT id, username, full_name, role, mfa_enabled, active, last_login FROM users ORDER BY id")
    return rows


@app.post("/api/users")
def create_user(body: dict = Body(...), u=Depends(need("users"))):
    if body.get("role") not in security.ROLES or not body.get("username") or len(body.get("password", "")) < 10:
        raise HTTPException(400, "username, role and a password of at least 10 characters are required")
    if db.q1("SELECT id FROM users WHERE username=?", (body["username"],)):
        raise HTTPException(400, "username taken")
    uid = db.insert("users", {"username": body["username"], "full_name": body.get("full_name", body["username"]),
                              "role": body["role"], "pw_hash": security.hash_password(body["password"]),
                              "active": 1, "created": db.now()})
    A(u, "USER.CREATE", "user", body["username"], {"role": body["role"]})
    return {"id": uid}


@app.put("/api/users/{uid}")
def update_user(uid: int, body: dict = Body(...), u=Depends(need("users"))):
    target = db.q1("SELECT * FROM users WHERE id=?", (uid,))
    if not target:
        raise HTTPException(404)
    changes = {}
    if body.get("role") in security.ROLES:
        changes["role"] = body["role"]
    if "active" in body:
        if uid == u["id"] and not body["active"]:
            raise HTTPException(400, "You cannot deactivate yourself")
        changes["active"] = int(bool(body["active"]))
    if body.get("reset_mfa"):
        changes["mfa_enabled"], changes["mfa_secret"] = 0, None
    if body.get("password"):
        changes["pw_hash"] = security.hash_password(body["password"])
    for k, v in changes.items():
        db.x(f"UPDATE users SET {k}=? WHERE id=?", (v, uid))
    if "active" in changes and not changes["active"]:
        db.x("DELETE FROM sessions WHERE user_id=?", (uid,))
    A(u, "USER.UPDATE", "user", target["username"], {k: v for k, v in changes.items() if k != "pw_hash"} |
      ({"password_reset": True} if "pw_hash" in changes else {}))
    return {"ok": True}


@app.get("/api/integrations")
def integrations(u=Depends(need("view"))):
    key = db.get_setting("ingest_api_key", "")
    show = security.can(u["role"], "integrations")
    return {"ingest_api_key": key if show else key[:6] + "…", "webhooks": db.q("SELECT * FROM webhooks")
            if show else [], "endpoints": [
        {"method": "POST", "path": "/api/v1/transactions", "desc": "Score one transaction in real time (CBS / switch)"},
        {"method": "POST", "path": "/api/v1/transactions/batch", "desc": "Historical import (JSON list)"},
        {"method": "POST", "path": "/api/v1/import/csv", "desc": "Historical import (CSV upload)"},
        {"method": "POST", "path": "/api/v1/logs", "desc": "SIEM-style security log ingestion"},
        {"method": "GET", "path": "/api/v1/decision/{txn_id}", "desc": "Fetch decision for a transaction"},
        {"method": "POST", "path": "/api/v1/npci/callback", "desc": "NPCI status callbacks (mock)"}],
        "webhook_events": ["alert.high", "fraud_team.triggered", "*"]}


@app.post("/api/integrations/rotate-key")
def rotate_key(u=Depends(need("integrations"))):
    key = "kvk_" + secrets.token_urlsafe(24)
    db.set_setting("ingest_api_key", key)
    A(u, "INTEGRATION.ROTATE_KEY", "api_key", "ingest")
    return {"ingest_api_key": key}


@app.post("/api/webhooks")
def add_webhook(body: dict = Body(...), u=Depends(need("integrations"))):
    if not str(body.get("url", "")).startswith(("http://", "https://")):
        raise HTTPException(400, "url must be http(s)")
    secret = secrets.token_hex(16)
    wid = db.insert("webhooks", {"url": body["url"], "events": json.dumps(body.get("events") or ["alert.high"]),
                                 "secret": secret, "active": 1, "created": db.now()})
    A(u, "WEBHOOK.CREATE", "webhook", wid, {"url": body["url"]})
    return {"id": wid, "secret": secret}


@app.delete("/api/webhooks/{wid}")
def del_webhook(wid: int, u=Depends(need("integrations"))):
    db.x("DELETE FROM webhooks WHERE id=?", (wid,))
    A(u, "WEBHOOK.DELETE", "webhook", wid)
    return {"ok": True}


@app.post("/api/webhooks/{wid}/test")
def test_webhook(wid: int, u=Depends(need("integrations"))):
    h = db.q1("SELECT * FROM webhooks WHERE id=?", (wid,))
    if not h:
        raise HTTPException(404)
    threading.Thread(target=response._deliver, args=(h, "test", {"hello": "from KAVACH"}), daemon=True).start()
    return {"ok": True}


@app.post("/api/webhook-sink")
async def webhook_sink(request: Request):
    """A local receiver so webhook delivery can be demonstrated without an external server."""
    WEBHOOK_SINK.appendleft({"ts": time.time(), "headers": {k: v for k, v in request.headers.items()
                                                            if k.lower().startswith("x-kavach")},
                             "body": (await request.body()).decode()[:2000]})
    return {"received": True}


@app.get("/api/webhook-sink")
def webhook_sink_list(u=Depends(need("integrations"))):
    return list(WEBHOOK_SINK)


@app.get("/api/simulator")
def sim_status(u=Depends(need("view"))):
    f = STATE["feed"]
    return (f.status() if f else {}) | {"scenarios": FRAUD_SCENARIOS}


@app.post("/api/simulator")
def sim_control(body: dict = Body(...), u=Depends(need("simulator"))):
    f = STATE["feed"]
    if not f:
        raise HTTPException(503, "starting")
    if "running" in body:
        f.running = bool(body["running"])
        db.set_setting("sim_running", f.running)
    if "tps" in body:
        f.tps = max(0.1, min(20.0, float(body["tps"])))
    if "fraud_rate" in body:
        f.fraud_rate = max(0.0, min(0.5, float(body["fraud_rate"])))
    A(u, "SIMULATOR.UPDATE", "simulator", "", body)
    return f.status()


@app.post("/api/simulator/inject")
def sim_inject(body: dict = Body(default={}), u=Depends(need("simulator"))):
    f = STATE["feed"]
    kind = body.get("kind")
    if kind and kind not in FRAUD_SCENARIOS:
        raise HTTPException(400, f"kind must be one of {FRAUD_SCENARIOS}")
    res = f.inject(kind)
    A(u, "SIMULATOR.INJECT", "simulator", res["kind"], res)
    return res


# ====================================================================== bank-facing integration API (API key)
def api_key(x_api_key: str = Header(None)):
    if not x_api_key or not secrets.compare_digest(x_api_key, db.get_setting("ingest_api_key", "")):
        raise HTTPException(401, "invalid X-API-Key")
    return "integration"


def _normalize(e):
    req = ("customer_id", "channel", "amount")
    if any(k not in e for k in req):
        raise HTTPException(400, f"fields required: {req}")
    city = e.get("city") or (db.q1("SELECT home_city FROM customers WHERE id=?", (e["customer_id"],)) or {}).get(
        "home_city", "Mumbai")
    lat, lon = CITIES.get(city, (e.get("lat", 19.07), e.get("lon", 72.87)))
    return {"kind": "txn", "id": e.get("id") or f"T{secrets.token_hex(7).upper()}", "ts": float(e.get("ts") or time.time()),
            "customer_id": e["customer_id"], "channel": str(e["channel"]).upper(), "amount": float(e["amount"]),
            "payee": e.get("payee", "UNKNOWN"), "payee_type": e.get("payee_type", "MERCHANT"),
            "category": e.get("category", "other"), "device_id": e.get("device_id", "UNKNOWN"),
            "ip": e.get("ip", "0.0.0.0"), "city": city, "lat": e.get("lat", lat), "lon": e.get("lon", lon),
            "truth": "IMPORTED_FRAUD" if str(e.get("is_fraud", "")).lower() in ("1", "true", "yes") else None}


@app.post("/api/v1/transactions")
def v1_txn(body: dict = Body(...), _=Depends(api_key)):
    need_ready()
    try:
        r = engine.process(_normalize(body), "API")
    except ValueError as ex:
        raise HTTPException(400, str(ex))
    security.audit("integration", "API", "INGEST.TRANSACTION", "transaction", r["id"], {"decision": r["status"]})
    return {"txn_id": r["id"], "decision": r["status"], "risk_score": r["risk_score"], "priority": r["priority"],
            "alert_id": r["alert_id"], "reasons": [h["name"] for h in r["reasons"]["rules"]] + r["reasons"]["profile"]}


def _import(events):
    need_ready()
    evs = sorted((_normalize(e) for e in events), key=lambda e: e["ts"])
    known = {r["id"] for r in db.q("SELECT id FROM customers")}
    evs = [e for e in evs if e["customer_id"] in known]
    engine.replay_history(evs)
    security.audit("integration", "API", "INGEST.HISTORICAL_IMPORT", "transactions", "", {"count": len(evs)})
    return {"imported": len(evs), "skipped_unknown_customer": len(events) - len(evs)}


@app.post("/api/v1/transactions/batch")
def v1_batch(body: list = Body(...), _=Depends(api_key)):
    return _import(body)


@app.post("/api/v1/import/csv")
async def v1_csv(file: UploadFile = File(...), _=Depends(api_key)):
    import csv
    import io
    text = (await file.read()).decode("utf-8-sig")
    return _import(list(csv.DictReader(io.StringIO(text))))


@app.post("/api/v1/logs")
def v1_logs(body: dict | list = Body(...), _=Depends(api_key)):
    items = body if isinstance(body, list) else [body]
    ids = [engine.ingest_log({"ts": float(i.get("ts") or time.time()), "source": i.get("source", "EXTERNAL"),
                              "event_type": i.get("event_type", "EVENT"), "customer_id": i.get("customer_id"),
                              "ip": i.get("ip", ""), "device_id": i.get("device_id", ""),
                              "severity": i.get("severity", "INFO"), "message": i.get("message", "")})
           for i in items]
    return {"ingested": len(ids)}


@app.get("/api/v1/decision/{tid}")
def v1_decision(tid: str, _=Depends(api_key)):
    t = db.q1("SELECT id, status, risk_score, priority, alert_id FROM transactions WHERE id=?", (tid,))
    if not t:
        raise HTTPException(404)
    return t


@app.post("/api/v1/npci/callback")
def v1_npci(body: dict = Body(...), _=Depends(api_key)):
    response._notify("NPCI", "KAVACH", f"NPCI callback {body.get('ref', '')}", json.dumps(body), body.get("ref", ""))
    security.audit("npci", "API", "NPCI.CALLBACK", "npci", body.get("ref", ""), body)
    return {"ok": True}


# ====================================================================== static dashboard
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.get("/", response_class=HTMLResponse)
def index():
    return FileResponse(BASE_DIR / "static" / "index.html")

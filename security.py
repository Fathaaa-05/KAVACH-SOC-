"""Authentication, MFA, role-based access control, PII encryption and the tamper-evident audit trail."""
import hashlib
import hmac
import json
import os
import secrets

import pyotp
from cryptography.fernet import Fernet

from . import db
from .config import KEY_PATH, SESSION_HOURS

# ---------------------------------------------------------------- RBAC
ROLES = ["ADMIN", "MANAGER", "ANALYST", "READONLY"]

PERMISSIONS = {
    "view":            {"ADMIN", "MANAGER", "ANALYST", "READONLY"},
    "reports":         {"ADMIN", "MANAGER", "ANALYST", "READONLY"},
    "export":          {"ADMIN", "MANAGER", "READONLY"},
    "audit":           {"ADMIN", "MANAGER", "READONLY"},
    "triage":          {"ADMIN", "MANAGER", "ANALYST"},
    "case_work":       {"ADMIN", "MANAGER", "ANALYST"},
    "case_assign":     {"ADMIN", "MANAGER"},
    "respond":         {"ADMIN", "MANAGER", "ANALYST"},
    "unblock":         {"ADMIN", "MANAGER"},
    "model":           {"ADMIN", "MANAGER"},
    "rules":           {"ADMIN"},
    "users":           {"ADMIN"},
    "integrations":    {"ADMIN"},
    "simulator":       {"ADMIN", "MANAGER"},
}


def can(role, perm):
    return role in PERMISSIONS.get(perm, set())


def permissions_for(role):
    return sorted(p for p, roles in PERMISSIONS.items() if role in roles)


# ---------------------------------------------------------------- passwords
def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000)
    return f"pbkdf2_sha256$200000${salt.hex()}${dk.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        _, iters, salt, h = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), int(iters))
        return hmac.compare_digest(dk.hex(), h)
    except Exception:
        return False


# ---------------------------------------------------------------- MFA (TOTP, RFC 6238)
def new_mfa_secret():
    return pyotp.random_base32()


def verify_totp(secret, code):
    if not secret or not code:
        return False
    return pyotp.TOTP(secret).verify(str(code).strip(), valid_window=1)


def provisioning_uri(secret, username):
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="KAVACH SOC")


# ---------------------------------------------------------------- sessions
def create_session(user_id, ip=None):
    token = secrets.token_urlsafe(32)
    now = db.now()
    db.insert("sessions", {"token": token, "user_id": user_id, "created": now,
                           "expires": now + SESSION_HOURS * 3600, "ip": ip})
    return token


def session_user(token):
    if not token:
        return None
    row = db.q1("""SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id
                   WHERE s.token=? AND s.expires>? AND u.active=1""", (token, db.now()))
    return row


def end_session(token):
    db.x("DELETE FROM sessions WHERE token=?", (token,))


# ---------------------------------------------------------------- encryption at rest
_fernet = None


def fernet():
    global _fernet
    if _fernet is None:
        key = os.environ.get("KAVACH_ENC_KEY")
        if not key:
            if KEY_PATH.exists():
                key = KEY_PATH.read_text().strip()
            else:
                key = Fernet.generate_key().decode()
                KEY_PATH.write_text(key)
                try:
                    os.chmod(KEY_PATH, 0o600)
                except OSError:
                    pass
        _fernet = Fernet(key.encode() if isinstance(key, str) else key)
    return _fernet


def enc(value: str) -> str:
    return fernet().encrypt(value.encode()).decode() if value else ""


def dec(value: str) -> str:
    try:
        return fernet().decrypt(value.encode()).decode() if value else ""
    except Exception:
        return "<undecryptable>"


def mask_phone(p):
    return (p[:3] + "XXXXX" + p[-2:]) if p and len(p) > 5 else p


def mask_email(e):
    if not e or "@" not in e:
        return e
    user, dom = e.split("@", 1)
    return user[:2] + "***@" + dom


# ---------------------------------------------------------------- audit trail (hash chained)
def audit(actor, role, action, entity="", entity_id="", details=None, ip=None):
    with db.lock():
        prev = db.scalar("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1") or "GENESIS"
        ts = db.now()
        det = json.dumps(details or {}, sort_keys=True, default=str)
        payload = f"{prev}|{ts:.6f}|{actor}|{role}|{action}|{entity}|{entity_id}|{det}|{ip or ''}"
        h = hashlib.sha256(payload.encode()).hexdigest()
        db.insert("audit_log", {"ts": ts, "actor": actor, "role": role, "action": action,
                                "entity": entity, "entity_id": str(entity_id), "details": det,
                                "ip": ip or "", "prev_hash": prev, "hash": h})
        return h


def verify_audit_chain():
    prev = "GENESIS"
    n = 0
    for r in db.q("SELECT * FROM audit_log ORDER BY id"):
        payload = (f"{prev}|{r['ts']:.6f}|{r['actor']}|{r['role']}|{r['action']}|{r['entity']}|"
                   f"{r['entity_id']}|{r['details']}|{r['ip']}")
        if r["prev_hash"] != prev or hashlib.sha256(payload.encode()).hexdigest() != r["hash"]:
            return {"valid": False, "broken_at_id": r["id"], "checked": n}
        prev = r["hash"]
        n += 1
    return {"valid": True, "checked": n, "head": prev}

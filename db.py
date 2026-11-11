"""SQLite storage. One shared connection guarded by a lock (fine for a single-node prototype)."""
import json
import sqlite3
import threading
import time

from .config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, full_name TEXT, role TEXT NOT NULL,
    pw_hash TEXT NOT NULL, mfa_secret TEXT, mfa_enabled INTEGER DEFAULT 0, active INTEGER DEFAULT 1,
    created REAL, last_login REAL
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY, user_id INTEGER, created REAL, expires REAL, ip TEXT
);
CREATE TABLE IF NOT EXISTS customers (
    id TEXT PRIMARY KEY, name TEXT, phone_enc TEXT, email_enc TEXT, account_no TEXT, vpa TEXT,
    card_last4 TEXT, home_city TEXT, home_lat REAL, home_lon REAL, segment TEXT,
    status TEXT DEFAULT 'ACTIVE', created REAL
);
CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY, ts REAL NOT NULL, customer_id TEXT, channel TEXT, amount REAL,
    payee TEXT, payee_type TEXT, category TEXT, device_id TEXT, ip TEXT, city TEXT, lat REAL, lon REAL,
    status TEXT, risk_score REAL, rule_score REAL, ml_score REAL, profile_score REAL,
    priority TEXT, reasons TEXT, label TEXT, truth TEXT, source TEXT, features TEXT,
    alert_id INTEGER
);
CREATE INDEX IF NOT EXISTS ix_txn_cust_ts ON transactions(customer_id, ts);
CREATE INDEX IF NOT EXISTS ix_txn_ts ON transactions(ts);
CREATE INDEX IF NOT EXISTS ix_txn_payee_ts ON transactions(payee, ts);
CREATE INDEX IF NOT EXISTS ix_txn_device ON transactions(device_id);
CREATE INDEX IF NOT EXISTS ix_txn_ip ON transactions(ip);
CREATE TABLE IF NOT EXISTS profiles (
    customer_id TEXT PRIMARY KEY, data TEXT, updated REAL
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY, txn_id TEXT, customer_id TEXT, created REAL, priority TEXT, score REAL,
    reasons TEXT, status TEXT DEFAULT 'OPEN', disposition TEXT, case_id INTEGER,
    assignee_id INTEGER, acked REAL, closed REAL
);
CREATE INDEX IF NOT EXISTS ix_alert_status ON alerts(status, created);
CREATE INDEX IF NOT EXISTS ix_alert_cust ON alerts(customer_id);
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY, title TEXT, customer_id TEXT, priority TEXT, status TEXT DEFAULT 'OPEN',
    assignee_id INTEGER, created_by INTEGER, created REAL, updated REAL, sla_due REAL,
    escalation_level INTEGER DEFAULT 0, resolution TEXT, closed REAL, fraud_amount REAL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS case_notes (
    id INTEGER PRIMARY KEY, case_id INTEGER, user_id INTEGER, ts REAL, note TEXT
);
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY, ts REAL, type TEXT, target TEXT, case_id INTEGER, alert_id INTEGER,
    actor TEXT, automated INTEGER DEFAULT 0, details TEXT
);
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY, ts REAL, channel TEXT, recipient TEXT, subject TEXT, message TEXT,
    status TEXT, ref TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY, ts REAL, actor TEXT, role TEXT, action TEXT, entity TEXT, entity_id TEXT,
    details TEXT, ip TEXT, prev_hash TEXT, hash TEXT
);
CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY, name TEXT, description TEXT, enabled INTEGER DEFAULT 1, weight REAL,
    params TEXT, hits INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS model_versions (
    id INTEGER PRIMARY KEY, version TEXT, trained_at REAL, n_samples INTEGER, n_labeled INTEGER,
    kind TEXT, metrics TEXT, active INTEGER DEFAULT 0, trigger TEXT
);
CREATE TABLE IF NOT EXISTS siem_logs (
    id INTEGER PRIMARY KEY, ts REAL, source TEXT, event_type TEXT, customer_id TEXT, ip TEXT,
    device_id TEXT, severity TEXT, message TEXT
);
CREATE INDEX IF NOT EXISTS ix_siem_cust_ts ON siem_logs(customer_id, ts);
CREATE TABLE IF NOT EXISTS watchlist (
    value TEXT PRIMARY KEY, kind TEXT, reason TEXT, added REAL, added_by TEXT
);
CREATE TABLE IF NOT EXISTS webhooks (
    id INTEGER PRIMARY KEY, url TEXT, events TEXT, secret TEXT, active INTEGER DEFAULT 1, created REAL,
    last_status TEXT
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY, value TEXT
);
"""

_lock = threading.RLock()
_conn = None


def conn():
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA synchronous=NORMAL")
        _conn.executescript(SCHEMA)
    return _conn


def q(sql, params=()):
    with _lock:
        return [dict(r) for r in conn().execute(sql, params).fetchall()]


def q1(sql, params=()):
    with _lock:
        r = conn().execute(sql, params).fetchone()
        return dict(r) if r else None


def scalar(sql, params=()):
    with _lock:
        r = conn().execute(sql, params).fetchone()
        return r[0] if r else None


def x(sql, params=()):
    with _lock:
        cur = conn().execute(sql, params)
        return cur.lastrowid


def xmany(sql, rows):
    with _lock:
        c = conn()
        c.execute("BEGIN")
        c.executemany(sql, rows)
        c.execute("COMMIT")


def insert(table, row: dict):
    cols = ",".join(row)
    ph = ",".join("?" for _ in row)
    return x(f"INSERT INTO {table} ({cols}) VALUES ({ph})", tuple(row.values()))


def get_setting(key, default=None):
    v = scalar("SELECT value FROM settings WHERE key=?", (key,))
    return json.loads(v) if v is not None else default


def set_setting(key, value):
    x("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
      (key, json.dumps(value)))


def lock():
    return _lock


def now():
    return time.time()

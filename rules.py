"""Rule-based engine: hard, explainable rules configurable by admins at runtime."""
import json

from . import db

DEFAULT_RULES = [
    ("R01", "High value velocity", "Total debits above the limit within a short window (e.g. >₹50k in 2 min)",
     85, {"window_sec": 120, "limit": 50000}),
    ("R02", "Transaction burst", "Too many transactions within a short window", 50, {"window_sec": 300, "count": 5}),
    ("R03", "New device, high value", "High-value transaction from a device never seen for the customer",
     70, {"min_amount": 20000}),
    ("R04", "Impossible travel", "Consecutive transactions on different devices imply travel faster than an aircraft",
     80, {"max_kmh": 600}),
    ("R05", "Night-time high value", "High-value transaction between 00:00 and 05:00 IST",
     55, {"min_amount": 25000, "start_hour": 0, "end_hour": 5}),
    ("R06", "Amount spike", "Amount many times above the customer's typical transaction",
     50, {"multiplier": 5, "min_amount": 10000}),
    ("R07", "Watchlist hit", "Payee VPA, IP or device is on the fraud watchlist / NPCI negative list",
     95, {}),
    ("R08", "Card testing pattern", "Several micro card transactions in quick succession (card validity probing)",
     75, {"window_sec": 900, "max_small_amount": 100, "count": 3}),
    ("R09", "Mule fan-in", "Payee is receiving money from many different customers in a short window",
     70, {"window_sec": 1800, "distinct_senders": 3}),
    ("R10", "Account takeover signals", "Failed logins, password reset, new-device login or SIM swap shortly before",
     65, {"window_sec": 3600, "failed_logins": 3}),
    ("R11", "First-time payee, large amount", "Large transfer to a payee never paid before",
     40, {"min_amount": 25000}),
]

_cache = None


def seed():
    for rid, name, desc, w, params in DEFAULT_RULES:
        db.x("INSERT OR IGNORE INTO rules(id,name,description,enabled,weight,params) VALUES (?,?,?,?,?,?)",
             (rid, name, desc, 1, w, json.dumps(params)))
    reload()


def reload():
    global _cache
    _cache = {r["id"]: {**r, "params": json.loads(r["params"])} for r in db.q("SELECT * FROM rules ORDER BY id")}


def all_rules():
    if _cache is None:
        reload()
    return _cache


def evaluate(t, f, ctx):
    """t: transaction, f: profile features, ctx: recent activity context. Returns (score, hits)."""
    hits = []
    R = all_rules()

    def on(rid):
        return R.get(rid) and R[rid]["enabled"]

    def hit(rid, detail):
        hits.append({"rule": rid, "name": R[rid]["name"], "weight": R[rid]["weight"], "detail": detail})

    amt = t["amount"]
    recent = ctx["recent"]  # this customer's earlier txns in last hour (excludes current)

    if on("R01"):
        p = R["R01"]["params"]
        total = amt + sum(r["amount"] for r in recent if t["ts"] - r["ts"] <= p["window_sec"])
        if total > p["limit"]:
            hit("R01", f"₹{total:,.0f} debited in {p['window_sec'] // 60} min (limit ₹{p['limit']:,})")
    if on("R02"):
        p = R["R02"]["params"]
        n = 1 + sum(1 for r in recent if t["ts"] - r["ts"] <= p["window_sec"])
        if n >= p["count"]:
            hit("R02", f"{n} transactions in {p['window_sec'] // 60} min")
    if on("R03") and f["new_device"] and amt >= R["R03"]["params"]["min_amount"]:
        hit("R03", f"₹{amt:,.0f} from unrecognised device {t['device_id']}")
    # a traveller carries their phone; the same customer on a *different* device far away is the red flag
    if on("R04") and f["travel_speed_kmh"] > R["R04"]["params"]["max_kmh"] and f["device_changed"]:
        hit("R04", f"{f['last_city']} → {t['city']} implies {f['travel_speed_kmh']:,.0f} km/h, on a different device")
    if on("R05"):
        p = R["R05"]["params"]
        if p["start_hour"] <= f["hour"] < p["end_hour"] and amt >= p["min_amount"]:
            hit("R05", f"₹{amt:,.0f} at {f['hour']:02d}:00 IST")
    if on("R06") and f["typical_amount"]:
        p = R["R06"]["params"]
        if amt >= p["min_amount"] and amt >= p["multiplier"] * f["typical_amount"]:
            hit("R06", f"₹{amt:,.0f} is {amt / max(f['typical_amount'], 1):.0f}× typical")
    if on("R07"):
        for v in (t["payee"], t["ip"], t["device_id"]):
            if v in ctx["watchlist"]:
                hit("R07", f"{v} — {ctx['watchlist'][v]}")
                break
    if on("R08") and t["channel"] == "CARD":
        p = R["R08"]["params"]
        small = [r for r in recent if r["channel"] == "CARD" and r["amount"] < p["max_small_amount"]
                 and t["ts"] - r["ts"] <= p["window_sec"]]
        n = len(small) + (1 if amt < p["max_small_amount"] else 0)
        if n >= p["count"]:
            hit("R08", f"{n} micro card transactions in {p['window_sec'] // 60} min")
    if on("R09") and t["payee_type"] == "P2P":
        p = R["R09"]["params"]
        senders = ctx["payee_senders"] | {t["customer_id"]}
        if len(senders) >= p["distinct_senders"]:
            hit("R09", f"{t['payee']} received from {len(senders)} different customers in "
                       f"{p['window_sec'] // 60} min")
    if on("R10"):
        p = R["R10"]["params"]
        logs = ctx["logs"]
        failed = sum(1 for l in logs if l["event_type"] == "LOGIN_FAILED")
        kinds = {l["event_type"] for l in logs}
        sig = []
        if failed >= p["failed_logins"]:
            sig.append(f"{failed} failed logins")
        sig += [k.replace("_", " ").lower() for k in ("PASSWORD_RESET", "NEW_DEVICE_LOGIN", "SIM_CHANGE")
                if k in kinds]
        if sig:
            hit("R10", "Recent: " + ", ".join(sig))
            if "SIM_CHANGE" in kinds:
                hits[-1]["weight"] = max(hits[-1]["weight"], 85)
    if on("R11") and f["new_payee"] and amt >= R["R11"]["params"]["min_amount"]:
        hit("R11", f"₹{amt:,.0f} to first-time payee {t['payee']}")

    if not hits:
        return 0.0, hits
    ws = sorted((h["weight"] for h in hits), reverse=True)
    score = min(100.0, ws[0] + 0.15 * sum(ws[1:]))
    return score, hits

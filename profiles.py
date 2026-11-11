"""Behavioral profiling: learns each customer's normal pattern and scores deviations from it."""
import json
import math
import threading

from . import db
from .config import ALERT_THRESHOLD
from .simulator import haversine


class Profile:
    __slots__ = ("n", "mu", "m2", "max_amt", "hours", "devices", "cities", "payees", "ip_prefixes",
                 "channels", "last")

    def __init__(self):
        self.n, self.mu, self.m2, self.max_amt = 0, 0.0, 0.0, 0.0
        self.hours = [0] * 24
        self.devices, self.cities, self.payees, self.ip_prefixes, self.channels = {}, {}, {}, {}, {}
        self.last = None

    @property
    def sigma(self):
        return math.sqrt(self.m2 / (self.n - 1)) if self.n > 1 else 1.0

    def update(self, t):
        la = math.log1p(t["amount"])
        self.n += 1
        d = la - self.mu
        self.mu += d / self.n
        self.m2 += d * (la - self.mu)
        self.max_amt = max(self.max_amt, t["amount"])
        self.hours[ist_hour(t["ts"])] += 1
        for attr, key in (("devices", t["device_id"]), ("cities", t["city"]), ("payees", t["payee"]),
                          ("ip_prefixes", ip_prefix(t["ip"])), ("channels", t["channel"])):
            dct = getattr(self, attr)
            dct[key] = dct.get(key, 0) + 1
        self.last = {"ts": t["ts"], "lat": t["lat"], "lon": t["lon"], "city": t["city"], "device": t["device_id"]}

    def to_dict(self):
        top = lambda d, k=5: sorted(d.items(), key=lambda kv: -kv[1])[:k]
        return {
            "transactions": self.n, "typical_amount": round(math.expm1(self.mu), 2),
            "amount_sigma_log": round(self.sigma, 3), "max_amount": round(self.max_amt, 2),
            "hour_histogram": self.hours, "active_hours": [h for h in range(24) if self.n and
                                                          self.hours[h] / self.n >= 0.06],
            "known_devices": top(self.devices, 10), "known_cities": top(self.cities, 10),
            "top_payees": top(self.payees, 8), "ip_prefixes": top(self.ip_prefixes, 8),
            "channels": self.channels, "last_seen": self.last,
        }


def ist_hour(ts):
    return int(((ts + 19800) % 86400) // 3600)


def ip_prefix(ip):
    return ".".join((ip or "").split(".")[:2])


class ProfileStore:
    def __init__(self):
        self.p = {}
        self.lock = threading.Lock()

    def get(self, cid):
        with self.lock:
            return self.p.setdefault(cid, Profile())

    def rebuild(self):
        """Learn profiles from all non-fraud history."""
        with self.lock:
            self.p = {}
        for t in db.q("""SELECT customer_id, ts, amount, device_id, city, payee, ip, channel, lat, lon
                         FROM transactions WHERE status='APPROVED' AND (label='LEGIT' OR
                         (label IS NULL AND COALESCE(risk_score, 0) < ?)) ORDER BY ts""", (ALERT_THRESHOLD,)):
            self.get(t["customer_id"]).update(t)

    def learn(self, t):
        p = self.get(t["customer_id"])
        with self.lock:
            p.update(t)

    def snapshot(self):
        with self.lock:
            rows = [(cid, json.dumps(p.to_dict()), db.now()) for cid, p in self.p.items()]
        db.xmany("INSERT OR REPLACE INTO profiles VALUES (?,?,?)", rows)

    def features(self, t, home):
        """Deviation features for one transaction against the customer's profile."""
        p = self.get(t["customer_id"])
        mature = p.n >= 5
        la = math.log1p(t["amount"])
        z = (la - p.mu) / max(p.sigma, 0.35) if mature else 0.0
        h = ist_hour(t["ts"])
        hour_p = (p.hours[h] + 1) / (p.n + 24)
        dist_home = haversine(home[0], home[1], t["lat"], t["lon"]) if home else 0.0
        speed = 0.0
        if p.last and t["ts"] > p.last["ts"]:
            km = haversine(p.last["lat"], p.last["lon"], t["lat"], t["lon"])
            hrs = max((t["ts"] - p.last["ts"]) / 3600, 1 / 60)
            speed = km / hrs if km > 50 else 0.0
        return {
            "amount_z": z, "hour_prob": hour_p, "hour": h,
            "new_device": int(mature and t["device_id"] not in p.devices),
            "new_city": int(mature and t["city"] not in p.cities),
            "new_payee": int(mature and t["payee"] not in p.payees),
            "new_ip_prefix": int(mature and ip_prefix(t["ip"]) not in p.ip_prefixes),
            "dist_home_km": dist_home, "travel_speed_kmh": speed, "profile_n": p.n,
            "device_changed": int(bool(p.last) and p.last.get("device") != t["device_id"]),
            "last_city": p.last["city"] if p.last else None,
            "typical_amount": math.expm1(p.mu) if p.n else None,
        }

    @staticmethod
    def score(f, amount):
        """0-100 behavioral deviation score with human-readable reasons."""
        s, why = 0.0, []
        if f["amount_z"] > 1.5:
            pts = min(1.0, (f["amount_z"] - 1.5) / 3) * 35
            s += pts
            why.append(f"Amount {f['amount_z']:.1f}σ above customer's normal (typical ₹{f['typical_amount']:,.0f})")
        if f["profile_n"] >= 5 and f["hour_prob"] < 0.03:
            s += 15
            why.append(f"Unusual time of day for this customer ({f['hour']:02d}:00 IST)")
        if f["new_device"]:
            s += 20
            why.append("Transaction from a device never seen for this customer")
        if f["new_city"]:
            s += 10
            why.append("Location never seen for this customer")
        if f["dist_home_km"] > 500:
            s += 5
        if f["new_payee"] and amount > 5000:
            s += 10
            why.append("First-time payee with significant amount")
        if f["new_ip_prefix"]:
            s += 5
        return min(100.0, s), why

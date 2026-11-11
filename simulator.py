"""Synthetic bank: customers, their normal behaviour, and injected fraud scenarios.

Stands in for the bank's core banking system (CBS), card switch, UPI switch (NPCI) and the
net-banking security logs. Everything here is fake data generated from a fixed seed.
"""
import heapq
import itertools
import math
import random
import threading
import time
import uuid

from . import db
from .config import HISTORY_DAYS, SIM_CUSTOMERS, SIM_FRAUD_RATE, SIM_TPS
from .security import enc

CITIES = {
    "Mumbai": (19.076, 72.877), "Delhi": (28.704, 77.102), "Bengaluru": (12.972, 77.594),
    "Chennai": (13.083, 80.270), "Kolkata": (22.573, 88.364), "Hyderabad": (17.385, 78.487),
    "Pune": (18.520, 73.857), "Ahmedabad": (23.023, 72.571), "Jaipur": (26.912, 75.787),
    "Lucknow": (26.847, 80.947), "Kochi": (9.931, 76.267), "Bhopal": (23.260, 77.413),
    "Patna": (25.594, 85.138), "Guwahati": (26.144, 91.736), "Chandigarh": (30.733, 76.779),
    "Indore": (22.720, 75.858), "Nagpur": (21.146, 79.088), "Surat": (21.170, 72.831),
    "Visakhapatnam": (17.687, 83.218), "Bhubaneswar": (20.296, 85.825),
}
FIRST = ["Aarav", "Vivaan", "Aditya", "Ananya", "Diya", "Ishaan", "Kavya", "Meera", "Rohan", "Saanvi",
         "Arjun", "Priya", "Rahul", "Sneha", "Vikram", "Neha", "Karthik", "Lakshmi", "Farhan", "Ayesha",
         "Harpreet", "Gurpreet", "Joseph", "Mary", "Suresh", "Divya", "Manoj", "Pooja", "Imran", "Zoya",
         "Rajesh", "Anjali", "Siddharth", "Nisha", "Abhishek", "Fatima", "Deepak", "Swati", "Nikhil", "Riya"]
LAST = ["Sharma", "Verma", "Iyer", "Nair", "Reddy", "Patel", "Shah", "Gupta", "Khan", "Singh", "Das",
        "Bose", "Menon", "Pillai", "Rao", "Joshi", "Kulkarni", "Mehta", "Chatterjee", "Fernandes",
        "Hussain", "Mishra", "Pandey", "Agarwal", "Kapoor", "Banerjee", "Naidu", "Gill", "Thomas", "Ali"]
MERCHANTS = {
    "grocery": ["BigBasket", "DMart", "Reliance Fresh", "More Supermarket", "Local Kirana"],
    "food": ["Swiggy", "Zomato", "Cafe Coffee Day", "Haldiram's", "Chai Point"],
    "fuel": ["IndianOil", "HP Petrol", "Bharat Petroleum"],
    "travel": ["IRCTC", "MakeMyTrip", "Ola", "Uber", "IndiGo"],
    "utility": ["BESCOM", "Tata Power", "Airtel", "Jio Recharge", "BSNL"],
    "shopping": ["Amazon", "Flipkart", "Myntra", "Nykaa", "Ajio"],
    "electronics": ["Croma", "Reliance Digital", "Vijay Sales"],
    "health": ["Apollo Pharmacy", "MedPlus", "1mg"],
}
BANK_HANDLES = ["okaxis", "okhdfcbank", "oksbi", "okicici", "ybl", "paytm", "ibl"]
SEGMENTS = {  # segment: (median amount, sigma, peak hour)
    "student": (350, 0.8, 20), "salaried": (1200, 1.0, 19), "business": (6500, 1.1, 13),
    "senior": (900, 0.9, 11), "homemaker": (800, 0.9, 12),
}

FRAUD_SCENARIOS = ["ACCOUNT_TAKEOVER", "MULE_RING", "CARD_TESTING", "IMPOSSIBLE_TRAVEL", "SIM_SWAP"]


def haversine(lat1, lon1, lat2, lon2):
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


class Bank:
    """Deterministic synthetic customer base plus fraudster infrastructure."""

    def __init__(self, n=SIM_CUSTOMERS, seed=42):
        self.rng = random.Random(seed)
        rng = self.rng
        self.customers = []
        city_names = list(CITIES)
        for i in range(n):
            fn, ln = rng.choice(FIRST), rng.choice(LAST)
            seg = rng.choices(list(SEGMENTS), weights=[2, 5, 2, 1.5, 1.5])[0]
            city = rng.choice(city_names)
            cid = f"C{10001 + i}"
            vpa = f"{fn.lower()}.{ln.lower()}{rng.randint(1, 99)}@{rng.choice(BANK_HANDLES)}"
            c = {
                "id": cid, "name": f"{fn} {ln}", "segment": seg, "city": city,
                "phone": f"+91{rng.choice('6789')}{rng.randint(100000000, 999999999)}",
                "email": f"{fn.lower()}.{ln.lower()}{rng.randint(1, 999)}@example.in",
                "account_no": f"{rng.randint(10**11, 10**12 - 1)}",
                "vpa": vpa, "card_last4": f"{rng.randint(0, 9999):04d}",
                "devices": [f"DEV-{uuid.UUID(int=rng.getrandbits(128)).hex[:10].upper()}"
                            for _ in range(rng.choice([1, 1, 2]))],
                "ip_prefix": f"{rng.choice([49, 103, 106, 117, 122, 157, 182, 223])}.{rng.randint(1, 254)}."
                             f"{rng.randint(1, 254)}",
                "channels": rng.choice([(0.7, 0.2, 0.1), (0.5, 0.35, 0.15), (0.4, 0.3, 0.3), (0.8, 0.1, 0.1)]),
                "activity": rng.uniform(0.4, 2.0),
            }
            med, sig, peak = SEGMENTS[seg]
            c["amt_mu"] = math.log(med * rng.uniform(0.6, 1.6))
            c["amt_sigma"] = sig
            c["peak"] = (peak + rng.randint(-2, 2)) % 24
            self.customers.append(c)
        for c in self.customers:  # friends' VPAs and favourite merchants
            friends = rng.sample(self.customers, 4)
            c["payees"] = [("P2P", f["vpa"], "p2p") for f in friends if f is not c]
            for _ in range(6):
                cat = rng.choice(list(MERCHANTS))
                c["payees"].append(("MERCHANT", rng.choice(MERCHANTS[cat]), cat))
        self.by_id = {c["id"]: c for c in self.customers}
        self.mule_vpas = [f"{rng.choice(['quickcash', 'refund.help', 'kyc.update', 'lucky.win', 'pmrelief', 'support.desk'])}"
                          f"{rng.randint(10, 999)}@{rng.choice(BANK_HANDLES)}" for _ in range(12)]
        self.fraud_devices = [f"DEV-FX{rng.randint(10**7, 10**8 - 1)}" for _ in range(6)]
        self.fraud_ips = [f"{rng.choice([45, 91, 185, 194])}.{rng.randint(1, 254)}.{rng.randint(1, 254)}."
                          f"{rng.randint(1, 254)}" for _ in range(8)]
        self.test_merchants = ["GiftCardHub", "DigiVoucher", "AppStoreTopup", "OnlineDonate", "GameCredits"]
        self.weights = [x["activity"] for x in self.customers]
        self.last_live = {}
        self.rng = random.Random()  # customer base is fixed; behaviour from here on is not

    def persist(self):
        if db.scalar("SELECT COUNT(*) FROM customers"):
            return
        rows = []
        for c in self.customers:
            lat, lon = CITIES[c["city"]]
            rows.append((c["id"], c["name"], enc(c["phone"]), enc(c["email"]), c["account_no"], c["vpa"],
                         c["card_last4"], c["city"], lat, lon, c["segment"], "ACTIVE", time.time() - 400 * 86400))
        db.xmany("INSERT INTO customers VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        # seed the watchlist with a few known mule accounts and fraud IPs
        for v in self.mule_vpas[:4]:
            db.x("INSERT OR IGNORE INTO watchlist VALUES (?,?,?,?,?)",
                 (v, "VPA", "Reported mule account (NPCI negative list - simulated)", time.time(), "system"))
        for ip in self.fraud_ips[:2]:
            db.x("INSERT OR IGNORE INTO watchlist VALUES (?,?,?,?,?)",
                 (ip, "IP", "Known malicious IP (threat intel feed - simulated)", time.time(), "system"))

    # ------------------------------------------------------------ event builders
    def _txn(self, c, ts, channel, amount, payee, payee_type, category, device=None, ip=None, city=None, truth=None):
        city = city or c["city"]
        lat, lon = CITIES[city]
        rng = self.rng
        return {
            "kind": "txn", "id": f"T{uuid.uuid4().hex[:14].upper()}", "ts": ts,
            "customer_id": c["id"], "channel": channel, "amount": round(amount, 2), "payee": payee,
            "payee_type": payee_type, "category": category,
            "device_id": device or rng.choice(c["devices"]),
            "ip": ip or f"{c['ip_prefix']}.{rng.randint(2, 250)}", "city": city,
            "lat": lat + rng.uniform(-0.05, 0.05), "lon": lon + rng.uniform(-0.05, 0.05), "truth": truth,
        }

    def _log(self, c, ts, event_type, severity, message, ip=None, device=None, source="NETBANKING"):
        return {"kind": "log", "ts": ts, "source": source, "event_type": event_type, "customer_id": c["id"],
                "ip": ip or "", "device_id": device or "", "severity": severity, "message": message}

    def pick_live_customer(self, cooldown=600):
        """Real customers rarely transact more than every few minutes; respect that so the live feed
        doesn't manufacture bursts that look like fraud."""
        now = time.time()
        for _ in range(20):
            c = self.rng.choices(self.customers, weights=self.weights)[0]
            if now - self.last_live.get(c["id"], 0) >= cooldown:
                break
        self.last_live[c["id"]] = now
        return c

    def normal_txn(self, ts=None, c=None):
        rng = self.rng
        c = c or self.pick_live_customer()
        ts = ts or time.time()
        channel = rng.choices(["UPI", "CARD", "MOBILE"], weights=c["channels"])[0]
        payee_type, payee, cat = rng.choice(c["payees"]) if rng.random() < 0.9 else \
            ("MERCHANT", rng.choice(sum(MERCHANTS.values(), [])), rng.choice(list(MERCHANTS)))
        if channel == "MOBILE" and rng.random() < 0.5:
            payee_type, payee, cat = "BENEFICIARY", f"A/C XX{rng.randint(1000, 9999)}", "transfer"
        amount = max(10.0, rng.lognormvariate(c["amt_mu"], c["amt_sigma"]))
        if cat in ("food", "utility"):
            amount *= 0.5
        if rng.random() < 0.02:  # legit occasional big purchase / rent
            amount *= rng.uniform(4, 10)
        city = c["city"]
        if rng.random() < 0.03:  # legit travel
            city = rng.choice(list(CITIES))
        return self._txn(c, ts, channel, amount, payee, payee_type, cat, city=city)

    def fraud_scenario(self, start=None, kind=None, victims=None):
        """Returns a list of (offset_seconds, event) for a fraud scenario."""
        rng = self.rng
        kind = kind or rng.choice(FRAUD_SCENARIOS)
        t0 = start or time.time()
        ev = []
        c = rng.choice(self.customers)
        fdev, fip = rng.choice(self.fraud_devices), rng.choice(self.fraud_ips)
        other_city = rng.choice([x for x in CITIES if x != c["city"]])
        mule = rng.choice(self.mule_vpas)
        if kind == "ACCOUNT_TAKEOVER":
            for i in range(rng.randint(3, 6)):
                ev.append((i * 4, self._log(c, 0, "LOGIN_FAILED", "MEDIUM", "Invalid password", fip, fdev)))
            ev.append((30, self._log(c, 0, "PASSWORD_RESET", "HIGH", "Password reset via OTP", fip, fdev)))
            ev.append((40, self._log(c, 0, "NEW_DEVICE_LOGIN", "HIGH", "Login from unregistered device", fip, fdev)))
            for i in range(rng.randint(2, 4)):
                ev.append((50 + i * rng.randint(15, 35), self._txn(c, 0, "UPI", rng.uniform(15000, 60000), mule,
                                                                  "P2P", "p2p", fdev, fip, other_city, kind)))
        elif kind == "MULE_RING":
            group = victims or rng.sample(self.customers, rng.randint(4, 6))
            for i, v in enumerate(group):
                ev.append((i * rng.randint(20, 70), self._txn(v, 0, "UPI", rng.uniform(8000, 30000), mule, "P2P",
                                                             "p2p", truth=kind)))
        elif kind == "CARD_TESTING":
            for i in range(rng.randint(3, 6)):
                ev.append((i * rng.randint(8, 20), self._txn(c, 0, "CARD", rng.uniform(1, 99),
                                                            rng.choice(self.test_merchants), "MERCHANT", "digital",
                                                            fdev, fip, other_city, kind)))
            ev.append((150, self._txn(c, 0, "CARD", rng.uniform(20000, 80000), rng.choice(MERCHANTS["electronics"]),
                                      "MERCHANT", "electronics", fdev, fip, other_city, kind)))
        elif kind == "IMPOSSIBLE_TRAVEL":
            far = max(CITIES, key=lambda x: haversine(*CITIES[c["city"]], *CITIES[x]) * rng.uniform(0.7, 1))
            ev.append((0, self._txn(c, 0, "CARD", rng.uniform(500, 3000), rng.choice(MERCHANTS["food"]), "MERCHANT",
                                    "food")))
            ev.append((rng.randint(240, 600), self._txn(c, 0, "CARD", rng.uniform(12000, 45000),
                                                       rng.choice(MERCHANTS["electronics"]), "MERCHANT", "electronics",
                                                       fdev, fip, far, kind)))
        elif kind == "SIM_SWAP":
            ev.append((0, self._log(c, 0, "SIM_CHANGE", "HIGH", "Telco reported SIM re-issue for registered mobile",
                                    source="TELCO")))
            ev.append((20, self._log(c, 0, "NEW_DEVICE_LOGIN", "HIGH", "Mobile banking re-registration", fip, fdev)))
            ev.append((45, self._txn(c, 0, "MOBILE", rng.uniform(40000, 150000), f"A/C XX{rng.randint(1000, 9999)}",
                                     "BENEFICIARY", "transfer", fdev, fip, other_city, kind)))
            ev.append((70, self._txn(c, 0, "MOBILE", rng.uniform(25000, 90000), f"A/C XX{rng.randint(1000, 9999)}",
                                     "BENEFICIARY", "transfer", fdev, fip, other_city, kind)))
        out = []
        for off, e in ev:
            e = dict(e)
            e["ts"] = t0 + off
            out.append((off, e))
        return kind, out

    # ------------------------------------------------------------ history
    def history(self, days=HISTORY_DAYS):
        """Generate past transactions (for profiles + model training). Fraud in history is pre-labelled
        as confirmed (chargebacks / customer complaints already processed)."""
        rng = self.rng
        now = time.time()
        start = now - days * 86400
        events = []
        for c in self.customers:
            n = int(days * c["activity"] * rng.uniform(1.0, 2.2))
            for _ in range(n):
                day = start + rng.randint(0, days - 1) * 86400
                hour = int(rng.gauss(c["peak"], 3)) % 24
                ts = day - (day % 86400) + hour * 3600 + rng.randint(0, 3599) - 19800  # IST offset
                if ts < now - 3600:
                    events.append(self.normal_txn(ts, c))
        for _ in range(int(days * 3)):
            t = start + rng.uniform(0, days * 86400 - 7200)
            if rng.random() < 0.5:  # most historic fraud happened at night
                t = t - (t % 86400) - 19800 + rng.randint(0, 4) * 3600 + 86400
            _, evs = self.fraud_scenario(t)
            events += [e for _, e in evs if e["ts"] < now - 3600]
        events.sort(key=lambda e: e["ts"])
        return events


class LiveFeed(threading.Thread):
    """Emits a continuous stream of transactions and security logs to the detection engine."""

    def __init__(self, bank, handler):
        super().__init__(daemon=True, name="kavach-feed")
        self.bank, self.handler = bank, handler
        self.tps = SIM_TPS
        self.fraud_rate = SIM_FRAUD_RATE
        self.running = True
        self.pending = []  # heap of (due, seq, event)
        self.seq = itertools.count()
        self.emitted = 0
        self.scenarios = 0
        self.last_scenario = None

    def inject(self, kind=None):
        kind, evs = self.bank.fraud_scenario(time.time() + 1, kind)
        for off, e in evs:
            heapq.heappush(self.pending, (e["ts"], next(self.seq), e))
        self.scenarios += 1
        self.last_scenario = {"kind": kind, "at": time.time(), "events": len(evs)}
        return self.last_scenario

    def run(self):
        while True:
            try:
                if self.running:
                    now = time.time()
                    while self.pending and self.pending[0][0] <= now:
                        _, _, e = heapq.heappop(self.pending)
                        e["ts"] = now
                        self.handler(e, "SIM_LIVE")
                        self.emitted += 1
                    self.handler(self.bank.normal_txn(), "SIM_LIVE")
                    self.emitted += 1
                    # fraud_rate is per-transaction; a scenario produces ~3-5 events
                    if self.bank.rng.random() < self.fraud_rate / 3:
                        self.inject()
                time.sleep(max(0.05, random.expovariate(self.tps)))
            except Exception as exc:  # keep the feed alive
                print("feed error:", exc)
                time.sleep(1)

    def status(self):
        return {"running": self.running, "tps": self.tps, "fraud_rate": self.fraud_rate,
                "emitted": self.emitted, "scenarios_injected": self.scenarios,
                "queued_events": len(self.pending), "last_scenario": self.last_scenario}

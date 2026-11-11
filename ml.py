"""ML engine: unsupervised anomaly detection (Isolation Forest) blended with a supervised model that
learns from analyst feedback, plus the retraining pipeline that versions every model."""
import json
import math
import threading

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.metrics import precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

from . import db
from .config import MODEL_DIR

FEATURE_NAMES = ["log_amount", "amount_z", "hour_sin", "hour_cos", "hour_rarity", "new_device", "new_city",
                 "new_payee", "new_ip_prefix", "log_dist_home", "log_travel_speed", "count_10m",
                 "log_sum_10m", "payee_fan_in", "siem_events_1h", "ch_upi", "ch_card", "ch_mobile"]


def vectorize(t, f, ctx):
    recent10 = [r for r in ctx["recent"] if t["ts"] - r["ts"] <= 600]
    h = f["hour"]
    return [
        math.log1p(t["amount"]), max(-5.0, min(10.0, f["amount_z"])),
        math.sin(2 * math.pi * h / 24), math.cos(2 * math.pi * h / 24), -math.log(f["hour_prob"]),
        f["new_device"], f["new_city"], f["new_payee"], f["new_ip_prefix"],
        math.log1p(f["dist_home_km"]), math.log1p(f["travel_speed_kmh"]), len(recent10),
        math.log1p(sum(r["amount"] for r in recent10)), len(ctx["payee_senders"]), len(ctx["logs"]),
        int(t["channel"] == "UPI"), int(t["channel"] == "CARD"), int(t["channel"] == "MOBILE"),
    ]


class Model:
    def __init__(self):
        self.iforest = None
        self.ref_scores = None   # sorted anomaly scores from training data for percentile calibration
        self.clf = None
        self.version = None
        self.lock = threading.Lock()

    @property
    def ready(self):
        return self.iforest is not None

    def score(self, vec):
        """Returns (ml_score 0-100, details)."""
        if not self.ready:
            return 0.0, {}
        X = np.array([vec])
        with self.lock:
            s = -self.iforest.score_samples(X)[0]           # higher = more anomalous
            pct = np.searchsorted(self.ref_scores, s) / len(self.ref_scores)
            unsup = float(np.clip((pct - 0.80) / 0.20, 0, 1) * 100)
            sup = float(self.clf.predict_proba(X)[0, 1] * 100) if self.clf is not None else None
        score = unsup if sup is None else 0.4 * unsup + 0.6 * sup
        return score, {"anomaly_pct": round(pct * 100, 1), "anomaly_score": round(unsup, 1),
                       "fraud_probability": None if sup is None else round(sup, 1)}

    # ------------------------------------------------------------ training pipeline
    def train(self, trigger="manual"):
        rows = db.q("""SELECT features, label FROM transactions WHERE features IS NOT NULL
                       ORDER BY ts DESC LIMIT 60000""")
        if len(rows) < 200:
            return {"ok": False, "error": "not enough data"}
        X = np.array([json.loads(r["features"]) for r in rows], dtype=float)
        labels = [r["label"] for r in rows]
        y_mask = np.array([l in ("FRAUD", "LEGIT") for l in labels])
        y = np.array([1 if l == "FRAUD" else 0 for l in labels])
        legit_or_unknown = np.array([l != "FRAUD" for l in labels])

        # unsupervised model learns "normal" from everything not confirmed fraud
        iforest = IsolationForest(n_estimators=200, contamination="auto", random_state=7, n_jobs=-1)
        iforest.fit(X[legit_or_unknown])
        ref = np.sort(-iforest.score_samples(X[legit_or_unknown]))

        metrics = {"samples": int(len(X)), "labeled": int(y_mask.sum()), "fraud_labels": int(y[y_mask].sum())}
        clf = None
        Xl, yl = X[y_mask], y[y_mask]
        if yl.sum() >= 15 and (len(yl) - yl.sum()) >= 50:
            Xtr, Xte, ytr, yte = train_test_split(Xl, yl, test_size=0.25, stratify=yl, random_state=7)
            w = np.where(ytr == 1, (len(ytr) - ytr.sum()) / max(ytr.sum(), 1), 1.0)
            clf = HistGradientBoostingClassifier(max_iter=200, learning_rate=0.08, random_state=7)
            clf.fit(Xtr, ytr, sample_weight=w)
            p = clf.predict_proba(Xte)[:, 1]
            metrics.update({
                "holdout_auc": round(float(roc_auc_score(yte, p)), 4),
                "holdout_precision@0.5": round(float(precision_score(yte, p >= 0.5, zero_division=0)), 4),
                "holdout_recall@0.5": round(float(recall_score(yte, p >= 0.5, zero_division=0)), 4),
            })
            clf.fit(Xl, yl, sample_weight=np.where(yl == 1, (len(yl) - yl.sum()) / max(yl.sum(), 1), 1.0))
        # how well the unsupervised score alone separates labelled fraud
        if y_mask.sum() and 0 < yl.sum() < len(yl):
            metrics["iforest_auc"] = round(float(roc_auc_score(yl, -iforest.score_samples(Xl))), 4)

        n = (db.scalar("SELECT COUNT(*) FROM model_versions") or 0) + 1
        version = f"v{n}"
        joblib.dump({"iforest": iforest, "ref": ref, "clf": clf, "features": FEATURE_NAMES},
                    MODEL_DIR / f"kavach_{version}.joblib")
        with self.lock:
            self.iforest, self.ref_scores, self.clf, self.version = iforest, ref, clf, version
        db.x("UPDATE model_versions SET active=0")
        db.insert("model_versions", {"version": version, "trained_at": db.now(), "n_samples": len(X),
                                     "n_labeled": int(y_mask.sum()),
                                     "kind": "IsolationForest + GradientBoosting" if clf else "IsolationForest",
                                     "metrics": json.dumps(metrics), "active": 1, "trigger": trigger})
        return {"ok": True, "version": version, "metrics": metrics}

    def load_active(self):
        row = db.q1("SELECT version FROM model_versions WHERE active=1")
        if not row:
            return False
        path = MODEL_DIR / f"kavach_{row['version']}.joblib"
        if not path.exists():
            return False
        m = joblib.load(path)
        with self.lock:
            self.iforest, self.ref_scores, self.clf, self.version = m["iforest"], m["ref"], m["clf"], row["version"]
        return True

    def activate(self, version):
        path = MODEL_DIR / f"kavach_{version}.joblib"
        if not path.exists():
            return False
        db.x("UPDATE model_versions SET active=0")
        db.x("UPDATE model_versions SET active=1 WHERE version=?", (version,))
        return self.load_active()


model = Model()

"""KAVACH runtime configuration. Everything can be overridden with environment variables."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("KAVACH_DATA_DIR", BASE_DIR.parent / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "kavach.db"
KEY_PATH = DATA_DIR / "kavach.key"          # Fernet key for PII encryption at rest
MODEL_DIR = DATA_DIR / "models"
MODEL_DIR.mkdir(exist_ok=True)

# Simulator
SIM_ENABLED = os.environ.get("KAVACH_SIM", "1") == "1"
SIM_TPS = float(os.environ.get("KAVACH_SIM_TPS", "1.2"))          # transactions per second
SIM_FRAUD_RATE = float(os.environ.get("KAVACH_SIM_FRAUD_RATE", "0.04"))
SIM_CUSTOMERS = int(os.environ.get("KAVACH_SIM_CUSTOMERS", "1500"))
HISTORY_DAYS = int(os.environ.get("KAVACH_HISTORY_DAYS", "14"))

# Scoring thresholds (0-100 risk score)
ALERT_THRESHOLD = 35
MEDIUM_THRESHOLD = 55
HIGH_THRESHOLD = 75
AUTO_HOLD_THRESHOLD = 80     # hold transaction + step-up notification
AUTO_BLOCK_THRESHOLD = 92    # block account + notify + trigger fraud team

# Blend weights for the final risk score
W_RULES, W_ML, W_PROFILE = 0.45, 0.30, 0.25

SESSION_HOURS = 10
CASE_SLA_HOURS = {"HIGH": 4, "MEDIUM": 24, "LOW": 72}
AUTO_RETRAIN_MINUTES = int(os.environ.get("KAVACH_RETRAIN_MINUTES", "60"))

# API key that bank core systems use for the ingestion API (rotate in Admin)
DEFAULT_INGEST_API_KEY = os.environ.get("KAVACH_INGEST_KEY", "kavach-demo-ingest-key")
DEMO_PASSWORD = "Kavach@123"

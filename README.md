# KAVACH — AI-SOC Fraud Detection Platform

KAVACH (कवच, "armour") is a working prototype of a Security Operations Centre platform that detects fraud in
**UPI, card and mobile-banking** transactions in real time, raises prioritised alerts, and gives SOC analysts the
tools to investigate, respond, and report to auditors and the regulator.

It runs on one machine with no external services: a built-in simulator stands in for the bank's core systems and
NPCI, and outbound SMS / email / NPCI / fraud-desk messages are mocked into an outbox you can inspect.

---

## Quick start

Requirements: Python 3.10+.

```bash
cd kavach
./run.sh                # macOS / Linux   (Windows: run.bat)
# or manually:
pip install -r requirements.txt
python -m uvicorn app.main:app --port 8000
```

Open **http://localhost:8000**. The first start takes 30–60 seconds while KAVACH generates 14 days of history for
1,500 synthetic customers, learns their behaviour and trains the first model. Later starts are a few seconds.

### Demo accounts

| User | Role | Password | Notes |
|---|---|---|---|
| `admin` | Admin | `Kavach@123` | MFA is on. Get the current code with `python -m app.totp admin`, or add the secret printed in `data/DEMO_CREDENTIALS.txt` to an authenticator app |
| `manager` | Manager | `Kavach@123` | Best account for a demo |
| `analyst1`, `analyst2` | Analyst | `Kavach@123` | |
| `auditor` | Read-only | `Kavach@123` | Reports, audit trail, exports |

Change these before showing the system to anyone outside the team.

### A 5-minute demo

1. Sign in as `manager`. The **Overview** shows the live feed being scored (about 1 transaction/second).
2. In **Attack simulator**, click *account takeover*, *mule ring* and *card testing*. Over the next 1–3 minutes,
   alerts pop up, high-risk payments are put on hold, the customer gets an SMS (see **Response log → Outbound
   notifications**), and very high-risk accounts are auto-blocked with the bank's fraud team notified.
3. Open **Alerts**, click a row to see exactly *why* it was flagged (rules hit, behaviour deviations, ML score).
4. Click **Case** on an alert → assign, add notes, escalate, block the account, report the mule VPA to NPCI, then
   close as *Confirmed fraud* and **Draft FMR report**.
5. **Investigate** the customer: timeline, devices & IPs shared with other customers, geo map, link graph.
6. **Fraud networks** shows rings of customers tied together by a shared mule account, device or IP.
7. Mark a few alerts as *False positive*, then **Rules & model → Retrain now**. The new version learns from that
   feedback.
8. **Reports & compliance** → daily / weekly report, KPI tiles, compliance checks, **Export auditor pack** (zip).
9. **Audit trail → Verify integrity** proves no log entry was altered.

---

## What's included (mapped to the charter)

| # | Area | What KAVACH does | Where |
|---|---|---|---|
| 1 | **Data ingestion** | Real-time feed of UPI / card / mobile-banking transactions; REST ingestion API for core banking (CBS) and switches; historical import (JSON or CSV); SIEM-style security log aggregation (failed logins, password resets, new-device logins, SIM swaps) | `app/simulator.py`, `/api/v1/*`, Admin → Security logs |
| 2 | **AI / ML engine** | Rule engine (11 configurable hard rules incl. **>₹50k in 2 min**); **behavioural profiling** per customer (amount distribution, active hours, devices, cities, payees, IP ranges); **Isolation Forest** anomaly detection blended with a **gradient-boosted classifier** trained on confirmed outcomes; every transaction gets a 0–100 risk score in ~10–20 ms; **retraining pipeline** (scheduled hourly + on demand) with versioning, holdout metrics and rollback | `app/rules.py`, `app/profiles.py`, `app/ml.py`, `app/engine.py`, Rules & model |
| 3 | **Alert & case management** | SOC dashboard; High / Medium / Low prioritisation; case creation and assignment; **escalation workflow** (analyst → manager → bank fraud team, automatic on SLA breach); **false-positive feedback loop** (dispositions label transactions for retraining) | Overview, Alerts, Cases |
| 4 | **Investigation tools** | Transaction timeline (transactions + security logs + actions); account history and behavioural profile; **device & IP fingerprinting** with "shared with other customers"; **geo-location** map with impossible-travel detection; **link analysis** graph and automatic **fraud-ring detection** | Investigate, Fraud networks |
| 5 | **Response & action** | Auto-hold (score ≥ 80) and auto-block (score ≥ 92); manual block / release of transactions and accounts; customer SMS + email; trigger bank fraud team; report VPA to NPCI; watchlist; **audit trail of every action** | Response log, case & customer pages |
| 6 | **Reporting & compliance** | Daily / weekly fraud reports (screen, print, CSV); KPI dashboard (detection rate, prevention rate, alert precision, false-positive rate, mean time to respond, case resolution time, loss prevented); compliance checks modelled on RBI norms; FMR (fraud monitoring return) draft per confirmed case; **auditor export** zip with SHA-256 manifest | Reports & compliance |
| 7 | **Security & access control** | Roles Admin / Manager / Analyst / Read-only enforced on every API call; **TOTP multi-factor authentication**; login lock-out after 5 failures; every action, login and PII reveal logged in a **hash-chained, tamper-evident audit log**; customer phone / email **encrypted at rest** (Fernet / AES-128-CBC + HMAC) and masked in the UI; **HTTPS** via `./run.sh --tls`; security headers | `app/security.py`, Audit trail, Administration |
| 8 | **Integration layer** | REST APIs with API-key auth (key rotation in Admin); **HMAC-signed webhooks** for real-time alerts; NPCI integration points (report VPA, status callback) mocked; interactive API docs at `/docs` | `app/main.py`, Administration → Integrations |

**Out of scope (per charter):** credit scoring, bank IT overhaul, customer-facing app, non-financial fraud.

---

## How a transaction is scored

```
transaction ──► context (last hour of this customer, payee fan-in, security logs, watchlist)
            ├─► Rule engine            → rule score     (strongest rule + 15% of the others)
            ├─► Behavioural profile    → profile score  (deviation from this customer's normal)
            └─► ML (18 features)       → ML score       (40% Isolation Forest percentile + 60% classifier)
risk = 45% rules + 30% ML + 25% behaviour, and a critical rule (≥80) is never diluted below 90% of itself
High ≥ 75 · Medium ≥ 55 · Low ≥ 35  →  alert;  ≥ 80 → hold + SMS;  ≥ 92 → block account + fraud team
```

Weights and thresholds live in `app/config.py`; rule thresholds are editable live by an admin.

Simulated fraud patterns: account takeover (failed logins → reset → new device → large UPI transfers to a mule),
mule ring (several victims paying the same VPA), card testing (micro-transactions then a big purchase), impossible
travel, and SIM swap (SIM re-issue → night-time transfers to new beneficiaries).

On a fresh run with all patterns injected, the prototype typically catches 90%+ of fraudulent transactions while
flagging about 2–4% of genuine ones. These figures come from synthetic data and say nothing about performance on
real bank data; the model has to be trained and validated on the bank's own history.

---

## Integration API (for the bank's systems)

All `/api/v1/*` calls need the header `X-API-Key` (default `kavach-demo-ingest-key`; rotate it in Administration).

```bash
# Score a transaction in real time (returns APPROVED / HELD / BLOCKED + reasons)
curl -X POST http://localhost:8000/api/v1/transactions -H "X-API-Key: kavach-demo-ingest-key" \
  -H "Content-Type: application/json" \
  -d '{"customer_id":"C10001","channel":"UPI","amount":49000,"payee":"quickcash77@ybl","payee_type":"P2P","device_id":"DEV-NEW1","city":"Delhi"}'

# Historical import (CSV columns: customer_id,channel,amount,payee,ts[,is_fraud,...])
curl -X POST http://localhost:8000/api/v1/import/csv -H "X-API-Key: kavach-demo-ingest-key" -F file=@history.csv

# Security / SIEM events
curl -X POST http://localhost:8000/api/v1/logs -H "X-API-Key: kavach-demo-ingest-key" \
  -H "Content-Type: application/json" -d '[{"customer_id":"C10002","event_type":"LOGIN_FAILED","severity":"MEDIUM","ip":"1.2.3.4"}]'
```

Webhooks: add a URL in **Administration → Integrations**. Each POST carries `X-Kavach-Event` and
`X-Kavach-Signature: sha256=<HMAC of body with the webhook secret>`. A built-in test receiver
(`/api/webhook-sink`) lets you see deliveries without another server.

Full API reference: **http://localhost:8000/docs**.

---

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `KAVACH_DATA_DIR` | `./data` | Database, encryption key, models, demo credentials |
| `KAVACH_SIM` | `1` | `0` disables the simulated feed (use the API instead) |
| `KAVACH_SIM_TPS` | `1.2` | Simulated transactions per second |
| `KAVACH_SIM_FRAUD_RATE` | `0.04` | Share of traffic that is fraud |
| `KAVACH_SIM_CUSTOMERS` | `1500` | Synthetic customers (only on first start) |
| `KAVACH_HISTORY_DAYS` | `14` | Days of history generated on first start |
| `KAVACH_RETRAIN_MINUTES` | `60` | Scheduled retraining interval |
| `KAVACH_ENC_KEY` | file `data/kavach.key` | Fernet key for PII encryption (use a KMS/HSM in production) |
| `KAVACH_INGEST_KEY` | `kavach-demo-ingest-key` | Initial integration API key |

To start over, stop the server and delete the `data/` folder.

## Project layout

```
kavach/
├── app/
│   ├── main.py        FastAPI app: auth, RBAC, alerts, cases, investigation, response, reports, admin, /api/v1
│   ├── engine.py      real-time scoring pipeline, alerting, automated response
│   ├── rules.py       rule engine (11 rules, editable at runtime)
│   ├── profiles.py    behavioural profiling
│   ├── ml.py          Isolation Forest + gradient boosting, retraining & versioning
│   ├── response.py    block / notify / fraud team / NPCI / webhooks / live event stream
│   ├── reports.py     KPIs, fraud reports, compliance checks, FMR draft, auditor export
│   ├── security.py    passwords, sessions, TOTP MFA, roles, PII encryption, hash-chained audit log
│   ├── simulator.py   synthetic customers, normal behaviour and fraud scenarios
│   ├── db.py, config.py, totp.py, tls.py
│   └── static/        SOC dashboard (vanilla JS, no build step, no external CDN)
├── requirements.txt, run.sh, run.bat
└── data/              created at first start
```

## Going from prototype to production

This prototype shows the full workflow end to end. A bank deployment would also need:

- **Real connectors** to CBS, card switch and the UPI switch (typically Kafka / MQ streams) and NPCI's actual
  fraud-reporting interfaces, replacing the simulator and mocks.
- **Scale-out storage and streaming** (PostgreSQL / a feature store, Kafka, a model-serving tier); SQLite and a
  single process are fine for a demo, not for millions of transactions a day.
- **SSO** with the bank's identity provider, keys in an HSM / KMS, TLS certificates from the bank's CA, and a
  formal security review / VAPT.
- **Model governance:** validation on the bank's labelled history, bias and drift monitoring, and sign-off of
  thresholds by the fraud risk committee.
- **Compliance sign-off:** the compliance checks and FMR layout here are modelled on RBI guidance and must be mapped
  to the bank's actual reporting formats and validated by its compliance team.

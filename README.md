# SENTINEL // AI — Intelligent Cybersecurity Threat Detection & Monitoring System

![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)
![React](https://img.shields.io/badge/React-18-61DAFB.svg)
![TailwindCSS](https://img.shields.io/badge/TailwindCSS-3.4-38B2AC.svg)
![Framer_Motion](https://img.shields.io/badge/Framer_Motion-11.11-FF0055.svg)
![Scikit--Learn](https://img.shields.io/badge/Scikit--Learn-1.3%2B-F7931E.svg)
![SQLite](https://img.shields.io/badge/SQLite-WAL--Mode-003B57.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Tests](https://img.shields.io/badge/Tests-39%20Passing-brightgreen.svg)

**Sentinel AI** is an enterprise-grade Security Operations Center (SOC) threat detection, analytics, and live telemetry monitoring platform. It pairs a high-performance **Python FastAPI REST & WebSocket backend** with a cinematic, motion-rich **React 18 / Tailwind / Framer Motion command center**.

The platform ingests heterogeneous network datasets, dynamically infers and confirms schema mappings, executes five modular explainable threat detectors alongside dual Scikit-Learn machine-learning ensembles, persists incident state to SQLite, and provides real-time time-series dataset replay and live telemetry monitoring.

---

## ⚡ Quick 24/7 Cloud Deployment (Render.com)

To deploy Sentinel AI to Render with a permanent 24/7 HTTPS URL that never resets:

1. **Push to GitHub:**
   ```bash
   git remote add origin https://github.com/<YOUR-USERNAME>/sentinel-ai.git
   git branch -M main
   git push -u origin main
   ```
2. **Deploy on Render:**
   - Go to [dashboard.render.com](https://dashboard.render.com) and click **New + > Web Service**.
   - Connect your `sentinel-ai` repository.
   - **Environment:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `python3 -m uvicorn backend.app.main:app --host 0.0.0.0 --port $PORT`
   - **Instance Type:** `Free`
   - Click **Create Web Service**. Your permanent link will be generated at `https://sentinel-ai-xxxx.onrender.com`.

---

## 1. Key System Capabilities

- **Flexible Dataset Ingestion & Profiling:** Drag-and-drop CSV ingestion with automatic encoding fallbacks (`utf-8`, `latin-1`), memory-bounded parsing, data quality profiling, and automated semantic column mapping (e.g., `client_ip` &rarr; `src_ip`, `dport` &rarr; `dst_port`, `tot_pkts` &rarr; `packet_count`).
- **Dataset Compatibility Assessment:** 
  - *Cybersecurity-Compatible:* Full 5-module detection and ML pipeline.
  - *Partially Compatible:* Executes only supported detectors with transparent missing-field explanations.
  - *General Tabular Dataset:* Profiles data and executes unsupervised Isolation Forest anomaly scoring without mislabeling statistical outliers as confirmed cyberattacks.
- **5 Modular Threat Detectors:**
  1. **Brute-Force Login:** Repeated failed authentications grouped by identity and source host.
  2. **Port Scanning:** Distinct destination port sweeps (&ge; 10 ports) and subnet recon.
  3. **Abnormally High Traffic:** Volumetric packet/byte rate baselines with Z-score outlier detection (&gt; 3.0&sigma;).
  4. **Suspicious User Behaviour:** High-volume asymmetric egress transfers and sensitive endpoint exfiltration.
  5. **Malicious URLs / Indicators:** Shannon entropy calculus (&gt; 4.2 bits/char), suspicious TLDs, and weaponized keyword heuristics.
- **Machine Learning Architecture:**
  - *Supervised:* Random Forest (100 trees, max depth 14) and Logistic Regression with leak-free `StandardScaler` fitted strictly on training data. Evaluates accuracy, precision, recall, F1-score, ROC-AUC, and confusion matrix.
  - *Unsupervised:* Isolation Forest (contamination = 0.05) for unlabelled telemetry.
- **Live Monitoring & Replay Engine:**
  - *Mode A (Authorized Live Telemetry):* Ingestion endpoint (`POST /api/v1/monitoring/telemetry/ingest`) for external logs.
  - *Mode B (Dataset Replay):* Time-series playback with Play, Pause, Resume, Stop, and 0.5x–10x speed multipliers.
  - *Mode C (Synthetic Demo):* Controlled parameter synthesis via Detection Playground.
  - *WebSocket Broadcast Bus:* Real-time event streaming directly to the 360° Threat Radar and live alert feeds without full-page reloads.
- **Persistent SOC Incident Workflow:** SQLite repository (`sentinel_main.db`) tracking alerts, lifecycle states (`Open` &rarr; `Investigating` &rarr; `Resolved` &rarr; `False Positive`), timestamped audit history, analyst notes, and CSV export.

---

## 2. Technology Stack & Repository Architecture

```
sentinel-ai/
├── backend/
│   ├── app/
│   │   ├── main.py                    # FastAPI application root & CORS setup
│   │   ├── api/
│   │   │   └── routes/                # REST API routers
│   │   │       ├── datasets.py        # Upload, list, activate, and delete datasets
│   │   │       ├── analysis.py        # Trigger & track background analysis jobs
│   │   │       ├── events.py          # Paginated forensic events & filtering
│   │   │       ├── alerts.py          # Incident lifecycle, notes, & CSV exports
│   │   │       ├── analytics.py       # Aggregated KPIs, charts, and port distributions
│   │   │       ├── detect.py          # Playground evaluation & threat injection
│   │   │       ├── monitoring.py      # Replay controls & WebSocket live stream
│   │   │       └── system.py          # Subsystem health verification & metrics
│   │   ├── core/
│   │   │   ├── config.py              # Pydantic Settings, thresholds, and limits
│   │   │   └── security.py            # Path-traversal safeguards and filename sanitization
│   │   ├── database/
│   │   │   ├── models.py              # SQLAlchemy ORM models (Datasets, Events, Alerts)
│   │   │   └── session.py             # Engine, SessionLocal, and init_db()
│   │   ├── detectors/                 # Explainable detection rules
│   │   │   ├── brute_force.py
│   │   │   ├── port_scan.py
│   │   │   ├── traffic_anomaly.py
│   │   │   ├── user_behavior.py
│   │   │   └── url_analysis.py
│   │   ├── ingestion/
│   │   │   └── csv_ingestion.py       # Safe CSV reader with encoding fallback
│   │   ├── schemas/                   # Pydantic v2 validation contracts
│   │   └── services/                  # Business logic, ML, and WebSocket hub
│   └── tests/                         # Pytest test suite (18 unit & integration tests)
├── frontend/                          # Cinematic React 18 + Vite + Tailwind + Framer Motion
│   ├── src/
│   │   ├── components/                # Hero Radar, Replay Bar, Upload Modal, Drawer
│   │   ├── pages/                     # 7 Dedicated security operations views
│   │   └── services/api.ts            # Typed API client & WebSocket listener
├── data/
│   ├── uploads/                       # User-uploaded dataset files
│   ├── models/                        # Saved Joblib model artifacts & scalers
│   └── sample/                        # Pre-packaged benchmark security telemetry
└── sentinel_alerts.db / sentinel_main.db
```

---

## 3. Quick Start & Execution

### Prerequisites
- Python 3.10+
- Node.js v18+ & npm

### Starting the Backend (FastAPI on Port 8000)
```bash
cd sentinel-ai
python3 -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```
- Interactive OpenAPI / Swagger Documentation: **[http://localhost:8000/docs](http://localhost:8000/docs)**
- Health Check Endpoint: **[http://localhost:8000/api/v1/system/health](http://localhost:8000/api/v1/system/health)**

### Starting the Frontend (React / Vite on Port 5173)
```bash
cd sentinel-ai/frontend
npm run dev
# or: ./node_modules/.bin/vite --port 5173 --host
```
- Open your browser at **[http://localhost:5173](http://localhost:5173)**

---

## 4. Supported Data Formats & Schemas

The ingestion engine supports standard tabular CSV or text files up to 50 MB. Column headers are automatically inspected and mapped against the following semantic fields:

| Target Field | Accepted Column Synonyms | Detection Purpose |
| :--- | :--- | :--- |
| `timestamp` | `time`, `timestamp`, `datetime`, `flow_start`, `ts` | Temporal sorting, sliding windows, time-series charts |
| `src_ip` | `src_ip`, `source_ip`, `client_ip`, `orig_ip`, `saddr` | Attacker attribution, topology, quarantine actions |
| `dst_ip` | `dst_ip`, `dest_ip`, `target_ip`, `server_ip`, `daddr` | Protected infrastructure, target exposure |
| `src_port` | `src_port`, `source_port`, `sport`, `orig_port` | Flow uniqueness, ephemeral client port tracking |
| `dst_port` | `dst_port`, `dest_port`, `destination_port`, `dport` | Port scan detection, targeted service distribution |
| `protocol` | `protocol`, `proto`, `transport`, `ip_proto` | L4 classification (TCP, UDP, ICMP) |
| `packet_count` | `packets`, `pkts`, `packet_count`, `tot_pkts` | Volumetric flood / DDoS detection |
| `byte_count` | `bytes`, `byte_count`, `tot_bytes`, `bytes_transferred` | Data exfiltration / abnormal egress detection |
| `duration` | `duration`, `dur`, `duration_sec`, `flow_duration` | Persistent beaconing, session dwell time |
| `login_failures` | `failed_logins`, `login_failures`, `failed_attempts` | Brute-force credential stuffing detection |
| `url` | `url`, `uri`, `domain`, `host`, `target_url` | Shannon entropy, suspicious TLDs, phishing indicators |
| `user` | `user`, `username`, `account`, `identity` | Account hijacking, user activity profiling |
| `label` | `label`, `attack`, `threat`, `category`, `class` | Supervised model training & evaluation benchmarks |

*Note:* If column names in your CSV differ, the built-in **Column Mapping Inspector** lets you re-assign or unmap fields prior to starting the detection pipeline.

---

## 5. Live Monitoring Modes Tested

1. **Mode A — Authorized Ingestion:** Verified via `POST /api/v1/monitoring/telemetry/ingest`. Ingested records are evaluated against live detection rules and immediately dispatched over the WebSocket bus.
2. **Mode B — Dataset Replay:** Verified via `POST /api/v1/monitoring/replay/start`. Replays analyzed dataset events chronologically into the 360° Threat Radar and live alert feeds with pause, resume, and variable playback speeds. Replayed events are tagged with `is_replay=True` to prevent database duplication.
3. **Mode C — Synthetic Simulation:** Verified via the Detection Playground. Injects synthetic attack vectors with customizable parameters directly into the live alert pipeline.

---

## 6. Automated Test Suite Results

The project includes 39 automated unit and integration tests covering the complete data pipeline:

```bash
python3 -m pytest backend/tests/ tests/ -v
```

### Verified Test Results (39 / 39 Passing):
- `backend/tests/test_ingestion_and_profiling.py` (5 tests): Safe CSV ingestion, synonym inference, compatibility categorization, and data profiling.
- `backend/tests/test_detectors.py` (5 tests): Brute-Force, Port Scanning, Traffic Floods, Data Exfiltration, and Malicious URL Shannon entropy.
- `backend/tests/test_ml_pipeline.py` (2 tests): Supervised Random Forest train/test evaluation (leak-free) and unsupervised Isolation Forest anomaly detection.
- `backend/tests/test_api_endpoints.py` (6 tests): Dataset upload, analysis jobs, alert patching, CSV audit export, analytics, and replay controls.
- `tests/test_alerts.py`, `tests/test_data_loader.py`, `tests/test_detection_rules.py`, `tests/test_models.py`, `tests/test_predict.py`, `tests/test_visualizations.py` (21 tests): Core detection engine benchmarks.

---

## 7. Connecting a Real Live Telemetry Source

To connect an external production log source (e.g., Zeek, Suricata, Syslog, or AWS VPC Flow Logs):

1. **Format Telemetry as JSON:** Map log fields to the ingestion schema (`timestamp`, `src_ip`, `dst_ip`, `dst_port`, `protocol`, `packets`, `bytes`, `failed_logins`, `url`).
2. **Push to Ingest Endpoint:**
   ```bash
   curl -X POST http://localhost:8000/api/v1/monitoring/telemetry/ingest \
     -H "Content-Type: application/json" \
     -d '{
       "src_ip": "198.51.100.42",
       "dst_ip": "10.0.0.12",
       "dst_port": 22,
       "protocol": "TCP",
       "failed_logins": 15
     }'
   ```
3. **Stream Over WebSocket:** Connect your client to `ws://localhost:8000/api/v1/monitoring/ws` to receive instant threat alerts and telemetry ticks as they occur.

---

## License

This project is licensed under the MIT License.

# CYBERSHIELD AI — Enterprise Cybersecurity Monitoring & SOC Platform

![CYBERSHIELD AI](https://img.shields.io/badge/CYBERSHIELD-Enterprise%20SOC%20v2.0-0284c7?style=for-the-badge&logo=shield)
![Build](https://img.shields.io/badge/Tests-25%2F25%20Passing-10b981?style=for-the-badge)
![FastAPI](https://img.shields.io/badge/Backend-FastAPI%20%7C%20Python%203.14-009688?style=for-the-badge&logo=fastapi)
![React](https://img.shields.io/badge/Frontend-React%2019%20%7C%20Vite%208-61dafb?style=for-the-badge&logo=react)
![Tailwind](https://img.shields.io/badge/CSS-Tailwind%20v4-38bdf8?style=for-the-badge&logo=tailwindcss)

**CYBERSHIELD AI** is a complete, modern enterprise cybersecurity monitoring and Security Operations Center (SOC) platform. It provides **zero-trust authentication & RBAC, corporate employee directory management, 24/7 multi-source telemetry monitoring, AI threat & anomaly detection, data loss prevention (DLP) secret detection with strict masking, URL interstitial warning gateways, automated alerting & deduplication, unified incident correlation, and digital forensics**.

---

## 1. System Architecture

```
                    ┌────────────────────────────────────────────────────────┐
                    │            CYBERSHIELD AI ENTERPRISE UI                │
                    │         React 19 • Vite 8 • Tailwind CSS v4            │
                    │       Recharts • Lucide React • TypeScript             │
                    │  [Super Admin | Security Admin | SOC Analyst | Employee│
                    └───────────────────────────┬────────────────────────────┘
                                                │ REST API (JSON + Bearer JWT)
                                                ▼
                    ┌────────────────────────────────────────────────────────┐
                    │               FASTAPI ENTERPRISE BACKEND               │
                    │          Pydantic v2 • SQLAlchemy 2.0 ORM             │
                    │        Bcrypt Password Hashing • JWT RBAC Auth         │
                    └──────┬────────────┬────────────┬────────────┬──────────┘
                           │            │            │            │
          ┌────────────────┴─┐   ┌──────┴────────┐  ┌┴────────────┴─────┐   ┌────────────────────┐
          │  DETECTION & ML  │   │ SSRF DEFENDER │  │  DATABASE ENGINE  │   │  AUTOMATED ALERTS  │
          │ • Scikit-Learn   │   │ • RFC 1918    │  │ • Supabase PG     │   │ • Deduplication    │
          │   TF-IDF + LogReg│   │ • Loopback    │  │   (if configured) │   │ • SOC Escalation   │
          │ • IsolationForest│   │ • Link-Local  │  │ • SQLite SOC Cache│   │ • Employee Warning │
          │ • Shannon Entropy│   │ • Metadata IP │  │   (auto-fallback) │   │ • Zero Secret Leak │
          │ • DLP Hashing    │   └───────────────┘  └───────────────────┘   └────────────────────┘
          └──────────────────┘
```

---

## 2. Key Enterprise Modules & Capabilities

### 1. Secure Authentication & Role-Based Access Control (RBAC)
- **4 Distinct Roles**: `Super Admin`, `Security Administrator`, `SOC Analyst`, and `Employee`.
- **Security Primitives**: Bcrypt password hashing, JWT bearer tokens, session persistence, automated logout, and password reset workflows.
- **Preconfigured Demo Accounts**:
  | Role | Email | Password | Scope |
  |---|---|---|---|
  | **Super Admin** | `admin@cybershield.corp` | `CyberShield@2026!` | Full platform administration & security governance |
  | **Security Admin** | `secadmin@cybershield.corp` | `CyberShield@2026!` | Employee directory, monitoring policies, DLP rules |
  | **SOC Analyst** | `analyst@cybershield.corp` | `CyberShield@2026!` | Incident triage, correlation, containment & forensics |
  | **Employee** | `alex.turner@enterprise-corp.com` | `CyberShield@2026!` | Personal security feed, link warnings, phishing report |

### 2. Corporate Employee Directory & Monitoring Governance
- Add, edit, activate/deactivate, search, and bulk-import employee records.
- Track **Employee ID**, **Full Name**, **Company Email**, **Phone Number (SMS alerts)**, **Department**, **Role**, and **Monitoring Policy** (`Strict`, `High`, `Standard`, `Low`).
- Enforces duplicate ID and email validation.
- Per-employee security telemetry history and risk profile cards.

### 3. 24/7 Multi-Source Telemetry & Monitoring Engine
- Continuous ingestion across 7 corporate authorized sources:
  1. **Microsoft 365 / Exchange** (Email Security Logs)
  2. **CrowdStrike Falcon** (EDR Endpoint Alerts)
  3. **Cisco Umbrella** (DNS Security Gateway)
  4. **Palo Alto Networks** (Enterprise Perimeter Firewall)
  5. **Zeek / Corelight** (Network Security Monitor)
  6. **Okta** (Identity Provider & Single Sign-On Access Logs)
  7. **AWS CloudTrail** (Cloud Audit & Infrastructure Events)
- Source health status (`ONLINE`, `DEGRADED`, `OFFLINE`), event throughput counters, and live heartbeat timestamps.
- **Simulate 24/7 Telemetry Pulse**: Injects real-time security events through the detection engine with automated incident creation.
- Explicit labeling: *Simulated Telemetry Feed* when external third-party production credentials are not bound.

### 4. Company Secret Detection & Data Loss Prevention (DLP)
- Real-time scanner for leaked credentials: **AWS Access Keys**, **GitHub Personal Access Tokens**, **Stripe Live Secret Keys**, **Database Connection URIs**, and **Private RSA Keys**.
- **Zero-Exposure Masking**: Raw secrets are immediately hashed with SHA-256 for deduplication and masked in the UI (`AKIA************MPLE`, `sk_l************************7890`).
- Remediation lifecycle tracking: `Active`, `Remediated`, `Revoked`, `False Positive`.

### 5. URL Warning & Interstitial Gateway
- Zero-hour link analysis displaying threat type, risk score (0–100), and recommended precautions.
- **Safe Return to Previous Page**: Prominent safe exit action.
- **Security Override Workflow**: Allows authorized personnel to request exceptions with mandatory business justification, logged directly to the backend audit trail.
- Labeled as *Simulated Safe Mode* when external firewall / gateway hardware is not bound.

### 6. SOC Analyst Operations Dashboard
- Live critical incidents, high-risk events, unacknowledged alerts, and security telemetry.
- Incident lifecycle management: `New` ➔ `Investigating` ➔ `Contained` ➔ `Resolved` ➔ `False Positive`.
- Containment execution: `FIREWALL_BLOCK`, `HOST_ISOLATION`, `SESSION_REVOCATION`, `URL_BLOCK`.
- Event acknowledgment workflow and printable forensic dossier export.

### 7. Personalized Employee Security Portal
- Tailored view showing individual security posture, active advisories, and warning history.
- 1-click **Acknowledge Advisory** confirmation.
- **Report Suspicious Email or Link**: Immediate triage submission to SOC analysts.

### 8. Automated Alerting & Notification Engine
- Dispatches severity-calibrated notices to Tier-1 SOC analysts and affected employees.
- Supports **Email** and **SMS** channels with delivery status tracking (`DELIVERED`, `SUPPRESSED_DUPLICATE`).
- Enforces a 15-minute deduplication window to prevent alert fatigue.
- Strictly strips raw passwords and secret values before transmission.

### 9. Unified Threat Correlation & Detection Models
- Multi-sensor event correlation grouping related alerts by shared pivots (IP, Domain, File Hash, User Account).
- Scikit-Learn TF-IDF N-Gram Phishing Classifier.
- Scikit-Learn Isolation Forest Network Anomaly Detector.
- Shannon Byte Entropy calculation (0.000–8.000 bits/byte) for file packing/encryption detection.

---

## 3. Technology Stack

| Layer | Technology | Details |
|---|---|---|
| **Frontend** | React 19, Vite 8, TypeScript | Modern enterprise SOC SPA architecture |
| **Styling** | Tailwind CSS v4 | Professional SOC palette: navy sidebar, sky-blue `#0284c7`, white/light-grey stage |
| **Charts & Icons** | Recharts, Lucide React | Threat distributions, 24h timelines, and telemetry cards |
| **Backend** | Python 3.14, FastAPI, Uvicorn | Validated REST APIs, Pydantic v2 schemas, JWT RBAC |
| **Database** | PostgreSQL / Supabase OR SQLite | SQLAlchemy 2.0 ORM with automatic local cache fallback |
| **Machine Learning**| Scikit-Learn, NumPy | TF-IDF NLP vectorizer, Logistic Regression, Isolation Forest |
| **Testing** | Pytest, HTTPX, TestClient | Complete end-to-end multi-role integration test suite |

---

## 4. Setup & Running Instructions

### Prerequisites
- Python 3.10+ (tested on Python 3.14)
- Node.js 18+ (tested on Node v24)

### 🚀 Quick Start (Joined / One-Command Full Stack)

CYBERSHIELD AI includes unified full-stack orchestration:

```bash
# Option A: One-command Unified Production/Demo Server (Port 8000)
# Serves both the React Frontend UI & FastAPI Backend REST API together:
python3 run.py
# or
./start.sh
# or
npm start
```
- **Unified Web Application & API**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **Interactive Swagger API Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

```bash
# Option B: One-command Dual-Server Development Mode (with Live Reload)
python3 run.py --dev
# or
npm run dev
# or
./start.sh --dev
```
- **Frontend (Vite HMR)**: [http://127.0.0.1:5173/](http://127.0.0.1:5173/) (automatically proxies `/api` calls to port 8000)
- **Backend (Uvicorn)**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)

---

### Manual Multi-Terminal Startup (Optional)

#### 1. Backend Startup
```bash
python3 -m venv backend/venv
source backend/venv/bin/activate
pip install -r backend/requirements.txt
PYTHONPATH=backend uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

#### 2. Frontend Startup
```bash
cd frontend
npm install
npm run dev
```

---

## 5. Automated Test Suite Results

The platform includes an automated pytest suite covering unit, security guard, RBAC, DLP, and end-to-end integration workflows.

```bash
PYTHONPATH=backend ./backend/venv/bin/pytest backend/tests -v
```

### Verified Test Run:
```
============================= test session starts ==============================
collected 25 items

backend/tests/test_api.py::test_system_health_endpoint PASSED            [  4%]
backend/tests/test_api.py::test_dashboard_metrics PASSED                 [  8%]
backend/tests/test_api.py::test_phishing_analysis_endpoint PASSED        [ 12%]
backend/tests/test_api.py::test_incidents_listing PASSED                 [ 16%]
backend/tests/test_api.py::test_incident_status_transition PASSED        [ 20%]
backend/tests/test_api.py::test_incident_report_export PASSED            [ 24%]
backend/tests/test_auth_rbac.py::test_password_hashing PASSED            [ 28%]
backend/tests/test_auth_rbac.py::test_jwt_token_generation_and_decoding PASSED [ 32%]
backend/tests/test_dlp.py::test_aws_key_detection_and_masking PASSED     [ 36%]
backend/tests/test_dlp.py::test_stripe_and_db_uri_detection PASSED       [ 40%]
backend/tests/test_dlp.py::test_clean_text_no_secrets PASSED             [ 44%]
backend/tests/test_e2e_workflow.py::test_complete_enterprise_cybersecurity_workflow PASSED [ 48%]
backend/tests/test_file_analysis.py::test_entropy_calculation PASSED     [ 52%]
backend/tests/test_file_analysis.py::test_powershell_dropper_file_analysis PASSED [ 56%]
backend/tests/test_file_analysis.py::test_known_malware_hash_match PASSED [ 60%]
backend/tests/test_file_analysis.py::test_benign_pdf_analysis PASSED     [ 64%]
backend/tests/test_network.py::test_ssh_brute_force_detection PASSED     [ 68%]
backend/tests/test_network.py::test_port_scan_detection PASSED           [ 72%]
backend/tests/test_network.py::test_benign_traffic_no_alerts PASSED      [ 76%]
backend/tests/test_phishing.py::test_ssrf_guard_blocks_localhost PASSED  [ 80%]
backend/tests/test_phishing.py::test_ssrf_guard_blocks_private_ip PASSED [ 84%]
backend/tests/test_phishing.py::test_ssrf_guard_blocks_cloud_metadata PASSED [ 88%]
backend/tests/test_phishing.py::test_phishing_url_detection PASSED       [ 92%]
backend/tests/test_phishing.py::test_benign_message_analysis PASSED      [ 96%]
backend/tests/test_phishing.py::test_urgent_bec_email_analysis PASSED    [100%]

======================== 25 passed, 1 warning in 2.61s =========================
```

---

## 6. Integrations & Reality Matrix

| Subsystem / Feature | Status | Operational Details |
|---|---|---|
| **JWT & RBAC Authentication** | **FUNCTIONAL (REAL)** | Bcrypt password hashing, signed JWT tokens, role guards. |
| **Employee Directory & Policy Engine** | **FUNCTIONAL (REAL)** | Persistent relational storage, duplicate prevention, and policy assignment. |
| **DLP Secret Detection & Masking** | **FUNCTIONAL (REAL)** | Regex patterns, SHA-256 deduplication hashing, UI redaction. Zero unencrypted storage. |
| **URL Warning Interstitial** | **FUNCTIONAL (REAL)** | Real-time threat classification, safe return, and override audit trail. |
| **Automated Alerts & Deduplication** | **FUNCTIONAL (REAL)** | Multi-recipient delivery engine with 15-min deduplication window. |
| **Unified Correlation Engine** | **FUNCTIONAL (REAL)** | Multi-sensor pivot clustering into suspected incidents. |
| **Machine Learning Classifiers** | **FUNCTIONAL (REAL)** | Scikit-Learn TF-IDF logistic regression and Isolation Forest network model. |
| **Database Storage** | **FUNCTIONAL (REAL)** | Supabase PostgreSQL when credentials configured, SQLite (`cybershield.db`) auto-fallback. |
| **24/7 Monitoring Pipelines** | **CALIBRATED SIMULATION** | Disclosed clearly in UI; generates synthetic enterprise telemetry without fabricating external API connectivity. |
| **Perimeter Firewall Blocking** | **SIMULATED SAFE MODE** | Simulates firewall IP dropping and logs to audit trail to avoid accidental network disruption. |
| **External VirusTotal / PhishTank** | **OPTIONAL / FALLBACK** | If API keys are not in `.env`, falls back cleanly to offline ML & heuristics without fake responses. |

---

## 7. Security and Privacy Commitments
- **SSRF Defense**: Strictly prevents server-side requests to private RFC 1918 IPs, loopbacks, and cloud metadata (`169.254.169.254`).
- **Secret Redaction**: Raw passwords and API secrets are never persisted in cleartext or transmitted to external services.
- **Privacy Assurance**: Telemetry collection is restricted exclusively to authorized enterprise devices and security events. No covert keylogging or personal surveillance is implemented.

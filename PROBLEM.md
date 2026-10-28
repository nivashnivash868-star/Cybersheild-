# CYBERSHIELD AI: Problem Statement, Solution and Reality Check

Source: *Open Agent Hackathon 2026* pitch deck (6 slides), Team **Tech Forge**, Theme: Cyber Security, Category: Software.

The first half of this file records what the deck says. The second half checks each claim against the code at commit `f3d60fb`. Findings of the form `S#` and `F#` refer to [AUDIT.md](AUDIT.md), which has the evidence.

---

## Part 1: What the deck says

### Problem (slides 1 and 6)

Phishing, scams and network attacks need an integrated, AI-powered solution that can **detect, prevent and investigate** threats and **assess risk** through one platform. A typical organisation faces phishing emails, fake websites, suspicious network activity and delayed response. Separate tools make it hard to connect related threats, identify risks and investigate incidents.

| Problem | Proposed solution |
|---|---|
| Phishing links and scams | AI-based URL and message analysis |
| Suspicious network activity | Anomaly detection and threat alerts |
| Delayed threat response | Automated alerts and authorized blocking |
| Complex incident investigation | Correlated evidence and forensic reports |

### Solution (slide 2)

CYBER SHIELD AI is an all-in-one platform that detects phishing, malware and suspicious network activity using AI. It correlates threats, assesses risk, blocks malicious activity through *authorized security controls*, and investigates incidents with evidence-based reports, all in a unified dashboard.

Pipeline: **Data Input → AI Threat Detection → Risk Analysis → Threat Response → Digital Forensics → Unified Security Dashboard.**

Claimed innovation:
1. Unified cybersecurity dashboard
2. AI-powered threat analysis and risk scoring
3. Cross-source threat correlation
4. Integrated detection, prevention and forensics

### Tech stack (slide 3)

| Technology | Purpose |
|---|---|
| React 19 + TypeScript + Vite 8 + Tailwind CSS 4 | UI and visualisation |
| Python + FastAPI | Backend and APIs |
| PostgreSQL / Supabase + SQLite + SQLAlchemy | Database and event management |
| Scikit-learn + NumPy | Threat classification and anomaly detection |
| JWT + Bcrypt | Secure authentication and password hashing |
| Recharts + Lucide React | Dashboard charts and icons |
| Pytest + HTTPX | Automated backend and API testing |

### Feasibility and risks (slide 4)

- Operational feasibility rests on "safe test URLs and simulated network logs" for prototype testing.
- Risks named: false positives (safe links flagged), and new attack patterns that are hard to detect.
- Mitigations named: diverse test datasets, explainable alerts, continuous evaluation, authorized security controls.
- SWOT: Strengths are the unified platform and AI detection. Weaknesses are false positives and dependence on data quality. Opportunities are real-time security integration and wider threat protection. Threats are evolving attacks and unknown threats.

### Impact (slide 5)

- **Users:** phishing warnings, safer browsing, an explanation of why a link is dangerous.
- **IT admins:** one dashboard, incident tracking, reports for investigation.
- **Security teams:** early detection of suspicious network activity, prioritised high-risk threats, less manual monitoring.
- **Organisation:** early detection, prevention by blocking, time saving, unified detection, risk analysis and forensics, better decisions from risk scores and explanations.

### Prior art cited (slide 6)

Google Safe Browsing, Snort, Microsoft Defender XDR, DEPHIDES, AI-IDS.

---

## Part 2: Cross-validation against the code

Verdicts: **Delivered** (works as described), **Partial** (exists but weaker than the deck implies), **Simulated** (the UI or API exists but nothing real sits behind it), **Not built**.

### 2.1 Tech stack (slide 3)

| Deck claim | Verdict | Evidence |
|---|---|---|
| React 19, TypeScript, Vite 8, Tailwind 4 | **Delivered** | `frontend/package.json`: react `^19.3.1`, vite `^8.3.4`, tailwindcss `^4.3.3`, typescript `~6.0.3`. I did not build the frontend (no `node_modules`), so a clean build is unverified. |
| Recharts + Lucide React | **Delivered** | Both in `package.json`. |
| Python + FastAPI | **Delivered** | `backend/app/main.py` and 13 routers. |
| SQLAlchemy + SQLite | **Delivered** | Default database is `./cybershield.db`. |
| **PostgreSQL / Supabase** | **Partial** | `database.py` reads `SUPABASE_DATABASE_URL` / `DATABASE_URL`, but `requirements.txt` has **no Postgres driver** (no psycopg2, psycopg or asyncpg). A Postgres URL fails to connect, and the code then **silently falls back to SQLite**. Postgres has never been exercised. |
| Scikit-learn + NumPy | **Delivered, but toy** | TF-IDF + LogisticRegression trained on 24 sentences; Isolation Forest on 12 rows (AUDIT §4). |
| JWT + Bcrypt | **Partial** | Both are real, but S1 (a universal backdoor password), S2 (unverified SSO with client-chosen role) and S3 (unauthenticated password reset) make the authentication bypassable. S6: the JWT secret defaults to a public string. |
| Pytest + HTTPX | **Delivered** | 25 tests pass. None check that RBAC denies anything, so S1–S5 ship green (AUDIT §7). |

### 2.2 The four problem → solution pairs (slide 2)

| Problem → Solution | Verdict | What exists | What does not |
|---|---|---|---|
| **Phishing links and scams → AI-based URL and message analysis** | **Partial** | `phishing_engine.py` scores email text and URLs with an ML model plus heuristics. It returns a score, a severity and a list of `indicators`, which delivers the "explainable" claim. The URL warning flow returns a verdict. | The ML model memorises 24 sentences; the same text model is applied to URLs it was never trained on. False positive proven: `login.microsoftonline.com` scores 57 / Medium. No VirusTotal or PhishTank call is ever made (F2). There is no browser extension, proxy or DNS hook (F5). |
| **Suspicious network activity → anomaly detection and threat alerts** | **Partial** | `network_engine.py` uses an Isolation Forest plus thresholds for port scans, brute force and large transfers. Events are stored and shown. | The forest is fit on 12 hardcoded rows and the alert condition is mostly a threshold. There is no real traffic source: logs are submitted manually or via `POST /monitoring/simulate-pulse`. Event IDs collide across IPs. |
| **Delayed threat response → automated alerts and authorized blocking** | **Simulated** | `alert_engine.py` creates alert rows and `incidents.py` has containment actions (FIREWALL_BLOCK, HOST_ISOLATION and so on). | No email or SMS transport exists, yet rows are marked `DELIVERED` (F1). Containment writes `SIMULATED_EXECUTED` and then sets the incident to *Contained* (F4). Nothing talks to a firewall, EDR or gateway. The `.env.example` integration variables are never read (F10). Nothing in the response path is automated; every action is a manual API call. |
| **Complex incident investigation → correlated evidence and forensic reports** | **Partial** | `correlation_engine.py` groups events by shared source IP across at least two sensors, and creates an incident with evidence and a timeline. A forensics view exists. | Correlation is an IP-equality match only; confidence labels are `if len(sources) > 1` picks and evidence confidence is a constant `0.92` (F7). The simulator hardcodes an IP, so it fabricates correlations. The MITRE mapping is a three-item default. "Forensic reports" are a timeline over DB rows. The Reports page produces no file (F14). |

### 2.3 Pipeline stages (slide 2)

| Stage | Verdict | Notes |
|---|---|---|
| Data input from multiple sources | **Simulated** | 7 monitoring sources are seeded rows with fabricated counts and `is_simulated=True`. No collectors, no background tasks (F3). Real inputs are manual submissions: an email, a URL, a file, a log. |
| AI threat detection | **Partial** | Works end to end, with weak models. The DLP engine is the most real component. |
| Risk analysis | **Partial** | Per-event scores exist. Employee `risk_score` is never updated by any code (F9). |
| Threat response | **Simulated** | See the response row above. |
| Digital forensics | **Partial** | A timeline view with a fixed MITRE mapping. |
| Unified dashboard | **Partial** | The page exists, but `DashboardPage.tsx` makes zero API calls. Every number on it is hardcoded, and so are Threat Detection, Monitoring Center, Incidents list, Notifications and Reports (AUDIT §3). The backend dashboard endpoints exist but are unused by the page. |

### 2.4 Claimed innovation (slide 2)

| Claim | Verdict |
|---|---|
| Unified cybersecurity dashboard | **Partial.** Unified navigation, yes. A dashboard that reflects real data, no. |
| AI-powered threat analysis and risk scoring | **Partial.** Scoring is real code; the "AI" is a baseline heuristic plus tiny models. |
| Cross-source threat correlation | **Partial.** IP-match correlation across event sources works; it is not a general correlation engine. |
| Integrated detection, prevention and forensics | **Detection and forensics view: partial. Prevention: simulated.** |

### 2.5 Feasibility and risk claims (slide 4)

| Claim | Verdict | Notes |
|---|---|---|
| "Safe test URLs and simulated network logs support prototype testing" | **Accurate** | This is the most honest line in the deck. The app does run on simulated data. It does not say that the dashboard figures are static, which is a larger gap. |
| "Test models with diverse datasets" | **Not done** | No dataset beyond 24 and 12 hand-written rows. No held-out evaluation, no precision or recall measurement. |
| "Continuous evaluation" | **Not built** | No evaluation pipeline, no feedback loop. |
| "Use explainable alerts" | **Delivered** for phishing and file analysis (the `indicators` list). Not for the network model. |
| "Authorized security controls" | **Not built** | No integration with any control. Also no role enforcement on most endpoints (S5). |
| Weakness: false positives | **Confirmed by testing**: a Microsoft login URL scores Medium, a finance note about bitcoin raises a SOC event, an empty file scores 90 / Critical. |
| Weakness: data quality | **Confirmed.** It is the central weakness of the current build. |

### 2.6 Impact claims (slide 5)

| Claim | Verdict |
|---|---|
| Users get phishing warnings and understand why a link is dangerous | **Partial.** The URL warning returns indicators, but there is no delivery channel to an end user (no extension or gateway). The employee page's "report phish" shows success even when the request fails. |
| Browse more safely with threat alerts | **Not built.** Nothing sits in the browsing path. |
| IT admins: one dashboard, track incidents, generate reports | **Partial.** Incident tracking works against the API. The dashboard figures are fake and no report file is generated. |
| Security teams: detect network activity early, reduce manual monitoring | **Not met.** There is no live collection, so there is nothing to detect early, and there is no automation. |
| Organisation: block malicious activity | **Simulated.** |

### 2.7 Other claims

- **Prototype link (slide 3 and 6):** the deck points to a live prototype. I can't see the URL from the extracted text, so I haven't verified it. Whatever is deployed there inherits S1–S4: an unauthenticated visitor can become Super Admin or wipe the database. The Render config sets no `SECRET_KEY`.
- **Existing solutions studied:** Google Safe Browsing, Snort, Microsoft Defender XDR, DEPHIDES, AI-IDS. The product uses none of them. Nothing queries Safe Browsing or any threat feed, and there are no Snort or Suricata rules, even though the seed data names a "Suricata NIDS" source.

---

## Part 3: Scorecard

| Deck pillar | Status |
|---|---|
| Detect phishing | Partial: working pipeline, toy model, no external intelligence |
| Detect network anomalies | Partial: working on submitted logs only |
| Correlate across sources | Partial: IP-pivot only |
| Assess risk | Partial: per-event scores; employee risk not updated |
| Block / prevent | **Simulated** |
| Alert | **Simulated** (`DELIVERED` with no transport) |
| Investigate / forensics | Partial: timeline over DB rows |
| Unified dashboard | **Mostly static** |
| Secure by design | **Not met** (S1–S5) |

**One-line summary:** the deck describes a working detect-prevent-investigate platform; the code is a convincing front end and API over simulated data, with a thin real detection layer and a prevention and alerting layer that does nothing outside the database.

---

## Part 4: What closes each gap

Ordered so that what the deck promises is made true, or the deck is corrected. Detail is in [AUDIT.md](AUDIT.md#recommended-order-of-fixes).

1. **Make it safe to demo publicly.** Remove S1–S4, require roles on every router, set `SECRET_KEY` from the environment. Until then the prototype link in the deck is an open admin console.
2. **Make the dashboard real.** Wire the six static pages to the backend endpoints that already exist. Remove silent mock fallbacks.
3. **Make alerting honest.** Either add a real transport (SMTP or a webhook) or relabel statuses as `RECORDED_NOT_SENT`.
4. **Make Postgres true.** Add a driver to `requirements.txt` and test against it, or drop it from the stack slide.
5. **Make "authorized blocking" real in one place.** Pick one control (for example a webhook to a firewall API or a blocklist file the gateway reads), implement it with authentication, and mark it as such in the UI. Everything else stays labelled "simulated".
6. **Back the ML claims.** Use a public phishing dataset (URL and email) for training, hold out a test split, and report precision and recall. This is what "diverse datasets" and "continuous evaluation" in the deck require.
7. **Add one real input.** For example a scheduled job that polls a mailbox, a log file or a pcap, so "data input from multiple sources" is true for at least one source.
8. **Fix the deck where the code won't catch up.** If a pillar will not be real by the demo, change the wording ("simulated containment", "baseline heuristics") instead of leaving a claim a judge can falsify in one request.

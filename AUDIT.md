# CYBERSHIELD AI: Honest Audit

Audited 2026-10-28 at commit `f3d60fb`. I read every backend file and every frontend page that holds data or logic. I installed the backend in a scratch venv outside the repo and ran the test suite plus about 30 behavioural probes against the live app. The frontend was **not built or run** (no `node_modules`), so UI claims come from reading source.

## Verdict

This is a **demo of a SOC product, not a SOC product**. The README's "Reality Matrix" is more candid than most, but it understates the problem in three ways:

1. **Authentication is broken enough that RBAC is decorative.** Anyone can become Super Admin in one request.
2. **Most of the dashboard UI never touches the backend.** Six pages are static arrays, and the main dashboard is entirely hardcoded.
3. **Several "FUNCTIONAL (REAL)" rows are not real.** Alerts "DELIVERED" with no transport, ML models trained on 24 sentences, and a reputation-API status that reports "Connected" without making any call.

What is genuinely real: bcrypt hashing, JWT signing, the DB schema and CRUD, the DLP regexes and masking, Shannon entropy, the PE header check, and the SSRF string checks. The 25 tests pass (verified: `25 passed`).

---

## 1. Security holes (verified by running them)

| # | Finding | Where | Proof |
|---|---|---|---|
| S1 | **Universal backdoor password.** Any account accepts `CyberShield@2026!`, `Admin@CyberShield2026!`, `Rahul@Employee2026!` or `password`, even after the real password is changed. | [auth.py:64-67](backend/app/routers/auth.py:64) | Logged in as `admin@cybershield.corp` with `password` → 200. Rotated the admin password; the default still worked → 200. |
| S2 | **SSO endpoint trusts the caller.** It does no OAuth or token verification, auto-creates the user, and lets the *request body* choose the role. | [auth.py:112-165](backend/app/routers/auth.py:112) | `POST /auth/sso {email: attacker@evil.com, role: "Super Admin"}` → 200, `role: Super Admin`. |
| S3 | **Unauthenticated password reset for any user**, including admin. No token, no email, no old password. | [auth.py:246-263](backend/app/routers/auth.py:246) | Reset admin with no auth → 200, then logged in with the attacker's password → 200. |
| S4 | **Unauthenticated database wipe.** `force_reset=true` deletes all users and re-seeds. | [system.py:71-74](backend/app/routers/system.py:71) | `POST /system/seed-demo?force_reset=true` with no auth → 200. |
| S5 | **RBAC is applied to only 3 endpoints** (employee create/update/bulk-import). Every other router has no auth dependency. | grep for `require_roles` | Unauthenticated 200s on: list/patch incidents, run containment actions, list employees, DLP findings, alert deliveries, `simulate-pulse`, `demo-accounts`. |
| S6 | **Hardcoded JWT secret.** `SECRET_KEY` defaults to a string in the public repo, and [render.yaml](render.yaml) never sets one, so a Render deploy runs with a forgeable key. | [config.py:28](backend/app/config.py:28) | Static read. |
| S7 | **Credentials served by an endpoint and baked into the repo.** `/auth/demo-accounts` returns the passwords. The seed password is also in the README. | [auth.py:265-297](backend/app/routers/auth.py:265) | Probe returned 200 with no auth. |
| S8 | **Actor identity is client-supplied.** Audit logs, notes and acknowledgements record whatever `analyst_name` the caller sends, or the fixed strings "SOC Lead" and "Active SOC Analyst". The audit trail cannot be trusted. | [incidents.py](backend/app/routers/incidents.py), [events.py](backend/app/routers/events.py), [dlp.py:130](backend/app/routers/dlp.py:130) | Static read. |
| S9 | **Ghost user auto-provisioning.** Logging in as `rahul`, `rahul@company.com` or `rahul.k@company.com` silently creates an Employee account with the default password. | [auth.py:29-45](backend/app/routers/auth.py:29) | Static read. |
| S10 | The JWT is stored in `localStorage` (XSS-readable), has no revocation, and "logout" only writes an audit row. | [App.tsx](frontend/src/App.tsx), [auth.py:233](backend/app/routers/auth.py:233) | Static read. |

---

## 2. Things that claim to be real but are not

| # | Claim | Reality |
|---|---|---|
| F1 | "Email and SMS alert delivery, `DELIVERED` status" | No SMTP, Twilio or HTTP client exists in `backend/app`. [alert_engine.py](backend/app/services/alert_engine.py) inserts a DB row with `delivery_status="DELIVERED"`. A dispatch to `nobody@nowhere.invalid` returned `DELIVERED`. The SMS path hardcodes `DELIVERED` and ignores dedup. |
| F2 | "VirusTotal / PhishTank integration" | The keys are only checked with `bool(...)`. Nothing calls either API. **Setting `VIRUSTOTAL_API_KEY` flips the dashboard to "Connected (Live External API)" and the file analyzer to "External reputation service queried successfully", both false.** See [dashboard.py:31-35](backend/app/routers/dashboard.py:31) and [file_analyzer.py:171-175](backend/app/services/file_analyzer.py:171). `ABUSEIPDB_API_KEY` is never read. |
| F3 | "24/7 monitoring, source health ONLINE/DEGRADED/OFFLINE" | There are no background tasks or collectors anywhere. Sources are 7 seeded rows with `is_simulated=True`, fabricated counts (18,420 / 42,190 / 129,400 ...) and "heartbeats" stamped at seed time. Nothing ever sets DEGRADED or OFFLINE. "Telemetry" only arrives via the manual `POST /monitoring/simulate-pulse`. |
| F4 | "Containment: FIREWALL_BLOCK, HOST_ISOLATION ..." | Writes a `ResponseAction` row with `status="SIMULATED_EXECUTED"` ([incidents.py:132-177](backend/app/routers/incidents.py:132)). Disclosed in the response, but a status of `Contained` is then set on the incident. |
| F5 | "URL interstitial gateway" | There is no browser extension, proxy or DNS hook. It is an API that scores a string. `is_simulated_block` is always `True`. |
| F6 | "AI / ML threat detection" | See §4. These are tiny toy models. |
| F7 | "Deterministic multi-sensor correlation, high confidence" | See §5. Confidence labels are `if len(sources) > 1` string picks, and evidence confidence is a constant `0.92`. |
| F8 | Dashboard `system_status: "Operational"`, `ml_models_active: True`, system `version: "1.0.0-soc-release"` | Literals, with no health check behind them. (The README and the app info endpoint say 2.0.0.) |
| F9 | Employee `risk_score` "dynamically updated based on active incidents" (model comment) | No code ever updates it. New employees stay at 0. The seeded 78 / 85 / 65 are literals. |
| F10 | `.env.example` options (`JWT_SECRET_KEY`, `ALERT_EMAIL_ENABLED`, `TWILIO_*`, `CISCO_UMBRELLA_API_KEY`, `PALO_ALTO_PANOS_API_KEY`, `GATEWAY_BLOCKING_INTEGRATION_URL`) | None are read anywhere. `ACCESS_TOKEN_EXPIRE_MINUTES=720` is ignored (the code hardcodes 1440). |
| F11 | 2FA (TOTP) in the profile modal | A `useState(true)` toggle. The "secret key" is the RFC example `JBSWY3DPEHPK3PXP`, shown to every user. The backend has no 2FA. |
| F12 | "Rotate API token" | `Math.random()` in the browser produces a `cs_live_...` string. It is never sent or stored, and no API-token auth exists. |
| F13 | Notification toggles, monitoring toggles, and "Save" in Settings | `handleSave` only flashes a "saved" message ([SettingsPage.tsx:52-55](frontend/src/pages/SettingsPage.tsx:52)). Nothing is persisted, and the toggles don't affect the backend. |
| F14 | "Generate Report" → `CYBERSHIELD_EXECUTIVE_AUDIT_Q4.pdf` | `setTimeout(1200)` then `alert(...)`. No PDF exists. [ReportsPage.tsx:27-33](frontend/src/pages/ReportsPage.tsx:27) |
| F15 | "SSO with Google / Microsoft" buttons | Call the unverified `/auth/sso` (S2) with an email picked in a modal. There is no OAuth. |
| F16 | Seeded `secret_hash` described as SHA-256 | Seed values are 40-char SHA-1-shaped hand-typed strings (`a1b2c3d4e5f6...`). They are not hashes of anything. Fake incident hash `ed01ebfb...41aa` appears as both a "CrowdStrike payload" and an "Emotet" signature. I believe that SHA-256 is a widely published **WannaCry** hash, not Emotet, so verify the label. |

---

## 3. Frontend: hardcoded and mock data

Pages that make **zero** API calls (static arrays in the component):

| Page | What's fake |
|---|---|
| [DashboardPage.tsx](frontend/src/pages/DashboardPage.tsx) | KPI cards (128 employees, 4,812 events, 24 incidents, 7 critical, 26 URLs, 15 leaks), the "+2.1% this week" / "12%" deltas, the 7-point activity chart, the donut distribution and all 5 "recent alerts". **The headline page is a screenshot.** Backend endpoints `/dashboard/metrics`, `/severity-distribution` and `/activity-timeline` exist, but the page doesn't use them. |
| [ThreatDetectionPage.tsx](frontend/src/pages/ThreatDetectionPage.tsx) | `phishingRecords` array |
| [MonitoringCenterPage.tsx](frontend/src/pages/MonitoringCenterPage.tsx) | `webActivityRecords` array |
| [IncidentsListPage.tsx](frontend/src/pages/IncidentsListPage.tsx) | incidents array. The IDs (`INC-0042`) don't even match the backend format (`INC-2026-0042`). |
| [NotificationsPage.tsx](frontend/src/pages/NotificationsPage.tsx) | notifications array, although `/alerts/deliveries` exists |
| [ReportsPage.tsx](frontend/src/pages/ReportsPage.tsx) | trend chart data |

Silent mock fallbacks, which are worse because they look live:

- [DLPPage.tsx:28-112](frontend/src/pages/DLPPage.tsx:28): on empty **or failed** API response, shows 5 invented findings (`secret_hash: 'hash-001'`, an S3 bucket and so on).
- [EmployeeManagementPage.tsx:38-63](frontend/src/pages/EmployeeManagementPage.tsx:38): same, with 8 invented employees. If the DB is empty or the API is down you edit "Rahul Kumar" and think it's real.
- [IncidentResponsePage.tsx:30-75](frontend/src/pages/IncidentResponsePage.tsx:30): falls back to a fake `INC-2026-0042`. Containment buttons always target the hardcoded `https://secure-login-okta-verify.com` and the note author is hardcoded to "Sarah Chen". On API failure the UI says "Action recorded in audit log" when nothing was recorded.
- [EmployeeDashboardPage.tsx:27-70](frontend/src/pages/EmployeeDashboardPage.tsx:27): 3 hardcoded alerts. Reporting a phish shows **success even when the request fails** (the `catch` calls `setReportSuccess(true)`).
- Settings and profile modal: default phone `+1 (555) 942-8321`, timezone `Asia/Kolkata`, default name "Chief Information Security Officer". The DLP form pre-fills `marcus.chen@enterprise-corp.com`.

Schema drift between frontend and backend, which only the mocks hide:

- The frontend `Employee` type uses `risk_level` ('Low'…'Critical'); the backend sends `risk_score` (int). Real data will render without a risk level.
- The frontend policies are `Strict|High|Standard|Low`; the seeded data uses "Executive High-Risk", "Standard Workstation", "Contractor Strict" and others.
- DLP mock fields (`source_type`, `location_reference`, `exposure_scope`, status `Active|Remediated`) don't exist in the backend (`NEW|CONTAINED|REVOKED|FALSE_POSITIVE`).
- The README demo-account table lists `alex.turner@...`, but `/auth/demo-accounts` and the login page use `rahul.k@company.com` (which exists only via S9).

---

## 4. Detection "AI": what it actually is

| Component | Reality |
|---|---|
| **Phishing NLP model** ([phishing_engine.py:46-81](backend/app/services/phishing_engine.py:46)) | TF-IDF + LogisticRegression **trained at import time on 24 hand-written sentences** (12 phish and 12 benign). No held-out evaluation. It will memorise those sentences. |
| **URL ML score** | The same email-text model is applied to `hostname + path` tokens. It was never trained on URLs, so the signal is noise (up to +30 points). |
| **URL heuristics** | Substring checks. **False positive proven:** `https://login.microsoftonline.com` scores 57 / Medium ("Brand Squatting (microsoft)"), because only `microsoft.com` is whitelisted. Real brand hosts such as `microsoftonline.com`, `amazonaws.com` and `apple.com` subdomain patterns are not. |
| **Isolation Forest** ([network_engine.py:22-38](backend/app/services/network_engine.py:22)) | Fit on **12 hardcoded rows** with `contamination=0.15`. Port number is used as a continuous feature, which is meaningless. An alert also requires `bytes > 80000 or packets > 90`, so the "ML" is mostly a threshold. Thresholds (4 ports, 3 fails, 5 MB) are constants. |
| **Network event IDs** | `NET-BRUTE-{last 6 digits of IP}` collide across IPs. |
| **File analyzer** ([file_analyzer.py](backend/app/services/file_analyzer.py)) | **6-entry "malware DB"; 4 are test vectors** (empty file, EICAR ×2). Matching a signature forces `score = max(score, 90)` regardless of its stated severity, so **an empty file scores 90 / Critical** (verified). Regex precedence bug: `cmd /c curl|wget|certutil` means any text containing `wget` matches (verified: prose scored 35). The word "bitcoin" or "ransom" adds +45, so a finance note about bitcoin scored 50 / Medium and raised a SOC event (verified). |
| **SSRF guard** ([ssrf_guard.py](backend/app/utils/ssrf_guard.py)) | It defends against a fetch that **never happens**; the app never requests the URL. Meanwhile it does a live DNS lookup of user-supplied hostnames (blocking, and leaks the query), and rejects `.corp` and `.test`, so your own intranet hosts get flagged "Critical (95)". |
| **DLP** | Real regexes with SHA-256 and masking. This is the most honest module. Caveats: no entropy or validation (the generic-password pattern will over-fire), it leaks 8 characters of each secret, and `sk_test_` keys are scored Critical like live ones. |

---

## 5. Simulation and data-integrity bugs

- **Same-second ID collisions crash the API.** Event IDs are `SEC-<kind>-{epoch_seconds % 100000}` (phishing, file, URL warning, override, simulate-pulse). Two submissions in the same second hit the `UNIQUE` constraint → **HTTP 500** (verified twice: file analysis and phishing). Analysis IDs (`TA-URL-{epoch}`) have the same problem. Incident IDs from the correlation engine are `INC-{HHMMSS}`, so they repeat every day.
- **Simulated pulses fabricate correlations.** Every `simulate-pulse` event hardcodes `source_ip=198.51.100.44`, `dest_ip=10.0.12.84`. Two unrelated pulses (email and DNS) were correlated into an incident "targeting 198.51.100.44" with "Moderate-High Confidence (Shared Cross-Domain Pivot)" (verified). The pivot is an artefact of the simulator.
- **The dashboard timeline is padded.** `max(total, (7-i)*3+4)` and `max(threats, ...)` impose a floor, and `phishing` and `network` series are pure arithmetic on the loop index ([dashboard.py:90-96](backend/app/routers/dashboard.py:90)). Verified: a fresh, almost empty DB returned a rising 7→25 events curve.
- **Seed data is internally inconsistent.** INC-0042 is assigned to EMP-1043 but its notification goes to Alex Turner (EMP-1042). Analyst names are free text and don't join to users. Timestamps are `now - N hours`, so the data always looks fresh and never ages. The seed claims "Suricata NIDS" and "Proofpoint" sources that aren't in the monitoring-source list.
- **Auto-seeding in production.** [main.py:31-33](backend/app/main.py:31) seeds fabricated incidents, employees and leaked-secret findings on any empty DB, including a deployed one. There is no `ENVIRONMENT` guard.
- **Forensics page.** The MITRE mapping is a default list of three tactics, overridden by `"Brute" in category` or `"Scan" in category`. "Digital forensics" is a timeline view over DB rows. The `is_simulated_notice` says "derived from verified sensor logs", which is false for seeded or simulated data.

---

## 6. Deployment and persistence

- **Data is ephemeral by default.** With no `SUPABASE_DATABASE_URL`, it uses SQLite. Render's free plan has an ephemeral disk, so every restart wipes the DB and re-seeds the fake data. On Vercel it is `/tmp` per lambda, so different instances see different data.
- `Base.metadata.create_all` with no migrations.
- A DB connection failure silently falls back to SQLite ([database.py:24-26](backend/app/database.py:24)). A mistyped production URL gives you a demo DB with no hard error.
- CORS allows `https://.*\.vercel\.app` with credentials, which is any Vercel app.
- `/docs`, `/redoc` and the demo-credential endpoint are public. `/api/v1` and `/v1` are both mounted.
- Rate limiting: none. Login lockout: none.

## 7. Tests: what the "25/25" does and doesn't prove

- They pass, and the README output is honest.
- `test_auth_rbac.py` is misnamed. It tests bcrypt and JWT round-trip only, with **no test that RBAC denies anything**. That's why S1-S5 ship green.
- Tests run against the dev SQLite file and call `seed_demo_soc_data(force_reset=True)`. They're integration tests of the seed data, and the e2e flow asserts on the fabricated dataset.
- ML tests assert on the same toy samples the models were trained on (`test_phishing`, `test_network`).
- No frontend tests. No CI config.

## 8. What I did not verify

- The frontend build, type-check and runtime behaviour (no `node_modules`; I read source only).
- Behaviour on Postgres/Supabase, or on Vercel/Render.
- I did not assess dependency CVEs. `requirements.txt` is unpinned (`>=`).
- `AuditLog` completeness beyond the endpoints I read.

---

## Recommended order of fixes

1. **Delete S1, S2, S3, S4 today.** Remove the password allow-list, the SSO endpoint (or verify real OIDC), the open reset and the open `seed-demo`. Then gate every router with `require_roles`. Add negative RBAC tests.
2. Set `SECRET_KEY` from the environment with no default (fail startup if missing in production). Remove `/auth/demo-accounts` and the README credentials outside a `DEMO_MODE` flag.
3. Fix F2 (a key being present must not report "connected") and F1 (don't write `DELIVERED` unless something was sent; use `RECORDED_NOT_SENT`).
4. Replace time-based IDs with UUIDs/sequences (fixes the 500s). Use `uuid4` for incident IDs.
5. Wire the six static pages to the existing endpoints. Remove silent mock fallbacks (show an error state). Make Settings, 2FA and API-token either real or visibly disabled.
6. Put a `DEMO_MODE` banner and seed guard around all fabricated data, and label every simulated surface in the UI the way `MonitoringSourcesPage` already does.
7. Fix the detector bugs (empty-file Critical, `wget` regex, brand whitelist, signature severity), and describe the models as "baseline heuristics", not "AI threat detection".

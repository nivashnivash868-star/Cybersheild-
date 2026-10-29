# CYBERSHIELD AI: final audit

Date: 2026-10-29. Branch `testing/white-box-fixes`, nothing committed yet.
Question asked: is anything hardcoded, simulated or a fake API call, and is Zetaris really part of the Docker setup?

## Verdict

No fake API calls remain. Every outbound call goes to a real service the operator configures. There is no fabricated data in a
production configuration. What the audit did find were **small dishonest labels and canned strings** (nine, listed below),
which are now fixed, and a set of **honest limits** you should know about (section 4).

## 1. Zetaris and Docker

| Question | Answer |
|---|---|
| Is Zetaris in this repository's `docker-compose.yml`? | **No.** CyberShield's compose file has `app`, `db` and `mailpit` only. |
| Is Zetaris running in Docker? | **Yes, as its own stack** from the hackathon bundle (`~/zetaris-platform`): `zetaris-ui`, `-api`, `-driver` (Spark), `-postgres`, plus two one-shot init jobs. `./verify.sh` passes 9 of 9 checks. |
| How does CyberShield reach it? | From the app container to `http://host.docker.internal:8888` (REST API), with `ZETARIS_ORG_ID`, the bundle's admin login and the `cybershield.*` tables set in `.env`. On Linux hosts `host.docker.internal` needs `extra_hosts: host.docker.internal:host-gateway` on the `app` service (not added; this was run on macOS). |
| Does the integration work live? | **Yes.** The end-to-end script signs in through the real REST API, ingests the three tables, runs L1/L2, previews each table, and the Test button lists the three Zetaris databases (`cybershield`, `NY_TAXI`, `TPCDS_DB`). |
| Is the Zetaris data real? | **No.** The tables hold the generated synthetic story from `scripts/generate_synthetic_logs.py`, and `ZETARIS_DATA_IS_SYNTHETIC=true` marks every event read from it SIMULATED. All 23 events in the running stack carry that flag. |
| Zetaris Cloud? | Not tested (no account). |

Observation: when the host is busy, the Spark driver can take over a minute per query. The first version of the worker did
ingest and alert delivery in one loop, so a slow ingest delayed an approved containment request (found by the end-to-end
run; fixed, see F8).

## 2. What was run

| Check | Result |
|---|---|
| Backend pytest, SQLite (Python 3.9) | 367 passed |
| Backend pytest, PostgreSQL 16 | 367 passed |
| Backend pytest, Python 3.13 image (`docker build --target test`) | 367 passed |
| Frontend: types, lint, tests, build | clean, 0 lint warnings, 36 passed, built |
| Docker stack (PostgreSQL, mail catcher, app) + live Zetaris + signed-webhook receiver, `scripts/e2e_stack.py` | 61 of 61 passed on a fresh database |
| Live API probe of a fresh database | 0 employees, 0 monitoring sources, 0 incidents until Zetaris data arrives; all ingested events flagged simulated |

## 3. Findings and what happened to them

Method: grep of every backend and frontend source file for randomness, sleeps, fake/mock/sample/demo/placeholder wording,
literal success responses, constant statuses, literal actors in the audit log, embedded credentials and token patterns,
static data arrays, and every outbound URL; then reading each hit; then a live probe of the running stack.

### Fixed in this pass

| # | Severity | What was wrong | Where | Fix |
|---|---|---|---|---|
| F1 | **High** | Audit entries for phishing, file and network analyses were written with the literal actor `"SOC Analyst / Portal User"` (or `"... / Ingestion Pipeline"`), not the signed-in person. The audit trail could not say who ran what. | `routers/phishing.py`, `file_analysis.py`, `network.py` | Actor is now the session user's email; tests added. |
| F2 | Medium | The URL gateway check returned a canned reason ("Disposable TLD and credential spoofing patterns detected") and category ("Phishing / Brand Spoofing") whatever the analysis found. | `routers/url_warning.py` | Reason and category come from the analysis indicators, and the reason says nothing was actually blocked (no gateway is connected). |
| F3 | Medium | The override response said "Workstation is being monitored." There is no such mechanism. | `routers/url_warning.py` | Reworded to what happens: logged and raised as an alert. |
| F4 | Medium | The dashboard's reputation status was a constant "Not connected: no external reputation lookups are made", now untrue. | `routers/dashboard.py` | Built from the real provider state. |
| F5 | Medium | The header showed a permanent green "System Active • 24/7 Monitoring" and the API returned the constant `"Operational"`. | `Header.tsx`, `dashboard.py`, `system.py` | Status is measured: database answers and the worker heartbeat is under two minutes old; otherwise "Platform degraded". The "24/7 Monitoring" claim is gone. |
| F6 | Medium | Running a built-in sample scenario created SOC events marked as real. | phishing and network routers, two pages | Sample runs carry `is_sample`; their events are marked SIMULATED. |
| F7 | Low | Forensics timeline called every containment action "(Simulated)", including real ones. The monitoring page showed local time labelled UTC. A hardcoded default employee email (`rahul.k@company.com`) and mock-up comments remained. | `forensics.py`, `MonitoringSourcesPage.tsx`, `URLWarningModal.tsx`, `App.tsx` | Label follows the record's own flag; UTC is real UTC; literals removed. The URL-warning page shows a SIMULATED badge when it is only a sample. |
| F8 | **High** (found by the end-to-end run) | One worker loop did Zetaris ingest and delivery together. A slow ingest delayed alerts and approved response requests. | `worker.py` | Delivery and analysis are separate loops (PostgreSQL); a test proves delivery does not wait. |
| F9 | Low | The Dockerfile pinned an external syntax image that made offline builds fail. | `Dockerfile` | Directive removed. |

Also fixed earlier in this session and re-verified: stale "not integrated" text for identity-provider/EDR actions,
decision cards that always said "manual step", and the URL warning override claiming success when the call failed.

### Verified clean

- **No fake API calls.** The only hosts the code contacts are Zetaris (`ZETARIS_BASE_URL`), VirusTotal, AbuseIPDB, Twilio,
  the SMTP server, the OIDC issuer and the response webhook, each only when configured. Nothing is stubbed in application
  code; fakes exist only in `tests/` and are injected through `_transport` hooks.
- **No fabricated values in the UI.** No `Math.random`, no faker, no static data arrays; every page fetches from the API;
  empty systems show empty tables ("Nothing needs a decision right now").
- **No embedded secrets.** No tracked `.env`, key or database files; no token-pattern strings; no default passwords outside
  the demo seeder and the tests. `SECRET_KEY` is required outside development.
- **Simulated data is gated and labelled.** `DEMO_MODE` (seed, `simulate-pulse`, demo accounts with known passwords) is
  refused when `ENVIRONMENT=production` and returns 404 when off. Simulated events show a SIMULATED badge and a banner.
- **Success messages.** The `{"status": "success"}` responses are returned after the operation ran; the one exception was F3.

## 4. Flagged and not changed: honest limits

| # | Flag | Why it matters |
|---|---|---|
| O1 | **Zetaris is a separate stack**, not in this compose file, and the app reaches it through `host.docker.internal`. | A new machine needs the bundle started first, and Linux needs the `extra_hosts` line. Say if you want a compose override added. |
| O2 | **All telemetry in the running system is synthetic.** The Zetaris tables are generated. | Nothing here has seen a real attack or a real network. The detection numbers are from small public samples and generated scenarios (`docs/detection-evaluation.md`). |
| O3 | **Built-in sample scenarios contain canned `expected_risk` labels** (`/phishing/samples`, `/network/sample-scenarios`, `/files/samples`), and a file sample run stores a normal analysis record with the sample name only in its metadata. | The labels are our expectation, not a verified result. They are test scenarios, not telemetry. |
| O4 | **Monitoring sources are only created by the demo seed.** `POST /monitoring/sources/{id}/heartbeat` lets an administrator *assert* a source is ACTIVE; nothing measures it. | In a real deployment the Monitoring Center is empty, which is accurate. Do not treat a status there as a probe result. |
| O5 | `ml_models_active` in the dashboard payload is a constant `true`; the model files are loaded at start-up (a missing URL model degrades to rules only and is named in the engine string). | Cosmetic; the evaluation page is the real statement of model state. |
| O6 | The network model baseline is **generated** unless you supply `NETWORK_BASELINE_CSV`; the built-in file signature list holds only the EICAR test file unless you supply `FILE_HASH_FEED_PATH` or a VirusTotal key. | Out of the box the file "reputation" check knows almost nothing. |
| O7 | **Thresholds are hand-set** (L1 risk cut-offs, L2 score weights, URL/message/file score bands). They are tunable and measured on synthetic data only. | Expect to retune on real traffic. |
| O8 | The rate limiter and reputation quotas are **in-process**. | With several API workers each process counts separately; use one process or put a limiter in front. |
| O9 | `POST /incidents/{id}/actions` still records host isolation and similar as "manual" and says the platform has no integration, even when a response connector is configured; the connector is used through approved decisions. | Slightly inconsistent wording on a rarely used path. |
| O10 | Test and e2e scripts contain test credentials (`Bootstrap-Temp-2026-x`) and the demo seeder has known passwords. | Intended for local use; never run the seeder or script against a real deployment. |
| O11 | **Unverified against the real service:** Zetaris Cloud, a live OIDC tenant, Twilio, VirusTotal/AbuseIPDB keys, a real SOAR/IdP/EDR receiver. | Covered by fakes that follow each service's documentation. Use the Test buttons. |

## 5. Suspicion list, ranked

1. **F1** (audit actor): the only finding that undermined a core claim ("actor identity always comes from the session"). Fixed.
2. **O2** (all data synthetic): the biggest caveat for any demo claim of "real threat detection".
3. **O7/O6** (hand-set thresholds, empty reputation by default).
4. **O4** (administrator-asserted source status).
5. Everything else is cosmetic or fixed.

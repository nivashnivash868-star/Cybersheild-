# CYBERSHIELD AI

An integrated security operations platform: it collects security data from your own sources, detects and
investigates threats with a tiered SOC (levels 1 and 2 automated, level 3 human), blocks through approval-gated
firewall feeds, and records everything in a tamper-evident audit log.

This README says what is real, what is simulated and what is not built. Nothing below is claimed unless it is
implemented and tested.

## What it does

| Area | State |
|---|---|
| **Sign-in and access** | Real. Server-side sessions in an HttpOnly cookie, Argon2id passwords, TOTP two-step verification (mandatory for staff outside development), CSRF protection, lockout and rate limits, role checks on every API route. |
| **Roles** | Security Administrator and SOC Analyst, each with its own dashboard. Details in [docs/roles-and-approvals.md](docs/roles-and-approvals.md). |
| **SOC level 1 (triage)** | Real, automated. Deduplicates, closes noise, escalates, with a reason and confidence on every decision. |
| **SOC level 2 (investigation)** | Real, automated. Correlates alerts into incidents, maps the kill chain, reaches a verdict, proposes a response. Rule-based and explainable, not learned. |
| **SOC level 3 (decisions)** | Real, human. Blocks, incident dispositions, account disabling, host isolation, Critical closures and alert rules wait for a person. See [docs/soc-tiers.md](docs/soc-tiers.md). |
| **Data sources** | Real through [Zetaris](docs/zetaris-schema.md) when configured. Verified against a live local Zetaris instance with synthetic data; see "Verification status". |
| **Blocking** | Real as authenticated pull feeds (IP, domain, URL) for firewalls and DNS sinkholes, with approval and expiry. Enforcement happens when your firewall pulls the feed. |
| **Alerts** | Real email (SMTP) and SMS (Twilio) through a queue with retries. Status says `SENT` only when the provider accepted the message. |
| **Audit** | Real. Append-only HMAC hash chain; administrators can verify it. |
| **Phishing, file and network detectors** | Rules plus small models, **measured** on held-out data with stated limits: see [docs/detection-evaluation.md](docs/detection-evaluation.md). On a held-out phishing-feed sample 64% of URLs scored High or above and 81% Medium or above, with about 0.3% false alerts on unfamiliar legitimate sites. They are a triage aid, not a verdict. |
| **Threat intelligence** | Real when `VIRUSTOTAL_API_KEY` / `ABUSEIPDB_API_KEY` are set: lookups for public IPs, domains and file hashes (never file contents, private addresses or, by default, full URLs), cached and rate-limited. Status says "connected" only after a call succeeded. See [docs/integration-testing.md](docs/integration-testing.md). |
| **Identity-provider and EDR actions** | Real through a signed webhook to your own automation ([docs/response-connector.md](docs/response-connector.md)): CyberShield holds no IdP or EDR credentials and counts an action as done only when your automation confirms it. Without a connector, disabling an account affects CyberShield only and host isolation is done by a person. |
| **SSO (OpenID Connect)** | Real: authorization code + PKCE, signed ID tokens verified, existing users only, never auto-created ([docs/sso.md](docs/sso.md)). Tested against a fake provider; not yet against a live tenant. |

Data that is fabricated (the demo seed, the telemetry pulse, or Zetaris tables marked as synthetic) is flagged
**SIMULATED** wherever it appears.

## Run it

### With Docker (recommended)

```bash
cp .env.example .env        # set SECRET_KEY, POSTGRES_PASSWORD, BOOTSTRAP_ADMIN_EMAIL, BOOTSTRAP_ADMIN_PASSWORD
docker compose up --build   # app on http://localhost:8000 (set APP_PORT to change it)
```

Sign in with the bootstrap administrator and choose a new password when asked. For a local mail inbox add
`--profile dev` and set `SMTP_HOST=mailpit SMTP_PORT=1025 SMTP_SECURITY=none`; messages appear at
http://localhost:8025.

### Without Docker, for development

```bash
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements-dev.txt
DEMO_MODE=true uvicorn app.main:app --port 8000     # DEMO_MODE seeds simulated data and demo accounts

cd ../frontend && npm ci && npm run build            # the backend serves frontend/dist
# or run the UI with live reload: npm run dev (proxies /api to port 8000)
```

`DEMO_MODE` is refused when `ENVIRONMENT=production`. Without it, the first administrator comes from
`BOOTSTRAP_ADMIN_EMAIL` / `BOOTSTRAP_ADMIN_PASSWORD`.

### Tests

```bash
cd backend && python -m pytest -q          # or: docker build --target test .
```

The backend suite (367 tests) covers authentication and role checks on every route, MFA, the audit chain, alert delivery,
the blocklist, all three SOC tiers, the administrator and analyst workflows, the Zetaris client against a fake server, SSO
against a fake identity provider, the response connector, threat-intelligence lookups, a schema-driven API fuzzer, and
whole-pipeline scenarios with known answers. The frontend has component tests and a lint gate:

```bash
cd frontend && npm test && npm run lint     # Vitest + Testing Library; 0 lint warnings
```

Set `TEST_DATABASE_URL` (a `postgresql://` URL) to run the backend suite on PostgreSQL.

## Configuration

Everything is an environment variable; [.env.example](.env.example) lists each one with its purpose. Notable groups:
database (`DATABASE_URL`, PostgreSQL), alert transports (`SMTP_*`, `TWILIO_*`, `ALERT_SOC_EMAILS`), Zetaris
(`ZETARIS_*`), blocklist limits and protected ranges, session and lockout settings. Severity thresholds and alert
severity are changed by administrators in the app (Administration → Security configuration) and are audited.

## Architecture

```
Zetaris / manual submissions ──> events ──> L1 triage ──> L2 investigation ──> decisions ──> L3 human
                                                  │                                              │
                                      auto-close / duplicate                       approve: block feeds, account
                                                                                    disable, closure, alert rules
FastAPI (Python) + SQLAlchemy ── PostgreSQL        React + TypeScript + Tailwind + Recharts
background worker: alert queue, Zetaris ingest, L1/L2, blocklist expiry
```

## Security model

- Sessions are random tokens stored hashed server-side; the cookie is HttpOnly and SameSite=Strict, and state-changing
  requests need a CSRF header. Sessions expire when idle and in absolute time, and are revoked on password change,
  role change and deactivation.
- Passwords are Argon2id (older bcrypt hashes are upgraded at sign-in). TOTP secrets are encrypted at rest; a code can
  be used once.
- The API denies by default: every route requires a session and a role, and a test fails if one doesn't.
- Actor identity always comes from the session, never from the request.
- Feeds use per-consumer tokens; blocks refuse private and over-broad ranges and a list of never-block domains.
- `SECRET_KEY` is required outside development and the app refuses to start with demo mode in production.

## Verification status

- **Backend:** 367 tests pass on SQLite (Python 3.9) and on Python 3.13 in the test image; the suite has also been run
  against PostgreSQL. **Frontend:** 36 component tests, TypeScript clean, 0 lint warnings, production build.
- The application has been run end to end in Docker against PostgreSQL, a mail catcher and the **live local Zetaris
  instance** (the hackathon bundle) loaded with synthetic data: ingest, L1 triage, L2 investigation with raw-log evidence,
  approvals, blocklist feed, activation email, and the integration test endpoints.
- A line-by-line audit for hardcoded, simulated and fake values is in [docs/final-audit.md](docs/final-audit.md).
- **Detection quality** is measured, not assumed ([docs/detection-evaluation.md](docs/detection-evaluation.md)), but on
  small public samples and synthetic scenarios. No real malware was analysed and no production traffic was seen.
- **Not verified against the real thing** (needs your accounts; use the Test buttons in Administration):
  Zetaris Cloud, a live OIDC tenant, Twilio SMS, VirusTotal/AbuseIPDB keys, and a real SOAR/IdP/EDR receiver. The code paths
  are tested against fakes that follow each service's documentation.
- The L1/L2 scoring thresholds are tunable defaults. They behave sensibly on the synthetic scenarios and have not been
  calibrated on real incident data or analyst feedback.

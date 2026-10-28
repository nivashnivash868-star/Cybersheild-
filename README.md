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
| **Data sources** | Real through [Zetaris](docs/zetaris-schema.md) when configured. Tested against a fake that follows Zetaris's API; see "Verification status". |
| **Blocking** | Real as authenticated pull feeds (IP, domain, URL) for firewalls and DNS sinkholes, with approval and expiry. Enforcement happens when your firewall pulls the feed. |
| **Alerts** | Real email (SMTP) and SMS (Twilio) through a queue with retries. Status says `SENT` only when the provider accepted the message. |
| **Audit** | Real. Append-only HMAC hash chain; administrators can verify it. |
| **Phishing, file and network detectors** | Baseline heuristics and small models trained on a handful of samples. They are not evaluated and will produce false positives. |
| **Threat intelligence** | Not built. Reputation API keys are accepted, but no lookups are made. |
| **Identity-provider and EDR actions** | Not integrated. Disabling an account affects CyberShield only; host isolation is approved here and carried out by a person. |
| **SSO (OIDC)** | Not built. |

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

The suite covers authentication and role checks on every route, MFA, the audit chain, alert delivery, the blocklist,
all three SOC tiers, the administrator and analyst workflows, and the Zetaris client against a fake server.

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

- The backend test suite passes, and the image builds and runs its tests on Python 3.13.
- The application has been run against PostgreSQL and a mail catcher in Docker, and each role's UI has been exercised.
- The Zetaris integration has been tested against a fake that follows Zetaris's published API and runs its SQL on
  SQLite. Dialect differences, timestamp formats and page numbering still need confirming against a live instance.
- The scoring thresholds in levels 1 and 2 are heuristics. They have not been validated on real incident data.

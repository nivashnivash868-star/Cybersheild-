# Zetaris integration

CyberShield reads security data **through Zetaris**, which queries your sources where they live, so nothing is
copied into CyberShield except the events it detects. Everything happens server-side; the browser never sees Zetaris
credentials.

## What CyberShield does with it

| Source | Read how | Becomes |
|---|---|---|
| `auth` | A `GROUP BY ... HAVING` runs **inside Zetaris**, so only suspicious (ip, user) pairs come back | Credential Brute Force, or Account Compromise Suspected when a success follows the failures |
| `network` | Flow rows since the last watermark, scored by the network anomaly engine | Port scans, exfiltration and similar |
| `email` | Messages since the last watermark, scored by the phishing engine | Phishing events |

New events go through the normal pipeline: email/SMS alerts, then cross-source correlation into incidents.
`GET /api/v1/zetaris/investigate?indicator=<ip or user>` returns a merged timeline across the sources.

The ingest pass runs in the background every `ZETARIS_INGEST_INTERVAL_SECONDS` (default 60) and can be triggered by
an administrator with `POST /api/v1/zetaris/ingest/run`. Run a single worker: the pass takes an in-process lock only.

## Settings

```
ZETARIS_ORG_ID=            # integer
ZETARIS_API_KEY=           # bearer token for the query APIs (or use username + password below)
ZETARIS_USERNAME=
ZETARIS_PASSWORD=
ZETARIS_BASE_URL=https://api.saas.enterprise.zetaris.com
ZETARIS_TABLE_AUTH=cybershield.auth_logs
ZETARIS_TABLE_NETWORK=cybershield.network_flows
ZETARIS_TABLE_EMAIL=cybershield.email_logs
```

Leave a table unset to skip that source. Use a **read-only** Zetaris account for the credential.

## Default columns

| Table | Columns |
|---|---|
| auth | `event_time` (timestamp), `username`, `src_ip`, `result` (`SUCCESS` or `FAILURE`) |
| network | `event_time`, `src_ip`, `dst_ip`, `dst_port`, `protocol`, `bytes`, `packets` |
| email | `event_time`, `message_id`, `sender`, `recipient`, `subject`, `body` |

If your columns are named differently, map them without code changes:

```
ZETARIS_COLUMNS={"auth": {"username": "account", "event_time": "ts"}}
```

## Trying it with synthetic data

`python backend/scripts/generate_synthetic_logs.py` writes three CSVs of **fabricated** logs with a scripted attack
hidden in ordinary traffic. Load them into Zetaris (as tables or a connected Postgres/S3 source), set the table
settings, and run an ingest. The story: a look-alike-domain phish to `priya.s@enterprise-corp.com`, a port scan and a
failed-login burst from `45.155.205.233` followed by a success, then a ~120 MB transfer to `185.220.101.47`.

## Safety

- Queries are read-only single `SELECT`s; every value embedded in SQL must match a strict whitelist (the API has no
  bind parameters), and table and column names are validated.
- The investigation endpoint accepts only an IP, username or email, and is limited to 30 requests a minute per user.
- Blocks suggested from an investigation are only suggestions: they still go through the blocklist approval workflow.

## Verified and not verified

Tested against an in-memory fake that follows Zetaris's published OpenAPI spec and executes the SQL on SQLite. **Not
yet verified against a live Zetaris instance**: Spark/Trino SQL dialect differences, timestamp formats in returned
records, and page numbering (the client handles a first page numbered from 0 or 1).

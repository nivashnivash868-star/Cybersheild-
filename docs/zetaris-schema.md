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

## Running against the local Zetaris bundle

The hackathon bundle runs Zetaris as Docker containers on your machine. Its REST API is the same one documented for the
cloud, with these local values:

```
ZETARIS_BASE_URL=http://127.0.0.1:8888
ZETARIS_ORG_ID=1
ZETARIS_USERNAME=<the bundle's admin email>      # logging in returns a token that works for queries
ZETARIS_PASSWORD=<the bundle's admin password>   # set in the environment, never committed
ZETARIS_TABLE_AUTH=cybershield.auth_logs
ZETARIS_TABLE_NETWORK=cybershield.network_flows
ZETARIS_TABLE_EMAIL=cybershield.email_logs
ZETARIS_DATA_IS_SYNTHETIC=true                   # marks the data SIMULATED while it is the generated test set
```

Things that are not in Zetaris's public documentation and had to be found out:

- **The query API only accepts `SELECT`.** Creating databases and tables is done over JDBC with the driver jar in the
  bundle (`com.zetaris.lightning.jdbc.LightningDriver`, `jdbc:zetaris:lightning@localhost:10000`), one statement per call.
- **Local files must live under `/home/zetaris/customer-data/shared`** inside the driver container; any other path is
  refused with "Invalid file path to access". Copy CSVs there (`docker cp`), then:

  ```sql
  CREATE LIGHTNING DATABASE cybershield DESCRIBE BY "CyberShield security logs - SYNTHETIC test data";
  CREATE LIGHTNING FILESTORE TABLE auth_logs FROM cybershield FORMAT CSV OPTIONS (
    path "/home/zetaris/customer-data/shared/synthetic/synthetic_auth_logs.csv", header "true", inferSchema "true");
  ```
- **Every value comes back as a string**, timestamps look like `2026-10-28 10:13:12.0`, and the first page is numbered 1.
  The client and the test fake both reflect this.

## Verification

Run against a live local Zetaris (the hackathon bundle) with the generated synthetic data: the client connects and
lists databases, the ingest read all three tables, L1 closed 18 of 23 alerts, L2 correlated the rest into one incident
and called it a true positive at 93% using raw-log evidence from Zetaris, and the investigation view returned the
attacker's 29-entry timeline. Also tested against a fake that follows the published API and returns real-world value
formats. Not yet checked: Zetaris Cloud (the SaaS endpoint), and other dialect behaviour such as very large result
sets.

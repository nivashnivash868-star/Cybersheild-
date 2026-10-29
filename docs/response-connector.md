# Response connector

CyberShield decides and records; your own systems act. When a Security Administrator approves **disabling an account**
or **isolating a host**, CyberShield queues a job and POSTs it, signed, to a webhook you run (a SOAR playbook, a small
service in front of your identity provider, an EDR wrapper). CyberShield holds no IdP or EDR credentials.

Status is reported only as far as it is known:

| Job status | Meaning |
|---|---|
| `QUEUED` | waiting to be sent (or to be retried with backoff) |
| `SENT` | your endpoint accepted the request (HTTP 2xx). **Not** a statement that the action happened |
| `COMPLETED` | your endpoint said it is done, in its reply or in a signed callback |
| `FAILED` | refused (4xx), reported failure, or all attempts failed |
| `UNCONFIRMED` | accepted but nothing reported back within `RESPONSE_WEBHOOK_ACK_MINUTES` (default 60): check the target system |

The incident's response action mirrors this (`QUEUED_FOR_CONNECTOR`, `SENT_TO_CONNECTOR`, `EXECUTED_BY_CONNECTOR`,
`CONNECTOR_FAILED`, `UNCONFIRMED`). With no connector configured, host isolation stays `APPROVED_MANUAL` and account
disabling affects CyberShield only, and the UI says so.

## Configure

```
RESPONSE_WEBHOOK_URL=https://soar.example.org/hooks/cybershield    # https required outside development
RESPONSE_WEBHOOK_SECRET=<32+ random characters, shared with the receiver>
RESPONSE_WEBHOOK_ACTIONS=DISABLE_ACCOUNT,HOST_ISOLATION            # which approvals are forwarded
```

## Request

`POST` JSON, one job per request:

```json
{"job_id":"RJ-3F9A...","action":"HOST_ISOLATION","target":"10.20.4.37","incident_id":"INC-...","decision_id":12,
 "approved_by":"admin@company.com","requested_at":"2026-10-28T20:01:11.123456Z",
 "callback_url":"https://cybershield.example.org/api/v1/response/callback"}
```

Headers: `X-CyberShield-Job: <job_id>`, `X-CyberShield-Signature: t=<unix seconds>,v1=<hex>` where
`v1 = HMAC-SHA256(secret, "<t>." + raw_body)`. Reject requests whose signature does not match or whose `t` is more than 5
minutes old. `job_id` is the idempotency key: the same job may be delivered more than once (retries), so act on it once.

Reply `2xx` to accept. To finish synchronously reply `{"status":"completed","detail":"..."}` (or `"failed"`). Reply `4xx`
to refuse (no retry); `5xx`, `408`, `425`, `429` or a timeout are retried with exponential backoff up to
`RESPONSE_WEBHOOK_MAX_ATTEMPTS` (default 5).

## Callback

When the work is done, `POST` to `callback_url`, signed the same way:

```json
{"job_id":"RJ-3F9A...","result":"succeeded","detail":"EDR isolation applied at 20:02:40"}
```

`result` is `succeeded` or `failed`. A job completes once; a second report gets `409`.

## Try it locally

```bash
export RESPONSE_WEBHOOK_SECRET=$(python3 -c "import secrets;print(secrets.token_urlsafe(32))")
python backend/scripts/example_response_receiver.py --port 9009 &
RESPONSE_WEBHOOK_URL=http://127.0.0.1:9009/hook uvicorn app.main:app --port 8000     # secret must match
```

The example receiver only prints what it would do. Administrators see jobs at `GET /api/v1/response/jobs` and can retry
failed or unconfirmed ones (`POST /response/jobs/{job_id}/retry`). Every state change is in the audit log.

# Testing the integrations against the real thing

Unit tests prove the code handles what each service is documented to send. They cannot prove your account, firewall or
log format works. Administrators can check each integration with a real call:
**Administration → Security configuration → Security integrations → Test** (or
`POST /api/v1/admin/integrations/{email|sms|zetaris|virustotal|abuseipdb|response|sso}/test`). A row says
"Connected" or "Test passed" only after a call really succeeded; "Configured, not verified" means the settings exist and
nothing has been tried. Every test is audited and limited to 10 a minute.

| Integration | What the test does | What a pass proves |
|---|---|---|
| Email | Sends a message to your own address (or `to`) over the configured SMTP server | the server accepted it. Look in the inbox: accepted is not delivered |
| SMS | Texts the number you enter (a few cents; never sent unprompted) | Twilio accepted it. Check the phone |
| Zetaris | Signs in and lists databases | credentials, org id and network path work |
| VirusTotal / AbuseIPDB | Looks up a harmless public indicator | the key is valid and the quota is not exhausted |
| Response connector | Sends a signed `PING` (no job, nothing executed) | the receiver is reachable and accepts the signature |
| Single sign-on | Reads the provider's discovery document and signing keys | issuer and URLs are right. A real sign-in is still needed once |

## Zetaris Cloud

1. Set `ZETARIS_BASE_URL` (default `https://api.saas.enterprise.zetaris.com`), `ZETARIS_ORG_ID` and either
   `ZETARIS_API_KEY` or `ZETARIS_USERNAME` / `ZETARIS_PASSWORD`.
2. Press **Test** on "Zetaris data sources". Then open the Zetaris page: "Connected" is a live round trip.
3. Point `ZETARIS_TABLE_AUTH / _NETWORK / _EMAIL` at your tables and map columns with `ZETARIS_COLUMNS` if yours differ
   (`docs/zetaris-schema.md`).

What has been verified: the local hackathon bundle (REST login, queries, paging, timestamp and string-typed values).
What has not: Zetaris Cloud's tenant-specific behaviour (quotas, API-key lifetime, SQL dialect differences). Expect to
adjust once on first contact, and use the preview below before trusting results.

## Real production logs

`GET /api/v1/zetaris/preview?source=auth|network|email` (administrators) reads the newest rows of a configured table and
**writes nothing**. It reports whether timestamps are understood, how many rows arrived in the last 24 hours, and, for
auth, the outcome values found in the table against `ZETARIS_AUTH_FAILURE_VALUES / _SUCCESS_VALUES`. A failed-login table
that spells failure `4625` finds nothing until you say so, and the preview says that rather than leaving you with an
empty dashboard. Typical first-contact problems it catches: wrong column names, timestamps in local time, an unexpected
outcome vocabulary, non-numeric ports or byte counts.

Before going live also: fit the network model on your own traffic (`NETWORK_BASELINE_CSV`), list backup/update targets
(`NETWORK_TRUSTED_DESTINATIONS`), load a bad-hash feed (`FILE_HASH_FEED_PATH`), and watch the first day's alerts with the
thresholds in Administration before anyone is paged. `docs/detection-evaluation.md` says what was measured and what was
not.

## Threat intelligence

`VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY` enable reputation lookups. Only public IPs, domains and file hashes leave
the system; file contents, private addresses, internal hostnames and (by default) full URLs never do. Answers are cached
for `TI_CACHE_HOURS` and calls respect the free-tier quotas (VirusTotal 4/minute and 500/day, AbuseIPDB 1,000/day),
so a busy SOC on a free key will see "rate-limited" rather than a broken page.

Where it is used: the file analyzer (hash), the URL analyzer and web-gateway check (domain; unknown domains only),
the alert investigation panel (**Check reputation**), `GET /api/v1/threat-intel/lookup?indicator=…` for analysts, and L2
incident investigation (a known-malicious address raises the confidence by 0.10; a clean result never lowers it). A
"clean" reputation does not clear a new phishing page, and "not seen" on VirusTotal means exactly that.

## SMS

Twilio trial accounts can only text verified numbers and prefix messages; a production sender needs a registered number
(country rules apply: A2P 10DLC in the US, sender ID registration elsewhere). `ALERT_SOC_SMS` is used for Critical alerts
only. Test with the button once on your real account; CI cannot do this for you.

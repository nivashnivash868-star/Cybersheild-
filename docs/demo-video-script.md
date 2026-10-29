# Demo video: script, shot list and setup

Target length **4:00** (a 2:30 cut is marked with ✂). Deadline: Thursday 2026-10-29, 23:45 UTC.
Everything on screen is real except the logs, which are generated: say so in the first minute. Judges reward honesty
and punish a demo that claims real telemetry.

## How the script maps to the scoring

| Criterion (points) | Where it is earned | Time on screen |
|---|---|---|
| Meaningful use of Zetaris (25), central and live | Scenes 3 and 4: Zetaris UI, live ingest, the investigation query, our own database next to the raw logs | ~1:30 |
| How it helped you (15), specific moments | Scene 7: four real moments, not praise | ~0:45 |
| Problem and impact (15) | Scenes 1 and 2: alert overload, no shared view of logs, nobody wants to wait for a human at 3 a.m. | ~0:40 |
| Technical execution (15) | Scenes 5 and 6: tiered automation, approvals, signed webhook, audit chain; the test numbers | ~1:00 |
| Working with SpaceXSI (15) | Scene 8, placeholders in brackets for you to fill in | ~0:30 |
| Creativity (10) | The idea: **two humans-in-the-loop tiers on top of a federated query engine**; Zetaris is the SOC's memory | woven through |
| Video quality (5) | Section 6 | |

## 1. One-minute setup (before you record)

```bash
demo/demo.sh up            # builds and starts CyberShield; prints where the login details are
demo/demo.sh refresh-data  # regenerates the logs so the attack happened "in the last 5 hours"
demo/demo.sh export        # copies CyberShield's own SOC data into Zetaris (database cybershield_soc)
demo/demo.sh open          # opens the tabs in the Chrome profile nitikasria@gmail.com
demo/demo.sh code          # the current two-step code (changes every 30 s)
```

Login details are in `~/.cybershield-demo/credentials.txt` (never in the repo). Close other Docker projects first
(`docker ps`): when this laptop is busy Zetaris takes a minute per query, which looks like a hang on camera. Run every
query you plan to show **once before recording** so Zetaris is warm. Wait about three minutes after `up` for the first ingest.

Tabs, in this order:

1. `http://127.0.0.1:8088` CyberShield (signed in as the administrator)
2. `http://localhost:3100` Zetaris UI (sign in with the bundle's admin from `~/zetaris-platform/.env`)
3. `http://127.0.0.1:8025` the mail catcher (shows the alert email arriving)
4. A terminal with `docker ps` and `demo/demo.sh status`

## 2. The script

Narration is in quotes; **bold** is what you click. Speak slower than feels natural.

### Scene 1: the problem (0:00 to 0:25)
**Screen:** title card, then the CyberShield Admin Overview.
> "A security team's evidence is scattered: sign-in logs here, network flows there, email gateway somewhere else. An
> attack is a story across all three, and by the time a person has pulled the three exports together, the attacker has
> been inside for hours. We built CyberShield so the boring ninety percent is handled automatically and a human only
> decides the few things that really matter."

### Scene 2: what it is (0:25 to 0:50)
**Screen:** the architecture sentence from the README (or a simple slide): *Zetaris → events → L1 triage → L2 investigation → L3 human decisions → firewall feed, identity-provider webhook, audit log.*
> "Level one and level two of a security operations centre are fully automated: triage, correlation, investigation.
> Level three is a human. Everything the machine decides carries a reason and a confidence, and anything with real
> consequences, blocking an address, disabling an account, isolating a host, waits for approval. The logs you are about
> to see are generated test data, and the product labels them SIMULATED everywhere."

### Scene 3: Zetaris is the data layer (0:50 to 1:45) ★ 25 points
**Screen:** Zetaris UI (tab 2).
1. **Databases** (or the SQL editor): show `cybershield` with `auth_logs`, `network_flows`, `email_logs`.
> "Three sources, three different shapes: logins, network flows, mail. Zetaris sits in front of them and gives me one SQL surface. CyberShield never copies this data into its own store first."

2. In the SQL editor run (warm it before recording):
```sql
SELECT src_ip, username, COUNT(*) AS failures, MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
FROM cybershield.auth_logs WHERE result = 'FAILURE'
GROUP BY src_ip, username HAVING COUNT(*) >= 5 ORDER BY failures DESC
```
> "This is the shape of the query CyberShield sends every two minutes. About eighteen hundred sign-in rows go in; the engine does the grouping and five rows come back. Four are people mistyping passwords from inside the network, which level one will close on its own. One is fourteen failures from an outside address. That is why it stays fast: the heavy work happens inside Zetaris, not in my application."

3. Switch to CyberShield, **Data Sources (Zetaris)**. Point at **Connected** and the latency.
> "This 'Connected' is not a flag in a settings file. Each time this page loads, CyberShield signs in to Zetaris and lists its databases. If Zetaris is down, this says so."
4. **Test** button on Zetaris in Administration → Security configuration (optional ✂).

### Scene 4: the investigation across all sources (1:45 to 2:20) ★ Zetaris + creativity
**Screen:** CyberShield **Data Sources (Zetaris)** → type `45.155.205.233` → **Investigate**.
> "One address, one question: what has this IP done? CyberShield asks Zetaris, and the answer is one timeline across all three sources: the port scan from the flow table, fourteen failed logins and then a success from the auth table, and the phishing mail that started it. Twenty-nine events in order. Doing this by hand is three exports and a spreadsheet."

Then back in Zetaris UI, run the **federated moment** (checked on the demo data: answers in well under a second):
```sql
SELECT e.source_ip,
       COUNT(DISTINCT e.event_id) AS cybershield_alerts,
       MAX(i.l2_verdict) AS verdict, MAX(i.l2_confidence) AS confidence,
       COUNT(DISTINCT a.event_id) AS raw_failed_logins
FROM cybershield_soc.security_events e
JOIN cybershield_soc.incidents i ON i.incident_id = e.incident_id
JOIN cybershield.auth_logs a ON a.src_ip = e.source_ip AND a.result = 'FAILURE'
WHERE e.source_ip = '45.155.205.233'
GROUP BY e.source_ip
```
> "And the part I like most: CyberShield's own verdicts are in Zetaris too, in a database called cybershield_soc. So one query joins the product's own memory, two alerts and a true-positive verdict at ninety-three percent, with the fourteen raw failed logins behind it, in a different database."

*(If the join is slow on camera, show the two `SELECT COUNT(*)` results from `cybershield_soc` and say it is a snapshot you refresh with one command.)*

### Scene 5: automation and the human decision (2:20 to 3:10) ★ execution
**Screen:** CyberShield **SOC Operations**.
1. Overview strip: "of 23 alerts, level one closed 18 on its own, with a reason on each." Click one **AUTO_CLOSED** event to show the reason and confidence.
2. **Waiting for a human decision**: open **Show the agent's evidence** on the block for `45.155.205.233`. Mention the L2 verdict: *true positive, 93%*, kill chain *Initial Access → Discovery → Credential Access → Exfiltration*.
> "Level two correlated the alerts into one incident and cross-checked the raw logs in Zetaris before deciding. It does not act. It proposes."
3. Click **Approve** on the block, add a note. Show the **Blocklist** page: the entry is live; open the feed URL in the browser tab.
4. Approve **Isolate host 10.20.4.37**. In the terminal run `demo/demo.sh receiver` (it shows the receiver accepting the signed request and calling back), then open `http://127.0.0.1:8088/api/v1/response/jobs` in a browser tab: the job reads `COMPLETED`. (There is no jobs page in the UI, only this API view.)
> "Isolating a host goes to our own automation as a signed request. It only counts as done when that system confirms. If nobody confirms within an hour, the status says UNCONFIRMED instead of pretending."
5. Mail catcher tab: the alert email that went out.

### Scene 6: trust (3:10 to 3:30)
**Screen:** Administration → **Audit log** → **Verify integrity**. Then one slide or the README table.
> "Every decision is in a hash-chained audit log that an administrator can verify. Security administrators and analysts have different powers: an analyst can approve a block but not disable an account. We tested this with 367 automated tests, a fuzzer over every API route, and an end-to-end run against the live Zetaris: 61 checks, all passing. Detection quality is measured and published with its limits: on held-out phishing URLs it flags about two thirds as high risk with a false-alert rate near one in three hundred on unfamiliar sites. That is a triage aid, not a verdict, and the page says so."

### Scene 7: what Zetaris did for us, 45 seconds (3:30 to 4:15)  ★ 15 points, pick 3 or 4
Say them in your own words. Each one really happened:
1. **"It collapsed three integrations into one."** "Without Zetaris I would have written a connector, a schema and a sync job for each log source. Instead the whole integration is about 700 lines: sign in, run SQL, page through results."
2. **"The engine does the aggregation."** "Detecting a brute-force burst is a GROUP BY. Pushing it into Zetaris meant the app receives a handful of rows, not thousands."
3. **"The real thing disagreed with the spec, and finding that was worth it."** "Everything comes back as a string, timestamps look like `2026-10-28 10:13:12.0`, and creating tables only works over JDBC, not the query API. My tests against a fake passed and the live system broke on the first timestamp. Running against real Zetaris early is what made the integration trustworthy."
4. **"Our own database became queryable next to the logs."** "I pointed Zetaris at CyberShield's own incident data, so past verdicts and raw logs can be joined in one place."
5. *(optional honesty beat)* "On a laptop with a lot running, the first query is slow. Warm it and it is fine."
> "Zetaris is the reason the second analyst question, 'what else did this address do', takes one query, not one afternoon."

### Scene 8: working with SpaceXSI's coding agents (4:15 to 4:45; trim scene 7 to fit, or drop ✂ items)
**Fill in the bracketed parts with what actually happened. These are the true facts from this build; swap in your agent's name.**
> "I built this with [SpaceXSI's coding agent / Claude Code]. Three things made the combination work. One: the agent
> read Zetaris's public API spec and wrote the client, then ran it against the live Zetaris on my laptop and fixed what
> the spec did not say: string results, the timestamp format, JDBC-only DDL. Two: it did white-box testing of its own
> work, found eleven defects, and wrote a fuzzer that sends hostile input to every route as every role. Three: when
> I asked for an audit of anything hardcoded or simulated, it found and fixed nine dishonest labels, including an audit log
> that had been recording a fixed name instead of the real user. [One specific moment from your own experience here.]"

### Close (4:45 to 5:00 if you have room; otherwise end Scene 7)
> "CyberShield: automatic where the work is boring, human where it matters, and Zetaris as the memory underneath."

## 3. The 2:30 cut
Scene 1 (0:15), Scene 3 steps 2 and 3 only (0:35), Scene 4 without the join (0:20), Scene 5 steps 2, 3, 4 (0:35), Scene 7 items 1, 3 and 4 (0:30), close (0:15).

## 4. If something goes wrong on camera
| Problem | Do this |
|---|---|
| Zetaris is slow | Say "first query is cold", cut away to the pre-recorded result, or show the second run. Never claim it is instant. |
| Investigate returns nothing | The logs have aged out of the 72-hour window: `demo/demo.sh refresh-data`, wait a minute, retry. |
| Session expired or you are signed out | `demo/demo.sh code`, sign in again (it takes ten seconds and shows MFA). |
| Port or container clash | `demo/demo.sh status`; stop the other Docker projects. |
| Someone asks "is this real data?" | "No: generated logs, labelled SIMULATED. The pipeline is real; pointing it at your tables is a configuration change." |

## 5. Things not to say
- Not "real-time threat detection on live traffic": there is none.
- Not "blocks attacks": it publishes a feed your firewall pulls; enforcement is the firewall's.
- Not "AI decides everything": levels one and two are rules, scoring and small models, explainable, with a human above them.
- Not that SSO, SMS, VirusTotal or Zetaris Cloud were tested live: they were tested against fakes that follow their documentation.

## 6. Recording
1080p or higher, browser zoom 110 to 125 percent, hide bookmarks, one window per scene, mouse slow and deliberate, no
notifications (Do Not Disturb). Record narration separately if you stumble; the on-screen actions are slow enough to talk over.
Keep each scene's mouse path rehearsed once; the Zetaris UI is the slowest tab.

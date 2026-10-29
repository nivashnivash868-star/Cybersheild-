# Detection quality: what was measured

This page replaces the earlier statement that the detectors were "not evaluated". Every number below comes from
`backend/ml/evaluate.py` and `backend/tests/test_pipeline_evaluation.py`; run them to reproduce it. Read the
**limits** under each table: they matter more than the numbers.

## What changed because of the evaluation

| Defect found | Fix |
|---|---|
| Internal and private URLs (`localhost`, `192.168.x.x`, `http://intranet/hr`) were reported as **Critical 95** | URLs are analysed as text only. An internal address is not evidence of phishing; it scores Low. No DNS lookup or fetch happens (a test enforces this). |
| Brand check was a substring search: `firstbank.com` matched "irs", a hosting parent like `vercel.app` was treated as trusted | Brand names are matched as whole words (short brands) with look-alike letters normalised; the brand's real domains are an allow-list; free-hosting parents (pages.dev, vercel.app, github.io…) never inherit trust. |
| The URL model was the *email-text* model (24 sentences) applied to URLs | A character n-gram model trained on real phishing URLs against popular sites; stored as JSON, no pickle. |
| Credential words ("login", "account") added risk even on sites that really have login pages | Ignored on domains in the top-20,000 list; only count on unknown domains. |
| File analyzer scored the empty file and test vectors **90** because their hashes were in the "malicious" list | Removed. Only the EICAR test file is built in. Real hashes come from your own feed (`FILE_HASH_FEED_PATH`). The old WannaCry/Emotet entries could not be verified and were deleted. |
| Any text containing "bitcoin" or "ransom" counted as ransomware | Needs ransom-note phrasing. |
| `cmd /c curl\|wget\|certutil` regex had an alternation bug (bare "wget" matched anywhere) | Fixed and tested. |
| One of `VirtualAlloc` / `WriteProcessMemory` / `CreateRemoteThread` scored 40 | All three steps are required. |
| High entropy flagged every PDF, PNG, ZIP and Office file | Entropy is ignored for formats that are compressed by design; kept for executables and unknown blobs. |
| Network: 5 distinct ports to *anything* = port scan; 3 failed logins = brute force; telnet = "C2"; 5 MB flow = exfiltration | Scan = 10+ ports on one host; brute force = 5+ failures; telnet is "Risky Service Port" (High); exfiltration = 50 MB summed per source/external destination, with an allow-list (`NETWORK_TRUSTED_DESTINATIONS`). |
| Isolation Forest trained on 12 hand-typed flows with 15% contamination | Fitted on a larger generated office-traffic baseline (0.5% contamination), or on your own flows via `NETWORK_BASELINE_CSV`. Results say which baseline was used. |
| Mail rules matched fixed phrases and gave every link +15 | Signal groups (pressure, secrecy, credential request, payment request, run-a-file, lure) with negation handling; embedded links are scored with the URL analyzer. |

## URLs (phishing vs. legitimate)

Data: an OpenPhish community-feed snapshot (300 URLs) against 5,500 URLs built from Tranco top-1M domains drawn from four
popularity buckets (with and without ordinary paths, including `/login`-style ones). The split is by registered domain,
so variants of one phishing kit cannot appear on both sides. Numbers are for the model trained **without** the held-out
domains (63 phishing, 1,100 legitimate URLs).

| Measure | Result |
|---|---|
| Phishing flagged High or above (score ≥ 60) | 63.5% |
| Phishing flagged at least Medium (score ≥ 35) | 81.0% |
| Legitimate, rank 1–10,000, flagged High+ / Medium+ | 0.0% / 0.0% |
| Legitimate, rank 10,001–100,000, flagged High+ / Medium+ | 0.0% / 2.5% |
| Legitimate, rank 100,001–1,000,000, flagged High+ / Medium+ | 0.3% / 1.6% |
| AUC, model alone / rules + model | 0.98 / 0.89 |

Limits:
- 300 phishing URLs from a single feed snapshot is small and skews to what that feed lists (free-hosting pages, parked
  kits). Fresh campaigns on other infrastructure will do worse.
- The legitimate side is domain names with paths we generated; it contains no real deep links. The ~0% false alarms for
  popular domains is partly by design (they are on the trusted list), so the rank 10k–1M rows are the honest ones.
- At a real-world mix (far fewer phishing URLs than legitimate ones) precision will be lower than recall suggests.
- A compromised legitimate site (phishing hosted on a trusted domain) is invisible to this analyzer.
- Retrain with `python -m ml.train_url_model --data <folder>`; get a fresh feed first.

## Messages

Two hand-written sets. `EVAL` (50 messages: 25 fraud, 25 legitimate, including urgent-but-legitimate and
credential-reset notices) was used while shaping the rules, so treat it as a regression set. `BLIND` (12 messages) was
written afterwards and not used for tuning.

| Measure | Result |
|---|---|
| Fraud flagged High+ (≥ 60): recall / precision | 72% / 100% |
| Fraud flagged Medium+ (≥ 35): recall / precision | 88% / 96% (1 false positive) |
| AUC | 0.99 |
| Blind set, correct at ≥ 35 | 12 / 12 |

Limits: these are our own sentences, not a mailbox sample, and the set is small. Expect weaker results on languages other
than English, image-only mail, and well-written targeted fraud. The text model trained on 60 messages is a supporting
signal; the rules and link analysis carry the result.

## Files

- **Constructed samples (22):** 10 with the indicators the analyzer looks for (encoded PowerShell, download command,
  ransom note, credential-dumper strings, injection APIs, executable posing as PDF, macro-enabled workbook, auto-run
  macro, packed executable, EICAR) and 12 ordinary files (empty, text, source, zip, docx-like, pdf, png, jpeg, csv, an
  installer-like executable). All 10 are flagged Medium+, 8 of 10 High+, and none of the 12 ordinary files is flagged.
- **Real ordinary files:** 1,500 files from a Python environment on the development machine (source, compiled
  libraries, images, archives): 0 flagged.

Limits: **no real malware was analysed**, so this shows the rules work as written, not that they catch live threats.
Static analysis cannot see in-memory payloads, and a clean score means "no static indicator", not "safe". Real hash
coverage depends entirely on the feed you load.

## Network

Ordinary traffic comes from the same generator as the default baseline (different seed), 10,000 flows. This tells us
how the model treats traffic like its baseline, **not** how it treats your network.

| Measure | Result |
|---|---|
| False alarms, rules only | 0 / 10,000 |
| False alarms, rules + Isolation Forest | 30 / 10,000 (0.3%) |
| Port scan (25 ports), SSH brute force, 120 MB upload, port 4444, 6×20 MB split upload | all detected |
| Tiny beacon flows to an unusual port | detected as a statistical anomaly |
| One 20 MB upload (under the threshold) | **missed** |
| Browsing across 7 services on many hosts | no alert |

Limits: thresholds are for a typical office. Slow, low-volume attacks (a scan spread over days, a trickle upload) are not
seen because the engine looks at one ingest batch at a time. Fit the anomaly model on your own flows
(`NETWORK_BASELINE_CSV`) and list known backup/update targets in `NETWORK_TRUSTED_DESTINATIONS` before trusting alerts.

## Whole pipeline (ingest → L1 → L2 → human decisions)

Synthetic scenarios with known answers, generated by `scripts/generate_synthetic_logs.py`:

| Scenario | Seeds | Result |
|---|---|---|
| Phishing mail → port scan → failed logins → success → 120 MB exfiltration | 6 | 6/6 incidents judged **true positive**; each produced a block proposal for the attacker, an account-disable proposal, a host-isolation proposal and a disposition request. L1 closed the benign events (6 to 18 per run). |
| Quiet background only | 3 | 0 incidents, 0 decisions |
| User fails 8 logins from their own workstation, then succeeds | 3 | 0 incidents, 0 decisions |
| 20 users with typos at 9 a.m. | 3 | 0 incidents, 0 decisions |
| Legitimate 120 MB nightly backup to a cloud address | 1 | Raised as a question to a human (host isolation, block, disposition), **all PENDING**; with `NETWORK_TRUSTED_DESTINATIONS` set: nothing raised |

Limits: both the attack and the noise were generated by us, so this proves the thresholds are coherent, not that they are
right for a particular real network. The L1 and L2 thresholds are still administrator-tunable (Administration →
Security configuration). Until the platform has run on real logs with analyst feedback, the right claim is "reasonable
defaults with a measured false-alarm profile on synthetic data".

## Reproduce

```bash
cd backend
python -m ml.train_url_model --data <folder with openphish.txt, tranco_all.csv>   # also writes holdout files
python -m ml.evaluate --data <same folder> --benign-files <folder of ordinary files>
python -m pytest tests/test_detection_quality.py tests/test_pipeline_evaluation.py -s
```

`openphish.txt` is a plain list of URLs from the OpenPhish community feed; `tranco_all.csv` is `rank,domain` from the
Tranco list. Both are parsed as text. The shipped data files are `app/detection_data/url_model.json` (model),
`popular_domains.txt` (top 20,000 Tranco domains) and `message_training.json` (60 labelled messages).

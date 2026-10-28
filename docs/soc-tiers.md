# Tiered SOC: automation and human decisions

| Level | Job | Who does it |
|---|---|---|
| **L1** | Alert monitoring, initial triage | **Automated** |
| **L2** | Investigation, correlation, incident analysis | **Automated** |
| **L3** | Advanced hunting, detection engineering, decisions | **People** |

The automated tiers run in the background worker every few seconds and need no one to start them. They never act
outside the platform. Whatever would block traffic, dismiss an incident or change detection logic is handed to a person.

## L1 triage (`soc_automation.run_l1`)
Every new alert gets exactly one outcome, with a rule id, a reason and a confidence:

| Outcome | When |
|---|---|
| `DUPLICATE` | Same category, source and user as an alert in the last 15 minutes |
| `AUTO_CLOSED` | Risk below 35 with nothing corroborating, or a human-approved suppression rule matches |
| `ESCALATED` | Everything else, plus low-risk alerts about an entity that has higher-risk alerts (pattern) |

Guardrails: a suppression rule can never close a Critical alert (risk 85+). A person can reopen anything L1 closed.

## L2 investigation (`soc_automation.run_l2`)
1. **Correlate.** Escalated alerts that share any entity (IP, user, domain) become one incident. A new alert about an
   entity already under investigation joins that incident and triggers a fresh investigation.
2. **Investigate.** Related activity in the last 24h, kill chain and MITRE ATT&CK mapping, context (external addresses,
   similar incidents, employee risk), and raw-log corroboration from Zetaris when configured.
3. **Judge.** A confidence score from risk, kill-chain breadth, number of independent sources and corroboration:
   `TRUE_POSITIVE` (>= 0.70), `FALSE_POSITIVE` (low, single internal source, nothing High), otherwise `NEEDS_HUMAN`.
   Clearly benign incidents are closed automatically; the same benign signature closed repeatedly produces a proposed
   suppression rule.
4. **Propose.** Blocks for attacker addresses and phishing domains (never your own ranges), and manual steps such as
   resetting credentials or isolating a host. Nothing is executed.

## L3 decisions (`/api/v1/soc/decisions`)
Three kinds of request wait for a person (SOC Analyst, Security Administrator or Super Admin):

| Kind | Approve | Reject |
|---|---|---|
| `CONTAINMENT` | Publish the indicator to the blocklist feeds with a TTL | Nothing happens |
| `INCIDENT_DISPOSITION` | Confirm as a true positive | Close as a false positive and withdraw its proposals |
| `DETECTION_RULE` | Activate the rule so L1 applies it | Discard |

Each decision records who decided, when, why (their note) and the outcome, in both the decision and the tamper-evident
audit log. Analysts also write detection rules directly (`/soc/rules`), typically as the outcome of a hunt.

## Transparency
Every automated decision is stored (`agent_runs`) and shown on the SOC Operations page with its reason and confidence.
The overview reports the share of alerts handled without a person.

## Known limits
- Scoring is rule-based and explainable, not learned. The thresholds are heuristics and have not been validated on
  real incident data.
- Linking an attacker to a host depends on shared entities in the alerts. Without a user-to-host mapping (Zetaris auth
  logs provide one when users log in from their own workstation) alerts can stay in separate incidents.
- No LLM is involved. A model could write the narrative or suggest hunts, with the same human gate on actions.

# Roles, dashboards and approvals

Two working roles, each with its own landing page. (A Super Admin is a Security Administrator who can also manage
administrator accounts. Employees only see their own portal.)

## Security Administrator
Lands on **Admin Overview**: total alerts, critical incidents, unresolved threats, active analysts, items awaiting
approval, a "needs your attention" list and system health (database, automation worker, email, SMS, alert delivery,
Zetaris, firewall feeds).

| Area | What they can do |
|---|---|
| Accounts | Create analysts by emailed activation link (the person picks their own password) or a temporary password; activate, deactivate, change role, reset MFA, sign someone out. Only a Super Admin can create or change administrators. |
| Security configuration | Severity thresholds (what L1 closes, what counts as Critical, duplicate window), alert severity for email and SMS, integrations status, alert rules |
| Access control | Role permission matrix; audit log (searchable). Super Admin can verify the audit chain |
| Approvals | High-impact decisions below |

## SOC Analyst
Receives an activation link, signs in, lands on the **SOC dashboard**:

| Module | What it is |
|---|---|
| Security Overview | Events, open incidents, trends, severity and category distribution |
| Critical Alerts | Open High and Critical alerts, unacknowledged first, each with Investigate |
| Threat Investigation | Per alert: evidence, how automation treated it, attack timeline, related alerts, acknowledge |
| Incident Management | Real incident list; acknowledge, assign to a named analyst, notes, change status; the AI risk assessment (verdict, confidence, kill chain, reasoning, proposed response) |

## Automation versus approval

| Automated | Needs a person |
|---|---|
| Event collection and analysis | Confirming a serious incident: **analyst or administrator** |
| Threat detection, risk scoring | Blocking an IP address or domain: **analyst or administrator** |
| Alert generation and prioritisation | Disabling a user account: **administrator** |
| Incident creation and correlation | Isolating a host: **administrator** |
| AI investigation summaries | Closing a Critical incident: analyst **requests**, administrator approves |
| | Creating or changing alert rules: analyst **requests**, administrator approves |

Approvals go to **SOC Operations**. Every approval records who, when, their note and the outcome in the audit log.

## What approval does and does not do
- **Block an IP or domain:** published to the authenticated feeds your firewall pulls. Enforcement happens when it pulls.
- **Disable an account:** deactivates the account in CyberShield and signs it out. CyberShield has no identity-provider
  integration, so disabling it in your IdP remains a manual step, and the record says so.
- **Isolate a host:** records the approval. CyberShield has no EDR or network-access integration, so a responder carries
  it out, and the record says so.

## Simulated data
Anything fabricated (the demo seed, the telemetry pulse, or Zetaris tables marked `ZETARIS_DATA_IS_SYNTHETIC=true`) is
flagged on the event, shown as **SIMULATED** beside it, and announced by a banner on both dashboards.

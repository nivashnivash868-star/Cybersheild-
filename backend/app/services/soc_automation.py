"""The tiered SOC.

  L1  Alert monitoring and initial triage       fully automated   (run_l1)
  L2  Investigation, correlation, analysis      fully automated   (run_l2)
  L3  Advanced hunting, detection engineering   human in the loop (decide, rules, hunts)

Automation never changes anything outside the platform on its own. L1 closes or escalates alerts, L2 investigates and
*proposes*, and every proposal that would block traffic, dismiss an incident or change detection logic becomes a
DecisionRequest that a human approves or rejects. All automated decisions are logged (AgentRun) with a reason and a
confidence, and are reversible.
"""
import ipaddress
import json
import logging
import time
from datetime import timedelta
from typing import Any, Dict, List, Optional

from fastapi import HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.config import settings
from app.models import (
    AgentRun, AuditLog, DecisionRequest, DetectionRule, Employee, Incident, ResponseAction, SecurityEvent, User,
    BlocklistEntry, UserSession, naive_utc_now,
)
from app.utils.auth import ADMIN_ROLES
from app.services import blocklist as blocklist_service
from app.services import enrichment, response_executor, settings_store
from app.services.alert_engine import alert_engine
from app.services.correlation_engine import correlation_engine

logger = logging.getLogger("cybershield.soc")

L1_AGENT = "agent:L1-triage"
L2_AGENT = "agent:L2-investigator"
LOW_RISK = 35          # defaults; administrators can change them (settings_store)
CRITICAL_RISK = 85     # at or above this, no rule may suppress the alert
# Decisions only an administrator may make: high-impact, or changing how the platform detects.
ADMIN_ONLY_KINDS = {"DISABLE_ACCOUNT", "HOST_ISOLATION", "INCIDENT_CLOSURE", "DETECTION_RULE"}
RULE_KEYS = {"category_contains", "source_ip", "user", "source_contains", "max_risk"}

# category keyword -> (kill-chain stage, MITRE ATT&CK technique)
KILL_CHAIN = [
    (("impersonation", "wire fraud", "bec"), "Initial Access", "T1566 Phishing (business email compromise)"),
    (("sql injection", "web shell", "exploit", "xss", "path traversal"), "Initial Access", "T1190 Exploit Public-Facing Application"),
    (("dns tunnel", "dga", "fast-flux"), "Command and Control", "T1071.004 Application Layer Protocol: DNS"),
    (("memory injection", "process injection", "hollowing"), "Execution", "T1055 Process Injection"),
    (("script execution", "payload execution", "macro"), "Execution", "T1059 Command and Scripting Interpreter"),
    (("credential stuffing", "password spray"), "Credential Access", "T1110.004 Credential Stuffing"),
    (("phish", "credential harvest"), "Initial Access", "T1566 Phishing"),
    (("compromise", "valid account"), "Initial Access", "T1078 Valid Accounts"),
    (("brute", "password spray"), "Credential Access", "T1110 Brute Force"),
    (("recon", "scan"), "Discovery", "T1046 Network Service Discovery"),
    (("c2", "backdoor", "beacon"), "Command and Control", "T1071 Application Layer Protocol"),
    (("exfil", "traffic spike", "egress"), "Exfiltration", "T1041 Exfiltration Over C2 Channel"),
    (("malware", "dropper", "ransom"), "Execution", "T1204 User Execution"),
    (("secret", "leak", "dlp", "credential exposure"), "Collection", "T1552 Unsecured Credentials"),
]
STAGE_ORDER = ["Initial Access", "Execution", "Credential Access", "Discovery", "Command and Control", "Collection",
               "Exfiltration", "Unclassified"]


def _log(db: Session, tier: str, agent: str, subject_type: str, subject_id: str, decision: str, reason: str,
         confidence: Optional[float], started: float) -> None:
    db.add(AgentRun(tier=tier, agent=agent, subject_type=subject_type, subject_id=subject_id, decision=decision,
                    reason=reason[:2000], confidence=confidence, duration_ms=int((time.monotonic() - started) * 1000)))


# =====================================================================================================================
# Detection rules (detection engineering)
# =====================================================================================================================
def validate_match(match: Dict[str, Any], kind: str, critical: int = CRITICAL_RISK) -> Dict[str, Any]:
    if not isinstance(match, dict) or not match:
        raise HTTPException(422, "A rule needs at least one condition.")
    unknown = set(match) - RULE_KEYS
    if unknown:
        raise HTTPException(422, f"Unknown condition(s): {sorted(unknown)}. Allowed: {sorted(RULE_KEYS)}.")
    clean: Dict[str, Any] = {}
    for k, v in match.items():
        if k == "max_risk":
            if not isinstance(v, int) or not 0 <= v <= 100:
                raise HTTPException(422, "max_risk must be an integer from 0 to 100.")
            clean[k] = v
        else:
            if not isinstance(v, str) or not v.strip() or len(v) > 128:
                raise HTTPException(422, f"{k} must be a non-empty string of at most 128 characters.")
            clean[k] = v.strip()
    if not (set(clean) & {"category_contains", "source_ip", "user", "source_contains"}):
        raise HTTPException(422, "Name what to match: category_contains, source_ip, user or source_contains.")
    if kind == "SUPPRESS" and clean.get("max_risk", 100) >= critical:
        clean["max_risk"] = critical - 1  # guardrail: suppression can never hide Critical alerts
    return clean


def rule_matches(match: Dict[str, Any], ev: SecurityEvent) -> bool:
    if not match:
        return False
    if "category_contains" in match and match["category_contains"].lower() not in (ev.threat_category or "").lower():
        return False
    if "source_contains" in match and match["source_contains"].lower() not in (ev.event_source or "").lower():
        return False
    if "source_ip" in match and ev.source_ip != match["source_ip"]:
        return False
    if "user" in match and (ev.user_account or "").lower() != match["user"].lower():
        return False
    if "max_risk" in match and ev.risk_score > int(match["max_risk"]):
        return False
    return True


# =====================================================================================================================
# L1: alert monitoring and initial triage
# =====================================================================================================================
def _eq(column, value):
    return column.is_(None) if value is None else column == value


def _conclude(ev: SecurityEvent, status: str, rule: str, reason: str, confidence: float, dup_of: Optional[str] = None) -> None:
    ev.triage_status, ev.triage_rule, ev.triage_reason, ev.triage_confidence = status, rule, reason[:500], confidence
    ev.triaged_at, ev.duplicate_of = naive_utc_now(), dup_of
    if status in ("AUTO_CLOSED", "DUPLICATE"):
        ev.analysis_status = "Closed"


def triage_event(db: Session, ev: SecurityEvent, rules: List[tuple], cfg: Optional[Dict[str, int]] = None) -> str:
    cfg = cfg or {"low": LOW_RISK, "critical": CRITICAL_RISK, "window": 15}
    low, critical, window = cfg["low"], cfg["critical"], timedelta(minutes=cfg["window"])
    started = time.monotonic()
    now = naive_utc_now()

    for rule, match in rules:                                           # 1. human-authored ESCALATE rules
        if rule.kind == "ESCALATE" and rule_matches(match, ev):
            rule.hit_count, rule.last_hit_at = rule.hit_count + 1, now
            _conclude(ev, "ESCALATED", f"RULE-{rule.id}", f"Matched detection rule '{rule.name}'.", 0.9)
            break
    else:
        suppressed = None
        if ev.risk_score < critical:                                    # 2. SUPPRESS rules, never for Critical
            for rule, match in rules:
                if rule.kind == "SUPPRESS" and rule_matches(match, ev):
                    suppressed = rule
                    break
        if suppressed is not None:
            suppressed.hit_count, suppressed.last_hit_at = suppressed.hit_count + 1, now
            _conclude(ev, "AUTO_CLOSED", f"RULE-{suppressed.id}",
                      f"Closed by detection rule '{suppressed.name}' (approved by {suppressed.created_by}).", 0.9)
        else:
            earlier = db.query(SecurityEvent).filter(                   # 3. duplicate of a recent alert
                SecurityEvent.id < ev.id, SecurityEvent.triage_status != "DUPLICATE",
                SecurityEvent.threat_category == ev.threat_category,
                _eq(SecurityEvent.source_ip, ev.source_ip), _eq(SecurityEvent.user_account, ev.user_account),
                SecurityEvent.timestamp >= ev.timestamp - window,
                SecurityEvent.timestamp <= ev.timestamp + window,
            ).order_by(SecurityEvent.id.desc()).first()
            if earlier is not None:
                _conclude(ev, "DUPLICATE", "L1-DUPLICATE", f"Same alert as {earlier.event_id} within {cfg['window']} minutes.", 0.95,
                          earlier.event_id)
            elif ev.risk_score < low:                                   # 4. low risk, unless part of a pattern
                pattern = False
                if ev.source_ip or ev.user_account:
                    pattern = db.query(SecurityEvent.id).filter(
                        SecurityEvent.id != ev.id, SecurityEvent.risk_score >= low,
                        SecurityEvent.timestamp >= now - timedelta(hours=24),
                        (SecurityEvent.source_ip == ev.source_ip) if ev.source_ip else (SecurityEvent.user_account == ev.user_account),
                    ).first() is not None
                if pattern:
                    _conclude(ev, "ESCALATED", "L1-PATTERN", "Low risk alone, but the same entity has higher-risk alerts in the last 24h.", 0.7)
                else:
                    _conclude(ev, "AUTO_CLOSED", "L1-LOWRISK", f"Risk score {ev.risk_score} is below {low} with no corroborating alerts.", 0.7)
            else:                                                       # 5. everything else goes to L2
                _conclude(ev, "ESCALATED", "L1-ESCALATE", f"{ev.severity} alert (risk {ev.risk_score}) needs investigation.", 0.8)

    _log(db, "L1", L1_AGENT, "event", ev.event_id, ev.triage_status, f"[{ev.triage_rule}] {ev.triage_reason}",
         ev.triage_confidence, started)
    return ev.triage_status


def run_l1(db: Session, limit: int = 300) -> Dict[str, int]:
    pending = db.query(SecurityEvent).filter(SecurityEvent.triage_status == "NEW").order_by(SecurityEvent.id).limit(limit).all()
    if not pending:
        return {"triaged": 0}
    rules = []
    for r in db.query(DetectionRule).filter(DetectionRule.enabled.is_(True)).all():
        try:
            rules.append((r, json.loads(r.match_json)))
        except ValueError:
            continue
    cfg = {"low": settings_store.get(db, "l1_low_risk_threshold"), "critical": settings_store.get(db, "l1_critical_threshold"),
           "window": settings_store.get(db, "l1_duplicate_window_minutes")}
    counts: Dict[str, int] = {"triaged": 0}
    for ev in pending:
        status = triage_event(db, ev, rules, cfg)
        counts[status.lower()] = counts.get(status.lower(), 0) + 1
        counts["triaged"] += 1
        db.flush()  # later events in the batch must see earlier decisions (duplicates)
    db.commit()
    return counts


# =====================================================================================================================
# L2: investigation, correlation, incident analysis
# =====================================================================================================================
def classify(category: str) -> tuple:
    low = (category or "").lower()
    for keys, stage, technique in KILL_CHAIN:
        if any(k in low for k in keys):
            return stage, technique
    return "Unclassified", None


def _is_global(ip: Optional[str]) -> bool:
    try:
        return bool(ip) and ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _pivot(ev: SecurityEvent) -> tuple:
    if ev.source_ip:
        return "IP Address", ev.source_ip
    if ev.user_account:
        return "User Account", ev.user_account
    if ev.domain:
        return "Domain", ev.domain
    return "Sensor", ev.event_source


def _entity_keys(ev: SecurityEvent) -> List[tuple]:
    keys = []
    if ev.source_ip:
        keys.append(("ip", ev.source_ip))
    if ev.dest_ip and _is_global(ev.dest_ip):          # a shared *external* destination links alerts; an internal one doesn't
        keys.append(("ip", ev.dest_ip))
    if ev.user_account:
        keys.append(("user", ev.user_account.lower()))
    if ev.domain:
        keys.append(("domain", ev.domain.lower()))
    return keys


def _attach_to_open_incident(db: Session, ev: SecurityEvent) -> Optional[Incident]:
    """New alert about an entity already under investigation: add it to that incident and investigate again."""
    since = naive_utc_now() - timedelta(hours=24)
    for kind, value in _entity_keys(ev):
        col = {"ip": SecurityEvent.source_ip, "user": SecurityEvent.user_account, "domain": SecurityEvent.domain}[kind]
        match = db.query(Incident).join(SecurityEvent, SecurityEvent.incident_id == Incident.incident_id).filter(
            func.lower(col) == value.lower(), SecurityEvent.id != ev.id, SecurityEvent.timestamp >= since,
            Incident.status.notin_(("False Positive", "Resolved"))).order_by(Incident.id.desc()).first()
        if match is not None:
            ev.incident_id, ev.analysis_status = match.incident_id, "Correlated"
            match.l2_status = "PENDING"
            match.updated_at = naive_utc_now()
            return match
    return None


def _open_incidents_for_escalated(db: Session) -> int:
    """L2 correlation: alerts that share any entity (IP, user, domain) become one incident."""
    escalated = db.query(SecurityEvent).filter(SecurityEvent.triage_status == "ESCALATED",
                                               SecurityEvent.incident_id.is_(None)).order_by(SecurityEvent.id).all()
    if not escalated:
        return 0
    remaining = [e for e in escalated if _attach_to_open_incident(db, e) is None]
    parent = {e.id: e.id for e in remaining}

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    owner: Dict[tuple, int] = {}
    for e in remaining:
        for key in _entity_keys(e):
            if key in owner:
                parent[find(e.id)] = find(owner[key])
            else:
                owner[key] = e.id
    clusters: Dict[int, List[SecurityEvent]] = {}
    for e in remaining:
        clusters.setdefault(find(e.id), []).append(e)

    created = 0
    for members in clusters.values():
        counts: Dict[tuple, int] = {}
        for e in members:
            for key in set(_entity_keys(e)):
                counts[key] = counts.get(key, 0) + 1
        if counts:
            kind, value = max(counts, key=lambda k: (counts[k], k[0] == "ip"))
            ptype = {"ip": "IP Address", "user": "User Account", "domain": "Domain"}[kind]
        else:
            ptype, value = "Sensor", members[0].event_source
        sources, categories = {e.event_source for e in members}, {e.threat_category for e in members}
        inc, _ = correlation_engine._create_correlated_incident(db, members, ptype, value, sources, categories)
        if len(members) == 1:
            inc.title = f"{members[0].threat_category} involving {value}"
            inc.description = f"Single escalated alert from {members[0].event_source}: {members[0].evidence[:300]}"
        created += 1
    db.flush()
    return created


def _zetaris_evidence(entities: List[str]) -> Dict[str, Any]:
    """Cross-source facts from Zetaris for the top entities. Never raises: an outage becomes a finding."""
    if not (settings.zetaris_configured):
        return {"available": False, "reason": "Zetaris is not configured."}
    from app.services import zetaris_ingest
    from app.services.zetaris import ZetarisClient, ZetarisError
    if not zetaris_ingest.configured_sources():
        return {"available": False, "reason": "No Zetaris tables are configured."}
    results = []
    try:
        with ZetarisClient() as client:
            for entity in entities[:2]:
                try:
                    r = zetaris_ingest.investigate(client, entity, limit=100)
                    results.append({"entity": entity, "stats": r["stats"], "sources": r["sources_queried"],
                                    "timeline_entries": len(r["timeline"])})
                except ValueError:
                    continue
    except ZetarisError as exc:
        return {"available": False, "reason": f"Zetaris query failed: {exc}"}
    return {"available": True, "results": results}


def _blockable(db: Session, indicator: str) -> Optional[str]:
    """None when it can be proposed for blocking, else the reason it can't."""
    try:
        _, value = blocklist_service.normalise_indicator(indicator)
    except HTTPException as exc:
        return str(exc.detail)
    if db.query(BlocklistEntry.id).filter(BlocklistEntry.value == value,
                                          BlocklistEntry.status.in_(("PENDING_APPROVAL", "ACTIVE"))).first():
        return "Already on the blocklist or awaiting approval."
    if db.query(DecisionRequest.id).filter(DecisionRequest.kind == "CONTAINMENT", DecisionRequest.status == "PENDING",
                                           DecisionRequest.title == f"Block {value}").first():
        return "A decision to block it is already pending."
    return None


def investigate_incident(db: Session, inc: Incident) -> Dict[str, Any]:
    started = time.monotonic()
    events = list(inc.events)
    now = naive_utc_now()
    steps: List[Dict[str, Any]] = []

    # --- entities -----------------------------------------------------------------------------------------------
    ips = sorted({ip for e in events for ip in (e.source_ip, e.dest_ip) if ip})
    users = sorted({e.user_account for e in events if e.user_account})
    domains = sorted({e.domain for e in events if e.domain})
    sources = sorted({e.event_source for e in events})
    steps.append({"step": "Entities", "finding": f"{len(events)} alert(s) from {len(sources)} source(s) involving "
                  f"{len(ips)} IP(s), {len(users)} user(s), {len(domains)} domain(s).",
                  "data": {"ips": ips, "users": users, "domains": domains, "sources": sources}})

    # --- related activity ---------------------------------------------------------------------------------------
    related = 0
    for ent_col, vals in ((SecurityEvent.source_ip, ips), (SecurityEvent.dest_ip, ips), (SecurityEvent.user_account, users)):
        for v in vals[:5]:
            related += db.query(SecurityEvent.id).filter(
                ent_col == v, SecurityEvent.incident_id != inc.incident_id, SecurityEvent.timestamp >= now - timedelta(hours=24),
                SecurityEvent.triage_status != "DUPLICATE").count()
    steps.append({"step": "Related activity (24h)", "finding": f"{related} other alert(s) involve the same entities.", "data": {"count": related}})

    # --- kill chain ---------------------------------------------------------------------------------------------
    chain: Dict[str, List[str]] = {}
    for e in events:
        stage, technique = classify(e.threat_category)
        chain.setdefault(stage, [])
        label = f"{technique or e.threat_category}"
        if label not in chain[stage]:
            chain[stage].append(label)
    stages = [s for s in STAGE_ORDER if s in chain]
    known_stages = [s for s in stages if s != "Unclassified"]
    steps.append({"step": "Kill chain", "finding": (" → ".join(known_stages) if known_stages else "No recognised attack stage."),
                  "data": {s: chain[s] for s in stages}})

    # --- enrichment ---------------------------------------------------------------------------------------------
    external = [ip for ip in ips if _is_global(ip)]
    emp = db.query(Employee).filter(Employee.company_email.in_(users)).first() if users else None
    prior = db.query(Incident.id).filter(Incident.id != inc.id, Incident.threat_category == inc.threat_category,
                                         Incident.created_at >= now - timedelta(days=30)).count()
    steps.append({"step": "Context", "finding": f"{len(external)} external address(es); {prior} similar incident(s) in 30 days"
                  + (f"; affected employee risk score {emp.risk_score}" if emp else "") + ".",
                  "data": {"external_ips": external, "similar_incidents_30d": prior}})

    # --- reputation (VirusTotal / AbuseIPDB) -----------------------------------------------------------------
    rep = enrichment.evidence_for_ips(db, external)
    if rep["available"] and rep["results"]:
        flagged = [r["ip"] for r in rep["results"] if r["malicious"]]
        steps.append({"step": "Reputation (threat intelligence)", "data": rep,
                      "finding": (f"Known malicious: {', '.join(flagged)}. " if flagged else "No address is known malicious. ")
                      + " ".join(f"{r['ip']}: {r['summary']}" for r in rep["results"])[:600]})
    else:
        steps.append({"step": "Reputation (threat intelligence)", "data": rep,
                      "finding": f"Skipped: {rep.get('reason', 'no external address to look up')}"})
    known_bad = bool(rep.get("known_bad"))

    # --- cross-source evidence (Zetaris) ------------------------------------------------------------------------
    focus = ([external[0]] if external else []) + users[:1]
    z = _zetaris_evidence(focus) if focus else {"available": False, "reason": "No entity to query."}
    corroborated = False
    if z["available"]:
        for r in z["results"]:
            s = r["stats"]
            if s.get("failed_logins", 0) >= settings.ZETARIS_BRUTE_FORCE_THRESHOLD or s.get("bytes_transferred", 0) > 50_000_000 \
                    or s.get("flows", 0) >= 10 or r["timeline_entries"] >= 8:
                corroborated = True
        steps.append({"step": "Cross-source evidence (Zetaris)", "finding": ("Corroborated by raw logs." if corroborated
                      else "Raw logs show no additional activity."), "data": z})
    else:
        steps.append({"step": "Cross-source evidence (Zetaris)", "finding": f"Skipped: {z['reason']}", "data": z})

    # --- verdict -------------------------------------------------------------------------------------------------
    max_risk = max((e.risk_score for e in events), default=0)
    max_sev_high = any(e.severity in ("High", "Critical") for e in events)
    score = (max_risk / 100) * 0.45 + (min(len(known_stages), 4) / 4) * 0.25 + (min(len(sources), 3) / 3) * 0.15 \
        + (0.15 if (corroborated or related >= 3) else 0.0) + (0.10 if known_bad else 0.0)
    score = round(min(score, 0.99), 2)
    if score >= 0.7:
        verdict = "TRUE_POSITIVE"
    elif score < 0.35 and not external and len(sources) == 1 and not max_sev_high:
        verdict = "FALSE_POSITIVE"
    else:
        verdict = "NEEDS_HUMAN"
    steps.append({"step": "Verdict", "finding": f"{verdict.replace('_', ' ').title()} (confidence {score:.0%}).",
                  "data": {"score": score, "max_risk": max_risk, "stages": len(known_stages), "sources": len(sources)}})

    # --- recommended response ------------------------------------------------------------------------------------
    containment: List[Dict[str, Any]] = []
    manual: List[Dict[str, str]] = []
    if verdict != "FALSE_POSITIVE":
        attackers = []
        for e in events:
            stage, _ = classify(e.threat_category)
            if e.source_ip and stage in ("Credential Access", "Discovery", "Initial Access", "Command and Control") and _is_global(e.source_ip):
                attackers.append(e.source_ip)
            if e.dest_ip and stage in ("Exfiltration", "Command and Control") and _is_global(e.dest_ip):
                attackers.append(e.dest_ip)
        for ip in sorted(set(attackers)):
            why = _blockable(db, ip)
            if why:
                steps.append({"step": "Containment", "finding": f"Not proposing a block for {ip}: {why}", "data": {}})
                continue
            containment.append({"action": "BLOCKLIST", "indicator": ip, "ttl_hours": settings.BLOCKLIST_DEFAULT_TTL_HOURS,
                                "reason": f"{inc.incident_id}: {inc.title}"})
        for d in domains:
            is_phish = any("phish" in e.threat_category.lower() for e in events if e.domain == d)
            if is_phish and not _blockable(db, d):
                containment.append({"action": "BLOCKLIST", "indicator": d, "ttl_hours": settings.BLOCKLIST_DEFAULT_TTL_HOURS,
                                    "reason": f"Phishing infrastructure in {inc.incident_id}"})
        for e in events:
            stage, _ = classify(e.threat_category)
            if "compromise" in e.threat_category.lower() and e.user_account:
                manual.append({"type": "RESET_CREDENTIALS", "target": e.user_account,
                               "details": "Force a password reset and revoke active sessions for this account."})
            if stage == "Exfiltration" and e.source_ip and not _is_global(e.source_ip):
                manual.append({"type": "HOST_ISOLATION", "target": e.source_ip,
                               "details": "Isolate this host from the network and capture memory before reimaging."})
        seen = set()
        manual = [m for m in manual if not ((m["type"], m["target"]) in seen or seen.add((m["type"], m["target"])))]
        steps.append({"step": "Recommended response", "finding": (f"Propose {len(containment)} block(s)" if containment else "No automatic block applies")
                      + (f"; {len(manual)} manual step(s) for the responder." if manual else "."),
                      "data": {"containment": containment, "manual": manual}})

    # --- narrative -----------------------------------------------------------------------------------------------
    headline = {"TRUE_POSITIVE": "This is very likely a genuine attack.", "NEEDS_HUMAN": "The evidence is inconclusive or high-impact, so a person must decide.",
                "FALSE_POSITIVE": "This looks like benign activity."}[verdict]
    summary = (f"{headline} {len(events)} alert(s) from {', '.join(sources)}"
               + (f" follow the kill chain {' → '.join(known_stages)}" if len(known_stages) > 1 else (f" show {known_stages[0]}" if known_stages else ""))
               + f". Highest risk {max_risk}/100; confidence {score:.0%}."
               + (f" Raw logs from Zetaris corroborate it." if corroborated else "")
               + (f" Recommended: {len(containment)} block(s) awaiting approval." if containment else ""))

    analysis = {"verdict": verdict, "confidence": score, "kill_chain": {s: chain[s] for s in stages}, "steps": steps,
                "containment": containment, "manual_actions": manual,
                "zetaris_used": bool(z.get("available"))}
    inc.l2_status, inc.l2_verdict, inc.l2_confidence = "DONE", verdict, score
    inc.l2_summary, inc.l2_analysis, inc.l2_completed_at = summary, json.dumps(analysis, default=str), now
    inc.risk_score = max(inc.risk_score, min(99, int(max_risk + (len(known_stages) - 1) * 4))) if len(known_stages) > 1 else inc.risk_score
    inc.severity = "Critical" if inc.risk_score >= 80 else "High" if inc.risk_score >= 60 else inc.severity

    if verdict == "FALSE_POSITIVE":
        inc.status, inc.disposition, inc.needs_human, inc.l3_status = "False Positive", "AUTO_FALSE_POSITIVE", False, "NONE"
        for e in events:
            e.analysis_status = "Closed"
        _propose_rule_from_false_positives(db, inc, events)
    else:
        inc.status = "Investigating" if inc.status == "New" else inc.status
        inc.needs_human, inc.l3_status = True, "AWAITING_DECISION"
        _open_decisions(db, inc, summary, steps, containment, manual, verdict, score)

    _log(db, "L2", L2_AGENT, "incident", inc.incident_id, verdict, summary, score, started)
    db.add(AuditLog(action="L2_INVESTIGATION", actor=L2_AGENT, resource_type="Incident", resource_id=inc.incident_id,
                    details=f"Verdict {verdict} ({score:.0%}). {len(containment)} containment proposal(s)."))
    return analysis


def _open_decisions(db: Session, inc: Incident, summary: str, steps: List[Dict[str, Any]], containment: List[Dict[str, Any]],
                    manual: List[Dict[str, str]], verdict: str, score: float) -> None:
    facts = [f"{s['step']}: {s['finding']}" for s in steps]
    has_pending = db.query(DecisionRequest.id).filter(
        DecisionRequest.incident_id == inc.incident_id, DecisionRequest.kind == "INCIDENT_DISPOSITION",
        DecisionRequest.status == "PENDING").first() is not None
    if not has_pending:
        db.add(DecisionRequest(
            kind="INCIDENT_DISPOSITION", incident_id=inc.incident_id, priority=inc.severity,
            title=f"Confirm or dismiss: {inc.title}"[:255], rationale=summary, evidence=json.dumps(facts),
            proposal=json.dumps({"on_approve": "Confirm as a true positive and keep it open for response.",
                                 "on_reject": "Dismiss as a false positive and close it.", "agent_verdict": verdict,
                                 "confidence": score, "manual_actions": manual}),
            created_by=L2_AGENT))
    for m in manual:
        kind = {"RESET_CREDENTIALS": "DISABLE_ACCOUNT", "HOST_ISOLATION": "HOST_ISOLATION"}.get(m["type"])
        if kind is None:
            continue
        title = f"Disable account {m['target']}" if kind == "DISABLE_ACCOUNT" else f"Isolate host {m['target']}"
        if db.query(DecisionRequest.id).filter(DecisionRequest.kind == kind, DecisionRequest.status == "PENDING",
                                               DecisionRequest.title == title).first():
            continue
        db.add(DecisionRequest(
            kind=kind, incident_id=inc.incident_id, priority=inc.severity, title=title,
            rationale=f"Proposed by L2 for {inc.incident_id}. {m['details']} Administrator approval is required because this affects a person or a device.",
            evidence=json.dumps(facts),
            proposal=json.dumps({"account": m["target"]} if kind == "DISABLE_ACCOUNT" else {"host": m["target"]}),
            created_by=L2_AGENT))
    for c in containment:
        db.add(DecisionRequest(
            kind="CONTAINMENT", incident_id=inc.incident_id, priority=inc.severity,
            title=f"Block {c['indicator']}"[:255],
            rationale=f"Proposed by L2 for {inc.incident_id}. {c['reason']}", evidence=json.dumps(facts), proposal=json.dumps(c),
            created_by=L2_AGENT))
    if inc.severity in ("High", "Critical"):
        alert_engine.dispatch_security_alert(
            db, title=f"Decision required: {inc.title}"[:200], sanitized_summary=summary[:500], severity=inc.severity,
            incident_id=inc.incident_id)


def _propose_rule_from_false_positives(db: Session, inc: Incident, events: List[SecurityEvent]) -> None:
    """Detection engineering: the same benign signature closed repeatedly is a candidate suppression rule."""
    if not events:
        return
    ev = events[0]
    sig = {"category_contains": ev.threat_category, "max_risk": 60}
    if ev.source_ip:
        sig["source_ip"] = ev.source_ip
    elif ev.user_account:
        sig["user"] = ev.user_account
    else:
        return
    similar = db.query(Incident).filter(Incident.id != inc.id, Incident.l2_verdict == "FALSE_POSITIVE",
                                        Incident.threat_category == inc.threat_category).count()
    if similar < 2:
        return
    sig_json = json.dumps(sig, sort_keys=True)
    for r in db.query(DetectionRule).filter(DetectionRule.kind == "SUPPRESS").all():
        if r.match_json == sig_json:
            return
    for d in db.query(DecisionRequest).filter(DecisionRequest.kind == "DETECTION_RULE", DecisionRequest.status == "PENDING").all():
        if json.loads(d.proposal).get("match_json") == sig_json:
            return
    db.add(DecisionRequest(
        kind="DETECTION_RULE", priority="Low", title=f"Suppress repeat false positive: {ev.threat_category}"[:255],
        rationale=f"L2 has now dismissed {similar + 1} incidents with this signature as benign. A rule would let L1 close them "
                  "without investigation. Critical alerts are never suppressed.",
        evidence=json.dumps([f"Signature: {sig}"]),
        proposal=json.dumps({"name": f"Suppress {ev.threat_category} ({sig.get('source_ip') or sig.get('user')})"[:128],
                             "kind": "SUPPRESS", "match": sig, "match_json": sig_json}),
        created_by=L2_AGENT))


def run_l2(db: Session, limit: int = 20) -> Dict[str, int]:
    created = _open_incidents_for_escalated(db)
    db.commit()
    pending = db.query(Incident).filter(Incident.l2_status == "PENDING").order_by(Incident.id).limit(limit).all()
    done = 0
    for inc in pending:
        try:
            investigate_incident(db, inc)
            db.commit()
            done += 1
        except Exception:
            db.rollback()
            logger.exception("L2 investigation of %s failed", inc.incident_id)
    return {"incidents_opened": created, "investigated": done}


def run_cycle(db: Session) -> Dict[str, Any]:
    """One pass of the automated tiers. Safe to run repeatedly."""
    out: Dict[str, Any] = {}
    out["l1"] = run_l1(db)
    out["l2"] = run_l2(db)
    return out


# =====================================================================================================================
# L3: human decisions
# =====================================================================================================================
def decide(db: Session, req: DecisionRequest, user: User, decision: str, note: Optional[str]) -> DecisionRequest:
    if req.status != "PENDING":
        raise HTTPException(409, f"This decision was already {req.status.lower()} by {req.decided_by}.")
    if req.kind in ADMIN_ONLY_KINDS and user.role not in ADMIN_ROLES:
        raise HTTPException(403, "This decision needs a Security Administrator: it is high-impact or changes security configuration.")
    if decision not in ("approve", "reject"):
        raise HTTPException(422, "decision must be 'approve' or 'reject'.")
    approve = decision == "approve"
    proposal = json.loads(req.proposal)
    inc = db.query(Incident).filter(Incident.incident_id == req.incident_id).first() if req.incident_id else None
    outcome = "Rejected." if not approve else ""

    if req.kind == "CONTAINMENT" and approve:
        entry, created = blocklist_service.propose(
            db, proposal["indicator"], proposal.get("reason", req.title), user.email, auto_approve=True,
            incident_id=req.incident_id, ttl_hours=proposal.get("ttl_hours"))
        outcome = f"Blocklist entry #{entry.id} {'published' if created else 'already existed'} until {entry.expires_at} UTC."
        if inc is not None:
            db.add(ResponseAction(incident_id=inc.incident_id, action_type="IP_BLOCK" if entry.indicator_type in ("ip", "cidr") else "URL_BLOCK",
                                  target=entry.value, status="PUBLISHED_TO_FEED", details=f"Approved by {user.email} (L3).",
                                  is_simulated=False, executed_by=user.email, executed_at=naive_utc_now()))
            if inc.status in ("New", "Investigating"):
                inc.status = "Contained"
    elif req.kind == "INCIDENT_DISPOSITION" and inc is not None:
        inc.l3_status = "DECIDED"
        if approve:
            inc.disposition = "CONFIRMED_TRUE_POSITIVE"
            outcome = "Confirmed as a true positive."
        else:
            inc.disposition, inc.status = "FALSE_POSITIVE", "False Positive"
            for e in inc.events:
                e.analysis_status = "Closed"
            outcome = "Dismissed as a false positive."
            for other in db.query(DecisionRequest).filter(DecisionRequest.incident_id == inc.incident_id,
                                                          DecisionRequest.status == "PENDING", DecisionRequest.id != req.id).all():
                other.status, other.decided_by, other.decided_at = "REJECTED", user.email, naive_utc_now()
                other.decision_note, other.outcome = "Incident dismissed.", "Closed with the incident."
    elif req.kind == "DISABLE_ACCOUNT" and approve:
        account = proposal["account"].lower()
        target = db.query(User).filter(func.lower(User.email) == account).first()
        emp = db.query(Employee).filter(func.lower(Employee.company_email) == account).first()
        if target is not None:
            target.is_active = False
            now = naive_utc_now()
            db.query(UserSession).filter(UserSession.user_id == target.id, UserSession.revoked_at.is_(None)).update(
                {UserSession.revoked_at: now}, synchronize_session=False)
        if emp is not None:
            emp.is_active = False
        executed = target is not None or emp is not None
        via_connector = response_executor.handles("DISABLE_ACCOUNT")
        outcome = ("Disabled in CyberShield and signed out everywhere. " if executed else "")
        outcome += ("A signed request was queued for your response connector to disable it in the identity provider; it counts as done only when the connector confirms."
                    if via_connector else "CyberShield has no identity-provider integration: disable the account in your IdP to finish.")
        action = None
        if inc is not None:
            action = ResponseAction(incident_id=inc.incident_id, action_type="ACCOUNT_DISABLE", target=proposal["account"],
                                    status="EXECUTED_IN_PLATFORM" if executed else "APPROVED_MANUAL", details=outcome,
                                    is_simulated=False, executed_by=user.email, executed_at=naive_utc_now())
            db.add(action)
            db.flush()
        if via_connector:
            response_executor.enqueue(db, "DISABLE_ACCOUNT", proposal["account"], decision=req, incident_id=req.incident_id,
                                      approved_by=user.email, response_action=action)
    elif req.kind == "HOST_ISOLATION" and approve:
        via_connector = response_executor.handles("HOST_ISOLATION")
        outcome = ("A signed request was queued for your response connector (EDR / network access control); it counts as done only when the connector confirms."
                   if via_connector else "Approved. CyberShield has no EDR or network-access integration: isolate the host with your EDR or NAC.")
        action = None
        if inc is not None:
            action = ResponseAction(incident_id=inc.incident_id, action_type="HOST_ISOLATION", target=proposal["host"],
                                    status="APPROVED_MANUAL", details=outcome, is_simulated=False, executed_by=user.email,
                                    executed_at=naive_utc_now())
            db.add(action)
            db.flush()
        if via_connector:
            response_executor.enqueue(db, "HOST_ISOLATION", proposal["host"], decision=req, incident_id=req.incident_id,
                                      approved_by=user.email, response_action=action)
    elif req.kind == "INCIDENT_CLOSURE" and inc is not None:
        if approve:
            inc.status, inc.l3_status = proposal["target_status"], "DECIDED"
            if proposal["target_status"] == "False Positive":
                inc.disposition = "FALSE_POSITIVE"
            for e in inc.events:
                e.analysis_status = "Closed"
            outcome = f"Incident closed as {proposal['target_status']}."
        else:
            outcome = "Closure refused; the incident stays open."
    elif req.kind == "DETECTION_RULE" and approve:
        rule = DetectionRule(name=proposal["name"], description=req.rationale[:500], kind=proposal["kind"],
                             match_json=json.dumps(validate_match(proposal["match"], proposal["kind"],
                                                                  settings_store.get(db, "l1_critical_threshold")), sort_keys=True),
                             created_by=user.email, source_decision_id=req.id)
        db.add(rule)
        db.flush()
        outcome = f"Detection rule #{rule.id} is now active."

    req.status = "APPROVED" if approve else "REJECTED"
    req.decided_by, req.decided_at, req.decision_note, req.outcome = user.email, naive_utc_now(), (note or "")[:500], outcome[:255]
    db.flush()  # autoflush is off: make the decisions above visible to the pending check below
    if inc is not None and not db.query(DecisionRequest.id).filter(
            DecisionRequest.incident_id == inc.incident_id, DecisionRequest.status == "PENDING").first():
        inc.needs_human = False
        inc.l3_status = "DECIDED"
    db.add(AuditLog(action=f"L3_DECISION_{req.status}", actor=user.email, resource_type="DecisionRequest", resource_id=str(req.id),
                    details=f"{req.kind}: {req.title}. {outcome} Note: {req.decision_note or '-'}"))
    return req


def request_closure(db: Session, inc: Incident, user: User, target_status: str, comment: Optional[str]) -> DecisionRequest:
    """A closing decision on a Critical incident is not an analyst's alone: an administrator must approve it."""
    existing = db.query(DecisionRequest).filter(DecisionRequest.kind == "INCIDENT_CLOSURE", DecisionRequest.incident_id == inc.incident_id,
                                                DecisionRequest.status == "PENDING").first()
    if existing is not None:
        return existing
    req = DecisionRequest(
        kind="INCIDENT_CLOSURE", incident_id=inc.incident_id, priority=inc.severity,
        title=f"Close {inc.incident_id} as {target_status}",
        rationale=f"{user.full_name} asks to close this {inc.severity} incident as {target_status}. "
                  f"Note: {comment or '(none given)'}",
        evidence=json.dumps([f"L2 verdict: {inc.l2_verdict or 'not investigated'}", f"Current status: {inc.status}"]),
        proposal=json.dumps({"target_status": target_status, "comment": comment, "requested_by": user.email}),
        created_by=user.email)
    db.add(req)
    db.add(AuditLog(action="INCIDENT_CLOSURE_REQUESTED", actor=user.email, resource_type="Incident", resource_id=inc.incident_id,
                    details=f"Asked an administrator to close it as {target_status}."))
    return req


def reopen_event(db: Session, ev: SecurityEvent, user: User) -> None:
    """A human overrides L1: put an automatically closed alert back for triage by escalating it."""
    if ev.triage_status not in ("AUTO_CLOSED", "DUPLICATE"):
        raise HTTPException(409, "Only alerts closed by automation can be reopened.")
    _conclude(ev, "ESCALATED", "L3-REOPEN", f"Reopened by {user.email}.", 1.0)
    ev.analysis_status = "Analyzed"
    ev.incident_id = None
    db.add(AuditLog(action="L1_OVERRIDDEN", actor=user.email, resource_type="SecurityEvent", resource_id=ev.event_id,
                    details="A human reopened an alert that L1 had closed."))

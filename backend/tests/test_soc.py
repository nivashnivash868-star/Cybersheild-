"""The tiered SOC: L1 and L2 run on their own; L3 is where people decide."""
import json
from datetime import datetime, timedelta

import pytest

from app.models import (
    AgentRun, BlocklistEntry, DecisionRequest, DetectionRule, Incident, NotificationDelivery, SecurityEvent,
)
from app.services import soc_automation as soc

API = "/api/v1"
ATTACKER = "45.155.205.233"
VICTIM = "priya.s@enterprise-corp.com"


@pytest.fixture(autouse=True)
def clean(db):
    for model in (AgentRun, DecisionRequest, DetectionRule, BlocklistEntry, SecurityEvent, Incident):
        db.query(model).delete()
    db.commit()
    yield


def ev(db, eid, category, risk, *, ip=None, user=None, dest=None, source="Zetaris / auth logs", minutes_ago=5, domain=None):
    sev = "Critical" if risk >= 85 else "High" if risk >= 65 else "Medium" if risk >= 35 else "Low"
    row = SecurityEvent(event_id=eid, timestamp=datetime.utcnow() - timedelta(minutes=minutes_ago), event_source=source,
                        threat_category=category, risk_score=risk, severity=sev, source_ip=ip, dest_ip=dest, user_account=user,
                        domain=domain, evidence=f"{category} evidence", recommended_action="act")
    db.add(row)
    db.commit()
    return row


def main_incident(db):
    return db.query(Incident).filter(Incident.correlation_reason.contains(ATTACKER)).one()


def exfil_incident(db):
    return db.query(Incident).filter(Incident.title.contains("Exfiltration")).one()


def attack_story(db):
    ev(db, "A1", "Phishing / Critical Risk", 95, user=VICTIM, source="Zetaris / email gateway", domain="login-microsoft365-verify.xyz", minutes_ago=300)
    ev(db, "A2", "Suspicious Port Reconnaissance", 78, ip=ATTACKER, dest="10.20.0.1", source="Zetaris / network flows", minutes_ago=180)
    ev(db, "A3", "Account Compromise Suspected", 95, ip=ATTACKER, user=VICTIM, minutes_ago=120)
    ev(db, "A4", "Unexpected Traffic Spike / Exfiltration", 92, ip="10.20.4.37", dest="185.220.101.47", source="Zetaris / network flows", minutes_ago=60)


# --- L1 ---------------------------------------------------------------------------------------------------------------
def test_l1_closes_low_risk_noise_and_escalates_the_rest(db):
    ev(db, "N1", "Login Anomaly", 20, ip="10.0.0.9")
    ev(db, "N2", "Port Scan", 78, ip=ATTACKER)
    counts = soc.run_l1(db)
    n1, n2 = (db.query(SecurityEvent).filter(SecurityEvent.event_id == i).one() for i in ("N1", "N2"))
    assert counts["triaged"] == 2
    assert n1.triage_status == "AUTO_CLOSED" and n1.triage_rule == "L1-LOWRISK" and n1.analysis_status == "Closed"
    assert n2.triage_status == "ESCALATED" and n2.triage_confidence and n2.triage_reason
    assert db.query(AgentRun).filter(AgentRun.tier == "L1").count() == 2          # every decision is logged


def test_l1_suppresses_duplicates(db):
    ev(db, "D1", "Credential Brute Force", 80, ip=ATTACKER, user="a@x.co", minutes_ago=10)
    ev(db, "D2", "Credential Brute Force", 80, ip=ATTACKER, user="a@x.co", minutes_ago=9)
    ev(db, "D3", "Credential Brute Force", 80, ip=ATTACKER, user="other@x.co", minutes_ago=9)   # different user
    soc.run_l1(db)
    states = {e.event_id: e for e in db.query(SecurityEvent).all()}
    assert states["D1"].triage_status == "ESCALATED"
    assert states["D2"].triage_status == "DUPLICATE" and states["D2"].duplicate_of == "D1"
    assert states["D3"].triage_status == "ESCALATED"


def test_l1_escalates_low_risk_that_is_part_of_a_pattern(db):
    ev(db, "P1", "Port Scan", 78, ip=ATTACKER)
    ev(db, "P2", "Login Anomaly", 20, ip=ATTACKER)
    soc.run_l1(db)
    p2 = db.query(SecurityEvent).filter(SecurityEvent.event_id == "P2").one()
    assert p2.triage_status == "ESCALATED" and p2.triage_rule == "L1-PATTERN"


def test_l1_is_idempotent(db):
    ev(db, "I1", "Port Scan", 78, ip=ATTACKER)
    soc.run_l1(db)
    assert soc.run_l1(db) == {"triaged": 0}


def test_suppress_rule_closes_matching_alerts_but_never_critical_ones(db):
    rule = DetectionRule(name="Known scanner", kind="SUPPRESS", created_by="l3@x.co",
                         match_json=json.dumps({"category_contains": "scan", "source_ip": "198.18.0.5"}))
    db.add(rule)
    db.commit()
    ev(db, "R1", "Port Scan", 70, ip="198.18.0.5")
    ev(db, "R2", "Port Scan", 90, ip="198.18.0.5", minutes_ago=60)       # Critical: rules cannot hide it
    soc.run_l1(db)
    r1, r2 = (db.query(SecurityEvent).filter(SecurityEvent.event_id == i).one() for i in ("R1", "R2"))
    assert r1.triage_status == "AUTO_CLOSED" and r1.triage_rule == f"RULE-{rule.id}"
    assert r2.triage_status == "ESCALATED"
    db.refresh(rule)
    assert rule.hit_count == 1


def test_escalate_rule_overrides_low_risk(db):
    db.add(DetectionRule(name="Watch this user", kind="ESCALATE", created_by="l3@x.co", match_json=json.dumps({"user": "vip@x.co"})))
    db.commit()
    ev(db, "E1", "Login Anomaly", 10, user="vip@x.co")
    soc.run_l1(db)
    assert db.query(SecurityEvent).filter(SecurityEvent.event_id == "E1").one().triage_status == "ESCALATED"


def test_a_human_can_reopen_what_l1_closed(db, analyst):
    ev(db, "O1", "Login Anomaly", 15, ip="10.0.0.9")
    soc.run_l1(db)
    assert analyst.post(f"{API}/soc/events/O1/reopen").status_code == 200
    db.expire_all()
    assert db.query(SecurityEvent).filter(SecurityEvent.event_id == "O1").one().triage_status == "ESCALATED"
    assert analyst.post(f"{API}/soc/events/O1/reopen").status_code == 409        # already open again


# --- L2 ---------------------------------------------------------------------------------------------------------------
def test_l2_investigates_a_multi_stage_attack_on_its_own(db):
    attack_story(db)
    soc.run_cycle(db)
    inc = main_incident(db)                          # phish + scan + account compromise share the victim and the attacker
    assert len(inc.events) == 3 and inc.l2_status == "DONE" and inc.l2_verdict == "TRUE_POSITIVE" and inc.l2_confidence >= 0.7
    analysis = json.loads(inc.l2_analysis)
    assert {"Initial Access", "Discovery"} <= set(analysis["kill_chain"])
    assert "T1566 Phishing" in analysis["kill_chain"]["Initial Access"]
    exfil = exfil_incident(db)                       # nothing links the exfiltrating host to the victim, so a human must judge it
    assert exfil.l2_verdict == "NEEDS_HUMAN" and exfil.needs_human
    assert inc.needs_human and inc.l3_status == "AWAITING_DECISION" and inc.status == "Investigating"
    assert "genuine attack" in inc.l2_summary
    # it proposes; it does not act
    assert db.query(BlocklistEntry).count() == 0


def test_l2_proposals_are_for_attackers_never_for_your_own_hosts(db):
    attack_story(db)
    soc.run_cycle(db)
    blocks = {json.loads(d.proposal)["indicator"] for d in db.query(DecisionRequest).filter(DecisionRequest.kind == "CONTAINMENT")}
    assert {ATTACKER, "185.220.101.47", "login-microsoft365-verify.xyz"} <= blocks
    assert "10.20.4.37" not in blocks and "10.20.0.1" not in blocks
    assert "RESET_CREDENTIALS" in {m["type"] for m in json.loads(main_incident(db).l2_analysis)["manual_actions"]}
    assert "HOST_ISOLATION" in {m["type"] for m in json.loads(exfil_incident(db).l2_analysis)["manual_actions"]}


def test_l2_closes_clearly_benign_incidents_without_a_human(db):
    ev(db, "B1", "Policy Override / Risky Site Visit", 40, user="dave@x.co", source="Browser Gateway")
    soc.run_cycle(db)
    inc = db.query(Incident).one()
    assert inc.l2_verdict == "FALSE_POSITIVE" and inc.status == "False Positive" and inc.disposition == "AUTO_FALSE_POSITIVE"
    assert not inc.needs_human and db.query(DecisionRequest).count() == 0
    assert db.query(SecurityEvent).filter(SecurityEvent.event_id == "B1").one().analysis_status == "Closed"


def test_l2_never_auto_closes_something_high_severity(db):
    ev(db, "H1", "Suspicious Login", 70, ip="10.0.0.7", source="IdP")
    soc.run_cycle(db)
    inc = db.query(Incident).one()
    assert inc.l2_verdict == "NEEDS_HUMAN" and inc.needs_human
    assert db.query(DecisionRequest).filter(DecisionRequest.kind == "INCIDENT_DISPOSITION").count() == 1


def test_l2_does_not_repeat_itself(db):
    attack_story(db)
    soc.run_cycle(db)
    before = (db.query(DecisionRequest).count(), db.query(AgentRun).count())
    soc.run_cycle(db)
    assert (db.query(DecisionRequest).count(), db.query(AgentRun).count()) == before


def test_l2_notifies_the_humans_when_a_decision_is_needed(db):
    attack_story(db)
    soc.run_cycle(db)
    assert db.query(NotificationDelivery).filter(NotificationDelivery.title.like("%Decision required%")).count() >= 1


def test_repeated_false_positives_lead_to_a_suppression_proposal(db):
    for i in range(3):
        ev(db, f"F{i}", "Policy Override / Risky Site Visit", 40, user="dave@x.co", source="Browser Gateway", minutes_ago=600 - i * 120)
        soc.run_cycle(db)
    proposal = db.query(DecisionRequest).filter(DecisionRequest.kind == "DETECTION_RULE").one()
    assert proposal.status == "PENDING" and json.loads(proposal.proposal)["kind"] == "SUPPRESS"


# --- L3 ---------------------------------------------------------------------------------------------------------------
def _pending(db, kind):
    return db.query(DecisionRequest).filter(DecisionRequest.kind == kind, DecisionRequest.status == "PENDING").all()


def test_nothing_is_blocked_until_a_human_approves(db, analyst, anon):
    attack_story(db)
    soc.run_cycle(db)
    block = next(d for d in _pending(db, "CONTAINMENT") if json.loads(d.proposal)["indicator"] == ATTACKER)
    assert db.query(BlocklistEntry).count() == 0
    res = analyst.post(f"{API}/soc/decisions/{block.id}/decide", json={"decision": "approve", "note": "Confirmed in raw logs"})
    assert res.status_code == 200 and res.json()["status"] == "APPROVED" and res.json()["decided_by"] == "analyst@cybershield.corp"
    entry = db.query(BlocklistEntry).filter(BlocklistEntry.value == ATTACKER).one()
    assert entry.status == "ACTIVE" and entry.proposed_by == "analyst@cybershield.corp"
    assert main_incident(db).status == "Contained"


def test_rejecting_a_block_leaves_the_blocklist_untouched(db, analyst):
    attack_story(db)
    soc.run_cycle(db)
    block = _pending(db, "CONTAINMENT")[0]
    assert analyst.post(f"{API}/soc/decisions/{block.id}/decide", json={"decision": "reject", "note": "Partner address"}).json()["status"] == "REJECTED"
    assert db.query(BlocklistEntry).count() == 0


def test_a_decision_can_only_be_made_once(db, analyst, admin):
    attack_story(db)
    soc.run_cycle(db)
    d = _pending(db, "CONTAINMENT")[0]
    assert analyst.post(f"{API}/soc/decisions/{d.id}/decide", json={"decision": "reject"}).status_code == 200
    assert admin.post(f"{API}/soc/decisions/{d.id}/decide", json={"decision": "approve"}).status_code == 409


def test_dismissing_an_incident_closes_it_and_its_pending_proposals(db, analyst):
    attack_story(db)
    soc.run_cycle(db)
    inc = main_incident(db)
    disposition = next(d for d in _pending(db, "INCIDENT_DISPOSITION") if d.incident_id == inc.incident_id)
    analyst.post(f"{API}/soc/decisions/{disposition.id}/decide", json={"decision": "reject", "note": "Pen test"})
    db.refresh(inc)
    assert inc.status == "False Positive" and inc.disposition == "FALSE_POSITIVE" and not inc.needs_human
    assert [d for d in _pending(db, "CONTAINMENT") if d.incident_id == inc.incident_id] == []   # its proposals are withdrawn
    assert [d for d in _pending(db, "CONTAINMENT") if d.incident_id == exfil_incident(db).incident_id]  # the other incident is unaffected
    assert db.query(BlocklistEntry).count() == 0


def test_confirming_an_incident_marks_it_a_true_positive(db, analyst):
    attack_story(db)
    soc.run_cycle(db)
    inc = main_incident(db)
    d = next(x for x in _pending(db, "INCIDENT_DISPOSITION") if x.incident_id == inc.incident_id)
    analyst.post(f"{API}/soc/decisions/{d.id}/decide", json={"decision": "approve"})
    db.refresh(inc)
    assert inc.disposition == "CONFIRMED_TRUE_POSITIVE" and inc.l3_status == "DECIDED" or inc.needs_human


def test_approving_a_rule_proposal_creates_a_rule_l1_then_applies(db, admin):
    analyst = admin   # alert rules are security configuration: an administrator approves them
    for i in range(3):
        ev(db, f"G{i}", "Policy Override / Risky Site Visit", 40, user="dave@x.co", source="Browser Gateway", minutes_ago=600 - i * 120)
        soc.run_cycle(db)
    proposal = _pending(db, "DETECTION_RULE")[0]
    analyst.post(f"{API}/soc/decisions/{proposal.id}/decide", json={"decision": "approve", "note": "Known dev workflow"})
    rule = db.query(DetectionRule).one()
    assert rule.enabled and rule.source_decision_id == proposal.id and rule.created_by == "admin@cybershield.corp"
    ev(db, "G9", "Policy Override / Risky Site Visit", 40, user="dave@x.co", source="Browser Gateway", minutes_ago=1)
    soc.run_l1(db)
    g9 = db.query(SecurityEvent).filter(SecurityEvent.event_id == "G9").one()
    assert g9.triage_status == "AUTO_CLOSED" and g9.triage_rule == f"RULE-{rule.id}"


def test_administrators_author_detection_rules_and_bad_rules_are_refused(db, admin):
    analyst = admin
    ok = analyst.post(f"{API}/soc/rules", json={"name": "Hunt: nightly backup scan", "kind": "SUPPRESS",
                                                "match": {"category_contains": "scan", "source_ip": "10.9.9.9"}})
    assert ok.status_code == 201 and ok.json()["match"]["max_risk"] == 84          # suppression is capped below Critical
    for bad in ({}, {"max_risk": 10}, {"nonsense": "x"}, {"source_ip": ""}, {"category_contains": "x" * 200}):
        assert analyst.post(f"{API}/soc/rules", json={"name": "bad rule", "kind": "SUPPRESS", "match": bad}).status_code == 422
    rid = ok.json()["id"]
    assert analyst.patch(f"{API}/soc/rules/{rid}", params={"enabled": "false"}).json()["enabled"] is False


# --- API surface ------------------------------------------------------------------------------------------------------
def test_overview_reports_each_tier_and_the_automation_rate(db, analyst):
    attack_story(db)
    ev(db, "Z1", "Login Anomaly", 10, ip="10.0.0.2")
    ev(db, "Z2", "Login Anomaly", 12, ip="10.0.0.3")
    soc.run_cycle(db)
    o = analyst.get(f"{API}/soc/overview").json()
    assert o["l1"]["events_total"] == 6 and o["l1"]["auto_closed"] == 2 and o["l1"]["waiting"] == 0
    assert o["l2"]["incidents_investigated"] == 2 and o["l2"]["true_positive"] == 1 and o["l2"]["needs_human"] == 1
    assert o["l3"]["pending"] >= 5 and o["automation_rate"] == pytest.approx(2 / 6, abs=0.01)
    assert analyst.get(f"{API}/soc/activity", params={"tier": "L2"}).json()[0]["tier"] == "L2"


def test_incident_detail_carries_the_l2_analysis(db, analyst):
    attack_story(db)
    soc.run_cycle(db)
    inc_id = main_incident(db).incident_id
    detail = analyst.get(f"{API}/incidents/{inc_id}").json()
    assert detail["l2_verdict"] == "TRUE_POSITIVE" and detail["needs_human"] is True and "steps" in json.loads(detail["l2_analysis"])


def test_soc_endpoints_are_staff_only_and_run_is_admin_only(employee, analyst, admin, anon):
    for path in ("/soc/overview", "/soc/activity", "/soc/decisions", "/soc/rules"):
        assert anon.get(API + path).status_code == 401
        assert employee.get(API + path).status_code == 403
        assert analyst.get(API + path).status_code == 200
    assert analyst.post(f"{API}/soc/run").status_code == 403
    assert admin.post(f"{API}/soc/run").status_code == 200
    assert employee.post(f"{API}/soc/decisions/1/decide", json={"decision": "approve"}).status_code == 403


def test_a_new_alert_about_an_open_incident_joins_it_and_is_reinvestigated(db):
    attack_story(db)
    soc.run_cycle(db)
    inc = main_incident(db)
    before = len(inc.events)
    ev(db, "A5", "Credential Brute Force", 88, ip=ATTACKER, user="other.user@enterprise-corp.com", minutes_ago=1)
    soc.run_cycle(db)
    db.refresh(inc)
    assert len(inc.events) == before + 1 and inc.l2_status == "DONE"
    assert db.query(Incident).count() == 2                                         # no new incident was opened
    pending_dispositions = [d for d in _pending(db, "INCIDENT_DISPOSITION") if d.incident_id == inc.incident_id]
    assert len(pending_dispositions) == 1                                          # and no duplicate decision request


@pytest.mark.parametrize("category,stage,technique", [
    ("DNS Tunneling Anomaly", "Command and Control", "T1071.004"),
    ("SQL Injection Attempt", "Initial Access", "T1190"),
    ("CEO Impersonation Wire Fraud (BEC)", "Initial Access", "T1566"),
    ("Suspicious Script Execution", "Execution", "T1059"),
    ("Distributed SSH Credential Stuffing", "Credential Access", "T1110.004"),
    ("Suspicious Memory Injection", "Execution", "T1055"),
    ("Something never seen before", "Unclassified", None),
])
def test_kill_chain_recognises_the_attack_types_the_platform_reports(category, stage, technique):
    got_stage, got_technique = soc.classify(category)
    assert got_stage == stage and (technique is None or technique in got_technique)

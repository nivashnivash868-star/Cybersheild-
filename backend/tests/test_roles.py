"""The two working roles: Security Administrator and SOC Analyst."""
import json
import re
from datetime import datetime, timedelta
from app.models import naive_utc_now

import pytest

from app.config import settings
from app.models import (
    AuditLog, DecisionRequest, Employee, Incident, NotificationDelivery, ResponseAction, SecuritySetting, SecurityEvent, User,
    UserSession,
)
from app.services import soc_automation as soc
from tests.conftest import ACCOUNTS, login, make_client, wipe_soc

API = "/api/v1"
STRONG = "Activated-Password-2026-zz"


def _invite_token(db, email):
    row = db.query(NotificationDelivery).filter(NotificationDelivery.recipient_address == email).order_by(NotificationDelivery.id.desc()).first()
    return re.search(r"reset_token=([\w\-]+)&activate=1", row.message_body).group(1)


# --- account creation and activation --------------------------------------------------------------------------------
def test_security_administrator_invites_an_analyst_who_activates_their_own_account(secadmin, db):
    res = secadmin.post(f"{API}/users", json={"email": "new.analyst@company.com", "full_name": "New Analyst", "role": "SOC Analyst", "department": "SOC"})
    assert res.status_code == 201 and res.json()["role"] == "SOC Analyst"
    token = _invite_token(db, "new.analyst@company.com")
    row = db.query(NotificationDelivery).filter(NotificationDelivery.recipient_address == "new.analyst@company.com").one()
    assert "Activate your CYBERSHIELD AI account" in row.title and row.body_preview == "(redacted)"      # the link is not kept in the preview

    with make_client() as c:                                       # nobody knows a password yet
        assert login(c, "new.analyst@company.com", "anything-at-all-123").status_code == 401
        assert c.post(f"{API}/auth/reset-password", json={"token": token, "new_password": "weak"}).status_code == 422
        assert c.post(f"{API}/auth/reset-password", json={"token": token, "new_password": STRONG}).status_code == 200
        assert c.post(f"{API}/auth/reset-password", json={"token": token, "new_password": STRONG}).status_code == 400   # single use
        state = login(c, "new.analyst@company.com", STRONG).json()
        assert state["user"]["role"] == "SOC Analyst" and state["must_change_password"] is False
        assert c.get(f"{API}/dashboard/metrics").status_code == 200
        assert c.get(f"{API}/admin/overview").status_code == 403          # an analyst has no administrator dashboard
    assert db.query(AuditLog).filter(AuditLog.action == "USER_CREATED", AuditLog.actor == "secadmin@cybershield.corp").count() >= 1


def test_a_temporary_password_can_be_used_instead_of_an_invite(secadmin, db):
    secadmin.post(f"{API}/users", json={"email": "temp.pw@company.com", "full_name": "Temp Pw", "role": "SOC Analyst", "temporary_password": "Temporary-Pass-2026-q"})
    assert db.query(NotificationDelivery).filter(NotificationDelivery.recipient_address == "temp.pw@company.com").count() == 0
    with make_client() as c:
        assert login(c, "temp.pw@company.com", "Temporary-Pass-2026-q").json()["must_change_password"] is True


def test_a_security_administrator_cannot_create_or_touch_administrators(secadmin, admin, db):
    base = {"full_name": "Someone", "send_invite": True}
    assert secadmin.post(f"{API}/users", json={**base, "email": "x1@company.com", "role": "Super Admin"}).status_code == 403
    assert secadmin.post(f"{API}/users", json={**base, "email": "x2@company.com", "role": "Security Administrator"}).status_code == 403
    assert admin.post(f"{API}/users", json={**base, "email": "x3@company.com", "role": "Security Administrator"}).status_code == 201
    boss = db.query(User).filter(User.email == "admin@cybershield.corp").one()
    assert secadmin.patch(f"{API}/users/{boss.id}", json={"is_active": False}).status_code == 403
    assert secadmin.post(f"{API}/users/{boss.id}/reset-mfa").status_code == 403
    analyst = db.query(User).filter(User.email == ACCOUNTS["analyst"]).one()
    assert secadmin.patch(f"{API}/users/{analyst.id}", json={"role": "Super Admin"}).status_code == 403    # no promotion either


def test_analysts_cannot_manage_accounts(analyst):
    assert analyst.get(f"{API}/users").status_code == 403
    assert analyst.post(f"{API}/users", json={"email": "z@company.com", "full_name": "Z", "role": "SOC Analyst"}).status_code == 403


def test_activating_and_deactivating_an_analyst_takes_effect_immediately(secadmin, db):
    made = secadmin.post(f"{API}/users", json={"email": "toggle.me@company.com", "full_name": "Toggle Me", "role": "SOC Analyst", "temporary_password": "Temporary-Pass-2026-q"}).json()
    with make_client() as c:
        login(c, "toggle.me@company.com", "Temporary-Pass-2026-q")
        assert c.get(f"{API}/auth/me").status_code == 200
        assert secadmin.patch(f"{API}/users/{made['id']}", json={"is_active": False}).json()["is_active"] is False
        assert c.get(f"{API}/auth/me").status_code == 401                          # signed out the moment they are deactivated


# --- administrator overview, health, configuration ---------------------------------------------------------------------
def test_admin_overview_reports_alerts_incidents_analysts_and_health(admin):
    o = admin.get(f"{API}/admin/overview").json()
    assert {"total", "critical_open", "last_24h"} <= set(o["alerts"])
    assert {"critical", "unresolved", "awaiting_approval"} <= set(o["incidents"])
    assert {"total", "active", "online_now"} <= set(o["analysts"]) and o["analysts"]["active"] >= 1
    names = {h["name"] for h in o["health"]}
    assert {"Database", "Automation worker", "Email alerts", "SMS alerts", "Zetaris data sources"} <= names
    assert next(h for h in o["health"] if h["name"] == "Database")["status"] == "ok"


def test_the_overview_says_when_the_data_is_simulated(admin):
    o = admin.get(f"{API}/admin/overview").json()
    assert o["data"]["any_simulated"] is True and o["data"]["simulated_events"] >= 1     # the demo seed is fabricated
    assert o["data"]["all_simulated"] == (o["data"]["simulated_events"] == o["data"]["total_events"])


def test_simulated_events_are_flagged_on_the_event_itself(analyst, db):
    seeded = db.query(SecurityEvent).filter(SecurityEvent.is_simulated.is_(True)).first()
    assert analyst.get(f"{API}/events/{seeded.event_id}").json()["event"]["is_simulated"] is True
    real = SecurityEvent(event_id="REAL-1", timestamp=naive_utc_now(), event_source="x", threat_category="Port Scan", risk_score=70,
                         severity="High", evidence="e", recommended_action="a", is_simulated=False)
    db.add(real)
    db.commit()
    assert analyst.get(f"{API}/events/REAL-1").json()["event"]["is_simulated"] is False
    db.delete(real)
    db.commit()


def test_analysts_cannot_reach_security_configuration(analyst, employee):
    for who in (analyst, employee):
        assert who.get(f"{API}/admin/settings").status_code == 403
        assert who.put(f"{API}/admin/settings", json={"l1_low_risk_threshold": 20}).status_code == 403
        assert who.get(f"{API}/admin/permissions").status_code == 403
        assert who.get(f"{API}/admin/integrations").status_code == 403


def test_thresholds_are_validated_audited_and_applied(admin, db):
    assert admin.put(f"{API}/admin/settings", json={"l1_low_risk_threshold": 5}).status_code == 422          # below the allowed range
    assert admin.put(f"{API}/admin/settings", json={"l1_low_risk_threshold": 90}).status_code == 422          # not below the critical threshold
    assert admin.put(f"{API}/admin/settings", json={"alert_min_severity": "Banana"}).status_code == 422
    assert admin.put(f"{API}/admin/settings", json={"nonsense": 1}).status_code == 422
    changed = admin.put(f"{API}/admin/settings", json={"l1_low_risk_threshold": 50}).json()
    assert next(s for s in changed if s["key"] == "l1_low_risk_threshold")["value"] == 50
    assert db.query(AuditLog).filter(AuditLog.action == "SECURITY_SETTING_CHANGED", AuditLog.resource_id == "l1_low_risk_threshold").count() == 1

    db.query(SecurityEvent).filter(SecurityEvent.event_id == "TH-1").delete()
    db.add(SecurityEvent(event_id="TH-1", timestamp=naive_utc_now(), event_source="t", threat_category="Odd Login", risk_score=40,
                         severity="Medium", user_account="t@x.co", evidence="e", recommended_action="a"))
    db.commit()
    soc.run_l1(db)
    assert db.query(SecurityEvent).filter(SecurityEvent.event_id == "TH-1").one().triage_status == "AUTO_CLOSED"   # 40 < 50 now
    admin.put(f"{API}/admin/settings", json={"l1_low_risk_threshold": 35})


def test_the_alert_severity_threshold_controls_who_gets_paged(admin, db):
    from app.services.alert_engine import alert_engine
    admin.put(f"{API}/admin/settings", json={"alert_min_severity": "High"})
    assert alert_engine.dispatch_security_alert(db, title="Medium thing", sanitized_summary="s", severity="Medium") == []
    assert alert_engine.dispatch_security_alert(db, title="High thing", sanitized_summary="s", severity="High") != []
    db.rollback()
    admin.put(f"{API}/admin/settings", json={"alert_min_severity": "Medium"})


def test_the_permission_matrix_and_integrations_are_visible_to_administrators(secadmin):
    matrix = secadmin.get(f"{API}/admin/permissions").json()
    close = next(r for r in matrix if r["capability"] == "Close a Critical incident")
    assert close["SOC Analyst"] == "Request, administrator approves" and close["Security Administrator"] is True
    integ = {i["name"]: i for i in secadmin.get(f"{API}/admin/integrations").json()}
    assert integ["Identity provider (disable accounts)"]["configured"] is False        # honest about what is not connected


# --- analyst workflow ---------------------------------------------------------------------------------------------------
@pytest.fixture
def critical_incident(db):
    wipe_soc(db)
    db.query(SecurityEvent).filter(SecurityEvent.event_id.like("CI-%")).delete(synchronize_session=False)
    inc = Incident(incident_id="INC-TEST-CRIT", title="Critical test", description="d", threat_category="Phishing", severity="Critical", risk_score=95, status="Investigating")
    db.add(inc)
    db.commit()
    return inc


def test_an_analyst_cannot_close_a_critical_incident_alone(analyst, admin, db, critical_incident):
    res = analyst.patch(f"{API}/incidents/INC-TEST-CRIT/status", json={"status": "Resolved", "comment": "Handled"}).json()
    assert res["status"] == "approval_requested"
    db.refresh(critical_incident)
    assert critical_incident.status == "Investigating"                                     # nothing changed yet
    req = db.get(DecisionRequest, res["decision_id"])
    assert req.kind == "INCIDENT_CLOSURE" and req.created_by == "analyst@cybershield.corp" and "Handled" in req.rationale
    assert analyst.post(f"{API}/soc/decisions/{req.id}/decide", json={"decision": "approve"}).status_code == 403   # they cannot approve their own request
    assert admin.post(f"{API}/soc/decisions/{req.id}/decide", json={"decision": "approve", "note": "Verified"}).status_code == 200
    db.refresh(critical_incident)
    assert critical_incident.status == "Resolved"


def test_an_administrator_can_refuse_a_closure_request(analyst, admin, db, critical_incident):
    rid = analyst.patch(f"{API}/incidents/INC-TEST-CRIT/status", json={"status": "False Positive"}).json()["decision_id"]
    admin.post(f"{API}/soc/decisions/{rid}/decide", json={"decision": "reject", "note": "Not convinced"})
    db.refresh(critical_incident)
    assert critical_incident.status == "Investigating"


def test_closing_lower_severity_incidents_needs_no_approval_and_admins_close_critical_ones_directly(analyst, admin, db, critical_incident):
    db.add(Incident(incident_id="INC-TEST-MED", title="Medium", description="d", threat_category="Phishing", severity="Medium", risk_score=50, status="Investigating"))
    db.commit()
    assert analyst.patch(f"{API}/incidents/INC-TEST-MED/status", json={"status": "Resolved"}).json()["new_status"] == "Resolved"
    assert admin.patch(f"{API}/incidents/INC-TEST-CRIT/status", json={"status": "Resolved"}).json()["new_status"] == "Resolved"


def test_disabling_an_account_and_isolating_a_host_need_an_administrator(analyst, admin, db):
    wipe_soc(db)
    victim = User(email="victim.user@company.com", full_name="Victim", role="Employee", hashed_password="x")
    db.add(victim)
    db.commit()
    with make_client() as c:
        db.add(Incident(incident_id="INC-ACC", title="t", description="d", threat_category="Phishing", severity="High", risk_score=80, status="Investigating"))
        a = DecisionRequest(kind="DISABLE_ACCOUNT", incident_id="INC-ACC", title="Disable account victim.user@company.com", rationale="r",
                            proposal=json.dumps({"account": "victim.user@company.com"}), created_by="agent:L2-investigator")
        h = DecisionRequest(kind="HOST_ISOLATION", incident_id="INC-ACC", title="Isolate host 10.20.4.37", rationale="r",
                            proposal=json.dumps({"host": "10.20.4.37"}), created_by="agent:L2-investigator")
        db.add_all([a, h])
        db.commit()
        for d in (a, h):
            r = analyst.post(f"{API}/soc/decisions/{d.id}/decide", json={"decision": "approve"})
            assert r.status_code == 403 and "Security Administrator" in r.json()["detail"]
        assert admin.get(f"{API}/soc/decisions").json()[0]["requires_admin"] is True
        assert admin.post(f"{API}/soc/decisions/{a.id}/decide", json={"decision": "approve", "note": "Confirmed compromise"}).status_code == 200
        db.expire_all()
        assert db.query(User).filter(User.email == "victim.user@company.com").one().is_active is False
        action = db.query(ResponseAction).filter(ResponseAction.action_type == "ACCOUNT_DISABLE").one()
        assert action.status == "EXECUTED_IN_PLATFORM" and "identity-provider" in action.details       # honest about the limit
        assert admin.post(f"{API}/soc/decisions/{h.id}/decide", json={"decision": "approve"}).status_code == 200
        assert db.query(ResponseAction).filter(ResponseAction.action_type == "HOST_ISOLATION").one().status == "APPROVED_MANUAL"


def test_l2_asks_for_account_and_host_decisions_instead_of_doing_them(db):
    wipe_soc(db)
    db.query(SecurityEvent).filter(SecurityEvent.event_id.like("AA-%")).delete(synchronize_session=False)
    now = naive_utc_now()
    rows = [("AA-1", "Phishing / Critical Risk", 95, None, "priya@enterprise-corp.com", None, now - timedelta(hours=5), "Email Gateway"),
            ("AA-2", "Account Compromise Suspected", 95, "45.155.205.233", "priya@enterprise-corp.com", None, now - timedelta(hours=2), "Auth"),
            ("AA-3", "Unexpected Traffic Spike / Exfiltration", 92, "10.20.4.37", "priya@enterprise-corp.com", "185.220.101.47", now - timedelta(hours=1), "Network")]
    for eid, cat, risk, ip, user, dst, ts, src in rows:
        db.add(SecurityEvent(event_id=eid, timestamp=ts, event_source=src, threat_category=cat, risk_score=risk, severity="Critical", source_ip=ip,
                             user_account=user, dest_ip=dst, evidence="e", recommended_action="a"))
    db.commit()
    soc.run_cycle(db)
    kinds = {d.kind for d in db.query(DecisionRequest).filter(DecisionRequest.status == "PENDING")}
    assert {"DISABLE_ACCOUNT", "HOST_ISOLATION", "CONTAINMENT", "INCIDENT_DISPOSITION"} <= kinds
    assert db.query(User).filter(User.email == "priya@enterprise-corp.com").count() == 0 and db.query(ResponseAction).count() == 0


def test_analysts_can_request_alert_rules_which_administrators_approve(analyst, admin, db):
    db.query(DecisionRequest).delete()
    db.commit()
    res = analyst.post(f"{API}/soc/rules", json={"name": "Known scanner", "kind": "SUPPRESS", "match": {"source_ip": "198.18.7.7", "category_contains": "scan"}})
    assert res.status_code == 201 and res.json()["status"] == "approval_requested"
    assert analyst.patch(f"{API}/soc/rules/1", params={"enabled": "false"}).status_code == 403
    req = db.get(DecisionRequest, res.json()["decision_id"])
    assert analyst.post(f"{API}/soc/decisions/{req.id}/decide", json={"decision": "approve"}).status_code == 403
    assert admin.post(f"{API}/soc/decisions/{req.id}/decide", json={"decision": "approve"}).status_code == 200


def test_cases_can_only_be_assigned_to_real_active_staff(analyst, db):
    db.query(Incident).filter(Incident.incident_id == "INC-ASSIGN").delete()
    db.add(Incident(incident_id="INC-ASSIGN", title="t", description="d", threat_category="x", severity="Low", risk_score=10, status="New"))
    db.commit()
    assert analyst.patch(f"{API}/incidents/INC-ASSIGN/assign", json={"assigned_analyst": "Imaginary Person"}).status_code == 422
    staff = analyst.get(f"{API}/users/analysts").json()
    assert staff and all(set(s) == {"id", "full_name", "email", "role"} for s in staff)
    assert "Alex Turner" not in [s["full_name"] for s in staff]                      # employees are not assignable
    ok = analyst.patch(f"{API}/incidents/INC-ASSIGN/assign", json={"assigned_analyst": staff[0]["full_name"]})
    assert ok.status_code == 200 and ok.json()["assigned_analyst"] == staff[0]["full_name"]


def test_the_analyst_list_is_for_staff_only(employee, anon):
    assert employee.get(f"{API}/users/analysts").status_code == 403
    assert anon.get(f"{API}/users/analysts").status_code == 401


def test_event_detail_gives_related_alerts_a_timeline_and_the_automation_trail(analyst, db):
    db.query(SecurityEvent).filter(SecurityEvent.event_id.like("DT-%")).delete(synchronize_session=False)
    now = naive_utc_now()
    for i, (cat, mins) in enumerate([("Port Scan", 90), ("Brute Force", 60), ("Exfiltration", 30)]):
        db.add(SecurityEvent(event_id=f"DT-{i}", timestamp=now - timedelta(minutes=mins), event_source="s", threat_category=cat, risk_score=80,
                             severity="High", source_ip="45.9.9.9", evidence="e", recommended_action="a"))
    db.commit()
    soc.run_l1(db)
    d = analyst.get(f"{API}/events/DT-1").json()
    assert {e["event_id"] for e in d["related_events"]} == {"DT-0", "DT-2"}
    assert [t["category"] for t in d["timeline"]] == ["Port Scan", "Brute Force", "Exfiltration"] and d["timeline"][1]["this"] is True
    assert d["automation"] and d["automation"][0]["tier"] == "L1"
    assert analyst.get(f"{API}/events/NOPE").status_code == 404


def test_critical_alerts_panel_lists_open_high_severity_alerts_unacknowledged_first(analyst, db):
    db.query(SecurityEvent).filter(SecurityEvent.event_id.like("CA-%")).delete(synchronize_session=False)
    now = naive_utc_now()
    specs = [("CA-1", "Critical", False, "Analyzed"), ("CA-2", "High", True, "Analyzed"), ("CA-3", "Low", False, "Analyzed"), ("CA-4", "Critical", False, "Closed")]
    for eid, sev, ack, status in specs:
        db.add(SecurityEvent(event_id=eid, timestamp=now, event_source="s", threat_category="x", risk_score=90, severity=sev,
                             evidence="e", recommended_action="a", is_acknowledged=ack, analysis_status=status))
    db.commit()
    ids = [e["event_id"] for e in analyst.get(f"{API}/dashboard/critical-alerts", params={"limit": 50}).json() if e["event_id"].startswith("CA-")]
    assert ids == ["CA-1", "CA-2"]                                                        # no Low, no closed; unacknowledged first
    assert analyst.patch(f"{API}/events/CA-1/acknowledge").status_code == 200

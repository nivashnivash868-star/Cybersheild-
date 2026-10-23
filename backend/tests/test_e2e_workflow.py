import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import Base, engine, SessionLocal
from app.services.demo_data_seeder import seed_demo_soc_data

@pytest.fixture(scope="module", autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed_demo_soc_data(db=db, force_reset=True)
    yield

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c

def test_complete_enterprise_cybersecurity_workflow(client):
    """
    Validates Requirement 14 end-to-end workflow:
    1. Administrator logs in and adds an employee.
    2. A security event enters the backend for that employee.
    3. The detection engine analyses it and assesses risk.
    4. An incident is formed.
    5. The SOC analyst receives an automated alert notification.
    6. The employee receives an appropriate security advisory.
    7. The SOC analyst investigates and executes containment action.
    """
    # 1. Admin Login
    login_res = client.post("/api/v1/auth/login", json={
        "email": "admin@cybershield.corp",
        "password": "CyberShield@2026!"
    })
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    auth_headers = {"Authorization": f"Bearer {token}"}

    # 2. Administrator adds an employee
    new_employee_payload = {
        "employee_id": "EMP-2099",
        "full_name": "Jordan Lee",
        "company_email": "jordan.lee@enterprise-corp.com",
        "phone_number": "+1 (555) 901-2345",
        "department": "Treasury & Finance",
        "role_title": "Treasury Operations Analyst",
        "monitoring_policy": "Executive High-Risk"
    }
    emp_res = client.post("/api/v1/employees", json=new_employee_payload, headers=auth_headers)
    assert emp_res.status_code == 201
    assert emp_res.json()["employee_id"] == "EMP-2099"

    # Verify duplicate prevention: attempting to create identical employee fails with 409
    dup_res = client.post("/api/v1/employees", json=new_employee_payload, headers=auth_headers)
    assert dup_res.status_code == 409

    # 3. Security Event enters backend for this employee (e.g. Inbound phishing URL / Credential attempt)
    phish_payload = {
        "submission_type": "url",
        "content": "http://login-microsoft365-verify.xyz/auth?user=jordan.lee@enterprise-corp.com",
        "reporting_employee_email": "jordan.lee@enterprise-corp.com"
    }
    phish_res = client.post("/api/v1/phishing/analyze", json=phish_payload)
    assert phish_res.status_code == 200
    phish_data = phish_res.json()
    assert phish_data["risk_score"] >= 80
    assert phish_data["risk_category"] in ("High", "Critical")

    # 4. Trigger telemetry pulse from Exchange Email Gateway targeting this employee
    pulse_res = client.post("/api/v1/monitoring/simulate-pulse", json={
        "source_id": "SRC-M365-EMAIL",
        "employee_email": "jordan.lee@enterprise-corp.com"
    })
    assert pulse_res.status_code == 200
    event_obj = pulse_res.json()
    assert event_obj["user_account"] == "jordan.lee@enterprise-corp.com"

    # 5. Verify automated alert notifications were generated for both SOC Analyst and Employee
    alerts_res = client.get("/api/v1/alerts/deliveries?limit=20")
    assert alerts_res.status_code == 200
    deliveries = alerts_res.json()
    
    # Check SOC analyst got alert
    soc_alerts = [d for d in deliveries if d["recipient_type"] == "SOC_ANALYST"]
    assert len(soc_alerts) >= 1
    assert soc_alerts[0]["delivery_status"] in ("DELIVERED", "SUPPRESSED_DUPLICATE")

    # Check Employee got personalized warning
    emp_alerts = [d for d in deliveries if d["recipient_address"] == "jordan.lee@enterprise-corp.com"]
    assert len(emp_alerts) >= 1
    assert emp_alerts[0]["recipient_type"] == "EMPLOYEE"
    # Verify no secret leakage
    assert "CyberShield@2026!" not in emp_alerts[0]["body_preview"]

    # 6. Execute Correlation Cycle to form an Incident
    corr_res = client.post("/api/v1/incidents/correlate")
    assert corr_res.status_code == 200

    # 7. SOC Analyst triages and executes containment response
    incidents_res = client.get("/api/v1/incidents")
    assert incidents_res.status_code == 200
    incidents = incidents_res.json()
    assert len(incidents) >= 1
    target_inc_id = incidents[0]["incident_id"]

    # Analyst records containment action: Block Perimeter IP
    action_res = client.post(f"/api/v1/incidents/{target_inc_id}/actions", json={
        "action_type": "FIREWALL_BLOCK",
        "target": "198.51.100.44",
        "details": "Simulated firewall block for adversary host targeting Jordan Lee."
    })
    assert action_res.status_code == 200
    assert action_res.json()["is_simulated"] is True

    # Analyst updates incident status to Contained
    status_res = client.patch(f"/api/v1/incidents/{target_inc_id}/status", json={
        "status": "Contained",
        "analyst_name": "Sarah Chen",
        "comment": "Malicious source blocked and employee verified."
    })
    assert status_res.status_code == 200
    assert status_res.json()["new_status"] == "Contained"

    # 8. Employee DLP Secret Scan Verification
    dlp_res = client.post("/api/v1/dlp/scan", json={
        "content": "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE and deploy",
        "source_location": "Git commit by jordan.lee@enterprise-corp.com",
        "employee_email": "jordan.lee@enterprise-corp.com"
    })
    assert dlp_res.status_code == 200
    findings = dlp_res.json()
    assert len(findings) >= 1
    assert "AKIAIOSFODNN7EXAMPLE" not in findings[0]["masked_value"]
    assert "AKIA" in findings[0]["masked_value"]

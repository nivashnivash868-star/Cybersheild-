import pytest

def test_system_health_endpoint(client):
    response = client.get("/api/v1/system/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "database" in data

def test_dashboard_metrics(client):
    response = client.get("/api/v1/dashboard/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "total_events_analyzed" in data
    assert "threats_detected" in data
    assert data["total_events_analyzed"] > 0

def test_phishing_analysis_endpoint(client):
    payload = {
        "submission_type": "url",
        "content": "http://login-microsoft365-verify.xyz/auth?session=456"
    }
    response = client.post("/api/v1/phishing/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] >= 60
    assert data["risk_category"] in ("High", "Critical")

def test_incidents_listing(client):
    response = client.get("/api/v1/incidents")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1

def test_incident_status_transition(client):
    # Fetch first incident
    res = client.get("/api/v1/incidents")
    incidents = res.json()
    first_id = incidents[0]["incident_id"]

    # Transition status
    patch_res = client.patch(
        f"/api/v1/incidents/{first_id}/status",
        json={"status": "Contained", "analyst_name": "Test Analyst", "comment": "Host isolated via SOC automation test."}
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["new_status"] == "Contained"

def test_incident_report_export(client):
    res = client.get("/api/v1/incidents")
    first_id = res.json()[0]["incident_id"]
    export_res = client.get(f"/api/v1/incidents/{first_id}/export?format=text")
    assert export_res.status_code == 200
    assert "DIGITAL FORENSIC INCIDENT REPORT" in export_res.text

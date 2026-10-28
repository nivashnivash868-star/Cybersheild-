from datetime import datetime, timedelta
from app.models import naive_utc_now

import pytest

from app.database import SessionLocal
from app.models import Incident, SecurityEvent
from app.services.demo_data_seeder import seed_demo_soc_data
from tests.conftest import wipe_soc

API = "/api/v1"


@pytest.fixture(autouse=True)
def _restore_seed():
    """These tests empty the event tables; put the shared demo seed back for the tests that follow."""
    yield
    with SessionLocal() as session:
        seed_demo_soc_data(db=session, force_reset=True)


def _event(db, eid, minutes_ago, category, score, severity):
    db.add(SecurityEvent(event_id=eid, timestamp=naive_utc_now() - timedelta(minutes=minutes_ago), event_source="test",
                         threat_category=category, risk_score=score, severity=severity, evidence="e",
                         recommended_action="a"))


def test_timeline_has_no_invented_floor(db, analyst):
    wipe_soc(db)
    points = analyst.get(f"{API}/dashboard/activity-timeline").json()
    assert len(points) == 7
    assert all(p["total_events"] == 0 and p["threats"] == 0 and p["phishing"] == 0 and p["network"] == 0 for p in points)


def test_timeline_and_metrics_count_real_events(db, analyst):
    db.query(SecurityEvent).delete()
    _event(db, "DB-1", 30, "Phishing / High Risk", 80, "High")
    _event(db, "DB-2", 40, "Suspicious Port Reconnaissance", 78, "High")
    _event(db, "DB-3", 50, "Credential Brute Force", 90, "Critical")
    _event(db, "DB-4", 60 * 30, "Phishing / High Risk", 70, "High")        # 30 hours ago
    db.commit()
    points = analyst.get(f"{API}/dashboard/activity-timeline").json()
    assert points[-1]["total_events"] == 3 and points[-1]["phishing"] == 1 and points[-1]["network"] == 2
    m = analyst.get(f"{API}/dashboard/metrics").json()
    assert m["total_events_analyzed"] == 4 and m["events_last_24h"] == 3 and m["events_prev_24h"] == 1
    assert m["critical_events_last_24h"] == 1


def test_category_distribution_groups_and_rolls_up_the_tail(db, analyst):
    db.query(SecurityEvent).delete()
    for i in range(3):
        _event(db, f"C-A{i}", 10, "Phishing / High Risk", 80, "High")
    for i in range(2):
        _event(db, f"C-B{i}", 10, "Credential Brute Force", 80, "High")
    _event(db, "C-C", 10, "One-off A", 50, "Medium")
    _event(db, "C-D", 10, "One-off B", 50, "Medium")
    db.commit()
    rows = analyst.get(f"{API}/dashboard/category-distribution", params={"limit": 2}).json()
    assert rows[0] == {"category": "Phishing / High Risk", "count": 3}
    assert rows[-1] == {"category": "Other", "count": 2}


def test_reputation_status_never_claims_a_live_connection_from_a_key(analyst, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "set")
    assert "Connected" not in analyst.get(f"{API}/dashboard/metrics").json()["reputation_service_status"]


def test_timeline_buckets_carry_a_utc_timestamp(analyst):
    points = analyst.get(f"{API}/dashboard/activity-timeline").json()
    assert all(p["bucket_end"].endswith("Z") for p in points)


def test_csp_allows_only_the_font_hosts_the_page_uses(anon):
    csp = anon.get("/").headers.get("content-security-policy", "")
    assert "https://fonts.googleapis.com" in csp and "https://fonts.gstatic.com" in csp and "script-src 'self'" in csp

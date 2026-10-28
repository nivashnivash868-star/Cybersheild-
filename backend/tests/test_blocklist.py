from datetime import timedelta

import pytest

from app.models import BlocklistEntry, naive_utc_now
from app.services import blocklist as svc
from app.services.blocklist import normalise_indicator
from fastapi import HTTPException

API = "/api/v1"
GOOD_IP = "45.155.205.233"


@pytest.mark.parametrize("bad", [
    "10.0.0.5", "192.168.1.1", "127.0.0.1", "169.254.169.254", "198.51.100.44", "::1", "0.0.0.0",
    "10.0.0.0/8", "8.0.0.0/8", "1.0.0.0/15",                      # private / reserved / too broad
    "google.com", "login.microsoft.com", "intranet.corp", "localhost", "not a domain", "",
    "ftp://evil.example/x", "evil.example\nBcc: x",
])
def test_dangerous_or_invalid_indicators_are_refused(bad):
    with pytest.raises(HTTPException):
        normalise_indicator(bad)


@pytest.mark.parametrize("raw,expected", [
    (GOOD_IP, ("ip", GOOD_IP)),
    ("45.155.205.0/24", ("cidr", "45.155.205.0/24")),
    ("Evil-Login.XYZ.", ("domain", "evil-login.xyz")),
    ("https://Evil-Login.xyz/a/b?x=1#frag", ("url", "https://evil-login.xyz/a/b?x=1")),
])
def test_indicators_are_classified_and_canonicalised(raw, expected):
    assert normalise_indicator(raw) == expected


def test_protected_ranges_from_config_are_refused(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "BLOCKLIST_PROTECTED", ["45.155.0.0/16", "partner.example.org"])
    with pytest.raises(HTTPException):
        normalise_indicator(GOOD_IP)
    with pytest.raises(HTTPException):
        normalise_indicator("api.partner.example.org")


def _token(admin, name):
    res = admin.post(f"{API}/blocklist/feeds", json={"name": name})
    assert res.status_code == 200, res.text
    return res.json()["token"]


def _feed(anon, token, kind="ip", **kw):
    return anon.get(f"{API}/feeds/blocklist/{kind}.txt", headers={"Authorization": f"Bearer {token}"}, **kw)


def test_feed_requires_a_valid_unrevoked_token(admin, anon):
    assert anon.get(f"{API}/feeds/blocklist/ip.txt").status_code == 401
    assert _feed(anon, "csf_not_a_real_token").status_code == 401
    tok = _token(admin, "fw-auth-test")
    assert _feed(anon, tok).status_code == 200
    ids = [t["id"] for t in admin.get(f"{API}/blocklist/feeds").json() if t["name"] == "fw-auth-test"]
    assert admin.delete(f"{API}/blocklist/feeds/{ids[0]}").status_code == 200
    assert _feed(anon, tok).status_code == 401


def test_session_cookie_does_not_open_the_feed(analyst):
    assert analyst.get(f"{API}/feeds/blocklist/ip.txt").status_code == 401   # feeds need a feed token


def test_analyst_proposal_waits_for_admin_approval_then_is_published(analyst, admin, anon):
    tok = _token(admin, "fw-flow")
    ip = "45.155.205.77"
    entry = analyst.post(f"{API}/blocklist", json={"indicator": ip, "reason": "C2 beacon seen in INC-1"}).json()
    assert entry["status"] == "PENDING_APPROVAL"
    assert ip not in _feed(anon, tok).text                                     # not enforced before approval

    assert analyst.post(f"{API}/blocklist/{entry['id']}/approve", json={}).status_code == 403
    done = admin.post(f"{API}/blocklist/{entry['id']}/approve", json={"note": "confirmed"}).json()
    assert done["status"] == "ACTIVE" and done["decided_by"] == "admin@cybershield.corp"
    assert ip in _feed(anon, tok).text.splitlines()
    assert admin.post(f"{API}/blocklist/{entry['id']}/approve", json={}).status_code == 409   # can't re-approve

    assert admin.post(f"{API}/blocklist/{entry['id']}/revoke", json={}).json()["status"] == "REVOKED"
    assert ip not in _feed(anon, tok).text


def test_admin_proposals_publish_immediately_and_feeds_are_split_by_type(admin, anon):
    tok = _token(admin, "fw-types")
    admin.post(f"{API}/blocklist", json={"indicator": "bad-login-portal.xyz", "reason": "phishing kit host"})
    admin.post(f"{API}/blocklist", json={"indicator": "https://bad-login-portal.xyz/verify", "reason": "phishing page"})
    assert "bad-login-portal.xyz" in _feed(anon, tok, "domain").text.splitlines()
    assert "https://bad-login-portal.xyz/verify" in _feed(anon, tok, "url").text.splitlines()
    assert "bad-login-portal.xyz/verify" in _feed(anon, tok, "url", params={"strip_scheme": "true"}).text.splitlines()
    assert "bad-login-portal.xyz" not in _feed(anon, tok, "ip").text


def test_feed_supports_etag_and_basic_auth(admin, anon):
    import base64
    tok = _token(admin, "fw-etag")
    first = _feed(anon, tok)
    etag = first.headers["etag"]
    again = anon.get(f"{API}/feeds/blocklist/ip.txt", headers={"Authorization": f"Bearer {tok}", "If-None-Match": etag})
    assert again.status_code == 304
    basic = base64.b64encode(f"fw:{tok}".encode()).decode()
    assert anon.get(f"{API}/feeds/blocklist/ip.txt", headers={"Authorization": f"Basic {basic}"}).status_code == 200
    consumers = {t["name"]: t for t in admin.get(f"{API}/blocklist/feeds").json()}
    assert consumers["fw-etag"]["last_fetched_at"]                              # we can see who actually pulled


def test_entries_expire_and_leave_the_feed(admin, anon, db):
    tok = _token(admin, "fw-expiry")
    ip = "45.155.205.99"
    entry = admin.post(f"{API}/blocklist", json={"indicator": ip, "reason": "short lived block", "ttl_hours": 1}).json()
    assert ip in _feed(anon, tok).text
    row = db.get(BlocklistEntry, entry["id"])
    row.expires_at = naive_utc_now() - timedelta(minutes=1)
    db.commit()
    assert ip not in _feed(anon, tok).text                                      # excluded even before the worker runs
    assert svc.expire_due(db) >= 1
    db.refresh(row)
    assert row.status == "EXPIRED"


def test_ttl_is_capped_and_duplicates_are_not_created(admin):
    a = admin.post(f"{API}/blocklist", json={"indicator": "45.155.205.100", "reason": "first listing", "ttl_hours": 24 * 30}).json()
    b = admin.post(f"{API}/blocklist", json={"indicator": "45.155.205.100", "reason": "second listing"}).json()
    assert a["id"] == b["id"]
    assert admin.post(f"{API}/blocklist", json={"indicator": "45.155.205.101", "reason": "too long", "ttl_hours": 99999}).status_code == 422


def test_unsafe_indicator_is_rejected_through_the_api(admin):
    r = admin.post(f"{API}/blocklist", json={"indicator": "10.1.2.3", "reason": "internal host"})
    assert r.status_code == 422


def test_incident_actions_feed_the_blocklist_and_are_labelled_truthfully(analyst, admin):
    inc = analyst.get(f"{API}/incidents").json()[0]["incident_id"]
    res = analyst.post(f"{API}/incidents/{inc}/actions", json={"action_type": "IP_BLOCK", "target": "45.155.205.150"}).json()
    assert res["action_status"] == "PENDING_APPROVAL" and res["is_simulated"] is False and res["blocklist_entry_id"]
    manual = analyst.post(f"{API}/incidents/{inc}/actions", json={"action_type": "HOST_ISOLATION", "target": "WS-1042"}).json()
    assert manual["action_status"] == "RECORDED_MANUAL" and "no integration" in manual["message"]
    assert analyst.post(f"{API}/incidents/{inc}/actions", json={"action_type": "DROP_TABLES", "target": "x"}).status_code == 400
    assert analyst.post(f"{API}/incidents/{inc}/actions", json={"action_type": "IP_BLOCK", "target": "192.168.0.10"}).status_code == 422


def test_manual_action_does_not_flip_the_incident_to_contained(analyst, db):
    from app.models import Incident
    db.add(Incident(incident_id="INC-TEST-MANUAL", title="t", description="d", threat_category="Phishing",
                    severity="High", risk_score=70, status="New"))
    db.commit()
    analyst.post(f"{API}/incidents/INC-TEST-MANUAL/actions", json={"action_type": "HOST_ISOLATION", "target": "WS-1"})
    assert analyst.get(f"{API}/incidents/INC-TEST-MANUAL").json()["status"] == "New"
    analyst.post(f"{API}/incidents/INC-TEST-MANUAL/actions", json={"action_type": "IP_BLOCK", "target": "45.155.205.151"})
    assert analyst.get(f"{API}/incidents/INC-TEST-MANUAL").json()["status"] == "New"   # pending approval is not containment

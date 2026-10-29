"""Threat-intelligence lookups against fake VirusTotal and AbuseIPDB servers."""
import base64
import json

import httpx
import pytest

from app.config import settings
from app.models import ThreatIntelRecord
from app.services import threat_intel as ti
from app.utils.ratelimit import limiter

API = "/api/v1"
BAD_IP, CLEAN_IP = "185.220.101.47", "8.8.8.8"
BAD_HASH = "a" * 64


class Providers:
    def __init__(self):
        self.calls, self.mode = [], "ok"

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(str(request.url))
        if self.mode == "down":
            raise httpx.ConnectError("unreachable")
        if self.mode == "badkey":
            return httpx.Response(401, json={})
        if self.mode == "limit":
            return httpx.Response(429, json={})
        url = request.url
        if url.host == "api.abuseipdb.com":
            assert request.headers["Key"] == "abuse-key"
            ip = url.params["ipAddress"]
            score = 96 if ip == BAD_IP else 0
            return httpx.Response(200, json={"data": {"abuseConfidenceScore": score, "totalReports": 40 if score else 0,
                                                      "countryCode": "NL", "isp": "Bulletproof Hosting", "usageType": "Data Center"}})
        assert url.host == "www.virustotal.com" and request.headers["x-apikey"] == "vt-key"
        path = url.path.removeprefix("/api/v3/")
        if path.startswith("ip_addresses/"):
            mal = 14 if path.endswith(BAD_IP) else 0
        elif path.startswith("files/"):
            if path.endswith("f" * 64):
                return httpx.Response(404, json={"error": {"code": "NotFoundError"}})
            mal = 52 if path.endswith(BAD_HASH) else 0
        elif path.startswith("domains/"):
            mal = 9 if "evil" in path else 0
        else:
            mal = 0
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": mal, "suspicious": 0, "harmless": 60, "undetected": 10},
                                                                  "reputation": -20 if mal else 5, "meaningful_name": "Trojan.Test" if mal else None}}})


@pytest.fixture
def providers(monkeypatch, db):
    p = Providers()
    monkeypatch.setattr(ti, "_transport", httpx.MockTransport(p))
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "vt-key")
    monkeypatch.setattr(settings, "ABUSEIPDB_API_KEY", "abuse-key")
    db.query(ThreatIntelRecord).delete()
    db.commit()
    limiter.reset()
    yield p
    db.query(ThreatIntelRecord).delete()
    db.commit()


def test_classification():
    assert ti.classify("185.220.101.47")[0] == "ip"
    assert ti.classify("10.0.0.5")[0] == "internal" and ti.classify("192.168.1.1")[0] == "internal" and ti.classify("127.0.0.1")[0] == "internal"
    assert ti.classify("evil-site.com")[0] == "domain" and ti.classify("intranet.corp")[0] == "internal" and ti.classify("localhost")[0] == "internal"
    assert ti.classify("a" * 64)[0] == "hash" and ti.classify("d41d8cd98f00b204e9800998ecf8427e")[0] == "hash"
    assert ti.classify("https://evil-site.com/login?x=1")[0] == "url" and ti.classify("http://10.1.1.1/x")[0] == "internal"
    assert ti.classify("")[0] == "invalid" and ti.classify("not a thing!!")[0] == "invalid"


def test_internal_indicators_are_never_sent(db, providers):
    for indicator in ("10.1.2.3", "intranet", "wiki.corp", "http://192.168.0.9/admin"):
        assert ti.lookup(db, indicator)["results"] == []
    assert providers.calls == []


def test_a_bad_ip_is_flagged_by_both_providers(db, providers):
    r = ti.lookup(db, BAD_IP)
    assert r["malicious"] and {x["provider"] for x in r["results"]} == {"abuseipdb", "virustotal"}
    assert "96%" in next(x for x in r["results"] if x["provider"] == "abuseipdb")["summary"]
    assert not ti.lookup(db, CLEAN_IP)["suspicious"]


def test_answers_are_cached_and_refresh_forces_a_new_call(db, providers):
    ti.lookup(db, BAD_IP)
    n = len(providers.calls)
    again = ti.lookup(db, BAD_IP)
    assert len(providers.calls) == n and all(x["cached"] for x in again["results"])
    ti.lookup(db, BAD_IP, force=True)
    assert len(providers.calls) == n + 2


def test_a_file_hash_vt_has_never_seen_is_unknown_not_clean(db, providers):
    r = ti.lookup(db, "f" * 64)
    assert r["results"][0]["status"] == "not_found" and r["results"][0]["verdict"] == "unknown" and not r["suspicious"]


def test_url_lookups_send_only_the_domain_by_default(db, providers, monkeypatch):
    r = ti.lookup(db, "https://evil-site.com/reset?token=SECRET123")
    assert r["malicious"] and all("SECRET123" not in c for c in providers.calls) and any("domains/evil-site.com" in c for c in providers.calls)
    monkeypatch.setattr(settings, "TI_SEND_FULL_URLS", True)
    ti.lookup(db, "https://evil-two.com/reset?token=SECRET123")
    assert any("/urls/" in c for c in providers.calls)


def test_provider_errors_are_reported_not_hidden(db, providers):
    providers.mode = "down"
    r = ti.lookup(db, BAD_IP)
    assert {x["status"] for x in r["results"]} == {"error"} and not r["malicious"]
    providers.mode = "badkey"
    db.query(ThreatIntelRecord).delete()
    assert "rejected the API key" in " ".join(x["summary"] for x in ti.lookup(db, "9.9.9.9")["results"])


def test_failures_are_not_cached_for_long_but_are_not_hammered(db, providers):
    providers.mode = "down"
    ti.lookup(db, BAD_IP)
    n = len(providers.calls)
    ti.lookup(db, BAD_IP)
    assert len(providers.calls) == n                                  # inside the 10 minute error window
    providers.mode = "ok"
    assert not ti.lookup(db, BAD_IP, force=True)["results"][0]["status"] == "error"


def test_quota_is_respected(db, providers, monkeypatch):
    monkeypatch.setattr(settings, "TI_VT_PER_MINUTE", 1)
    first = ti.lookup(db, "evil-one.com")
    second = ti.lookup(db, "evil-two.com")
    assert first["results"][0]["status"] == "ok" and second["results"][0]["status"] == "rate_limited"


def test_not_configured_says_so(db, monkeypatch):
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", None)
    monkeypatch.setattr(settings, "ABUSEIPDB_API_KEY", None)
    assert {x["status"] for x in ti.lookup(db, BAD_IP)["results"]} == {"not_configured"}
    assert {p["state"] for p in ti.provider_status(db)} == {"not_configured"}


def test_status_is_connected_only_after_a_real_success(db, providers):
    assert {p["state"] for p in ti.provider_status(db)} <= {"unverified", "connected", "error"}
    assert ti.test_provider(db, "virustotal")["ok"] is True
    assert next(p for p in ti.provider_status(db) if p["provider"] == "virustotal")["state"] == "connected"
    providers.mode = "badkey"
    assert ti.test_provider(db, "abuseipdb")["ok"] is False
    assert next(p for p in ti.provider_status(db) if p["provider"] == "abuseipdb")["state"] == "error"


# ---------------------------------------------------------------------------------------- API and enrichment

def test_lookup_endpoint_is_for_staff_only(analyst, employee, anon, providers):
    assert anon.get(f"{API}/threat-intel/lookup", params={"indicator": BAD_IP}).status_code == 401
    assert employee.get(f"{API}/threat-intel/lookup", params={"indicator": BAD_IP}).status_code == 403
    assert analyst.get(f"{API}/threat-intel/lookup", params={"indicator": BAD_IP}).json()["malicious"] is True


def test_malicious_file_hash_raises_the_file_score(analyst, db, providers, monkeypatch):
    import hashlib
    from app.services import file_analyzer as fa
    payload = b"harmless looking text"
    real = hashlib.sha256(payload).hexdigest()
    monkeypatch.setattr(providers, "__call__", providers.__call__)
    # make the fake provider treat this file's real hash as the known-bad one
    original = Providers.__call__

    def patched(self, request):
        return original(self, httpx.Request(request.method, str(request.url).replace(real, BAD_HASH), headers=request.headers))
    monkeypatch.setattr(Providers, "__call__", patched)
    res = analyst.post(f"{API}/files/analyze", files={"file": ("memo.txt", payload)}).json()
    assert res["risk_score"] >= 90 and any("VirusTotal" in p for p in res["suspicious_patterns"])
    assert res["reputation_lookup"]["virustotal_status"] == "ok"


def test_url_analysis_uses_domain_reputation_but_not_for_popular_sites(analyst, db, providers):
    res = analyst.post(f"{API}/phishing/analyze", json={"submission_type": "url", "content": "https://evil-site.com/home"}).json()
    assert res["risk_score"] >= 90 and any(i["category"] == "Threat Intelligence" for i in res["indicators"])
    calls = len(providers.calls)
    analyst.post(f"{API}/phishing/analyze", json={"submission_type": "url", "content": "https://www.google.com/"})
    analyst.post(f"{API}/phishing/analyze", json={"submission_type": "url", "content": "http://localhost:8080/x"})
    assert len(providers.calls) == calls


def test_detectors_work_without_any_provider(analyst, monkeypatch):
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", None)
    monkeypatch.setattr(settings, "ABUSEIPDB_API_KEY", None)
    res = analyst.post(f"{API}/phishing/analyze", json={"submission_type": "url", "content": "http://login-microsoft365-verify.xyz/auth"}).json()
    assert res["risk_score"] >= 60 and "Local analysis only" in res["reputation_status"] or "No reputation service" in res["reputation_status"]


def test_l2_uses_reputation_as_evidence_and_a_known_bad_address_raises_confidence(db, providers, monkeypatch):
    from datetime import timedelta
    from app.models import Incident, SecurityEvent, naive_utc_now
    from app.services import soc_automation as soc
    from tests.conftest import wipe_soc

    def confidence(ip):
        wipe_soc(db)
        now = naive_utc_now()
        db.add(SecurityEvent(event_id=f"TI-{ip}", timestamp=now - timedelta(hours=1), event_source="Auth", threat_category="Account Compromise Suspected",
                             risk_score=70, severity="High", source_ip=ip, user_account="x@y.zz", evidence="e", recommended_action="a"))
        db.commit()
        soc.run_cycle(db)
        inc = db.query(Incident).first()
        analysis = json.loads(inc.l2_analysis)
        step = next(s for s in analysis["steps"] if s["step"].startswith("Reputation"))
        return inc.l2_confidence, step

    bad_conf, bad_step = confidence(BAD_IP)
    clean_conf, clean_step = confidence(CLEAN_IP)
    assert "Known malicious" in bad_step["finding"] and "No address is known malicious" in clean_step["finding"]
    assert bad_conf == round(clean_conf + 0.10, 2) or bad_conf > clean_conf
    from app.database import SessionLocal
    from app.services.demo_data_seeder import seed_demo_soc_data
    with SessionLocal() as s:
        seed_demo_soc_data(db=s, force_reset=True)

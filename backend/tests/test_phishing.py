import pytest
from app.services.phishing_engine import phishing_detector
from app.utils.ssrf_guard import validate_url_safe_for_inspection

def test_ssrf_guard_blocks_localhost():
    is_safe, msg = validate_url_safe_for_inspection("http://localhost:8080/admin")
    assert not is_safe
    assert "loopback/internal" in msg.lower() or "prohibited" in msg.lower()

def test_ssrf_guard_blocks_private_ip():
    is_safe, msg = validate_url_safe_for_inspection("http://192.168.1.1/router-login")
    assert not is_safe
    assert "private" in msg.lower() or "restricted" in msg.lower()

def test_ssrf_guard_blocks_cloud_metadata():
    is_safe, msg = validate_url_safe_for_inspection("http://169.254.169.254/latest/meta-data/")
    assert not is_safe

def test_phishing_url_detection():
    result = phishing_detector.analyze_url("http://login-microsoft365-verify.xyz/auth?session=123")
    assert result.risk_score >= 60
    assert result.risk_category in ("High", "Critical")
    assert any("Brand Squatting" in ind.signal for ind in result.indicators)

def test_benign_message_analysis():
    benign_text = "Hi team, please find attached the meeting notes from Thursday's design review."
    result = phishing_detector.analyze_message(content=benign_text, submission_type="email", email_subject="Design Review Notes")
    assert result.risk_score < 40
    assert result.risk_category == "Low"

def test_urgent_bec_email_analysis():
    bec_text = "URGENT: Please process an immediate wire transfer of $50,000 to contractor account before 5 PM today. Keep this strictly confidential."
    result = phishing_detector.analyze_message(content=bec_text, submission_type="email", email_subject="URGENT WIRE TRANSFER")
    assert result.risk_score >= 65
    assert result.risk_category in ("High", "Critical")
    assert any("Urgency" in ind.signal or "Financial" in ind.signal for ind in result.indicators)

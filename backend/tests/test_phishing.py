import pytest
from app.services.phishing_engine import phishing_detector

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
    assert any("Pressure" in ind.signal or "Payment" in ind.signal for ind in result.indicators)

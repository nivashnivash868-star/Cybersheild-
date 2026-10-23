import pytest
from app.services.file_analyzer import file_analyzer, calculate_shannon_entropy

def test_entropy_calculation():
    # Uniform repetitive bytes = low entropy
    low_data = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    assert calculate_shannon_entropy(low_data) == 0.0

    # High variance pseudo-random bytes = high entropy
    high_data = bytes([(i * 37 + 11) % 256 for i in range(1024)])
    assert calculate_shannon_entropy(high_data) > 7.0

def test_powershell_dropper_file_analysis():
    malicious_script = b"powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Enc aQBmACAA"
    result = file_analyzer.analyze_file_bytes("invoice_update.ps1", malicious_script)
    assert result.risk_score >= 50
    assert any("PowerShell" in p for p in result.suspicious_patterns)

def test_known_malware_hash_match():
    # EICAR standard AV signature hash
    eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    result = file_analyzer.analyze_file_bytes("eicar.com", eicar_bytes)
    assert result.reputation_lookup["match_found"] is True
    assert result.risk_score >= 80
    assert result.risk_category in ("High", "Critical")

def test_benign_pdf_analysis():
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF"
    result = file_analyzer.analyze_file_bytes("quarterly_report.pdf", pdf_bytes)
    assert result.risk_score < 40
    assert result.risk_category == "Low"

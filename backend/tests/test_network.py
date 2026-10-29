import pytest
from app.services.network_engine import network_detector
from app.schemas import NetworkRecordInput

def test_ssh_brute_force_detection():
    records = [
        NetworkRecordInput(source_ip="194.26.29.112", destination_ip="172.16.50.4", destination_port=22, auth_status="FAILED", user_account=u)
        for u in ("root", "admin", "deploy", "ubuntu", "test", "oracle")
    ]
    result = network_detector.analyze_batch(records)
    assert result.anomalies_detected >= 1
    assert any("Brute-Force" in a.event_type for a in result.alerts)

def test_port_scan_detection():
    records = [NetworkRecordInput(source_ip="45.143.200.12", destination_ip="172.16.50.8", destination_port=p) for p in range(20, 35)]
    result = network_detector.analyze_batch(records)
    assert result.anomalies_detected >= 1
    assert any("Port" in a.event_type for a in result.alerts)

def test_benign_traffic_no_alerts():
    records = [
        NetworkRecordInput(source_ip="10.0.12.50", destination_ip="1.1.1.1", destination_port=53, bytes_transferred=250, packet_count=2),
        NetworkRecordInput(source_ip="10.0.12.50", destination_ip="142.250.190.46", destination_port=443, bytes_transferred=14200, packet_count=18)
    ]
    result = network_detector.analyze_batch(records)
    assert result.anomalies_detected == 0
    assert result.benign_count == 2

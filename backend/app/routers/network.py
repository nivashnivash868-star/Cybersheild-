from datetime import datetime, timezone
from typing import List
from fastapi import APIRouter, Depends, Body
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import SecurityEvent, ThreatAnalysis, AuditLog
from app.schemas import NetworkRecordInput, NetworkAnalysisBatchResponse
from app.services.network_engine import network_detector

router = APIRouter(prefix="/network", tags=["Network Anomaly Detection"])

@router.post("/analyze-batch", response_model=NetworkAnalysisBatchResponse)
def analyze_network_batch(records: List[NetworkRecordInput] = Body(...), db: Session = Depends(get_db)):
    result = network_detector.analyze_batch(records)

    # Persist any generated alerts as SecurityEvents
    now = datetime.now(timezone.utc)
    for alert in result.alerts:
        sec_event = SecurityEvent(
            event_id=f"SEC-{alert.event_id}",
            timestamp=now,
            event_source="Network Anomaly Engine",
            threat_category=alert.event_type,
            risk_score=alert.risk_score,
            severity=alert.severity,
            source_ip=alert.source_ip,
            dest_ip=alert.destination_ip,
            domain=None,
            file_hash=None,
            user_account=None,
            evidence=f"{alert.detection_reason} Evidence: {', '.join(alert.evidence_tokens)}",
            analysis_status="Analyzed",
            recommended_action=alert.recommended_response
        )
        db.add(sec_event)

    audit = AuditLog(
        action="NETWORK_BATCH_ANALYZED",
        actor="SOC Analyst / Ingestion Pipeline",
        resource_type="NetworkBatch",
        resource_id=f"BATCH-{int(now.timestamp())}",
        details=f"Analyzed {result.total_records_analyzed} network records. Detected {result.anomalies_detected} anomalies ({result.benign_count} benign)."
    )
    db.add(audit)
    db.commit()

    return result

@router.get("/sample-scenarios")
def get_network_sample_scenarios():
    return [
        {
            "id": "brute_force_ssh",
            "name": "Distributed SSH Credential Brute-Force",
            "description": "5 sequential failed login attempts from external host 194.26.29.112 targeting port 22.",
            "records": [
                {"timestamp": "2026-10-22 14:10:01", "source_ip": "194.26.29.112", "destination_ip": "172.16.50.4", "destination_port": 22, "protocol": "TCP", "bytes_transferred": 1420, "packet_count": 8, "auth_status": "FAILED", "user_account": "root"},
                {"timestamp": "2026-10-22 14:10:04", "source_ip": "194.26.29.112", "destination_ip": "172.16.50.4", "destination_port": 22, "protocol": "TCP", "bytes_transferred": 1420, "packet_count": 8, "auth_status": "FAILED", "user_account": "admin"},
                {"timestamp": "2026-10-22 14:10:07", "source_ip": "194.26.29.112", "destination_ip": "172.16.50.4", "destination_port": 22, "protocol": "TCP", "bytes_transferred": 1420, "packet_count": 8, "auth_status": "FAILED", "user_account": "deploy"},
                {"timestamp": "2026-10-22 14:10:10", "source_ip": "194.26.29.112", "destination_ip": "172.16.50.4", "destination_port": 22, "protocol": "TCP", "bytes_transferred": 1420, "packet_count": 8, "auth_status": "FAILED", "user_account": "support"},
                {"timestamp": "2026-10-22 14:10:13", "source_ip": "194.26.29.112", "destination_ip": "172.16.50.4", "destination_port": 22, "protocol": "TCP", "bytes_transferred": 1420, "packet_count": 8, "auth_status": "FAILED", "user_account": "ubuntu"}
            ]
        },
        {
            "id": "port_scan_recon",
            "name": "Sequential Port Sweep Reconnaissance",
            "description": "Host 45.143.200.12 systematically querying open listening ports across DMZ gateway.",
            "records": [
                {"timestamp": "2026-10-22 14:15:10", "source_ip": "45.143.200.12", "destination_ip": "172.16.50.8", "destination_port": 21, "protocol": "TCP", "bytes_transferred": 64, "packet_count": 1, "auth_status": "SUCCESS"},
                {"timestamp": "2026-10-22 14:15:11", "source_ip": "45.143.200.12", "destination_ip": "172.16.50.8", "destination_port": 22, "protocol": "TCP", "bytes_transferred": 64, "packet_count": 1, "auth_status": "SUCCESS"},
                {"timestamp": "2026-10-22 14:15:12", "source_ip": "45.143.200.12", "destination_ip": "172.16.50.8", "destination_port": 23, "protocol": "TCP", "bytes_transferred": 64, "packet_count": 1, "auth_status": "SUCCESS"},
                {"timestamp": "2026-10-22 14:15:13", "source_ip": "45.143.200.12", "destination_ip": "172.16.50.8", "destination_port": 80, "protocol": "TCP", "bytes_transferred": 64, "packet_count": 1, "auth_status": "SUCCESS"},
                {"timestamp": "2026-10-22 14:15:14", "source_ip": "45.143.200.12", "destination_ip": "172.16.50.8", "destination_port": 443, "protocol": "TCP", "bytes_transferred": 64, "packet_count": 1, "auth_status": "SUCCESS"},
                {"timestamp": "2026-10-22 14:15:15", "source_ip": "45.143.200.12", "destination_ip": "172.16.50.8", "destination_port": 3389, "protocol": "TCP", "bytes_transferred": 64, "packet_count": 1, "auth_status": "SUCCESS"}
            ]
        },
        {
            "id": "data_exfil_spike",
            "name": "Massive Outbound Data Exfiltration Spike",
            "description": "Internal workstation pushing 8.4MB archive to unindexed foreign destination.",
            "records": [
                {"timestamp": "2026-10-22 14:20:00", "source_ip": "10.0.12.84", "destination_ip": "185.220.101.45", "destination_port": 443, "protocol": "TCP", "bytes_transferred": 8800000, "packet_count": 6200, "auth_status": "SUCCESS"}
            ]
        },
        {
            "id": "benign_traffic",
            "name": "Nominal Enterprise Web & DNS Traffic",
            "description": "Baseline HTTP/HTTPS and DNS traffic with expected nominal byte counts.",
            "records": [
                {"timestamp": "2026-10-22 14:25:01", "source_ip": "10.0.12.50", "destination_ip": "1.1.1.1", "destination_port": 53, "protocol": "UDP", "bytes_transferred": 240, "packet_count": 2, "auth_status": "SUCCESS"},
                {"timestamp": "2026-10-22 14:25:03", "source_ip": "10.0.12.50", "destination_ip": "142.250.190.46", "destination_port": 443, "protocol": "TCP", "bytes_transferred": 28400, "packet_count": 32, "auth_status": "SUCCESS"},
                {"timestamp": "2026-10-22 14:25:05", "source_ip": "10.0.12.51", "destination_ip": "151.101.65.140", "destination_port": 443, "protocol": "TCP", "bytes_transferred": 14200, "packet_count": 18, "auth_status": "SUCCESS"}
            ]
        }
    ]

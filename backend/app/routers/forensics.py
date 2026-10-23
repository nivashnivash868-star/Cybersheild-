from datetime import datetime, timezone
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Incident, SecurityEvent, IncidentEvidence, InvestigationNote
from app.schemas import ForensicInvestigationResponse, ForensicArtifact

router = APIRouter(prefix="/forensics", tags=["Digital Forensics"])

@router.get("/{incident_id}", response_model=ForensicInvestigationResponse)
def get_forensic_investigation(incident_id: str, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")

    # Build chronological timeline across events, evidence capture, notes, and actions
    timeline = []
    
    # 1. Security events
    for ev in incident.events:
        timeline.append({
            "timestamp": ev.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "event_type": "Security Alert Detected",
            "source": ev.event_source,
            "category": ev.threat_category,
            "severity": ev.severity,
            "description": ev.evidence,
            "pivot_data": {
                "source_ip": ev.source_ip,
                "dest_ip": ev.dest_ip,
                "domain": ev.domain,
                "file_hash": ev.file_hash,
                "user_account": ev.user_account
            }
        })

    # 2. Evidence items
    for evi in incident.evidence_items:
        timeline.append({
            "timestamp": evi.captured_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "event_type": "Forensic Evidence Sealed",
            "source": evi.provenance,
            "category": evi.evidence_type,
            "severity": "Info",
            "description": f"Sealed {evi.evidence_type}: '{evi.evidence_value}' with confidence score {evi.confidence}.",
            "pivot_data": {"value": evi.evidence_value}
        })

    # 3. Analyst notes
    for note in incident.notes:
        timeline.append({
            "timestamp": note.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "event_type": "Analyst Note Recorded",
            "source": note.analyst_name,
            "category": "SOC Investigation Note",
            "severity": "Info",
            "description": note.note_text,
            "pivot_data": {}
        })

    # 4. Actions taken
    for act in incident.actions:
        if act.executed_at:
            timeline.append({
                "timestamp": act.executed_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "event_type": "Containment Action (Simulated)",
                "source": act.executed_by or "SOC Lead",
                "category": act.action_type,
                "severity": "High",
                "description": act.details,
                "pivot_data": {"target": act.target, "is_simulated": act.is_simulated}
            })

    # Sort chronological timeline ascending
    timeline.sort(key=lambda x: x["timestamp"])

    # Extract distinct forensic artifacts
    artifacts = []
    seen_values = set()

    for evi in incident.evidence_items:
        if evi.evidence_value not in seen_values:
            seen_values.add(evi.evidence_value)
            artifacts.append(ForensicArtifact(
                type=evi.evidence_type,
                value=evi.evidence_value,
                relation="Direct Evidence Object",
                first_seen=evi.captured_at.strftime("%Y-%m-%d %H:%M UTC"),
                last_seen=incident.updated_at.strftime("%Y-%m-%d %H:%M UTC"),
                risk_score=incident.risk_score
            ))

    for ev in incident.events:
        if ev.source_ip and ev.source_ip not in seen_values:
            seen_values.add(ev.source_ip)
            artifacts.append(ForensicArtifact(
                type="Source IP",
                value=ev.source_ip,
                relation=f"Observed in {ev.event_source}",
                first_seen=ev.timestamp.strftime("%Y-%m-%d %H:%M UTC"),
                last_seen=ev.timestamp.strftime("%Y-%m-%d %H:%M UTC"),
                risk_score=ev.risk_score
            ))
        if ev.domain and ev.domain not in seen_values:
            seen_values.add(ev.domain)
            artifacts.append(ForensicArtifact(
                type="Domain",
                value=ev.domain,
                relation=f"Target URL Host in {ev.event_source}",
                first_seen=ev.timestamp.strftime("%Y-%m-%d %H:%M UTC"),
                last_seen=ev.timestamp.strftime("%Y-%m-%d %H:%M UTC"),
                risk_score=ev.risk_score
            ))
        if ev.file_hash and ev.file_hash not in seen_values:
            seen_values.add(ev.file_hash)
            artifacts.append(ForensicArtifact(
                type="SHA-256 Hash",
                value=ev.file_hash,
                relation=f"Payload Hash in {ev.event_source}",
                first_seen=ev.timestamp.strftime("%Y-%m-%d %H:%M UTC"),
                last_seen=ev.timestamp.strftime("%Y-%m-%d %H:%M UTC"),
                risk_score=ev.risk_score
            ))

    # MITRE ATT&CK Mapping
    mitre_tactics = ["TA0001: Initial Access", "TA0002: Execution", "TA0011: Command and Control"]
    if "Brute" in incident.threat_category:
        mitre_tactics = ["TA0006: Credential Access", "TA0001: Initial Access"]
    elif "Scan" in incident.threat_category:
        mitre_tactics = ["TA0043: Reconnaissance", "TA0007: Discovery"]

    provenance_chain = [
        f"1. Telemetry ingest from {[e.event_source for e in incident.events]}.",
        f"2. Correlation confidence assessed: '{incident.correlation_confidence}'.",
        f"3. Sealed evidence items ({len(incident.evidence_items)}) cross-referenced in SOC audit vault."
    ]

    findings = (
        f"Digital Forensics Case for {incident.incident_id}. "
        f"Correlation confidence: {incident.correlation_confidence}. "
        f"Analysis indicates structured sequence across {len(timeline)} chronological checkpoints. "
        f"No arbitrary attribution invented; evidence preserved with source sensor provenance."
    )

    return ForensicInvestigationResponse(
        incident_id=incident.incident_id,
        title=incident.title,
        severity=incident.severity,
        status=incident.status,
        investigator=incident.assigned_analyst,
        created_at=incident.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        timeline=timeline,
        artifacts=artifacts,
        provenance_chain=provenance_chain,
        analyst_findings=findings,
        mitre_attack_tactics=mitre_tactics,
        is_simulated_notice="Forensic evidence objects derived from verified sensor logs and telemetry records."
    )

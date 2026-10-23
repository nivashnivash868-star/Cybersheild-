from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Incident, IncidentEvidence, InvestigationNote, ResponseAction, AuditLog, SecurityEvent
from app.schemas import (
    IncidentDetailResponse, IncidentStatusUpdateRequest, IncidentAssignRequest,
    AddNoteRequest, ExecuteResponseActionRequest
)
from app.services.correlation_engine import correlation_engine

router = APIRouter(prefix="/incidents", tags=["Threat Prevention & Incident Response"])

@router.get("", response_model=List[IncidentDetailResponse])
def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(Incident)
    if status and status != "All":
        query = query.filter(Incident.status == status)
    if severity and severity != "All":
        query = query.filter(Incident.severity == severity)
    if search:
        s = f"%{search}%"
        query = query.filter(
            Incident.incident_id.ilike(s) |
            Incident.title.ilike(s) |
            Incident.threat_category.ilike(s) |
            Incident.assigned_analyst.ilike(s)
        )
    incidents = query.order_by(Incident.created_at.desc()).offset(offset).limit(limit).all()
    return incidents

@router.get("/{incident_id}", response_model=IncidentDetailResponse)
def get_incident_detail(incident_id: str, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")
    return incident

@router.patch("/{incident_id}/status")
def update_incident_status(incident_id: str, payload: IncidentStatusUpdateRequest, db: Session = Depends(get_db)):
    valid_statuses = ["New", "Investigating", "Contained", "Resolved", "False Positive"]
    if payload.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status '{payload.status}'. Allowed: {valid_statuses}")

    incident = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")

    old_status = incident.status
    incident.status = payload.status
    incident.updated_at = datetime.now(timezone.utc)

    # Optional investigation note on status change
    if payload.comment:
        note = InvestigationNote(
            incident_id=incident_id,
            analyst_name=payload.analyst_name or "SOC Analyst",
            note_text=f"[Status changed from {old_status} to {payload.status}] {payload.comment}"
        )
        db.add(note)

    audit = AuditLog(
        action="INCIDENT_STATUS_CHANGE",
        actor=payload.analyst_name or "SOC Analyst",
        resource_type="Incident",
        resource_id=incident_id,
        details=f"Status transitioned from {old_status} to {payload.status}. Comment: {payload.comment or 'None'}"
    )
    db.add(audit)
    db.commit()

    return {"status": "success", "incident_id": incident_id, "new_status": payload.status}

@router.patch("/{incident_id}/assign")
def assign_incident_analyst(incident_id: str, payload: IncidentAssignRequest, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")

    old_analyst = incident.assigned_analyst
    incident.assigned_analyst = payload.assigned_analyst
    if incident.status == "New":
        incident.status = "Investigating"
    incident.updated_at = datetime.now(timezone.utc)

    audit = AuditLog(
        action="INCIDENT_ASSIGNED",
        actor="SOC Lead",
        resource_type="Incident",
        resource_id=incident_id,
        details=f"Assigned analyst updated from '{old_analyst}' to '{payload.assigned_analyst}'"
    )
    db.add(audit)
    db.commit()

    return {"status": "success", "incident_id": incident_id, "assigned_analyst": payload.assigned_analyst}

@router.post("/{incident_id}/notes")
def add_investigation_note(incident_id: str, payload: AddNoteRequest, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")

    note = InvestigationNote(
        incident_id=incident_id,
        analyst_name=payload.analyst_name,
        note_text=payload.note_text
    )
    db.add(note)

    audit = AuditLog(
        action="NOTE_ADDED",
        actor=payload.analyst_name,
        resource_type="Incident",
        resource_id=incident_id,
        details=f"Added forensic note: {payload.note_text[:60]}..."
    )
    db.add(audit)
    db.commit()

    return {"status": "success", "note_id": note.id, "created_at": note.created_at}

@router.post("/{incident_id}/actions")
def execute_response_action(incident_id: str, payload: ExecuteResponseActionRequest, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")

    now = datetime.now(timezone.utc)
    
    # Create or update response action
    action = ResponseAction(
        incident_id=incident_id,
        action_type=payload.action_type,
        target=payload.target,
        status="SIMULATED_EXECUTED",
        details=payload.details or f"Simulated {payload.action_type} executed for target {payload.target}.",
        is_simulated=True,
        executed_by="Active SOC Analyst",
        executed_at=now
    )
    db.add(action)

    # If action is containment, advance incident status
    if payload.action_type in ["FIREWALL_BLOCK", "HOST_ISOLATION"] and incident.status in ["New", "Investigating"]:
        incident.status = "Contained"

    incident.updated_at = now

    audit = AuditLog(
        action="RESPONSE_ACTION_SIMULATED",
        actor="Active SOC Analyst",
        resource_type="Incident",
        resource_id=incident_id,
        details=f"Executed simulated response '{payload.action_type}' against target '{payload.target}'."
    )
    db.add(audit)
    db.commit()

    return {
        "status": "success",
        "action_id": action.id,
        "is_simulated": True,
        "message": (
            f"Simulated response action '{payload.action_type}' recorded successfully. "
            "NOTE: Action is simulated. Production firewall/EDR push requires active provider API credentials."
        )
    }

@router.post("/correlate")
def run_correlation_cycle(db: Session = Depends(get_db)):
    results = correlation_engine.run_correlation(db)
    return {
        "status": "success",
        "correlations_created": len(results),
        "details": results
    }

@router.get("/{incident_id}/export")
def export_incident_report(incident_id: str, format: str = Query("json", pattern="^(json|text|csv)$"), db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")

    if format == "json":
        return incident

    # Text / Forensics format
    lines = [
        f"=" * 70,
        f"CYBERSHIELD AI — DIGITAL FORENSIC INCIDENT REPORT",
        f"=" * 70,
        f"INCIDENT ID:          {incident.incident_id}",
        f"TITLE:                {incident.title}",
        f"SEVERITY:             {incident.severity} (Risk Score: {incident.risk_score}/100)",
        f"STATUS:               {incident.status}",
        f"ASSIGNED ANALYST:     {incident.assigned_analyst}",
        f"CREATED AT:           {incident.created_at} UTC",
        f"LAST UPDATED:         {incident.updated_at} UTC",
        f"CORRELATION CONF.:    {incident.correlation_confidence}",
        f"CORRELATION REASON:   {incident.correlation_reason}",
        f"-" * 70,
        f"EXECUTIVE SUMMARY & FORENSIC TRIAGE:",
        f"{incident.forensic_summary or 'No forensic summary compiled yet.'}",
        f"-" * 70,
        f"EVIDENCE INVENTORY ({len(incident.evidence_items)} items):"
    ]
    for ev in incident.evidence_items:
        lines.append(f"  * [{ev.evidence_type}] {ev.evidence_value} (Provenance: {ev.provenance}, Confidence: {ev.confidence})")

    lines.append(f"-" * 70)
    lines.append(f"INVESTIGATION NOTES ({len(incident.notes)} entries):")
    for n in incident.notes:
        lines.append(f"  * [{n.created_at}] {n.analyst_name}: {n.note_text}")

    lines.append(f"-" * 70)
    lines.append(f"RESPONSE ACTIONS TAKEN ({len(incident.actions)} actions):")
    for a in incident.actions:
        lines.append(f"  * [{a.status}] {a.action_type} -> {a.target} (Simulated: {a.is_simulated}) - {a.details}")

    lines.append(f"=" * 70)
    lines.append(f"CONFIDENTIAL — LAW ENFORCEMENT & SOC AUDIT RECORD ONLY")

    return PlainTextResponse("\n".join(lines), media_type="text/plain")

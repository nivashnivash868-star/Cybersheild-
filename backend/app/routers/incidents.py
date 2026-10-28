from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Incident, IncidentEvidence, InvestigationNote, ResponseAction, AuditLog, SecurityEvent, User
from app.schemas import (
    IncidentDetailResponse, IncidentStatusUpdateRequest, IncidentAssignRequest,
    AddNoteRequest, ExecuteResponseActionRequest
)
from app.services import blocklist as blocklist_service
from app.services import soc_automation
from app.services.correlation_engine import correlation_engine
from app.utils.auth import ADMIN_ROLES, STAFF_ROLES, require_authenticated_user

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
def update_incident_status(incident_id: str, payload: IncidentStatusUpdateRequest, db: Session = Depends(get_db),
                           user: User = Depends(require_authenticated_user)):
    valid_statuses = ["New", "Investigating", "Contained", "Resolved", "False Positive"]
    if payload.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status '{payload.status}'. Allowed: {valid_statuses}")

    incident = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")

    # Final closure of a Critical incident is not an analyst's decision alone: it becomes a request for an administrator.
    if payload.status in ("Resolved", "False Positive") and incident.severity == "Critical" and user.role not in ADMIN_ROLES:
        req = soc_automation.request_closure(db, incident, user, payload.status, payload.comment)
        db.commit()
        return {"status": "approval_requested", "incident_id": incident_id, "decision_id": req.id,
                "message": "Closing a Critical incident needs a Security Administrator's approval. The request has been sent."}

    old_status = incident.status
    incident.status = payload.status
    incident.updated_at = datetime.now(timezone.utc)

    # Optional investigation note on status change
    if payload.comment:
        note = InvestigationNote(
            incident_id=incident_id,
            analyst_name=user.full_name,
            note_text=f"[Status changed from {old_status} to {payload.status}] {payload.comment}"
        )
        db.add(note)

    audit = AuditLog(
        action="INCIDENT_STATUS_CHANGE",
        actor=user.email,
        resource_type="Incident",
        resource_id=incident_id,
        details=f"Status transitioned from {old_status} to {payload.status}. Comment: {payload.comment or 'None'}"
    )
    db.add(audit)
    db.commit()

    return {"status": "success", "incident_id": incident_id, "new_status": payload.status}

@router.patch("/{incident_id}/assign")
def assign_incident_analyst(incident_id: str, payload: IncidentAssignRequest, db: Session = Depends(get_db),
                            user: User = Depends(require_authenticated_user)):
    incident = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")

    assignee = db.query(User).filter(User.is_active.is_(True), User.role.in_(STAFF_ROLES),
                                     (User.full_name == payload.assigned_analyst) | (User.email == payload.assigned_analyst.lower())).first()
    if assignee is None:
        raise HTTPException(status_code=422, detail="Cases can only be assigned to an active analyst or administrator.")
    old_analyst = incident.assigned_analyst
    incident.assigned_analyst = assignee.full_name
    payload.assigned_analyst = assignee.full_name
    if incident.status == "New":
        incident.status = "Investigating"
    incident.updated_at = datetime.now(timezone.utc)

    audit = AuditLog(
        action="INCIDENT_ASSIGNED",
        actor=user.email,
        resource_type="Incident",
        resource_id=incident_id,
        details=f"Assigned analyst updated from '{old_analyst}' to '{payload.assigned_analyst}'"
    )
    db.add(audit)
    db.commit()

    return {"status": "success", "incident_id": incident_id, "assigned_analyst": payload.assigned_analyst}

@router.post("/{incident_id}/notes")
def add_investigation_note(incident_id: str, payload: AddNoteRequest, db: Session = Depends(get_db),
                           user: User = Depends(require_authenticated_user)):
    incident = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")

    note = InvestigationNote(
        incident_id=incident_id,
        analyst_name=user.full_name,
        note_text=payload.note_text
    )
    db.add(note)

    audit = AuditLog(
        action="NOTE_ADDED",
        actor=user.email,
        resource_type="Incident",
        resource_id=incident_id,
        details=f"Added forensic note: {payload.note_text[:60]}..."
    )
    db.add(audit)
    db.commit()

    return {"status": "success", "note_id": note.id, "created_at": note.created_at}

BLOCKING_ACTIONS = {"FIREWALL_BLOCK", "IP_BLOCK", "URL_BLOCK", "DOMAIN_BLOCK"}
MANUAL_ACTIONS = {"HOST_ISOLATION", "SESSION_REVOKE", "EMAIL_PURGE", "SECRET_REVOKE"}


@router.post("/{incident_id}/actions")
def execute_response_action(incident_id: str, payload: ExecuteResponseActionRequest, db: Session = Depends(get_db),
                            user: User = Depends(require_authenticated_user)):
    """
    Blocking actions create a blocklist entry: administrators publish it immediately, analysts' proposals wait
    for approval. The entry is then served to firewalls / DNS sinkholes through the authenticated feeds.
    Other action types are recorded as manual work: the platform has no integration that performs them.
    """
    incident = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")
    if payload.action_type not in BLOCKING_ACTIONS | MANUAL_ACTIONS:
        raise HTTPException(status_code=400, detail=f"Unknown action type. Allowed: {sorted(BLOCKING_ACTIONS | MANUAL_ACTIONS)}")

    now = datetime.now(timezone.utc)
    if payload.action_type in BLOCKING_ACTIONS:
        reason = payload.details or f"{payload.action_type} from {incident_id}: {incident.title}"
        entry, created = blocklist_service.propose(
            db, payload.target, reason, user.email, auto_approve=user.role in ADMIN_ROLES,
            incident_id=incident_id, ttl_hours=payload.ttl_hours,
        )
        published = entry.status == "ACTIVE"
        action = ResponseAction(
            incident_id=incident_id, action_type=payload.action_type, target=entry.value,
            status="PUBLISHED_TO_FEED" if published else "PENDING_APPROVAL",
            details=(f"Blocklist entry #{entry.id} ({entry.indicator_type}) "
                     f"{'published until ' + str(entry.expires_at) + ' UTC' if published else 'awaiting administrator approval'}."),
            is_simulated=False, executed_by=user.email, executed_at=now if published else None,
        )
        message = (f"Blocklist entry #{entry.id} is {'live in the feeds' if published else 'pending approval'}. "
                   "Enforcement happens when your firewall or DNS sinkhole next pulls the feed.")
    else:
        entry = None
        action = ResponseAction(
            incident_id=incident_id, action_type=payload.action_type, target=payload.target,
            status="RECORDED_MANUAL",
            details=payload.details or "Recorded by the analyst. The platform did not perform this action.",
            is_simulated=False, executed_by=user.email, executed_at=now,
        )
        message = "Recorded as a manual action. The platform has no integration that performs it."
    db.add(action)
    incident.updated_at = now
    db.add(AuditLog(
        action="RESPONSE_ACTION", actor=user.email, resource_type="Incident", resource_id=incident_id,
        details=f"{payload.action_type} on '{action.target}' -> {action.status}.",
    ))
    db.commit()
    return {
        "status": "success", "action_id": action.id, "action_status": action.status, "is_simulated": False,
        "blocklist_entry_id": entry.id if entry else None, "message": message,
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

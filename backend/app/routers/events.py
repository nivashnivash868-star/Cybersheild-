from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException, Body
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import AgentRun, SecurityEvent, AuditLog, User
from app.utils.auth import require_authenticated_user
from app.schemas import SecurityEventResponse, AcknowledgeEventRequest

router = APIRouter(prefix="/events", tags=["Unified Security Events"])

@router.get("", response_model=List[SecurityEventResponse])
def list_security_events(
    severity: Optional[str] = None,
    threat_category: Optional[str] = None,
    source: Optional[str] = None,
    is_acknowledged: Optional[bool] = None,
    search: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(SecurityEvent)
    if severity and severity != "All":
        query = query.filter(SecurityEvent.severity == severity)
    if threat_category and threat_category != "All":
        query = query.filter(SecurityEvent.threat_category.ilike(f"%{threat_category}%"))
    if source and source != "All":
        query = query.filter(SecurityEvent.event_source.ilike(f"%{source}%"))
    if is_acknowledged is not None:
        query = query.filter(SecurityEvent.is_acknowledged == is_acknowledged)
    if search:
        s = f"%{search}%"
        query = query.filter(
            SecurityEvent.event_id.ilike(s) |
            SecurityEvent.threat_category.ilike(s) |
            SecurityEvent.source_ip.ilike(s) |
            SecurityEvent.dest_ip.ilike(s) |
            SecurityEvent.domain.ilike(s) |
            SecurityEvent.file_hash.ilike(s) |
            SecurityEvent.user_account.ilike(s) |
            SecurityEvent.evidence.ilike(s)
        )
    events = query.order_by(SecurityEvent.timestamp.desc()).offset(offset).limit(limit).all()
    return events

@router.get("/{event_id}")
def get_event_detail(event_id: str, db: Session = Depends(get_db)):
    """Everything an analyst needs to judge one alert: the alert, the triage decision, and what else involves the same entities."""
    ev = db.query(SecurityEvent).filter(SecurityEvent.event_id == event_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail=f"Event '{event_id}' not found.")
    conds = []
    if ev.source_ip:
        conds += [SecurityEvent.source_ip == ev.source_ip, SecurityEvent.dest_ip == ev.source_ip]
    if ev.user_account:
        conds.append(SecurityEvent.user_account == ev.user_account)
    if ev.domain:
        conds.append(SecurityEvent.domain == ev.domain)
    related = []
    if conds:
        from sqlalchemy import or_
        related = db.query(SecurityEvent).filter(or_(*conds), SecurityEvent.id != ev.id).order_by(SecurityEvent.timestamp.desc()).limit(25).all()
    runs = db.query(AgentRun).filter(AgentRun.subject_type == "event", AgentRun.subject_id == ev.event_id).order_by(AgentRun.id).all()
    ordered = sorted([ev] + related, key=lambda e: e.timestamp)
    return {
        "event": SecurityEventResponse.model_validate(ev),
        "related_events": [SecurityEventResponse.model_validate(e) for e in related],
        "timeline": [{"time": e.timestamp, "event_id": e.event_id, "category": e.threat_category, "severity": e.severity,
                      "source": e.event_source, "this": e.id == ev.id} for e in ordered],
        "automation": [{"tier": r.tier, "decision": r.decision, "reason": r.reason, "confidence": r.confidence, "at": r.created_at} for r in runs],
    }


@router.patch("/{event_id}/acknowledge")
def acknowledge_security_event(
    event_id: str,
    payload: Optional[AcknowledgeEventRequest] = Body(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(require_authenticated_user),
):
    ev = db.query(SecurityEvent).filter(SecurityEvent.event_id == event_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail=f"Event '{event_id}' not found.")

    analyst = user.email
    now = datetime.now(timezone.utc)

    ev.is_acknowledged = True
    ev.acknowledged_by = analyst
    ev.acknowledged_at = now

    audit = AuditLog(
        action="EVENT_ACKNOWLEDGED",
        actor=analyst,
        resource_type="SecurityEvent",
        resource_id=event_id,
        details=f"Alert {event_id} acknowledged by {analyst}."
    )
    db.add(audit)
    db.commit()

    return {
        "status": "success",
        "event_id": event_id,
        "is_acknowledged": True,
        "acknowledged_by": analyst,
        "acknowledged_at": now.isoformat()
    }

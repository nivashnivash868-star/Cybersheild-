import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AgentRun, AuditLog, DecisionRequest, DetectionRule, Incident, SecurityEvent, User, naive_utc_now
from app.config import settings
from app.services import response_executor, settings_store, soc_automation
from app.utils.auth import ADMIN_ROLES, STAFF_ROLES, require_roles

router = APIRouter(prefix="/soc", tags=["Tiered SOC: L1/L2 automation, L3 human decisions"])


class AgentRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    tier: str
    agent: str
    subject_type: str
    subject_id: str
    decision: str
    reason: str
    confidence: Optional[float] = None
    duration_ms: int
    created_at: datetime


class DecisionOut(BaseModel):
    requires_admin: bool = False
    id: int
    kind: str
    incident_id: Optional[str]
    title: str
    rationale: str
    evidence: List[str]
    proposal: Dict[str, Any]
    priority: str
    status: str
    created_by: str
    created_at: datetime
    decided_by: Optional[str]
    decided_at: Optional[datetime]
    decision_note: Optional[str]
    outcome: Optional[str]


class DecideIn(BaseModel):
    decision: str = Field(..., pattern="^(approve|reject)$")
    note: Optional[str] = Field(None, max_length=500)


class RuleIn(BaseModel):
    name: str = Field(..., min_length=3, max_length=128)
    kind: str = Field(..., pattern="^(SUPPRESS|ESCALATE)$")
    match: Dict[str, Any]
    description: Optional[str] = Field(None, max_length=500)


class RuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    description: Optional[str]
    kind: str
    match: Dict[str, Any] = {}
    enabled: bool
    created_by: str
    created_at: datetime
    hit_count: int
    last_hit_at: Optional[datetime]


def _decision(d: DecisionRequest) -> DecisionOut:
    return DecisionOut(
        id=d.id, kind=d.kind, incident_id=d.incident_id, title=d.title, rationale=d.rationale,
        evidence=json.loads(d.evidence or "[]"), proposal=json.loads(d.proposal), priority=d.priority, status=d.status,
        created_by=d.created_by, created_at=d.created_at, decided_by=d.decided_by, decided_at=d.decided_at,
        decision_note=d.decision_note, outcome=d.outcome, requires_admin=d.kind in soc_automation.ADMIN_ONLY_KINDS)


def _rule(r: DetectionRule) -> RuleOut:
    out = RuleOut.model_validate(r)
    out.match = json.loads(r.match_json)
    return out


@router.get("/overview")
def overview(db: Session = Depends(get_db), _: User = Depends(require_roles(STAFF_ROLES))):
    by_triage = dict(db.query(SecurityEvent.triage_status, func.count(SecurityEvent.id)).group_by(SecurityEvent.triage_status).all())
    total_events = sum(by_triage.values())
    triaged = total_events - by_triage.get("NEW", 0)
    auto_closed = by_triage.get("AUTO_CLOSED", 0) + by_triage.get("DUPLICATE", 0)
    verdicts = dict(db.query(Incident.l2_verdict, func.count(Incident.id)).filter(Incident.l2_status == "DONE").group_by(Incident.l2_verdict).all())
    auto_fp = db.query(Incident).filter(Incident.disposition == "AUTO_FALSE_POSITIVE").count()
    by_decision = dict(db.query(DecisionRequest.status, func.count(DecisionRequest.id)).group_by(DecisionRequest.status).all())
    pending_by_kind = dict(db.query(DecisionRequest.kind, func.count(DecisionRequest.id)).filter(DecisionRequest.status == "PENDING").group_by(DecisionRequest.kind).all())
    # events that never needed a person: closed by L1, plus those in incidents L2 closed as false positives
    fp_events = db.query(SecurityEvent).join(Incident, SecurityEvent.incident_id == Incident.incident_id).filter(
        Incident.disposition == "AUTO_FALSE_POSITIVE").count()
    handled_by_automation = auto_closed + fp_events
    return {
        "l1": {"events_total": total_events, "triaged": triaged, "waiting": by_triage.get("NEW", 0),
               "auto_closed": by_triage.get("AUTO_CLOSED", 0), "duplicates": by_triage.get("DUPLICATE", 0),
               "escalated": by_triage.get("ESCALATED", 0)},
        "l2": {"incidents_investigated": sum(verdicts.values()), "waiting": db.query(Incident).filter(Incident.l2_status == "PENDING").count(),
               "true_positive": verdicts.get("TRUE_POSITIVE", 0), "needs_human": verdicts.get("NEEDS_HUMAN", 0),
               "false_positive": verdicts.get("FALSE_POSITIVE", 0), "auto_closed_incidents": auto_fp},
        "l3": {"pending": by_decision.get("PENDING", 0), "approved": by_decision.get("APPROVED", 0), "rejected": by_decision.get("REJECTED", 0),
               "pending_by_kind": pending_by_kind, "active_rules": db.query(DetectionRule).filter(DetectionRule.enabled.is_(True)).count()},
        "automation_rate": round(handled_by_automation / triaged, 3) if triaged else None,
        "response_connector": {"configured": response_executor.configured(), "actions": sorted(settings.response_actions) if response_executor.configured() else []},
    }


@router.get("/activity", response_model=List[AgentRunOut])
def activity(tier: Optional[str] = Query(None, pattern="^(L1|L2)$"), limit: int = Query(50, ge=1, le=200),
             db: Session = Depends(get_db), _: User = Depends(require_roles(STAFF_ROLES))):
    q = db.query(AgentRun)
    if tier:
        q = q.filter(AgentRun.tier == tier)
    return q.order_by(AgentRun.id.desc()).limit(limit).all()


@router.get("/decisions", response_model=List[DecisionOut])
def list_decisions(status: Optional[str] = Query("PENDING", pattern="^(PENDING|APPROVED|REJECTED|All)$"),
                   kind: Optional[str] = None, limit: int = Query(100, ge=1, le=300), db: Session = Depends(get_db),
                   _: User = Depends(require_roles(STAFF_ROLES))):
    q = db.query(DecisionRequest)
    if status and status != "All":
        q = q.filter(DecisionRequest.status == status)
    if kind:
        q = q.filter(DecisionRequest.kind == kind)
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    rows = q.order_by(DecisionRequest.id.desc()).limit(limit).all()
    rows.sort(key=lambda d: (order.get(d.priority, 4), -d.id) if d.status == "PENDING" else (9, -d.id))
    return [_decision(d) for d in rows]


@router.post("/decisions/{decision_id}/decide", response_model=DecisionOut)
def decide(decision_id: int, payload: DecideIn, db: Session = Depends(get_db), user: User = Depends(require_roles(STAFF_ROLES))):
    """The L3 human decision. Only people can approve a block, dismiss an incident or activate a detection rule."""
    req = db.get(DecisionRequest, decision_id)
    if not req:
        raise HTTPException(404, "Decision not found.")
    soc_automation.decide(db, req, user, payload.decision, payload.note)
    db.commit()
    return _decision(req)


@router.get("/rules", response_model=List[RuleOut])
def list_rules(db: Session = Depends(get_db), _: User = Depends(require_roles(STAFF_ROLES))):
    return [_rule(r) for r in db.query(DetectionRule).order_by(DetectionRule.id.desc()).all()]


@router.post("/rules", status_code=201)
def create_rule(payload: RuleIn, db: Session = Depends(get_db), user: User = Depends(require_roles(STAFF_ROLES))):
    """Alert rules are security configuration. Administrators create them; an analyst's rule is a request they approve."""
    match = soc_automation.validate_match(payload.match, payload.kind, settings_store.get(db, "l1_critical_threshold"))
    if user.role not in ADMIN_ROLES:
        req = DecisionRequest(
            kind="DETECTION_RULE", title=f"Rule requested: {payload.name.strip()}"[:255], priority="Low", created_by=user.email,
            rationale=f"{user.full_name} proposes a {payload.kind} rule. {payload.description or ''}".strip(),
            evidence=json.dumps([f"Conditions: {match}"]),
            proposal=json.dumps({"name": payload.name.strip(), "kind": payload.kind, "match": match,
                                 "match_json": json.dumps(match, sort_keys=True)}))
        db.add(req)
        db.add(AuditLog(action="DETECTION_RULE_REQUESTED", actor=user.email, resource_type="DecisionRequest", resource_id="new",
                        details=f"{payload.kind} rule '{payload.name}' requested: {match}"))
        db.commit()
        return {"status": "approval_requested", "decision_id": req.id}
    rule = DetectionRule(name=payload.name.strip(), description=payload.description, kind=payload.kind,
                         match_json=json.dumps(match, sort_keys=True), created_by=user.email)
    db.add(rule)
    db.flush()
    db.add(AuditLog(action="DETECTION_RULE_CREATED", actor=user.email, resource_type="DetectionRule", resource_id=str(rule.id),
                    details=f"{payload.kind} rule '{rule.name}': {rule.match_json}"))
    db.commit()
    return _rule(rule)


@router.patch("/rules/{rule_id}", response_model=RuleOut)
def toggle_rule(rule_id: int, enabled: bool = Query(...), db: Session = Depends(get_db), user: User = Depends(require_roles(ADMIN_ROLES))):
    rule = db.get(DetectionRule, rule_id)
    if not rule:
        raise HTTPException(404, "Rule not found.")
    rule.enabled = enabled
    db.add(AuditLog(action="DETECTION_RULE_TOGGLED", actor=user.email, resource_type="DetectionRule", resource_id=str(rule.id),
                    details=f"'{rule.name}' {'enabled' if enabled else 'disabled'}."))
    db.commit()
    return _rule(rule)


@router.post("/events/{event_id}/reopen")
def reopen(event_id: str, db: Session = Depends(get_db), user: User = Depends(require_roles(STAFF_ROLES))):
    ev = db.query(SecurityEvent).filter(SecurityEvent.event_id == event_id).first()
    if not ev:
        raise HTTPException(404, "Event not found.")
    soc_automation.reopen_event(db, ev, user)
    db.commit()
    return {"status": "reopened", "event_id": event_id}


@router.post("/run")
def run_now(db: Session = Depends(get_db), _: User = Depends(require_roles(ADMIN_ROLES))):
    """Runs the automated tiers immediately instead of waiting for the background worker."""
    return soc_automation.run_cycle(db)

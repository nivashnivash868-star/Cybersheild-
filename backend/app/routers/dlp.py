from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Body
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import SecretFinding, SecurityEvent, AuditLog, User
from app.utils.auth import require_authenticated_user
from app.schemas import DLPScanRequest, SecretFindingResponse
from app.services.dlp_engine import dlp_engine
from app.services.alert_engine import alert_engine

router = APIRouter(prefix="/dlp", tags=["Data Loss Prevention & Secret Detection"])

@router.post("/scan", response_model=List[SecretFindingResponse])
def scan_content_for_secrets(payload: DLPScanRequest, db: Session = Depends(get_db)):
    """
    Scans content for exposed secrets (AWS keys, GitHub tokens, Stripe secrets, Private Keys, DB URIs).
    Returns masked findings and records security events. Raw secrets are NEVER saved in plaintext.
    """
    findings_raw = dlp_engine.scan_content(
        text=payload.content,
        source_location=payload.source_location,
        employee_id=payload.employee_id,
        employee_email=payload.employee_email
    )

    created_findings = []
    now = datetime.now(timezone.utc)

    for item in findings_raw:
        # Check duplicate secret hash
        existing = db.query(SecretFinding).filter(
            SecretFinding.secret_hash == item["secret_hash"]
        ).first()

        finding_obj = existing
        if not existing:
            finding_obj = SecretFinding(
                finding_id=item["finding_id"],
                secret_type=item["secret_type"],
                masked_value=item["masked_value"],
                secret_hash=item["secret_hash"],
                source_location=item["source_location"],
                employee_id=item["employee_id"],
                employee_email=item["employee_email"],
                severity=item["severity"],
                risk_score=item["risk_score"],
                status="NEW",
                recommendations=item["recommendations"],
                detected_at=now
            )
            db.add(finding_obj)

            # Create SecurityEvent in SOC stream
            sec_event = SecurityEvent(
                event_id=f"SEC-DLP-{finding_obj.finding_id}",
                timestamp=now,
                event_source="DLP Secret Exposure Sensor",
                threat_category=f"Secret Leak: {finding_obj.secret_type}",
                risk_score=finding_obj.risk_score,
                severity=finding_obj.severity,
                source_ip=None,
                dest_ip=None,
                domain=None,
                file_hash=None,
                user_account=payload.employee_email,
                employee_id=payload.employee_id,
                evidence=f"Exposed {finding_obj.secret_type} ({finding_obj.masked_value}) detected in {finding_obj.source_location}.",
                analysis_status="Analyzed",
                recommended_action=finding_obj.recommendations,
                is_acknowledged=False
            )
            db.add(sec_event)

            # Dispatch notification
            alert_engine.dispatch_security_alert(
                db=db,
                title=f"Potential Secret Leak: {finding_obj.secret_type}",
                sanitized_summary=f"DLP sensor detected exposed {finding_obj.secret_type} ({finding_obj.masked_value}) in {finding_obj.source_location}.",
                severity=finding_obj.severity,
                target_employee_email=payload.employee_email,
                event_id=sec_event.event_id
            )

        created_findings.append(finding_obj)

    db.commit()
    return [SecretFindingResponse.model_validate(f) for f in created_findings]

@router.get("/findings", response_model=List[SecretFindingResponse])
def list_secret_findings(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(SecretFinding)
    if severity and severity != "All":
        query = query.filter(SecretFinding.severity == severity)
    if status and status != "All":
        query = query.filter(SecretFinding.status == status)
    if search:
        s = f"%{search}%"
        query = query.filter(
            SecretFinding.secret_type.ilike(s) |
            SecretFinding.masked_value.ilike(s) |
            SecretFinding.source_location.ilike(s) |
            SecretFinding.employee_email.ilike(s)
        )
    return query.order_by(SecretFinding.detected_at.desc()).offset(offset).limit(limit).all()

@router.patch("/findings/{finding_id}/status")
def update_secret_finding_status(
    finding_id: str,
    status_val: str = Body(..., embed=True),
    db: Session = Depends(get_db),
    user: User = Depends(require_authenticated_user),
):
    valid_statuses = ["NEW", "REVOKED", "CONTAINED", "FALSE_POSITIVE"]
    if status_val not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Allowed: {valid_statuses}")

    finding = db.query(SecretFinding).filter(SecretFinding.finding_id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")

    old_status = finding.status
    finding.status = status_val

    audit = AuditLog(
        action="DLP_STATUS_CHANGED",
        actor=user.email,
        resource_type="SecretFinding",
        resource_id=finding_id,
        details=f"DLP finding status updated from {old_status} to {status_val}."
    )
    db.add(audit)
    db.commit()
    return {"status": "success", "finding_id": finding_id, "new_status": status_val}

import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse
from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import SecurityEvent, AuditLog, ThreatAnalysis, User
from app.utils.auth import require_authenticated_user
from app.schemas import URLWarningInspectRequest, URLWarningInspectResponse, URLOverrideLogRequest
from app.services.phishing_engine import phishing_detector
from app.services.alert_engine import alert_engine

router = APIRouter(prefix="/url", tags=["URL Warning & Gateway Protection"])

@router.post("/inspect", response_model=URLWarningInspectResponse)
def inspect_url_for_warning(payload: URLWarningInspectRequest, db: Session = Depends(get_db)):
    """
    Inspects URL accessed by an employee. If flagged as elevated risk,
    generates an enterprise warning interstitial response and creates a SOC alert.
    """
    analysis = phishing_detector.analyze_url(payload.url)
    
    parsed = urlparse(payload.url if payload.url.startswith("http") else f"http://{payload.url}")
    domain = parsed.hostname or "unknown-domain"

    is_dangerous = analysis.risk_score >= 60
    now = datetime.now(timezone.utc)

    # If dangerous, log SecurityEvent in SOC stream
    if is_dangerous:
        sec_event = SecurityEvent(
            event_id=f"SEC-URL-WARN-{uuid.uuid4().hex[:12].upper()}",
            timestamp=now,
            event_source="Browser Web Gateway Sensor",
            threat_category=f"Suspicious URL Access Attempt ({analysis.risk_category})",
            risk_score=analysis.risk_score,
            severity=analysis.risk_category,
            source_ip=None,
            dest_ip=None,
            domain=domain,
            file_hash=None,
            user_account=payload.employee_email or "unknown-employee",
            employee_id=None,
            evidence=f"Employee attempted to navigate to high-risk destination '{payload.url}'. {analysis.explanation}",
            analysis_status="Analyzed",
            recommended_action="Block target URL on perimeter DNS and proxy filter; notify user of credential hazard.",
            is_acknowledged=False
        )
        db.add(sec_event)

        # Dispatch warning alert to employee & SOC
        alert_engine.dispatch_security_alert(
            db=db,
            title=f"Suspicious URL Intercepted: {domain}",
            sanitized_summary=f"Navigation attempt to {domain} was intercepted. Flagged as {analysis.risk_category} risk.",
            severity=analysis.risk_category,
            target_employee_email=payload.employee_email,
            event_id=sec_event.event_id
        )
        db.commit()

    advisory = (
        f"CYBERSHIELD AI Gateway intercepted an outbound request to '{domain}'. "
        f"This destination exhibits traits of {analysis.risk_category} Risk credential harvesting or scam infrastructure."
        if is_dangerous else
        f"URL '{domain}' evaluated as nominal risk. No malicious indicators found."
    )

    return URLWarningInspectResponse(
        target_url=payload.url,
        domain=domain,
        threat_category="Phishing / Brand Spoofing" if is_dangerous else "Nominal Web Traffic",
        risk_score=analysis.risk_score,
        severity=analysis.risk_category,
        is_blocked=is_dangerous,
        is_simulated_block=True,
        blocking_reason="Simulated gateway block: Disposable TLD and credential spoofing patterns detected." if is_dangerous else "Not blocked",
        advisory_message=advisory,
        safe_return_url="about:blank",
        can_proceed_override=True,
        soc_alert_generated=is_dangerous
    )

@router.post("/override")
def record_employee_override(payload: URLOverrideLogRequest, db: Session = Depends(get_db),
                             user: User = Depends(require_authenticated_user)):
    """Logs when an employee overrides a warning banner and proceeds at their own risk."""
    now = datetime.now(timezone.utc)
    
    audit = AuditLog(
        action="URL_WARNING_OVERRIDE",
        actor=user.email,
        resource_type="URL",
        resource_id=payload.url[:128],
        details=f"Employee {user.email} bypassed warning for {payload.url}. Justification: {payload.override_reason}"
    )
    db.add(audit)

    # Create escalated SOC event
    sec_event = SecurityEvent(
        event_id=f"SEC-OVERRIDE-{uuid.uuid4().hex[:12].upper()}",
        timestamp=now,
        event_source="Browser Web Gateway (User Override)",
        threat_category="Policy Override / Risky Site Visit",
        risk_score=80,
        severity="High",
        source_ip="10.0.12.84",
        dest_ip=None,
        domain=payload.url[:64],
        file_hash=None,
        user_account=user.email,
        employee_id=None,
        evidence=f"User bypassed warning banner with justification: '{payload.override_reason}'. Destination: {payload.url}",
        analysis_status="Analyzed",
        recommended_action="Triage host workstation for active payload staging or credential leakage.",
        is_acknowledged=False
    )
    db.add(sec_event)
    db.commit()

    return {"status": "success", "message": "Override logged in SOC audit record. Workstation is being monitored."}

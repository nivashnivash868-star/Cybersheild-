import uuid
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import MonitoringSource, SecurityEvent, AuditLog
from app.schemas import MonitoringSourceResponse, SecurityEventResponse
from app.config import settings
from app.services.alert_engine import alert_engine
from app.utils.auth import ADMIN_ROLES, require_roles

router = APIRouter(prefix="/monitoring", tags=["24/7 Security Monitoring Engine"])

@router.get("/sources", response_model=List[MonitoringSourceResponse])
def list_monitoring_sources(db: Session = Depends(get_db)):
    sources = db.query(MonitoringSource).order_by(MonitoringSource.id.asc()).all()
    return sources

@router.post("/sources/{source_id}/heartbeat", dependencies=[Depends(require_roles(ADMIN_ROLES))])
def record_source_heartbeat(source_id: str, status_val: str = "ACTIVE", db: Session = Depends(get_db)):
    src = db.query(MonitoringSource).filter(MonitoringSource.source_id == source_id).first()
    if not src:
        raise HTTPException(status_code=404, detail=f"Monitoring source '{source_id}' not found.")

    src.last_heartbeat = datetime.now(timezone.utc)
    src.status = status_val
    db.commit()
    return {"status": "success", "source_id": source_id, "last_heartbeat": src.last_heartbeat}

@router.post("/simulate-pulse", response_model=SecurityEventResponse, dependencies=[Depends(require_roles(ADMIN_ROLES))])
def simulate_telemetry_pulse(
    source_id: str = Body(..., embed=True),
    employee_email: Optional[str] = Body(None, embed=True),
    db: Session = Depends(get_db)
):
    """
    Simulates a live inbound security event from an authorized corporate monitoring source.
    Clearly marked as synthetic telemetry until external integrations are configured.
    """
    if not settings.DEMO_MODE:
        raise HTTPException(status_code=404, detail="Synthetic telemetry is only available when DEMO_MODE is on.")
    src = db.query(MonitoringSource).filter(MonitoringSource.source_id == source_id).first()
    if not src:
        raise HTTPException(status_code=404, detail=f"Source '{source_id}' not found.")

    now = datetime.now(timezone.utc)
    now_ts = int(now.timestamp())

    event_id = f"SEC-{source_id[:3]}-{uuid.uuid4().hex[:10].upper()}"

    threat_presets = {
        "SRC-M365-EMAIL": {
            "threat_category": "Phishing / Malicious Attachment",
            "severity": "High",
            "risk_score": 84,
            "evidence": f"Inbound spoofed email targeting {employee_email or 'staff'} with macro payload attachment.",
            "recommended_action": "Quarantine email from all recipient inboxes and block origin IP."
        },
        "SRC-CRWD-EDR": {
            "threat_category": "Suspicious Memory Injection",
            "severity": "Critical",
            "risk_score": 94,
            "evidence": f"CrowdStrike EDR detected VirtualAlloc process hollowing targeting explorer.exe on endpoint {employee_email or 'workstation'}.",
            "recommended_action": "Immediately isolate endpoint host via EDR containment action."
        },
        "SRC-CISCO-DNS": {
            "threat_category": "DGA / Fast-Flux Domain Resolution",
            "severity": "Medium",
            "risk_score": 68,
            "evidence": "Repeated anomalous DNS queries resolving to bulletproof dynamic DNS infrastructure.",
            "recommended_action": "Sinkhole apex domain on internal recursive DNS resolvers."
        },
        "SRC-PALO-NGFW": {
            "threat_category": "Inbound Exploit Probe (Log4j / CVE-2021-44228)",
            "severity": "High",
            "risk_score": 86,
            "evidence": "Perimeter firewall blocked inbound jndi:ldap string attempting remote code execution.",
            "recommended_action": "Add origin CIDR block to firewall ingress drop ACL."
        },
        "SRC-ZEEK-NIDS": {
            "threat_category": "Suspicious C2 Heartbeat",
            "severity": "Critical",
            "risk_score": 91,
            "evidence": "Observed 18 uniform TLS connections with 0-jitter heartbeat to unclassified external IP.",
            "recommended_action": "Sever active TCP session and isolate origin host."
        },
        "SRC-AZURE-IDP": {
            "threat_category": "Anomalous Geolocation Login",
            "severity": "High",
            "risk_score": 82,
            "evidence": f"Impossible travel detected: Successful login for {employee_email or 'user'} from Lagos 12 minutes after login from New York.",
            "recommended_action": "Revoke active Azure AD session refresh tokens and require biometric MFA re-verification."
        },
        "SRC-AWS-TRAIL": {
            "threat_category": "Unauthorized Cloud IAM Modification",
            "severity": "Critical",
            "risk_score": 92,
            "evidence": "CloudTrail logged PutUserPolicy call attaching AdministratorAccess to unmanaged role.",
            "recommended_action": "Revert IAM inline policy change and rotate admin credentials."
        }
    }

    preset = threat_presets.get(source_id, {
        "threat_category": "Unclassified Ingress Alert",
        "severity": "Medium",
        "risk_score": 60,
        "evidence": "Automated security sensor telemetry pulse received.",
        "recommended_action": "Investigate sensor event log."
    })

    sec_event = SecurityEvent(
        is_simulated=True,
        event_id=event_id,
        timestamp=now,
        event_source=f"{src.name} (Simulated Ingress)",
        threat_category=preset["threat_category"],
        risk_score=preset["risk_score"],
        severity=preset["severity"],
        source_ip="198.51.100.44",
        dest_ip="10.0.12.84",
        domain="auth-update-notice.xyz" if "EMAIL" in source_id else None,
        file_hash=None,
        user_account=employee_email or "system",
        employee_id=None,
        evidence=preset["evidence"],
        analysis_status="Analyzed",
        recommended_action=preset["recommended_action"],
        is_acknowledged=False
    )
    db.add(sec_event)

    # Update source metrics
    src.events_ingested_count += 1
    src.last_heartbeat = now

    # Trigger automated notification dispatch
    alert_engine.dispatch_security_alert(
        db=db,
        title=f"New Security Event: {preset['threat_category']}",
        sanitized_summary=preset["evidence"],
        severity=preset["severity"],
        target_employee_email=employee_email,
        event_id=event_id
    )

    db.commit()
    db.refresh(sec_event)
    return sec_event

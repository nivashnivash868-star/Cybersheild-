from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from datetime import datetime
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.config import settings
from app.services import threat_intel as ti
from app.services.platform_status import platform_status
from app.database import get_db, get_db_status
from app.models import AuditLog, BlocklistEntry, FeedToken, User
from app.schemas import SystemStatusResponse
from app.services.demo_data_seeder import seed_demo_soc_data
from app.services.outbox import email_configured, sms_configured
from app.utils.audit import verify_chain
from app.utils.auth import ADMIN_ROLES, STAFF_ROLES, require_roles

router = APIRouter(prefix="/system", tags=["System & Integrations Status"])


@router.get("/health")
def get_health_status(db: Session = Depends(get_db)):
    """Liveness/readiness probe. Public and deliberately minimal."""
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        raise HTTPException(status_code=503, detail="database unavailable")
    return {"status": "healthy", "database": {"status": "connected"}}


@router.get("/status", response_model=SystemStatusResponse)
def get_full_system_status(db: Session = Depends(get_db), _: User = Depends(require_roles(STAFF_ROLES))):
    active_blocks = db.query(BlocklistEntry).filter(BlocklistEntry.status == "ACTIVE").count()
    consumers = db.query(FeedToken).filter(FeedToken.revoked_at.is_(None)).all()
    pulled = [c for c in consumers if c.last_fetched_at]
    integrations = {
        "database": {
            "configured": bool(settings.database_url),
            "status": "PostgreSQL" if settings.database_url else "SQLite (development only)",
        },
        "email_alerts": {
            "configured": email_configured(),
            "status": "SMTP configured" if email_configured() else "Not configured: alerts are recorded as NOT_CONFIGURED",
        },
        "sms_alerts": {
            "configured": sms_configured(),
            "status": "Twilio configured" if sms_configured() else "Not configured: alerts are recorded as NOT_CONFIGURED",
        },
        "blocklist_feed": {
            "configured": bool(consumers),
            "status": (f"{active_blocks} active entries; {len(pulled)}/{len(consumers)} consumers have pulled the feed"
                       if consumers else "No feed consumer registered: blocks are not enforced anywhere yet"),
        },
        "zetaris": {
            "configured": settings.zetaris_configured,
            "status": ("Configured; see /zetaris/status for a live connection check" if settings.zetaris_configured
                       else "Not configured: no external data sources are being read"),
        },
        "threat_intelligence": {
            "configured": bool(settings.VIRUSTOTAL_API_KEY or settings.ABUSEIPDB_API_KEY),
            "status": "; ".join(f"{p['name']}: {p['state']}" for p in ti.provider_status(db)),
        },
    }
    ml_engine = {
        "status": "Evaluated, with stated limits (docs/detection-evaluation.md)",
        "phishing_url_model": "Character n-gram model on an OpenPhish snapshot vs. Tranco sites, plus brand/host rules; ~64% of held-out phishing High+, ~0.3% false alerts on unfamiliar legitimate sites",
        "phishing_text_classifier": "Rules + link analysis + a 60-message word model; evaluated on our own message sets, not a real mailbox",
        "network_anomaly_detector": "Rules plus an IsolationForest fitted on a generated baseline unless NETWORK_BASELINE_CSV supplies your traffic",
        "file_scanner": "Static analysis (format, entropy, byte patterns); built-in signatures are the EICAR test file only unless FILE_HASH_FEED_PATH is set",
    }
    security_guards = {
        "authentication": "Server-side sessions (HttpOnly cookie), Argon2id, TOTP MFA, CSRF token, lockout and rate limits",
        "audit_trail": "Append-only HMAC hash chain; verify at /system/audit/verify",
        "url_handling": "Submitted URLs are analysed as text only: never fetched, never resolved",
    }
    return SystemStatusResponse(
        name=settings.PROJECT_NAME, version="2.0.0", environment=settings.ENVIRONMENT, status=platform_status(db),
        database=get_db_status(), integrations=integrations, ml_engine=ml_engine, security_guards=security_guards,
    )


@router.post("/seed-demo")
def seed_or_reset_demo_data(force_reset: bool = False, db: Session = Depends(get_db),
                            _: User = Depends(require_roles(["Super Admin"]))):
    if not settings.DEMO_MODE:
        raise HTTPException(status_code=404, detail="Demo data is disabled (DEMO_MODE is off).")
    return seed_demo_soc_data(db=db, force_reset=force_reset)


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    timestamp: datetime
    action: str
    actor: str
    resource_type: str
    resource_id: str
    details: Optional[str] = None
    request_id: Optional[str] = None
    ip_address: Optional[str] = None


@router.get("/audit", response_model=List[AuditOut])
def list_audit(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0), action: Optional[str] = None,
               q: Optional[str] = Query(None, max_length=100), db: Session = Depends(get_db),
               _: User = Depends(require_roles(ADMIN_ROLES))):
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action == action)
    if q:
        like = f"%{q}%"
        query = query.filter(AuditLog.actor.ilike(like) | AuditLog.details.ilike(like) | AuditLog.resource_id.ilike(like)
                             | AuditLog.action.ilike(like))
    return query.order_by(AuditLog.id.desc()).offset(offset).limit(limit).all()


@router.get("/audit/verify")
def verify_audit_chain(db: Session = Depends(get_db), _: User = Depends(require_roles(["Super Admin"]))):
    return verify_chain(db)

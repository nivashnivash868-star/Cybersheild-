"""Reputation lookups for analysts, and the status of the reputation providers."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AuditLog, User
from app.services import threat_intel as ti
from app.utils.auth import STAFF_ROLES, require_roles
from app.utils.ratelimit import limiter

router = APIRouter(prefix="/threat-intel", tags=["Threat intelligence"])


@router.get("/lookup")
def lookup(indicator: str = Query(..., min_length=1, max_length=2000), refresh: bool = False, db: Session = Depends(get_db),
           user: User = Depends(require_roles(STAFF_ROLES))):
    """Reputation of an IP, domain, file hash or URL (domain only unless TI_SEND_FULL_URLS). Cached; rate-limited."""
    if not limiter.hit(f"ti-lookup:{user.id}", 30, 60):
        from fastapi import HTTPException
        raise HTTPException(429, "Too many lookups; slow down.")
    result = ti.lookup(db, indicator, force=refresh)
    db.add(AuditLog(action="TI_LOOKUP", actor=user.email, resource_type="Indicator", resource_id=result["indicator"][:60],
                    details=f"type={result['type']} malicious={result['malicious']}"))
    db.commit()
    return result


@router.get("/status")
def status(db: Session = Depends(get_db), _: User = Depends(require_roles(STAFF_ROLES))):
    return ti.provider_status(db)

import secrets
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from datetime import datetime
from sqlalchemy.orm import Session
from app.config import settings
from app.database import get_db
from app.models import AuditLog, BlocklistEntry, FeedToken, User
from app.services import blocklist as svc
from app.utils.auth import ADMIN_ROLES, STAFF_ROLES, require_roles
from app.utils.crypto import sha256_hex

router = APIRouter(prefix="/blocklist", tags=["Threat Prevention: Blocklist"])


class EntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    indicator_type: str
    value: str
    reason: str
    incident_id: Optional[str] = None
    status: str
    ttl_hours: int
    proposed_by: str
    proposed_at: datetime
    decided_by: Optional[str] = None
    decided_at: Optional[datetime] = None
    decision_note: Optional[str] = None
    activated_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None


class ProposeIn(BaseModel):
    indicator: str = Field(..., max_length=512)
    reason: str = Field(..., min_length=5, max_length=2000)
    incident_id: Optional[str] = Field(None, max_length=64)
    ttl_hours: Optional[int] = Field(None, ge=1, le=24 * 30)


class DecisionIn(BaseModel):
    note: Optional[str] = Field(None, max_length=500)


class FeedTokenIn(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)


class FeedTokenOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    created_by: str
    created_at: datetime
    revoked_at: Optional[datetime] = None
    last_fetched_at: Optional[datetime] = None
    last_fetched_version: Optional[str] = None
    last_fetched_ip: Optional[str] = None


def _entry_or_404(db: Session, entry_id: int) -> BlocklistEntry:
    entry = db.get(BlocklistEntry, entry_id)
    if not entry:
        raise HTTPException(404, "Blocklist entry not found.")
    return entry


@router.get("", response_model=List[EntryOut])
def list_entries(status: Optional[str] = None, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
                 db: Session = Depends(get_db), _: User = Depends(require_roles(STAFF_ROLES))):
    q = db.query(BlocklistEntry)
    if status and status != "All":
        q = q.filter(BlocklistEntry.status == status)
    return q.order_by(BlocklistEntry.id.desc()).offset(offset).limit(limit).all()


@router.post("", response_model=EntryOut, status_code=201)
def propose_entry(payload: ProposeIn, db: Session = Depends(get_db), user: User = Depends(require_roles(STAFF_ROLES))):
    entry, _ = svc.propose(db, payload.indicator, payload.reason, user.email,
                           auto_approve=user.role in ADMIN_ROLES, incident_id=payload.incident_id,
                           ttl_hours=payload.ttl_hours)
    db.commit()
    return entry


@router.post("/{entry_id}/approve", response_model=EntryOut)
def approve_entry(entry_id: int, payload: DecisionIn, db: Session = Depends(get_db),
                  admin: User = Depends(require_roles(ADMIN_ROLES))):
    entry = _entry_or_404(db, entry_id)
    svc.approve(db, entry, admin.email, payload.note)
    db.commit()
    return entry


@router.post("/{entry_id}/reject", response_model=EntryOut)
def reject_entry(entry_id: int, payload: DecisionIn, db: Session = Depends(get_db),
                 admin: User = Depends(require_roles(ADMIN_ROLES))):
    entry = _entry_or_404(db, entry_id)
    svc.reject(db, entry, admin.email, payload.note)
    db.commit()
    return entry


@router.post("/{entry_id}/revoke", response_model=EntryOut)
def revoke_entry(entry_id: int, payload: DecisionIn, db: Session = Depends(get_db),
                 admin: User = Depends(require_roles(ADMIN_ROLES))):
    entry = _entry_or_404(db, entry_id)
    svc.revoke(db, entry, admin.email, payload.note)
    db.commit()
    return entry


@router.get("/feeds", response_model=List[FeedTokenOut])
def list_feed_tokens(db: Session = Depends(get_db), _: User = Depends(require_roles(ADMIN_ROLES))):
    return db.query(FeedToken).order_by(FeedToken.id).all()


@router.post("/feeds")
def create_feed_token(payload: FeedTokenIn, db: Session = Depends(get_db),
                      admin: User = Depends(require_roles(ADMIN_ROLES))):
    """The token is shown once. Give it to the firewall / DNS sinkhole as a bearer token or the Basic-auth password."""
    if db.query(FeedToken).filter(FeedToken.name == payload.name).first():
        raise HTTPException(409, "A feed token with that name already exists.")
    raw = "csf_" + secrets.token_urlsafe(32)
    row = FeedToken(name=payload.name, token_hash=sha256_hex(raw), created_by=admin.email)
    db.add(row)
    db.flush()
    db.add(AuditLog(action="FEED_TOKEN_CREATED", actor=admin.email, resource_type="FeedToken",
                    resource_id=str(row.id), details=f"Feed credential '{payload.name}' created."))
    db.commit()
    base = settings.PUBLIC_BASE_URL.rstrip("/") + settings.API_V1_PREFIX + "/feeds/blocklist"
    return {"id": row.id, "name": row.name, "token": raw,
            "urls": {"ip": f"{base}/ip.txt", "domain": f"{base}/domain.txt", "url": f"{base}/url.txt"},
            "note": "Store this token now; it can't be shown again."}


@router.delete("/feeds/{token_id}")
def revoke_feed_token(token_id: int, db: Session = Depends(get_db), admin: User = Depends(require_roles(ADMIN_ROLES))):
    from app.models import naive_utc_now
    row = db.get(FeedToken, token_id)
    if not row or row.revoked_at:
        raise HTTPException(404, "Active feed token not found.")
    row.revoked_at = naive_utc_now()
    db.add(AuditLog(action="FEED_TOKEN_REVOKED", actor=admin.email, resource_type="FeedToken",
                    resource_id=str(row.id), details=f"Feed credential '{row.name}' revoked."))
    db.commit()
    return {"status": "success"}

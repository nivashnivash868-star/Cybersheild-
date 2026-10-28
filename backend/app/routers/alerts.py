from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Body
from sqlalchemy import func
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import AuditLog, NotificationDelivery, User, naive_utc_now
from app.schemas import NotificationDeliveryResponse
from app.services.alert_engine import alert_engine
from app.utils.auth import ADMIN_ROLES, require_roles

router = APIRouter(prefix="/alerts", tags=["Automated Alerts & Delivery Engine"])

@router.get("/deliveries", response_model=List[NotificationDeliveryResponse])
def list_notification_deliveries(
    recipient_type: Optional[str] = None,
    channel: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    q: Optional[str] = Query(None, max_length=100),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(NotificationDelivery)
    if status and status != "All":
        query = query.filter(NotificationDelivery.delivery_status == status)
    if q:
        like = f"%{q}%"
        query = query.filter(NotificationDelivery.title.ilike(like) | NotificationDelivery.recipient_address.ilike(like)
                             | NotificationDelivery.body_preview.ilike(like))
    if recipient_type and recipient_type != "All":
        query = query.filter(NotificationDelivery.recipient_type == recipient_type)
    if channel and channel != "All":
        query = query.filter(NotificationDelivery.channel == channel)
    if severity and severity != "All":
        query = query.filter(NotificationDelivery.severity == severity)
    return query.order_by(NotificationDelivery.sent_at.desc()).offset(offset).limit(limit).all()

@router.get("/summary")
def delivery_summary(db: Session = Depends(get_db)):
    """Counts per delivery status, so operators can see at a glance whether alerts are actually going out."""
    rows = db.query(NotificationDelivery.delivery_status, func.count(NotificationDelivery.id)).group_by(
        NotificationDelivery.delivery_status).all()
    return {status: count for status, count in rows}


@router.post("/deliveries/{delivery_id}/retry", dependencies=[Depends(require_roles(ADMIN_ROLES))])
def retry_delivery(delivery_id: int, db: Session = Depends(get_db), admin: User = Depends(require_roles(ADMIN_ROLES))):
    row = db.get(NotificationDelivery, delivery_id)
    if not row:
        raise HTTPException(status_code=404, detail="Delivery not found.")
    if row.delivery_status not in ("FAILED", "NOT_CONFIGURED"):
        raise HTTPException(status_code=409, detail=f"Only failed or unconfigured deliveries can be retried (this one is {row.delivery_status}).")
    row.delivery_status, row.retry_count, row.last_error = "QUEUED", 0, None
    row.next_attempt_at = naive_utc_now()
    db.add(AuditLog(action="ALERT_RETRY", actor=admin.email, resource_type="NotificationDelivery",
                    resource_id=row.delivery_id, details=f"Re-queued {row.channel} delivery to {row.recipient_address}."))
    db.commit()
    return {"status": "queued", "delivery_id": row.delivery_id}


@router.post("/test-dispatch", response_model=List[NotificationDeliveryResponse],
             dependencies=[Depends(require_roles(ADMIN_ROLES))])
def test_alert_dispatch(
    title: str = Body(..., embed=True, max_length=200),
    summary: str = Body(..., embed=True, max_length=2000),
    severity: str = Body(default="High", embed=True, pattern="^(Low|Medium|High|Critical)$"),
    target_email: Optional[str] = Body(None, embed=True, max_length=255),
    db: Session = Depends(get_db)
):
    deliveries = alert_engine.dispatch_security_alert(
        db=db,
        title=title,
        sanitized_summary=summary,
        severity=severity,
        target_employee_email=target_email
    )
    db.commit()
    return deliveries

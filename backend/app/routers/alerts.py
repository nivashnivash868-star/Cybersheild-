from typing import List, Optional
from fastapi import APIRouter, Depends, Query, Body
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import NotificationDelivery
from app.schemas import NotificationDeliveryResponse
from app.services.alert_engine import alert_engine
from app.utils.auth import ADMIN_ROLES, require_roles

router = APIRouter(prefix="/alerts", tags=["Automated Alerts & Delivery Engine"])

@router.get("/deliveries", response_model=List[NotificationDeliveryResponse])
def list_notification_deliveries(
    recipient_type: Optional[str] = None,
    channel: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(NotificationDelivery)
    if recipient_type and recipient_type != "All":
        query = query.filter(NotificationDelivery.recipient_type == recipient_type)
    if channel and channel != "All":
        query = query.filter(NotificationDelivery.channel == channel)
    if severity and severity != "All":
        query = query.filter(NotificationDelivery.severity == severity)
    return query.order_by(NotificationDelivery.sent_at.desc()).offset(offset).limit(limit).all()

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

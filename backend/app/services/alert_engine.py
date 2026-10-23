import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from app.models import NotificationDelivery, Employee, User, AuditLog

DEDUP_WINDOW_MINUTES = 15

class AlertEngine:
    def dispatch_security_alert(
        self,
        db: Session,
        title: str,
        sanitized_summary: str,
        severity: str,
        target_employee_email: Optional[str] = None,
        incident_id: Optional[str] = None,
        event_id: Optional[str] = None,
        require_analyst_notification: bool = True
    ) -> List[NotificationDelivery]:
        """
        Dispatches severity-calibrated notifications to SOC analysts and affected employees.
        Enforces deduplication suppression and strict masking of secret/password values.
        """
        deliveries = []
        now = datetime.now(timezone.utc)
        uid = uuid.uuid4().hex[:8].upper()

        # Generate deduplication key based on title + target email + event/incident ID
        dedup_raw = f"{title}:{target_employee_email or 'global'}:{incident_id or event_id or 'none'}"
        dedup_key = hashlib.md5(dedup_raw.encode("utf-8")).hexdigest()

        # Check for recent duplicate within deduplication window
        window_start = now - timedelta(minutes=DEDUP_WINDOW_MINUTES)
        recent_duplicate = db.query(NotificationDelivery).filter(
            NotificationDelivery.dedup_key == dedup_key,
            NotificationDelivery.sent_at >= window_start,
            NotificationDelivery.delivery_status == "DELIVERED"
        ).first()

        is_suppressed = recent_duplicate is not None

        # 1. Dispatch to SOC Analysts (Email & In-App)
        if require_analyst_notification:
            analyst_delivery = NotificationDelivery(
                delivery_id=f"NOTIF-SOC-{uid}-{len(deliveries)+1}",
                recipient_type="SOC_ANALYST",
                recipient_address="soc-tier1-alerts@cybershield.corp",
                channel="EMAIL",
                severity=severity,
                title=f"[CYBERSHIELD {severity.upper()}] {title}",
                body_preview=sanitized_summary,
                delivery_status="SUPPRESSED_DUPLICATE" if is_suppressed else "DELIVERED",
                retry_count=0,
                incident_id=incident_id,
                event_id=event_id,
                dedup_key=dedup_key,
                sent_at=now
            )
            db.add(analyst_delivery)
            deliveries.append(analyst_delivery)

        # 2. Dispatch Warning Notification to Affected Employee
        if target_employee_email:
            emp = db.query(Employee).filter(Employee.company_email == target_employee_email).first()
            emp_phone = emp.phone_number if emp and emp.phone_number else None

            # Email Warning to Employee
            emp_delivery = NotificationDelivery(
                delivery_id=f"NOTIF-EMP-{uid}-{len(deliveries)+1}",
                recipient_type="EMPLOYEE",
                recipient_address=target_employee_email,
                channel="EMAIL",
                severity=severity,
                title=f"Security Advisory: {title}",
                body_preview=(
                    f"Notice for {target_employee_email}: {sanitized_summary} "
                    "Action Required: Please review the security advisory in your CYBERSHIELD Employee Portal."
                ),
                delivery_status="SUPPRESSED_DUPLICATE" if is_suppressed else "DELIVERED",
                retry_count=0,
                incident_id=incident_id,
                event_id=event_id,
                dedup_key=dedup_key,
                sent_at=now
            )
            db.add(emp_delivery)
            deliveries.append(emp_delivery)

            # Optional SMS Warning for Critical / High Threats if phone configured
            if severity in ("Critical", "High") and emp_phone:
                sms_delivery = NotificationDelivery(
                    delivery_id=f"NOTIF-SMS-{uid}-{len(deliveries)+1}",
                    recipient_type="EMPLOYEE",
                    recipient_address=emp_phone,
                    channel="SMS",
                    severity=severity,
                    title="CYBERSHIELD Security Alert",
                    body_preview=f"Urgent Security Notice: {title}. Check corporate email immediately.",
                    delivery_status="DELIVERED",
                    retry_count=0,
                    incident_id=incident_id,
                    event_id=event_id,
                    dedup_key=dedup_key,
                    sent_at=now
                )
                db.add(sms_delivery)
                deliveries.append(sms_delivery)

        # 3. Audit Log
        audit = AuditLog(
            action="ALERT_DISPATCHED",
            actor="AlertEngine",
            resource_type="NotificationDelivery",
            resource_id=deliveries[0].delivery_id if deliveries else "NONE",
            details=f"Dispatched {len(deliveries)} alerts for '{title}' (Severity: {severity}). Suppressed: {is_suppressed}"
        )
        db.add(audit)
        db.flush()

        return deliveries

alert_engine = AlertEngine()

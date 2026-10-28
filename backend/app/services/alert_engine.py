import hashlib
from datetime import timedelta
from typing import List, Optional
from sqlalchemy.orm import Session
from app.config import settings
from app.models import AuditLog, Employee, NotificationDelivery, naive_utc_now
from app.services.outbox import enqueue_email, enqueue_sms

DEDUP_WINDOW_MINUTES = 15
_LIVE_STATUSES = ("QUEUED", "SENDING", "SENT")


class AlertEngine:
    def _is_duplicate(self, db: Session, dedup_key: str, address: str, channel: str) -> bool:
        window_start = naive_utc_now() - timedelta(minutes=DEDUP_WINDOW_MINUTES)
        return db.query(NotificationDelivery.id).filter(
            NotificationDelivery.dedup_key == dedup_key,
            NotificationDelivery.recipient_address == address,
            NotificationDelivery.channel == channel,
            NotificationDelivery.delivery_status.in_(_LIVE_STATUSES),
            NotificationDelivery.sent_at >= window_start,
        ).first() is not None

    def dispatch_security_alert(
        self,
        db: Session,
        title: str,
        sanitized_summary: str,
        severity: str,
        target_employee_email: Optional[str] = None,
        incident_id: Optional[str] = None,
        event_id: Optional[str] = None,
        require_analyst_notification: bool = True,
    ) -> List[NotificationDelivery]:
        """
        Queues severity-calibrated email (and SMS for High/Critical) alerts for the SOC and the affected employee.
        Nothing is sent inline: the outbox worker delivers and records the real provider outcome.
        """
        deliveries: List[NotificationDelivery] = []
        dedup_raw = f"{title}:{target_employee_email or 'global'}:{incident_id or event_id or 'none'}"
        dedup_key = hashlib.sha256(dedup_raw.encode("utf-8")).hexdigest()
        common = dict(severity=severity, incident_id=incident_id, event_id=event_id, dedup_key=dedup_key)

        def queue_email(address: str, recipient_type: str, subject: str, body: str) -> None:
            if self._is_duplicate(db, dedup_key, address, "EMAIL"):
                deliveries.append(enqueue_email(db, address, subject, body, recipient_type=recipient_type,
                                                status="SUPPRESSED_DUPLICATE", **common))
            else:
                deliveries.append(enqueue_email(db, address, subject, body, recipient_type=recipient_type, **common))

        def queue_sms(address: str, recipient_type: str, body: str) -> None:
            status = "SUPPRESSED_DUPLICATE" if self._is_duplicate(db, dedup_key, address, "SMS") else "QUEUED"
            deliveries.append(enqueue_sms(db, address, body, recipient_type=recipient_type, status=status, **common))

        if require_analyst_notification:
            subject = f"[CYBERSHIELD {severity.upper()}] {title}"
            if settings.ALERT_SOC_EMAILS:
                for addr in settings.ALERT_SOC_EMAILS:
                    queue_email(addr, "SOC_ANALYST", subject, sanitized_summary)
            else:
                row = enqueue_email(db, "unconfigured", subject, sanitized_summary, recipient_type="SOC_ANALYST",
                                    status="NOT_CONFIGURED", **common)
                row.last_error = "ALERT_SOC_EMAILS is empty: no SOC recipient is configured."
                deliveries.append(row)
            if severity == "Critical":
                for number in settings.ALERT_SOC_SMS:
                    queue_sms(number, "SOC_ANALYST", f"CYBERSHIELD CRITICAL: {title}"[:300])

        if target_employee_email:
            emp = db.query(Employee).filter(Employee.company_email == target_employee_email).first()
            queue_email(
                target_employee_email, "EMPLOYEE", f"Security advisory: {title}",
                f"{sanitized_summary}\n\nWhat to do: open the CYBERSHIELD employee portal and follow the advisory.",
            )
            if severity in ("Critical", "High") and emp and emp.phone_number:
                queue_sms(emp.phone_number, "EMPLOYEE",
                          f"CYBERSHIELD: security notice - {title}. Check your work email."[:300])

        db.add(AuditLog(
            action="ALERT_QUEUED", actor="AlertEngine", resource_type="NotificationDelivery",
            resource_id=incident_id or event_id or "none",
            details=f"Queued {len(deliveries)} alerts for '{title}' (severity {severity}).",
        ))
        db.flush()
        return deliveries


alert_engine = AlertEngine()

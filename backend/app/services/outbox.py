"""Alert outbox with real transports.

Alerts are written as QUEUED rows and sent by a worker, so a slow or failing provider never blocks a request
and nothing is reported as sent unless a provider accepted it:

  QUEUED -> SENDING -> SENT                      (SMTP server / Twilio accepted the message)
                    -> QUEUED (retry, backoff)   (transient failure)
                    -> FAILED                    (permanent failure or attempts exhausted)
  NOT_CONFIGURED                                 (no transport set up; re-queued when one appears)

SENT means "accepted by the provider", not "read by a person".
"""
import logging
import re
import smtplib
import ssl
import uuid
from datetime import timedelta
from email.message import EmailMessage
from typing import Optional

import httpx
from sqlalchemy import update
from sqlalchemy.orm import Session

from app.config import settings
from app.models import NotificationDelivery, naive_utc_now

logger = logging.getLogger("cybershield.outbox")

_E164 = re.compile(r"^\+[1-9]\d{7,14}$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class PermanentDeliveryError(Exception):
    pass


def email_configured() -> bool:
    return bool(settings.SMTP_HOST and settings.SMTP_FROM)


def sms_configured() -> bool:
    return bool(settings.TWILIO_ACCOUNT_SID and settings.TWILIO_AUTH_TOKEN and settings.TWILIO_FROM_NUMBER)


def _one_line(value: str) -> str:
    return re.sub(r"[\r\n]+", " ", value).strip()


def _new_delivery_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12].upper()}"


def enqueue_email(db: Session, to: str, subject: str, body: str, *, recipient_type: str = "SOC_ANALYST",
                  severity: str = "Low", title: Optional[str] = None, preview: Optional[str] = None,
                  incident_id: Optional[str] = None, event_id: Optional[str] = None,
                  dedup_key: Optional[str] = None, redact_after_send: bool = False,
                  status: str = "QUEUED") -> NotificationDelivery:
    row = NotificationDelivery(
        delivery_id=_new_delivery_id("EML"), recipient_type=recipient_type, recipient_address=_one_line(to),
        channel="EMAIL", severity=severity, title=_one_line(title or subject)[:255],
        body_preview=(preview if preview is not None else ("(redacted)" if redact_after_send else body))[:2000],
        message_body=body, redact_after_send=redact_after_send, delivery_status=status,
        incident_id=incident_id, event_id=event_id, dedup_key=dedup_key,
        next_attempt_at=naive_utc_now() if status == "QUEUED" else None,
    )
    db.add(row)
    return row


def enqueue_sms(db: Session, to: str, body: str, *, recipient_type: str = "EMPLOYEE", severity: str = "High",
                title: str = "CYBERSHIELD Security Alert", incident_id: Optional[str] = None,
                event_id: Optional[str] = None, dedup_key: Optional[str] = None,
                status: str = "QUEUED") -> NotificationDelivery:
    row = NotificationDelivery(
        delivery_id=_new_delivery_id("SMS"), recipient_type=recipient_type, recipient_address=_one_line(to),
        channel="SMS", severity=severity, title=title, body_preview=body[:2000], message_body=body[:600],
        delivery_status=status, incident_id=incident_id, event_id=event_id, dedup_key=dedup_key,
        next_attempt_at=naive_utc_now() if status == "QUEUED" else None,
    )
    db.add(row)
    return row


# ---------------------------------------------------------------------------
# Transports
# ---------------------------------------------------------------------------
def send_email(to: str, subject: str, body: str) -> str:
    if not _EMAIL.match(to):
        raise PermanentDeliveryError("Recipient is not a valid email address.")
    msg = EmailMessage()
    msg["From"] = settings.SMTP_FROM
    msg["To"] = to
    msg["Subject"] = _one_line(subject)
    msg["Message-ID"] = f"<{uuid.uuid4().hex}@cybershield>"
    msg.set_content(body)
    context = ssl.create_default_context()
    try:
        if settings.SMTP_SECURITY == "ssl":
            server = smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15, context=context)
        else:
            server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15)
        with server:
            if settings.SMTP_SECURITY == "starttls":
                server.starttls(context=context)
            if settings.SMTP_USERNAME:
                server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD or "")
            server.send_message(msg)
    except (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused, smtplib.SMTPAuthenticationError) as exc:
        raise PermanentDeliveryError(f"SMTP refused the message: {type(exc).__name__}") from exc
    return msg["Message-ID"]


def send_sms(to: str, body: str) -> str:
    if not _E164.match(to):
        raise PermanentDeliveryError("Recipient is not an E.164 phone number (+15551234567).")
    url = f"https://api.twilio.com/2010-04-01/Accounts/{settings.TWILIO_ACCOUNT_SID}/Messages.json"
    resp = httpx.post(
        url, data={"To": to, "From": settings.TWILIO_FROM_NUMBER, "Body": body},
        auth=(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN), timeout=15,
    )
    if resp.status_code == 201:
        return resp.json().get("sid", "")
    if 400 <= resp.status_code < 500 and resp.status_code != 429:
        try:
            msg = resp.json().get("message", "")
        except ValueError:
            msg = ""
        raise PermanentDeliveryError(f"Twilio rejected the message ({resp.status_code}) {msg}"[:300])
    raise RuntimeError(f"Twilio temporary error {resp.status_code}")


# ---------------------------------------------------------------------------
# Worker pass
# ---------------------------------------------------------------------------
def process_outbox(db: Session, batch: int = 20) -> dict:
    now = naive_utc_now()
    stats = {"sent": 0, "failed": 0, "retried": 0, "not_configured": 0}

    # Recover rows a crashed worker left in SENDING, and revive NOT_CONFIGURED rows once a transport exists.
    db.execute(update(NotificationDelivery).where(
        NotificationDelivery.delivery_status == "SENDING",
        NotificationDelivery.next_attempt_at <= now - timedelta(minutes=10),
    ).values(delivery_status="QUEUED"))
    for channel, ok in (("EMAIL", email_configured()), ("SMS", sms_configured())):
        if ok:
            db.execute(update(NotificationDelivery).where(
                NotificationDelivery.delivery_status == "NOT_CONFIGURED",
                NotificationDelivery.channel == channel,
                NotificationDelivery.sent_at >= now - timedelta(hours=24),
            ).values(delivery_status="QUEUED", next_attempt_at=now))
    db.commit()

    ids = [r[0] for r in db.query(NotificationDelivery.id).filter(
        NotificationDelivery.delivery_status == "QUEUED",
        NotificationDelivery.next_attempt_at <= now,
    ).order_by(NotificationDelivery.id).limit(batch).all()]

    for row_id in ids:
        claimed = db.execute(update(NotificationDelivery).where(
            NotificationDelivery.id == row_id, NotificationDelivery.delivery_status == "QUEUED",
        ).values(delivery_status="SENDING", next_attempt_at=now)).rowcount
        db.commit()
        if not claimed:
            continue
        row = db.get(NotificationDelivery, row_id)
        try:
            if row.channel == "EMAIL":
                if not email_configured():
                    row.delivery_status, row.last_error = "NOT_CONFIGURED", "SMTP_HOST / SMTP_FROM are not set."
                    stats["not_configured"] += 1
                    db.commit()
                    continue
                provider_id = send_email(row.recipient_address, row.title, row.message_body or row.body_preview)
            elif row.channel == "SMS":
                if not sms_configured():
                    row.delivery_status, row.last_error = "NOT_CONFIGURED", "TWILIO_* settings are not set."
                    stats["not_configured"] += 1
                    db.commit()
                    continue
                provider_id = send_sms(row.recipient_address, row.message_body or row.body_preview)
            else:
                row.delivery_status, row.last_error = "FAILED", f"Unsupported channel {row.channel}."
                stats["failed"] += 1
                db.commit()
                continue
            row.delivery_status = "SENT"
            row.dispatched_at = naive_utc_now()
            row.provider_message_id = (provider_id or "")[:128]
            row.last_error = None
            if row.redact_after_send:
                row.message_body = None
            stats["sent"] += 1
        except PermanentDeliveryError as exc:
            row.delivery_status, row.last_error = "FAILED", str(exc)[:500]
            stats["failed"] += 1
        except Exception as exc:  # network / provider outage: retry with backoff
            row.retry_count += 1
            row.last_error = f"{type(exc).__name__}: {exc}"[:500]
            if row.retry_count >= settings.ALERT_MAX_ATTEMPTS:
                row.delivery_status = "FAILED"
                stats["failed"] += 1
            else:
                row.delivery_status = "QUEUED"
                row.next_attempt_at = naive_utc_now() + timedelta(seconds=30 * 2 ** row.retry_count)
                stats["retried"] += 1
            logger.warning("Delivery %s attempt %s failed: %s", row.delivery_id, row.retry_count, row.last_error)
        db.commit()
    return stats

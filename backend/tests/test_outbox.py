import smtplib
from datetime import timedelta

import pytest

from app.config import settings
from app.models import NotificationDelivery, naive_utc_now
from app.services import outbox
from app.services.alert_engine import alert_engine


@pytest.fixture
def transports(monkeypatch):
    """Pretend SMTP and Twilio are configured, and record what the transports are asked to send."""
    sent = {"email": [], "sms": []}
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.test")
    monkeypatch.setattr(settings, "SMTP_FROM", "alerts@test")
    monkeypatch.setattr(settings, "TWILIO_ACCOUNT_SID", "ACtest")
    monkeypatch.setattr(settings, "TWILIO_AUTH_TOKEN", "tok")
    monkeypatch.setattr(settings, "TWILIO_FROM_NUMBER", "+15550000000")
    monkeypatch.setattr(outbox, "send_email", lambda to, subject, body: sent["email"].append((to, subject, body)) or "<id@test>")
    monkeypatch.setattr(outbox, "send_sms", lambda to, body: sent["sms"].append((to, body)) or "SMabc")
    return sent


def _queue(db, severity="High", email="alex.turner@enterprise-corp.com", title="Outbox test"):
    rows = alert_engine.dispatch_security_alert(db, title=title, sanitized_summary="summary", severity=severity,
                                                target_employee_email=email, event_id=f"EV-{title}")
    db.commit()
    return rows


def test_alert_is_queued_not_claimed_delivered(db, transports):
    rows = _queue(db, title="Queued only")
    assert rows and all(r.delivery_status == "QUEUED" for r in rows)
    assert transports["email"] == []                      # nothing is sent inside the request


def test_worker_sends_and_records_provider_acceptance(db, transports):
    _queue(db, severity="Critical", title="Send me")
    stats = outbox.process_outbox(db)
    assert stats["sent"] >= 2
    assert {t[0] for t in transports["email"]} >= {"soc@example.org", "alex.turner@enterprise-corp.com"}
    rows = db.query(NotificationDelivery).filter(NotificationDelivery.title.like("%Send me%")).all()
    assert rows and all(r.delivery_status == "SENT" and r.dispatched_at for r in rows)
    assert all(r.delivery_status != "DELIVERED" for r in rows)


def test_sms_goes_only_to_high_severity_with_valid_phone(db, transports):
    from app.models import Employee
    emp = db.query(Employee).filter(Employee.company_email == "alex.turner@enterprise-corp.com").first()
    emp.phone_number = "+15551234567"
    db.commit()
    _queue(db, severity="Low", title="Low sev")
    _queue(db, severity="High", title="High sev")
    outbox.process_outbox(db)
    assert [s for s in transports["sms"] if "High sev" in s[1]]
    assert not [s for s in transports["sms"] if "Low sev" in s[1]]


def test_invalid_phone_number_fails_permanently(db, monkeypatch):
    monkeypatch.setattr(settings, "TWILIO_ACCOUNT_SID", "ACtest")
    monkeypatch.setattr(settings, "TWILIO_AUTH_TOKEN", "tok")
    monkeypatch.setattr(settings, "TWILIO_FROM_NUMBER", "+15550000000")
    row = outbox.enqueue_sms(db, "555-1234", "hello", title="bad phone")
    db.commit()
    outbox.process_outbox(db)
    db.refresh(row)
    assert row.delivery_status == "FAILED" and "E.164" in row.last_error


def test_unconfigured_transport_is_reported_honestly_then_revived(db, monkeypatch):
    monkeypatch.setattr(settings, "SMTP_HOST", None)
    row = outbox.enqueue_email(db, "someone@example.org", "needs smtp", "body")
    db.commit()
    outbox.process_outbox(db)
    db.refresh(row)
    assert row.delivery_status == "NOT_CONFIGURED" and "SMTP" in row.last_error

    sent = []
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.test")
    monkeypatch.setattr(settings, "SMTP_FROM", "alerts@test")
    monkeypatch.setattr(outbox, "send_email", lambda to, subject, body: sent.append(to) or "<id>")
    outbox.process_outbox(db)
    db.refresh(row)
    assert row.delivery_status == "SENT" and sent == ["someone@example.org"]


def test_transient_failure_retries_with_backoff_then_gives_up(db, monkeypatch):
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.test")
    monkeypatch.setattr(settings, "SMTP_FROM", "alerts@test")
    monkeypatch.setattr(settings, "ALERT_MAX_ATTEMPTS", 3)

    def boom(*a):
        raise ConnectionError("smtp down")
    monkeypatch.setattr(outbox, "send_email", boom)
    row = outbox.enqueue_email(db, "retry@example.org", "flaky", "body")
    db.commit()

    outbox.process_outbox(db)
    db.refresh(row)
    assert row.delivery_status == "QUEUED" and row.retry_count == 1
    assert row.next_attempt_at > naive_utc_now() + timedelta(seconds=30)
    assert "smtp down" in row.last_error

    for _ in range(2):                                   # make it due again and fail twice more
        row.next_attempt_at = naive_utc_now() - timedelta(seconds=1)
        db.commit()
        outbox.process_outbox(db)
        db.refresh(row)
    assert row.delivery_status == "FAILED" and row.retry_count == 3


def test_permanent_smtp_refusal_is_not_retried(db, monkeypatch):
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.test")
    monkeypatch.setattr(settings, "SMTP_FROM", "alerts@test")

    def refuse(*a):
        raise outbox.PermanentDeliveryError("SMTP refused the message: SMTPRecipientsRefused")
    monkeypatch.setattr(outbox, "send_email", refuse)
    row = outbox.enqueue_email(db, "nobody@nowhere.invalid", "refused", "body")
    db.commit()
    outbox.process_outbox(db)
    db.refresh(row)
    assert row.delivery_status == "FAILED" and row.retry_count == 0


def test_duplicate_alerts_are_suppressed_per_recipient_and_channel(db, transports):
    first = _queue(db, title="Dup alert")
    second = _queue(db, title="Dup alert")
    assert all(r.delivery_status == "QUEUED" for r in first)
    assert second and all(r.delivery_status == "SUPPRESSED_DUPLICATE" for r in second)


def test_secret_bearing_message_body_is_wiped_after_send(db, transports):
    row = outbox.enqueue_email(db, "reset@example.org", "reset", "https://x/?reset_token=SECRET", redact_after_send=True)
    db.commit()
    outbox.process_outbox(db)
    db.refresh(row)
    assert row.delivery_status == "SENT" and row.message_body is None and "SECRET" not in row.body_preview


def test_header_injection_in_subject_or_recipient_is_flattened(db):
    row = outbox.enqueue_email(db, "a@example.org\r\nBcc: evil@example.org", "hi\r\nBcc: evil@example.org", "body")
    assert "\n" not in row.recipient_address and "\n" not in row.title


def test_real_smtp_transport_speaks_smtp(monkeypatch):
    calls = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            calls["connect"] = (host, port)
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def starttls(self, context=None): calls["tls"] = True
        def login(self, u, p): calls["login"] = u
        def send_message(self, msg): calls["msg"] = msg

    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.test")
    monkeypatch.setattr(settings, "SMTP_PORT", 587)
    monkeypatch.setattr(settings, "SMTP_FROM", "alerts@test")
    monkeypatch.setattr(settings, "SMTP_USERNAME", "user")
    monkeypatch.setattr(settings, "SMTP_PASSWORD", "pw")
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    outbox.send_email("to@example.org", "Subject", "Body")
    assert calls["connect"] == ("smtp.test", 587) and calls["tls"] and calls["login"] == "user"
    assert calls["msg"]["To"] == "to@example.org" and calls["msg"]["Subject"] == "Subject"


def test_twilio_call_shape_and_error_handling(monkeypatch):
    import httpx
    seen = {}

    class Resp:
        def __init__(self, code, body): self.status_code, self._b = code, body
        def json(self): return self._b

    def fake_post(url, data=None, auth=None, timeout=None):
        seen.update(url=url, data=data, auth=auth)
        return Resp(201, {"sid": "SM123"})
    monkeypatch.setattr(settings, "TWILIO_ACCOUNT_SID", "ACtest")
    monkeypatch.setattr(settings, "TWILIO_AUTH_TOKEN", "tok")
    monkeypatch.setattr(settings, "TWILIO_FROM_NUMBER", "+15550000000")
    monkeypatch.setattr(httpx, "post", fake_post)
    assert outbox.send_sms("+15551234567", "hi") == "SM123"
    assert seen["url"].endswith("/Accounts/ACtest/Messages.json")
    assert seen["data"]["To"] == "+15551234567" and seen["auth"] == ("ACtest", "tok")

    monkeypatch.setattr(httpx, "post", lambda *a, **k: Resp(400, {"message": "bad number"}))
    with pytest.raises(outbox.PermanentDeliveryError):
        outbox.send_sms("+15551234567", "hi")
    monkeypatch.setattr(httpx, "post", lambda *a, **k: Resp(503, {}))
    with pytest.raises(RuntimeError):
        outbox.send_sms("+15551234567", "hi")

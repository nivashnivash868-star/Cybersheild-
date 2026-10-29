"""Response connector: approved account-disable / host-isolation actions are sent, signed, to the organisation's automation."""
import json
import time
from datetime import timedelta

import httpx
import pytest

from app.config import settings
from app.models import AuditLog, DecisionRequest, Incident, ResponseAction, ResponseJob, User, naive_utc_now
from app.services import response_executor as rx
from tests.conftest import wipe_soc

API = "/api/v1"
SECRET = "s" * 40
URL = "https://soar.example.org/hooks/cybershield"


@pytest.fixture(autouse=True)
def _restore_demo_data():
    yield
    from app.database import SessionLocal
    from app.services.demo_data_seeder import seed_demo_soc_data
    with SessionLocal() as s:
        seed_demo_soc_data(db=s, force_reset=True)


@pytest.fixture
def connector(monkeypatch):
    monkeypatch.setattr(settings, "RESPONSE_WEBHOOK_URL", URL)
    monkeypatch.setattr(settings, "RESPONSE_WEBHOOK_SECRET", SECRET)


class Receiver:
    """Stands in for the organisation's automation: records requests, verifies the signature, answers as told."""

    def __init__(self, status=202, body=None):
        self.status, self.body, self.requests = status, body, []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        raw = request.content
        assert rx.verify(SECRET, raw, request.headers[rx.SIGNATURE_HEADER]), "request was not signed correctly"
        self.requests.append(json.loads(raw))
        if isinstance(self.status, Exception):
            raise self.status
        return httpx.Response(self.status, json=self.body or {})

    @property
    def transport(self):
        return httpx.MockTransport(self)


def callback(client, job_id, result="succeeded", detail="done", secret=SECRET, ts=None):
    body = json.dumps({"job_id": job_id, "result": result, "detail": detail}).encode()
    return client.post(f"{API}/response/callback", content=body,
                       headers={"Content-Type": "application/json", rx.SIGNATURE_HEADER: rx.sign(secret, body, ts)})


@pytest.fixture
def pending(db):
    wipe_soc(db)
    db.query(User).filter(User.email == "victim.user@company.com").delete()
    db.add(User(email="victim.user@company.com", full_name="Victim", role="Employee", hashed_password="x"))
    db.add(Incident(incident_id="INC-RX", title="t", description="d", threat_category="Phishing", severity="High", risk_score=80, status="Investigating"))
    a = DecisionRequest(kind="DISABLE_ACCOUNT", incident_id="INC-RX", title="Disable account victim.user@company.com", rationale="r",
                        proposal=json.dumps({"account": "victim.user@company.com"}), created_by="agent:L2-investigator")
    h = DecisionRequest(kind="HOST_ISOLATION", incident_id="INC-RX", title="Isolate host 10.20.4.37", rationale="r",
                        proposal=json.dumps({"host": "10.20.4.37"}), created_by="agent:L2-investigator")
    db.add_all([a, h])
    db.commit()
    return a.id, h.id


# ------------------------------------------------------------------------------------------ signatures

def test_signature_roundtrip_and_tamper_and_replay():
    body = b'{"a":1}'
    header = rx.sign(SECRET, body)
    assert rx.verify(SECRET, body, header)
    assert not rx.verify(SECRET, b'{"a":2}', header)
    assert not rx.verify("other" * 10, body, header)
    assert not rx.verify(SECRET, body, rx.sign(SECRET, body, int(time.time()) - 3600))      # replayed
    assert not rx.verify(SECRET, body, "garbage") and not rx.verify(SECRET, body, "")


# ------------------------------------------------------------------------------------------ not configured

def test_without_a_connector_nothing_is_queued_and_the_limit_is_stated(admin, db, pending):
    a, h = pending
    assert admin.post(f"{API}/soc/decisions/{h}/decide", json={"decision": "approve"}).status_code == 200
    assert db.query(ResponseJob).count() == 0
    action = db.query(ResponseAction).filter(ResponseAction.action_type == "HOST_ISOLATION").one()
    assert action.status == "APPROVED_MANUAL" and "no EDR" in action.details


def test_short_secret_means_not_configured(monkeypatch):
    monkeypatch.setattr(settings, "RESPONSE_WEBHOOK_URL", URL)
    monkeypatch.setattr(settings, "RESPONSE_WEBHOOK_SECRET", "too-short")
    assert not rx.configured()


# ------------------------------------------------------------------------------------------ happy path

def test_approved_action_is_sent_signed_then_confirmed_by_callback(admin, anon, db, pending, connector):
    a, h = pending
    assert admin.post(f"{API}/soc/decisions/{h}/decide", json={"decision": "approve", "note": "ok"}).status_code == 200
    job = db.query(ResponseJob).one()
    assert job.status == "QUEUED" and job.action == "HOST_ISOLATION" and job.target == "10.20.4.37" and job.approved_by == "admin@cybershield.corp"
    action = db.query(ResponseAction).filter(ResponseAction.action_type == "HOST_ISOLATION").one()
    assert action.status == "QUEUED_FOR_CONNECTOR"

    receiver = Receiver(202)
    assert rx.process_due(db, transport=receiver.transport)["sent"] == 1
    db.expire_all()
    job = db.query(ResponseJob).one()
    sent = receiver.requests[0]
    assert sent["job_id"] == job.job_id and sent["action"] == "HOST_ISOLATION" and sent["target"] == "10.20.4.37"
    assert sent["callback_url"].endswith("/response/callback") and sent["incident_id"] == "INC-RX"
    assert job.status == "SENT"                                  # accepted, NOT yet confirmed
    assert db.query(ResponseAction).filter(ResponseAction.action_type == "HOST_ISOLATION").one().status == "SENT_TO_CONNECTOR"

    assert callback(anon, job.job_id).json() == {"job_id": job.job_id, "status": "COMPLETED"}
    db.expire_all()
    assert db.query(ResponseJob).one().status == "COMPLETED"
    assert db.query(ResponseAction).filter(ResponseAction.action_type == "HOST_ISOLATION").one().status == "EXECUTED_BY_CONNECTOR"
    assert db.query(AuditLog).filter(AuditLog.action == "RESPONSE_JOB_COMPLETED").count() >= 1
    assert callback(anon, job.job_id).status_code == 409         # a job completes once


def test_disable_account_does_both_platform_and_connector_work(admin, db, pending, connector):
    a, _ = pending
    assert admin.post(f"{API}/soc/decisions/{a}/decide", json={"decision": "approve"}).status_code == 200
    assert db.query(User).filter(User.email == "victim.user@company.com").one().is_active is False
    assert db.query(ResponseJob).one().action == "DISABLE_ACCOUNT"
    out = db.get(DecisionRequest, a).outcome
    assert "confirms" in out


def test_receiver_can_complete_synchronously(admin, db, pending, connector):
    _, h = pending
    admin.post(f"{API}/soc/decisions/{h}/decide", json={"decision": "approve"})
    rx.process_due(db, transport=Receiver(200, {"status": "completed", "detail": "isolated in EDR"}).transport)
    db.expire_all()
    job = db.query(ResponseJob).one()
    assert job.status == "COMPLETED" and job.result_detail == "isolated in EDR"


# ------------------------------------------------------------------------------------------ failure handling

def test_transient_failures_retry_with_backoff_then_give_up(admin, db, pending, connector, monkeypatch):
    _, h = pending
    monkeypatch.setattr(settings, "RESPONSE_WEBHOOK_MAX_ATTEMPTS", 3)
    admin.post(f"{API}/soc/decisions/{h}/decide", json={"decision": "approve"})
    for attempt in (1, 2):
        assert rx.process_due(db, transport=Receiver(503).transport)["retry"] == 1
        db.expire_all()
        job = db.query(ResponseJob).one()
        assert job.status == "QUEUED" and job.attempts == attempt and job.next_attempt_at > naive_utc_now()
        job.next_attempt_at = naive_utc_now()
        db.commit()
    assert rx.process_due(db, transport=Receiver(httpx.ConnectError("refused")).transport)["failed"] == 1
    db.expire_all()
    job = db.query(ResponseJob).one()
    assert job.status == "FAILED" and "Gave up after 3" in job.result_detail
    assert db.query(ResponseAction).filter(ResponseAction.action_type == "HOST_ISOLATION").one().status == "CONNECTOR_FAILED"


def test_a_refusal_fails_immediately_and_an_admin_can_retry(admin, analyst, db, pending, connector):
    _, h = pending
    admin.post(f"{API}/soc/decisions/{h}/decide", json={"decision": "approve"})
    assert rx.process_due(db, transport=Receiver(403).transport)["failed"] == 1
    db.expire_all()
    job = db.query(ResponseJob).one()
    assert job.status == "FAILED" and job.attempts == 1 and job.http_status == 403
    assert analyst.post(f"{API}/response/jobs/{job.job_id}/retry").status_code == 403
    assert admin.post(f"{API}/response/jobs/{job.job_id}/retry").json()["status"] == "QUEUED"
    assert admin.post(f"{API}/response/jobs/{job.job_id}/retry").status_code == 409        # already queued
    assert admin.get(f"{API}/response/jobs").json()[0]["job_id"] == job.job_id
    assert analyst.get(f"{API}/response/jobs").status_code == 403


def test_a_job_nobody_confirms_becomes_unconfirmed(admin, db, pending, connector):
    _, h = pending
    admin.post(f"{API}/soc/decisions/{h}/decide", json={"decision": "approve"})
    rx.process_due(db, transport=Receiver(202).transport)
    job = db.query(ResponseJob).one()
    job.sent_at = naive_utc_now() - timedelta(minutes=settings.RESPONSE_WEBHOOK_ACK_MINUTES + 1)
    db.commit()
    assert rx.process_due(db, transport=Receiver(202).transport)["unconfirmed"] == 1
    db.expire_all()
    assert db.query(ResponseJob).one().status == "UNCONFIRMED"
    assert db.query(ResponseAction).filter(ResponseAction.action_type == "HOST_ISOLATION").one().status == "UNCONFIRMED"


def test_receiver_can_report_failure(admin, anon, db, pending, connector):
    _, h = pending
    admin.post(f"{API}/soc/decisions/{h}/decide", json={"decision": "approve"})
    rx.process_due(db, transport=Receiver(202).transport)
    job = db.query(ResponseJob).one()
    assert callback(anon, job.job_id, result="failed", detail="EDR agent offline").json()["status"] == "FAILED"


# ------------------------------------------------------------------------------------------ callback security

def test_callback_rejects_bad_signatures_unknown_jobs_and_junk(anon, db, connector):
    assert callback(anon, "RJ-NOPE").status_code == 404
    assert callback(anon, "RJ-NOPE", secret="x" * 40).status_code == 401
    assert callback(anon, "RJ-NOPE", ts=int(time.time()) - 3600).status_code == 401
    assert anon.post(f"{API}/response/callback", content=b"{}").status_code == 401
    body = b"[1,2]"
    assert anon.post(f"{API}/response/callback", content=body, headers={rx.SIGNATURE_HEADER: rx.sign(SECRET, body)}).status_code == 422
    body = json.dumps({"job_id": "RJ-X", "result": "maybe"}).encode()
    assert anon.post(f"{API}/response/callback", content=body, headers={rx.SIGNATURE_HEADER: rx.sign(SECRET, body)}).status_code in (404, 409)


def test_callback_is_closed_when_no_connector_is_configured(anon):
    assert callback(anon, "RJ-1").status_code == 401


def test_plain_http_to_a_remote_host_is_refused_outside_development(monkeypatch):
    monkeypatch.setattr(settings, "RESPONSE_WEBHOOK_URL", "http://soar.example.org/hook")
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    assert rx.url_problem()
    monkeypatch.setattr(settings, "RESPONSE_WEBHOOK_URL", "https://soar.example.org/hook")
    assert rx.url_problem() is None


def test_worker_delivery_does_not_wait_for_the_slow_analysis_half(db, monkeypatch):
    """A Zetaris ingest that takes minutes must not delay alerts or approved responses."""
    import time as _t
    from app import worker
    monkeypatch.setattr(worker, "_maybe_ingest", lambda _db: _t.sleep(0.5) or 0)
    started = _t.monotonic()
    worker.deliver_once()
    assert _t.monotonic() - started < 0.4
    assert "zetaris_events" in worker.analyse_once() and "soc" in worker.run_once()

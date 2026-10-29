"""Response connector: hands approved containment actions to the organisation's own automation.

CyberShield does not hold identity-provider or EDR credentials. When a person approves disabling an account or
isolating a host, a job is queued and POSTed to RESPONSE_WEBHOOK_URL, signed with a shared secret, and the receiver
(a SOAR playbook, an IdP script, an EDR wrapper) does the work and reports back. Statuses never claim more than was
confirmed: SENT means the receiver accepted the request, COMPLETED only when the receiver said it was done.

Signature: header  X-CyberShield-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<raw body>">
The same scheme signs the receiver's callback to POST /api/v1/response/callback.
"""
import hashlib
import hmac
import json
import logging
import time
import uuid
from datetime import timedelta
from typing import Any, Dict, Optional

import httpx
from sqlalchemy import update
from sqlalchemy.orm import Session

from app.config import settings
from app.models import AuditLog, DecisionRequest, ResponseAction, ResponseJob, naive_utc_now

logger = logging.getLogger("cybershield.response")

SIGNATURE_HEADER = "X-CyberShield-Signature"
JOB_HEADER = "X-CyberShield-Job"
REPLAY_WINDOW_SECONDS = 300
OPEN_STATUSES = ("QUEUED", "SENDING", "SENT", "UNCONFIRMED")


def sign(secret: str, body: bytes, timestamp: Optional[int] = None) -> str:
    ts = int(timestamp if timestamp is not None else time.time())
    mac = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"


def verify(secret: str, body: bytes, header: str, now: Optional[float] = None) -> bool:
    try:
        parts = dict(p.split("=", 1) for p in header.split(","))
        ts, given = int(parts["t"]), parts["v1"]
    except (ValueError, KeyError):
        return False
    if abs((now if now is not None else time.time()) - ts) > REPLAY_WINDOW_SECONDS:
        return False
    expected = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, given)


def configured() -> bool:
    return settings.response_connector_configured


def handles(action: str) -> bool:
    return configured() and action in settings.response_actions


def url_problem() -> Optional[str]:
    """Plain HTTP is only acceptable to a local receiver or in development."""
    url = settings.RESPONSE_WEBHOOK_URL or ""
    if url.startswith("https://") or settings.is_development:
        return None
    if url.startswith("http://localhost") or url.startswith("http://127.0.0.1"):
        return None
    return "RESPONSE_WEBHOOK_URL must use https outside development."


def enqueue(db: Session, action: str, target: str, *, decision: Optional[DecisionRequest], incident_id: Optional[str],
            approved_by: str, response_action: Optional[ResponseAction] = None) -> ResponseJob:
    job = ResponseJob(job_id=f"RJ-{uuid.uuid4().hex[:16].upper()}", action=action, target=target[:255],
                      decision_id=decision.id if decision is not None else None, incident_id=incident_id,
                      approved_by=approved_by, status="QUEUED", next_attempt_at=naive_utc_now(),
                      response_action_id=response_action.id if response_action is not None and response_action.id else None)
    db.add(job)
    db.flush()
    if response_action is not None:
        response_action.status = "QUEUED_FOR_CONNECTOR"
        response_action.details = f"{response_action.details} Queued as {job.job_id}."[:2000]
    return job


def _payload(job: ResponseJob) -> bytes:
    body: Dict[str, Any] = {
        "job_id": job.job_id, "action": job.action, "target": job.target, "incident_id": job.incident_id,
        "decision_id": job.decision_id, "approved_by": job.approved_by,
        "requested_at": job.created_at.isoformat() + "Z",
        "callback_url": f"{settings.PUBLIC_BASE_URL.rstrip('/')}{settings.API_V1_PREFIX}/response/callback",
    }
    return json.dumps(body, separators=(",", ":"), sort_keys=True).encode()


def _sync_action(db: Session, job: ResponseJob, status: str, note: str) -> None:
    if not job.response_action_id:
        return
    row = db.get(ResponseAction, job.response_action_id)
    if row is not None:
        row.status = status
        row.details = f"{row.details} {note}"[-2000:]


def _finish(db: Session, job: ResponseJob, status: str, detail: str) -> None:
    job.status, job.result_detail = status, detail[:500]
    if status in ("COMPLETED", "FAILED"):
        job.completed_at = naive_utc_now()
    _sync_action(db, job, {"COMPLETED": "EXECUTED_BY_CONNECTOR", "FAILED": "CONNECTOR_FAILED"}.get(status, status), f"[{job.job_id}: {status.lower()}: {detail[:200]}]")
    db.add(AuditLog(action=f"RESPONSE_JOB_{status}", actor="response-connector", resource_type="ResponseJob", resource_id=job.job_id,
                    details=f"{job.action} {job.target}: {detail[:300]}"))


def _interpret_reply(db: Session, job: ResponseJob, response: httpx.Response) -> None:
    """2xx = accepted. A reply body may also carry the final result for receivers that act synchronously."""
    job.http_status, job.sent_at = response.status_code, naive_utc_now()
    result = None
    try:
        data = response.json()
        result = str(data.get("status", "")).lower() if isinstance(data, dict) else None
        detail = str(data.get("detail", ""))[:300] if isinstance(data, dict) else ""
    except ValueError:
        detail = ""
    if result in ("completed", "succeeded", "success", "done"):
        _finish(db, job, "COMPLETED", detail or "The receiver reported the action done.")
    elif result in ("failed", "error"):
        _finish(db, job, "FAILED", detail or "The receiver reported failure.")
    else:
        job.status = "SENT"
        _sync_action(db, job, "SENT_TO_CONNECTOR", f"[{job.job_id}: accepted by the receiver, completion not yet confirmed]")


def process_due(db: Session, transport: Optional[httpx.BaseTransport] = None) -> Dict[str, int]:
    """Worker pass: send due jobs, retry transient failures, flag jobs nobody has confirmed."""
    stats = {"sent": 0, "retry": 0, "failed": 0, "unconfirmed": 0}
    now = naive_utc_now()
    cutoff = now - timedelta(minutes=settings.RESPONSE_WEBHOOK_ACK_MINUTES)
    for job in db.query(ResponseJob).filter(ResponseJob.status == "SENT", ResponseJob.sent_at <= cutoff).all():
        job.status = "UNCONFIRMED"
        _sync_action(db, job, "UNCONFIRMED", f"[{job.job_id}: no confirmation within {settings.RESPONSE_WEBHOOK_ACK_MINUTES} min; verify in the target system]")
        stats["unconfirmed"] += 1
    # a worker that died mid-send leaves SENDING rows; make them due again
    db.execute(update(ResponseJob).where(ResponseJob.status == "SENDING", ResponseJob.next_attempt_at <= now - timedelta(minutes=5))
               .values(status="QUEUED", next_attempt_at=now))
    db.commit()
    due = db.query(ResponseJob).filter(ResponseJob.status == "QUEUED", ResponseJob.next_attempt_at <= now).order_by(ResponseJob.id).limit(20).all()
    if not due:
        return stats
    if not configured() or url_problem():
        for job in due:
            job.last_error = url_problem() or "Response connector is not configured."
            job.next_attempt_at = now + timedelta(minutes=5)
        db.commit()
        return stats
    with httpx.Client(timeout=settings.RESPONSE_WEBHOOK_TIMEOUT_SECONDS, transport=transport, follow_redirects=False) as client:
        for job in due:
            claimed = db.execute(update(ResponseJob).where(ResponseJob.id == job.id, ResponseJob.status == "QUEUED")
                                 .values(status="SENDING", next_attempt_at=now)).rowcount
            db.commit()
            if not claimed:
                continue
            db.refresh(job)
            body = _payload(job)
            job.attempts += 1
            try:
                reply = client.post(settings.RESPONSE_WEBHOOK_URL, content=body, headers={
                    "Content-Type": "application/json", JOB_HEADER: job.job_id, SIGNATURE_HEADER: sign(settings.RESPONSE_WEBHOOK_SECRET, body),
                    "User-Agent": "CyberShield-Response/1"})
                if 200 <= reply.status_code < 300:
                    _interpret_reply(db, job, reply)
                    stats["sent"] += 1
                elif reply.status_code in (408, 425, 429) or reply.status_code >= 500:
                    raise httpx.HTTPError(f"receiver answered {reply.status_code}")
                else:
                    job.http_status = reply.status_code
                    _finish(db, job, "FAILED", f"The receiver refused the request (HTTP {reply.status_code}).")
                    stats["failed"] += 1
            except httpx.HTTPError as exc:
                job.last_error = f"{type(exc).__name__}: {exc}"[:500]
                if job.attempts >= settings.RESPONSE_WEBHOOK_MAX_ATTEMPTS:
                    _finish(db, job, "FAILED", f"Gave up after {job.attempts} attempts. Last error: {job.last_error}")
                    stats["failed"] += 1
                else:
                    job.status, job.next_attempt_at = "QUEUED", naive_utc_now() + timedelta(seconds=30 * 2 ** job.attempts)
                    stats["retry"] += 1
            db.commit()
    return stats


def apply_callback(db: Session, payload: Dict[str, Any]) -> ResponseJob:
    """A signed report from the receiver. Only jobs we sent (or that await confirmation) can be updated, and only once."""
    job = db.query(ResponseJob).filter(ResponseJob.job_id == str(payload.get("job_id", ""))).first()
    if job is None:
        raise LookupError("unknown job")
    if job.status in ("COMPLETED", "FAILED"):
        raise ValueError(f"job already {job.status.lower()}")
    if job.status not in ("SENT", "UNCONFIRMED", "SENDING", "QUEUED"):
        raise ValueError("job is not awaiting a result")
    result = str(payload.get("result", "")).lower()
    detail = str(payload.get("detail", ""))[:400]
    if result in ("succeeded", "success", "completed"):
        _finish(db, job, "COMPLETED", detail or "The receiver reported the action done.")
    elif result in ("failed", "error"):
        _finish(db, job, "FAILED", detail or "The receiver reported failure.")
    else:
        raise ValueError("result must be 'succeeded' or 'failed'")
    if job.decision_id:
        decision = db.get(DecisionRequest, job.decision_id)
        if decision is not None:
            decision.outcome = f"{(decision.outcome or '')[:140]} Connector: {job.status.lower()}."[:255]
    return job


def retry(db: Session, job: ResponseJob, user_email: str) -> ResponseJob:
    if job.status not in ("FAILED", "UNCONFIRMED"):
        raise ValueError("Only failed or unconfirmed jobs can be retried.")
    job.status, job.attempts, job.next_attempt_at, job.last_error = "QUEUED", 0, naive_utc_now(), None
    db.add(AuditLog(action="RESPONSE_JOB_RETRIED", actor=user_email, resource_type="ResponseJob", resource_id=job.job_id, details=f"{job.action} {job.target}"))
    return job


def ping(transport: Optional[httpx.BaseTransport] = None) -> Dict[str, Any]:
    """A signed PING to the receiver (no job is created and nothing is executed). The receiver should answer 2xx."""
    if not configured():
        return {"ok": False, "detail": "Not configured: RESPONSE_WEBHOOK_URL and a 32+ character RESPONSE_WEBHOOK_SECRET are required."}
    problem = url_problem()
    if problem:
        return {"ok": False, "detail": problem}
    body = json.dumps({"job_id": f"RJ-PING-{uuid.uuid4().hex[:8].upper()}", "action": "PING", "target": "connectivity-test",
                       "requested_at": naive_utc_now().isoformat() + "Z"}, separators=(",", ":"), sort_keys=True).encode()
    try:
        with httpx.Client(timeout=settings.RESPONSE_WEBHOOK_TIMEOUT_SECONDS, transport=transport, follow_redirects=False) as client:
            reply = client.post(settings.RESPONSE_WEBHOOK_URL, content=body, headers={
                "Content-Type": "application/json", SIGNATURE_HEADER: sign(settings.RESPONSE_WEBHOOK_SECRET, body), "User-Agent": "CyberShield-Response/1"})
    except httpx.HTTPError as exc:
        return {"ok": False, "detail": f"Could not reach the receiver ({type(exc).__name__})."}
    ok = 200 <= reply.status_code < 300
    return {"ok": ok, "detail": f"The receiver answered HTTP {reply.status_code}" + ("." if ok else "; it should accept a signed PING with 2xx.")}

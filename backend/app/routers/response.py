"""Response connector: the receiver's signed callback, and administrators' view of the jobs sent to it."""
import json
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import ResponseJob, User
from app.services import response_executor as svc
from app.utils.auth import ADMIN_ROLES, require_roles
from app.utils.ratelimit import client_ip, limiter

router = APIRouter(prefix="/response", tags=["Response connector"])


class JobOut(BaseModel):
    job_id: str
    action: str
    target: str
    incident_id: Optional[str] = None
    decision_id: Optional[int] = None
    approved_by: str
    status: str
    attempts: int
    http_status: Optional[int] = None
    last_error: Optional[str] = None
    result_detail: Optional[str] = None
    created_at: str
    sent_at: Optional[str] = None
    completed_at: Optional[str] = None


def _out(j: ResponseJob) -> JobOut:
    iso = lambda d: d.isoformat() + "Z" if d else None  # noqa: E731
    return JobOut(job_id=j.job_id, action=j.action, target=j.target, incident_id=j.incident_id, decision_id=j.decision_id,
                  approved_by=j.approved_by, status=j.status, attempts=j.attempts, http_status=j.http_status,
                  last_error=j.last_error, result_detail=j.result_detail, created_at=iso(j.created_at),
                  sent_at=iso(j.sent_at), completed_at=iso(j.completed_at))


@router.post("/callback")
async def callback(request: Request, db: Session = Depends(get_db)):
    """The receiver reports the outcome of a job. Authenticated by the HMAC signature, not by a session."""
    if not limiter.hit(f"response-callback:{client_ip(request)}", 60, 60):
        raise HTTPException(429, "Too many requests.")
    if not settings.response_connector_configured:
        raise HTTPException(401, "Invalid signature.")
    body = await request.body()
    if len(body) > 20_000 or not svc.verify(settings.RESPONSE_WEBHOOK_SECRET, body, request.headers.get(svc.SIGNATURE_HEADER, "")):
        raise HTTPException(401, "Invalid signature.")
    try:
        payload = json.loads(body)
        if not isinstance(payload, dict):
            raise ValueError
    except ValueError:
        raise HTTPException(422, "The body must be a JSON object.")
    try:
        job = svc.apply_callback(db, payload)
    except LookupError:
        raise HTTPException(404, "Unknown job.")
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    db.commit()
    return {"job_id": job.job_id, "status": job.status}


@router.get("/jobs", response_model=List[JobOut])
def list_jobs(status: Optional[str] = None, limit: int = Query(50, ge=1, le=200), db: Session = Depends(get_db),
              _: User = Depends(require_roles(ADMIN_ROLES))):
    q = db.query(ResponseJob)
    if status:
        q = q.filter(ResponseJob.status == status.upper())
    return [_out(j) for j in q.order_by(ResponseJob.id.desc()).limit(limit).all()]


@router.post("/jobs/{job_id}/retry", response_model=JobOut)
def retry_job(job_id: str, db: Session = Depends(get_db), user: User = Depends(require_roles(ADMIN_ROLES))):
    job = db.query(ResponseJob).filter(ResponseJob.job_id == job_id).first()
    if job is None:
        raise HTTPException(404, "Unknown job.")
    try:
        svc.retry(db, job, user.email)
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    db.commit()
    return _out(job)

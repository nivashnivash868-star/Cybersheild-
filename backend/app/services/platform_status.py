"""One honest answer to "is the platform working?": the database answers and the automation worker has reported in."""
from datetime import timedelta

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.models import naive_utc_now
from app.services import settings_store

WORKER_STALE_AFTER = timedelta(minutes=2)


def platform_status(db: Session) -> str:
    try:
        db.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001
        return "Degraded: database unreachable"
    _, seen = settings_store.get_fact(db, "worker_heartbeat")
    if seen is None:
        return "Degraded: automation worker has not reported in"
    if naive_utc_now() - seen > WORKER_STALE_AFTER:
        return "Degraded: automation worker stopped reporting"
    return "Operational"

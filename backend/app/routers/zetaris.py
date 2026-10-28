import time
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.config import settings
from app.database import get_db
from app.models import IngestState, User
from app.services import zetaris_ingest
from app.services.zetaris import ZetarisClient, ZetarisError, ZetarisNotConfigured
from app.utils.auth import ADMIN_ROLES, STAFF_ROLES, require_roles
from app.utils.ratelimit import limiter

router = APIRouter(prefix="/zetaris", tags=["Zetaris Data Integration"])

_ping_cache: Dict[str, Any] = {"at": 0.0, "value": None}


def _client() -> ZetarisClient:
    try:
        return ZetarisClient()
    except ZetarisNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc))


def _throttle(user: User) -> None:
    if not limiter.hit(f"zetaris:{user.id}", 30, 60):
        raise HTTPException(status_code=429, detail="Too many Zetaris requests. Wait a moment.")


@router.get("/status")
def status(db: Session = Depends(get_db), user: User = Depends(require_roles(STAFF_ROLES))):
    """'connected' is true only after a real authenticated round trip to Zetaris just now."""
    sources = [
        {"source": s.source, "table": zetaris_ingest.table(s.source) if s.source in zetaris_ingest.configured_sources() else None,
         "watermark": s.watermark, "last_run_at": s.last_run_at, "last_status": s.last_status, "last_error": s.last_error,
         "rows_seen": s.rows_seen, "events_created": s.events_created}
        for s in db.query(IngestState).order_by(IngestState.source).all()
    ]
    base: Dict[str, Any] = {"configured": settings.zetaris_configured, "base_url": settings.ZETARIS_BASE_URL,
                            "tables": {k: getattr(settings, f"ZETARIS_TABLE_{k.upper()}") for k in zetaris_ingest.SOURCES},
                            "sources": sources, "connected": False, "error": None}
    if not settings.zetaris_configured:
        base["error"] = "Not configured: set ZETARIS_ORG_ID and ZETARIS_API_KEY."
        return base
    now = time.monotonic()
    if _ping_cache["value"] is None or now - _ping_cache["at"] > 15:
        _throttle(user)
        try:
            with _client() as c:
                ping = c.ping()
            _ping_cache.update(at=now, value={"connected": True, "latency_ms": ping["latency_ms"],
                                              "databases": [d.get("name") for d in ping["databases"]], "error": None})
        except ZetarisError as exc:
            _ping_cache.update(at=now, value={"connected": False, "error": str(exc)})
    return {**base, **_ping_cache["value"]}


@router.post("/ingest/run")
def run_ingest_now(db: Session = Depends(get_db), user: User = Depends(require_roles(ADMIN_ROLES))):
    _throttle(user)
    if not zetaris_ingest.configured_sources():
        raise HTTPException(status_code=409, detail="No tables configured: set ZETARIS_TABLE_AUTH / _NETWORK / _EMAIL.")
    try:
        with _client() as c:
            return zetaris_ingest.run_ingest(db, c)
    except ZetarisError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@router.get("/investigate")
def investigate(indicator: str = Query(..., min_length=2, max_length=128), user: User = Depends(require_roles(STAFF_ROLES))):
    _throttle(user)
    if not zetaris_ingest.configured_sources():
        raise HTTPException(status_code=409, detail="No tables configured: set ZETARIS_TABLE_AUTH / _NETWORK / _EMAIL.")
    try:
        with _client() as c:
            return zetaris_ingest.investigate(c, indicator)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except ZetarisError as exc:
        raise HTTPException(status_code=502, detail=str(exc))

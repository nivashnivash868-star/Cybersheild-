"""Machine-facing blocklist feeds. Authenticated by a per-consumer feed token, not by a user session."""
import base64
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import FeedToken, naive_utc_now
from app.services import blocklist as svc
from app.utils.crypto import sha256_hex
from app.utils.ratelimit import client_ip, limiter

router = APIRouter(prefix="/feeds/blocklist", tags=["Blocklist Feeds (for firewalls and DNS)"])


def _token_from(request: Request) -> str:
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() == "bearer" and value:
        return value.strip()
    if scheme.lower() == "basic" and value:
        try:
            return base64.b64decode(value).decode().split(":", 1)[1]
        except Exception:
            return ""
    return ""


def authenticate_feed(request: Request, db: Session = Depends(get_db)) -> FeedToken:
    token = _token_from(request)
    row = db.query(FeedToken).filter(FeedToken.token_hash == sha256_hex(token)).first() if token else None
    if row is None or row.revoked_at is not None:
        raise HTTPException(status_code=401, detail="Invalid feed credential.", headers={"WWW-Authenticate": 'Basic realm="feeds"'})
    if not limiter.hit(f"feed:{row.id}", 120, 60):
        raise HTTPException(status_code=429, detail="Too many requests.")
    return row


@router.get("/{feed}.txt")
def get_feed(feed: str, request: Request, strip_scheme: bool = Query(False), db: Session = Depends(get_db),
             token: FeedToken = Depends(authenticate_feed)):
    if feed not in svc.FEEDS:
        raise HTTPException(status_code=404, detail="Unknown feed. Use ip, domain or url.")
    body, version = svc.render_feed(db, feed, strip_scheme)
    etag = f'"{version}"'
    token.last_fetched_at = naive_utc_now()
    token.last_fetched_version = f"{feed}:{version}"
    token.last_fetched_ip = client_ip(request)
    db.commit()
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers={"ETag": etag})
    return Response(content=body, media_type="text/plain; charset=utf-8",
                    headers={"ETag": etag, "Cache-Control": "no-store"})

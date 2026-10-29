"""Single sign-on with OpenID Connect. Browser redirects, so these routes are public; every outcome is audited."""
import logging
from typing import Optional
from urllib.parse import quote

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import AuditLog, User, naive_utc_now
from app.services import oidc
from app.utils.auth import create_session, set_session_cookies, user_needs_mfa
from app.utils.ratelimit import enforce

router = APIRouter(prefix="/auth/sso", tags=["Single sign-on"])
logger = logging.getLogger("cybershield.sso")
TXN_COOKIE = "cs_sso"


def _audit(db: Session, action: str, actor: str, details: str, user: Optional[User] = None) -> None:
    db.add(AuditLog(action=action, actor=actor, resource_type="User", resource_id=str(user.id) if user else actor, details=details[:480]))


def _deny(db: Session, reason: str, actor: str = "sso", user: Optional[User] = None) -> RedirectResponse:
    _audit(db, "AUTH_SSO_DENIED", actor, reason, user)
    db.commit()
    response = RedirectResponse("/?sso_error=denied", status_code=303)
    response.delete_cookie(TXN_COOKIE, path="/")
    return response


@router.get("/config")
def sso_config():
    """Whether to show the SSO button. Reveals nothing about the provider beyond its display name."""
    return {"enabled": settings.oidc_configured, "provider_name": settings.OIDC_PROVIDER_NAME}


@router.get("/login")
def sso_login(request: Request, db: Session = Depends(get_db)):
    enforce(request, "sso-login", 30)
    if not settings.oidc_configured:
        return JSONResponse({"detail": "Single sign-on is not configured."}, status_code=404)
    try:
        state, nonce, verifier, cookie = oidc.new_transaction()
        url = oidc.authorization_url(state, nonce, verifier)
    except Exception as exc:  # noqa: BLE001 - provider unreachable or misconfigured
        logger.warning("SSO start failed: %s", exc)
        return _deny(db, f"could not reach the identity provider: {type(exc).__name__}")
    response = RedirectResponse(url, status_code=303)
    # Lax so the browser returns it on the provider's redirect back; it holds only a one-time, signed, 10 minute transaction.
    response.set_cookie(TXN_COOKIE, cookie, max_age=oidc.TXN_SECONDS, httponly=True, secure=settings.cookie_secure, samesite="lax", path="/")
    return response


@router.get("/callback")
def sso_callback(request: Request, code: Optional[str] = None, state: Optional[str] = None, error: Optional[str] = None,
                 db: Session = Depends(get_db)):
    enforce(request, "sso-callback", 30)
    if not settings.oidc_configured:
        return JSONResponse({"detail": "Single sign-on is not configured."}, status_code=404)
    if error:
        return _deny(db, f"provider returned error '{error[:60]}'")
    try:
        txn = oidc.open_transaction(request.cookies.get(TXN_COOKIE, ""))
        if not code or not state or state != txn["s"]:
            raise oidc.OidcError("state missing or does not match")
        tokens = oidc.exchange_code(code, txn["v"])
        claims = oidc.verify_id_token(tokens["id_token"], txn["n"])
        email = oidc.email_from(claims)
    except oidc.OidcError as exc:
        return _deny(db, str(exc))
    except Exception as exc:  # noqa: BLE001 - network or malformed provider reply
        logger.warning("SSO callback failed: %s", exc)
        return _deny(db, f"provider exchange failed: {type(exc).__name__}")

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        return _deny(db, "no CyberShield account for this email (SSO does not create accounts)", actor=email)
    if not user.is_active:
        return _deny(db, "account is deactivated", actor=email, user=user)
    now = naive_utc_now()
    if user.locked_until and user.locked_until > now:
        return _deny(db, "account is locked", actor=email, user=user)

    user.last_login = now
    mfa_ok = settings.OIDC_IDP_ENFORCES_MFA or not user_needs_mfa(user)
    raw, session = create_session(db, user, request, mfa_verified=mfa_ok)
    _audit(db, "AUTH_SSO_SUCCESS", user.email, f"Session {session.id} opened with role '{user.role}' via {settings.OIDC_PROVIDER_NAME} (sub {str(claims['sub'])[:40]}). MFA satisfied: {mfa_ok}.", user)
    db.commit()
    response = RedirectResponse("/", status_code=303)
    set_session_cookies(response, raw)
    response.delete_cookie(TXN_COOKIE, path="/")
    return response

import hmac
import re
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

import bcrypt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.config import PRIVILEGED_ROLES, settings
from app.database import get_db
from app.models import User, UserSession, naive_utc_now
from app.utils.crypto import decrypt_text, hmac_hex, sha256_hex
from app.utils.ratelimit import client_ip

# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------
ADMIN_ROLES = ["Super Admin", "Security Administrator"]
STAFF_ROLES = ["Super Admin", "Security Administrator", "SOC Analyst"]
ALL_ROLES = STAFF_ROLES + ["Employee"]

# ---------------------------------------------------------------------------
# Passwords: Argon2id for new hashes; bcrypt hashes still verify and are upgraded on login.
# ---------------------------------------------------------------------------
_hasher = PasswordHasher()
_DUMMY_HASH = _hasher.hash("timing-equaliser-for-unknown-accounts")

_COMMON_PASSWORDS = {
    "password", "password1", "password123", "123456789012", "qwertyuiop12", "letmein12345",
    "cybershield", "cybershield@2026!", "admin@cybershield2026!", "welcome12345",
}


def get_password_hash(password: str) -> str:
    return _hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        if hashed_password.startswith("$argon2"):
            return _hasher.verify(hashed_password, plain_password)
        if hashed_password.startswith("$2"):
            return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except (VerifyMismatchError, VerificationError, InvalidHashError, ValueError):
        return False
    return False


def password_needs_rehash(hashed_password: str) -> bool:
    return not hashed_password.startswith("$argon2") or _hasher.check_needs_rehash(hashed_password)


def burn_password_check() -> None:
    """Spend the same time as a real check when the account doesn't exist."""
    verify_password("x", _DUMMY_HASH)


def validate_password_strength(password: str, email: Optional[str] = None) -> None:
    if len(password) < settings.MIN_PASSWORD_LENGTH:
        raise HTTPException(status_code=422, detail=f"Password must be at least {settings.MIN_PASSWORD_LENGTH} characters.")
    if len(password) > 256:
        raise HTTPException(status_code=422, detail="Password is too long.")
    if password.lower() in _COMMON_PASSWORDS or len(set(password)) < 5:
        raise HTTPException(status_code=422, detail="Password is too common or too repetitive.")
    if email and email.split("@")[0].lower() in password.lower() and len(email.split("@")[0]) >= 4:
        raise HTTPException(status_code=422, detail="Password must not contain your account name.")


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_TOUCH_INTERVAL = timedelta(seconds=60)


@dataclass
class SessionContext:
    user: User
    session: UserSession
    raw_token: str


def csrf_token_for(raw_session_token: str) -> str:
    return hmac_hex("csrf-v1", raw_session_token)


def user_needs_mfa(user: User) -> bool:
    return bool(user.mfa_enabled) or (settings.mfa_enforced and user.role in PRIVILEGED_ROLES)


def create_session(db: Session, user: User, request: Request, mfa_verified: bool) -> Tuple[str, UserSession]:
    raw = secrets.token_urlsafe(32)
    now = naive_utc_now()
    row = UserSession(
        token_hash=sha256_hex(raw),
        user_id=user.id,
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(hours=settings.SESSION_ABSOLUTE_HOURS),
        mfa_verified=mfa_verified,
        ip_address=client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:255],
    )
    db.add(row)
    db.flush()
    return raw, row


def set_session_cookies(response: Response, raw_token: str) -> None:
    max_age = settings.SESSION_ABSOLUTE_HOURS * 3600
    response.set_cookie(
        settings.SESSION_COOKIE_NAME, raw_token, max_age=max_age, httponly=True,
        secure=settings.cookie_secure, samesite="strict", path="/",
    )
    # Readable by the SPA so it can echo the value in X-CSRF-Token. It's bound to the session via HMAC.
    response.set_cookie(
        settings.CSRF_COOKIE_NAME, csrf_token_for(raw_token), max_age=max_age, httponly=False,
        secure=settings.cookie_secure, samesite="strict", path="/",
    )


def clear_session_cookies(response: Response) -> None:
    response.delete_cookie(settings.SESSION_COOKIE_NAME, path="/")
    response.delete_cookie(settings.CSRF_COOKIE_NAME, path="/")


def revoke_user_sessions(db: Session, user_id: int, except_session_id: Optional[int] = None) -> int:
    now = naive_utc_now()
    q = db.query(UserSession).filter(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
    if except_session_id is not None:
        q = q.filter(UserSession.id != except_session_id)
    return q.update({UserSession.revoked_at: now}, synchronize_session=False)


def _unauthenticated(detail: str = "Authentication required. Please log in.") -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


def get_session_context(request: Request, db: Session = Depends(get_db)) -> Optional[SessionContext]:
    raw = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if not raw:
        return None
    row = db.query(UserSession).filter(UserSession.token_hash == sha256_hex(raw)).first()
    if row is None or row.revoked_at is not None:
        return None
    now = naive_utc_now()
    if row.expires_at <= now or row.last_seen_at + timedelta(minutes=settings.SESSION_IDLE_MINUTES) <= now:
        return None
    user = db.get(User, row.user_id)
    if user is None or not user.is_active:
        return None

    if request.method not in _SAFE_METHODS:
        supplied = request.headers.get("x-csrf-token", "")
        if not hmac.compare_digest(supplied, csrf_token_for(raw)):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token missing or invalid.")

    if now - row.last_seen_at > _TOUCH_INTERVAL:
        row.last_seen_at = now
        db.commit()
    return SessionContext(user=user, session=row, raw_token=raw)


def require_session(ctx: Optional[SessionContext] = Depends(get_session_context)) -> SessionContext:
    """Any live session, including one that still owes an MFA step or a password change."""
    if ctx is None:
        raise _unauthenticated()
    return ctx


def require_authenticated_user(ctx: SessionContext = Depends(require_session)) -> User:
    """A fully authenticated user: password + MFA (where required) and no forced password change."""
    if not ctx.session.mfa_verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="mfa_required")
    if ctx.user.must_change_password:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="password_change_required")
    return ctx.user


# Kept for modules that imported the old name.
get_current_user = require_authenticated_user


def require_roles(allowed_roles: List[str]):
    def role_checker(current_user: User = Depends(require_authenticated_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You don't have permission to do this.")
        return current_user
    return role_checker


# ---------------------------------------------------------------------------
# TOTP
# ---------------------------------------------------------------------------
def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=settings.MFA_ISSUER)


def check_totp(user: User, secret: str, code: str) -> bool:
    """Accepts the current and adjacent 30 s steps; a counter can only be used once."""
    code = (code or "").strip().replace(" ", "")
    if not re.fullmatch(r"\d{6}", code):
        return False
    totp = pyotp.TOTP(secret)
    now_counter = int(time.time() // 30)
    for counter in (now_counter, now_counter - 1, now_counter + 1):
        if hmac.compare_digest(totp.at(counter * 30), code):
            if user.totp_last_counter is not None and counter <= user.totp_last_counter:
                return False
            user.totp_last_counter = counter
            return True
    return False


def user_totp_secret(user: User) -> Optional[str]:
    return decrypt_text(user.totp_secret_enc) if user.totp_secret_enc else None

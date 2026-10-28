import secrets
from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.config import PRIVILEGED_ROLES, settings
from app.database import get_db
from app.models import AuditLog, Employee, PasswordResetToken, User, UserSession, naive_utc_now
from app.schemas import (
    ChangePasswordRequest, ForgotPasswordRequest, MfaCodeRequest, MfaDisableRequest, MfaSetupResponse,
    PasswordResetRequest, SessionStateResponse, UserLoginRequest, UserProfileResponse,
    UserProfileUpdateRequest,
)
from app.services.outbox import enqueue_email
from app.utils.auth import (
    SessionContext, burn_password_check, check_totp, clear_session_cookies, create_session,
    get_password_hash, new_totp_secret, password_needs_rehash, require_session, revoke_user_sessions,
    set_session_cookies, totp_uri, user_needs_mfa, user_totp_secret, validate_password_strength,
    verify_password,
)
from app.utils.crypto import decrypt_text, encrypt_text, sha256_hex
from app.utils.ratelimit import client_ip, enforce, limiter

router = APIRouter(prefix="/auth", tags=["Authentication & Access Control"])

_BAD_LOGIN = "Incorrect email or password."


def _audit(db: Session, action: str, actor: str, user: Optional[User], details: str) -> None:
    db.add(AuditLog(
        action=action, actor=actor, resource_type="User",
        resource_id=str(user.id) if user else actor, details=details,
    ))


def _mfa_state(ctx_user: User, session: UserSession) -> str:
    if session.mfa_verified:
        return "ok"
    return "verify" if ctx_user.mfa_enabled else "enroll"


def _state(user: User, session: UserSession) -> SessionStateResponse:
    return SessionStateResponse(
        user=UserProfileResponse.model_validate(user),
        mfa_state=_mfa_state(user, session),
        must_change_password=user.must_change_password,
    )


@router.post("/login", response_model=SessionStateResponse)
def login(payload: UserLoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    enforce(request, "login", settings.RATE_LIMIT_LOGIN_PER_MINUTE)
    email = payload.email.strip().lower()
    user = db.query(User).filter(User.email == email).first()
    now = naive_utc_now()

    if user is None:
        burn_password_check()
        _audit(db, "AUTH_LOGIN_FAILED", email, None, "Unknown account.")
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _BAD_LOGIN)

    if user.locked_until and user.locked_until > now:
        burn_password_check()
        _audit(db, "AUTH_LOGIN_BLOCKED", user.email, user, "Attempt while account is locked.")
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _BAD_LOGIN)

    if not verify_password(payload.password, user.hashed_password):
        user.failed_login_count += 1
        detail = f"Wrong password (failure {user.failed_login_count})."
        if user.failed_login_count >= settings.LOGIN_MAX_FAILURES:
            user.locked_until = now + timedelta(minutes=settings.LOGIN_LOCKOUT_MINUTES)
            user.failed_login_count = 0
            detail += f" Account locked for {settings.LOGIN_LOCKOUT_MINUTES} minutes."
        _audit(db, "AUTH_LOGIN_FAILED", user.email, user, detail)
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _BAD_LOGIN)

    if not user.is_active:
        _audit(db, "AUTH_LOGIN_BLOCKED", user.email, user, "Correct password on a deactivated account.")
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _BAD_LOGIN)

    if password_needs_rehash(user.hashed_password):
        user.hashed_password = get_password_hash(payload.password)
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login = now

    raw, session = create_session(db, user, request, mfa_verified=not user_needs_mfa(user))
    _audit(db, "AUTH_LOGIN_SUCCESS", user.email, user,
           f"Session {session.id} opened with role '{user.role}'. MFA state: {_mfa_state(user, session)}.")
    db.commit()
    set_session_cookies(response, raw)
    return _state(user, session)


@router.get("/me", response_model=SessionStateResponse)
def me(ctx: SessionContext = Depends(require_session)):
    return _state(ctx.user, ctx.session)


@router.post("/logout")
def logout(response: Response, ctx: SessionContext = Depends(require_session), db: Session = Depends(get_db)):
    ctx.session.revoked_at = naive_utc_now()
    _audit(db, "AUTH_LOGOUT", ctx.user.email, ctx.user, f"Session {ctx.session.id} revoked.")
    db.commit()
    clear_session_cookies(response)
    return {"status": "success"}


@router.post("/logout-all")
def logout_everywhere(response: Response, ctx: SessionContext = Depends(require_session), db: Session = Depends(get_db)):
    count = revoke_user_sessions(db, ctx.user.id)
    _audit(db, "AUTH_LOGOUT_ALL", ctx.user.email, ctx.user, f"{count} sessions revoked.")
    db.commit()
    clear_session_cookies(response)
    return {"status": "success", "sessions_revoked": count}


# ---------------------------------------------------------------------------
# MFA (TOTP)
# ---------------------------------------------------------------------------
@router.post("/mfa/setup", response_model=MfaSetupResponse)
def mfa_setup(ctx: SessionContext = Depends(require_session), db: Session = Depends(get_db)):
    user = ctx.user
    if user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA is already enabled. Disable it first to re-enrol.")
    secret = new_totp_secret()
    user.totp_pending_enc = encrypt_text(secret)
    db.commit()
    return MfaSetupResponse(secret=secret, otpauth_uri=totp_uri(secret, user.email))


@router.post("/mfa/enable", response_model=SessionStateResponse)
def mfa_enable(payload: MfaCodeRequest, request: Request, ctx: SessionContext = Depends(require_session),
               db: Session = Depends(get_db)):
    enforce(request, "mfa", 10)
    user = ctx.user
    if user.mfa_enabled or not user.totp_pending_enc:
        raise HTTPException(status.HTTP_409_CONFLICT, "No MFA enrolment in progress.")
    secret = decrypt_text(user.totp_pending_enc)
    if not check_totp(user, secret, payload.code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "That code is not valid.")
    user.totp_secret_enc = user.totp_pending_enc
    user.totp_pending_enc = None
    user.mfa_enabled = True
    ctx.session.mfa_verified = True
    revoke_user_sessions(db, user.id, except_session_id=ctx.session.id)
    _audit(db, "AUTH_MFA_ENABLED", user.email, user, "TOTP enabled. Other sessions revoked.")
    db.commit()
    return _state(user, ctx.session)


@router.post("/mfa/verify", response_model=SessionStateResponse)
def mfa_verify(payload: MfaCodeRequest, request: Request, ctx: SessionContext = Depends(require_session),
               db: Session = Depends(get_db)):
    user = ctx.user
    if not user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA is not enabled for this account.")
    if not limiter.hit(f"mfa-user:{user.id}", 5, 60):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts. Wait a minute.")
    if not check_totp(user, user_totp_secret(user), payload.code):
        user.failed_login_count += 1
        if user.failed_login_count >= settings.LOGIN_MAX_FAILURES:
            user.locked_until = naive_utc_now() + timedelta(minutes=settings.LOGIN_LOCKOUT_MINUTES)
            user.failed_login_count = 0
            ctx.session.revoked_at = naive_utc_now()
        _audit(db, "AUTH_MFA_FAILED", user.email, user, "Wrong TOTP code.")
        db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "That code is not valid.")
    user.failed_login_count = 0
    ctx.session.mfa_verified = True
    _audit(db, "AUTH_MFA_VERIFIED", user.email, user, f"Session {ctx.session.id} passed MFA.")
    db.commit()
    return _state(user, ctx.session)


@router.post("/mfa/disable")
def mfa_disable(payload: MfaDisableRequest, ctx: SessionContext = Depends(require_session),
                db: Session = Depends(get_db)):
    user = ctx.user
    if not ctx.session.mfa_verified or not user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA is not active on this session.")
    if user.role in PRIVILEGED_ROLES and settings.mfa_enforced:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "MFA is mandatory for your role.")
    if not verify_password(payload.password, user.hashed_password) or not check_totp(user, user_totp_secret(user), payload.code):
        _audit(db, "AUTH_MFA_DISABLE_FAILED", user.email, user, "Wrong password or code.")
        db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Password or code is not valid.")
    user.mfa_enabled = False
    user.totp_secret_enc = None
    user.totp_last_counter = None
    _audit(db, "AUTH_MFA_DISABLED", user.email, user, "TOTP disabled by the user.")
    db.commit()
    return {"status": "success"}


# ---------------------------------------------------------------------------
# Profile & password
# ---------------------------------------------------------------------------
@router.put("/profile", response_model=UserProfileResponse)
def update_profile(payload: UserProfileUpdateRequest, ctx: SessionContext = Depends(require_session),
                   db: Session = Depends(get_db)):
    user = ctx.user
    if not ctx.session.mfa_verified:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "mfa_required")
    if payload.full_name:
        user.full_name = payload.full_name.strip()
    if payload.department:
        user.department = payload.department.strip()
    emp = db.query(Employee).filter(Employee.company_email == user.email).first()
    if emp:
        if payload.full_name:
            emp.full_name = payload.full_name.strip()
        if payload.department:
            emp.department = payload.department.strip()
        if payload.phone_number:
            emp.phone_number = payload.phone_number.strip()
    _audit(db, "USER_PROFILE_UPDATED", user.email, user, "Profile fields updated.")
    db.commit()
    db.refresh(user)
    return UserProfileResponse.model_validate(user)


@router.post("/change-password")
def change_password(payload: ChangePasswordRequest, request: Request, ctx: SessionContext = Depends(require_session),
                    db: Session = Depends(get_db)):
    enforce(request, "change-password", 10)
    user = ctx.user
    if not ctx.session.mfa_verified:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "mfa_required")
    if not verify_password(payload.current_password, user.hashed_password):
        _audit(db, "PASSWORD_CHANGE_FAILED", user.email, user, "Current password was wrong.")
        db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect.")
    validate_password_strength(payload.new_password, user.email)
    if verify_password(payload.new_password, user.hashed_password):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "New password must differ from the current one.")
    user.hashed_password = get_password_hash(payload.new_password)
    user.password_changed_at = naive_utc_now()
    user.must_change_password = False
    revoked = revoke_user_sessions(db, user.id, except_session_id=ctx.session.id)
    _audit(db, "PASSWORD_CHANGED", user.email, user, f"Password changed; {revoked} other sessions revoked.")
    db.commit()
    return {"status": "success", "message": "Password changed. Other sessions were signed out."}


@router.post("/forgot-password")
def forgot_password(payload: ForgotPasswordRequest, request: Request, db: Session = Depends(get_db)):
    enforce(request, "forgot", 5)
    email = payload.email.strip().lower()
    user = db.query(User).filter(User.email == email, User.is_active.is_(True)).first()
    if user is not None and limiter.hit(f"forgot-user:{user.id}", 3, 3600):
        raw = secrets.token_urlsafe(32)
        db.add(PasswordResetToken(
            token_hash=sha256_hex(raw), user_id=user.id,
            expires_at=naive_utc_now() + timedelta(minutes=30),
        ))
        link = f"{settings.PUBLIC_BASE_URL.rstrip('/')}/?reset_token={raw}"
        enqueue_email(
            db, to=user.email, subject="Reset your CYBERSHIELD password",
            body=(f"Someone asked to reset the password for {user.email}.\n\n"
                  f"Open this link within 30 minutes to choose a new one:\n{link}\n\n"
                  "If this wasn't you, ignore this email; your password hasn't changed."),
            recipient_type="ACCOUNT", redact_after_send=True,
        )
        _audit(db, "PASSWORD_RESET_REQUESTED", user.email, user, "Reset link queued.")
        db.commit()
    return {"status": "success", "message": "If that account exists, a reset link has been emailed."}


@router.post("/reset-password")
def reset_password(payload: PasswordResetRequest, request: Request, db: Session = Depends(get_db)):
    enforce(request, "reset", 10)
    row = db.query(PasswordResetToken).filter(PasswordResetToken.token_hash == sha256_hex(payload.token)).first()
    now = naive_utc_now()
    if row is None or row.used_at is not None or row.expires_at <= now:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This reset link is invalid or has expired.")
    user = db.get(User, row.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This reset link is invalid or has expired.")
    validate_password_strength(payload.new_password, user.email)
    user.hashed_password = get_password_hash(payload.new_password)
    user.password_changed_at = now
    user.must_change_password = False
    user.failed_login_count = 0
    user.locked_until = None
    row.used_at = now
    revoke_user_sessions(db, user.id)
    _audit(db, "PASSWORD_RESET_COMPLETED", user.email, user, "Password reset with a one-time link; all sessions revoked.")
    db.commit()
    return {"status": "success", "message": "Password updated. Sign in with your new password."}

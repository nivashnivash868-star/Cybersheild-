import secrets
from datetime import timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import AuditLog, PasswordResetToken, User, naive_utc_now
from app.schemas import UserAdminUpdateRequest, UserCreateRequest, UserProfileResponse
from app.services.outbox import enqueue_email
from app.utils.auth import (
    ADMIN_ROLES, ALL_ROLES, STAFF_ROLES, get_password_hash, require_roles, revoke_user_sessions, validate_password_strength,
)
from app.utils.crypto import sha256_hex

router = APIRouter(prefix="/users", tags=["User Administration"])

# A Security Administrator manages analysts and staff. Only a Super Admin manages administrators.
MANAGEABLE_BY_ADMIN = {"SOC Analyst", "Employee"}
INVITE_HOURS = 72


class AnalystOut(BaseModel):
    id: int
    full_name: str
    email: str
    role: str


def _check_can_manage(actor: User, target_role: str) -> None:
    if actor.role != "Super Admin" and target_role not in MANAGEABLE_BY_ADMIN:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only a Super Admin can create or change administrator accounts.")


def _send_invite(db: Session, user: User) -> None:
    raw = secrets.token_urlsafe(32)
    db.add(PasswordResetToken(token_hash=sha256_hex(raw), user_id=user.id, expires_at=naive_utc_now() + timedelta(hours=INVITE_HOURS)))
    link = f"{settings.PUBLIC_BASE_URL.rstrip('/')}/?reset_token={raw}&activate=1"
    enqueue_email(
        db, to=user.email, subject="Activate your CYBERSHIELD AI account",
        body=(f"Hello {user.full_name},\n\nA CYBERSHIELD AI account with the role '{user.role}' was created for you.\n\n"
              f"Open this link within {INVITE_HOURS} hours to choose your password and activate it:\n{link}\n\n"
              "If you weren't expecting this, ignore the email and tell your security administrator."),
        recipient_type="ACCOUNT", redact_after_send=True)


@router.get("/analysts", response_model=List[AnalystOut])
def assignable_staff(db: Session = Depends(get_db), _: User = Depends(require_roles(STAFF_ROLES))):
    """Active people an incident can be assigned to. Name and email only."""
    rows = db.query(User).filter(User.is_active.is_(True), User.role.in_(STAFF_ROLES)).order_by(User.full_name).all()
    return [AnalystOut(id=u.id, full_name=u.full_name, email=u.email, role=u.role) for u in rows]


@router.get("", response_model=List[UserProfileResponse])
def list_users(db: Session = Depends(get_db), _: User = Depends(require_roles(ADMIN_ROLES))):
    return db.query(User).order_by(User.id).all()


@router.post("", response_model=UserProfileResponse, status_code=status.HTTP_201_CREATED)
def create_user(payload: UserCreateRequest, db: Session = Depends(get_db), admin: User = Depends(require_roles(ADMIN_ROLES))):
    email = payload.email.strip().lower()
    if payload.role not in ALL_ROLES:
        raise HTTPException(422, f"Role must be one of {ALL_ROLES}.")
    _check_can_manage(admin, payload.role)
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(409, "A user with that email already exists.")
    invite = bool(payload.send_invite) or (payload.send_invite is None and not payload.temporary_password)
    if invite:
        password = secrets.token_urlsafe(32)               # nobody knows it: the person chooses their own at activation
    else:
        password = payload.temporary_password
        validate_password_strength(password, email)
    user = User(
        email=email, full_name=payload.full_name.strip(), role=payload.role, department=payload.department,
        employee_id=payload.employee_id, hashed_password=get_password_hash(password),
        must_change_password=True, password_changed_at=naive_utc_now(),
    )
    db.add(user)
    db.flush()
    if invite:
        _send_invite(db, user)
    db.add(AuditLog(action="USER_CREATED", actor=admin.email, resource_type="User", resource_id=str(user.id),
                    details=f"Created {email} with role '{payload.role}'; "
                            + ("activation link emailed." if invite else "temporary password set, change required at first login.")))
    db.commit()
    return user


@router.post("/{user_id}/resend-invite")
def resend_invite(user_id: int, db: Session = Depends(get_db), admin: User = Depends(require_roles(ADMIN_ROLES))):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found.")
    _check_can_manage(admin, user.role)
    if user.last_login is not None:
        raise HTTPException(409, "This person has already signed in. Use the password reset instead.")
    _send_invite(db, user)
    db.add(AuditLog(action="USER_INVITE_RESENT", actor=admin.email, resource_type="User", resource_id=str(user.id), details=f"Activation link re-sent to {user.email}."))
    db.commit()
    return {"status": "success"}


@router.patch("/{user_id}", response_model=UserProfileResponse)
def update_user(user_id: int, payload: UserAdminUpdateRequest, db: Session = Depends(get_db), admin: User = Depends(require_roles(ADMIN_ROLES))):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found.")
    if user.id == admin.id:
        raise HTTPException(409, "You can't change your own role or deactivate yourself.")
    _check_can_manage(admin, user.role)
    changes = []
    if payload.role is not None:
        if payload.role not in ALL_ROLES:
            raise HTTPException(422, f"Role must be one of {ALL_ROLES}.")
        _check_can_manage(admin, payload.role)
        changes.append(f"role {user.role} -> {payload.role}")
        user.role = payload.role
    if payload.is_active is not None:
        changes.append(f"active {user.is_active} -> {payload.is_active}")
        user.is_active = payload.is_active
    if changes:
        revoke_user_sessions(db, user.id)  # privileges changed: force a fresh login
        db.add(AuditLog(action="USER_UPDATED", actor=admin.email, resource_type="User", resource_id=str(user.id),
                        details="; ".join(changes) + ". Sessions revoked."))
    db.commit()
    db.refresh(user)
    return user


@router.post("/{user_id}/reset-mfa")
def reset_mfa(user_id: int, db: Session = Depends(get_db), admin: User = Depends(require_roles(ADMIN_ROLES))):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found.")
    _check_can_manage(admin, user.role)
    user.mfa_enabled, user.totp_secret_enc, user.totp_pending_enc, user.totp_last_counter = False, None, None, None
    revoke_user_sessions(db, user.id)
    db.add(AuditLog(action="USER_MFA_RESET", actor=admin.email, resource_type="User", resource_id=str(user.id),
                    details="MFA enrolment cleared; the user must enrol again at next login."))
    db.commit()
    return {"status": "success"}


@router.post("/{user_id}/revoke-sessions")
def revoke_sessions(user_id: int, db: Session = Depends(get_db), admin: User = Depends(require_roles(ADMIN_ROLES))):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found.")
    _check_can_manage(admin, user.role)
    count = revoke_user_sessions(db, user_id)
    db.add(AuditLog(action="USER_SESSIONS_REVOKED", actor=admin.email, resource_type="User", resource_id=str(user_id),
                    details=f"{count} sessions revoked."))
    db.commit()
    return {"status": "success", "sessions_revoked": count}

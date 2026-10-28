from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import AuditLog, User, naive_utc_now
from app.schemas import UserAdminUpdateRequest, UserCreateRequest, UserProfileResponse
from app.utils.auth import (
    ALL_ROLES, get_password_hash, require_roles, revoke_user_sessions, validate_password_strength,
)

router = APIRouter(prefix="/users", tags=["User Administration"])
SUPER = ["Super Admin"]


@router.get("", response_model=List[UserProfileResponse])
def list_users(db: Session = Depends(get_db), _: User = Depends(require_roles(SUPER))):
    return db.query(User).order_by(User.id).all()


@router.post("", response_model=UserProfileResponse, status_code=status.HTTP_201_CREATED)
def create_user(payload: UserCreateRequest, db: Session = Depends(get_db),
                admin: User = Depends(require_roles(SUPER))):
    email = payload.email.strip().lower()
    if payload.role not in ALL_ROLES:
        raise HTTPException(422, f"Role must be one of {ALL_ROLES}.")
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(409, "A user with that email already exists.")
    validate_password_strength(payload.temporary_password, email)
    user = User(
        email=email, full_name=payload.full_name.strip(), role=payload.role, department=payload.department,
        employee_id=payload.employee_id, hashed_password=get_password_hash(payload.temporary_password),
        must_change_password=True, password_changed_at=naive_utc_now(),
    )
    db.add(user)
    db.flush()
    db.add(AuditLog(action="USER_CREATED", actor=admin.email, resource_type="User", resource_id=str(user.id),
                    details=f"Created {email} with role '{payload.role}'; password change required at first login."))
    db.commit()
    return user


@router.patch("/{user_id}", response_model=UserProfileResponse)
def update_user(user_id: int, payload: UserAdminUpdateRequest, db: Session = Depends(get_db),
                admin: User = Depends(require_roles(SUPER))):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found.")
    if user.id == admin.id:
        raise HTTPException(409, "You can't change your own role or deactivate yourself.")
    changes = []
    if payload.role is not None:
        if payload.role not in ALL_ROLES:
            raise HTTPException(422, f"Role must be one of {ALL_ROLES}.")
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
def reset_mfa(user_id: int, db: Session = Depends(get_db), admin: User = Depends(require_roles(SUPER))):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found.")
    user.mfa_enabled, user.totp_secret_enc, user.totp_pending_enc, user.totp_last_counter = False, None, None, None
    revoke_user_sessions(db, user.id)
    db.add(AuditLog(action="USER_MFA_RESET", actor=admin.email, resource_type="User", resource_id=str(user.id),
                    details="MFA enrolment cleared; the user must enrol again at next login."))
    db.commit()
    return {"status": "success"}


@router.post("/{user_id}/revoke-sessions")
def revoke_sessions(user_id: int, db: Session = Depends(get_db), admin: User = Depends(require_roles(SUPER))):
    if not db.get(User, user_id):
        raise HTTPException(404, "User not found.")
    count = revoke_user_sessions(db, user_id)
    db.add(AuditLog(action="USER_SESSIONS_REVOKED", actor=admin.email, resource_type="User", resource_id=str(user_id),
                    details=f"{count} sessions revoked."))
    db.commit()
    return {"status": "success", "sessions_revoked": count}

"""First-run setup: create the initial Super Admin from the environment when no users exist."""
import logging
from sqlalchemy.orm import Session
from app.config import settings
from app.models import AuditLog, User, naive_utc_now
from app.utils.auth import get_password_hash, validate_password_strength

logger = logging.getLogger("cybershield.bootstrap")


def bootstrap_admin(db: Session) -> None:
    if db.query(User).count() > 0:
        return
    email, password = settings.BOOTSTRAP_ADMIN_EMAIL, settings.BOOTSTRAP_ADMIN_PASSWORD
    if not email or not password:
        logger.warning("No users exist and BOOTSTRAP_ADMIN_EMAIL / BOOTSTRAP_ADMIN_PASSWORD are not set: nobody can log in.")
        return
    validate_password_strength(password, email)
    user = User(
        email=email.strip().lower(), full_name=settings.BOOTSTRAP_ADMIN_NAME, role="Super Admin",
        hashed_password=get_password_hash(password), must_change_password=True,
        password_changed_at=naive_utc_now(), department="Security",
    )
    db.add(user)
    db.flush()
    db.add(AuditLog(action="BOOTSTRAP_ADMIN_CREATED", actor="System", resource_type="User", resource_id=str(user.id),
                    details=f"Initial Super Admin {user.email} created from environment; password change required."))
    db.commit()
    logger.info("Created initial Super Admin %s (password change required at first login).", user.email)

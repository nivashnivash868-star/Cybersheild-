import logging
import secrets
from typing import List, Optional
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("cybershield.config")

PRIVILEGED_ROLES = ("Super Admin", "Security Administrator", "SOC Analyst")


class Settings(BaseSettings):
    PROJECT_NAME: str = "CYBERSHIELD AI"
    API_V1_PREFIX: str = "/api/v1"
    ENVIRONMENT: str = "development"  # development | staging | production

    # Demo data (fabricated incidents, employees, known demo passwords).
    # Never allowed in production.
    DEMO_MODE: bool = False

    # Database: PostgreSQL via DATABASE_URL / SUPABASE_DATABASE_URL, SQLite only outside production.
    SUPABASE_DATABASE_URL: Optional[str] = None
    DATABASE_URL: Optional[str] = None
    SQLITE_URL: Optional[str] = None  # development/tests only, e.g. sqlite:///./dev.db

    # Secret used to HMAC the audit chain, CSRF tokens and to encrypt TOTP secrets.
    # Required in production; a random per-process value is generated in development.
    SECRET_KEY: Optional[str] = None

    # Sessions
    SESSION_IDLE_MINUTES: int = 30
    SESSION_ABSOLUTE_HOURS: int = 12
    SESSION_COOKIE_NAME: str = "cs_session"
    CSRF_COOKIE_NAME: str = "cs_csrf"
    COOKIE_SECURE: Optional[bool] = None  # defaults to True outside development

    # Login protection
    LOGIN_MAX_FAILURES: int = 5
    LOGIN_LOCKOUT_MINUTES: int = 15
    RATE_LIMIT_LOGIN_PER_MINUTE: int = 10
    MIN_PASSWORD_LENGTH: int = 12

    # MFA (TOTP). Enforced for privileged roles outside development unless overridden.
    MFA_ENFORCED: Optional[bool] = None
    MFA_ISSUER: str = "CYBERSHIELD AI"

    # First administrator, created only when the users table is empty.
    BOOTSTRAP_ADMIN_EMAIL: Optional[str] = None
    BOOTSTRAP_ADMIN_PASSWORD: Optional[str] = None
    BOOTSTRAP_ADMIN_NAME: str = "Security Administrator"

    # Public URL of the app (used in password reset links)
    PUBLIC_BASE_URL: str = "http://localhost:8000"

    # CORS: the unified build is same-origin and needs none. Add origins for a separate dev frontend.
    CORS_ORIGINS: List[str] = []

    # Alert transports. Email: SMTP. SMS: Twilio.
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_FROM: Optional[str] = None
    SMTP_SECURITY: str = "starttls"  # starttls | ssl | none
    TWILIO_ACCOUNT_SID: Optional[str] = None
    TWILIO_AUTH_TOKEN: Optional[str] = None
    TWILIO_FROM_NUMBER: Optional[str] = None
    ALERT_SOC_EMAILS: List[str] = []
    ALERT_SOC_SMS: List[str] = []
    ALERT_MAX_ATTEMPTS: int = 5
    OUTBOX_WORKER_ENABLED: bool = True

    # Blocklist feed
    BLOCKLIST_DEFAULT_TTL_HOURS: int = 24
    BLOCKLIST_MAX_TTL_HOURS: int = 24 * 30
    BLOCKLIST_PROTECTED: List[str] = []  # extra CIDRs / domains that may never be blocked

    # External reputation integrations (keys only; clients are not implemented yet)
    VIRUSTOTAL_API_KEY: Optional[str] = None
    PHISHTANK_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"

    @property
    def is_development(self) -> bool:
        return self.ENVIRONMENT.lower() == "development"

    @property
    def cookie_secure(self) -> bool:
        if self.COOKIE_SECURE is not None:
            return self.COOKIE_SECURE
        return not self.is_development

    @property
    def mfa_enforced(self) -> bool:
        if self.MFA_ENFORCED is not None:
            return self.MFA_ENFORCED
        return not self.is_development

    @property
    def database_url(self) -> Optional[str]:
        return self.SUPABASE_DATABASE_URL or self.DATABASE_URL

    @model_validator(mode="after")
    def _validate(self):
        if not self.SECRET_KEY:
            if self.is_production or not self.is_development:
                raise ValueError("SECRET_KEY must be set when ENVIRONMENT is not 'development'.")
            self.SECRET_KEY = secrets.token_urlsafe(48)
            logger.warning("SECRET_KEY not set; using a random per-process key (sessions reset on restart).")
        elif len(self.SECRET_KEY) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters.")
        if self.is_production and self.DEMO_MODE:
            raise ValueError("DEMO_MODE cannot be enabled when ENVIRONMENT is 'production'.")
        if self.is_production and not self.database_url:
            raise ValueError("DATABASE_URL (PostgreSQL) is required when ENVIRONMENT is 'production'.")
        return self


settings = Settings()

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

    # Single sign-on (OpenID Connect, authorization-code flow with PKCE). Users must already exist: nothing is auto-created.
    OIDC_ISSUER: Optional[str] = None                 # e.g. https://login.microsoftonline.com/<tenant>/v2.0 or https://<org>.okta.com
    OIDC_CLIENT_ID: Optional[str] = None
    OIDC_CLIENT_SECRET: Optional[str] = None
    OIDC_SCOPES: str = "openid email profile"
    OIDC_REDIRECT_URI: Optional[str] = None           # default: {PUBLIC_BASE_URL}/api/v1/auth/sso/callback
    OIDC_PROVIDER_NAME: str = "Single sign-on"
    OIDC_EMAIL_CLAIM: str = "email"
    OIDC_ALLOWED_EMAIL_DOMAINS: str = ""              # optional comma-separated allow-list
    OIDC_IDP_ENFORCES_MFA: bool = False               # True: an SSO sign-in counts as two-step verified (the IdP does MFA)

    # Response connector: approved account-disable / host-isolation requests are POSTed (HMAC-signed) to your automation
    # (SOAR playbook, IdP script, EDR wrapper). See docs/response-connector.md.
    RESPONSE_WEBHOOK_URL: Optional[str] = None
    RESPONSE_WEBHOOK_SECRET: Optional[str] = None            # at least 32 characters; shared with the receiver
    RESPONSE_WEBHOOK_ACTIONS: str = "DISABLE_ACCOUNT,HOST_ISOLATION"
    RESPONSE_WEBHOOK_TIMEOUT_SECONDS: int = 10
    RESPONSE_WEBHOOK_MAX_ATTEMPTS: int = 5
    RESPONSE_WEBHOOK_ACK_MINUTES: int = 60                   # a sent job with no report back after this is shown as UNCONFIRMED

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

    # Zetaris: federated queries over your log/data sources (https://api.saas.enterprise.zetaris.com/redoc/)
    ZETARIS_BASE_URL: str = "https://api.saas.enterprise.zetaris.com"
    ZETARIS_ORG_ID: Optional[int] = None
    ZETARIS_API_KEY: Optional[str] = None       # Bearer token for the query APIs
    ZETARIS_USERNAME: Optional[str] = None      # optional: log in for an idToken when no API key is set
    ZETARIS_PASSWORD: Optional[str] = None
    ZETARIS_INGEST_ENABLED: bool = True
    ZETARIS_INGEST_INTERVAL_SECONDS: int = 60
    ZETARIS_INITIAL_LOOKBACK_HOURS: int = 72    # how far back the first ingest looks
    ZETARIS_BRUTE_FORCE_THRESHOLD: int = 5      # failed logins per (ip, user) in one pass
    ZETARIS_LOW_SIGNAL_THRESHOLD: int = 3       # smaller bursts become Low alerts for L1 to close (0 disables)
    ZETARIS_DATA_IS_SYNTHETIC: bool = False     # mark everything read from Zetaris as SIMULATED in the UI
    ZETARIS_BATCH_ROWS: int = 2000
    ZETARIS_MAX_BATCHES_PER_PASS: int = 10
    # The Isolation Forest is trained on a tiny fixed sample and flags ordinary traffic; its Medium "statistical
    # outlier" alerts are left out of ingestion unless you opt in. Rule-based detections (scans, exfiltration, ...) stay.
    ZETARIS_NETWORK_INCLUDE_ML_OUTLIERS: bool = False
    NETWORK_TRUSTED_DESTINATIONS: str = ""          # comma-separated IPs/CIDRs the network rules ignore (backup targets, update servers)
    NETWORK_BASELINE_CSV: Optional[str] = None     # CSV of the organisation's ordinary flows (dst_port,bytes,packets) to fit the anomaly model
    ZETARIS_INTERNAL_FAILURE_MULTIPLIER: int = 4  # typos from private addresses need this many times more failures
    # Table names as Zetaris sees them (database.table). Column names default to the schema in
    # docs/zetaris-schema.md and can be overridden with ZETARIS_COLUMNS='{"auth": {"event_time": "ts"}}'.
    ZETARIS_TABLE_AUTH: Optional[str] = None
    ZETARIS_TABLE_NETWORK: Optional[str] = None
    ZETARIS_TABLE_EMAIL: Optional[str] = None
    ZETARIS_COLUMNS: dict = {}
    # How the auth table spells outcomes. Compared case-insensitively. Windows logs use 4625 / 4624, many apps use FAILED / OK.
    ZETARIS_AUTH_FAILURE_VALUES: str = "FAILURE,FAILED,FAIL"
    ZETARIS_AUTH_SUCCESS_VALUES: str = "SUCCESS,SUCCEEDED,OK"

    # External reputation integrations (clients: services/threat_intel.py)
    VIRUSTOTAL_API_KEY: Optional[str] = None
    FILE_HASH_FEED_PATH: Optional[str] = None      # text file of known-bad md5/sha256 hashes (see file_analyzer.load_hash_feed)
    PHISHTANK_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    # Threat-intelligence lookups (VirusTotal v3, AbuseIPDB v2). Only public indicators are sent: IPs, domains and file hashes.
    # File contents and internal addresses never leave; full URLs are not sent unless TI_SEND_FULL_URLS is true.
    TI_LOOKUPS_ENABLED: bool = True
    TI_CACHE_HOURS: int = 24
    TI_VT_PER_MINUTE: int = 4                  # the free VirusTotal tier allows 4 requests a minute, 500 a day
    TI_VT_PER_DAY: int = 500
    TI_ABUSEIPDB_PER_DAY: int = 1000
    TI_SEND_FULL_URLS: bool = False

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
    def zetaris_configured(self) -> bool:
        has_auth = bool(self.ZETARIS_API_KEY or (self.ZETARIS_USERNAME and self.ZETARIS_PASSWORD))
        return bool(self.ZETARIS_ORG_ID is not None and has_auth)

    @property
    def oidc_configured(self) -> bool:
        return bool(self.OIDC_ISSUER and self.OIDC_CLIENT_ID)

    @property
    def oidc_redirect_uri(self) -> str:
        return self.OIDC_REDIRECT_URI or f"{self.PUBLIC_BASE_URL.rstrip('/')}{self.API_V1_PREFIX}/auth/sso/callback"

    @property
    def response_connector_configured(self) -> bool:
        return bool(self.RESPONSE_WEBHOOK_URL and self.RESPONSE_WEBHOOK_SECRET and len(self.RESPONSE_WEBHOOK_SECRET) >= 32)

    @property
    def response_actions(self) -> set:
        return {a.strip().upper() for a in self.RESPONSE_WEBHOOK_ACTIONS.split(",") if a.strip()}

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

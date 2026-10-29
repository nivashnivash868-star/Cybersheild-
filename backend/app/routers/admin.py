from datetime import timedelta
from typing import Any, Dict, List

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import (
    AuditLog, DecisionRequest, FeedToken, IngestState, Incident, NotificationDelivery, SecurityEvent, User, UserSession,
    naive_utc_now,
)
from app.services import integration_tests, response_executor, settings_store, threat_intel
from app.services.outbox import email_configured, sms_configured
from app.utils.auth import ADMIN_ROLES, require_roles
from app.utils.ratelimit import limiter

router = APIRouter(prefix="/admin", tags=["Security Administrator"])

# What each role can do. Roles are fixed by the platform; this is the reference administrators audit against.
PERMISSIONS: List[Dict[str, Any]] = [
    {"capability": "View dashboards, alerts and incidents", "Super Admin": True, "Security Administrator": True, "SOC Analyst": True, "Employee": False},
    {"capability": "Acknowledge alerts, add notes, assign cases", "Super Admin": True, "Security Administrator": True, "SOC Analyst": True, "Employee": False},
    {"capability": "Confirm or dismiss an incident", "Super Admin": True, "Security Administrator": True, "SOC Analyst": True, "Employee": False},
    {"capability": "Approve blocking an IP address or domain", "Super Admin": True, "Security Administrator": True, "SOC Analyst": True, "Employee": False},
    {"capability": "Close a Critical incident", "Super Admin": True, "Security Administrator": True, "SOC Analyst": "Request, administrator approves", "Employee": False},
    {"capability": "Disable a user account / isolate a host", "Super Admin": True, "Security Administrator": True, "SOC Analyst": "Request, administrator approves", "Employee": False},
    {"capability": "Create alert rules and change thresholds", "Super Admin": True, "Security Administrator": True, "SOC Analyst": "Request, administrator approves", "Employee": False},
    {"capability": "Create and manage analyst accounts", "Super Admin": True, "Security Administrator": True, "SOC Analyst": False, "Employee": False},
    {"capability": "Create and manage administrator accounts", "Super Admin": True, "Security Administrator": False, "SOC Analyst": False, "Employee": False},
    {"capability": "Read the audit log", "Super Admin": True, "Security Administrator": True, "SOC Analyst": False, "Employee": False},
    {"capability": "Verify audit-log integrity", "Super Admin": True, "Security Administrator": False, "SOC Analyst": False, "Employee": False},
    {"capability": "Firewall feeds and integrations", "Super Admin": True, "Security Administrator": True, "SOC Analyst": False, "Employee": False},
]


@router.get("/overview")
def overview(db: Session = Depends(get_db), _: User = Depends(require_roles(ADMIN_ROLES))):
    now = naive_utc_now()
    day = now - timedelta(hours=24)
    open_inc = Incident.status.notin_(("Resolved", "False Positive"))

    analysts = db.query(User).filter(User.role == "SOC Analyst")
    online = db.query(func.count(func.distinct(UserSession.user_id))).join(User, User.id == UserSession.user_id).filter(
        User.role == "SOC Analyst", UserSession.revoked_at.is_(None), UserSession.expires_at > now,
        UserSession.last_seen_at > now - timedelta(minutes=settings.SESSION_IDLE_MINUTES)).scalar()

    # --- health -----------------------------------------------------------------------------------------------------
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False
    hb_value, hb_at = settings_store.get_fact(db, "worker_heartbeat")
    worker_age = int((now - hb_at).total_seconds()) if hb_at else None
    z = db.query(IngestState).all()
    z_ok = [s for s in z if s.last_status == "OK"]
    z_err = [s for s in z if s.last_status == "ERROR"]
    queued = db.query(NotificationDelivery).filter(NotificationDelivery.delivery_status.in_(("QUEUED", "SENDING"))).count()
    failed = db.query(NotificationDelivery).filter(NotificationDelivery.delivery_status.in_(("FAILED", "NOT_CONFIGURED"))).count()
    consumers = db.query(FeedToken).filter(FeedToken.revoked_at.is_(None)).all()

    def level(ok: bool, warn: bool = False) -> str:
        return "ok" if ok else ("warn" if warn else "down")

    health = [
        {"name": "Database", "status": level(db_ok), "detail": "PostgreSQL" if settings.database_url else "SQLite (development)"},
        {"name": "Automation worker", "status": level(worker_age is not None and worker_age < 60, warn=worker_age is None),
         "detail": "No heartbeat yet" if worker_age is None else f"Last cycle {worker_age}s ago"},
        {"name": "Email alerts", "status": level(email_configured(), warn=True), "detail": "SMTP configured" if email_configured() else "Not configured"},
        {"name": "SMS alerts", "status": level(sms_configured(), warn=True), "detail": "Twilio configured" if sms_configured() else "Not configured"},
        {"name": "Alert delivery", "status": level(failed == 0, warn=True), "detail": f"{queued} queued, {failed} failed or unsent"},
        {"name": "Zetaris data sources", "status": level(settings.zetaris_configured and not z_err, warn=not settings.zetaris_configured),
         "detail": ("Not configured" if not settings.zetaris_configured else f"{len(z_ok)} source(s) healthy" + (f", {len(z_err)} failing" if z_err else ""))},
        {"name": "Firewall feeds", "status": level(any(c.last_fetched_at for c in consumers), warn=True),
         "detail": f"{sum(1 for c in consumers if c.last_fetched_at)} of {len(consumers)} consumers have pulled"},
    ]
    simulated = db.query(SecurityEvent).filter(SecurityEvent.is_simulated.is_(True)).count()
    total_events = db.query(SecurityEvent).count()
    return {
        "alerts": {
            "total": total_events, "last_24h": db.query(SecurityEvent).filter(SecurityEvent.timestamp >= day).count(),
            "critical_open": db.query(SecurityEvent).filter(SecurityEvent.severity == "Critical", SecurityEvent.analysis_status != "Closed").count(),
            "unacknowledged_high": db.query(SecurityEvent).filter(SecurityEvent.severity.in_(("Critical", "High")),
                                                                  SecurityEvent.is_acknowledged.is_(False), SecurityEvent.analysis_status != "Closed").count()},
        "incidents": {
            "critical": db.query(Incident).filter(Incident.severity == "Critical", open_inc).count(),
            "unresolved": db.query(Incident).filter(open_inc).count(),
            "awaiting_approval": db.query(DecisionRequest).filter(DecisionRequest.status == "PENDING").count(),
            "awaiting_admin": db.query(DecisionRequest).filter(DecisionRequest.status == "PENDING", DecisionRequest.kind.in_(
                ("DISABLE_ACCOUNT", "HOST_ISOLATION", "INCIDENT_CLOSURE", "DETECTION_RULE"))).count()},
        "analysts": {"total": analysts.count(), "active": analysts.filter(User.is_active.is_(True)).count(), "online_now": online or 0,
                     "never_signed_in": analysts.filter(User.last_login.is_(None)).count(),
                     "without_mfa": analysts.filter(User.is_active.is_(True), User.mfa_enabled.is_(False)).count()},
        "health": health,
        "data": {"simulated_events": simulated, "total_events": total_events,
                 "all_simulated": total_events > 0 and simulated == total_events, "any_simulated": simulated > 0},
        "audit_entries": db.query(AuditLog).count(),
    }


@router.get("/settings")
def get_settings(db: Session = Depends(get_db), _: User = Depends(require_roles(ADMIN_ROLES))):
    return settings_store.all_settings(db)


@router.put("/settings")
def put_settings(changes: Dict[str, Any] = Body(...), db: Session = Depends(get_db), admin: User = Depends(require_roles(ADMIN_ROLES))):
    settings_store.update(db, changes, admin.email)
    db.commit()
    return settings_store.all_settings(db)


@router.get("/permissions")
def permissions(_: User = Depends(require_roles(ADMIN_ROLES))):
    return PERMISSIONS


@router.get("/integrations")
def integrations(db: Session = Depends(get_db), _: User = Depends(require_roles(ADMIN_ROLES))):
    """Where alerts and data come from, and whether each is really connected. Secrets are set in the server environment.
    `configured` means settings are present; use the Test button (POST /admin/integrations/{key}/test) for a real call."""
    ti = {p["provider"]: p for p in threat_intel.provider_status(db)}
    return [
        {"key": "email", "name": "Email (SMTP)", "configured": email_configured(), "detail": settings.SMTP_HOST or "SMTP_HOST is not set", "recipients": settings.ALERT_SOC_EMAILS},
        {"key": "sms", "name": "SMS (Twilio)", "configured": sms_configured(), "detail": "Twilio account set" if sms_configured() else "TWILIO_* are not set", "recipients": settings.ALERT_SOC_SMS},
        {"key": "zetaris", "name": "Zetaris data sources", "configured": settings.zetaris_configured,
         "detail": settings.ZETARIS_BASE_URL if settings.zetaris_configured else "ZETARIS_ORG_ID / ZETARIS_API_KEY are not set",
         "synthetic": settings.ZETARIS_DATA_IS_SYNTHETIC},
        {"key": None, "name": "Firewall / DNS blocklist feeds", "configured": db.query(FeedToken).filter(FeedToken.revoked_at.is_(None)).count() > 0,
         "detail": "Credentials are managed on the Blocklist page"},
        {"key": "virustotal", "name": "Threat intelligence: VirusTotal", "configured": ti["virustotal"]["state"] in ("connected", "unverified", "error"),
         "detail": ti["virustotal"]["detail"], "state": ti["virustotal"]["state"]},
        {"key": "abuseipdb", "name": "Threat intelligence: AbuseIPDB", "configured": ti["abuseipdb"]["state"] in ("connected", "unverified", "error"),
         "detail": ti["abuseipdb"]["detail"], "state": ti["abuseipdb"]["state"]},
        {"key": "response", "name": "Response connector (identity provider / EDR)", "configured": response_executor.configured(),
         "detail": (f"Approved {', '.join(sorted(settings.response_actions))} requests are sent, signed, to {settings.RESPONSE_WEBHOOK_URL}; "
                    "an action counts as done only when your automation confirms it") if response_executor.configured()
                   else "RESPONSE_WEBHOOK_URL / RESPONSE_WEBHOOK_SECRET (32+ characters) are not set: disabling an account affects CyberShield only and host isolation is carried out by a responder"},
        {"key": "sso", "name": "Single sign-on (OpenID Connect)", "configured": settings.oidc_configured,
         "detail": f"{settings.OIDC_PROVIDER_NAME} via {settings.OIDC_ISSUER}" if settings.oidc_configured else "OIDC_ISSUER / OIDC_CLIENT_ID are not set: staff sign in with passwords"},
    ]


@router.post("/integrations/{key}/test")
def test_integration(key: str, payload: Dict[str, Any] = Body(default={}), db: Session = Depends(get_db),
                     user: User = Depends(require_roles(ADMIN_ROLES))):
    """Make a real call to one integration and say what happened. Email/SMS test messages go to the address in `to`
    (email defaults to the administrator's own address; SMS must be given a number)."""
    if key not in integration_tests.KEYS:
        raise HTTPException(404, "Unknown integration.")
    if not limiter.hit(f"integration-test:{user.id}", 10, 60):
        raise HTTPException(429, "Too many tests; wait a minute.")
    to = payload.get("to") if isinstance(payload.get("to"), str) else None
    result = integration_tests.run(db, key, user, to)
    db.add(AuditLog(action="INTEGRATION_TEST", actor=user.email, resource_type="Integration", resource_id=key,
                    details=f"ok={result['ok']}: {result['detail']}"[:480]))
    db.commit()
    return {"key": key, **result}

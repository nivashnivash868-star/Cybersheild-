"""Administrator-triggered connection tests. Each makes a real call to the integration and reports what happened, so a
green result means the path works now, not that a key is present."""
import logging
import time
from typing import Any, Callable, Dict, Optional

from sqlalchemy.orm import Session

from app.config import settings
from app.models import User
from app.services import oidc, outbox, response_executor, threat_intel
from app.services.zetaris import ZetarisError, get_client

logger = logging.getLogger("cybershield.integration_tests")
KEYS = ("email", "sms", "zetaris", "virustotal", "abuseipdb", "response", "sso")


def _timed(fn: Callable[[], Dict[str, Any]]) -> Dict[str, Any]:
    start = time.monotonic()
    out = fn()
    out["latency_ms"] = int((time.monotonic() - start) * 1000)
    return out


def _email(user: User, to: Optional[str]) -> Dict[str, Any]:
    if not outbox.email_configured():
        return {"ok": False, "detail": "SMTP_HOST / SMTP_FROM are not set."}
    to = (to or user.email).strip()
    try:
        outbox.send_email(to, "CyberShield connection test", f"This message was requested by {user.email} to check that CyberShield can send email. No action is needed.")
    except outbox.PermanentDeliveryError as exc:
        return {"ok": False, "detail": str(exc)}
    except Exception as exc:  # noqa: BLE001 - network / TLS / auth errors
        return {"ok": False, "detail": f"Could not send ({type(exc).__name__})."}
    return {"ok": True, "detail": f"The mail server accepted a message for {to}. Check that it arrives; 'accepted' is not 'delivered'."}


def _sms(user: User, to: Optional[str]) -> Dict[str, Any]:
    if not outbox.sms_configured():
        return {"ok": False, "detail": "TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN / TWILIO_FROM_NUMBER are not set."}
    if not to:
        return {"ok": False, "detail": "Give the phone number to text (+15551234567); a test SMS costs money so it is never sent by default."}
    try:
        sid = outbox.send_sms(to.strip(), "CyberShield connection test. No action is needed.")
    except outbox.PermanentDeliveryError as exc:
        return {"ok": False, "detail": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "detail": f"Could not send ({type(exc).__name__})."}
    return {"ok": True, "detail": f"Twilio accepted the message (id {sid}). Check that the phone receives it."}


def _zetaris() -> Dict[str, Any]:
    if not settings.zetaris_configured:
        return {"ok": False, "detail": "ZETARIS_ORG_ID and credentials are not set."}
    try:
        with get_client() as c:
            ping = c.ping()
    except ZetarisError as exc:
        return {"ok": False, "detail": str(exc)}
    names = [d.get("name") for d in ping["databases"]]
    return {"ok": True, "detail": f"Signed in and listed {len(names)} database(s): {', '.join(str(n) for n in names[:5])}."}


def _sso() -> Dict[str, Any]:
    if not settings.oidc_configured:
        return {"ok": False, "detail": "OIDC_ISSUER and OIDC_CLIENT_ID are not set."}
    oidc.reset_cache()
    try:
        doc = oidc.discovery()
        keys = oidc._jwks(force=True).get("keys", [])
    except Exception as exc:  # noqa: BLE001 - OidcError, network
        return {"ok": False, "detail": f"{type(exc).__name__}: {exc}"[:300]}
    usable = [k for k in keys if k.get("kty") in ("RSA", "EC")]
    note = "" if usable else " but it publishes no RSA/EC signing key"
    return {"ok": bool(usable), "detail": f"Discovery document read for {doc['issuer']}; {len(usable)} signing key(s) published{note}. "
            f"Register this redirect URI at the provider: {settings.oidc_redirect_uri}"}


def run(db: Session, key: str, user: User, to: Optional[str] = None) -> Dict[str, Any]:
    if key not in KEYS:
        raise KeyError(key)
    if key == "email":
        return _timed(lambda: _email(user, to))
    if key == "sms":
        return _timed(lambda: _sms(user, to))
    if key == "zetaris":
        return _timed(_zetaris)
    if key in ("virustotal", "abuseipdb"):
        def ti() -> Dict[str, Any]:
            if not threat_intel.configured(key):
                return {"ok": False, "detail": "API key is not set (or lookups are disabled)."}
            r = threat_intel.test_provider(db, key)
            return {"ok": r["ok"], "detail": r["detail"] if r["ok"] else f"Lookup did not succeed: {r['detail']}"}
        return _timed(ti)
    if key == "response":
        return _timed(response_executor.ping)
    return _timed(_sso)

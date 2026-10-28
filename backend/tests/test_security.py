import re
import time

import pyotp
import pytest
from sqlalchemy import update

from app.config import settings
from app.main import app
from app.models import AuditLog, NotificationDelivery, User, UserSession, naive_utc_now
from app.utils.audit import verify_chain
from app.utils.auth import get_password_hash
from tests.conftest import ACCOUNTS, PASSWORD, login, make_client

API = "/api/v1"
PUBLIC = {
    ("POST", f"{API}/auth/login"), ("POST", f"{API}/auth/forgot-password"), ("POST", f"{API}/auth/reset-password"),
    ("GET", f"{API}/system/health"), ("GET", API),
}


def _routes():
    """Every API operation, taken from the OpenAPI schema so it works across FastAPI versions."""
    for path, ops in app.openapi()["paths"].items():
        if not path.startswith(API):
            continue
        for method in ops:
            if method.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                url = re.sub(r"\{[^}]+\}", "1", path)
                yield method.upper(), url.replace("/1.txt", "/ip.txt") if "/feeds/" in url else url


def test_every_route_rejects_anonymous_callers(anon):
    checked = 0
    for method, path in _routes():
        if (method, path) in PUBLIC:
            continue
        res = anon.request(method, path, json={})
        assert res.status_code == 401, f"{method} {path} answered {res.status_code} to an anonymous caller"
        checked += 1
    assert checked > 40


@pytest.mark.parametrize("password", ["password", "Admin@CyberShield2026!", "Rahul@Employee2026!"])
def test_old_backdoor_passwords_are_rejected(anon, password):
    for email in (ACCOUNTS["admin"], ACCOUNTS["employee"]):
        assert login(anon, email, password).status_code == 401


def test_removed_endpoints_are_gone(anon):
    assert anon.post(f"{API}/auth/sso", json={"provider": "google", "email": "a@b.co", "role": "Super Admin"}).status_code in (404, 405)
    assert anon.get(f"{API}/auth/demo-accounts").status_code in (404, 405)


def test_unknown_alias_does_not_create_accounts(anon, db):
    for alias in ("rahul", "rahul@company.com", "rahul.k@company.com"):
        assert login(anon, alias, "CyberShield@2026!").status_code == 401
    assert db.query(User).filter(User.email == "rahul.k@company.com").first() is None


def test_login_sets_httponly_cookie_and_returns_no_token(anon):
    res = login(anon, ACCOUNTS["analyst"])
    assert res.status_code == 200
    assert "access_token" not in res.text
    cookies = res.headers.get_list("set-cookie")
    session_cookie = next(c for c in cookies if c.startswith(settings.SESSION_COOKIE_NAME))
    assert "HttpOnly" in session_cookie and "SameSite=strict" in session_cookie
    csrf_cookie = next(c for c in cookies if c.startswith(settings.CSRF_COOKIE_NAME))
    assert "HttpOnly" not in csrf_cookie


def test_state_changing_request_needs_csrf_header(analyst):
    del analyst.headers["X-CSRF-Token"]
    res = analyst.post(f"{API}/incidents/correlate")
    assert res.status_code == 403 and "CSRF" in res.json()["detail"]


def test_logout_really_revokes_the_session(analyst):
    stolen = analyst.cookies.get(settings.SESSION_COOKIE_NAME)
    assert analyst.post(f"{API}/auth/logout").status_code == 200
    other = make_client()
    other.cookies.set(settings.SESSION_COOKIE_NAME, stolen)
    assert other.get(f"{API}/auth/me").status_code == 401


def test_idle_and_absolute_expiry(analyst, db):
    row = db.query(UserSession).order_by(UserSession.id.desc()).first()
    row.last_seen_at = naive_utc_now().replace(microsecond=0) - __import__("datetime").timedelta(minutes=settings.SESSION_IDLE_MINUTES + 1)
    db.commit()
    assert analyst.get(f"{API}/auth/me").status_code == 401


def test_account_lockout_blocks_even_the_right_password(db):
    email = "lockout.test@company.com"
    db.add(User(email=email, full_name="Lock Test", role="Employee", hashed_password=get_password_hash("Correct-Horse-9!x")))
    db.commit()
    with make_client() as c:
        for _ in range(settings.LOGIN_MAX_FAILURES):
            assert login(c, email, "wrong-password-1").status_code == 401
        assert login(c, email, "Correct-Horse-9!x").status_code == 401
    user = db.query(User).filter(User.email == email).first()
    assert user.locked_until is not None


def test_login_error_does_not_reveal_whether_account_exists(anon):
    a = login(anon, "nobody@company.com", "whatever-12345")
    b = login(anon, ACCOUNTS["admin"], "whatever-12345")
    assert a.status_code == b.status_code == 401 and a.json() == b.json()


def test_legacy_bcrypt_hash_is_upgraded_to_argon2(db):
    import bcrypt
    email = "legacy.bcrypt@company.com"
    legacy = bcrypt.hashpw(b"Legacy-Pass-2026!", bcrypt.gensalt(rounds=4)).decode()
    db.add(User(email=email, full_name="Legacy", role="Employee", hashed_password=legacy))
    db.commit()
    with make_client() as c:
        assert login(c, email, "Legacy-Pass-2026!").status_code == 200
    db.expire_all()
    assert db.query(User).filter(User.email == email).first().hashed_password.startswith("$argon2id$")


# --- RBAC -------------------------------------------------------------------------------------------------------
def test_employee_cannot_use_soc_endpoints(employee):
    for path in ("/incidents", "/dashboard/metrics", "/events", "/dlp/findings", "/alerts/deliveries",
                 "/employees", "/blocklist", "/system/status"):
        assert employee.get(API + path).status_code == 403, path
    assert employee.post(f"{API}/incidents/correlate").status_code == 403


def test_employee_can_use_their_own_surface(employee):
    assert employee.post(f"{API}/phishing/analyze", json={"submission_type": "url", "content": "http://example.com/login"}).status_code == 200
    assert employee.get(f"{API}/employees/EMP-1042/events").status_code == 200  # their own
    assert employee.get(f"{API}/employees/EMP-1043/events").status_code == 403  # someone else's


def test_analyst_cannot_do_admin_things(analyst):
    assert analyst.get(f"{API}/users").status_code == 403
    assert analyst.post(f"{API}/alerts/test-dispatch", json={"title": "t", "summary": "s"}).status_code == 403
    assert analyst.post(f"{API}/system/seed-demo?force_reset=true").status_code == 403
    assert analyst.get(f"{API}/system/audit/verify").status_code == 403
    assert analyst.post(f"{API}/blocklist/feeds", json={"name": "fw"}).status_code == 403
    assert analyst.post(f"{API}/employees", json={}).status_code == 403


def test_client_supplied_identity_is_ignored(analyst, db):
    inc = analyst.get(f"{API}/incidents").json()[0]["incident_id"]
    res = analyst.post(f"{API}/incidents/{inc}/notes", json={"analyst_name": "Totally Someone Else", "note_text": "spoof attempt"})
    assert res.status_code == 200
    detail = analyst.get(f"{API}/incidents/{inc}").json()
    note = next(n for n in detail["notes"] if n["note_text"] == "spoof attempt")
    assert note["analyst_name"] == "Sarah Chen"
    entry = db.query(AuditLog).filter(AuditLog.action == "NOTE_ADDED").order_by(AuditLog.id.desc()).first()
    assert entry.actor == ACCOUNTS["analyst"]


# --- password change / reset ------------------------------------------------------------------------------------
def test_change_password_requires_current_and_a_strong_new_one(db):
    email = "pw.change@company.com"
    db.add(User(email=email, full_name="Pw Change", role="Employee", hashed_password=get_password_hash("Original-Pass-77!")))
    db.commit()
    with make_client() as c, make_client() as other:
        assert login(c, email, "Original-Pass-77!").status_code == 200
        assert login(other, email, "Original-Pass-77!").status_code == 200
        assert c.post(f"{API}/auth/change-password", json={"current_password": "nope", "new_password": "Another-Pass-88!"}).status_code == 400
        assert c.post(f"{API}/auth/change-password", json={"current_password": "Original-Pass-77!", "new_password": "short"}).status_code == 422
        assert c.post(f"{API}/auth/change-password", json={"current_password": "Original-Pass-77!", "new_password": "Another-Pass-88!"}).status_code == 200
        assert c.get(f"{API}/auth/me").status_code == 200       # this session survives
        assert other.get(f"{API}/auth/me").status_code == 401   # every other session is signed out
    with make_client() as fresh:
        assert login(fresh, email, "Original-Pass-77!").status_code == 401
        assert login(fresh, email, "Another-Pass-88!").status_code == 200


def test_password_reset_flow_is_single_use_and_does_not_enumerate(anon, db):
    email = "reset.me@company.com"
    db.add(User(email=email, full_name="Reset Me", role="Employee", hashed_password=get_password_hash("Before-Reset-55!")))
    db.commit()
    unknown = anon.post(f"{API}/auth/forgot-password", json={"email": "ghost@company.com"})
    known = anon.post(f"{API}/auth/forgot-password", json={"email": email})
    assert unknown.json() == known.json()

    row = db.query(NotificationDelivery).filter(NotificationDelivery.recipient_address == email).order_by(NotificationDelivery.id.desc()).first()
    token = re.search(r"reset_token=([\w\-]+)", row.message_body).group(1)
    assert "reset_token" not in row.body_preview  # the secret isn't kept in the preview column

    assert anon.post(f"{API}/auth/reset-password", json={"token": token, "new_password": "weak"}).status_code == 422
    assert anon.post(f"{API}/auth/reset-password", json={"token": token, "new_password": "After-Reset-66!!"}).status_code == 200
    assert anon.post(f"{API}/auth/reset-password", json={"token": token, "new_password": "Second-Use-77!!"}).status_code == 400
    assert anon.post(f"{API}/auth/reset-password", json={"token": "x" * 43, "new_password": "After-Reset-66!!"}).status_code == 400
    assert login(anon, email, "After-Reset-66!!").status_code == 200


# --- MFA ----------------------------------------------------------------------------------------------------------
def test_totp_enrolment_login_and_replay_protection(db):
    email = "mfa.user@company.com"
    db.add(User(email=email, full_name="Mfa User", role="SOC Analyst", hashed_password=get_password_hash("Mfa-Test-Pass-12!")))
    db.commit()
    with make_client() as c:
        assert login(c, email, "Mfa-Test-Pass-12!").status_code == 200
        setup = c.post(f"{API}/auth/mfa/setup").json()
        totp = pyotp.TOTP(setup["secret"])
        assert c.post(f"{API}/auth/mfa/enable", json={"code": "000000"}).status_code == 400
        code = totp.now()
        res = c.post(f"{API}/auth/mfa/enable", json={"code": code})
        assert res.status_code == 200 and res.json()["mfa_state"] == "ok"
        # stored encrypted, never in the clear
        db.expire_all()
        stored = db.query(User).filter(User.email == email).first().totp_secret_enc
        assert stored and setup["secret"] not in stored

    with make_client() as c2:
        state = login(c2, email, "Mfa-Test-Pass-12!").json()
        assert state["mfa_state"] == "verify"
        assert c2.get(f"{API}/incidents").status_code == 403           # password alone is not enough
        assert c2.post(f"{API}/auth/mfa/verify", json={"code": code}).status_code == 400   # replay of a used code
        future = totp.at(int(time.time()) + 30)
        assert c2.post(f"{API}/auth/mfa/verify", json={"code": future}).status_code == 200
        assert c2.get(f"{API}/incidents").status_code == 200


def test_privileged_roles_must_enrol_when_mfa_is_enforced(db, monkeypatch):
    monkeypatch.setattr(settings, "MFA_ENFORCED", True)
    with make_client() as c:
        state = login(c, ACCOUNTS["analyst"]).json()
        assert state["mfa_state"] == "enroll"
        assert c.get(f"{API}/incidents").status_code == 403
    with make_client() as e:                                             # employees are not forced
        assert login(e, ACCOUNTS["employee"]).json()["mfa_state"] == "ok"


# --- audit trail --------------------------------------------------------------------------------------------------
def test_audit_chain_verifies_and_detects_tampering(admin, db):
    assert admin.get(f"{API}/system/audit/verify").json()["valid"] is True
    victim = db.query(AuditLog).filter(AuditLog.entry_hash.isnot(None)).order_by(AuditLog.id.desc()).offset(2).first()
    original = victim.details
    db.execute(update(AuditLog).where(AuditLog.id == victim.id).values(details="rewritten by an attacker"))
    db.commit()
    result = admin.get(f"{API}/system/audit/verify").json()
    assert result["valid"] is False and result["first_bad_id"] == victim.id
    db.execute(update(AuditLog).where(AuditLog.id == victim.id).values(details=original))
    db.commit()
    assert admin.get(f"{API}/system/audit/verify").json()["valid"] is True


def test_audit_rows_carry_request_id_and_ip(admin, db):
    admin.post(f"{API}/incidents/correlate")
    login(make_client(), ACCOUNTS["admin"], "bad-password-123")
    row = db.query(AuditLog).filter(AuditLog.action == "AUTH_LOGIN_FAILED").order_by(AuditLog.id.desc()).first()
    assert row.request_id and row.ip_address


def test_security_headers_present(anon):
    res = anon.get(f"{API}/system/health")
    assert res.headers["x-content-type-options"] == "nosniff"
    assert res.headers["x-frame-options"] == "DENY"
    assert res.headers["cache-control"] == "no-store"
    assert res.headers["x-request-id"]


def test_demo_mode_cannot_be_enabled_in_production():
    from app.config import Settings
    with pytest.raises(ValueError):
        Settings(ENVIRONMENT="production", DEMO_MODE=True, SECRET_KEY="x" * 40, DATABASE_URL="postgresql://u:p@h/d")
    with pytest.raises(ValueError):
        Settings(ENVIRONMENT="production", SECRET_KEY=None, DATABASE_URL="postgresql://u:p@h/d")
    with pytest.raises(ValueError):
        Settings(ENVIRONMENT="production", SECRET_KEY="x" * 40)  # no database configured

"""Administrators can test each integration with a real call; results are honest and audited."""
import httpx
import pytest

from app.config import settings
from app.models import AuditLog
from app.services import integration_tests, oidc, outbox, response_executor
from tests.fake_zetaris import API_KEY, ORG_ID, FakeZetaris
from tests.test_zetaris import client_for  # noqa: F401
from tests.test_sso import FakeIdP, ISSUER, CLIENT_ID

API = "/api/v1"


def test_listing_names_each_integration_and_marks_the_testable_ones(secadmin):
    rows = {r["name"]: r for r in secadmin.get(f"{API}/admin/integrations").json()}
    keys = {r["key"] for r in rows.values()}
    assert {"email", "sms", "zetaris", "virustotal", "abuseipdb", "response", "sso"} <= keys
    assert rows["Single sign-on (OpenID Connect)"]["configured"] is False


def test_only_administrators_may_run_tests(analyst, employee, anon):
    for c, code in ((analyst, 403), (employee, 403), (anon, 401)):
        assert c.post(f"{API}/admin/integrations/email/test", json={}).status_code == code


def test_unknown_integration_is_404(secadmin):
    assert secadmin.post(f"{API}/admin/integrations/nonsense/test", json={}).status_code == 404


def test_unconfigured_integrations_say_what_is_missing(secadmin, monkeypatch):
    monkeypatch.setattr(settings, "SMTP_HOST", None)
    for key, expect in (("email", "SMTP_HOST"), ("sms", "TWILIO"), ("zetaris", "ZETARIS"), ("virustotal", "API key"),
                        ("abuseipdb", "API key"), ("response", "Not configured"), ("sso", "OIDC_ISSUER")):
        if key == "zetaris":
            monkeypatch.setattr(settings, "ZETARIS_ORG_ID", None)
        r = secadmin.post(f"{API}/admin/integrations/{key}/test", json={}).json()
        assert r["ok"] is False and expect in r["detail"], (key, r)


def test_email_test_sends_to_the_administrator_and_reports_failures(secadmin, monkeypatch):
    sent = []
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.example.org")
    monkeypatch.setattr(settings, "SMTP_FROM", "soc@example.org")
    monkeypatch.setattr(outbox, "send_email", lambda to, subject, body: sent.append((to, subject)) or "<id>")
    r = secadmin.post(f"{API}/admin/integrations/email/test", json={}).json()
    assert r["ok"] and sent == [("secadmin@cybershield.corp", "CyberShield connection test")] and "not 'delivered'" in r["detail"]

    def boom(*a, **k):
        raise ConnectionRefusedError("no route")
    monkeypatch.setattr(outbox, "send_email", boom)
    r = secadmin.post(f"{API}/admin/integrations/email/test", json={"to": "x@y.zz"}).json()
    assert r["ok"] is False and "ConnectionRefusedError" in r["detail"] and "no route" not in r["detail"]


def test_sms_test_needs_an_explicit_number(secadmin, monkeypatch):
    monkeypatch.setattr(outbox, "sms_configured", lambda: True)
    monkeypatch.setattr(integration_tests.outbox, "sms_configured", lambda: True)
    assert "never sent by default" in secadmin.post(f"{API}/admin/integrations/sms/test", json={}).json()["detail"]
    monkeypatch.setattr(outbox, "send_sms", lambda to, body: "SM123")
    r = secadmin.post(f"{API}/admin/integrations/sms/test", json={"to": "+15551234567"}).json()
    assert r["ok"] and "SM123" in r["detail"]


def test_zetaris_test_reports_a_real_round_trip(secadmin, monkeypatch):
    fake = FakeZetaris()
    for name, value in (("ZETARIS_ORG_ID", int(ORG_ID)), ("ZETARIS_API_KEY", API_KEY)):
        monkeypatch.setattr(settings, name, value)
    monkeypatch.setattr(integration_tests, "get_client", lambda: client_for(fake))
    r = secadmin.post(f"{API}/admin/integrations/zetaris/test", json={}).json()
    assert r["ok"] and "database" in r["detail"] and r["latency_ms"] >= 0


def test_response_connector_ping_is_signed_and_creates_no_job(secadmin, db, monkeypatch):
    from app.models import ResponseJob
    secret = "k" * 40
    monkeypatch.setattr(settings, "RESPONSE_WEBHOOK_URL", "https://soar.example.org/hook")
    monkeypatch.setattr(settings, "RESPONSE_WEBHOOK_SECRET", secret)
    seen = []

    def receiver(request):
        assert response_executor.verify(secret, request.content, request.headers[response_executor.SIGNATURE_HEADER])
        seen.append(request.content)
        return httpx.Response(202)
    real = response_executor.ping
    monkeypatch.setattr(integration_tests.response_executor, "ping", lambda: real(transport=httpx.MockTransport(receiver)))
    before = db.query(ResponseJob).count()
    r = secadmin.post(f"{API}/admin/integrations/response/test", json={}).json()
    assert r["ok"] and b'"action":"PING"' in seen[0]
    assert db.query(ResponseJob).count() == before
    monkeypatch.setattr(integration_tests.response_executor, "ping", lambda: real(transport=httpx.MockTransport(lambda req: httpx.Response(401))))
    assert secadmin.post(f"{API}/admin/integrations/response/test", json={}).json()["ok"] is False


def test_sso_test_reads_discovery_and_keys(secadmin, monkeypatch):
    fake = FakeIdP()
    monkeypatch.setattr(oidc, "_transport", httpx.MockTransport(fake.handler))
    monkeypatch.setattr(settings, "OIDC_ISSUER", ISSUER)
    monkeypatch.setattr(settings, "OIDC_CLIENT_ID", CLIENT_ID)
    r = secadmin.post(f"{API}/admin/integrations/sso/test", json={}).json()
    assert r["ok"] and "2 signing key" in r["detail"] and "/api/v1/auth/sso/callback" in r["detail"]
    oidc.reset_cache()


def test_tests_are_audited_and_rate_limited(secadmin, db):
    for _ in range(10):
        secadmin.post(f"{API}/admin/integrations/sso/test", json={})
    assert secadmin.post(f"{API}/admin/integrations/sso/test", json={}).status_code == 429
    db.expire_all()
    assert db.query(AuditLog).filter(AuditLog.action == "INTEGRATION_TEST").count() >= 10

from app.models import NotificationDelivery, naive_utc_now
from app.services.outbox import enqueue_email

API = "/api/v1"


def _failed(db, status="FAILED", to="nobody@example.org"):
    row = enqueue_email(db, to, "Retry me", "body", status=status)
    row.delivery_status, row.last_error = status, "boom"
    db.commit()
    return row


def test_delivery_filters_and_summary(db, analyst):
    _failed(db, "FAILED", "filter-me@example.org")
    body = analyst.get(f"{API}/alerts/deliveries", params={"status": "FAILED", "q": "filter-me"}).json()
    assert body and all(d["delivery_status"] == "FAILED" and "filter-me" in d["recipient_address"] for d in body)
    summary = analyst.get(f"{API}/alerts/summary").json()
    assert summary.get("FAILED", 0) >= 1


def test_only_admins_can_retry_and_only_failed_deliveries(db, analyst, admin):
    row = _failed(db)
    assert analyst.post(f"{API}/alerts/deliveries/{row.id}/retry").status_code == 403
    assert admin.post(f"{API}/alerts/deliveries/{row.id}/retry").json()["status"] == "queued"
    db.refresh(row)
    assert row.delivery_status == "QUEUED" and row.retry_count == 0 and row.last_error is None
    assert admin.post(f"{API}/alerts/deliveries/{row.id}/retry").status_code == 409      # already queued
    assert admin.post(f"{API}/alerts/deliveries/999999/retry").status_code == 404


def test_audit_search(admin):
    admin.post(f"{API}/incidents/correlate")
    hits = admin.get(f"{API}/system/audit", params={"q": "admin@cybershield"}).json()
    assert hits and all("admin@cybershield" in (h["actor"] + (h["details"] or "") + h["resource_id"] + h["action"]) for h in hits)
    assert admin.get(f"{API}/system/audit", params={"q": "zzz-no-such-thing-zzz"}).json() == []


def test_security_administrator_reads_the_audit_log_but_cannot_verify_its_integrity(secadmin):
    assert secadmin.get(f"{API}/system/audit").status_code == 200
    assert secadmin.get(f"{API}/system/audit/verify").status_code == 403


def test_super_admin_user_lifecycle(admin, db):
    new = {"email": "lifecycle.user@company.com", "full_name": "Life Cycle", "role": "SOC Analyst",
           "temporary_password": "Temp-Password-2026-zz"}
    made = admin.post(f"{API}/users", json=new)
    assert made.status_code == 201 and made.json()["role"] == "SOC Analyst"
    uid = made.json()["id"]
    assert admin.post(f"{API}/users", json=new).status_code == 409
    assert admin.post(f"{API}/users", json={**new, "email": "x@company.com", "role": "Wizard"}).status_code == 422
    assert admin.post(f"{API}/users", json={**new, "email": "y@company.com", "temporary_password": "short"}).status_code == 422

    # the new account must change its password before it can do anything
    from tests.conftest import make_client, login
    with make_client() as c:
        assert login(c, new["email"], new["temporary_password"]).json()["must_change_password"] is True
        assert c.get(f"{API}/incidents").status_code == 403

    assert admin.patch(f"{API}/users/{uid}", json={"role": "Employee"}).json()["role"] == "Employee"
    assert admin.patch(f"{API}/users/{uid}", json={"is_active": False}).json()["is_active"] is False
    with make_client() as c:
        assert login(c, new["email"], new["temporary_password"]).status_code == 401      # deactivated
    assert admin.post(f"{API}/users/{uid}/reset-mfa").status_code == 200
    assert admin.post(f"{API}/users/{uid}/revoke-sessions").status_code == 200
    me = next(u for u in admin.get(f"{API}/users").json() if u["email"] == "admin@cybershield.corp")
    assert admin.patch(f"{API}/users/{me['id']}", json={"is_active": False}).status_code == 409   # can't lock yourself out

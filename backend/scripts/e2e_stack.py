"""End-to-end run against the real Docker stack (PostgreSQL, mail catcher, live Zetaris, response connector).

Prints one line per check and exits non-zero if any fails. Needs the compose stack up with the `dev` profile, a bootstrap
administrator owner@example.org / Bootstrap-Temp-2026-x, Zetaris tables loaded with scripts/generate_synthetic_logs.py data,
and RESPONSE_WEBHOOK_URL=http://127.0.0.1:9009/hook with a 32+ character RESPONSE_WEBHOOK_SECRET in the app's environment.
Configure with E2E_BASE (default http://127.0.0.1:8088/api/v1), E2E_MAIL, E2E_APP_CONTAINER.
"""
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pyotp

BASE = os.environ.get("E2E_BASE", "http://127.0.0.1:8088/api/v1")
MAIL = os.environ.get("E2E_MAIL", "http://127.0.0.1:8025/api/v1")
APP = os.environ.get("E2E_APP_CONTAINER", "cybersheild--app-1")
OK, BAD = [], []


def check(name, cond, detail=""):
    (OK if cond else BAD).append(name)
    print(("PASS  " if cond else "FAIL  ") + name + (f"   [{detail}]" if detail and not cond else ""))
    return cond


class Session:
    def __init__(self):
        self.c = httpx.Client(base_url=BASE, timeout=240)

    def req(self, method, path, **kw):
        headers = kw.pop("headers", {})
        csrf = self.c.cookies.get("cs_csrf")
        if csrf:
            headers["X-CSRF-Token"] = csrf
        return self.c.request(method, path, headers=headers, **kw)


def wait_for(fn, seconds=120, every=3):
    end = time.time() + seconds
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(every)
    return None


# ---------------------------------------------------------------------------------------------------------------------
admin = Session()
check("health endpoint", admin.req("GET", "/system/health").json().get("status") == "healthy")
check("anonymous request is refused", admin.req("GET", "/incidents").status_code == 401)

r = admin.req("POST", "/auth/login", json={"email": "owner@example.org", "password": "Bootstrap-Temp-2026-x"})
state = r.json()
check("bootstrap admin can sign in", r.status_code == 200)
check("staff must enrol MFA (policy enforced outside development)", state.get("mfa_state") == "enroll", state)
check("a session without MFA cannot reach data", admin.req("GET", "/incidents").status_code == 403)
check("a session without MFA cannot create users", admin.req("POST", "/users", json={"email": "x@y.zz", "full_name": "X Y", "role": "SOC Analyst"}).status_code == 403)

secret = admin.req("POST", "/auth/mfa/setup").json()["secret"]
totp = pyotp.TOTP(secret)
r = admin.req("POST", "/auth/mfa/enable", json={"code": totp.now()})
check("MFA enrolment with a real authenticator code", r.status_code == 200 and r.json()["mfa_state"] == "ok", r.text[:120])
r = admin.req("POST", "/auth/change-password", json={"current_password": "Bootstrap-Temp-2026-x", "new_password": "E2E-Admin-Pass-2026-zz"})
check("forced password change", r.status_code == 200, r.text[:120])
check("admin overview works after MFA", admin.req("GET", "/admin/overview").status_code == 200)

# --- Zetaris pipeline on PostgreSQL ------------------------------------------------------------------------------------
z = wait_for(lambda: (lambda d: d if d.get("connected") and any(s["last_status"] == "OK" for s in d["sources"]) else None)(admin.req("GET", "/zetaris/status").json()), 90)
check("connected to the live Zetaris from inside Docker", bool(z), "no connection")
overview = wait_for(lambda: (lambda d: d if d["l2"]["incidents_investigated"] >= 1 else None)(admin.req("GET", "/soc/overview").json()), 120)
check("L1 triaged the Zetaris alerts on its own", bool(overview) and overview["l1"]["triaged"] >= 20, overview and overview["l1"])
check("L1 closed the noise automatically", bool(overview) and overview["l1"]["auto_closed"] >= 10, overview and overview["l1"])
check("L2 investigated and reached a verdict", bool(overview) and overview["l2"]["true_positive"] >= 1, overview and overview["l2"])
decisions = admin.req("GET", "/soc/decisions").json()
kinds = sorted({d["kind"] for d in decisions})
check("humans are asked to decide (block / disable / isolate / confirm)", {"CONTAINMENT", "DISABLE_ACCOUNT", "HOST_ISOLATION", "INCIDENT_DISPOSITION"} <= set(kinds), kinds)
incident = admin.req("GET", "/incidents").json()[0]
check("incident carries the AI assessment", incident["l2_verdict"] == "TRUE_POSITIVE" and "Corroborated" in incident["l2_analysis"], incident["l2_verdict"])

inv = admin.req("GET", "/zetaris/investigate", params={"indicator": "45.155.205.233"}).json()
check("live investigation returns a cross-source timeline", inv.get("stats", {}).get("failed_logins") == 14 and len(inv["timeline"]) > 20, inv.get("stats"))

# --- human decision -> firewall feed -----------------------------------------------------------------------------------
tok = admin.req("POST", "/blocklist/feeds", json={"name": "e2e-firewall"}).json()["token"]
feed_before = httpx.get(f"{BASE}/feeds/blocklist/ip.txt", headers={"Authorization": f"Bearer {tok}"}).text
check("nothing is blocked before a human approves", "45.155.205.233" not in feed_before)
block = next(d for d in decisions if d["kind"] == "CONTAINMENT" and d["proposal"]["indicator"] == "45.155.205.233")
r = admin.req("POST", f"/soc/decisions/{block['id']}/decide", json={"decision": "approve", "note": "E2E: confirmed in raw Zetaris logs"})
check("administrator approves the block", r.status_code == 200 and r.json()["status"] == "APPROVED", r.text[:120])
feed_after = httpx.get(f"{BASE}/feeds/blocklist/ip.txt", headers={"Authorization": f"Bearer {tok}"}).text
check("the approved address is now in the firewall feed", "45.155.205.233" in feed_after.splitlines(), feed_after[:100])

# --- analyst invite over real SMTP -------------------------------------------------------------------------------------
r = admin.req("POST", "/users", json={"email": "e2e.analyst@company.com", "full_name": "E2E Analyst", "role": "SOC Analyst"})
check("analyst account created with an activation invite", r.status_code == 201, r.text[:120])


def invite_mail():
    msgs = httpx.get(f"{MAIL}/messages").json().get("messages", [])
    for m in msgs:
        if any(t["Address"] == "e2e.analyst@company.com" for t in m["To"]):
            return httpx.get(f"{MAIL}/message/{m['ID']}").json()
    return None


mail = wait_for(invite_mail, 40)
check("the activation email really arrived over SMTP", bool(mail), "no message in the mail catcher")
token = re.search(r"reset_token=([\w\-]+)&activate=1", mail["Text"]).group(1) if mail else None
analyst = Session()
if token:
    r = analyst.req("POST", "/auth/reset-password", json={"token": token, "new_password": "E2E-Analyst-Pass-2026-zz"})
    check("analyst activates their own account from the link", r.status_code == 200, r.text[:100])
    check("the link works only once", analyst.req("POST", "/auth/reset-password", json={"token": token, "new_password": "Another-Pass-2026-zz"}).status_code == 400)
    r = analyst.req("POST", "/auth/login", json={"email": "e2e.analyst@company.com", "password": "E2E-Analyst-Pass-2026-zz"})
    check("analyst must also enrol MFA", r.json().get("mfa_state") == "enroll", r.text[:100])
    s2 = pyotp.TOTP(analyst.req("POST", "/auth/mfa/setup").json()["secret"])
    # the secret is returned once; re-derive from the setup response
    sec2 = None
analyst2 = Session()
r = analyst2.req("POST", "/auth/login", json={"email": "e2e.analyst@company.com", "password": "E2E-Analyst-Pass-2026-zz"})
sec = analyst2.req("POST", "/auth/mfa/setup").json()["secret"]
check("analyst completes MFA enrolment", analyst2.req("POST", "/auth/mfa/enable", json={"code": pyotp.TOTP(sec).now()}).status_code == 200)
check("analyst reaches the SOC dashboard data", analyst2.req("GET", "/dashboard/critical-alerts").status_code == 200)
check("analyst cannot reach administrator pages", analyst2.req("GET", "/admin/overview").status_code == 403 and analyst2.req("GET", "/users").status_code == 403)
inc = analyst2.req("GET", "/incidents").json()[0]
r = analyst2.req("PATCH", f"/incidents/{inc['incident_id']}/status", json={"status": "Resolved", "comment": "E2E closure attempt by analyst"})
check("analyst cannot close a Critical incident alone (approval requested)", r.json().get("status") == "approval_requested", r.text[:120])
disable = next(d for d in admin.req("GET", "/soc/decisions").json() if d["kind"] == "DISABLE_ACCOUNT")
check("analyst cannot approve disabling an account", analyst2.req("POST", f"/soc/decisions/{disable['id']}/decide", json={"decision": "approve"}).status_code == 403)

# --- alerts delivered over SMTP, audit, integrity --------------------------------------------------------------------
sent = wait_for(lambda: [m for m in httpx.get(f"{MAIL}/messages").json().get("messages", []) if "Decision required" in m["Subject"] or "CRITICAL" in m["Subject"]], 45)
check("SOC alert emails delivered by the outbox worker", bool(sent), "none in the mail catcher")
deliv = admin.req("GET", "/alerts/deliveries", params={"limit": 50}).json()
check("delivery status is truthful (SENT, never DELIVERED)", any(d["delivery_status"] == "SENT" for d in deliv) and not any(d["delivery_status"] == "DELIVERED" for d in deliv))
chain = admin.req("GET", "/system/audit/verify").json()
check("audit hash chain is intact on PostgreSQL", chain["valid"] and chain["checked"] > 15, chain)
acts = {a["action"] for a in admin.req("GET", "/system/audit", params={"limit": 200}).json()}
check("every step above was audited", {"AUTH_MFA_ENABLED", "USER_CREATED", "L3_DECISION_APPROVED", "BLOCKLIST_APPROVED", "L2_INVESTIGATION", "INCIDENT_CLOSURE_REQUESTED"} <= acts, sorted(acts))
health = {h["name"]: h["status"] for h in admin.req("GET", "/admin/overview").json()["health"]}
check("worker heartbeat is fresh", health.get("Automation worker") == "ok", health)
check("Zetaris health is ok", health.get("Zetaris data sources") == "ok", health)
check("email health is ok", health.get("Email alerts") == "ok", health)


# --- detection quality through the API ----------------------------------------------------------------------------------
def analyse(url):
    return admin.req("POST", "/phishing/analyze", json={"submission_type": "url", "content": url}).json()


check("internal address is not reported as phishing", analyse("http://10.0.0.5/admin")["risk_score"] < 35)
check("brand impersonation is flagged", analyse("http://login-microsoft365-verify.xyz/auth")["risk_score"] >= 60)
check("a real sign-in page is not flagged", analyse("https://accounts.google.com/signin")["risk_score"] < 35)
msg = admin.req("POST", "/phishing/analyze", json={"submission_type": "email", "content": "Hi team, the minutes from today are attached. Thanks!"}).json()
check("an ordinary message stays Low", msg["risk_category"] == "Low")
empty = admin.req("POST", "/files/analyze", files={"file": ("empty.txt", b"")}).json()
check("an empty file is not malicious", empty["risk_score"] < 35)

# --- integrations: real calls --------------------------------------------------------------------------------------------
rows = {r["key"]: r for r in admin.req("GET", "/admin/integrations").json() if r.get("key")}
check("integrations list names every testable service", {"email", "zetaris", "virustotal", "abuseipdb", "response", "sso"} <= set(rows), sorted(rows))
t = admin.req("POST", "/admin/integrations/email/test", json={}).json()
check("email test is accepted by the real SMTP server", t.get("ok"), t)
check("the test email really arrived", bool(wait_for(lambda: [m for m in httpx.get(f"{MAIL}/messages").json().get("messages", []) if "connection test" in m["Subject"]], 20)))
t = admin.req("POST", "/admin/integrations/zetaris/test", json={}).json()
check("Zetaris test signs in and lists databases (live)", t.get("ok") and "database" in t.get("detail", ""), t)
check("SSO test says it is not configured", admin.req("POST", "/admin/integrations/sso/test", json={}).json().get("ok") is False)
check("threat-intel test says the key is missing", "API key" in admin.req("POST", "/admin/integrations/virustotal/test", json={}).json().get("detail", ""))
check("SSO button is off", httpx.get(f"{BASE}/auth/sso/config").json()["enabled"] is False)
ti = admin.req("GET", "/threat-intel/lookup", params={"indicator": "185.220.101.47"}).json()
check("reputation lookup is honest when nothing is configured", {r["status"] for r in ti["results"]} == {"not_configured"}, ti)
check("internal addresses are never sent for reputation", admin.req("GET", "/threat-intel/lookup", params={"indicator": "10.0.0.5"}).json()["results"] == [])

# --- previewing the live Zetaris tables -----------------------------------------------------------------------------------
def preview_ok(src):
    r = admin.req("GET", "/zetaris/preview", params={"source": src})
    return r.json() if r.status_code == 200 else None      # Zetaris (Spark) can be slow when the machine is busy: retry


for src in ("auth", "network", "email"):
    p = wait_for(lambda: preview_ok(src), 180, 5) or {}
    check(f"preview of the {src} table reads rows and timestamps", p.get("sample_rows") and p["timestamps_read"].split("/")[0] == p["timestamps_read"].split("/")[1], p)
auth = wait_for(lambda: preview_ok("auth"), 180, 5) or {"warnings": ["preview unavailable"]}
check("auth outcome vocabulary matches the configuration", auth.get("failure_values_matched") == ["FAILURE"] and not auth.get("warnings"), auth.get("warnings"))

# --- response connector: approval -> signed webhook -> receiver -> callback ------------------------------------------------
script = Path(__file__).resolve().parent / "example_response_receiver.py"
# the image's root filesystem is read-only (docker cp refuses), but /tmp is a writable tmpfs: stream the file in
subprocess.run(["docker", "exec", "-i", APP, "sh", "-c", "cat > /tmp/receiver.py"], input=script.read_bytes(), check=True, capture_output=True)
subprocess.run(["docker", "exec", "-d", APP, "python", "/tmp/receiver.py", "--port", "9009"], check=True, capture_output=True)
ping = {}
for _ in range(8):                           # the receiver needs a moment to start listening (limit: 10 tests a minute)
    time.sleep(5)
    ping = admin.req("POST", "/admin/integrations/response/test", json={}).json()
    if ping.get("ok"):
        break
check("response connector ping is accepted by the receiver", ping.get("ok"), ping)
check("overview says a connector is configured", admin.req("GET", "/soc/overview").json()["response_connector"]["configured"] is True)
pending = admin.req("GET", "/soc/decisions").json()
host = next(d for d in pending if d["kind"] == "HOST_ISOLATION")
r = admin.req("POST", f"/soc/decisions/{host['id']}/decide", json={"decision": "approve", "note": "E2E: host isolation via connector"})
check("administrator approves host isolation", r.status_code == 200, r.text[:120])


def finished_job():
    jobs = [j for j in admin.req("GET", "/response/jobs").json() if j["action"] == "HOST_ISOLATION"]
    return jobs[0] if jobs and jobs[0]["status"] in ("COMPLETED", "FAILED", "UNCONFIRMED") else None


job = wait_for(finished_job, 45, 2)
check("the receiver confirmed the job through the signed callback", bool(job) and job["status"] == "COMPLETED", job)
inc_actions = admin.req("GET", f"/incidents/{host['incident_id']}").json().get("actions", [])
check("the incident's action reflects the confirmed result", any(a.get("status") == "EXECUTED_BY_CONNECTOR" for a in inc_actions), inc_actions)
bad = httpx.post(f"{BASE}/response/callback", content=b'{"job_id":"RJ-X","result":"succeeded"}', headers={"Content-Type": "application/json"})
check("an unsigned callback is refused", bad.status_code == 401)
check("audit chain is still intact after everything", admin.req("GET", "/system/audit/verify").json()["valid"])

print(f"\n{len(OK)} passed, {len(BAD)} failed")
sys.exit(1 if BAD else 0)

import httpx
import pytest

from app.config import settings
from app.models import IngestState, NotificationDelivery, SecurityEvent, Incident
from app.services import zetaris_ingest
from app.services.zetaris import (
    ZetarisClient, ZetarisError, ZetarisNotConfigured, assert_read_only, sql_table, sql_value,
)
from tests.fake_zetaris import API_KEY, ATTACKER, ORG_ID, PASSWORD, USER, FakeZetaris

API = "/api/v1"


@pytest.fixture
def fake():
    f = FakeZetaris()
    f.seed_attack()
    return f


def client_for(fake, **kw):
    kw.setdefault("api_key", API_KEY)
    return ZetarisClient(base_url="https://zetaris.test", org_id=int(ORG_ID), transport=fake.transport(), **kw)


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setattr(settings, "ZETARIS_ORG_ID", int(ORG_ID))
    monkeypatch.setattr(settings, "ZETARIS_API_KEY", API_KEY)
    monkeypatch.setattr(settings, "ZETARIS_TABLE_AUTH", "auth_logs")
    monkeypatch.setattr(settings, "ZETARIS_TABLE_NETWORK", "network_flows")
    monkeypatch.setattr(settings, "ZETARIS_TABLE_EMAIL", "email_logs")
    monkeypatch.setattr(settings, "ZETARIS_INITIAL_LOOKBACK_HOURS", 24)


@pytest.fixture
def clean_events(db):
    db.query(IngestState).delete()
    db.query(SecurityEvent).filter(SecurityEvent.event_id.like("ZT-%")).delete(synchronize_session=False)
    db.commit()


# --- SQL safety --------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("bad", ["1.2.3.4' OR '1'='1", "a;b", "x' --", "a b", "x\\y", "", "a" * 200, "\n"])
def test_unsafe_values_are_refused(bad):
    with pytest.raises(ValueError):
        sql_value(bad)


@pytest.mark.parametrize("sql", [
    "DROP TABLE auth_logs", "SELECT 1; DELETE FROM auth_logs", "UPDATE t SET a=1", "INSERT INTO t VALUES (1)",
    "SELECT * FROM t; SELECT 2", "CREATE TABLE x AS SELECT 1", "SET spark.sql.x=1", "  -- comment\nDROP TABLE t",
])
def test_non_read_only_sql_is_refused(sql):
    with pytest.raises(ValueError):
        assert_read_only(sql)


def test_read_only_sql_allows_keywords_inside_string_literals():
    assert assert_read_only("SELECT * FROM t WHERE note = 'please drop; table' ;")
    assert assert_read_only("WITH a AS (SELECT 1) SELECT * FROM a")


def test_table_names_are_whitelisted():
    assert sql_table("db.schema.table")
    for bad in ("t; drop", "a b", "", None, "x'y"):
        with pytest.raises(ValueError):
            sql_table(bad)


# --- client ------------------------------------------------------------------------------------------------------
def test_not_configured_is_a_clear_error(monkeypatch):
    monkeypatch.setattr(settings, "ZETARIS_ORG_ID", None)
    with pytest.raises(ZetarisNotConfigured):
        ZetarisClient()


def test_query_pages_through_results_and_closes_the_cursor(fake):
    with client_for(fake) as c:
        rows = c.query("SELECT * FROM auth_logs", page_limit=5)
    assert len(rows) == 16
    assert fake.open_count == fake.closed_count == 1 and fake.cursors == {}
    assert sum(1 for m, p in fake.requests if p.endswith("/query/sql/page")) == 3


def test_cursor_is_closed_even_when_a_page_fails(fake):
    with client_for(fake) as c:
        original = c._call
        def flaky(method, path, **kw):
            if path.endswith("/query/sql/page"):
                raise ZetarisError("boom")
            return original(method, path, **kw)
        c._call = flaky
        with pytest.raises(ZetarisError):
            c.query("SELECT * FROM auth_logs", page_limit=5)
    assert fake.closed_count == 1


def test_max_rows_caps_the_result(fake):
    with client_for(fake) as c:
        assert len(c.query("SELECT * FROM auth_logs", page_limit=5, max_rows=7)) == 7


def test_login_flow_with_username_password_and_token_refresh(fake):
    with client_for(fake, api_key="", username=USER, password=PASSWORD) as c:
        c.api_key = None
        fake.expire_id_token_once = False
        assert c.list_databases()[0]["name"] == "cybershield"
        fake.expire_id_token_once = True                      # server expires the token mid-session
        assert len(c.query("SELECT * FROM auth_logs")) == 16  # client logs in again and carries on
    assert sum(1 for m, p in fake.requests if p.endswith("/auth/login")) == 2


def test_server_errors_surface_the_message_without_credentials(fake):
    fake.fail_next_start = (400, "Table or view not found: nope")
    with client_for(fake) as c:
        with pytest.raises(ZetarisError) as exc:
            c.query("SELECT * FROM nope")
    assert "Table or view not found" in str(exc.value) and API_KEY not in str(exc.value)


def test_bad_credentials_are_reported(fake):
    with client_for(fake, api_key="wrong") as c:
        with pytest.raises(ZetarisError, match="401"):
            c.list_databases()


def test_unreachable_server_is_reported():
    def refuse(request):
        raise httpx.ConnectError("no route")
    c = ZetarisClient(base_url="https://zetaris.test", org_id=1, api_key="k", transport=httpx.MockTransport(refuse))
    with pytest.raises(ZetarisError, match="Could not reach"):
        c.list_databases()


# --- ingestion ---------------------------------------------------------------------------------------------------
def test_ingest_turns_zetaris_rows_into_correlated_alerting_events(fake, configured, clean_events, db):
    with client_for(fake) as c:
        report = zetaris_ingest.run_ingest(db, c)
    assert report["status"] == "ok" and all(s["status"] == "OK" for k, s in report["sources"].items() if k in zetaris_ingest.SOURCES)

    events = db.query(SecurityEvent).filter(SecurityEvent.event_id.like("ZT-%")).all()
    by_source = {}
    for e in events:
        by_source.setdefault(e.event_source, []).append(e)

    auth = by_source["Zetaris / auth logs"]
    serious = [e for e in auth if e.severity != "Low"]
    assert len(serious) == 1                                      # the 2-failure user is below even the low-signal floor
    assert serious[0].threat_category == "Account Compromise Suspected" and serious[0].severity == "Critical"
    assert serious[0].source_ip == ATTACKER and serious[0].user_account == "jane.doe@corp.example"

    assert any(e.source_ip == ATTACKER for e in by_source["Zetaris / network flows"])
    mail = by_source["Zetaris / email gateway"]
    assert len(mail) == 1 and mail[0].user_account == "jane.doe@corp.example"   # the lunch email is not flagged

    queued = db.query(NotificationDelivery).filter(NotificationDelivery.event_id.in_([e.event_id for e in events])).all()
    assert queued and all(d.delivery_status in ("QUEUED", "NOT_CONFIGURED", "SUPPRESSED_DUPLICATE") for d in queued)

    from app.services import soc_automation
    soc_automation.run_cycle(db)                       # L1 triages the new events, L2 correlates and investigates
    incident = db.query(Incident).filter(Incident.correlation_reason.contains(ATTACKER)).first()
    assert incident is not None and incident.l2_status == "DONE"


def test_second_pass_is_idempotent_and_advances_the_watermark(fake, configured, clean_events, db):
    with client_for(fake) as c:
        first = zetaris_ingest.run_ingest(db, c)
        second = zetaris_ingest.run_ingest(db, c)
    assert first["events_created"] >= 3 and second["events_created"] == 0
    state = {s.source: s for s in db.query(IngestState).all()}
    assert set(state) == {"auth", "network", "email"} and all(s.last_status == "OK" for s in state.values())


def test_new_rows_after_the_watermark_are_picked_up(fake, configured, clean_events, db):
    with client_for(fake) as c:
        zetaris_ingest.run_ingest(db, c)
        for i in range(6):
            fake.add_auth(1, "svc.backup@corp.example", "203.0.113.250".replace("203.0.113", "185.220.101"), "FAILURE")
        again = zetaris_ingest.run_ingest(db, c)
    assert again["events_created"] == 1


def test_one_failing_source_does_not_stop_the_others(fake, configured, clean_events, db, monkeypatch):
    monkeypatch.setattr(settings, "ZETARIS_TABLE_NETWORK", "no_such_table")
    with client_for(fake) as c:
        report = zetaris_ingest.run_ingest(db, c)
    assert report["sources"]["network"]["status"] == "ERROR"
    assert report["sources"]["auth"]["status"] == "OK" and report["sources"]["email"]["status"] == "OK"
    state = db.query(IngestState).filter(IngestState.source == "network").first()
    assert state.last_status == "ERROR" and state.last_error


def test_column_overrides_are_honoured(fake, configured, clean_events, db, monkeypatch):
    fake.db.execute("ALTER TABLE auth_logs RENAME COLUMN username TO account")
    monkeypatch.setattr(settings, "ZETARIS_COLUMNS", {"auth": {"username": "account"}})
    monkeypatch.setattr(settings, "ZETARIS_TABLE_NETWORK", None)
    monkeypatch.setattr(settings, "ZETARIS_TABLE_EMAIL", None)
    with client_for(fake) as c:
        report = zetaris_ingest.run_ingest(db, c)
    assert report["sources"]["auth"]["status"] == "OK" and report["events_created"] == 1


def test_bad_column_override_is_refused_not_injected(monkeypatch):
    monkeypatch.setattr(settings, "ZETARIS_COLUMNS", {"auth": {"username": "x; DROP TABLE auth_logs"}})
    with pytest.raises(ValueError):
        zetaris_ingest.columns("auth")


# --- investigation -----------------------------------------------------------------------------------------------
def test_investigating_an_ip_merges_sources_and_suggests_a_block(fake, configured):
    with client_for(fake) as c:
        result = zetaris_ingest.investigate(c, ATTACKER)
    assert result["type"] == "ip" and set(result["sources_queried"]) == {"auth", "network"}
    assert result["stats"]["failed_logins"] == 12 and result["stats"]["flows"] == 11
    assert {e["source"] for e in result["timeline"]} == {"auth", "network"}
    assert [e["time"] for e in result["timeline"]] == sorted(e["time"] for e in result["timeline"])
    assert result["suggested_blocks"][0]["indicator"] == ATTACKER


def test_investigating_a_user_covers_auth_and_email(fake, configured):
    with client_for(fake) as c:
        result = zetaris_ingest.investigate(c, "jane.doe@corp.example")
    assert result["type"] == "user" and {"auth", "email"} <= set(result["sources_queried"])
    assert result["stats"]["emails"] == 1 and result["suggested_blocks"] == []


@pytest.mark.parametrize("payload", ["1.2.3.4' OR '1'='1", "x'; DROP TABLE auth_logs; --", "a b", "x" * 300])
def test_investigation_rejects_injection_attempts(fake, configured, payload):
    with client_for(fake) as c:
        with pytest.raises(ValueError):
            zetaris_ingest.investigate(c, payload)
    assert fake.db.execute("SELECT COUNT(*) FROM auth_logs").fetchone()[0] == 16


# --- HTTP API ----------------------------------------------------------------------------------------------------
@pytest.fixture
def api_fake(fake, configured, monkeypatch):
    import app.routers.zetaris as router
    monkeypatch.setattr(router, "ZetarisClient", lambda: client_for(fake))
    router._ping_cache.update(at=0.0, value=None)
    return fake


def test_status_says_not_configured_when_it_is_not(analyst, monkeypatch):
    monkeypatch.setattr(settings, "ZETARIS_ORG_ID", None)
    body = analyst.get(f"{API}/zetaris/status").json()
    assert body["configured"] is False and body["connected"] is False and "Not configured" in body["error"]


def test_status_connected_only_after_a_real_round_trip(analyst, api_fake):
    body = analyst.get(f"{API}/zetaris/status").json()
    assert body["connected"] is True and body["databases"] == ["cybershield"] and body["latency_ms"] >= 0
    assert any(p.endswith("/lightning-database/databases") for _, p in api_fake.requests)


def test_status_reports_a_failed_connection(analyst, api_fake):
    api_fake.valid_tokens.clear()
    body = analyst.get(f"{API}/zetaris/status").json()
    assert body["connected"] is False and "401" in body["error"]


def test_ingest_endpoint_is_admin_only(analyst, admin, employee, api_fake, clean_events):
    assert employee.post(f"{API}/zetaris/ingest/run").status_code == 403
    assert analyst.post(f"{API}/zetaris/ingest/run").status_code == 403
    res = admin.post(f"{API}/zetaris/ingest/run")
    assert res.status_code == 200 and res.json()["events_created"] >= 3


def test_investigate_endpoint(analyst, employee, api_fake):
    assert employee.get(f"{API}/zetaris/investigate", params={"indicator": ATTACKER}).status_code == 403
    ok = analyst.get(f"{API}/zetaris/investigate", params={"indicator": ATTACKER})
    assert ok.status_code == 200 and ok.json()["stats"]["failed_logins"] == 12
    assert analyst.get(f"{API}/zetaris/investigate", params={"indicator": "x' OR '1'='1"}).status_code == 422


def test_a_zetaris_failure_is_reported_per_source_not_as_a_crash(admin, api_fake):
    api_fake.fail_next_start = (400, "Table or view not found")
    res = admin.post(f"{API}/zetaris/ingest/run")
    assert res.status_code == 200 and res.json()["sources"]["auth"]["status"] == "ERROR"


# --- detection rules ---------------------------------------------------------------------------------------------
def _fresh(fake_obj):
    fake_obj.db.execute("DELETE FROM auth_logs")
    fake_obj.db.execute("DELETE FROM network_flows")
    fake_obj.db.execute("DELETE FROM email_logs")


def _only_auth(monkeypatch):
    monkeypatch.setattr(settings, "ZETARIS_TABLE_NETWORK", None)
    monkeypatch.setattr(settings, "ZETARIS_TABLE_EMAIL", None)


def test_internal_typos_do_not_page_anyone(fake, configured, clean_events, db, monkeypatch):
    _only_auth(monkeypatch)
    _fresh(fake)
    for i in range(8):                                   # 8 wrong passwords from the user's own workstation, then success
        fake.add_auth(30 - i, "dave@corp.example", "10.20.3.44", "FAILURE")
    fake.add_auth(10, "dave@corp.example", "10.20.3.44", "SUCCESS")
    with client_for(fake) as c:
        zetaris_ingest.run_ingest(db, c)
    ev = db.query(SecurityEvent).filter(SecurityEvent.event_id.like("ZT-AUTH-%")).all()
    assert [(e.threat_category, e.severity) for e in ev] == [("Failed Login Burst", "Low")]     # reported, but never paged
    assert not db.query(NotificationDelivery).filter(NotificationDelivery.event_id == ev[0].event_id).count()


def test_a_very_large_internal_burst_is_brute_force_but_not_called_a_compromise(fake, configured, clean_events, db, monkeypatch):
    _only_auth(monkeypatch)
    _fresh(fake)
    for i in range(25):
        fake.add_auth(40 - i, "svc.ci@corp.example", "10.20.3.99", "FAILURE")
    fake.add_auth(5, "svc.ci@corp.example", "10.20.3.99", "SUCCESS")
    with client_for(fake) as c:
        zetaris_ingest.run_ingest(db, c)
    ev = db.query(SecurityEvent).filter(SecurityEvent.event_id.like("ZT-AUTH-%")).all()
    assert [e.threat_category for e in ev] == ["Credential Brute Force"]


def test_external_failures_without_a_success_are_brute_force_only(fake, configured, clean_events, db, monkeypatch):
    _only_auth(monkeypatch)
    _fresh(fake)
    for i in range(7):
        fake.add_auth(30 - i, "ops@corp.example", "185.220.101.9", "FAILURE")
    with client_for(fake) as c:
        zetaris_ingest.run_ingest(db, c)
    ev = db.query(SecurityEvent).filter(SecurityEvent.event_id.like("ZT-AUTH-%")).all()
    assert [e.threat_category for e in ev] == ["Credential Brute Force"] and ev[0].severity in ("High", "Critical")


def test_statistical_outliers_are_left_out_unless_opted_in(fake, configured, clean_events, db, monkeypatch):
    monkeypatch.setattr(settings, "ZETARIS_TABLE_AUTH", None)
    monkeypatch.setattr(settings, "ZETARIS_TABLE_EMAIL", None)
    _fresh(fake)
    for i in range(5):                                    # large but unremarkable HTTPS flows
        fake.add_flow(20 - i, f"10.20.3.{10 + i}", "93.184.216.34", 443, nbytes=95_000, packets=95)
    with client_for(fake) as c:
        assert zetaris_ingest.run_ingest(db, c)["events_created"] == 0


@pytest.mark.parametrize("raw,expected", [
    ("2026-10-28 10:13:12.0", "2026-10-28 10:13:12"),              # what a real Zetaris/Spark returns
    ("2026-10-28 10:13:12", "2026-10-28 10:13:12"),
    ("2026-10-28 10:13:12.5", "2026-10-28 10:13:12.500000"),
    ("2026-10-28T10:13:12.123Z", "2026-10-28 10:13:12.123000"),
    ("2026-10-28 10:13:12.123456789", "2026-10-28 10:13:12.123456"),
    ("2026-10-28T15:43:12+05:30", "2026-10-28 10:13:12"),         # offsets are converted to UTC
    ("1793182392000", "2026-10-28 10:13:12"),                      # epoch milliseconds
])
def test_timestamps_in_every_format_zetaris_returns_are_understood(raw, expected):
    assert str(zetaris_ingest.parse_time(raw)).replace(".000000", "") == expected.replace(".000000", "")


@pytest.mark.parametrize("raw", [None, "", "not a time", "2026-13-45 99:99:99"])
def test_unparseable_timestamps_are_none_not_errors(raw):
    assert zetaris_ingest.parse_time(raw) is None


# --- real-log robustness: outcome vocabulary and previewing a source -----------------------------------------------------
def _auth_rows(fake, outcome_fail, outcome_ok, n=12):
    from datetime import datetime, timedelta
    now = datetime.utcnow().replace(microsecond=0)
    rows = [(f"e{i}", (now - timedelta(minutes=30, seconds=-i * 10)).strftime("%Y-%m-%d %H:%M:%S"), "j.doe@corp.test", "45.155.205.233", outcome_fail) for i in range(n)]
    rows.append(("ok1", (now - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S"), "j.doe@corp.test", "45.155.205.233", outcome_ok))
    fake.db.execute("DELETE FROM auth_logs")
    fake.db.executemany("INSERT INTO auth_logs VALUES (?,?,?,?,?)", rows)


@pytest.mark.parametrize("fail,ok", [("Failed", "ok"), ("FAILURE", "Success"), ("failed", "OK")])
def test_other_spellings_of_failed_and_success_are_understood(db, configured, clean_events, fake, fail, ok):
    _auth_rows(fake, fail, ok)
    with client_for(fake) as c:
        zetaris_ingest.run_ingest(db, c)
    ev = db.query(SecurityEvent).filter(SecurityEvent.event_id.like("ZT-AUTH%")).all()
    assert any(e.threat_category == "Account Compromise Suspected" for e in ev), [e.threat_category for e in ev]


def test_unknown_vocabulary_finds_nothing_and_preview_explains_why(db, configured, clean_events, fake):
    _auth_rows(fake, "4625", "4624")
    with client_for(fake) as c:
        zetaris_ingest.run_ingest(db, c)
        report = zetaris_ingest.preview(c, "auth")
    assert not db.query(SecurityEvent).filter(SecurityEvent.event_id.like("ZT-AUTH%")).count()
    assert any("ZETARIS_AUTH_FAILURE_VALUES" in w for w in report["warnings"]), report["warnings"]
    assert {v["value"] for v in report["outcome_values"]} == {"4625", "4624"} and report["timestamps_read"] == "5/5"


def test_preview_reports_rows_and_timestamp_problems(db, configured, fake):
    with client_for(fake) as c:
        r = zetaris_ingest.preview(c, "network")
    assert r["table"] == "network_flows" and r["sample_rows"] and r["rows_last_24h"] > 0
    fake.db.execute("UPDATE network_flows SET event_time = 'not a time'")
    with client_for(fake) as c:
        assert any("event_time" in w for w in zetaris_ingest.preview(c, "network")["warnings"])


def test_preview_endpoint_is_admin_only_and_validates_source(admin, analyst, monkeypatch):
    assert analyst.get(f"{API}/zetaris/preview", params={"source": "auth"}).status_code == 403
    assert admin.get(f"{API}/zetaris/preview", params={"source": "evil"}).status_code == 422
    monkeypatch.setattr(settings, "ZETARIS_TABLE_AUTH", None)
    assert admin.get(f"{API}/zetaris/preview", params={"source": "auth"}).status_code in (409, 502, 503)

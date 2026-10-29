"""Whole-pipeline evaluation on synthetic scenarios with known answers: ingest -> L1 triage -> L2 investigation -> decisions.

Attack scenarios must be called true positives and produce a block proposal; quiet and benign-but-odd scenarios must not.
Run with `-s` to print the table that docs/detection-evaluation.md reports. The data is synthetic and the scenarios are
ones we thought of, so this shows the thresholds are coherent, not that they are right for a real network.
"""
import importlib.util
from collections import Counter
from pathlib import Path

import pytest

from app.config import settings
from app.models import DecisionRequest, Incident, IngestState, SecurityEvent
from app.services import soc_automation, zetaris_ingest
from tests.conftest import wipe_soc
from tests.fake_zetaris import API_KEY, ORG_ID, FakeZetaris
from tests.test_zetaris import client_for  # noqa: F401

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "generate_synthetic_logs.py"


def _generator():
    spec = importlib.util.spec_from_file_location("gen", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_scenario(db, monkeypatch, scenario: str, seed: int):
    gen = _generator()
    fake = FakeZetaris()
    auth, flows, mails = gen.build(seed=seed, scenario=scenario)
    fake.db.executemany("INSERT INTO auth_logs VALUES (?,?,?,?,?)", auth)
    fake.db.executemany("INSERT INTO network_flows VALUES (?,?,?,?,?,?,?,?)", flows)
    fake.db.executemany("INSERT INTO email_logs VALUES (?,?,?,?,?,?)", mails)
    for name, value in (("ZETARIS_ORG_ID", int(ORG_ID)), ("ZETARIS_API_KEY", API_KEY), ("ZETARIS_TABLE_AUTH", "auth_logs"),
                        ("ZETARIS_TABLE_NETWORK", "network_flows"), ("ZETARIS_TABLE_EMAIL", "email_logs"),
                        ("ZETARIS_INITIAL_LOOKBACK_HOURS", 24)):
        monkeypatch.setattr(settings, name, value)
    wipe_soc(db)
    db.query(IngestState).delete()
    db.commit()
    with client_for(fake) as c:
        zetaris_ingest.run_ingest(db, c)
    soc_automation.run_cycle(db)
    events = db.query(SecurityEvent).all()
    incidents = db.query(Incident).all()
    decisions = db.query(DecisionRequest).all()
    return {
        "gen": gen, "events": events, "incidents": incidents, "decisions": decisions,
        "triage": Counter(e.triage_status for e in events),
        "verdicts": Counter(i.l2_verdict for i in incidents),
        "kinds": Counter(d.kind for d in decisions),
    }


@pytest.fixture(autouse=True)
def _restore_demo_data():
    yield
    from app.database import SessionLocal
    from app.services.demo_data_seeder import seed_demo_soc_data
    with SessionLocal() as s:
        seed_demo_soc_data(db=s, force_reset=True)


@pytest.mark.parametrize("seed", [1, 2, 3, 4, 5, 6])
def test_planted_attack_is_a_true_positive_with_a_block_proposal(db, monkeypatch, seed):
    r = run_scenario(db, monkeypatch, "attack", seed)
    gen = r["gen"]
    assert r["verdicts"].get("TRUE_POSITIVE", 0) >= 1, r["verdicts"]
    assert any(d.kind == "CONTAINMENT" and gen.ATTACKER in d.proposal for d in r["decisions"]), r["kinds"]
    print(f"\nattack seed={seed}: events={len(r['events'])} triage={dict(r['triage'])} verdicts={dict(r['verdicts'])} decisions={dict(r['kinds'])}")


@pytest.mark.parametrize("scenario", ["quiet", "forgot_password", "new_hire_burst"])
@pytest.mark.parametrize("seed", [1, 2, 3])
def test_benign_scenarios_raise_no_true_positive_and_no_block(db, monkeypatch, scenario, seed):
    r = run_scenario(db, monkeypatch, scenario, seed)
    assert r["verdicts"].get("TRUE_POSITIVE", 0) == 0, (scenario, r["verdicts"])
    assert r["kinds"].get("CONTAINMENT", 0) == 0 and r["kinds"].get("DISABLE_ACCOUNT", 0) == 0, (scenario, r["kinds"])
    print(f"\n{scenario} seed={seed}: events={len(r['events'])} triage={dict(r['triage'])} incidents={len(r['incidents'])} decisions={dict(r['kinds'])}")


def test_legitimate_cloud_backup_reaches_a_human_and_nothing_is_applied_automatically(db, monkeypatch):
    """A 120 MB upload looks like exfiltration to any volume rule. Without an allow-list it becomes a question for a person:
    proposals stay PENDING, nothing is blocked or isolated on its own."""
    r = run_scenario(db, monkeypatch, "cloud_backup", 1)
    print(f"\ncloud_backup (no allow-list): events={len(r['events'])} triage={dict(r['triage'])} verdicts={dict(r['verdicts'])} decisions={dict(r['kinds'])}")
    assert r["decisions"] and all(d.status == "PENDING" for d in r["decisions"])


def test_trusted_destination_silences_the_backup(db, monkeypatch):
    monkeypatch.setattr(settings, "NETWORK_TRUSTED_DESTINATIONS", "52.95.110.0/24")
    r = run_scenario(db, monkeypatch, "cloud_backup", 1)
    print(f"\ncloud_backup (allow-listed): events={len(r['events'])} triage={dict(r['triage'])} decisions={dict(r['kinds'])}")
    assert not r["decisions"] and not r["incidents"]

"""End-to-end: the synthetic dataset's planted attack must be found, and its benign noise must not flood the SOC."""
import csv
import importlib.util
from collections import Counter
from pathlib import Path

import pytest

from app.config import settings
from app.models import Incident, IngestState, SecurityEvent
from app.services import zetaris_ingest
from tests.fake_zetaris import API_KEY, ORG_ID, FakeZetaris
from tests.test_zetaris import client_for  # noqa: F401

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "generate_synthetic_logs.py"


def _generator():
    spec = importlib.util.spec_from_file_location("gen", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load(fake: FakeZetaris, gen) -> None:
    auth, flows, mails = gen.build(seed=7)
    fake.db.executemany("INSERT INTO auth_logs VALUES (?,?,?,?,?)", auth)
    fake.db.executemany("INSERT INTO network_flows VALUES (?,?,?,?,?,?,?,?)", flows)
    fake.db.executemany("INSERT INTO email_logs VALUES (?,?,?,?,?,?)", mails)


def test_planted_attack_is_found_without_drowning_in_false_positives(db, monkeypatch):
    gen = _generator()
    fake = FakeZetaris()
    _load(fake, gen)
    monkeypatch.setattr(settings, "ZETARIS_ORG_ID", int(ORG_ID))
    monkeypatch.setattr(settings, "ZETARIS_API_KEY", API_KEY)
    monkeypatch.setattr(settings, "ZETARIS_TABLE_AUTH", "auth_logs")
    monkeypatch.setattr(settings, "ZETARIS_TABLE_NETWORK", "network_flows")
    monkeypatch.setattr(settings, "ZETARIS_TABLE_EMAIL", "email_logs")
    monkeypatch.setattr(settings, "ZETARIS_INITIAL_LOOKBACK_HOURS", 24)
    db.query(IngestState).delete()
    db.query(SecurityEvent).filter(SecurityEvent.event_id.like("ZT-%")).delete(synchronize_session=False)
    db.commit()

    with client_for(fake) as c:
        report = zetaris_ingest.run_ingest(db, c)
    assert all(s["status"] == "OK" for k, s in report["sources"].items()), report

    events = db.query(SecurityEvent).filter(SecurityEvent.event_id.like("ZT-%")).all()
    by = Counter((e.event_source, e.threat_category) for e in events)
    print("\n", dict(by))

    # the story
    assert any(e.event_source == "Zetaris / auth logs" and e.source_ip == gen.ATTACKER and e.user_account == gen.VICTIM
               and e.threat_category == "Account Compromise Suspected" for e in events)
    assert any(e.event_source == "Zetaris / email gateway" and e.user_account == gen.VICTIM for e in events)
    net_from_attacker = [e for e in events if e.event_source == "Zetaris / network flows" and e.source_ip == gen.ATTACKER]
    assert net_from_attacker, "the port scan was not detected"
    from app.services import soc_automation
    soc_automation.run_cycle(db)
    victim_incident = db.query(Incident).filter(Incident.correlation_reason.contains(gen.ATTACKER)).first()
    assert victim_incident is not None and victim_incident.l2_verdict == "TRUE_POSITIVE", "L2 should call the planted attack a true positive"

    # noise: 40 employees' ordinary traffic must not be raising alarms
    benign_auth = [e for e in events if e.event_source == "Zetaris / auth logs" and e.user_account != gen.VICTIM]
    assert all(e.severity == "Low" for e in benign_auth), "benign typos must stay Low"
    from app.models import AgentRun
    assert benign_auth and all(e.triage_status == "AUTO_CLOSED" for e in db.query(SecurityEvent).filter(
        SecurityEvent.id.in_([x.id for x in benign_auth])).all()), "L1 should close every benign typo"
    benign_mail = [e for e in events if e.event_source == "Zetaris / email gateway" and e.user_account != gen.VICTIM]
    assert not benign_mail, f"{len(benign_mail)} benign emails flagged"
    benign_net = [e for e in events if e.event_source == "Zetaris / network flows" and e.source_ip != gen.ATTACKER
                  and not e.source_ip.startswith("10.20.4.37")]
    assert len(benign_net) <= 3, f"{len(benign_net)} benign network flows flagged: {[ (e.source_ip,e.threat_category) for e in benign_net]}"

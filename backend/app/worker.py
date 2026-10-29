"""Background loop: delivers queued alerts and expires blocklist entries.

Runs inside the API process by default (OUTBOX_WORKER_ENABLED=true). To run it separately, set that to false on the
API and start `python -m app.worker` as its own service.
"""
import asyncio
import logging
import time
from app.config import settings
from app.database import SessionLocal
from app.models import naive_utc_now
from app.services.blocklist import expire_due
from app.services.outbox import process_outbox

logger = logging.getLogger("cybershield.worker")


_last_ingest = 0.0


def _maybe_ingest(db) -> int:
    """Pull new events from Zetaris on its own interval, when it is configured."""
    global _last_ingest
    if not (settings.ZETARIS_INGEST_ENABLED and settings.zetaris_configured):
        return 0
    if time.monotonic() - _last_ingest < settings.ZETARIS_INGEST_INTERVAL_SECONDS:
        return 0
    _last_ingest = time.monotonic()
    from app.services import zetaris_ingest
    from app.services.zetaris import ZetarisClient, ZetarisError
    if not zetaris_ingest.configured_sources():
        return 0
    try:
        with ZetarisClient() as client:
            return zetaris_ingest.run_ingest(db, client).get("events_created", 0)
    except ZetarisError as exc:
        logger.warning("Zetaris ingest skipped: %s", exc)
        return 0


def deliver_once() -> dict:
    """The fast, time-sensitive half: alerts, blocklist expiry and response-connector jobs. Never waits on Zetaris."""
    with SessionLocal() as db:
        stats = process_outbox(db)
        stats["expired_blocks"] = expire_due(db)
        from app.services import response_executor
        for key, n in response_executor.process_due(db).items():
            stats[f"response_{key}"] = n
        from app.services import settings_store
        settings_store.put_fact(db, "worker_heartbeat", naive_utc_now().isoformat())
        db.commit()
    return stats


def analyse_once() -> dict:
    """The slow half: pull from Zetaris (which can take minutes when it is busy), then L1 triage and L2 investigation."""
    stats: dict = {}
    with SessionLocal() as db:
        stats["zetaris_events"] = _maybe_ingest(db)
    with SessionLocal() as db:
        from app.services import soc_automation
        stats["soc"] = soc_automation.run_cycle(db)  # L1 triage, then L2 investigation; L3 stays with people
        db.commit()
    return stats


def run_once() -> dict:
    return {**deliver_once(), **analyse_once()}


async def _loop(name: str, fn, interval_seconds: float) -> None:
    while True:
        try:
            stats = await asyncio.to_thread(fn)
            if any(stats.values()):
                logger.info("worker %s pass: %s", name, stats)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("worker %s pass failed", name)
        await asyncio.sleep(interval_seconds)


async def run_forever(interval_seconds: float = 5.0) -> None:
    """Delivery and analysis run as separate loops, so a slow data source never delays an alert or an approved response.
    SQLite (development only) allows one writer at a time, so there they take turns in a single loop."""
    from app.database import engine
    if engine.dialect.name == "sqlite":
        await _loop("combined", run_once, interval_seconds)
    else:
        await asyncio.gather(_loop("delivery", deliver_once, interval_seconds), _loop("analysis", analyse_once, interval_seconds))


if __name__ == "__main__":
    from app.database import Base, engine
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    Base.metadata.create_all(bind=engine)
    asyncio.run(run_forever())

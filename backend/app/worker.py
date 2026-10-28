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


def run_once() -> dict:
    with SessionLocal() as db:
        stats = process_outbox(db)
        stats["expired_blocks"] = expire_due(db)
        stats["zetaris_events"] = _maybe_ingest(db)
    with SessionLocal() as db:
        from app.services import soc_automation
        stats["soc"] = soc_automation.run_cycle(db)  # L1 triage, then L2 investigation; L3 stays with people
        from app.services import settings_store
        settings_store.put_fact(db, "worker_heartbeat", naive_utc_now().isoformat())
        db.commit()
    return stats


async def run_forever(interval_seconds: float = 5.0) -> None:
    while True:
        try:
            stats = await asyncio.to_thread(run_once)
            if any(stats.values()):
                logger.info("worker pass: %s", stats)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("worker pass failed")
        await asyncio.sleep(interval_seconds)


if __name__ == "__main__":
    from app.database import Base, engine
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    Base.metadata.create_all(bind=engine)
    asyncio.run(run_forever())

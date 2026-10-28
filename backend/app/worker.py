"""Background loop: delivers queued alerts and expires blocklist entries.

Runs inside the API process by default (OUTBOX_WORKER_ENABLED=true). To run it separately, set that to false on the
API and start `python -m app.worker` as its own service.
"""
import asyncio
import logging
from app.database import SessionLocal
from app.services.blocklist import expire_due
from app.services.outbox import process_outbox

logger = logging.getLogger("cybershield.worker")


def run_once() -> dict:
    with SessionLocal() as db:
        stats = process_outbox(db)
        stats["expired_blocks"] = expire_due(db)
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

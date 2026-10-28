import logging
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import settings

logger = logging.getLogger("cybershield.database")

Base = declarative_base()

def _normalise(url: str) -> str:
    # Use the psycopg 3 driver for any plain PostgreSQL URL
    for prefix in ("postgres://", "postgresql://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix):]
    return url


def get_database_connection():
    target_url = settings.database_url
    if target_url:
        try:
            engine = create_engine(_normalise(target_url), pool_pre_ping=True)
            with engine.connect():
                pass
            logger.info("Connected to PostgreSQL.")
            return engine, "PostgreSQL", False, _normalise(target_url)
        except Exception as e:
            # Never fall back to a throwaway local database when a real one was configured.
            raise RuntimeError(f"Could not connect to the configured database: {type(e).__name__}") from e

    if settings.is_production:
        raise RuntimeError("DATABASE_URL is required in production.")
    sqlite_url = settings.SQLITE_URL or ("sqlite:////tmp/cybershield.db" if os.getenv("VERCEL") else "sqlite:///./cybershield.db")
    engine = create_engine(sqlite_url, connect_args={"check_same_thread": False})
    return engine, "SQLite (development)", True, sqlite_url

engine, DB_PROVIDER_NAME, IS_DEMO_DB, ACTIVE_DB_URL = get_database_connection()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_db_status():
    return {
        "provider": DB_PROVIDER_NAME,
        "is_demo_mode": IS_DEMO_DB,
        "status": "connected",
        "notice": "SQLite is for local development only." if IS_DEMO_DB else "PostgreSQL.",
        "target": "cybershield.db" if IS_DEMO_DB else "PostgreSQL"
    }

import logging
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import settings

logger = logging.getLogger("cybershield.database")

Base = declarative_base()

def get_database_connection():
    target_url = settings.SUPABASE_DATABASE_URL or settings.DATABASE_URL
    if target_url:
        # Standardize postgres:// to postgresql://
        if target_url.startswith("postgres://"):
            target_url = target_url.replace("postgres://", "postgresql://", 1)
        try:
            logger.info("Connecting to PostgreSQL / Supabase...")
            engine = create_engine(target_url, pool_pre_ping=True)
            # Test connection
            with engine.connect() as conn:
                logger.info("Successfully connected to Supabase PostgreSQL.")
            return engine, "Supabase PostgreSQL", False, target_url
        except Exception as e:
            logger.warning(f"Could not connect to configured database URL ({e}). Falling back to local SQLite.")
            
    # SQLite fallback (uses /tmp on Vercel Serverless where root filesystem is read-only)
    if os.getenv("VERCEL"):
        sqlite_url = "sqlite:////tmp/cybershield.db"
    else:
        sqlite_url = "sqlite:///./cybershield.db"
    engine = create_engine(
        sqlite_url,
        connect_args={"check_same_thread": False}
    )
    return engine, "Local SQLite (SOC Cache / Demo Mode)", True, sqlite_url

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
        "notice": (
            "Operating in Local SQLite SOC Cache mode. Full relational schema and persistence active."
            if IS_DEMO_DB else "Operating with Supabase PostgreSQL enterprise cluster."
        ),
        "target": "cybershield.db" if IS_DEMO_DB else "Supabase Managed Instance"
    }

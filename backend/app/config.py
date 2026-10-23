import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Optional

class Settings(BaseSettings):
    PROJECT_NAME: str = "CYBERSHIELD AI"
    API_V1_PREFIX: str = "/api/v1"
    
    # Database Settings: PostgreSQL via Supabase or fallback to SQLite
    SUPABASE_DATABASE_URL: Optional[str] = os.getenv("SUPABASE_DATABASE_URL", None)
    DATABASE_URL: Optional[str] = os.getenv("DATABASE_URL", None)
    
    # External Reputation Integrations (Clearly labeled if not configured)
    VIRUSTOTAL_API_KEY: Optional[str] = os.getenv("VIRUSTOTAL_API_KEY", None)
    PHISHTANK_API_KEY: Optional[str] = os.getenv("PHISHTANK_API_KEY", None)
    ABUSEIPDB_API_KEY: Optional[str] = os.getenv("ABUSEIPDB_API_KEY", None)
    
    # CORS Configuration
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]
    
    SECRET_KEY: str = os.getenv("SECRET_KEY", "cybershield-soc-secret-development-key")
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()

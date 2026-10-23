from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db, get_db_status
from app.config import settings
from app.schemas import SystemStatusResponse
from app.services.demo_data_seeder import seed_demo_soc_data

router = APIRouter(prefix="/system", tags=["System & Integrations Status"])

@router.get("/health")
def get_health_status(db: Session = Depends(get_db)):
    db_info = get_db_status()
    return {
        "status": "healthy",
        "service": "CYBERSHIELD AI Platform",
        "database": db_info,
        "environment": settings.ENVIRONMENT
    }

@router.get("/status", response_model=SystemStatusResponse)
def get_full_system_status(db: Session = Depends(get_db)):
    db_info = get_db_status()
    
    integrations = {
        "supabase_postgresql": {
            "configured": bool(settings.SUPABASE_DATABASE_URL),
            "status": "Active" if bool(settings.SUPABASE_DATABASE_URL) else "Not Configured (Running Local SQLite Cache)",
            "details": "PostgreSQL relational enterprise cluster connection."
        },
        "virustotal_reputation": {
            "configured": bool(settings.VIRUSTOTAL_API_KEY),
            "status": "Active" if bool(settings.VIRUSTOTAL_API_KEY) else "Heuristic Fallback Mode (VIRUSTOTAL_API_KEY not in .env)",
            "details": "External hash and domain reputation score lookup."
        },
        "phishtank_feed": {
            "configured": bool(settings.PHISHTANK_API_KEY),
            "status": "Active" if bool(settings.PHISHTANK_API_KEY) else "Offline NLP / Rule Engine Active",
            "details": "Community verified zero-hour phishing URL blacklists."
        },
        "perimeter_firewall_sync": {
            "configured": False,
            "status": "Simulated Safe Mode",
            "details": "Simulated IP blocking active to prevent accidental network disruption during triage."
        }
    }

    ml_engine = {
        "status": "Online & Calibrated",
        "phishing_nlp_classifier": "Scikit-Learn TF-IDF N-Gram Vectorizer + Calibrated Logistic Regression",
        "network_anomaly_detector": "Scikit-Learn Multi-Dimensional Isolation Forest",
        "file_entropy_scanner": "Shannon Entropy Engine (Byte Distribution Curve)"
    }

    security_guards = {
        "ssrf_firewall": "Active (Enforces RFC-1918 Private IP, Loopback, Link-Local & Cloud Metadata Blocking)",
        "upload_safety_guard": "Enforced (Static Non-Execution File Sandbox, 15MB Size Cap)",
        "audit_trail_logging": "Continuous Relational Audit Trail Recording"
    }

    return SystemStatusResponse(
        name=settings.PROJECT_NAME,
        version="1.0.0-soc-release",
        environment=settings.ENVIRONMENT,
        status="Operational",
        database=db_info,
        integrations=integrations,
        ml_engine=ml_engine,
        security_guards=security_guards
    )

@router.post("/seed-demo")
def seed_or_reset_demo_data(force_reset: bool = False, db: Session = Depends(get_db)):
    result = seed_demo_soc_data(db=db, force_reset=force_reset)
    return result

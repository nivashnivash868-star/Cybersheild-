import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database import engine, Base, SessionLocal
from app.services.demo_data_seeder import seed_demo_soc_data
from app.routers import (
    dashboard, phishing, file_analysis, network,
    incidents, forensics, events, system,
    auth, employees, monitoring, dlp, url_warning, alerts
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("cybershield.main")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Ensure database tables are created
    logger.info("Initializing enterprise database schema...")
    Base.metadata.create_all(bind=engine)
    
    # Auto-seed synthetic cybersecurity data for demonstration if empty
    with SessionLocal() as db:
        res = seed_demo_soc_data(db=db, force_reset=False)
        logger.info(f"Database seed check: {res}")
        
    logger.info("CYBERSHIELD AI Enterprise backend successfully started.")
    yield
    logger.info("CYBERSHIELD AI backend shutting down.")

app = FastAPI(
    title="CYBERSHIELD AI — Enterprise Cybersecurity Monitoring Platform",
    description=(
        "Unified Enterprise SOC, Threat Intelligence & Monitoring Platform combining "
        "Secure RBAC Authentication, Employee Directory & Monitoring Policies, 24/7 Multi-Source Telemetry, "
        "Data Loss Prevention (DLP) Secret Scanner, Phishing Detection, File Static Analysis, "
        "NetFlow Anomaly Detection, Unified Incident Correlation, Automated Alert Notifications, and Digital Forensics."
    ),
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers under /api/v1
api_v1_prefix = settings.API_V1_PREFIX
app.include_router(auth.router, prefix=api_v1_prefix)
app.include_router(employees.router, prefix=api_v1_prefix)
app.include_router(monitoring.router, prefix=api_v1_prefix)
app.include_router(dlp.router, prefix=api_v1_prefix)
app.include_router(url_warning.router, prefix=api_v1_prefix)
app.include_router(alerts.router, prefix=api_v1_prefix)
app.include_router(dashboard.router, prefix=api_v1_prefix)
app.include_router(phishing.router, prefix=api_v1_prefix)
app.include_router(file_analysis.router, prefix=api_v1_prefix)
app.include_router(network.router, prefix=api_v1_prefix)
app.include_router(incidents.router, prefix=api_v1_prefix)
app.include_router(forensics.router, prefix=api_v1_prefix)
app.include_router(events.router, prefix=api_v1_prefix)
app.include_router(system.router, prefix=api_v1_prefix)

@app.get("/")
def read_root():
    return {
        "platform": "CYBERSHIELD AI",
        "edition": "Enterprise 24/7 Security Operations Center",
        "api_docs": "/docs",
        "version": "2.0.0",
        "status": "ONLINE"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)

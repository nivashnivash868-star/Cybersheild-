import logging
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
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
    allow_origins=settings.CORS_ORIGINS,
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

# API Platform Info Endpoint
@app.get("/api")
@app.get("/api/v1")
def read_api_info():
    return {
        "platform": "CYBERSHIELD AI",
        "edition": "Enterprise 24/7 Security Operations Center",
        "api_docs": "/docs",
        "version": "2.0.0",
        "status": "ONLINE"
    }

# Unified Frontend Serving (Single Page Application)
frontend_dist = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"

if frontend_dist.exists() and (frontend_dist / "index.html").exists():
    logger.info(f"Serving integrated frontend UI from {frontend_dist}")

    # Mount static assets directory
    assets_dir = frontend_dist / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    # Serve index.html for root path
    @app.get("/")
    async def serve_root():
        return FileResponse(frontend_dist / "index.html")

    # Catch-all route for SPA client-side routes and static files
    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        # Do not catch API or documentation routes
        if full_path.startswith("api") or full_path in ("docs", "redoc", "openapi.json"):
            return JSONResponse(status_code=404, content={"detail": f"Route '/{full_path}' not found"})

        file_path = frontend_dist / full_path
        if file_path.is_file():
            return FileResponse(file_path)
        return FileResponse(frontend_dist / "index.html")
else:
    logger.info("Frontend dist not found; running in standalone API mode.")
    @app.get("/")
    def read_root():
        return {
            "platform": "CYBERSHIELD AI",
            "edition": "Enterprise 24/7 Security Operations Center",
            "api_docs": "/docs",
            "version": "2.0.0",
            "status": "ONLINE",
            "message": "Frontend build not detected. Run 'npm run build' inside frontend/ to serve the unified UI."
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)

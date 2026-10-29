import asyncio
import logging
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.exc import DataError, IntegrityError
from app.bootstrap import bootstrap_admin
from app.config import settings
from app.database import engine, Base, SessionLocal
from app.services.demo_data_seeder import seed_demo_soc_data
from app.utils import audit as _audit_chain  # noqa: F401  (registers the audit hash-chain hook)
from app.utils.auth import STAFF_ROLES, ALL_ROLES, require_roles
from app.utils.context import client_ip_var, request_id_var
from app.worker import run_forever
from app.routers import (
    dashboard, phishing, file_analysis, network,
    incidents, forensics, events, system,
    auth, employees, monitoring, dlp, url_warning, alerts, users, blocklist, feeds, zetaris, soc, admin, response, sso, threat_intel
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
    
    with SessionLocal() as db:
        if settings.DEMO_MODE:
            logger.warning("DEMO_MODE is on: seeding fabricated demo data with known passwords.")
            logger.info(f"Database seed check: {seed_demo_soc_data(db=db, force_reset=False)}")
        bootstrap_admin(db)

    worker = asyncio.create_task(run_forever()) if settings.OUTBOX_WORKER_ENABLED else None
    logger.info("CYBERSHIELD AI backend started (environment=%s).", settings.ENVIRONMENT)
    yield
    if worker:
        worker.cancel()
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
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None if settings.is_production else "/redoc",
    openapi_url=None if settings.is_production else "/openapi.json",
)

@app.exception_handler(DataError)
async def _data_error(request: Request, exc: DataError):
    """A value the database refused (too long, wrong type). The caller sent bad data: that is a 422, not a crash."""
    logger.warning("Rejected oversized or malformed value on %s %s: %s", request.method, request.url.path, type(exc.orig).__name__)
    return JSONResponse(status_code=422, content={"detail": "A value is too long or in the wrong format."})


@app.exception_handler(IntegrityError)
async def _integrity_error(request: Request, exc: IntegrityError):
    logger.warning("Integrity conflict on %s %s: %s", request.method, request.url.path, type(exc.orig).__name__)
    return JSONResponse(status_code=409, content={"detail": "This conflicts with data that already exists."})


# CORS: only explicitly configured origins (the bundled UI is same-origin and needs none).
if settings.CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "X-CSRF-Token"],
    )

_CSP = (
    "default-src 'self'; img-src 'self' data:; script-src 'self'; connect-src 'self'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; "
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)


@app.middleware("http")
async def request_context_and_headers(request: Request, call_next):
    rid = uuid.uuid4().hex
    t1 = request_id_var.set(rid)
    t2 = client_ip_var.set(request.client.host if request.client else None)
    try:
        response = await call_next(request)
    finally:
        request_id_var.reset(t1)
        client_ip_var.reset(t2)
    response.headers["X-Request-ID"] = rid
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path.startswith("/api") or request.url.path.startswith("/v1"):
        response.headers["Cache-Control"] = "no-store"
    elif not request.url.path.startswith("/docs") and not request.url.path.startswith("/redoc"):
        response.headers["Content-Security-Policy"] = _CSP
    if settings.cookie_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# Deny by default: every router needs a signed-in session and the minimum role below. Routers that need
# stricter or different rules (auth, system, users, blocklist, feeds) declare them per route.
_STAFF = [Depends(require_roles(STAFF_ROLES))]
_ANY_USER = [Depends(require_roles(ALL_ROLES))]
api_routers = [
    (auth.router, []),                       # public routes + per-route session checks
    (sso.router, []),                        # OIDC redirects (public by nature; state/nonce/PKCE protected)
    (system.router, []),                     # /health public; the rest per route
    (feeds.router, []),                      # feed-token auth
    (response.router, []),                   # signed callback (HMAC) + administrators' job list
    (users.router, []),                      # Super Admin per route
    (blocklist.router, []),                  # per route
    (zetaris.router, []),                    # per route
    (soc.router, []),                        # per route
    (admin.router, []),                      # administrators only (per route)
    (employees.router, _ANY_USER),           # staff-only except an employee's own events (per route)
    (monitoring.router, _STAFF), (dlp.router, _STAFF), (alerts.router, _STAFF), (dashboard.router, _STAFF),
    (file_analysis.router, _STAFF), (network.router, _STAFF), (incidents.router, _STAFF),
    (forensics.router, _STAFF), (events.router, _STAFF),
    (phishing.router, _ANY_USER), (url_warning.router, _ANY_USER), (threat_intel.router, []),
]

for router, deps in api_routers:
    app.include_router(router, prefix=settings.API_V1_PREFIX, dependencies=deps)
    # Also support /v1 if hosting service strips /api prefix
    app.include_router(router, prefix="/v1", dependencies=deps)

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

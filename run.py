#!/usr/bin/env python3
"""
CYBERSHIELD AI — Full-Stack Platform Runner
Unifies and launches both the frontend and backend.

Usage:
  python3 run.py             # Launches unified mode: serves both React frontend & FastAPI backend on http://localhost:8000
  python3 run.py --dev       # Launches development mode: Vite dev server (port 5173) + FastAPI backend (port 8000)
"""

import sys
import os
import signal
import subprocess
import argparse
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "backend"
FRONTEND_DIR = ROOT_DIR / "frontend"
FRONTEND_DIST = FRONTEND_DIR / "dist"

VENV_PYTHON = BACKEND_DIR / "venv" / "bin" / "python"
VENV_UVICORN = BACKEND_DIR / "venv" / "bin" / "uvicorn"

# Colors for terminal output
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

processes = []

def signal_handler(sig, frame):
    print(f"\n{YELLOW}Shutting down CYBERSHIELD AI services...{RESET}")
    for p in processes:
        if p.poll() is None:
            p.terminate()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def ensure_venv():
    """Ensure python virtualenv and uvicorn exist."""
    if not VENV_UVICORN.exists():
        print(f"{YELLOW}Virtualenv not found at {VENV_UVICORN}. Using system python/uvicorn...{RESET}")
        return sys.executable, "uvicorn"
    return str(VENV_PYTHON), str(VENV_UVICORN)

def build_frontend():
    """Build frontend dist assets if missing."""
    if not (FRONTEND_DIST / "index.html").exists():
        print(f"{CYAN}Building frontend production bundle...{RESET}")
        result = subprocess.run(["npm", "run", "build"], cwd=str(FRONTEND_DIR))
        if result.returncode != 0:
            print(f"{RED}Frontend build failed with exit code {result.returncode}{RESET}")
            sys.exit(1)
        print(f"{GREEN}✓ Frontend built successfully into {FRONTEND_DIST}{RESET}")
    else:
        print(f"{GREEN}✓ Frontend bundle verified at {FRONTEND_DIST}{RESET}")

def run_unified(host="127.0.0.1", port=8000):
    """Serve unified React SPA + FastAPI backend on a single port."""
    build_frontend()
    py_bin, uvicorn_bin = ensure_venv()
    
    print("\n" + "=" * 65)
    print(f"{BOLD}{CYAN}  🛡️  CYBERSHIELD AI — UNIFIED ENTERPRISE SOC PLATFORM  🛡️{RESET}")
    print("=" * 65)
    print(f"  {GREEN}► Integrated Web Application:{RESET}  http://localhost:{port}/")
    print(f"  {GREEN}► REST API Base:{RESET}              http://localhost:{port}/api/v1")
    print(f"  {GREEN}► Interactive API Docs:{RESET}       http://localhost:{port}/docs")
    print("=" * 65)
    print(f"{YELLOW}Press Ctrl+C to stop the platform.{RESET}\n")

    cmd = [uvicorn_bin, "app.main:app", "--host", host, "--port", str(port)]
    subprocess.run(cmd, cwd=str(BACKEND_DIR))

def run_dev(host="127.0.0.1", backend_port=8000, frontend_port=5173):
    """Run backend (Uvicorn) and frontend (Vite) simultaneously with live-reload."""
    py_bin, uvicorn_bin = ensure_venv()

    print("\n" + "=" * 65)
    print(f"{BOLD}{CYAN}  🛡️  CYBERSHIELD AI — DUAL-SERVICE DEV ENVIRONMENT  🛡️{RESET}")
    print("=" * 65)
    print(f"  {GREEN}► Frontend (Vite HMR):{RESET}       http://localhost:{frontend_port}/")
    print(f"  {GREEN}► Backend (Uvicorn):{RESET}         http://localhost:{backend_port}/")
    print(f"  {GREEN}► Interactive API Docs:{RESET}       http://localhost:{backend_port}/docs")
    print("=" * 65)
    print(f"{YELLOW}Press Ctrl+C to stop both servers.{RESET}\n")

    backend_proc = subprocess.Popen(
        [uvicorn_bin, "app.main:app", "--host", host, "--port", str(backend_port), "--reload"],
        cwd=str(BACKEND_DIR)
    )
    processes.append(backend_proc)

    frontend_proc = subprocess.Popen(
        ["npm", "run", "dev"],
        cwd=str(FRONTEND_DIR)
    )
    processes.append(frontend_proc)

    try:
        backend_proc.wait()
    except KeyboardInterrupt:
        pass

def main():
    parser = argparse.ArgumentParser(description="CYBERSHIELD AI Full-Stack Platform Launcher")
    parser.add_argument("--dev", action="store_true", help="Launch in development mode (Vite dev server + Uvicorn)")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    args = parser.parse_args()

    if args.dev:
        run_dev(host=args.host, backend_port=args.port)
    else:
        run_unified(host=args.host, port=args.port)

if __name__ == "__main__":
    main()

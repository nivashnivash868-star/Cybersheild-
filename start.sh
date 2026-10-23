#!/bin/bash
# CYBERSHIELD AI — One-click Startup Script

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

if [ "$1" = "--dev" ]; then
    echo "Starting CYBERSHIELD AI in Development Mode (Vite + FastAPI)..."
    python3 run.py --dev
else
    echo "Starting CYBERSHIELD AI in Unified Mode (Port 8000)..."
    python3 run.py "$@"
fi

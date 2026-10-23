# ===== Stage 1: Build the React frontend =====
FROM node:22-slim AS frontend-build
WORKDIR /build

# Install dependencies first for better layer caching
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

# Build the production bundle
COPY frontend/ ./
RUN npm run build
# Output is in /build/dist

# ===== Stage 2: Python backend runtime =====
FROM python:3.13-slim

# Install OS dependencies needed by some Python wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/backend

# Install Python dependencies first for better layer caching
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source
COPY backend/ ./

# Copy the built frontend dist so FastAPI can serve it (SPA mode)
# main.py resolves frontend dist as: <repo-root>/frontend/dist
# With backend at /app/backend, repo root is /app, so dist goes to /app/frontend/dist
COPY --from=frontend-build /build/dist /app/frontend/dist

EXPOSE 8000

# Run the FastAPI app, serving both the API (/api/v1) and the SPA (root)
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

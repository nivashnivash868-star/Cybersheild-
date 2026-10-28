# syntax=docker/dockerfile:1

# ===== Stage 1: build the React frontend =====
FROM node:22-slim AS frontend-build
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ===== Stage 2: Python dependencies, built once =====
FROM python:3.13-slim AS python-base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app/backend

# ===== Stage 3: tests (docker build --target test .) =====
FROM python-base AS test
COPY backend/requirements.txt backend/requirements-dev.txt ./
RUN pip install -r requirements-dev.txt
COPY backend/ ./
RUN python -m pytest -q

# ===== Stage 4: runtime image =====
FROM python-base AS runtime
COPY backend/requirements.txt ./
RUN pip install -r requirements.txt \
 && useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin cybershield
COPY --chown=cybershield:cybershield backend/app ./app
# main.py resolves the UI at <repo-root>/frontend/dist, i.e. /app/frontend/dist
COPY --from=frontend-build --chown=cybershield:cybershield /build/dist /app/frontend/dist

USER cybershield
ENV ENVIRONMENT=production
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/system/health', timeout=4).status == 200 else 1)"

# Behind a TLS-terminating proxy (Render, nginx, a load balancer), trust its forwarded headers.
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]

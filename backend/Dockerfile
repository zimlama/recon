# =============================================================================
# zimlama/recon — Backend Dockerfile (multi-stage)
# Build: docker build -t zimlama/recon-backend:0.1.0 backend/
# =============================================================================

# ---- Stage 1: builder ----
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# System deps for building wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# ---- Stage 2: runtime ----
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/home/recon/.local/bin:$PATH \
    PYTHONPATH=/app

# Install runtime system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    tini \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r recon && useradd -r -g recon -m -d /home/recon recon

WORKDIR /app

# Copy Python deps from builder
COPY --from=builder /root/.local /home/recon/.local

# Copy application code
COPY --chown=recon:recon app/ /app/app/
COPY --chown=recon:recon alembic/ /app/alembic/
COPY --chown=recon:recon alembic.ini /app/
COPY --chown=recon:recon pyproject.toml /app/
COPY --chown=recon:recon README.md /app/

# Create data directory
RUN mkdir -p /app/data/handoffs /app/data/reports /app/data/audit /app/data/artifacts \
    && chown -R recon:recon /app/data

USER recon

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/health || exit 1

EXPOSE 8000

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]

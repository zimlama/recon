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

# Install runtime system deps + recon tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    tini \
    whois \
    bind9-dnsutils \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Go + recon tools (subfinder, httpx, waybackurls, katana, gau)
ENV GO_VERSION=1.22.1
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o go.tar.gz \
    && tar -C /usr/local -xzf go.tar.gz \
    && rm go.tar.gz
ENV PATH="/usr/local/go/bin:/home/recon/go/bin:${PATH}" \
    GOPATH=/home/recon/go \
    GOBIN=/home/recon/go/bin

# Create non-root user
RUN groupadd -r recon && useradd -r -g recon -m -d /home/recon recon

WORKDIR /app

# Copy Python deps from builder
COPY --from=builder /root/.local /home/recon/.local

# Install Go-based recon tools as recon user
USER recon
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.3 \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.3.7 \
    && go install github.com/tomnomnom/waybackurls@v0.1.0 \
    && go install -v github.com/projectdiscovery/katana/cmd/katana@latest
USER root

# Copy application code
COPY --chown=recon:recon app/ /app/app/
COPY --chown=recon:recon alembic/ /app/alembic/
COPY --chown=recon:recon alembic.ini /app/
COPY --chown=recon:recon pyproject.toml /app/
COPY --chown=recon:recon README.md /app/

# Create data directory
RUN mkdir -p /app/data/handoffs /app/data/reports /app/data/audit /app/data/artifacts \
    && chown -R recon:recon /app/data

# Ensure recon user owns the Go bin
RUN chown -R recon:recon /home/recon/go

USER recon

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/health || exit 1

EXPOSE 8000

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]

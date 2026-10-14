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
# Architecture-aware: maps `uname -m` → Go tarball suffix so the same
# Dockerfile builds on x86_64 and aarch64 (Graviton, Raspberry Pi, M-series
# Macs running arm64 Linux). Without this, arm64 hosts get
# 'go: Exec format error' (exit 126) when invoking the downloaded binary.
ENV GO_VERSION=1.22.1
RUN set -eux; \
    arch="$(uname -m)"; \
    case "$arch" in \
        x86_64)  go_arch=amd64 ;; \
        aarch64) go_arch=arm64 ;; \
        armv7l|armv6l) go_arch=armv6l ;; \
        *) echo "Unsupported architecture: $arch"; exit 1 ;; \
    esac; \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${go_arch}.tar.gz" -o go.tar.gz \
    && tar -C /usr/local -xzf go.tar.gz \
    && rm go.tar.gz
ENV PATH="/usr/local/go/bin:/home/recon/go/bin:${PATH}" \
    GOPATH=/home/recon/go \
    GOBIN=/home/recon/go/bin \
    # Move Go build cache and temp dirs OUT of /tmp (tmpfs, ~RAM/2, ~2.7 GB
    # on 5 GB hosts — too small for subfinder+katana+httpx+waybackurls combined,
    # which can exceed 3 GB of build artifacts and fail with "no space left on
    # device" mid-compile). Use real disk in /home/recon.
    GOCACHE=/home/recon/.cache/go-build \
    GOMODCACHE=/home/recon/go/pkg/mod \
    TMPDIR=/home/recon/tmp

# Go module proxy. The default `proxy.golang.org` is fine in most networks
# but gets blocked by some corporate firewalls, Pi-hole setups, and local
# DNS filters (symptom: "dial tcp: lookup proxy.golang.org: no such host").
# Override at build time with:
#   docker compose build --build-arg GOPROXY=https://goproxy.cn,direct
# Common mirrors: goproxy.io, goproxy.cn, goproxy.io/goproxy, mirrors.aliyun.com/goproxy/
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}

# Create non-root user
RUN groupadd -r recon && useradd -r -g recon -m -d /home/recon recon \
    && mkdir -p /home/recon/.cache/go-build /home/recon/go/pkg/mod /home/recon/tmp \
    && chown -R recon:recon /home/recon

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

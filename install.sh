#!/usr/bin/env bash
# =============================================================================
# zimlama/recon — Installer
# Detects mac/linux, verifies Docker, bootstraps .env, builds + starts services.
# Idempotent — safe to re-run.
# =============================================================================

set -euo pipefail

# ---- Colors (only if TTY) ----
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' NC=''
fi

# ---- Helpers ----
log()  { printf "${BLUE}>>>${NC} %s\n" "$*"; }
ok()   { printf "${GREEN}✅${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}⚠️ ${NC} %s\n" "$*"; }
die()  { printf "${RED}❌${NC} %s\n" "$*" >&2; exit 1; }

banner() {
    cat <<'EOF'

  ███████╗██╗███╗   ███╗██╗      █████╗ ███╗   ███╗ █████╗
  ╚══███╔╝██║████╗ ████║██║     ██╔══██╗████╗ ████║██╔══██╗
    ███╔╝ ██║██╔████╔██║██║     ███████║██╔████╔██║███████║
   ███╔╝  ██║██║╚██╔╝██║██║     ██╔══██║██║╚██╔╝██║██╔══██║
  ███████╗██║██║ ╚═╝ ██║███████╗██║  ██║██║ ╚═╝ ██║██║  ██║
  ╚══════╝╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝

  Recon Phase 1 — Installer

EOF
}

# ---- Sanity checks ----
banner

# 1. Working directory must be repo root
if [ ! -f "docker-compose.yml" ] || [ ! -f ".env.example" ]; then
    die "Run this from the repo root (where docker-compose.yml lives)."
fi

# 2. Detect OS
OS_RAW="$(uname -s)"
case "$OS_RAW" in
    Darwin) OS=mac ;;
    Linux)
        OS=linux
        # WSL detection
        if grep -qiE "microsoft|wsl" /proc/version 2>/dev/null; then
            OS=wsl
        fi
        ;;
    *) die "Unsupported OS: $OS_RAW. Use macOS, Linux, or WSL." ;;
esac
log "Detected OS: $OS"

# 3. Verify Docker
command -v docker >/dev/null 2>&1 || die "Docker not installed. Install Docker Desktop: https://www.docker.com/products/docker-desktop"
docker info >/dev/null 2>&1 || die "Docker daemon not running. Start Docker Desktop."
ok "Docker present"

# 4. Verify Docker Compose v2
if ! docker compose version >/dev/null 2>&1; then
    die "Docker Compose v2 not installed. Update Docker Desktop or install compose-plugin."
fi
COMPOSE_VERSION="$(docker compose version --short)"
ok "Docker Compose v$COMPOSE_VERSION"

# 5. Verify git
command -v git >/dev/null 2>&1 || die "git not installed"
ok "git present"

# ---- Bootstrap .env ----
if [ ! -f ".env" ]; then
    log "Creating .env from .env.example"
    cp .env.example .env
    chmod 600 .env
    ok ".env created"
else
    log ".env already exists — keeping current values"
fi

# 6. Prompt for API key (masked input)
CURRENT_KEY="$(grep -E '^MINIMAX_API_KEY=' .env | cut -d= -f2- || true)"
if [ -z "$CURRENT_KEY" ] || [ "$CURRENT_KEY" = "sk-minimax-replace-with-real-key" ]; then
    log "Configuring MiniMax M3 API key (input is hidden)"
    API_KEY=""
    while [ -z "$API_KEY" ]; do
        if [ -t 0 ]; then
            read -r -s -p "  MINIMAX_API_KEY (sk-...): " API_KEY
            echo
        else
            # Non-interactive (CI) — fail
            die "MINIMAX_API_KEY is required. Set it in .env manually or run interactively."
        fi
        if [ -z "$API_KEY" ]; then
            warn "API key cannot be empty. Try again."
        fi
    done

    # Replace in .env (cross-platform sed)
    if [ "$OS" = "mac" ]; then
        sed -i '' "s|^MINIMAX_API_KEY=.*|MINIMAX_API_KEY=$API_KEY|" .env
    else
        sed -i "s|^MINIMAX_API_KEY=.*|MINIMAX_API_KEY=$API_KEY|" .env
    fi
    ok "API key set in .env"
else
    log "MINIMAX_API_KEY already configured — keeping current value"
fi

# ---- Build + start ----
log "Building Docker images (this may take 5-10 min on first run)..."
docker compose build

log "Starting services (production profile)..."
docker compose --profile prod up -d

# ---- Health check ----
log "Waiting for backend to be healthy..."
for i in {1..30}; do
    if curl -fsS http://localhost:8000/health >/dev/null 2>&1; then
        ok "Backend is up"
        break
    fi
    if [ "$i" -eq 30 ]; then
        warn "Backend did not respond within 30s. Check: docker compose logs backend"
    fi
    sleep 1
done

log "Waiting for frontend to be healthy..."
for i in {1..30}; do
    if curl -fsS http://localhost:8080 >/dev/null 2>&1; then
        ok "Frontend is up"
        break
    fi
    if [ "$i" -eq 30 ]; then
        warn "Frontend did not respond within 30s. Check: docker compose logs frontend"
    fi
    sleep 1
done

# ---- Done ----
cat <<EOF

${GREEN}🎉 Installation complete!${NC}

  🌐 Frontend:    http://localhost:8080
  🔌 Backend API: http://localhost:8000
  📚 API docs:    http://localhost:8000/docs
  📂 Data:        ./data/

  ${YELLOW}Quick commands:${NC}
     make logs         # tail all logs
     make shell-backend  # shell into backend container
     make test         # run all tests
     make down         # stop everything
     make help         # show all targets

  ${YELLOW}First steps:${NC}
     1. Open http://localhost:8080
     2. Click "New Job" → enter target domain
     3. Accept the pentester responsibility modal
     4. Watch the recon run

  ${RED}⚠️  Use only on systems you have WRITTEN AUTHORIZATION to test.${NC}

EOF

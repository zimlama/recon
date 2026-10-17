#!/usr/bin/env bash
# =============================================================================
# zimlama/recon — Installer v0.2.5
# Auto-installs system prerequisites (git, python3, Docker), then runs an
# interactive wizard for every API key, auto-generates local secrets
# (Fernet + SECRET), reports which external binaries are missing, builds
# + starts services, and finishes with a self-test pass that verifies
# every configured integration.
#
# Idempotent: safe to re-run. Existing .env values are kept unless you type
# a new value. Backwards compatible with bash 3.2 (macOS default).
#
# Supported OSes: macOS (Homebrew), Ubuntu/Debian (apt), Fedora/RHEL (dnf),
# Arch/Manjaro (pacman), WSL (treated as the underlying distro).
# Use --skip-prereqs to bypass auto-install.
# =============================================================================

set -euo pipefail

# ---- CLI flags (parsed early, before any output) ----------------------------
SKIP_PREREQS=0
# Preserve original args (quoted) for re-exec via `sg docker` when the user's
# docker group membership hasn't propagated to this session yet.
SCRIPT_ARGS=""
for arg in "$@"; do
  case "$arg" in
    --skip-prereqs) SKIP_PREREQS=1 ;;
    -h|--help)
      printf "Usage: %s [--skip-prereqs]\n  --skip-prereqs  skip the system-prereq install block (use if you already have git/python3/Docker)\n" "$0"
      exit 0
      ;;
    *) SCRIPT_ARGS="$SCRIPT_ARGS $(printf '%q' "$arg")" ;;
  esac
done
SCRIPT_ARGS="${SCRIPT_ARGS# }"

# ---- Colors (only if TTY) ----
if [ -t 1 ]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  BLUE='\033[0;34m'
  CYAN='\033[0;36m'
  BOLD='\033[1m'
  NC='\033[0m'
else
  RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' NC=''
fi

log()    { printf "${BLUE}>>>${NC} %s\n" "$*"; }
ok()     { printf "${GREEN} ✅${NC} %s\n" "$*"; }
warn()   { printf "${YELLOW} ⚠ ${NC} %s\n" "$*"; }
err()    { printf "${RED} ✗${NC} %s\n" "$*"; }
section(){ printf "\n${CYAN}${BOLD}═══ %s ═══${NC}\n" "$*"; }
die()    { err "$*"; printf "\n${RED}Install aborted.${NC} Fix the issue above and re-run.\n" >&2; exit 1; }

# ---- Source install_lib.sh (detection + install helpers) -------------------
# Sourced AFTER color/log helpers so ensure_* functions can use them.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=install_lib.sh
. "${SCRIPT_DIR}/install_lib.sh"

banner() {
  cat <<'EOF'

    ███████╗██╗███╗   ███╗██╗      █████╗ ███╗   ███╗ █████╗
    ╚══███╔╝██║████╗ ████║██║     ██╔══██╗████╗ ████║██╔══██╗
      ███╔╝ ██║██╔████╔██║██║     ███████║██╔████╔██║███████║
     ███╔╝  ██║██║╚██╔╝██║██║     ██╔══██║██║╚██╔╝██║██╔══██║
    ███████╗██║██║ ╚═╝ ██║███████╗██║  ██║██║ ╚═╝ ██║██║  ██║
    ╚══════╝╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝

    Recon Phase 1 — Installer v0.2.5
    Self-testing wizard. Idempotent. Re-run any time.

EOF
}

# Track test results across the self-test section
TESTS_PASSED=0
TESTS_FAILED=0
TEST_FAILURES=""

record_pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); }
record_fail() {
  TESTS_FAILED=$((TESTS_FAILED + 1))
  TEST_FAILURES="${TEST_FAILURES}\n  • $1"
}

# Print a masked preview of a secret value, e.g. "sk-abc...xyz"
mask() {
  local v="${1:-}"
  if [ -z "$v" ]; then printf "(empty)"; return; fi
  if [ "${#v}" -le 12 ]; then printf "%s" "$v"; return; fi
  printf "%s...%s" "${v:0:6}" "${v: -4}"
}

# Read the current value of a key from .env, or empty string
get_env() {
  local key="$1"
  awk -F= -v k="$key" '$1==k { sub(/^[^=]*=/, "", $0); print; exit }' .env 2>/dev/null
}

# Set (or replace) a key in .env. Cross-platform, safe for arbitrary values
# (including '|', '&', '\', quotes, newlines). Uses awk because sed's
# delimiter + escape rules for the replacement half are fragile: values
# containing an unescaped '|' terminate the `s|...|...|` command early on
# BSD sed, and GNU sed's '\1' back-reference interacts badly with shell
# quoting when the value contains digits. Awk just prints the line — no
# special-char interpretation.
set_env() {
  local key="$1"
  local value="$2"
  local tmp
  tmp="$(mktemp)"
  # index($0, k "=") == 1 matches lines that BEGIN with KEY= (no leading
  # whitespace, exact key boundary). The END block appends KEY=value if
  # the key was not present.
  if ! awk -v k="$key" -v v="$value" '
    {
      if (index($0, k "=") == 1) {
        print k "=" v
        found = 1
        next
      }
      print
    }
    END {
      if (!found) print k "=" v
    }
  ' .env > "$tmp"; then
    rm -f "$tmp"
    die "set_env: awk failed while writing key=$key"
  fi
  mv "$tmp" .env
}

# Ask for an OPTIONAL value. Empty input is allowed and means "skip".
# Echoes the value to stdout so the caller can act on it.
ask_optional() {
  local var_name="$1"
  local help="$2"
  local current="$3"

  if [ ! -t 0 ]; then
    printf "%s" "$current"
    return 0
  fi

  local prompt="  ${var_name}"
  if [ -n "$current" ]; then
    prompt="${prompt} ${CYAN}[current: $(mask "$current") — Enter to keep]${NC}"
  else
    prompt="${prompt} ${CYAN}[Enter to skip]${NC}"
  fi
  # Print prompt to stderr (>/dev/tty if available) and read input separately.
  # See ask_secret() for why split print + read matters under PTY.
  if [ -w /dev/tty ]; then
    printf "%s\n  %s\n  > " "$prompt" "$help" >/dev/tty
  else
    printf "%s\n  %s\n  > " "$prompt" "$help" >&2
  fi

  local value
  IFS= read -r value </dev/tty 2>/dev/null || IFS= read -r value
  if [ -z "$value" ]; then
    printf "%s" "$current"
  else
    printf "%s" "$value"
  fi
}

# Ask for a SECRET value. Input is masked. Empty input means "keep current".
# Echoes the value to stdout so the caller can act on it.
ask_secret() {
  local var_name="$1"
  local help="$2"
  local current="$3"
  local required="${4:-false}"

  if [ ! -t 0 ]; then
    printf "%s" "$current"
    return 0
  fi

  local prompt="  ${var_name}"
  if [ -n "$current" ]; then
    prompt="${prompt} ${CYAN}[current: $(mask "$current") — Enter to keep]${NC}"
  else
    prompt="${prompt} ${CYAN}[required, no default]${NC}"
  fi
  # Print prompt to stderr (>/dev/tty if available) and read input separately.
  # Using `read -p` echoes the prompt string back through the PTY in some
  # terminal configurations (tmux, screen, `script`, certain SSH clients),
  # causing read to capture the prompt text as the value. Splitting print and
  # read, with the print on stderr, avoids that round-trip.
  if [ -w /dev/tty ]; then
    printf "%s\n  %s\n  > " "$prompt" "$help" >/dev/tty
  else
    printf "%s\n  %s\n  > " "$prompt" "$help" >&2
  fi

  local value
  while true; do
    IFS= read -r -s value </dev/tty 2>/dev/null || IFS= read -r -s value
    echo >/dev/tty 2>/dev/null || echo >&2
    if [ -z "$value" ] && [ "$required" = "true" ] && [ -z "$current" ]; then
      warn "  ${var_name} is required. Get one at the link above."
      if [ -w /dev/tty ]; then printf "  > " >/dev/tty; else printf "  > " >&2; fi
      continue
    fi
    break
  done

  if [ -z "$value" ]; then
    printf "%s" "$current"
  else
    printf "%s" "$value"
  fi
}

# Ask a yes/no question. Default if Enter.
ask_yn() {
  local question="$1"
  local default="$2"  # "y" or "n"

  if [ ! -t 0 ]; then
    [ "$default" = "y" ] && return 0 || return 1
  fi

  local hint
  if [ "$default" = "y" ]; then hint="[Y/n]"; else hint="[y/N]"; fi

  local reply
  read -r -p "  ${question} ${hint}: " reply
  reply="${reply:-$default}"
  case "${reply,,}" in
    y|yes) return 0 ;;
    *)     return 1 ;;
  esac
}

# =============================================================================
# STEP 0 — System prerequisites (auto-install)
# =============================================================================
section "Step 0/8 — System prerequisites"
ensure_prereqs

# =============================================================================
# STEP 1 — Pre-flight checks
# =============================================================================
section "Step 1/8 — Pre-flight checks"
banner

# 1.1 Working directory
if [ ! -f "docker-compose.yml" ] || [ ! -f ".env.example" ]; then
  die "Run this from the repo root (the directory with docker-compose.yml and .env.example)."
fi
ok "Repo root detected"

# 1.2 OS detection
OS_RAW="$(uname -s)"
case "$OS_RAW" in
  Darwin) OS=mac ;;
  Linux)
    OS=linux
    if grep -qiE "microsoft|wsl" /proc/version 2>/dev/null; then
      OS=wsl
    fi
    ;;
  *) die "Unsupported OS: $OS_RAW. Supported: macOS, Linux, WSL." ;;
esac
log "Detected OS: ${BOLD}${OS}${NC}"

# 1.3 Docker
if [ "${DOCKER_REQUIRES_RELOGIN:-0}" = "1" ] && command -v sg >/dev/null 2>&1; then
  # Step 0 just added us to the docker group; the change hasn't propagated
  # to this shell session. Re-exec via `sg docker` to pick it up inline.
  log "Re-executing installer with 'docker' group active (one-shot group fix)..."
  exec sg docker -c "$(realpath "$0") $SCRIPT_ARGS"
fi
if ! command -v docker >/dev/null 2>&1; then
  die "Docker is not installed. Get it at: https://www.docker.com/products/docker-desktop"
fi
if ! docker info >/dev/null 2>&1; then
  die "Docker daemon is not running. Start Docker Desktop (or 'sudo systemctl start docker' on Linux)."
fi
ok "Docker daemon reachable"

# 1.4 Compose v2
if ! docker compose version >/dev/null 2>&1; then
  die "Docker Compose v2 not installed. Update Docker Desktop or install the compose-plugin (apt install docker-compose-plugin)."
fi
ok "Docker Compose v$(docker compose version --short 2>/dev/null || echo '2')"

# 1.5 git
command -v git >/dev/null 2>&1 || die "git not installed. Install with: brew install git / apt install git"
ok "git present"

# 1.6 Python (needed for key generation + Fernet check)
if ! command -v python3 >/dev/null 2>&1; then
  warn "python3 not found. Auto-generation of SECRET_KEY and PERSON_DOSSIER_ENCRYPTION_KEY will be skipped."
  PYTHON_AVAILABLE=false
else
  PYTHON_AVAILABLE=true
  ok "python3 present: $(python3 --version 2>&1 | awk '{print $2}')"
  if ! python3 -c "from cryptography.fernet import Fernet" 2>/dev/null; then
    warn "python3 'cryptography' module not installed. PERSON_DOSSIER_ENCRYPTION_KEY auto-gen disabled."
    warn "  Install: pip3 install cryptography   (or let Docker handle it — backend image includes it)"
    FERNET_AVAILABLE=false
  else
    FERNET_AVAILABLE=true
  fi
fi

# =============================================================================
# STEP 2 — Bootstrap .env
# =============================================================================
section "Step 2/8 — Environment file"

if [ ! -f ".env" ]; then
  log "Creating .env from .env.example (mode 600 — owner only)"
  cp .env.example .env
  chmod 600 .env
  ok ".env created"
else
  log ".env already exists. Existing values will be kept unless you type a new one."
fi

# =============================================================================
# STEP 3 — Wizard: required keys
# =============================================================================
section "Step 3/8 — Required keys (1)"

log "The LLM powers AI validation. Without it, jobs still run in 'stub mode'"
log "  (findings are produced but not AI-classified). Get a key at the link below."
log ""

current="$(get_env MINIMAX_API_KEY)"
new_value="$(ask_secret 'MINIMAX_API_KEY' 'M Plan Subscription Key: https://platform.minimax.io/user-center/payment/token-plan  |  Pay-as-you-go: https://platform.minimax.io/user-center/basic-information/interface-key' "$current" true)"
if [ -n "$new_value" ] && [ "$new_value" != "$current" ]; then
  set_env MINIMAX_API_KEY "$new_value"
  ok "MINIMAX_API_KEY set"
else
  log "MINIMAX_API_KEY unchanged"
fi

# =============================================================================
# STEP 4 — Wizard: auto-generated local secrets
# =============================================================================
section "Step 4/8 — Local secrets (auto-generated)"

# 4.1 SECRET_KEY
current="$(get_env SECRET_KEY)"
if [ -n "$current" ] && [ "$current" != "change-me-in-production-this-is-only-for-local-dev" ]; then
  log "SECRET_KEY already set (keeping current value: $(mask "$current"))"
else
  if [ "$PYTHON_AVAILABLE" = "true" ]; then
    generated="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
    set_env SECRET_KEY "$generated"
    ok "SECRET_KEY auto-generated: $(mask "$generated")"
    warn "  Back up this key. If you lose it, all signed tokens become invalid."
  else
    warn "Cannot auto-generate SECRET_KEY (python3 missing). Edit .env manually."
  fi
fi

# 4.2 PERSON_DOSSIER_ENCRYPTION_KEY
current="$(get_env PERSON_DOSSIER_ENCRYPTION_KEY)"
if [ -n "$current" ]; then
  log "PERSON_DOSSIER_ENCRYPTION_KEY already set (keeping current value: $(mask "$current"))"
else
  if [ "$FERNET_AVAILABLE" = "true" ]; then
    generated="$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
    set_env PERSON_DOSSIER_ENCRYPTION_KEY "$generated"
    ok "PERSON_DOSSIER_ENCRYPTION_KEY auto-generated: $(mask "$generated")"
    warn "  CRITICAL: back this up in a password manager."
    warn "  If you lose it, encrypted data in 'identity_map' is unrecoverable forever."
    warn "  Key rotation is not supported in v0.2.x (tracked for v0.3.0)."
  else
    warn "Cannot auto-generate PERSON_DOSSIER_ENCRYPTION_KEY (cryptography missing)."
    warn "  Edit .env manually with: python3 -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
  fi
fi

# =============================================================================
# STEP 5 — Wizard: optional API keys
# =============================================================================
section "Step 5/8 — Optional API keys (free + paid)"

log "Each one is skippable. Press Enter on any prompt to skip."
log "Full guide: docs/EXTERNAL_SERVICES.md"
log ""

# 5.1 Censys
log "${BOLD}Censys Search${NC} — free 250 queries/mo. Enriches shodan_censys with CVEs/services/geo."
log "  Get credentials: https://search.censys.io/register"
current_id="$(get_env CENSYS_API_ID)"
new_id="$(ask_optional 'CENSYS_API_ID' 'API ID from the Censys account page.' "$current_id")"
if [ -n "$new_id" ] && [ "$new_id" != "$current_id" ]; then
  set_env CENSYS_API_ID "$new_id"
  ok "CENSYS_API_ID set"
fi

# Only ask for SECRET if ID was provided (now or previously)
current_secret="$(get_env CENSYS_API_SECRET)"
have_id="$(get_env CENSYS_API_ID)"
if [ -n "$have_id" ]; then
  new_secret="$(ask_secret 'CENSYS_API_SECRET' 'API Secret from the same Censys account page.' "$current_secret" false)"
  if [ -n "$new_secret" ] && [ "$new_secret" != "$current_secret" ]; then
    set_env CENSYS_API_SECRET "$new_secret"
    ok "CENSYS_API_SECRET set"
  fi
fi

# 5.2 GitHub
log ""
log "${BOLD}GitHub personal access token${NC} — free with any account. 5000 req/h with token vs 60 without."
log "  Generate (classic, no scopes): https://github.com/settings/tokens"
current="$(get_env GITHUB_TOKEN)"
new_value="$(ask_secret 'GITHUB_TOKEN' 'Classic token with no scopes is enough for public recon.' "$current" false)"
if [ -n "$new_value" ] && [ "$new_value" != "$current" ]; then
  set_env GITHUB_TOKEN "$new_value"
  ok "GITHUB_TOKEN set"
fi

# 5.3 SerpAPI
log ""
log "${BOLD}SerpAPI${NC} — free 100/mo. Enables real Google dorking instead of curated GHDB templates."
log "  Sign up: https://serpapi.com/"
current="$(get_env SERP_API_KEY)"
new_value="$(ask_secret 'SERP_API_KEY' 'Private API key from the SerpAPI dashboard.' "$current" false)"
if [ -n "$new_value" ] && [ "$new_value" != "$current" ]; then
  set_env SERP_API_KEY "$new_value"
  ok "SERP_API_KEY set"
fi

# 5.4 HIBP
log ""
log "${BOLD}HIBP (Have I Been Pwned)${NC} — paid \$3.50/mo. Removes 429s on breach_data module."
log "  Subscribe: https://haveibeenpwned.com/API/Key"
current="$(get_env HIBP_API_KEY)"
new_value="$(ask_secret 'HIBP_API_KEY' 'API key from the HIBP account page after subscribing.' "$current" false)"
if [ -n "$new_value" ] && [ "$new_value" != "$current" ]; then
  set_env HIBP_API_KEY "$new_value"
  ok "HIBP_API_KEY set"
fi

# 5.5 RECON_API_KEY (Bearer auth, optional)
log ""
log "${BOLD}RECON_API_KEY${NC} — optional Bearer token to lock all business routes."
log "  Leave empty for dev (no auth). For production, generate one and set it."
current="$(get_env RECON_API_KEY)"
new_value="$(ask_secret 'RECON_API_KEY' 'secrets.token_urlsafe(32). When set, every request needs: Authorization: Bearer <key>' "$current" false)"
if [ -n "$new_value" ] && [ "$new_value" != "$current" ]; then
  set_env RECON_API_KEY "$new_value"
  ok "RECON_API_KEY set — auth is now enforced"
fi

# 5.6 ROE_ENABLED
log ""
log "${BOLD}RoE (Rules of Engagement) enforcement${NC} — opt-in. When true, POST /jobs requires"
log "  an active RoE for the target. Recommended for production."
current="$(get_env ROE_ENABLED)"
if [ "$current" = "true" ]; then
  log "ROE_ENABLED is already true (keeping)"
else
  if ask_yn "Enable ROE enforcement?" "n"; then
    set_env ROE_ENABLED true
    ok "ROE_ENABLED=true"
  else
    set_env ROE_ENABLED false
    log "ROE_ENABLED=false (jobs accepted without RoE check)"
  fi
fi

# =============================================================================
# STEP 6 — External binaries check
# =============================================================================
section "Step 6/8 — External binaries (informational)"

log "Required (used by dns_enum, mostly built-in on macOS):"
for bin in dig host; do
  if command -v "$bin" >/dev/null 2>&1; then
    ok "  $bin — $(command -v "$bin")"
  else
    warn "  $bin — NOT FOUND (dns_enum may fail or skip)"
  fi
done

log ""
log "Optional (modules degrade gracefully if missing):"
MISSING_BINARIES=""
for bin in subfinder exiftool theHarvester gh gitleaks gau waybackurls recon-ng sherlock; do
  if command -v "$bin" >/dev/null 2>&1; then
    ok "  $bin — $(command -v "$bin")"
  else
    printf "  "
    warn "$bin — not installed"
    MISSING_BINARIES="${MISSING_BINARIES} $bin"
  fi
done

if [ -n "$MISSING_BINARIES" ]; then
  log ""
  log "Install missing binaries per docs/EXTERNAL_SERVICES.md §Tier 0."
  log "The app will still run without them — affected modules just produce less data."
fi

# =============================================================================
# STEP 7 — Build + start + self-tests
# =============================================================================
section "Step 7/8 — Build, start, self-test"

# 7.0 Reachability pre-check for Go module proxy.
# Some networks (corporate firewalls, Pi-hole, MikroTik DNS filters) block
# proxy.golang.org, which makes `go install` fail mid-build with
# "lookup proxy.golang.org: no such host". Detect that here and suggest a
# mirror via the GOPROXY env var so the user fixes it before the build dies.
GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"
GOPROXY_HOST="$(printf '%s' "$GOPROXY" | sed -E 's|^https?://||; s|/.*$||; s|,direct$||')"
if ! getent hosts "$GOPROXY_HOST" >/dev/null 2>&1; then
  warn "Go module proxy ${GOPROXY_HOST} does not resolve from this host."
  warn "  Likely blocked by local DNS / firewall / Pi-hole."
  warn "  Re-run with a mirror:"
  warn "    GOPROXY=https://goproxy.io,direct  ./install.sh"
  warn "    GOPROXY=https://goproxy.cn,direct   ./install.sh"
  warn "    GOPROXY=https://mirrors.aliyun.com/goproxy/,direct  ./install.sh"
  warn "  Continuing anyway — the build may still succeed if your DNS"
  warn "  resolves inside the Docker build context but not from the host."
fi
export GOPROXY

# 7.1 Build
log "Building Docker images (first run takes 5-10 min)..."
if ! docker compose build 2>&1 | tee /tmp/recon-install-build.log; then
  printf "\n"
  die "Docker build failed. Diagnostics:
    • Port already in use:    docker compose ps ; lsof -i :8000 ; lsof -i :8080
    • Out of disk space:      docker system df
    • Network/proxy issues:   check .env for HTTPS_PROXY / NO_PROXY
    • Go module proxy blocked:
        re-run with:  GOPROXY=https://goproxy.io,direct ./install.sh
    Full log: /tmp/recon-install-build.log"
fi
ok "Images built"

# 7.1.5 Fix data-dir permissions so the bind mount is writable by the
# 'recon' user inside the container (UID 999). The bind mount preserves
# host-side ownership, so if ./data is owned by root:root (mode 755)
# the SQLite database open fails with 'unable to open database file'
# on startup. chmod 777 is overkill but it's the only safe mode that
# works across all host UIDs (some hosts run docker with user namespace
# remapping, some don't).
chmod 777 ./data 2>/dev/null || warn "Could not chmod 777 ./data (non-fatal — runtime will surface the error if it matters)"

# 7.2 Start
log "Starting services (prod profile)..."
if ! docker compose --profile prod up -d 2>&1 | tee /tmp/recon-install-up.log; then
  printf "\n"
  die "docker compose up failed. Common causes:
    • .env syntax error (run: bash -n install.sh is not enough — check with: grep -E '^[A-Z]' .env)
    • Port 8000 or 8080 already in use:  lsof -i :8000 -i :8080
    • Docker out of memory:               docker system df
    Full log: /tmp/recon-install-up.log"
fi
ok "Services started"

# 7.3 Wait for backend
log "Waiting for backend to become healthy (up to 60s)..."
BACKEND_OK=false
for i in $(seq 1 60); do
  if curl -fsS http://localhost:8000/health >/dev/null 2>&1; then
    ok "Backend is healthy (after ${i}s)"
    BACKEND_OK=true
    break
  fi
  if [ "$i" -eq 60 ]; then
    die "Backend did not respond within 60s. Diagnose:
    • docker compose ps                     (are all services Up?)
    • docker compose logs backend --tail=100
    • curl -v http://localhost:8000/health
    If you see a 'module import' error, the .env may be malformed."
  fi
  sleep 1
done

# 7.4 Wait for frontend
log "Waiting for frontend to become healthy (up to 60s)..."
FRONTEND_OK=false
for i in $(seq 1 60); do
  if curl -fsS http://localhost:8080 >/dev/null 2>&1; then
    ok "Frontend is healthy (after ${i}s)"
    FRONTEND_OK=true
    break
  fi
  if [ "$i" -eq 60 ]; then
    warn "Frontend did not respond within 60s. The backend is up at :8000."
    warn "  Diagnose: docker compose logs frontend"
    break
  fi
  sleep 1
done

# 7.5 Self-tests
log ""
log "Running self-tests (verifying every integration actually works)..."
log ""

# We allow individual tests to fail without aborting the script — we want to
# run all of them and report a summary at the end.
set +e

# Helper: run a self-test and record the outcome
self_test() {
  local name="$1"
  local cmd="$2"
  local fix="$3"

  printf "  %-50s " "$name"
  if eval "$cmd" >/dev/null 2>&1; then
    printf "${GREEN}PASS${NC}\n"
    record_pass
  else
    printf "${RED}FAIL${NC}\n"
    record_fail "${name} — ${fix}"
  fi
}

# Capture RECON_API_KEY for use in tests T2 and T3 (both require Bearer auth
# after the JWT hardening in PRs #70-#74). Falls back to empty string so curl
# without the header still attempts (and produces a clear 401 if missing).
recon_api_key="$(get_env RECON_API_KEY)"

# T1: backend /health
self_test "Backend /health" \
  "curl -fsS http://localhost:8000/health" \
  "docker compose logs backend"

# T2: /health/ready (probes DB + LLM dependency)
self_test "Backend /health/ready (DB + LLM)" \
  "curl -fsS -H 'Authorization: Bearer ${recon_api_key}' http://localhost:8000/health/ready" \
  "Check: docker compose logs backend | tail -50. If 'DB fail', verify DATABASE_URL. If 'LLM fail', verify MINIMAX_API_KEY. If 'unauthorized', ensure ALLOW_LEGACY_API_KEY=true or set RECON_API_KEY in .env."

# T3: module registry
self_test "Module registry returns modules" \
  "curl -fsS -H 'Authorization: Bearer ${recon_api_key}' http://localhost:8000/api/v1/modules | python3 -c 'import sys,json; assert len(json.load(sys.stdin)) > 0'" \
  "Backend did not load modules. Check: docker compose logs backend | grep -i 'module\\|registry'. If 'unauthorized', set RECON_API_KEY in .env or ALLOW_LEGACY_API_KEY=true."

# T4-T8: API key validation
minimax="$(get_env MINIMAX_API_KEY)"
if [ -n "$minimax" ] && [ "$minimax" != "sk-minimax-replace-with-real-key" ]; then
  base_url="$(get_env MINIMAX_BASE_URL)"
  base_url="${base_url:-https://api.minimax.io/anthropic/v1}"
  model="$(get_env MINIMAX_MODEL)"
  model="${model:-MiniMax-M3.1-Flash-Preview}"
  self_test "MiniMax API authentication (Anthropic Messages)" \
    "curl -fsS -X POST '${base_url}/messages' -H 'x-api-key: ${minimax}' -H 'anthropic-version: 2023-06-01' -H 'Content-Type: application/json' -d '{\"model\":\"${model}\",\"max_tokens\":10,\"system\":\"Reply with just the word OK.\",\"messages\":[{\"role\":\"user\",\"content\":\"OK\"}]}'" \
    "Wrong key, out of credits, or wrong model. M Plan: https://platform.minimax.io/user-center/payment/token-plan  |  Pay-as-you-go: https://platform.minimax.io/user-center/basic-information/interface-key"
else
  printf "  %-50s ${YELLOW}SKIP${NC} (key not set — running in stub mode)\n" "MiniMax API authentication"
fi

gh_token="$(get_env GITHUB_TOKEN)"
if [ -n "$gh_token" ]; then
  self_test "GitHub API (5000 req/h with token)" \
    "curl -fsS -H 'Authorization: Bearer ${gh_token}' https://api.github.com/rate_limit | python3 -c 'import sys,json; assert json.load(sys.stdin)[\"rate\"][\"limit\"] == 5000'" \
    "Token invalid or wrong type. Regenerate (classic): https://github.com/settings/tokens"
fi

censys_id="$(get_env CENSYS_API_ID)"
censys_secret="$(get_env CENSYS_API_SECRET)"
if [ -n "$censys_id" ] && [ -n "$censys_secret" ]; then
  self_test "Censys Search API authentication" \
    "curl -fsS -u '${censys_id}:${censys_secret}' https://search.censys.io/api/v1/hosts/8.8.8.8 | python3 -c 'import sys,json; d=json.load(sys.stdin); assert \"ip\" in d'" \
    "Wrong credentials. Verify: https://search.censys.io/account/api"
fi

serp="$(get_env SERP_API_KEY)"
if [ -n "$serp" ]; then
  self_test "SerpAPI authentication" \
    "curl -fsS 'https://serpapi.com/search?q=test&api_key=${serp}' | python3 -c 'import sys,json; assert json.load(sys.stdin)[\"search_metadata\"][\"status\"] == \"Success\"'" \
    "Wrong key. Verify: https://serpapi.com/dashboard"
fi

hibp="$(get_env HIBP_API_KEY)"
if [ -n "$hibp" ]; then
  self_test "HIBP API authentication" \
    "curl -fsS -H 'hibp-api-key: ${hibp}' https://api.haveibeenpwned.com/range/21DA1 | head -1 | grep -qE '^[A-F0-9]{35}:'" \
    "Wrong key or subscription inactive. Verify: https://haveibeenpwned.com/API/Key"
fi

# Fernet key works
fernet="$(get_env PERSON_DOSSIER_ENCRYPTION_KEY)"
if [ -n "$fernet" ] && [ "$FERNET_AVAILABLE" = "true" ]; then
  self_test "Fernet encryption key valid" \
    "PERSON_DOSSIER_ENCRYPTION_KEY='${fernet}' python3 -c 'from cryptography.fernet import Fernet; import os; f=Fernet(os.environ[\"PERSON_DOSSIER_ENCRYPTION_KEY\"].encode()); assert f.decrypt(f.encrypt(b\"x\")) == b\"x\"'" \
    "Key is malformed. Regenerate: python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
fi

# Docker containers
# Note: docker compose --format json emits NDJSON (one JSON object per line,
# NOT a single JSON array). Use json.loads per iteration, not json.load once.
self_test "Docker containers running" \
  "[ \$(docker compose ps --format json 2>/dev/null | python3 -c 'import sys,json; print(sum(1 for line in sys.stdin if line.strip() and json.loads(line).get(\"State\") == \"running\"))' 2>/dev/null) -gt 0 ]" \
  "Check: docker compose ps — restart with: docker compose --profile prod up -d"

# Restore strict mode
set -e

# =============================================================================
# Final report
# =============================================================================
section "Summary"

cat <<EOF
${BOLD}Services${NC}
  Backend   http://localhost:8000  (API docs: http://localhost:8000/docs)
  Frontend  http://localhost:8080

${BOLD}Self-tests${NC}
  Passed: ${GREEN}${TESTS_PASSED}${NC}
  Failed: $([ "$TESTS_FAILED" -gt 0 ] && printf "${RED}${TESTS_FAILED}${NC}" || printf "${GREEN}0${NC}")
EOF

if [ "$TESTS_FAILED" -gt 0 ]; then
  printf "${RED}Failures:${NC}\n"
  printf "${TEST_FAILURES}\n"
  printf "\n${YELLOW}The install completed but some tests failed.${NC}\n"
  printf "${YELLOW}Read the error above and fix the configuration. Then:${NC}\n"
  printf "  1. Edit .env to correct the failing key\n"
  printf "  2. Restart: docker compose --profile prod restart backend\n"
  printf "  3. Re-run: ./install.sh (it is idempotent — re-runs self-tests only)\n\n"
  exit 1
fi

cat <<EOF
${BOLD}Configuration${NC}
EOF
for key in MINIMAX_API_KEY SECRET_KEY PERSON_DOSSIER_ENCRYPTION_KEY CENSYS_API_ID GITHUB_TOKEN SERP_API_KEY HIBP_API_KEY RECON_API_KEY; do
  val="$(get_env "$key")"
  if [ -n "$val" ]; then
    printf "  ${GREEN}✓${NC} %-35s = %s\n" "$key" "$(mask "$val")"
  else
    printf "  ${YELLOW}○${NC} %-35s (not set)\n" "$key"
  fi
done

if [ -n "$MISSING_BINARIES" ]; then
  cat <<EOF

${YELLOW}Missing optional binaries:${NC}$(echo "$MISSING_BINARIES" | tr ' ' '\n' | sed 's/^/  •/')
  Install per docs/EXTERNAL_SERVICES.md §Tier 0. The app still runs.
EOF
fi

cat <<EOF

${BOLD}Next steps${NC}
  1. Open http://localhost:8080
  2. Click "New Job" → enter target domain (e.g. example.com)
  3. Accept the pentester responsibility modal
  4. Watch the recon pipeline run

${BOLD}Common commands${NC}
  make logs            # tail all container logs
  make shell-backend   # open a shell in the backend container
  make test            # run the test suite
  make down            # stop everything
  ./install.sh         # re-run this installer (idempotent — updates only what you change)

${BOLD}To add API keys later${NC}
  1. Edit .env
  2. docker compose --profile prod restart backend
  3. Re-run ./install.sh to verify

${RED}⚠  Use only on systems you have WRITTEN AUTHORIZATION to test.${NC}

${GREEN}Install complete.${NC}
EOF

#!/usr/bin/env bash
# =============================================================================
# Copyright 2026 zimlama
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# =============================================================================
# zimlama/recon — Health monitor
# Checks backend health, frontend reachability, disk usage, and docker state.
# Suitable for cron and uptime-kuma. Exit 0 = pass, 1 = fail.
#
# Usage: ./scripts/monitor.sh
# Env:   BACKEND_URL    default: http://localhost:8000
#        FRONTEND_URL   default: http://localhost:8080
#        RECON_API_KEY  sent as X-API-Key header (optional)
#        DISK_THRESHOLD default: 80 (%)
# =============================================================================

set -euo pipefail

# ---- Resolve repo root + load .env ----
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ -f "$REPO_ROOT/.env" ]; then
    # shellcheck disable=SC1090,SC1091
    set -a
    . "$REPO_ROOT/.env"
    set +a
fi

BACKEND_URL="${BACKEND_URL:-http://localhost:8000}"
FRONTEND_URL="${FRONTEND_URL:-http://localhost:8080}"
RECON_API_KEY="${RECON_API_KEY:-}"
DISK_THRESHOLD="${DISK_THRESHOLD:-80}"

# ---- Helpers ----
# Build curl auth args as an array (works under `set -u`).
auth_args=()
if [ -n "$RECON_API_KEY" ]; then
    auth_args=(-H "X-API-Key: $RECON_API_KEY")
fi

# ---- Check backend health ----
if ! curl -fsS "${auth_args[@]+"${auth_args[@]}"}" "$BACKEND_URL/health" \
        | jq -e '.status == "ok"' >/dev/null 2>&1; then
    echo "❌ Backend unhealthy at $BACKEND_URL/health" >&2
    exit 1
fi

# ---- Check frontend reachability ----
if ! curl -fsI "$FRONTEND_URL" 2>/dev/null | head -1 | grep -q "200"; then
    echo "❌ Frontend unhealthy at $FRONTEND_URL" >&2
    exit 1
fi

# ---- Check disk ----
DISK_USAGE=$(df -P / | tail -1 | awk '{print $5}' | tr -d '%')
if [ "$DISK_USAGE" -gt "$DISK_THRESHOLD" ]; then
    echo "⚠️  Disk usage high: ${DISK_USAGE}% (threshold: ${DISK_THRESHOLD}%)" >&2
    exit 1
fi

# ---- Check Docker backend state (warn-only if docker absent) ----
if command -v docker >/dev/null 2>&1; then
    if ! (cd "$REPO_ROOT" && docker compose --profile prod ps --format json 2>/dev/null \
            | jq -e '.[] | select(.Service=="backend") | .State == "running"' >/dev/null 2>&1); then
        echo "❌ Backend container not running" >&2
        exit 1
    fi
else
    echo "WARN: docker not found on PATH — skipping container check" >&2
fi

echo "✅ All checks passed"
exit 0
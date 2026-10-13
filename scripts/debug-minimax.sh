#!/usr/bin/env bash
# =============================================================================
# scripts/debug-minimax.sh — Standalone MiniMax API debug script.
#
# Runs 3 curl tests against the configured endpoint and redacts the API key
# from the output before printing. Safe to paste into chat / share with anyone.
#
# Usage: bash scripts/debug-minimax.sh
# =============================================================================

set -uo pipefail
cd "$(dirname "$0")/.."

# Load .env (export all vars)
if [ ! -f .env ]; then
  echo "ERROR: .env not found in $(pwd)"
  exit 1
fi
set -a; source .env; set +a

# Validate .env format (Docker Compose rejects lines with spaces in keys).
# Parses .env with Python (very strict about format) and reports malformed lines.
echo "=== .env format check ==="
python3 - <<'EOF'
import re, sys
ok = True
with open('.env') as f:
    for lineno, raw in enumerate(f, start=1):
        line = raw.rstrip('\n')
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        # Strict KEY=VALUE (KEY cannot contain whitespace before the '=').
        if not re.match(r'^[A-Z_][A-Z0-9_]*=', line):
            print(f"  ✗ line {lineno}: MALFORMED — {line!r}", file=sys.stderr)
            ok = False
if ok:
    print("  ✓ all lines parse cleanly")
else:
    print("  FIX: edit .env manually, then re-run this script", file=sys.stderr)
    sys.exit(1)
EOF
if [ $? -ne 0 ]; then exit 1; fi
echo ""

# Validate config
echo "=== Config ==="
echo "BASE_URL: ${MINIMAX_BASE_URL:-NOT_SET}"
echo "MODEL:    ${MINIMAX_MODEL:-NOT_SET}"
if [ -z "${MINIMAX_API_KEY:-}" ] || [ "$MINIMAX_API_KEY" = "sk-minimax-replace-with-real-key" ]; then
  echo "KEY:      NOT SET or still placeholder"
  exit 1
fi
echo "KEY:      ${MINIMAX_API_KEY:0:6}***REDACTED*** (length ${#MINIMAX_API_KEY})"
echo ""

# Helper: redacts the key from any text it finds
redact() {
  sed "s|$MINIMAX_API_KEY|${MINIMAX_API_KEY:0:6}***REDACTED***|g"
}

# Tiny test payload
PAYLOAD='{"model":"'"$MINIMAX_MODEL"'","max_tokens":50,"messages":[{"role":"user","content":"Reply with only: OK"}]}'

echo "=== Test 1: Correct URL + correct header (expect 200) ==="
curl -sS -w "\nHTTP_STATUS=%{http_code}\nTOTAL_TIME=%{time_total}s\n" \
  -H "x-api-key: $MINIMAX_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" \
  "$MINIMAX_BASE_URL/messages" 2>&1 | redact
echo ""

echo "=== Test 2: Wrong URL (expect 404) ==="
curl -sS -w "\nHTTP_STATUS=%{http_code}\n" \
  -H "x-api-key: $MINIMAX_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" \
  "https://api.minimax.io/v1/messages" 2>&1 | redact
echo ""

echo "=== Test 3: Wrong header (Bearer instead of x-api-key, expect 401) ==="
curl -sS -w "\nHTTP_STATUS=%{http_code}\n" \
  -H "Authorization: Bearer $MINIMAX_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" \
  "$MINIMAX_BASE_URL/messages" 2>&1 | redact
echo ""

echo "=== Done ==="

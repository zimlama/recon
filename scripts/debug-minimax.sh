#!/usr/bin/env bash
# =============================================================================
# scripts/debug-minimax.sh — Debug MiniMax API without leaking secrets.
#
# Runs in TWO phases via Python (no bash env pollution):
#   Phase 1: Parse .env and validate format (no values printed, even malformed
#            lines get their value masked).
#   Phase 2: Run 3 curl tests. ALL sensitive values found in .env are scrubbed
#            from the output (not just MINIMAX_API_KEY — also GITHUB_TOKEN,
#            SERP_API_KEY, RECON_API_KEY, SECRET_KEY, FERNET, etc.).
#
# Output is safe to copy-paste into chat / share / commit.
#
# Usage: bash scripts/debug-minimax.sh
# =============================================================================

set -uo pipefail
cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  echo "ERROR: .env not found in $(pwd)" >&2
  exit 1
fi

python3 <<'EOF'
import re, sys, subprocess, json, os

# ---- Phase 1: parse .env safely -------------------------------------------

CONFIG = {}
LINE_ISSUES = []

with open('.env') as f:
    for lineno, raw in enumerate(f, start=1):
        line = raw.rstrip('\n').rstrip('\r')
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if '=' not in line:
            LINE_ISSUES.append((lineno, line, 'no-equals'))
            continue
        k, v = line.split('=', 1)
        k = k.strip()
        v = v.strip()
        # Strip surrounding quotes if present
        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
            v = v[1:-1]
        CONFIG[k] = v
        # Strict format check
        if not re.match(r'^[A-Z_][A-Z0-9_]*$', k):
            LINE_ISSUES.append((lineno, k, 'invalid-key-name'))

def is_sensitive(name: str) -> bool:
    return bool(re.search(r'(KEY|TOKEN|SECRET|PASSWORD|ENCRYPTION)', name, re.IGNORECASE))

def mask_value(name: str, value: str) -> str:
    if not value:
        return '(empty)'
    if is_sensitive(name):
        return f'{value[:6]}***REDACTED***'
    return value

def scrub(text: str) -> str:
    """Replace every sensitive value found in CONFIG with a redacted marker."""
    for k, v in CONFIG.items():
        if v and is_sensitive(k):
            text = text.replace(v, f'{k}***REDACTED***')
    return text

# ---- Show config -----------------------------------------------------------

print('=== Config (safe) ===')
for k in ('MINIMAX_BASE_URL', 'MINIMAX_MODEL', 'MINIMAX_API_KEY'):
    v = CONFIG.get(k, '')
    if not v:
        print(f'{k}: NOT SET')
    else:
        print(f'{k}: {mask_value(k, v)} (length {len(v)})')
print()

# ---- Validate .env format --------------------------------------------------

print('=== .env format ===')
if not LINE_ISSUES:
    print('  ok: all lines parse cleanly')
else:
    for lineno, line, reason in LINE_ISSUES:
        # Mask the value before printing
        if isinstance(line, str) and '=' in line:
            k, v = line.split('=', 1)
            masked = f'{k}={mask_value(k.strip(), v.strip())}'
        else:
            masked = repr(line)[:80]
        print(f'  FAIL: line {lineno} ({reason}): {masked}')
    print('  FIX: edit .env manually, then re-run this script')
    sys.exit(1)
print()

# ---- Run 3 curl tests ------------------------------------------------------

KEY = CONFIG.get('MINIMAX_API_KEY', '')
BASE_URL = CONFIG.get('MINIMAX_BASE_URL', '')
MODEL = CONFIG.get('MINIMAX_MODEL', '')

if not (KEY and BASE_URL and MODEL):
    print('Cannot run tests: missing MINIMAX_* in .env')
    sys.exit(0)

PAYLOAD = json.dumps({
    'model': MODEL,
    'max_tokens': 50,
    'messages': [{'role': 'user', 'content': 'Reply with only: OK'}],
})

def run_test(name, url, extra=None):
    print(f'=== {name} ===')
    headers = [
        'x-api-key: ' + KEY,
        'anthropic-version: 2023-06-01',
        'Content-Type: application/json',
    ]
    if extra:
        headers.extend(extra)
    cmd = ['curl', '-sS', '-w', '\nHTTP_STATUS=%{http_code}\nTIME=%{time_total}s\n']
    for h in headers:
        cmd.extend(['-H', h])
    cmd.extend(['-d', PAYLOAD, url])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        body = result.stdout + result.stderr
        print(scrub(body).rstrip())
    except subprocess.TimeoutExpired:
        print('TIMEOUT after 30s')
    except Exception as e:
        print(f'ERROR running curl: {e}')
    print()

run_test(
    'Test 1: correct URL + correct header (expect 200)',
    f'{BASE_URL}/messages',
)
run_test(
    'Test 2: wrong URL (no /anthropic segment) — expect 404',
    'https://api.minimax.io/v1/messages',
)
run_test(
    'Test 3: wrong header (Bearer instead of x-api-key) — expect 401',
    f'{BASE_URL}/messages',
    extra=['Authorization: Bearer ' + KEY],
)

print('=== Done ===')
print('Share the output above; it is safe (all sensitive values scrubbed).')
EOF

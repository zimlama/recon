#!/usr/bin/env bash
# Delete all data for a target (jobs, findings, handoffs, audit logs).
# Usage: ./scripts/purge-target.sh <target>

set -euo pipefail

if [ -z "${1:-}" ]; then
    echo "Usage: $0 <target>" >&2
    exit 1
fi

TARGET="$1"

echo "⚠️  This will DELETE ALL DATA for target: $TARGET"
echo "    (jobs, findings, handoffs, audit logs)"
read -p "Type 'yes' to confirm: " confirm

if [ "$confirm" != "yes" ]; then
    echo "Aborted."
    exit 0
fi

docker compose exec -T backend python -m recon.purge --target "$TARGET" --yes
echo "✅ Purged all data for $TARGET"

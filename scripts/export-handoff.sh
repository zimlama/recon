#!/usr/bin/env bash
# Export a handoff packet for a job.
# Usage: ./scripts/export-handoff.sh <job_id> [output_path]

set -euo pipefail

if [ -z "${1:-}" ]; then
    echo "Usage: $0 <job_id> [output_path]" >&2
    exit 1
fi

JOB_ID="$1"
OUTPUT="${2:-/dev/stdout}"

echo ">>> Exporting handoff for job $JOB_ID..."

docker compose exec -T backend python -c "
import asyncio, json
from app.handoff.exporter import export_handoff

async def main():
    packet = await export_handoff('$JOB_ID')
    print(json.dumps(packet.model_dump(mode='json'), indent=2, ensure_ascii=False))

asyncio.run(main())
" > "$OUTPUT"

if [ "$OUTPUT" != "/dev/stdout" ]; then
    echo "✅ Handoff written to $OUTPUT"
fi

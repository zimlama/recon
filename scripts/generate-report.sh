#!/usr/bin/env bash
# Generate MD + PDF report for a job.
# Usage: ./scripts/generate-report.sh <job_id>

set -euo pipefail

if [ -z "${1:-}" ]; then
    echo "Usage: $0 <job_id>" >&2
    exit 1
fi

JOB_ID="$1"
echo ">>> Generating report for job $JOB_ID..."

docker compose exec -T backend python -m recon.report.generate "$JOB_ID" || \
    docker compose exec backend python -c "
import asyncio
from app.database import SessionLocal
from app.models import Job
from app.report.markdown_gen import MarkdownReportGenerator

async def main():
    with SessionLocal() as db:
        job = db.get(Job, '$JOB_ID')
        if not job:
            print('Job not found')
            return
        gen = MarkdownReportGenerator(db, job)
        path = await gen.generate()
        print(f'Report: {path}')

asyncio.run(main())
"

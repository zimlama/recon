# scripts/

Helper scripts for the zimlama/recon workflow. Each script is a thin wrapper
around the Docker Compose service of the same name.

| Script | Purpose |
|--------|---------|
| `install-deps.sh` | Install host-side dependencies (Docker, git) |
| `generate-report.sh` | Generate MD + PDF report for a job |
| `export-handoff.sh` | Export a handoff packet for a job |
| `test-module.sh` | Run a single module in isolation |
| `lint.sh` | Run all linters (backend + frontend) |
| `format.sh` | Auto-format all code |
| `purge-target.sh` | Delete all data for a target |

All scripts are idempotent and safe to re-run.

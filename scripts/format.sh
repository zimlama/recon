#!/usr/bin/env bash
# Auto-format all code.
# Usage: ./scripts/format.sh

set -euo pipefail

echo ">>> Backend format..."
(cd backend && ruff format .)
(cd backend && ruff check --fix .)

echo ">>> Frontend format..."
(cd frontend && pnpm format)

echo "✅ All code formatted"

#!/usr/bin/env bash
# Run all linters.
# Usage: ./scripts/lint.sh

set -euo pipefail

echo ">>> Backend lint..."
(cd backend && ruff check .)
(cd backend && ruff format --check .)

echo ">>> Frontend lint..."
(cd frontend && pnpm lint)
(cd frontend && pnpm typecheck)

echo "✅ All lints passed"

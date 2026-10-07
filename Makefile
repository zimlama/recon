# Makefile for zimlama/recon
# Convenience targets. The canonical entry point is `make install`.

.PHONY: help install install-deps up up-dev down logs build rebuild \
        test test-backend test-frontend test-e2e lint typecheck format \
        shell-backend shell-frontend shell-db report clean purge

# ---- Config ----
PROJECT_NAME := zimlama-recon
COMPOSE      := docker compose
BACKEND_DIR  := backend
FRONTEND_DIR := frontend

# ---- Help ----
help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ---- Install & Lifecycle ----
install:  ## Run first-time install (idempotent)
	./install.sh

install-deps:  ## Install host-side dependencies (Docker, etc.)
	./scripts/install-deps.sh

up:  ## Start all services in production mode
	$(COMPOSE) --profile prod up -d --build

up-dev:  ## Start all services in dev mode (hot reload)
	$(COMPOSE) --profile dev up -d --build

down:  ## Stop all services
	$(COMPOSE) --profile prod --profile dev down

logs:  ## Tail logs from all services
	$(COMPOSE) logs -f

build:  ## Build all Docker images
	$(COMPOSE) build

rebuild:  ## Rebuild all Docker images without cache
	$(COMPOSE) build --no-cache

# ---- Testing ----
test: test-backend test-frontend  ## Run all tests

test-backend:  ## Run backend tests with coverage gate
	cd $(BACKEND_DIR) && pytest --cov=app --cov-report=term-missing --cov-fail-under=90

test-frontend:  ## Run frontend unit tests
	cd $(FRONTEND_DIR) && pnpm test

test-e2e:  ## Run Playwright E2E tests
	cd $(FRONTEND_DIR) && pnpm test:e2e

# ---- Lint & Typecheck ----
lint:  ## Run all linters
	cd $(BACKEND_DIR) && ruff check .
	cd $(FRONTEND_DIR) && pnpm lint

typecheck:  ## Run all type checkers
	cd $(BACKEND_DIR) && mypy app/ && pyright app/
	cd $(FRONTEND_DIR) && pnpm typecheck

format:  ## Auto-format all code
	cd $(BACKEND_DIR) && ruff format .
	cd $(FRONTEND_DIR) && pnpm format

# ---- Shell access ----
shell-backend:  ## Open a shell in the backend container
	$(COMPOSE) exec backend bash

shell-frontend:  ## Open a shell in the frontend container
	$(COMPOSE) exec frontend sh

shell-db:  ## Open a SQLite shell in the backend container
	$(COMPOSE) exec backend sqlite3 /app/data/recon.db

# ---- Reports ----
report:  ## Generate a report for a job (usage: make report JOB=<id>)
	@if [ -z "$(JOB)" ]; then echo "Usage: make report JOB=<job_id>"; exit 1; fi
	$(COMPOSE) exec backend python -m recon.report.generate $(JOB)

# ---- Cleanup ----
clean:  ## Remove build artifacts and caches
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	cd $(FRONTEND_DIR) && rm -rf .next node_modules/.cache

purge:  ## Delete ALL data for a target (usage: make purge TARGET=example.com)
	@if [ -z "$(TARGET)" ]; then echo "Usage: make purge TARGET=example.com"; exit 1; fi
	$(COMPOSE) exec backend python -m recon.purge --target $(TARGET)

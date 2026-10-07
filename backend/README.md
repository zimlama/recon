# zimlama/recon — Backend

FastAPI backend for the zimlama/recon Phase 1 reconnaissance framework.

## Stack

- **FastAPI** 0.110+ — async web framework
- **Pydantic v2** — validation, settings, schemas
- **SQLAlchemy 2** + **Alembic** — ORM + migrations
- **httpx** + **aiohttp** — async HTTP clients
- **structlog** — structured logging
- **typer** — CLI

## Dev Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp ../.env.example .env  # edit values
```

## Test

```bash
# Run all tests with coverage
pytest --cov=app --cov-report=term-missing --cov-fail-under=90

# Run only unit tests
pytest -m unit

# Run only integration tests
pytest -m integration

# Run specific test
pytest tests/test_handoff.py::test_export_writes_file -v
```

## Lint + Typecheck

```bash
ruff check .          # linter
ruff format .         # formatter
mypy app/             # type checker (strict)
pyright app/          # secondary type checker
```

## Database

```bash
# Initialize DB (creates tables on first run)
python -m recon init-db

# Create migration after schema changes
alembic revision --autogenerate -m "add new field"

# Apply migrations
alembic upgrade head

# Rollback
alembic downgrade -1
```

## CLI

```bash
# Initialize database
recon init-db

# Run a recon from CLI
recon run example.com

# Export a handoff packet
recon handoff <job_id>

# Purge all data for a target
recon purge example.com

# Start MCP server (stdio)
recon mcp
```

## Structure

```
backend/
├── app/
│   ├── main.py              # FastAPI app factory
│   ├── config.py            # Settings (pydantic-settings)
│   ├── database.py          # SQLAlchemy 2 setup
│   ├── models.py            # ORM models
│   ├── schemas.py           # Pydantic API models
│   ├── cli.py               # Typer CLI
│   ├── audit/               # Audit middleware
│   ├── orchestrator/        # Job runner, AI validator, rate limiter
│   ├── modules/             # Recon modules (14)
│   │   ├── base.py
│   │   ├── whois_rdap.py
│   │   └── ...
│   ├── llm/                 # MiniMax M3 client + prompts + schemas
│   ├── handoff/             # Handoff packet schema + export/import
│   ├── routes/              # FastAPI routes
│   ├── report/              # MD + PDF generation
│   └── mcp/                 # MCP stdio server
├── alembic/                 # DB migrations
├── tests/                   # pytest
├── pyproject.toml
├── requirements.txt
├── Dockerfile
└── README.md
```

## License

Apache-2.0

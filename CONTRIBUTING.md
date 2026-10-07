# Contributing to zimlama/recon

Thank you for your interest in contributing! This document covers development workflow, code style, and the PR process.

## Code of Conduct

By participating, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Be respectful, constructive, and security-minded.

## Development Setup

```bash
git clone https://github.com/zimlama/recon.git
cd recon
./install.sh
```

See [README.md](README.md) for full prerequisites.

## Development Workflow

This project uses **Spec-Driven Development (SDD)** with the gentle-ai workflow.

### 1. Open a change

For any non-trivial change, start with `/sdd-propose`:

```bash
openspec/changes/<change-id>/
├── proposal.md     # what & why
├── spec.md         # detailed requirements + scenarios
├── design.md       # technical approach
└── tasks.md        # implementation checklist
```

### 2. Test-Driven Development (TDD)

**Tests first, then code.** Coverage gate: **90%** (strict).

- Backend: `pytest --cov=app --cov-fail-under=90`
- Frontend: `vitest run --coverage --coverage.thresholds.lines=90`

### 3. Conventional Commits

Format: `<type>(<scope>): <subject>`

Examples:
- `feat(modules): add shodan_censys module`
- `fix(handoff): validate target before export`
- `docs(rfc): add RFC-005 for multi-tenant support`
- `test(modules): increase coverage of subdomain_enum to 95%`

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `perf`.

### 4. No `Co-Authored-By`

Conventional commits only. No AI attribution.

## Code Style

### Python (backend)

- **Linter**: `ruff check .` (replaces black, flake8, isort)
- **Formatter**: `ruff format .`
- **Type checker**: `mypy app/` (strict mode)
- **Secondary check**: `pyright app/`

Style guidelines:
- Type hints on every public function
- `from __future__ import annotations` at top of every module
- Max line length: 100
- Max function length: 30 lines (refactor if longer)
- Classes: dataclasses preferred over plain classes
- Use `Protocol` for ports (dependency inversion)
- Async/await for I/O

### TypeScript (frontend)

- **Linter**: `eslint .`
- **Formatter**: `prettier --write .`
- **Type checker**: `tsc --noEmit`

Style guidelines:
- `strict: true` in tsconfig
- Prefer `function` declarations over `const` for components
- Props: `Readonly<Props>` + destructuring at signature
- State: Zustand stores, one per domain
- API calls: typed via openapi-typescript

## Module Architecture

Each recon module follows the same contract:

```python
# backend/app/modules/base.py
class BaseReconModule(ABC):
    name: str
    description: str
    phase: str = "01-recon-osint"
    mitre_techniques: List[str]
    requires_api_keys: List[str] = []
    
    @abstractmethod
    async def run(self, input: ModuleInput) -> ModuleOutput: ...
    
    @abstractmethod
    def get_ai_prompt(self) -> str: ...
    
    async def validate(self, findings: List[Finding], target: str) -> LLMDecision: ...
```

To add a new module:
1. Create `backend/app/modules/<name>.py` extending `BaseReconModule`
2. Create `backend/tests/test_<name>.py` with ≥5 test cases
3. Add the module to `backend/app/modules/__init__.py` registry
4. Add a row to `docs/MODULE_GUIDE.md` (non-programmer friendly)
5. Update `frontend/src/lib/types.ts` if the module exposes new finding types

## Pull Request Process

1. Open a PR with a clear title and description
2. Link the related `openspec/changes/<id>/` directory
3. Ensure CI passes (lint + test + typecheck + docker build)
4. Request 1 review (2 for breaking changes)
5. Squash-merge after approval

PR template:

```markdown
## What
[1-2 sentences]

## Why
[Link to proposal/spec]

## How
[Key implementation notes]

## Testing
[What you tested + how]

## Checklist
- [ ] Tests added (≥90% coverage)
- [ ] Docs updated
- [ ] Lint + typecheck pass
- [ ] No breaking changes (or noted in CHANGELOG)
```

## Reporting Issues

Use [GitHub Issues](https://github.com/zimlama/recon/issues) for:
- Bug reports
- Feature requests
- Documentation improvements

For security issues, see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under [Apache-2.0](LICENSE).

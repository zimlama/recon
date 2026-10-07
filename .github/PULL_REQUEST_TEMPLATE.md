## What
<!-- 1-2 sentences: what does this PR do? -->

## Why
<!-- Link to issue / proposal / spec. Why is this change needed? -->

## How
<!-- Key implementation notes (architecture, breaking changes, etc.) -->

## Testing
<!-- What you tested + how (commands, manual steps, etc.) -->

## Checklist
- [ ] Tests added (>= 90% coverage for changed lines)
- [ ] Docs updated (README, MODULE_GUIDE, RFC, etc.)
- [ ] `ruff check .` + `ruff format --check .` pass (backend)
- [ ] `mypy app/ --strict` + `pyright app/` pass (backend)
- [ ] `pnpm lint` + `pnpm typecheck` pass (frontend)
- [ ] `pytest --cov-fail-under=90` passes
- [ ] `pnpm test:coverage` passes
- [ ] No breaking changes (or noted in CHANGELOG.md)
- [ ] No `Co-Authored-By` in commits

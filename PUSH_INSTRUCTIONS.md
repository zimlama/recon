# Push to GitHub — Manual Steps

This document explains how to push `zimlama/recon` to GitHub. The repo
is ready locally but the remote was not configured (requires interactive
auth).

## Prerequisites

1. GitHub CLI installed and authenticated: `gh auth login`
2. Or git credentials configured

## Steps

```bash
# 1. Create the repo on GitHub (if not already done)
gh repo create zimlama/recon --public --description "Phase 1 ethical hacking reconnaissance framework" --source .

# Or create via web: https://github.com/new

# 2. Add the remote
git remote add origin git@github.com:zimlama/recon.git

# 3. Push main branch
git push -u origin main

# 4. Create v0.1.0 tag
git tag -a v0.1.0 -m "zimlama/recon v0.1.0 — initial release"
git push origin v0.1.0

# 5. Create GitHub release (UI or CLI)
gh release create v0.1.0 --title "zimlama/recon v0.1.0" --notes-file CHANGELOG.md

# 6. Verify CI passes on GitHub
gh run watch
```

## Post-push checklist

- [ ] GitHub Actions CI is green (lint + test + typecheck + Docker build)
- [ ] CodeQL scan is clean
- [ ] README renders correctly on the GitHub repo page
- [ ] Releases page shows v0.1.0 with changelog notes
- [ ] Docker images are built and pushed to ghcr.io/zimlama/recon-{backend,frontend}:v0.1.0

## Docker image URLs

After push, Docker images will be available at:

- `ghcr.io/zimlama/recon-backend:v0.1.0`
- `ghcr.io/zimlama/recon-frontend:v0.1.0`

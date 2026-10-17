# zimlama/recon — Frontend (Next.js 14)

FROM node:20-alpine AS base
RUN corepack enable && corepack prepare pnpm@9.0.0 --activate

# ---- Dependencies ----
FROM base AS deps
WORKDIR /app
COPY package.json pnpm-lock.yaml* ./
# Use plain `pnpm install` (no --frozen-lockfile) so the build works even
# when pnpm-lock.yaml is absent from the repo. The first build generates
# the lockfile inside the container; subsequent builds reuse it via
# a BuildKit cache mount on /root/.local/share/pnpm. tmpfs at /tmp
# prevents pnpm's transient metadata and artifact downloads from being
# persisted to the image layer (which exhausts space on small hosts).
RUN --mount=type=tmpfs,target=/tmp \
    --mount=type=cache,target=/root/.local/share/pnpm,sharing=shared \
    pnpm install

# ---- Builder ----
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
RUN --mount=type=tmpfs,target=/tmp \
    pnpm build

# ---- Production runner (Next.js standalone) ----
# 2026-10-14 fix: rewrite from nginx to node server.js.
#
# Root cause (see TROUBLESHOOTING.md entry 2026-10-14 "Frontend devuelve HTTP 403"):
#   output: 'standalone' in next.config.js produces a `server.js` Node bundle,
#   NOT a static `index.html`. Serving it with nginx (root /app + try_files /index.html)
#   fails with `directory index of "/app/" is forbidden` because there is no
#   index.html — the runner must execute the Node server directly.
#
# Same rewrite preserves the proxy_pass behavior (frontend → backend on
# /api/*) by declaring it via next.config.js → async rewrites() instead of
# nginx `proxy_pass`. See the matching commit on next.config.js.
FROM node:20-alpine AS runner
ENV NODE_ENV=production \
    HOSTNAME=0.0.0.0 \
    PORT=80
WORKDIR /app

# Non-root user (Alpine has `addgroup`/`adduser` — busybox applet equivalents)
RUN addgroup -S recon && adduser -S -G recon recon -u 1001

# Copy Next.js standalone build (server.js + node_modules + .next/static).
# --chown ensures the non-root user can read everything.
COPY --from=builder --chown=recon:recon /app/.next/standalone ./
COPY --from=builder --chown=recon:recon /app/.next/static ./.next/static
# /app/public is intentionally NOT copied: the directory is empty and the
# app code references no public assets. If you later add static files
# (favicon, robots.txt, OG image), reintroduce this COPY line:
#   COPY --from=builder --chown=recon:recon /app/public ./public

USER recon
EXPOSE 80

# Health check — wget is part of busybox in node:20-alpine, no extra install.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:80/ >/dev/null 2>&1 || exit 1

CMD ["node", "server.js"]

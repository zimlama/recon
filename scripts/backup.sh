#!/usr/bin/env bash
# =============================================================================
# Copyright 2026 zimlama
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# =============================================================================
# zimlama/recon — Backup
# Snapshots ./data/ to a timestamped tar.gz, optionally uploads to a remote
# bucket via rclone, and prunes old backups beyond MAX_BACKUPS.
# Designed for cron. Idempotent — safe to re-run (timestamped filenames).
#
# Usage: ./scripts/backup.sh
# Env:   BACKUP_BUCKET  rclone target e.g. "s3:my-bucket/backups"
#        BACKUP_LOCATION override local backup dir (default: ./backups)
#        MAX_BACKUPS    number of local archives to keep (default: 7)
# =============================================================================

set -euo pipefail

# ---- Resolve paths ----
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA_DIR="$REPO_ROOT/data"
BACKUP_DIR="${BACKUP_LOCATION:-$REPO_ROOT/backups}"
BACKUP_BUCKET="${BACKUP_BUCKET:-}"
MAX_BACKUPS="${MAX_BACKUPS:-7}"

# ---- Load .env if present (override defaults) ----
if [ -f "$REPO_ROOT/.env" ]; then
    # shellcheck disable=SC1090,SC1091
    set -a
    . "$REPO_ROOT/.env"
    set +a
    BACKUP_BUCKET="${BACKUP_BUCKET:-}"
    MAX_BACKUPS="${MAX_BACKUPS:-7}"
    BACKUP_DIR="${BACKUP_LOCATION:-$REPO_ROOT/backups}"
fi

# ---- Verify MAX_BACKUPS is numeric ----
if ! [[ "$MAX_BACKUPS" =~ ^[0-9]+$ ]]; then
    echo "MAX_BACKUPS must be a non-negative integer (got: $MAX_BACKUPS)" >&2
    exit 1
fi

TS=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="zimlama-recon_backup_$TS"

# ---- Stop backend to flush SQLite WAL ----
echo ">>> Stopping backend (flush SQLite WAL)..."
cd "$REPO_ROOT"
docker compose stop backend 2>/dev/null || true
sleep 2

# ---- Build backup bundle in a tempdir ----
echo ">>> Building backup bundle..."
mkdir -p "$BACKUP_DIR"
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT
mkdir -p "$TEMP_DIR/$BACKUP_NAME"

if [ -d "$DATA_DIR" ]; then
    cp -r "$DATA_DIR" "$TEMP_DIR/$BACKUP_NAME/"
else
    echo "WARN: $DATA_DIR does not exist — snapshot will not include data/" >&2
fi

if [ -f "$REPO_ROOT/.env" ]; then
    cp "$REPO_ROOT/.env" "$TEMP_DIR/$BACKUP_NAME/"
fi

# ---- Tar + gzip ----
tar -czf "$BACKUP_DIR/$BACKUP_NAME.tar.gz" -C "$TEMP_DIR" "$BACKUP_NAME"
BACKUP_FILE="$BACKUP_DIR/$BACKUP_NAME.tar.gz"

# ---- Restart backend ----
echo ">>> Restarting backend..."
cd "$REPO_ROOT"
docker compose start backend 2>/dev/null || true

# ---- Upload to cloud if configured ----
if [ -n "$BACKUP_BUCKET" ]; then
    if command -v rclone >/dev/null 2>&1; then
        echo ">>> Uploading to $BACKUP_BUCKET..."
        rclone copy "$BACKUP_FILE" "$BACKUP_BUCKET/" || {
            echo "WARN: rclone upload failed for $BACKUP_FILE" >&2
        }
    else
        echo "WARN: BACKUP_BUCKET is set but rclone is not installed — skipping upload" >&2
    fi
fi

# ---- Prune old local backups ----
echo ">>> Pruning local backups beyond MAX_BACKUPS=$MAX_BACKUPS..."
cd "$BACKUP_DIR"
ls -t zimlama-recon_backup_*.tar.gz 2>/dev/null | tail -n +$((MAX_BACKUPS + 1)) | xargs -r rm --

# ---- Summary ----
echo ""
echo "✅ Backup created: $BACKUP_FILE"
if [ -f "$BACKUP_FILE" ]; then
    ls -lh "$BACKUP_FILE"
fi
echo "  Local backups kept: $(ls zimlama-recon_backup_*.tar.gz 2>/dev/null | wc -l | tr -d ' ') / $MAX_BACKUPS"
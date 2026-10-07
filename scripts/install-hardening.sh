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
# zimlama/recon — Host security hardening
# Applies a defense-in-depth baseline to a fresh Ubuntu 22.04+ install.
# Idempotent — safe to re-run.
#
# Usage: sudo ./scripts/install-hardening.sh
# =============================================================================

set -euo pipefail

# ---- Verify root ----
if [[ $EUID -ne 0 ]]; then
    echo "Run as root or with sudo" >&2
    exit 1
fi

# ---- 1. Update + upgrade ----
echo ">>> Updating package lists..."
apt-get update -qq
echo ">>> Upgrading installed packages..."
apt-get upgrade -y -qq

# ---- 2. Install base packages ----
echo ">>> Ensuring base packages are installed..."
for pkg in curl wget git ufw fail2ban unattended-upgrades jq; do
    if ! command -v "$pkg" >/dev/null 2>&1; then
        apt-get install -y -qq "$pkg"
    fi
done

# ---- 3. Configure UFW (idempotent — only if not running) ----
if ! ufw status 2>/dev/null | grep -q "Status: active"; then
    echo ">>> Configuring UFW..."
    ufw --force reset >/dev/null
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow OpenSSH
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    ufw --force enable
else
    echo ">>> UFW already active — skipping rules reset"
fi

# ---- 4. SSH hardening (only if sshd is installed) ----
if [ -f /etc/ssh/sshd_config ]; then
    echo ">>> Hardening sshd_config..."
    if [ ! -f /etc/ssh/sshd_config.bak ]; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    fi
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    if systemctl is-active --quiet ssh; then
        systemctl reload ssh
    elif systemctl is-active --quiet sshd; then
        systemctl reload sshd
    fi
else
    echo ">>> sshd not installed — skipping SSH hardening"
fi

# ---- 5. fail2ban ----
echo ">>> Enabling fail2ban..."
systemctl enable fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban >/dev/null 2>&1 || true

# ---- 6. Auto-updates ----
echo ">>> Configuring unattended-upgrades..."
dpkg-reconfigure --priority=low unattended-upgrades

# ---- 7. Summary ----
echo ""
echo "✅ Hardening complete"
echo "  - UFW: $(ufw status 2>/dev/null | head -1 || echo 'unknown')"
if command -v fail2ban-client >/dev/null 2>&1; then
    echo "  - fail2ban: $(fail2ban-client status 2>/dev/null | head -1 || echo 'installed')"
else
    echo "  - fail2ban: installed"
fi
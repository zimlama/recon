#!/usr/bin/env bash
# =============================================================================
# zimlama/recon — debug script for "go install" failing during docker build.
#
# Purpose
#   Capture everything needed to understand why `RUN go install ...` in
#   backend/Dockerfile fails with "no such host" while the same hostname
#   resolves fine from the host and from regular `docker run alpine`.
#
# Usage
#   bash scripts/debug-recon-install.sh | tee /tmp/recon-debug.log
#   cat /tmp/recon-debug.log                    # then paste or scp the log
#
# Safe: read-only. No docker images built with tags, no destructive ops.
# =============================================================================
set -u  # NOT -e: a single failed probe should not abort the whole report

hr() { printf '\n============================================================\n%s\n============================================================\n' "$1"; }
sec() { printf '\n--- %s ---\n' "$1"; }

hr "TIMESTAMP / ID"
date -u +"%Y-%m-%dT%H:%M:%SZ"
printf 'hostname: %s\n' "$(hostname 2>/dev/null || echo unknown)"
printf 'cwd: %s\n' "$(pwd)"

hr "1. HOST INFO"
sec "uname -a"
uname -a
sec "/etc/os-release (filtered)"
grep -E '^(NAME|VERSION|ID|ID_LIKE|VERSION_CODENAME|PRETTY_NAME)=' /etc/os-release 2>/dev/null || echo "(no /etc/os-release)"
sec "arch"
arch
sec "whoami / id"
whoami
id

hr "2. DOCKER VERSIONS"
sec "docker version"
docker version 2>&1 | head -40
sec "docker compose version"
docker compose version 2>&1 | head -5
sec "docker buildx version"
docker buildx version 2>&1 | head -5

hr "3. DOCKER DAEMON CONFIG"
sec "/etc/docker/ contents"
ls -la /etc/docker/ 2>&1
sec "/etc/docker/daemon.json (if exists)"
if [ -f /etc/docker/daemon.json ]; then
  cat /etc/docker/daemon.json
else
  echo "(no /etc/docker/daemon.json — Docker uses defaults)"
fi
sec "docker info (DNS, Server, Security, Storage)"
docker info 2>&1 | grep -iE '^(server version|storage driver|cgroup version|operating system|kernel version|docker root dir|experimental|registry|live restore|dns|default address pools)' | head -25

hr "4. HOST DNS CONFIG"
sec "/etc/resolv.conf"
cat /etc/resolv.conf 2>&1
sec "/etc/nsswitch.conf (hosts line)"
grep '^hosts:' /etc/nsswitch.conf 2>&1 || echo "(no nsswitch.conf — musl/alpine?)"
sec "systemd-resolved status (if present)"
if command -v systemctl >/dev/null 2>&1 && systemctl is-active systemd-resolved >/dev/null 2>&1; then
  sudo systemctl status systemd-resolved --no-pager -n 0 2>&1 | head -5
  resolvectl status 2>&1 | head -30
else
  echo "(systemd-resolved not active or not present)"
fi

hr "5. PROXY ENVIRONMENT (host)"
sec "HTTP_PROXY / HTTPS_PROXY / NO_PROXY / GOPROXY"
printenv | grep -iE '^(http_proxy|https_proxy|no_proxy|HTTP_PROXY|HTTPS_PROXY|NO_PROXY|GOPROXY|GOFLAGS|GOSUMDB|GONOSUMCHECK|GOPRIVATE|GO111MODULE)=' || echo "(no proxy env vars set)"

hr "6. NETWORK CONNECTIVITY FROM HOST (curl)"
for url in \
  https://goproxy.io \
  https://goproxy.cn \
  https://proxy.golang.org \
  https://mirrors.aliyun.com/goproxy/ \
  https://registry-1.docker.io \
  https://go.dev \
  https://github.com \
  https://files.pythonhosted.org ; do
  sec "GET $url"
  curl -sS -o /dev/null -w 'http_code=%{http_code}  time=%{time_total}s  resolve=%{remote_ip}\n' --max-time 8 "$url" 2>&1 || echo "(curl failed)"
done

hr "7. DNS LOOKUP FROM REGULAR CONTAINER (alpine runtime)"
sec "alpine: cat /etc/resolv.conf"
sg docker -c "docker run --rm alpine cat /etc/resolv.conf" 2>&1 | head -10
for host in goproxy.io goproxy.cn proxy.golang.org mirrors.aliyun.com registry-1.docker.io github.com; do
  sec "alpine: nslookup $host"
  sg docker -c "docker run --rm alpine nslookup $host" 2>&1 | head -10
done
sec "alpine: getent hosts for each"
sg docker -c "docker run --rm alpine sh -c '
  for h in goproxy.io goproxy.cn proxy.golang.org registry-1.docker.io; do
    printf \"getent hosts %s -> \" \"\$h\"
    getent hosts \"\$h\" || echo \"FAILED\"
  done
'" 2>&1

hr "8. DNS LOOKUP FROM BUILDKIT STEP (the real culprit, if any)"
sec "Write minimal Dockerfile.debug"
DEBUG_DIR=$(mktemp -d)
cat > "$DEBUG_DIR/Dockerfile.debug" <<'EOF'
# Minimal probe — runs entirely during docker build, so DNS = BuildKit DNS.
FROM alpine:3.19
RUN echo "=== /etc/resolv.conf (BuildKit view) ===" && cat /etc/resolv.conf
RUN echo "=== /etc/hosts (BuildKit view) ===" && cat /etc/hosts
RUN echo "=== getent hosts probes ===" && \
    for h in goproxy.io goproxy.cn proxy.golang.org mirrors.aliyun.com registry-1.docker.io github.com; do \
      printf 'getent hosts %-30s ' "$h"; getent hosts "$h" || echo "FAILED"; \
    done
RUN echo "=== ip route / network namespace ===" && \
    (ip route 2>/dev/null || route -n 2>/dev/null || echo "no route cmd")
RUN echo "=== proxy env inside BuildKit ===" && env | grep -iE 'proxy|goproxy|goflags' || echo "(none)"
EOF
printf 'Dockerfile.debug written to %s\n' "$DEBUG_DIR/Dockerfile.debug"
cat "$DEBUG_DIR/Dockerfile.debug"
sec "docker buildx build --no-cache (BuildKit DNS probe)"
sg docker -c "docker buildx build --no-cache --progress=plain -f $DEBUG_DIR/Dockerfile.debug $DEBUG_DIR" 2>&1 | tail -80

hr "9. BUILDX CONFIG"
sec "docker buildx ls"
docker buildx ls 2>&1
sec "buildx default inspect"
docker buildx inspect default 2>&1 | head -40 || true
sec "/etc/buildkit/ (if exists)"
ls -la /etc/buildkit/ 2>&1 || true
sec "~/.docker/config.json (if exists)"
cat ~/.docker/config.json 2>&1 || echo "(no config.json)"
sec "current builder"
sg docker -c "docker buildx inspect --current 2>&1" | head -20 || true

hr "10. DOCKER NETWORK"
sec "docker network ls"
docker network ls 2>&1
sec "docker network inspect bridge (top 30 lines)"
docker network inspect bridge 2>&1 | head -30

hr "11. REPO CONFIG (GOPROXY flow)"
sec "install.sh GOPROXY block"
grep -n -B1 -A3 'GOPROXY' install.sh
sec "docker-compose.yml GOPROXY block"
grep -n -B1 -A4 'GOPROXY' docker-compose.yml
sec "backend/Dockerfile GOPROXY block + go install line"
sed -n '66,90p' backend/Dockerfile

hr "12. PREVIOUS INSTALL LOG"
sec "ls /tmp/recon-install-*.log"
ls -la /tmp/recon-install-*.log 2>&1 || echo "(no prior install log)"
sec "tail of /tmp/recon-install-up.log (last 120 lines)"
if [ -f /tmp/recon-install-up.log ]; then
  tail -120 /tmp/recon-install-up.log
else
  echo "(no /tmp/recon-install-up.log)"
fi

hr "13. IPTABLES / ROUTING (may intercept DNS)"
sec "iptables NAT table (first 25 lines)"
sudo iptables -t nat -L -n 2>&1 | head -25
sec "ip route"
ip route 2>&1
sec "ip link show docker0 (if present)"
ip link show docker0 2>&1 || echo "(no docker0 interface)"

hr "END OF DEBUG"
printf 'Total runtime: %s\n' "$(date)"
echo "If anything is empty, that's data — paste the whole log anyway."
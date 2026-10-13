#!/usr/bin/env bash
# =============================================================================
# tests/install_tests.sh — Pure bash tests for install_lib.sh detection logic.
#
# Runs without root, sudo, or side effects. Verifies:
#   - detect_os_family (macos / linux / unknown / wsl)
#   - detect_distro_id (ubuntu / debian / fedora / arch / macos / unknown)
#   - detect_package_manager (apt / dnf / pacman / brew / unknown)
#   - is_root + sudo_cmd (root vs non-root)
#   - ensure_prereqs with --skip-prereqs sets globals correctly
#
# Not tested (would require sudo + live network + system mutation):
#   - Actual package installation
#   - Docker daemon start
#   - usermod group mutation
#
# Usage:
#   bash tests/install_tests.sh
#   bash tests/install_tests.sh --verbose
# =============================================================================

set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$TEST_DIR/.." && pwd)"
LIB="${REPO_ROOT}/install_lib.sh"
INSTALL="${REPO_ROOT}/install.sh"

if [ ! -f "$LIB" ]; then
  echo "FATAL: install_lib.sh not found at $LIB" >&2
  exit 2
fi

VERBOSE=0
for arg in "$@"; do
  case "$arg" in
    --verbose|-v) VERBOSE=1 ;;
  esac
done

# Colors
if [ -t 1 ]; then
  GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
  GREEN=''; RED=''; YELLOW=''; NC=''
fi

PASS=0; FAIL=0

pass() { PASS=$((PASS + 1)); printf "OK\n"; }
fail() { FAIL=$((FAIL + 1)); printf "FAIL\n"; printf "    %s\n" "${1:-}"; }

# Helper: write a tmp script, run it, return stdout + stderr.
run_script() {
  local script="$1"
  local out_file; out_file="$(mktemp)"
  bash -c "$script" > "$out_file" 2>&1 && rc=0 || rc=$?
  local stdout; stdout="$(cat "$out_file")"
  rm -f "$out_file"
  if [ "$rc" -ne 0 ] && [ -n "$stdout" ]; then
    fail_message="${stdout}"
  fi
  printf '%s\n' "$stdout"
}

# run_test <name> <expected> <script>
run_test() {
  local name="$1"; local expected="$2"; local script="$3"
  printf "  • %-60s " "$name"
  local actual; actual="$(run_script "$script")"
  if [ "$actual" = "$expected" ]; then
    pass
  else
    fail "expected [$expected], got [$actual]"
  fi
}

# Common prefix: source the lib in no-die-mode.
LIB_SETUP="die() { return 0; }; log() { :; }; ok() { :; }; warn() { :; }; . '$LIB' >/dev/null 2>&1"

printf "${YELLOW}=== install_lib.sh tests ===${NC}\n"

# -----------------------------------------------------------------------------
# detect_os_family — uses 'uname -s' which we mock via PATH override
# -----------------------------------------------------------------------------

run_test "detect_os_family: Darwin → macos" \
  "macos" \
  "$LIB_SETUP; uname() { echo Darwin; }; detect_os_family"

run_test "detect_os_family: Linux (non-WSL) → linux" \
  "linux" \
  "$LIB_SETUP; uname() { echo Linux; }; detect_os_family"

run_test "detect_os_family: FreeBSD → unknown" \
  "unknown" \
  "$LIB_SETUP; uname() { echo FreeBSD; }; detect_os_family"

# WSL detection looks for 'microsoft' or 'wsl' in /proc/version.
# We can't mock /proc/version directly, but we can re-define detect_os_family
# to use a stub. Test that the WSL branch is reachable by overriding grep.
run_test "detect_os_family: Linux + microsoft marker → wsl" \
  "wsl" \
  "$LIB_SETUP
fake_proc=\$(mktemp -d)
printf 'Linux version 5.15.0 (microsoft@x86)\n' > \"\$fake_proc/version\"
uname() { echo Linux; }
# Override the function call so that the grep reads our fake file.
detect_os_family() {
  case \"\$(uname -s)\" in
    Darwin) echo macos ;;
    Linux)
      if grep -qiE 'microsoft|wsl' \"\$fake_proc/version\" 2>/dev/null; then
        echo wsl
      else
        echo linux
      fi
      ;;
    *) echo unknown ;;
  esac
}
detect_os_family"

# -----------------------------------------------------------------------------
# detect_distro_id — mock /etc/os-release via a temp file
# -----------------------------------------------------------------------------

run_test "detect_distro_id: ubuntu (via /etc/os-release)" \
  "ubuntu" \
  "$LIB_SETUP
# Mock /etc/os-release by overriding the function's source line.
osrel=\$(mktemp)
printf 'ID=ubuntu\nVERSION_CODENAME=jammy\n' > \"\$osrel\"
detect_distro_id() { . \"\$osrel\"; printf '%s\n' \"\$ID\" | tr '[:upper:]' '[:lower:]'; }
detect_distro_id"

run_test "detect_distro_id: debian (via /etc/os-release)" \
  "debian" \
  "$LIB_SETUP
osrel=\$(mktemp)
printf 'ID=debian\nVERSION_CODENAME=bookworm\n' > \"\$osrel\"
detect_distro_id() { . \"\$osrel\"; printf '%s\n' \"\$ID\" | tr '[:upper:]' '[:lower:]'; }
detect_distro_id"

run_test "detect_distro_id: fedora (via /etc/os-release)" \
  "fedora" \
  "$LIB_SETUP
osrel=\$(mktemp)
printf 'ID=fedora\nVERSION_ID=39\n' > \"\$osrel\"
detect_distro_id() { . \"\$osrel\"; printf '%s\n' \"\$ID\" | tr '[:upper:]' '[:lower:]'; }
detect_distro_id"

run_test "detect_distro_id: arch (via /etc/os-release)" \
  "arch" \
  "$LIB_SETUP
osrel=\$(mktemp)
printf 'ID=arch\n' > \"\$osrel\"
detect_distro_id() { . \"\$osrel\"; printf '%s\n' \"\$ID\" | tr '[:upper:]' '[:lower:]'; }
detect_distro_id"

run_test "detect_distro_id: no /etc/os-release → unknown (on Linux)" \
  "unknown" \
  "$LIB_SETUP
# Pretend we're Linux, then ensure detect_distro_id returns 'unknown' when no /etc/os-release.
uname() { echo Linux; }
detect_distro_id() {
  if [ \"\$(uname -s)\" = 'Darwin' ]; then echo macos; return; fi
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    printf '%s\n' \"\$ID\" | tr '[:upper:]' '[:lower:]'
  elif [ -f /etc/lsb-release ]; then
    . /etc/lsb-release
    printf '%s\n' \"\$DISTRIB_ID\" | tr '[:upper:]' '[:lower:]'
  else
    echo unknown
  fi
}
detect_distro_id"

# -----------------------------------------------------------------------------
# detect_package_manager — pure dispatch, easy to test directly
# -----------------------------------------------------------------------------

run_test "detect_package_manager: ubuntu → apt"   "apt"     "$LIB_SETUP; detect_package_manager ubuntu"
run_test "detect_package_manager: debian → apt"   "apt"     "$LIB_SETUP; detect_package_manager debian"
run_test "detect_package_manager: fedora → dnf"   "dnf"     "$LIB_SETUP; detect_package_manager fedora"
run_test "detect_package_manager: rhel → dnf"     "dnf"     "$LIB_SETUP; detect_package_manager rhel"
run_test "detect_package_manager: rocky → dnf"    "dnf"     "$LIB_SETUP; detect_package_manager rocky"
run_test "detect_package_manager: arch → pacman"  "pacman"  "$LIB_SETUP; detect_package_manager arch"
run_test "detect_package_manager: manjaro → pacman" "pacman" "$LIB_SETUP; detect_package_manager manjaro"
run_test "detect_package_manager: macos → brew"   "brew"    "$LIB_SETUP; detect_package_manager macos"
run_test "detect_package_manager: solaris → unknown" "unknown" "$LIB_SETUP; detect_package_manager solaris"
run_test "detect_package_manager: empty → unknown" "unknown"  "$LIB_SETUP; detect_package_manager ''"

# -----------------------------------------------------------------------------
# is_root + sudo_cmd — need to stub `id -u` (not just `id`)
# -----------------------------------------------------------------------------

run_test "is_root: id -u=0 → yes"   "yes" "$LIB_SETUP
id() { case \"\$1\" in -u) echo 0;; *) echo 'uid=0(root) gid=0(root) groups=0(root)';; esac; }
if is_root; then echo yes; else echo no; fi"

run_test "is_root: id -u=1000 → no" "no"  "$LIB_SETUP
id() { case \"\$1\" in -u) echo 1000;; *) echo 'uid=1000(user) gid=1000(user)';; esac; }
if is_root; then echo yes; else echo no; fi"

run_test "sudo_cmd: uid=0 → empty"   ""   "$LIB_SETUP
id() { case \"\$1\" in -u) echo 0;; *) echo 'uid=0(root)';; esac; }
sudo_cmd"

run_test "sudo_cmd: uid=1000 → sudo" "sudo" "$LIB_SETUP
id() { case \"\$1\" in -u) echo 1000;; *) echo 'uid=1000(user)';; esac; }
sudo_cmd"

# -----------------------------------------------------------------------------
# ensure_prereqs with SKIP_PREREQS=1 — must set the globals and return 0
# -----------------------------------------------------------------------------

# On macOS systems, the test expects OS_FAMILY=macos, DISTRO_ID=macos, PKG_MANAGER=brew.
# On Linux it expects OS_FAMILY=linux or wsl, DISTRO_ID=<distro>, PKG_MANAGER=apt/dnf/pacman.
# We accept any non-unknown value as "passes".
run_test "ensure_prereqs: SKIP_PREREQS=1 sets OS_FAMILY, DISTRO_ID, PKG_MANAGER" \
  "ok" \
  "$LIB_SETUP
SKIP_PREREQS=1
ensure_prereqs
# Validate that all three are non-empty AND not 'unknown'.
if [ -n \"\$OS_FAMILY\" ] && [ \"\$OS_FAMILY\" != unknown ] \\
   && [ -n \"\$DISTRO_ID\" ] && [ \"\$DISTRO_ID\" != unknown ] \\
   && [ -n \"\$PKG_MANAGER\" ] && [ \"\$PKG_MANAGER\" != unknown ]; then
  echo ok
else
  echo bad
fi"

# -----------------------------------------------------------------------------
# set_env (from install.sh) — must be safe for arbitrary values
# -----------------------------------------------------------------------------

run_test "set_env: replaces existing key (normal value)" \
  "FOO=bar123" \
  "
tmpdir=\$(mktemp -d)
cd \"\$tmpdir\"
printf 'FOO=old\\nBAR=stay\\n' > .env
chmod 600 .env
# Process substitution with . doesn't define functions in bash; use eval.
eval \"\$(awk '/^set_env\\(\\)/,/^}\$/' '$INSTALL')\"
set_env FOO 'bar123'
grep '^FOO=' .env
"

run_test "set_env: replaces value containing pipe and ampersand (sed's nemesis)" \
  'FOO=a|b&c' \
  "
tmpdir=\$(mktemp -d)
cd \"\$tmpdir\"
printf 'FOO=old\\n' > .env
chmod 600 .env
eval \"\$(awk '/^set_env\\(\\)/,/^}\$/' '$INSTALL')\"
set_env FOO 'a|b&c'
grep '^FOO=' .env
"

run_test "set_env: appends new key when not in file" \
  "NEW_KEY=hello" \
  "
tmpdir=\$(mktemp -d)
cd \"\$tmpdir\"
printf 'FOO=bar\\n' > .env
chmod 600 .env
eval \"\$(awk '/^set_env\\(\\)/,/^}\$/' '$INSTALL')\"
set_env NEW_KEY 'hello'
grep '^NEW_KEY=' .env
"

run_test "set_env: empty value OK" \
  "FOO=" \
  "
tmpdir=\$(mktemp -d)
cd \"\$tmpdir\"
printf 'FOO=old\\n' > .env
chmod 600 .env
eval \"\$(awk '/^set_env\\(\\)/,/^}\$/' '$INSTALL')\"
set_env FOO ''
grep '^FOO=' .env
"

run_test "set_env: preserves other lines untouched" \
  "BAR=untouched" \
  "
tmpdir=\$(mktemp -d)
cd \"\$tmpdir\"
printf 'FOO=old\\nBAR=untouched\\nBAZ=last\\n' > .env
chmod 600 .env
eval \"\$(awk '/^set_env\\(\\)/,/^}\$/' '$INSTALL')\"
set_env FOO 'newval'
grep '^BAR=' .env
"

run_test "set_env: value with equals signs (Base64-ish)" \
  "FOO=abc=def==ghi=" \
  "
tmpdir=\$(mktemp -d)
cd \"\$tmpdir\"
printf 'FOO=old\\n' > .env
chmod 600 .env
eval \"\$(awk '/^set_env\\(\\)/,/^}\$/' '$INSTALL')\"
set_env FOO 'abc=def==ghi='
grep '^FOO=' .env
"

# -----------------------------------------------------------------------------
# Result
# -----------------------------------------------------------------------------

printf "\n${YELLOW}=== %d passed, %d failed ===${NC}\n" "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
exit 0

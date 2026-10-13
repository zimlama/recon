#!/usr/bin/env bash
# =============================================================================
# install_lib.sh — Detection + install helpers, extracted for unit testing.
#
# Sourced by install.sh (top of file) and by tests/install_tests.sh.
# All functions are pure: they read env, do detection, and print. They do NOT
# modify global state except for the assigned globals documented below.
#
# Globals written (so callers can read them after ensure_prereqs runs):
#   OS_FAMILY       — macos | linux | wsl | unknown
#   DISTRO_ID       — ubuntu | debian | fedora | rhel | centos | rocky |
#                     almalinux | arch | manjaro | pop | linuxmint |
#                     elementary | macos | unknown
#   PKG_MANAGER     — apt | dnf | pacman | brew | unknown
#
# Tested by tests/install_tests.sh (pure bash, no root).
# =============================================================================

# ---- OS / Distro / Package manager detection --------------------------------

detect_os_family() {
  # Returns: macos | linux | wsl | unknown
  case "$(uname -s)" in
    Darwin) echo "macos" ;;
    Linux)
      if grep -qiE "microsoft|wsl" /proc/version 2>/dev/null; then
        echo "wsl"
      else
        echo "linux"
      fi
      ;;
    *) echo "unknown" ;;
  esac
}

detect_distro_id() {
  # Returns distro ID (lowercased) or "unknown".
  if [ "$(uname -s)" = "Darwin" ]; then
    echo "macos"
    return
  fi
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    printf "%s\n" "$ID" | tr '[:upper:]' '[:lower:]'
  elif [ -f /etc/lsb-release ]; then
    # shellcheck disable=SC1091
    . /etc/lsb-release
    printf "%s\n" "$DISTRIB_ID" | tr '[:upper:]' '[:lower:]'
  else
    echo "unknown"
  fi
}

detect_package_manager() {
  # Args: distro_id. Returns: apt | dnf | pacman | brew | unknown.
  local distro="$1"
  case "$distro" in
    ubuntu|debian|pop|linuxmint|elementary) echo "apt" ;;
    fedora)                                echo "dnf" ;;
    rhel|centos|rocky|almalinux)           echo "dnf" ;;
    arch|manjaro|endeavouros)              echo "pacman" ;;
    macos)                                 echo "brew" ;;
    *)                                     echo "unknown" ;;
  esac
}

# ---- Privilege helpers -------------------------------------------------------

is_root() {
  [ "$(id -u)" -eq 0 ]
}

sudo_cmd() {
  # Echo "sudo" if we need it, or "" if we're already root.
  if is_root; then echo ""; else echo "sudo"; fi
}

# ---- Per-package-manager install helpers ------------------------------------

pkg_install_native() {
  # Args: package_manager packages...
  local pm="$1"; shift
  local sudo
  sudo="$(sudo_cmd)"
  case "$pm" in
    apt)
      $sudo apt-get update -qq
      $sudo apt-get install -y "$@"
      ;;
    dnf)
      $sudo dnf install -y "$@"
      ;;
    pacman)
      $sudo pacman -S --noconfirm "$@"
      ;;
    *) die "pkg_install_native: unsupported package manager: $pm" ;;
  esac
}

# ---- Individual prereq installers -------------------------------------------

ensure_brew() {
  if command -v brew >/dev/null 2>&1; then
    ok "brew already installed: $(command -v brew)"
    return 0
  fi
  log "Installing Homebrew..."
  NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  # Add brew to PATH for the rest of this session (Apple Silicon default location).
  if [ -f /opt/homebrew/bin/brew ]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
  elif [ -f /usr/local/bin/brew ]; then
    eval "$(/usr/local/bin/brew shellenv)"
  fi
}

ensure_git() {
  if command -v git >/dev/null 2>&1; then
    ok "git already installed: $(command -v git)"
    return 0
  fi
  log "Installing git..."
  case "$PKG_MANAGER" in
    apt)    pkg_install_native apt git ;;
    dnf)    pkg_install_native dnf git ;;
    pacman) pkg_install_native pacman git ;;
    brew)
      ensure_brew
      brew install git
      ;;
    *) die "Cannot install git: unsupported package manager $PKG_MANAGER" ;;
  esac
}

ensure_python3() {
  if command -v python3 >/dev/null 2>&1; then
    ok "python3 already installed: $(command -v python3) ($(python3 --version))"
    return 0
  fi
  log "Installing python3..."
  case "$PKG_MANAGER" in
    apt)    pkg_install_native apt python3 python3-pip python3-venv ca-certificates gnupg curl ;;
    dnf)    pkg_install_native dnf python3 python3-pip ca-certificates gnupg curl ;;
    pacman) pkg_install_native pacman python python-pip ca-certificates gnupg curl ;;
    brew)
      ensure_brew
      brew install python3
      ;;
    *) die "Cannot install python3: unsupported package manager $PKG_MANAGER" ;;
  esac
}

ensure_python_cryptography() {
  if python3 -c "import cryptography" 2>/dev/null; then
    ok "python3-cryptography already installed"
    return 0
  fi
  log "Installing python3-cryptography..."
  local sudo
  sudo="$(sudo_cmd)"
  case "$PKG_MANAGER" in
    apt)
      pkg_install_native apt python3-cryptography \
        || $sudo pip3 install --break-system-packages cryptography
      ;;
    dnf)
      pkg_install_native dnf python3-cryptography \
        || $sudo pip3 install cryptography
      ;;
    pacman)
      pkg_install_native pacman python-cryptography \
        || $sudo pip3 install cryptography
      ;;
    brew)
      brew install cryptography \
        || pip3 install --user cryptography
      ;;
    *)
      $sudo pip3 install cryptography
      ;;
  esac
}

ensure_docker_linux() {
  if command -v docker >/dev/null 2>&1; then
    ok "docker already installed: $(command -v docker)"
    return 0
  fi
  log "Installing Docker (Linux)..."
  local sudo
  sudo="$(sudo_cmd)"
  case "$PKG_MANAGER" in
    apt)
      # Docker's apt repo only supports ubuntu + debian.
      # Ubuntu-derivatives (pop, linuxmint, elementary) reuse the ubuntu repo.
      local distro_id codename docker_distro
      distro_id="$(detect_distro_id)"
      # shellcheck disable=SC1091
      . /etc/os-release
      codename="${VERSION_CODENAME:-}"
      if [ -z "$codename" ]; then
        die "Cannot read VERSION_CODENAME from /etc/os-release. Add the Docker repo manually: https://docs.docker.com/engine/install/"
      fi
      case "$distro_id" in
        ubuntu|debian)     docker_distro="$distro_id" ;;
        pop|linuxmint|elementary|zorin|kubuntu) docker_distro="ubuntu" ;;
        *)                 docker_distro="$distro_id" ;;
      esac
      # Verify the codename exists in Docker's repo for this distro (some derivatives
      # use different codenames that aren't shipped there).
      if ! curl -fsSI -o /dev/null -w '%{http_code}' "https://download.docker.com/linux/${docker_distro}/dists/${codename}/Release" \
          | grep -q '^200$'; then
        die "Docker does not publish packages for ${distro_id} (codename ${codename}). Install Docker manually: https://docs.docker.com/engine/install/${distro_id}/"
      fi
      $sudo install -m 0755 -d /etc/apt/keyrings
      curl -fsSL "https://download.docker.com/linux/${docker_distro}/gpg" \
        | $sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
      $sudo chmod a+r /etc/apt/keyrings/docker.gpg
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${docker_distro} ${codename} stable" \
        | $sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
      $sudo apt-get update -qq
      pkg_install_native apt docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
      ;;
    dnf)
      $sudo dnf -y install dnf-plugins-core
      $sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
      pkg_install_native dnf docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
      ;;
    pacman)
      pkg_install_native pacman docker docker-compose
      ;;
    *)
      die "Cannot auto-install Docker for package manager: $PKG_MANAGER. Install manually: https://docs.docker.com/engine/install/"
      ;;
  esac
}

ensure_docker_macos() {
  if command -v docker >/dev/null 2>&1; then
    ok "docker already installed: $(command -v docker)"
    return 0
  fi
  log "Installing Docker Desktop (macOS via Homebrew Cask)..."
  ensure_brew
  brew install --cask docker-desktop
  warn "Docker Desktop installed (Cask). Next steps:"
  warn "  1. Launch Docker Desktop from Applications (or Spotlight: 'Docker Desktop')"
  warn "  2. Accept the Docker Subscription Service Agreement when prompted"
  warn "  3. Wait for the menu-bar icon to stop animating"
  warn "  4. Re-run this installer (./install.sh) — it will skip installation and start the build"
}

ensure_docker() {
  if [ "$OS_FAMILY" = "macos" ]; then
    ensure_docker_macos
  else
    ensure_docker_linux
  fi
}

ensure_user_in_docker_group() {
  if [ "$OS_FAMILY" = "macos" ]; then
    return 0  # macOS Docker Desktop runs as the user, no group needed.
  fi
  local current_user
  current_user="${SUDO_USER:-$(whoami)}"
  if id -nG "$current_user" 2>/dev/null | grep -qw docker; then
    ok "User $current_user already in docker group"
    return 0
  fi
  log "Adding user $current_user to docker group..."
  local sudo
  sudo="$(sudo_cmd)"
  $sudo usermod -aG docker "$current_user" \
    || warn "Could not add user to docker group — you may need to run docker with sudo"
}

ensure_docker_daemon_running() {
  # If the user can already access docker, nothing to do.
  if docker info >/dev/null 2>&1; then
    ok "Docker daemon is running"
    return 0
  fi
  log "Starting Docker daemon..."
  local sudo
  sudo="$(sudo_cmd)"
  case "$OS_FAMILY" in
    macos)
      warn "On macOS, launch Docker Desktop from Applications (Spotlight → 'Docker Desktop')."
      warn "Wait for the menu-bar icon to stop animating, then press Enter."
      if [ -t 0 ]; then
        read -r -p "  Press Enter when Docker Desktop is running (or Ctrl+C to abort)..."
      fi
      if docker info >/dev/null 2>&1; then
        ok "Docker daemon is now running"
      else
        die "Docker daemon still not reachable. Launch Docker Desktop manually and re-run."
      fi
      ;;
    linux|wsl)
      if command -v systemctl >/dev/null 2>&1; then
        if ! $sudo systemctl enable --now docker 2>&1 | grep -v 'Created symlink' | tee -a /tmp/docker-install.log >/dev/null; then
          warn "systemctl enable --now docker returned non-zero — check /tmp/docker-install.log"
        fi
      else
        $sudo service docker start || warn "Could not start docker — start it manually with 'sudo service docker start'"
      fi
      # Give the daemon a beat to fully initialize (it can take 3-5s after unit activation).
      for _ in 1 2 3 4 5 6; do
        if $sudo docker info >/dev/null 2>&1; then break; fi
        sleep 1
      done
      # Authoritative check: can sudo reach the daemon?
      if ! $sudo docker info >/dev/null 2>&1; then
        warn "Docker daemon did not start. Last journal entries:"
        $sudo journalctl -u docker.service -n 15 --no-pager 2>/dev/null | sed 's/^/    /' || true
        die "Cannot start Docker daemon. Investigate: 'sudo journalctl -u docker -n 50'"
      fi
      ok "Docker daemon is running (verified via sudo)"
      # Best-effort user-level access. If we just added the user to the docker
      # group, this fails until the session picks up the new supplementary
      # group (which requires re-login — OR a re-exec via `sg docker`, see
      # install.sh Step 1.3).
      if ! docker info >/dev/null 2>&1; then
        DOCKER_REQUIRES_RELOGIN=1
        warn "Docker daemon is up but your user can't access it yet."
        warn "Reason: usermod added you to 'docker' group; the change hasn't"
        warn "        propagated to this shell session. The installer will"
        warn "        re-exec via 'sg docker' to pick it up inline."
      fi
      return 0
      ;;
  esac
}

# ---- Main orchestrator ------------------------------------------------------

ensure_prereqs() {
  if [ "${SKIP_PREREQS:-0}" = "1" ]; then
    log "Skipping prereq install (--skip-prereqs)"
    # Still detect globals so callers can read them.
    OS_FAMILY="$(detect_os_family)"
    DISTRO_ID="$(detect_distro_id)"
    PKG_MANAGER="$(detect_package_manager "$DISTRO_ID")"
    return 0
  fi

  OS_FAMILY="$(detect_os_family)"
  DISTRO_ID="$(detect_distro_id)"
  PKG_MANAGER="$(detect_package_manager "$DISTRO_ID")"

  if [ "$PKG_MANAGER" = "unknown" ]; then
    die "Unsupported OS / distro: $(uname -s) / ${DISTRO_ID}. Auto-install supports macOS, Ubuntu/Debian, Fedora/RHEL, Arch. Install manually: git, docker, python3."
  fi

  log "Detected: OS=$OS_FAMILY, distro=$DISTRO_ID, package manager=$PKG_MANAGER"

  if [ "$OS_FAMILY" != "macos" ] && ! is_root && ! command -v sudo >/dev/null 2>&1; then
    die "sudo is required to install system packages. Install sudo or run as root."
  fi

  ensure_git
  ensure_python3
  ensure_python_cryptography
  ensure_docker
  ensure_user_in_docker_group
  ensure_docker_daemon_running

  ok "System prerequisites ready"
}

#!/bin/sh
# Common helpers for Crypta Linux installers (DEB/RPM)
# Safe to source from maintainer scripts and RPM spec scriptlets.

LOG_FILE="${CRYPTA_LOG:-/var/log/crypta-installer.log}"

# Basic timestamped logging. Only active when CRYPTA_DEBUG=1 to avoid noise.
log_line() {
  [ "${CRYPTA_DEBUG:-}" = "1" ] || return 0
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  msg="$*"
  # Ensure world-readable log file (no secrets; helps debugging without root later)
  umask 022
  printf '[%s] %s\n' "$ts" "$msg" | tee -a "$LOG_FILE" >/dev/null
}

# Honor CRYPTA_DEBUG=1 for shell tracing during install/uninstall.
if [ "${CRYPTA_DEBUG:-}" = "1" ]; then
  set -x
  log_line "CRYPTA_DEBUG=1: shell tracing enabled"
fi

is_desktop() {
  # Treat as desktop when a display manager is enabled/active.
  if command -v systemctl >/dev/null 2>&1; then
    # Directly probe the generic alias even if not listed in unit-files.
    if systemctl is-enabled display-manager >/dev/null 2>&1 || \
       systemctl is-active display-manager >/dev/null 2>&1; then
      return 0
    fi
    # Common DMs (Fedora/Ubuntu/Arch variants)
    for dm in gdm sddm lightdm ly xdm; do
      if systemctl is-enabled "$dm" >/dev/null 2>&1 || \
         systemctl is-active "$dm" >/dev/null 2>&1; then
        return 0
      fi
    done
  fi
  # Fallback: presence of session files
  ls /usr/share/xsessions/*.desktop >/dev/null 2>&1 && return 0
  ls /usr/share/wayland-sessions/*.desktop >/dev/null 2>&1 && return 0
  return 1
}

ensure_user() {
  # Ensure system group explicitly to match Group= in the service unit
  if ! getent group cryptad >/dev/null 2>&1; then
    if command -v groupadd >/dev/null 2>&1; then
      groupadd --system cryptad || true
    elif command -v addgroup >/dev/null 2>&1; then
      addgroup --system cryptad || true
    fi
  fi
  # Ensure system user with primary group cryptad
  if ! id -u cryptad >/dev/null 2>&1; then
    if command -v useradd >/dev/null 2>&1; then
      useradd --system --home-dir /var/lib/cryptad --shell /usr/sbin/nologin \
        --gid cryptad --comment "Cryptad service user" cryptad || true
    fi
  else
    if command -v usermod >/dev/null 2>&1; then
      usermod -g cryptad cryptad >/dev/null 2>&1 || true
    fi
  fi
  install -d -m 0750 -o cryptad -g cryptad /var/lib/cryptad || true
}

service_disable_quiet() {
  unit="${1:-cryptad.service}"
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-enabled "$unit" >/dev/null 2>&1 || systemctl is-active "$unit" >/dev/null 2>&1; then
      systemctl disable --now "$unit" >/dev/null 2>&1 || true
    fi
  fi
}

refresh_desktop_caches() {
  if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
    update-desktop-database -q /usr/local/share/applications || true
  fi
  if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t /usr/share/icons/hicolor || true
  fi
}

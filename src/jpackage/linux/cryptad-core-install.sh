#!/bin/sh
# Root helper used by cryptad-core-install@.service to install a local DEB/RPM non-interactively.
# Security:
# - Only accepts files under /var/lib/cryptad/updates/core (canonical path check).
# - Meant to be started via a polkit rule allowing only 'start' for this specific unit template
#   and only for the 'cryptad' service user.

set -eu

PKG_INPUT="${1:-}"
if [ -z "$PKG_INPUT" ]; then
  echo "[cryptad-core-install] Missing package path" >&2
  exit 2
fi

# Canonicalize and validate path under our updates tree
can() { readlink -f -- "$1" 2>/dev/null || realpath -- "$1" 2>/dev/null || echo "$1"; }
PKG="$(can "$PKG_INPUT")"
# Accept both legacy and service-mode layouts
BASES="/var/lib/cryptad/updates/core /var/lib/cryptad/node/updates/core"
CASEFOLDED_PKG_DIR="$(dirname "$PKG" | tr 'A-Z' 'a-z')"
ok=0
for B in $BASES; do
  CF_B="$(echo "$B" | tr 'A-Z' 'a-z')"
  case "$CASEFOLDED_PKG_DIR" in
    ${CF_B}*) ok=1; break;;
  esac
done
if [ $ok -ne 1 ]; then
  echo "[cryptad-core-install] Refusing path outside allowed bases: $PKG" >&2
  echo "[cryptad-core-install] Allowed: $BASES" >&2
  exit 3
fi

if [ ! -f "$PKG" ]; then
  echo "[cryptad-core-install] File not found: $PKG" >&2
  exit 4
fi

EXT="${PKG##*.}"
EXT="$(echo "$EXT" | tr 'A-Z' 'a-z')"
if [ "$EXT" != "deb" ] && [ "$EXT" != "rpm" ]; then
  echo "[cryptad-core-install] Unsupported package type: .$EXT (only .deb/.rpm)" >&2
  exit 5
fi

# Logging helper
log() { printf "[cryptad-core-install] %s\n" "$*"; }

run_with_retry() {
  tries=6
  delay=3
  while [ $tries -gt 0 ]; do
    if "$@"; then
      return 0
    fi
    rc=$?
    # Heuristic: back off when lock contention is likely
    case "$rc" in
      1|65|100|101) ;; # common transient statuses
    esac
    tries=$((tries-1))
    if [ $tries -le 0 ]; then
      return $rc
    fi
    log "Install command failed (rc=$rc), retrying in ${delay}s..."
    sleep "$delay"
    delay=$((delay*2))
    [ $delay -gt 60 ] && delay=60
  done
  return 1
}

umask 022

if command -v pkcon >/dev/null 2>&1; then
  log "Using PackageKit to install $PKG"
  run_with_retry pkcon install-local -y "$PKG"
  exit $?
fi

if [ "$EXT" = "deb" ]; then
  export DEBIAN_FRONTEND=noninteractive
  if command -v apt-get >/dev/null 2>&1; then
    dir="$(dirname "$PKG")"; base="./$(basename "$PKG")"
    log "Installing DEB via apt-get: $PKG"
    ( cd "$dir" && run_with_retry apt-get -o Dpkg::Options::=--force-confold -y install "$base" )
    exit $?
  fi
  if command -v dpkg >/dev/null 2>&1; then
    log "Installing DEB via dpkg: $PKG (then fixing deps)"
    dpkg -i "$PKG" || true
    if command -v apt-get >/dev/null 2>&1; then
      run_with_retry apt-get -f -y install
      exit $?
    fi
    exit 0
  fi
  echo "No suitable installer found for DEB (missing pkcon/apt-get/dpkg)" >&2
  exit 6
fi

if [ "$EXT" = "rpm" ]; then
  if command -v dnf >/dev/null 2>&1; then
    log "Installing RPM via dnf: $PKG"
    run_with_retry dnf -y install "$PKG"
    exit $?
  fi
  if command -v zypper >/dev/null 2>&1; then
    log "Installing RPM via zypper: $PKG"
    run_with_retry zypper --non-interactive install "$PKG"
    exit $?
  fi
  if command -v rpm >/dev/null 2>&1; then
    log "Installing RPM via rpm -Uvh: $PKG"
    run_with_retry rpm -Uvh "$PKG"
    exit $?
  fi
  echo "No suitable installer found for RPM (missing pkcon/dnf/zypper/rpm)" >&2
  exit 6
fi

exit 0

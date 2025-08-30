#!/usr/bin/env bash
set -euo pipefail

# Resolve installation root (../ from bin)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."
BIN_DIR="$ROOT_DIR/bin"
CONF_DIR="$ROOT_DIR/conf"
LIB_DIR="$ROOT_DIR/lib"
TMP_DIR="$ROOT_DIR/tmp"

# If running inside a Snap, prefer user-writable working directory
if [ -n "${SNAP_USER_COMMON:-}" ]; then
  cd "$SNAP_USER_COMMON"
fi

CONF="$CONF_DIR/wrapper.conf"
if [ ! -f "$CONF" ]; then
  echo "Missing configuration at $CONF" >&2
  exit 1
fi

# Friendly warning when running as root in interactive mode
if [ "$EUID" -eq 0 ] && [ -z "${CRYPTAD_ALLOW_ROOT:-}" ]; then
  echo "Refusing to run as root. Create a service or use a non-root user." >&2
  echo "Set CRYPTAD_ALLOW_ROOT=1 to override." >&2
  exit 1
fi

# Resolve native wrapper
WRAPPER="$BIN_DIR/wrapper"
OS_RAW=$(uname -s 2>/dev/null || echo unknown)
ARCH_RAW=$(uname -m 2>/dev/null || echo unknown)

normalize_os() {
  # Lowercase argument in a Bash-3 compatible way (macOS ships Bash 3.2)
  # Avoids ${var,,} which is Bash 4+ only.
  local in
  in=$(printf "%s" "$1" | tr '[:upper:]' '[:lower:]')
  case "$in" in
    darwin) echo macosx ;;
    linux|gnu/linux|linux-gnu) echo linux ;;
    *) echo "$in" ;;
  esac
}

# Prefer Snap and distro hints when available
detect_arch() {
  # Use default expansion to be compatible with 'set -u' when SNAP_ARCH is not set
  local snap_arch="${SNAP_ARCH:-}"  # set by Snap: amd64, arm64, armhf, ppc64el, s390x, riscv64
  local dpkg_arch=""
  if command -v dpkg >/dev/null 2>&1; then
    dpkg_arch=$(dpkg --print-architecture 2>/dev/null || true)
  fi
  local raw="$ARCH_RAW"

  local src=""
  local a=""
  if [ -n "$snap_arch" ]; then
    a="$snap_arch"; src="SNAP_ARCH"
  elif [ -n "$dpkg_arch" ]; then
    a="$dpkg_arch"; src="dpkg"
  else
    a="$raw"; src="uname"
  fi

  local dist_arch=""; local dist_bit=""
  case "$a" in
    x86_64|amd64) dist_arch=x86 ; dist_bit=64 ;;
    i386|i486|i586|i686) dist_arch=x86 ; dist_bit=32 ;;
    aarch64|arm64) dist_arch=aarch64 ; dist_bit=64 ;;
    armv8*) dist_arch=aarch64 ; dist_bit=64 ;;
    armv7*|armhf) dist_arch=armhf ; dist_bit=32 ;;
    armv6*) dist_arch=armhf ; dist_bit=32 ;;
    ppc64le|ppc64el) dist_arch=ppc64le ; dist_bit=64 ;;
    s390x) dist_arch=s390x ; dist_bit=64 ;;
    riscv64) dist_arch=riscv64 ; dist_bit=64 ;;
    *)
      # Fallback: keep raw arch, infer bits from getconf if possible
      dist_arch="$a"
      if command -v getconf >/dev/null 2>&1; then
        dist_bit=$(getconf LONG_BIT 2>/dev/null || echo 64)
      else
        dist_bit=64
      fi
      ;;
  esac

  echo "$dist_arch:$dist_bit:$src:$a"
}

DIST_OS=$(normalize_os "$OS_RAW")
IFS=":" read -r DIST_ARCH DIST_BIT ARCH_SRC ARCH_INPUT < <(detect_arch)

# Map to distribution wrapper naming (what files are called in bin/)
# Examples present in distrib:
#  - wrapper-linux-arm-64
#  - wrapper-linux-x86-64
#  - wrapper-macosx-arm-64
#  - wrapper-macosx-universal-64
WRAP_OS="$DIST_OS"
WRAP_ARCH="$DIST_ARCH"
WRAP_BIT="$DIST_BIT"
case "$DIST_OS" in
  linux)
    case "$DIST_ARCH" in
      aarch64|arm64|armhf|arm*) WRAP_ARCH=arm ;;
      x86|amd64|x86_64|i386|i486|i586|i686) WRAP_ARCH=x86 ;;
    esac
    ;;
  macosx)
    case "$DIST_ARCH" in
      aarch64|arm64|arm*) WRAP_ARCH=arm ; WRAP_BIT=64 ;;
      *) WRAP_ARCH=universal ; WRAP_BIT=64 ;;
    esac
    ;;
esac

# Try generic wrapper first
if [ ! -x "$WRAPPER" ]; then
  CANDIDATES=(
    "$BIN_DIR/wrapper-$WRAP_OS-$WRAP_ARCH-$WRAP_BIT"
    "$BIN_DIR/wrapper-$DIST_OS-$DIST_ARCH-$DIST_BIT"
    "$BIN_DIR/wrapper-$DIST_OS-universal-$DIST_BIT"
    "$BIN_DIR/wrapper-$DIST_OS-arm64-$DIST_BIT"
    "$BIN_DIR/wrapper-$DIST_OS-amd64-$DIST_BIT"
  )
  for c in "${CANDIDATES[@]}"; do
    if [ -x "$c" ]; then WRAPPER="$c"; break; fi
  done
fi

# Print directory diagnostics to help users verify paths
echo "[cryptad] Directory layout"
echo "  SCRIPT_DIR=$SCRIPT_DIR"
echo "  ROOT_DIR=$ROOT_DIR"
echo "  BIN_DIR=$BIN_DIR"
echo "  CONF_DIR=$CONF_DIR"
echo "  LIB_DIR=$LIB_DIR"
echo "  TMP_DIR=$TMP_DIR"
echo "  WRAPPER=$WRAPPER"
echo "  DETECTED_OS=$DIST_OS (raw=$OS_RAW)"
echo "  DETECTED_ARCH=$DIST_ARCH (bits=$DIST_BIT source=$ARCH_SRC input=$ARCH_INPUT raw=$ARCH_RAW)"
echo "  WRAP_TARGET=$WRAP_OS-$WRAP_ARCH-$WRAP_BIT"

if [ -x "$WRAPPER" ]; then
  exec "$WRAPPER" -c "$CONF" "$@"
fi

echo "No native wrapper found or not executable: $WRAPPER" >&2
echo "Searched in: $BIN_DIR" >&2
echo "Please install the appropriate native wrapper for $DIST_OS/$DIST_ARCH or rebuild the distribution." >&2
exit 1

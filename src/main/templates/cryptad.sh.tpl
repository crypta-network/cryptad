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

# Prefer the jpackage-bundled runtime, when present, so the
# Java Service Wrapper can reliably find a compatible `java`.
# We discover common jpackage layouts and prepend their `bin`
# directory to PATH. This does not override explicit JAVA_HOME
# within the Wrapper; it only influences PATH-based discovery.
add_path_prefix() {
  case ":$PATH:" in
    *":$1:"*) return 0 ;;  # already present
    *) PATH="$1:$PATH" ; export PATH ;;
  esac
}

# Candidates relative to the distribution root inside a jpackage image.
# Layouts:
#  - Linux:   <image>/lib/runtime/bin/java
#  - macOS:   <app>.app/Contents/runtime/Contents/Home/bin/java
#  - Windows: <image>/app/runtime/bin/java.exe (handled by .bat script)
# From ROOT_DIR (= .../cryptad-dist), reach the image root parents and test.
JPKG_CANDIDATES=(
  "$ROOT_DIR/../../runtime/bin"                  # Linux
  "$ROOT_DIR/../../runtime/Contents/Home/bin"   # macOS
)
for jb in "${JPKG_CANDIDATES[@]}"; do
  if [ -x "$jb/java" ]; then
    add_path_prefix "$jb"
    JPKG_JAVA_BIN="$jb/java"
    break
  fi
done

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

# Optional: enable Java remote debugging when requested via environment.
# When CRYPTAD_REMOTE_DEBUG is set (to any value), we append a JDWP agent option
# using Wrapper command-line properties so it applies only for this run.
# Tuning via env (all optional):
#   CRYPTAD_DEBUG_PORT     default: 5005
#   CRYPTAD_DEBUG_HOST     default: 127.0.0.1  (use '*' to listen on all interfaces)
#   CRYPTAD_DEBUG_SUSPEND  default: n         (use 'y' to wait for debugger)
#   CRYPTAD_DEBUG_TIMEOUT  default: unset     (milliseconds; optional)
EXTRA_PROPS=()
DEBUG_DESC="off"
if [ -n "${CRYPTAD_REMOTE_DEBUG:-}" ]; then
  DEBUG_HOST="${CRYPTAD_DEBUG_HOST:-127.0.0.1}"
  DEBUG_PORT="${CRYPTAD_DEBUG_PORT:-5005}"
  DEBUG_SUSPEND="${CRYPTAD_DEBUG_SUSPEND:-n}"
  DEBUG_TIMEOUT_OPT=""
  if [ -n "${CRYPTAD_DEBUG_TIMEOUT:-}" ]; then
    DEBUG_TIMEOUT_OPT=",timeout=${CRYPTAD_DEBUG_TIMEOUT}"
  fi
  JDWP_OPT="-agentlib:jdwp=transport=dt_socket,server=y,suspend=${DEBUG_SUSPEND},address=${DEBUG_HOST}:${DEBUG_PORT}${DEBUG_TIMEOUT_OPT} "
  # Allow non-contiguous numbering and use a high index to avoid collisions with wrapper.conf
  EXTRA_PROPS+=("wrapper.ignore_sequence_gaps=TRUE")
  EXTRA_PROPS+=("wrapper.java.additional.250=${JDWP_OPT}")
  EXTRA_PROPS+=("wrapper.java.additional.251=-Xdebug")
  DEBUG_DESC="enabled (${DEBUG_HOST}:${DEBUG_PORT} suspend=${DEBUG_SUSPEND})"
fi

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
echo "  REMOTE_DEBUG=$DEBUG_DESC"
if [ -n "${JPKG_JAVA_BIN:-}" ]; then
  echo "  JPACKAGE_JAVA=$JPKG_JAVA_BIN (prepended to PATH)"
fi

if [ -x "$WRAPPER" ]; then
  if (( ${#EXTRA_PROPS[@]} > 0 )); then
    exec "$WRAPPER" -c "$CONF" "${EXTRA_PROPS[@]}" "$@"
  else
    exec "$WRAPPER" -c "$CONF" "$@"
  fi
fi

echo "No native wrapper found or not executable: $WRAPPER" >&2
echo "Searched in: $BIN_DIR" >&2
echo "Please install the appropriate native wrapper for $DIST_OS/$DIST_ARCH or rebuild the distribution." >&2
exit 1

#!/usr/bin/env bash
set -euo pipefail

# Resolve installation root (../ from bin)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."
BIN_DIR="$ROOT_DIR/bin"
CONF_DIR="$ROOT_DIR/conf"
LIB_DIR="$ROOT_DIR/lib"
TMP_DIR="$ROOT_DIR/tmp"

CONF="$CONF_DIR/wrapper.conf"
if [ ! -f "$CONF" ]; then
  echo "Missing configuration at $CONF" >&2
  exit 1
fi

# Friendly warning when running as root in interactive mode
if [ "$EUID" -eq 0 ] && [ -z "$CRYPTAD_ALLOW_ROOT" ]; then
  echo "Refusing to run as root. Create a service or use a non-root user." >&2
  echo "Set CRYPTAD_ALLOW_ROOT=1 to override." >&2
  exit 1
fi

# Resolve native wrapper
WRAPPER="$BIN_DIR/wrapper"
OS=$(uname -s || echo unknown)
ARCH=$(uname -m || echo unknown)

# Normalize identifiers
case "$OS" in
  Darwin) DIST_OS=macosx ;;
  Linux)  DIST_OS=linux ;;
  *) DIST_OS=$OS ;;
esac
case "$ARCH" in
  x86_64|amd64) DIST_ARCH=x86 ; DIST_BIT=64 ;;
  aarch64|arm64) DIST_ARCH=aarch64 ; DIST_BIT=64 ;;
  *) DIST_ARCH=$ARCH ; DIST_BIT=64 ;;
esac

# Try generic wrapper first
if [ ! -x "$WRAPPER" ]; then
  CANDIDATES=(
    "$BIN_DIR/wrapper-$DIST_OS-$DIST_ARCH-$DIST_BIT"
    "$BIN_DIR/wrapper-$DIST_OS-universal-$DIST_BIT"
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

if [ -x "$WRAPPER" ]; then
  exec "$WRAPPER" -c "$CONF" "$@"
fi

echo "No native wrapper found or not executable: $WRAPPER" >&2
echo "Searched in: $BIN_DIR" >&2
echo "Please install the appropriate native wrapper for $DIST_OS/$DIST_ARCH or rebuild the distribution." >&2
exit 1

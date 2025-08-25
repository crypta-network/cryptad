#!/usr/bin/env bash
set -euo pipefail

# Resolve installation root (../ from bin)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."

CONF="$ROOT_DIR/conf/wrapper.conf"
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

# If CRYPTAD_NO_WRAPPER=1, or no wrapper binary is available, run with plain java.
USE_WRAPPER=1
if [ "${CRYPTAD_NO_WRAPPER:-0}" = "1" ]; then
  USE_WRAPPER=0
fi

WRAPPER="$ROOT_DIR/bin/wrapper"
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
    "$ROOT_DIR/bin/wrapper-$DIST_OS-$DIST_ARCH-$DIST_BIT"
    "$ROOT_DIR/bin/wrapper-$DIST_OS-universal-$DIST_BIT"
  )
  for c in "${CANDIDATES[@]}"; do
    if [ -x "$c" ]; then WRAPPER="$c"; break; fi
  done
fi

if [ "$USE_WRAPPER" = "1" ] && [ -x "$WRAPPER" ]; then
  exec "$WRAPPER" -c "$CONF" "$@"
fi

# Fallback: run Java main directly (no native wrapper). Set CRYPTAD_JAVA_OPTS to override.
JAVA_BIN="${JAVA:-}"
if [ -z "$JAVA_BIN" ] && [ -n "$JAVA_HOME" ]; then
  JAVA_BIN="$JAVA_HOME/bin/java"
fi
if [ -z "$JAVA_BIN" ]; then
  JAVA_BIN="java"
fi

JAVA_OPTS_DEFAULT=(
  "-Dnetworkaddress.cache.ttl=0"
  "-Dnetworkaddress.cache.negative.ttl=0"
  "-Djava.io.tmpdir=$ROOT_DIR/tmp/"
  "--enable-native-access=ALL-UNNAMED"
  "--add-opens=java.base/java.lang=ALL-UNNAMED"
  "--add-opens=java.base/java.util=ALL-UNNAMED"
  "--add-opens=java.base/java.io=ALL-UNNAMED"
  "--illegal-access=permit"
)

# Allow user overrides (e.g., -Xms64m -Xmx1536m etc.)
read -r -a JAVA_OPTS_USER <<< "${CRYPTAD_JAVA_OPTS:-}"

exec "$JAVA_BIN" "${JAVA_OPTS_DEFAULT[@]}" "${JAVA_OPTS_USER[@]:-}" \
  -cp "$ROOT_DIR/lib/*" \
  network.crypta.node.NodeStarter "$@"


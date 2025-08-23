#!/usr/bin/env sh
# Launcher for Cryptad via Java Service Wrapper
# Resolves the distribution root and delegates to the platform wrapper binary.

set -eu

# Resolve distribution root (script dir is bin/, root is parent)
DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

# Basic sanity checks
if [ ! -x "$DIR/bin/wrapper" ]; then
  echo "Missing wrapper binary at $DIR/bin/wrapper" >&2
  exit 1
fi
if [ ! -f "$DIR/conf/wrapper.conf" ]; then
  echo "Missing configuration at $DIR/conf/wrapper.conf" >&2
  exit 1
fi

# Do not run as root unless explicitly intended
if [ "$(id -u)" = "0" ]; then
  echo "Refusing to run as root. Create a service or use a non-root user." >&2
  exit 1
fi

exec "$DIR/bin/wrapper" -c "$DIR/conf/wrapper.conf" "$@"


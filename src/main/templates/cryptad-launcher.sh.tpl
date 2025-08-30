#!/usr/bin/env bash
set -euo pipefail

# Resolve script directory without altering working directory
DIR="$(cd "$(dirname "$0")" && pwd)"

# Prefer embedded jlink runtime when available (image/bin/java)
if [ -x "$DIR/java" ]; then
  JAVA_EXE="$DIR/java"
else
  JAVA_EXE="${JAVA_HOME:-}/bin/java"
  if [ ! -x "$JAVA_EXE" ]; then JAVA_EXE="java"; fi
fi

CP="$DIR/../lib/*"

# If running inside a Snap, prefer user-writable working directory
if [ -n "${SNAP_USER_COMMON:-}" ]; then
  cd "$SNAP_USER_COMMON"
fi

# Start the launcher without replacing this shell, so we can trap Ctrl+C
"$JAVA_EXE" -cp "$CP" network.crypta.launcher.LauncherKt "$@" &
LAUNCHER_PID=$!

cleanup() {
  if kill -0 "$LAUNCHER_PID" 2>/dev/null; then
    echo "[cryptad-launcher] Requesting graceful shutdown (TERM, waiting up to 40s)..." >&2
    # Send SIGTERM to the Java process; JVM will run the shutdown hook and stop wrapper
    kill -TERM "$LAUNCHER_PID" 2>/dev/null || true
    # Give the launcher time to stop the wrapper (INT->20s, TERM->5s, KILL->2s)
    for i in {1..80}; do  # 80 * 0.5s = 40s
      if ! kill -0 "$LAUNCHER_PID" 2>/dev/null; then break; fi
      sleep 0.5
    done
    if kill -0 "$LAUNCHER_PID" 2>/dev/null; then
      echo "[cryptad-launcher] Still running; forcing termination with KILL ..." >&2
      kill -KILL "$LAUNCHER_PID" 2>/dev/null || true
    fi
  fi
}

trap cleanup INT TERM
wait "$LAUNCHER_PID"

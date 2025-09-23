#!/usr/bin/env bash
set -euo pipefail

echo "[dummy] Crypta daemon starting..."
sleep 1
echo "Starting FProxy on 127.0.0.1,0:0:0:0:0:0:0:1:15441"
echo "[dummy] Ready to accept connections."

cleanup() {
  echo "[dummy] Caught SIGINT, shutting down..."
  sleep 1
  echo "[dummy] Bye."
  exit 130
}
trap cleanup INT

i=0
while true; do
  echo "[dummy] Tick ${i}"
  i=$((i+1))
  sleep 1
done


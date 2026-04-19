#!/bin/sh
set -eu

log_file="${CRYPTAD_APP_RUN_DIR:-.}/queue-manager.log"

printf 'Queue Manager started for %s %s\n' \
  "${CRYPTAD_APP_NAME:-Queue Manager}" \
  "${CRYPTAD_APP_VERSION:-unknown}" >>"$log_file"

trap 'printf "Queue Manager stopping\n" >>"$log_file"; exit 0' INT TERM

while :; do
  sleep 5
done

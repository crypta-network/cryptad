#!/bin/sh
set -eu

log_file="${CRYPTAD_APP_RUN_DIR:-.}/site-publisher.log"

printf 'Site Publisher started for %s %s\n' \
  "${CRYPTAD_APP_NAME:-Site Publisher}" \
  "${CRYPTAD_APP_VERSION:-unknown}" >>"$log_file"

trap 'printf "Site Publisher stopping\n" >>"$log_file"; exit 0' INT TERM

while :; do
  sleep 5
done

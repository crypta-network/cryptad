#!/bin/sh
set -eu

log_file="${CRYPTAD_APP_RUN_DIR:-.}/feed-reader.log"

printf 'Feed Reader & Publisher started for %s %s\n' \
  "${CRYPTAD_APP_NAME:-Feed Reader & Publisher}" \
  "${CRYPTAD_APP_VERSION:-unknown}" >>"$log_file"

trap 'printf "Feed Reader & Publisher stopping\n" >>"$log_file"; exit 0' INT TERM

while :; do
  sleep 5
done

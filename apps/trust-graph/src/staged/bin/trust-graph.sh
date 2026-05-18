#!/bin/sh
set -eu

log_file="${CRYPTAD_APP_RUN_DIR:-.}/trust-graph.log"

printf 'Trust Graph Preview started for %s %s\n' \
  "${CRYPTAD_APP_NAME:-Trust Graph Preview}" \
  "${CRYPTAD_APP_VERSION:-unknown}" >>"$log_file"

trap 'printf "Trust Graph Preview stopping\n" >>"$log_file"; exit 0' INT TERM

while :; do
  sleep 5
done

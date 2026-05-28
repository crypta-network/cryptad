#!/bin/sh
set -eu

log_file="${CRYPTAD_APP_RUN_DIR:-.}/social-inbox.log"
printf "Social Inbox Preview started\n" >> "$log_file"
trap 'printf "Social Inbox Preview stopping\n" >> "$log_file"; exit 0' INT TERM

while :; do
  sleep 5
done

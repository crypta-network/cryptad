#!/bin/sh
set -eu

mode="${CRYPTA_APP_MIGRATION_MODE:-}"
namespace="${CRYPTA_APP_MIGRATION_NAMESPACE:-}"
from_schema="${CRYPTA_APP_MIGRATION_FROM:-}"
to_schema="${CRYPTA_APP_MIGRATION_TO:-}"
input_payload="${CRYPTA_APP_MIGRATION_INPUT:-}"
output_payload="${CRYPTA_APP_MIGRATION_OUTPUT:-}"

if [ "$namespace" != "ui-state" ] || [ "$from_schema" != "1" ] || [ "$to_schema" != "2" ]; then
  printf 'Trust Graph Local RC migration precondition failed\n' >&2
  exit 2
fi
if [ ! -r "$input_payload" ] || [ -z "$output_payload" ]; then
  printf 'Trust Graph Local RC migration payload channel unavailable\n' >&2
  exit 2
fi

case "$mode" in
  dry-run|apply)
    awk '
    {
      pos = index($0, "\"records\"")
      if (pos > 0 && migrated == 0) {
        prefix = substr($0, 1, pos - 1)
        suffix = substr($0, pos)
        gsub(/"schemaVersion":1/, "\"schemaVersion\":2", suffix)
        print prefix suffix
        migrated = 1
        next
      }
      if (migrated != 0) {
        gsub(/"schemaVersion":1/, "\"schemaVersion\":2")
      }
      print
    }
    ' "$input_payload" > "$output_payload"
    printf 'Trust Graph Local RC app-data migration %s validated\n' "$mode"
    ;;
  *)
    printf 'Unsupported Trust Graph Local RC migration mode\n' >&2
    exit 2
    ;;
esac

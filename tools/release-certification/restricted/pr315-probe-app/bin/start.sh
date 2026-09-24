#!/bin/sh
set -eu
: "${CRYPTAD_APP_TOKEN:?AppHost launch required}"
: "${CRYPTAD_APP_DATA_DIR:?AppHost data required}"
exec /usr/bin/python3 -I -S -B "$(dirname "$0")/probe.py"

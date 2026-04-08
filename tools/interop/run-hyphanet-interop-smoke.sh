#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
BASELINE_ENV="$ROOT_DIR/tools/interop/hyphanet-baseline.env"
OUT_DIR="${INTEROP_OUT_DIR:-$ROOT_DIR/build/interop-smoke}"
CACHE_DIR="${INTEROP_CACHE_DIR:-$ROOT_DIR/build/interop-cache}"
CRYPTAD_DIST_DIR="${CRYPTAD_DIST_DIR:-$ROOT_DIR/build/cryptad-dist}"
INTEROP_SKIP_BUILD="${INTEROP_SKIP_BUILD:-0}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This interoperability smoke harness is Linux-only." >&2
  exit 1
fi

if [[ ! -f "$BASELINE_ENV" ]]; then
  echo "Missing baseline definition: $BASELINE_ENV" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required." >&2
  exit 1
fi

if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "dpkg-deb is required to extract the pinned Hyphanet Debian package." >&2
  exit 1
fi

# shellcheck disable=SC1090
set -a
source "$BASELINE_ENV"
set +a

if [[ "$INTEROP_SKIP_BUILD" != "1" ]]; then
  (
    cd "$ROOT_DIR"
    ./gradlew assembleCryptadDist
  )
fi

if [[ ! -d "$CRYPTAD_DIST_DIR" ]]; then
  echo "Cryptad dist directory not found: $CRYPTAD_DIST_DIR" >&2
  exit 1
fi

exec python3 \
  "$ROOT_DIR/tools/interop/interop_smoke.py" \
  --workspace-root "$ROOT_DIR" \
  --cryptad-dist-dir "$CRYPTAD_DIST_DIR" \
  --out-dir "$OUT_DIR" \
  --download-cache-dir "$CACHE_DIR" \
  "$@"

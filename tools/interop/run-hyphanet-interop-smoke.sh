#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASELINE_ENV="$ROOT_DIR/tools/interop/hyphanet-baseline.env"

if [[ -f "$BASELINE_ENV" ]]; then
  # shellcheck disable=SC1090
  set -a
  source "$BASELINE_ENV"
  set +a
else
  mkdir -p "$ROOT_DIR/build/interop-smoke"
  echo "Missing baseline definition: $BASELINE_ENV" | tee "$ROOT_DIR/build/interop-smoke/shell-error.txt" >&2
  exit 1
fi

OUT_DIR="${INTEROP_WORKDIR:-${INTEROP_OUT_DIR:-$ROOT_DIR/build/interop-smoke}}"
CACHE_DIR="${INTEROP_CACHE_DIR:-$OUT_DIR/downloads}"
CRYPTAD_DIST_DIR="${CRYPTAD_DIST_DIR:-$ROOT_DIR/build/cryptad-dist}"
INTEROP_SKIP_BUILD="${INTEROP_SKIP_BUILD:-0}"
INTEROP_TIMEOUT_SECONDS="${INTEROP_TIMEOUT_SECONDS:-900}"
INTEROP_STARTUP_TIMEOUT_SECONDS="${INTEROP_STARTUP_TIMEOUT_SECONDS:-180}"
INTEROP_PEER_TIMEOUT_SECONDS="${INTEROP_PEER_TIMEOUT_SECONDS:-120}"
INTEROP_REQUEST_TIMEOUT_SECONDS="${INTEROP_REQUEST_TIMEOUT_SECONDS:-300}"
INTEROP_KEEP_WORKDIR="${INTEROP_KEEP_WORKDIR:-0}"
CRYPTAD_FNP_PORT="${CRYPTAD_FNP_PORT:-19401}"
CRYPTAD_FCP_PORT="${CRYPTAD_FCP_PORT:-19402}"
HYPHANET_FNP_PORT="${HYPHANET_FNP_PORT:-19501}"
HYPHANET_FCP_PORT="${HYPHANET_FCP_PORT:-19502}"

mkdir -p "$OUT_DIR"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This interoperability smoke harness is Linux-only." | tee "$OUT_DIR/shell-error.txt" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required." | tee "$OUT_DIR/shell-error.txt" >&2
  exit 1
fi

if [[ "$INTEROP_SKIP_BUILD" != "1" ]]; then
  (
    cd "$ROOT_DIR"
    ./gradlew assembleCryptadDist
  )
fi

if [[ ! -d "$CRYPTAD_DIST_DIR" ]]; then
  echo "Cryptad dist directory not found: $CRYPTAD_DIST_DIR" | tee "$OUT_DIR/shell-error.txt" >&2
  exit 1
fi

python_args=(
  "$ROOT_DIR/tools/interop/interop_smoke.py"
  --workspace-root "$ROOT_DIR"
  --cryptad-dist-dir "$CRYPTAD_DIST_DIR"
  --out-dir "$OUT_DIR"
  --download-cache-dir "$CACHE_DIR"
  --suite-timeout-seconds "$INTEROP_TIMEOUT_SECONDS"
  --startup-timeout-seconds "$INTEROP_STARTUP_TIMEOUT_SECONDS"
  --peer-timeout-seconds "$INTEROP_PEER_TIMEOUT_SECONDS"
  --request-timeout-seconds "$INTEROP_REQUEST_TIMEOUT_SECONDS"
  --cryptad-fnp-port "$CRYPTAD_FNP_PORT"
  --cryptad-fcp-port "$CRYPTAD_FCP_PORT"
  --hyphanet-fnp-port "$HYPHANET_FNP_PORT"
  --hyphanet-fcp-port "$HYPHANET_FCP_PORT"
)

if [[ "$INTEROP_KEEP_WORKDIR" == "1" ]]; then
  python_args+=(--keep-workdir)
fi

exec python3 "${python_args[@]}" "$@"

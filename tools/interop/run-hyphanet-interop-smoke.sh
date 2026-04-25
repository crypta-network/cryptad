#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASELINE_ENV="$ROOT_DIR/tools/interop/hyphanet-baseline.env"
CALLER_SET_INTEROP_TIMEOUT_SECONDS=0
if [[ -v INTEROP_TIMEOUT_SECONDS ]]; then
  CALLER_SET_INTEROP_TIMEOUT_SECONDS=1
fi

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

INTEROP_MODE="${INTEROP_MODE:-smoke}"
PASSTHROUGH_ARGS=("$@")
for ((arg_index = 0; arg_index < ${#PASSTHROUGH_ARGS[@]}; arg_index++)); do
  arg="${PASSTHROUGH_ARGS[$arg_index]}"
  case "$arg" in
    --)
      break
      ;;
    --mode=*)
      INTEROP_MODE="${arg#--mode=}"
      ;;
    --mode)
      arg_index=$((arg_index + 1))
      if ((arg_index >= ${#PASSTHROUGH_ARGS[@]})); then
        mkdir -p "$ROOT_DIR/build/interop-smoke"
        echo "--mode requires smoke or extended" | tee "$ROOT_DIR/build/interop-smoke/shell-error.txt" >&2
        exit 1
      fi
      INTEROP_MODE="${PASSTHROUGH_ARGS[$arg_index]}"
      ;;
  esac
done
if [[ "$INTEROP_MODE" != "smoke" && "$INTEROP_MODE" != "extended" ]]; then
  mkdir -p "$ROOT_DIR/build/interop-smoke"
  echo "INTEROP_MODE must be smoke or extended, got: $INTEROP_MODE" | tee "$ROOT_DIR/build/interop-smoke/shell-error.txt" >&2
  exit 1
fi

if [[ "$INTEROP_MODE" == "extended" ]]; then
  DEFAULT_OUT_DIR="$ROOT_DIR/build/interop-extended"
else
  DEFAULT_OUT_DIR="$ROOT_DIR/build/interop-smoke"
fi

OUT_DIR="${INTEROP_WORKDIR:-${INTEROP_OUT_DIR:-$DEFAULT_OUT_DIR}}"
CACHE_DIR="${INTEROP_CACHE_DIR:-$ROOT_DIR/build/interop-cache}"
CRYPTAD_DIST_DIR="${CRYPTAD_DIST_DIR:-$ROOT_DIR/build/cryptad-dist}"
INTEROP_SKIP_BUILD="${INTEROP_SKIP_BUILD:-0}"
INTEROP_EXTENDED_TIMEOUT_SECONDS="${INTEROP_EXTENDED_TIMEOUT_SECONDS:-3600}"
if [[ "$CALLER_SET_INTEROP_TIMEOUT_SECONDS" == "1" ]]; then
  INTEROP_TIMEOUT_SECONDS="${INTEROP_TIMEOUT_SECONDS}"
elif [[ "$INTEROP_MODE" == "extended" ]]; then
  INTEROP_TIMEOUT_SECONDS="$INTEROP_EXTENDED_TIMEOUT_SECONDS"
else
  INTEROP_TIMEOUT_SECONDS="900"
fi
INTEROP_STARTUP_TIMEOUT_SECONDS="${INTEROP_STARTUP_TIMEOUT_SECONDS:-180}"
INTEROP_PEER_TIMEOUT_SECONDS="${INTEROP_PEER_TIMEOUT_SECONDS:-120}"
INTEROP_REQUEST_TIMEOUT_SECONDS="${INTEROP_REQUEST_TIMEOUT_SECONDS:-300}"
INTEROP_SOAK_DURATION_SECONDS="${INTEROP_SOAK_DURATION_SECONDS:-300}"
INTEROP_SOAK_POLL_INTERVAL_SECONDS="${INTEROP_SOAK_POLL_INTERVAL_SECONDS:-15}"
INTEROP_KEEP_WORKDIR="${INTEROP_KEEP_WORKDIR:-0}"
CRYPTAD_FNP_PORT="${CRYPTAD_FNP_PORT:-19401}"
CRYPTAD_FCP_PORT="${CRYPTAD_FCP_PORT:-19402}"
HYPHANET_FNP_PORT="${HYPHANET_FNP_PORT:-19501}"
HYPHANET_FCP_PORT="${HYPHANET_FCP_PORT:-19502}"
INTEROP_SELF_TEST=0

for arg in "$@"; do
  if [[ "$arg" == "--self-test" ]]; then
    INTEROP_SELF_TEST=1
  fi
done

mkdir -p "$OUT_DIR"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This interoperability smoke harness is Linux-only." | tee "$OUT_DIR/shell-error.txt" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required." | tee "$OUT_DIR/shell-error.txt" >&2
  exit 1
fi

if [[ "$INTEROP_SELF_TEST" != "1" && "$INTEROP_SKIP_BUILD" != "1" ]]; then
  (
    cd "$ROOT_DIR"
    ./gradlew assembleCryptadDist
  )
fi

if [[ "$INTEROP_SELF_TEST" != "1" && ! -d "$CRYPTAD_DIST_DIR" ]]; then
  echo "Cryptad dist directory not found: $CRYPTAD_DIST_DIR" | tee "$OUT_DIR/shell-error.txt" >&2
  exit 1
fi

python_args=(
  "$ROOT_DIR/tools/interop/interop_smoke.py"
  --workspace-root "$ROOT_DIR"
  --cryptad-dist-dir "$CRYPTAD_DIST_DIR"
  --out-dir "$OUT_DIR"
  --download-cache-dir "$CACHE_DIR"
  --mode "$INTEROP_MODE"
  --suite-timeout-seconds "$INTEROP_TIMEOUT_SECONDS"
  --startup-timeout-seconds "$INTEROP_STARTUP_TIMEOUT_SECONDS"
  --peer-timeout-seconds "$INTEROP_PEER_TIMEOUT_SECONDS"
  --request-timeout-seconds "$INTEROP_REQUEST_TIMEOUT_SECONDS"
  --soak-duration-seconds "$INTEROP_SOAK_DURATION_SECONDS"
  --soak-poll-interval-seconds "$INTEROP_SOAK_POLL_INTERVAL_SECONDS"
  --cryptad-fnp-port "$CRYPTAD_FNP_PORT"
  --cryptad-fcp-port "$CRYPTAD_FCP_PORT"
  --hyphanet-fnp-port "$HYPHANET_FNP_PORT"
  --hyphanet-fcp-port "$HYPHANET_FCP_PORT"
)

if [[ "$INTEROP_KEEP_WORKDIR" == "1" ]]; then
  python_args+=(--keep-workdir)
fi

exec python3 "${python_args[@]}" "$@"

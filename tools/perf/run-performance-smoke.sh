#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PERF_MODE="${PERF_MODE:-smoke}"
PERF_OUT_DIR="${PERF_OUT_DIR:-$ROOT_DIR/build/perf-smoke}"
PERF_BASELINE="${PERF_BASELINE:-$ROOT_DIR/tools/perf/baselines/performance-smoke.json}"
CRYPTAD_DIST_DIR="${CRYPTAD_DIST_DIR:-$ROOT_DIR/build/cryptad-dist}"
PERF_SKIP_BUILD="${PERF_SKIP_BUILD:-0}"
PERF_TIMEOUT_SECONDS="${PERF_TIMEOUT_SECONDS:-300}"
PERF_STARTUP_TIMEOUT_SECONDS="${PERF_STARTUP_TIMEOUT_SECONDS:-120}"
PERF_REQUEST_TIMEOUT_SECONDS="${PERF_REQUEST_TIMEOUT_SECONDS:-30}"
PERF_FAIL_ON_REGRESSION="${PERF_FAIL_ON_REGRESSION:-0}"
PERF_UPDATE_BASELINE="${PERF_UPDATE_BASELINE:-0}"
CRYPTAD_FCP_PORT="${CRYPTAD_FCP_PORT:-29602}"
CRYPTAD_WEB_PORT="${CRYPTAD_WEB_PORT:-29603}"
CRYPTAD_FNP_PORT="${CRYPTAD_FNP_PORT:-29601}"

if [[ "$PERF_MODE" != "smoke" && "$PERF_MODE" != "collect" ]]; then
  mkdir -p "$PERF_OUT_DIR"
  echo "PERF_MODE must be smoke or collect, got: $PERF_MODE" | tee "$PERF_OUT_DIR/shell-error.txt" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  mkdir -p "$PERF_OUT_DIR"
  echo "python3 is required." | tee "$PERF_OUT_DIR/shell-error.txt" >&2
  exit 1
fi

if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)' >/dev/null 2>&1; then
  mkdir -p "$PERF_OUT_DIR"
  python_version="$(python3 -c 'import platform; print(platform.python_version())' 2>/dev/null || echo unknown)"
  echo "python3 3.12 or newer is required; found ${python_version}." | tee "$PERF_OUT_DIR/shell-error.txt" >&2
  exit 1
fi

python_args=(
  "$ROOT_DIR/tools/perf/perf_smoke.py"
  --workspace-root "$ROOT_DIR"
  --cryptad-dist-dir "$CRYPTAD_DIST_DIR"
  --out-dir "$PERF_OUT_DIR"
  --baseline "$PERF_BASELINE"
  --mode "$PERF_MODE"
  --timeout-seconds "$PERF_TIMEOUT_SECONDS"
  --startup-timeout-seconds "$PERF_STARTUP_TIMEOUT_SECONDS"
  --request-timeout-seconds "$PERF_REQUEST_TIMEOUT_SECONDS"
  --fcp-port "$CRYPTAD_FCP_PORT"
  --web-port "$CRYPTAD_WEB_PORT"
  --fnp-port "$CRYPTAD_FNP_PORT"
)

if [[ "$PERF_SKIP_BUILD" == "1" ]]; then
  python_args+=(--skip-build)
fi

if [[ "$PERF_FAIL_ON_REGRESSION" == "1" ]]; then
  python_args+=(--fail-on-regression)
fi

if [[ "$PERF_UPDATE_BASELINE" == "1" ]]; then
  python_args+=(--update-baseline)
fi

exec python3 "${python_args[@]}" "$@"

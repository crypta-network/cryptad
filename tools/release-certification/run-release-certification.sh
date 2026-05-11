#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODE="${CRYPTAD_CERT_MODE:-pr}"
OUT_DIR="${CRYPTAD_CERT_OUT_DIR:-$ROOT_DIR/build/release-certification}"
SKIP_APP_SMOKE="${CRYPTAD_CERT_SKIP_APP_SMOKE:-0}"
SKIP_GRADLE_ARG=()
LIVE_ARGS=()
CERT_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="$2"
      shift 2
      ;;
    --mode=*)
      MODE="${1#--mode=}"
      shift
      ;;
    --out-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    --out-dir=*)
      OUT_DIR="${1#--out-dir=}"
      shift
      ;;
    --skip-app-smoke)
      SKIP_APP_SMOKE=1
      shift
      ;;
    --skip-gradle)
      SKIP_GRADLE_ARG=(--skip-gradle)
      shift
      ;;
    --live)
      LIVE_ARGS+=(--live)
      shift
      ;;
    --node-base-url)
      LIVE_ARGS+=(--node-base-url "$2")
      shift 2
      ;;
    --node-base-url=*)
      LIVE_ARGS+=(--node-base-url "${1#--node-base-url=}")
      shift
      ;;
    --form-password)
      echo "--form-password is not supported; set CRYPTAD_CERT_FORM_PASSWORD in the environment." >&2
      exit 2
      ;;
    --form-password=*)
      echo "--form-password is not supported; set CRYPTAD_CERT_FORM_PASSWORD in the environment." >&2
      exit 2
      ;;
    --waive|--metadata|--previous-summary|--history-dir|--history-label|--waiver-file)
      CERT_ARGS+=("$1" "$2")
      shift 2
      ;;
    --waive=*|--metadata=*|--previous-summary=*|--history-dir=*|--history-label=*|--waiver-file=*)
      CERT_ARGS+=("$1")
      shift
      ;;
    --skip-git-metadata|--require-history|--write-history)
      CERT_ARGS+=("$1")
      shift
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

case "$MODE" in
  pr|nightly|release-candidate)
    ;;
  *)
    echo "--mode must be pr, nightly, or release-candidate; got: $MODE" >&2
    exit 2
    ;;
esac

case "$OUT_DIR" in
  /*)
    ;;
  *)
    OUT_DIR="$ROOT_DIR/$OUT_DIR"
    ;;
esac

if ! command -v python3 >/dev/null 2>&1; then
  mkdir -p "$OUT_DIR"
  echo "python3 is required." | tee "$OUT_DIR/shell-error.txt" >&2
  exit 1
fi

if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
  mkdir -p "$OUT_DIR"
  python_version="$(python3 -c 'import platform; print(platform.python_version())' 2>/dev/null || echo unknown)"
  echo "python3 3.10 or newer is required; found ${python_version}." | tee "$OUT_DIR/shell-error.txt" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
APP_SMOKE_OUT_DIR="$OUT_DIR/app-platform-smoke"
APP_SMOKE_SUMMARY="$APP_SMOKE_OUT_DIR/summary.json"

if [[ ${#SKIP_GRADLE_ARG[@]} -eq 0 && "$MODE" == "pr" && "${CRYPTAD_CERT_RUN_GRADLE:-0}" != "1" ]]; then
  SKIP_GRADLE_ARG=(--skip-gradle)
fi

rm -f "$APP_SMOKE_SUMMARY" "$APP_SMOKE_OUT_DIR/app-platform-smoke-report.md"

if [[ "$SKIP_APP_SMOKE" != "1" ]]; then
  set +e
  python3 "$ROOT_DIR/tools/release-certification/app_platform_smoke.py" \
    --workspace-root "$ROOT_DIR" \
    --out-dir "$APP_SMOKE_OUT_DIR" \
    --mode "$MODE" \
    "${SKIP_GRADLE_ARG[@]}" \
    "${LIVE_ARGS[@]}"
  APP_SMOKE_EXIT=$?
  set -e
  if [[ "$APP_SMOKE_EXIT" -ne 0 ]]; then
    echo "App-platform smoke exited with $APP_SMOKE_EXIT; certification aggregation will record the evidence state." >&2
  fi
else
  rm -rf "$APP_SMOKE_OUT_DIR/artifacts"
fi

exec python3 "$ROOT_DIR/tools/release-certification/release_certification.py" \
  --workspace-root "$ROOT_DIR" \
  --out-dir "$OUT_DIR" \
  --mode "$MODE" \
  --app-platform-summary "$APP_SMOKE_SUMMARY" \
  "${CERT_ARGS[@]}"

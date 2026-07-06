#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODE="${CRYPTAD_CERT_MODE:-pr}"
OUT_DIR="${CRYPTAD_CERT_OUT_DIR:-$ROOT_DIR/build/release-certification}"
SKIP_APP_SMOKE="${CRYPTAD_CERT_SKIP_APP_SMOKE:-0}"
LIVE_NETWORK_BETA="${CRYPTAD_CERT_LIVE_NETWORK_BETA:-0}"
REQUIRE_LIVE_NETWORK_BETA="${CRYPTAD_CERT_REQUIRE_LIVE_NETWORK_BETA:-0}"
NODE_BASE_URL="${CRYPTAD_CERT_NODE_BASE_URL:-}"
NETWORK_SCALE_SOAK_SUMMARY="${CRYPTAD_CERT_NETWORK_SCALE_SOAK_SUMMARY:-}"
NETWORK_SCALE_SOAK_SUMMARY_PROVIDED=0
MULTI_NODE_SOAK_SUMMARY="${CRYPTAD_CERT_MULTI_NODE_SOAK_SUMMARY:-}"
MULTI_NODE_SOAK_SUMMARY_PROVIDED=0
MULTI_NODE_MODE="${CRYPTAD_CERT_MULTI_NODE_MODE:-}"
MULTI_NODE_MODE_PROVIDED=0
MULTI_NODE_SOAK_CONFIG="${CRYPTAD_CERT_MULTI_NODE_SOAK_CONFIG:-}"
REQUIRE_MULTI_NODE_SOAK="${CRYPTAD_CERT_REQUIRE_MULTI_NODE_SOAK:-0}"
SECURITY_DRILLS_SUMMARY="${CRYPTAD_CERT_SECURITY_DRILLS_SUMMARY:-}"
SECURITY_DRILLS_SUMMARY_PROVIDED=0
SKIP_GRADLE_ARG=()
LIVE_ARGS=()
LIVE_NETWORK_ARGS=()
CERT_LIVE_ARGS=()
CERT_ARGS=()

if [[ -n "$NETWORK_SCALE_SOAK_SUMMARY" ]]; then
  NETWORK_SCALE_SOAK_SUMMARY_PROVIDED=1
fi
if [[ -n "$MULTI_NODE_SOAK_SUMMARY" ]]; then
  MULTI_NODE_SOAK_SUMMARY_PROVIDED=1
fi
if [[ -n "$MULTI_NODE_MODE" ]]; then
  MULTI_NODE_MODE_PROVIDED=1
fi
if [[ -n "$SECURITY_DRILLS_SUMMARY" ]]; then
  SECURITY_DRILLS_SUMMARY_PROVIDED=1
fi

normalize_flag() {
  case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on)
      printf '1'
      ;;
    *)
      printf '0'
      ;;
  esac
}

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
    --live-network-beta)
      LIVE_NETWORK_BETA=1
      shift
      ;;
    --require-live-network-beta)
      LIVE_NETWORK_BETA=1
      REQUIRE_LIVE_NETWORK_BETA=1
      shift
      ;;
    --node-base-url)
      NODE_BASE_URL="$2"
      shift 2
      ;;
    --node-base-url=*)
      NODE_BASE_URL="${1#--node-base-url=}"
      shift
      ;;
    --network-scale-soak-summary)
      NETWORK_SCALE_SOAK_SUMMARY="$2"
      NETWORK_SCALE_SOAK_SUMMARY_PROVIDED=1
      shift 2
      ;;
    --network-scale-soak-summary=*)
      NETWORK_SCALE_SOAK_SUMMARY="${1#--network-scale-soak-summary=}"
      NETWORK_SCALE_SOAK_SUMMARY_PROVIDED=1
      shift
      ;;
    --multi-node-soak-summary)
      MULTI_NODE_SOAK_SUMMARY="$2"
      MULTI_NODE_SOAK_SUMMARY_PROVIDED=1
      shift 2
      ;;
    --multi-node-soak-summary=*)
      MULTI_NODE_SOAK_SUMMARY="${1#--multi-node-soak-summary=}"
      MULTI_NODE_SOAK_SUMMARY_PROVIDED=1
      shift
      ;;
    --multi-node-mode)
      MULTI_NODE_MODE="$2"
      MULTI_NODE_MODE_PROVIDED=1
      shift 2
      ;;
    --multi-node-mode=*)
      MULTI_NODE_MODE="${1#--multi-node-mode=}"
      MULTI_NODE_MODE_PROVIDED=1
      shift
      ;;
    --multi-node-soak-config)
      MULTI_NODE_SOAK_CONFIG="$2"
      shift 2
      ;;
    --multi-node-soak-config=*)
      MULTI_NODE_SOAK_CONFIG="${1#--multi-node-soak-config=}"
      shift
      ;;
    --require-multi-node-soak)
      REQUIRE_MULTI_NODE_SOAK=1
      shift
      ;;
    --security-drills-summary|--security-response-summary)
      SECURITY_DRILLS_SUMMARY="$2"
      SECURITY_DRILLS_SUMMARY_PROVIDED=1
      shift 2
      ;;
    --security-drills-summary=*|--security-response-summary=*)
      SECURITY_DRILLS_SUMMARY="${1#*=}"
      SECURITY_DRILLS_SUMMARY_PROVIDED=1
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
    --waive|--metadata|--previous-summary|--history-dir|--history-label|--waiver-file|--stable-readiness-summary|--stable-1-0-readiness-summary)
      CERT_ARGS+=("$1" "$2")
      shift 2
      ;;
    --waive=*|--metadata=*|--previous-summary=*|--history-dir=*|--history-label=*|--waiver-file=*|--stable-readiness-summary=*|--stable-1-0-readiness-summary=*)
      CERT_ARGS+=("$1")
      shift
      ;;
    --skip-git-metadata|--require-history|--write-history|--require-stable-readiness)
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

if [[ "$MULTI_NODE_MODE_PROVIDED" == "1" ]]; then
  case "$MULTI_NODE_MODE" in
    simulated|hybrid|live)
      ;;
    *)
      echo "--multi-node-mode must be simulated, hybrid, or live; got: $MULTI_NODE_MODE" >&2
      exit 2
      ;;
  esac
fi

case "$OUT_DIR" in
  /*)
    ;;
  *)
    OUT_DIR="$ROOT_DIR/$OUT_DIR"
    ;;
esac

case "$NETWORK_SCALE_SOAK_SUMMARY" in
  "")
    NETWORK_SCALE_SOAK_SUMMARY_PROVIDED=0
    NETWORK_SCALE_SOAK_SUMMARY="$OUT_DIR/network-scale-soak/summary.json"
    ;;
  /*)
    ;;
  *)
    NETWORK_SCALE_SOAK_SUMMARY="$ROOT_DIR/$NETWORK_SCALE_SOAK_SUMMARY"
    ;;
esac
NETWORK_SCALE_SOAK_OUT_DIR="$(dirname "$NETWORK_SCALE_SOAK_SUMMARY")"

case "$MULTI_NODE_SOAK_SUMMARY" in
  "")
    MULTI_NODE_SOAK_SUMMARY_PROVIDED=0
    MULTI_NODE_SOAK_SUMMARY="$OUT_DIR/multi-node-beta-soak/summary.json"
    ;;
  /*)
    ;;
  *)
    MULTI_NODE_SOAK_SUMMARY="$ROOT_DIR/$MULTI_NODE_SOAK_SUMMARY"
    ;;
esac
MULTI_NODE_SOAK_OUT_DIR="$(dirname "$MULTI_NODE_SOAK_SUMMARY")"

case "$SECURITY_DRILLS_SUMMARY" in
  "")
    SECURITY_DRILLS_SUMMARY_PROVIDED=0
    SECURITY_DRILLS_SUMMARY="$OUT_DIR/security-drills/security-drills-summary.json"
    ;;
  /*)
    ;;
  *)
    SECURITY_DRILLS_SUMMARY="$ROOT_DIR/$SECURITY_DRILLS_SUMMARY"
    ;;
esac
SECURITY_DRILLS_OUT_DIR="$(dirname "$SECURITY_DRILLS_SUMMARY")"

if [[ -n "$MULTI_NODE_SOAK_CONFIG" ]]; then
  case "$MULTI_NODE_SOAK_CONFIG" in
    /*)
      ;;
    *)
      MULTI_NODE_SOAK_CONFIG="$ROOT_DIR/$MULTI_NODE_SOAK_CONFIG"
      ;;
  esac
fi

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

EFFECTIVE_MULTI_NODE_MODE="$MULTI_NODE_MODE"
if [[ "$MULTI_NODE_MODE_PROVIDED" != "1" ]]; then
  EFFECTIVE_MULTI_NODE_MODE="simulated"
  if [[ -n "$MULTI_NODE_SOAK_CONFIG" ]]; then
    EFFECTIVE_MULTI_NODE_MODE="$(
      python3 - "$MULTI_NODE_SOAK_CONFIG" <<'PY'
import json
import sys
from pathlib import Path

try:
    value = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
except Exception:
    print("simulated")
else:
    mode = str(value.get("mode", "simulated")).strip()
    print(mode or "simulated")
PY
    )"
  fi
fi

mkdir -p "$OUT_DIR"
APP_SMOKE_OUT_DIR="$OUT_DIR/app-platform-smoke"
APP_SMOKE_SUMMARY="$APP_SMOKE_OUT_DIR/summary.json"
LIVE_NETWORK_OUT_DIR="$OUT_DIR/live-network-beta-smoke"
LIVE_NETWORK_SUMMARY="$LIVE_NETWORK_OUT_DIR/summary.json"

if [[ ${#SKIP_GRADLE_ARG[@]} -eq 0 && "$MODE" == "pr" && "${CRYPTAD_CERT_RUN_GRADLE:-0}" != "1" ]]; then
  SKIP_GRADLE_ARG=(--skip-gradle)
fi

if [[ -n "$NODE_BASE_URL" ]]; then
  LIVE_ARGS+=(--node-base-url "$NODE_BASE_URL")
  LIVE_NETWORK_ARGS+=(--node-base-url "$NODE_BASE_URL")
fi
LIVE_NETWORK_BETA="$(normalize_flag "$LIVE_NETWORK_BETA")"
REQUIRE_LIVE_NETWORK_BETA="$(normalize_flag "$REQUIRE_LIVE_NETWORK_BETA")"
REQUIRE_MULTI_NODE_SOAK="$(normalize_flag "$REQUIRE_MULTI_NODE_SOAK")"
if [[ "$REQUIRE_LIVE_NETWORK_BETA" == "1" ]]; then
  LIVE_NETWORK_BETA=1
  LIVE_NETWORK_ARGS+=(--require)
fi
if [[ "$LIVE_NETWORK_BETA" == "1" ]]; then
  CERT_LIVE_ARGS+=(--live-network-beta)
fi
if [[ "$REQUIRE_LIVE_NETWORK_BETA" == "1" ]]; then
  CERT_LIVE_ARGS+=(--require-live-network-beta)
fi
if [[ "$REQUIRE_MULTI_NODE_SOAK" == "1" ]]; then
  CERT_ARGS+=(--require-multi-node-soak)
fi

rm -f "$APP_SMOKE_SUMMARY" "$APP_SMOKE_OUT_DIR/app-platform-smoke-report.md"
rm -f "$LIVE_NETWORK_SUMMARY" "$LIVE_NETWORK_OUT_DIR/live-network-beta-smoke-report.md"
if [[ "$NETWORK_SCALE_SOAK_SUMMARY_PROVIDED" != "1" ]]; then
  rm -f "$NETWORK_SCALE_SOAK_SUMMARY"
fi
if [[ "$MULTI_NODE_SOAK_SUMMARY_PROVIDED" != "1" ]]; then
  rm -f \
    "$MULTI_NODE_SOAK_SUMMARY" \
    "$MULTI_NODE_SOAK_OUT_DIR/multi-node-beta-soak-summary.json" \
    "$MULTI_NODE_SOAK_OUT_DIR/multi-node-beta-soak-summary.md"
fi
if [[ "$SECURITY_DRILLS_SUMMARY_PROVIDED" != "1" ]]; then
  rm -rf "$SECURITY_DRILLS_OUT_DIR"
fi

set +e
(
  cd "$ROOT_DIR" &&
    python3 "$ROOT_DIR/tools/release-certification/security_response_runbook.py" verify
)
SECURITY_RUNBOOK_EXIT=$?
set -e
if [[ "$SECURITY_RUNBOOK_EXIT" -ne 0 ]]; then
  echo "Security response runbook verification exited with $SECURITY_RUNBOOK_EXIT; certification aggregation will record" \
    "the evidence state." >&2
fi

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

if [[ "$LIVE_NETWORK_BETA" == "1" ]]; then
  set +e
  python3 "$ROOT_DIR/tools/release-certification/live_network_beta_smoke.py" \
    --workspace-root "$ROOT_DIR" \
    --out-dir "$LIVE_NETWORK_OUT_DIR" \
    --mode "$MODE" \
    "${LIVE_NETWORK_ARGS[@]}"
  LIVE_NETWORK_EXIT=$?
  set -e
  if [[ "$LIVE_NETWORK_EXIT" -ne 0 ]]; then
    echo "Live-network beta smoke exited with $LIVE_NETWORK_EXIT; certification aggregation will record the evidence state." >&2
  fi
fi

if [[ "$NETWORK_SCALE_SOAK_SUMMARY_PROVIDED" != "1" ]]; then
  mkdir -p "$NETWORK_SCALE_SOAK_OUT_DIR"
  set +e
  python3 "$ROOT_DIR/tools/release-certification/network_scale_soak.py" \
    --output "$NETWORK_SCALE_SOAK_SUMMARY"
  NETWORK_SCALE_SOAK_EXIT=$?
  set -e
  if [[ "$NETWORK_SCALE_SOAK_EXIT" -ne 0 ]]; then
    echo "Network-scale soak evidence exited with $NETWORK_SCALE_SOAK_EXIT; certification aggregation will record" \
      "the evidence state." >&2
  fi
fi

if [[ "$MULTI_NODE_SOAK_SUMMARY_PROVIDED" != "1" ]]; then
  mkdir -p "$MULTI_NODE_SOAK_OUT_DIR"
  MULTI_NODE_ARGS=(
    run
    --out-dir "$MULTI_NODE_SOAK_OUT_DIR"
  )
  if [[ "$MULTI_NODE_MODE_PROVIDED" == "1" ]]; then
    MULTI_NODE_ARGS+=(--mode "$MULTI_NODE_MODE")
  fi
  if [[ -n "$MULTI_NODE_SOAK_CONFIG" ]]; then
    MULTI_NODE_ARGS+=(--config "$MULTI_NODE_SOAK_CONFIG")
  fi
  if [[ "$REQUIRE_MULTI_NODE_SOAK" == "1" && "$EFFECTIVE_MULTI_NODE_MODE" == "live" ]]; then
    MULTI_NODE_ARGS+=(--require-live)
  fi
  if [[ "$REQUIRE_MULTI_NODE_SOAK" == "1" || "$MODE" == "release-candidate" ]]; then
    MULTI_NODE_ARGS+=(--require-all-scenarios)
  fi
  set +e
  python3 "$ROOT_DIR/tools/release-certification/multi_node_beta_soak.py" "${MULTI_NODE_ARGS[@]}"
  MULTI_NODE_SOAK_EXIT=$?
  set -e
  if [[ "$MULTI_NODE_SOAK_EXIT" -ne 0 ]]; then
    echo "Multi-node beta soak evidence exited with $MULTI_NODE_SOAK_EXIT; certification aggregation will record" \
      "the evidence state." >&2
  fi
fi

if [[ "$SECURITY_DRILLS_SUMMARY_PROVIDED" != "1" ]]; then
  mkdir -p "$SECURITY_DRILLS_OUT_DIR"
  set +e
  (
    cd "$ROOT_DIR" &&
      python3 "$ROOT_DIR/tools/release-certification/security_response_runbook.py" drill run-all \
        --out-dir "$SECURITY_DRILLS_OUT_DIR" \
        --summary-out "$SECURITY_DRILLS_SUMMARY" \
        --release-id "cryptad-cert-${MODE}" \
        --mode "$MODE" \
        --release-notes-out "$OUT_DIR/security/security-release-notes-draft.md"
  )
  SECURITY_DRILL_RUN_EXIT=$?
  set -e
  if [[ "$SECURITY_DRILL_RUN_EXIT" -ne 0 ]]; then
    echo "Security response drill generation exited with $SECURITY_DRILL_RUN_EXIT; certification aggregation will record" \
      "the evidence state." >&2
  fi
fi

if [[ "$SECURITY_DRILLS_SUMMARY_PROVIDED" != "1" ]]; then
  set +e
  (
    cd "$ROOT_DIR" &&
      python3 "$ROOT_DIR/tools/release-certification/security_response_runbook.py" drill verify-all \
        --input-dir "$SECURITY_DRILLS_OUT_DIR" \
        --summary-out "$SECURITY_DRILLS_SUMMARY" \
        --release-id "cryptad-cert-${MODE}" \
        --mode "$MODE"
  )
  SECURITY_DRILL_VERIFY_EXIT=$?
  set -e
  if [[ "$SECURITY_DRILL_VERIFY_EXIT" -ne 0 ]]; then
    echo "Security response drill verification exited with $SECURITY_DRILL_VERIFY_EXIT; certification aggregation will record" \
      "the evidence state." >&2
  fi
fi

exec python3 "$ROOT_DIR/tools/release-certification/release_certification.py" \
  --workspace-root "$ROOT_DIR" \
  --out-dir "$OUT_DIR" \
  --mode "$MODE" \
  --app-platform-summary "$APP_SMOKE_SUMMARY" \
  --live-network-summary "$LIVE_NETWORK_SUMMARY" \
  --network-scale-soak-summary "$NETWORK_SCALE_SOAK_SUMMARY" \
  --multi-node-soak-summary "$MULTI_NODE_SOAK_SUMMARY" \
  --security-drills-summary "$SECURITY_DRILLS_SUMMARY" \
  "${CERT_LIVE_ARGS[@]}" \
  "${CERT_ARGS[@]}"

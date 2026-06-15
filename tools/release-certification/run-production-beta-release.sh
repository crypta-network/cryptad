#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required." >&2
  exit 1
fi

if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
  python_version="$(python3 -c 'import platform; print(platform.python_version())' 2>/dev/null || echo unknown)"
  echo "python3 3.10 or newer is required; found ${python_version}." >&2
  exit 1
fi

has_workspace_root=0
for arg in "$@"; do
  case "$arg" in
    --workspace-root|--workspace-root=*)
      has_workspace_root=1
      break
      ;;
  esac
done

if [[ "$has_workspace_root" -eq 1 ]]; then
  exec python3 "$ROOT_DIR/tools/release-certification/production_beta_release.py" "$@"
fi

exec python3 "$ROOT_DIR/tools/release-certification/production_beta_release.py" --workspace-root "$ROOT_DIR" "$@"

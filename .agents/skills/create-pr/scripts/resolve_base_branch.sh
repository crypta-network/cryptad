#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  resolve_base_branch.sh [base-branch]

Behavior:
  - No argument: choose develop by default, fall back to main only if origin/develop is missing.
  - With argument: treat the branch as explicitly requested; do not fall back to main.

Notes:
  - Run "git fetch origin --prune" before this script to refresh remote refs.
  - Prints the selected base branch to stdout.
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

if [ "$#" -gt 1 ]; then
  usage >&2
  exit 2
fi

user_specified_base=false
if [ "$#" -eq 1 ]; then
  base_branch="$1"
  user_specified_base=true
else
  base_branch="develop"
fi

if ! git show-ref --verify --quiet "refs/remotes/origin/$base_branch"; then
  if [ "$base_branch" = "develop" ] && [ "$user_specified_base" = "false" ]; then
    base_branch="main"
  fi
fi

if ! git show-ref --verify --quiet "refs/remotes/origin/$base_branch"; then
  echo "Base branch origin/$base_branch not found" >&2
  exit 1
fi

printf '%s\n' "$base_branch"

#!/usr/bin/env bash
set -euo pipefail

codex_home="${CODEX_HOME:-/root/.codex}"
standalone_codex="${codex_home}/packages/standalone/current/codex"

ensure_standalone_codex() {
  if [[ -x "${standalone_codex}" ]]; then
    return
  fi

  local codex_on_path
  codex_on_path="$(command -v codex)"
  if [[ -z "${codex_on_path}" ]]; then
    echo "codex executable not found on PATH" >&2
    exit 1
  fi

  mkdir -p "$(dirname "${standalone_codex}")"
  ln -sf "${codex_on_path}" "${standalone_codex}"
}

daemon_is_running() {
  codex app-server daemon version >/dev/null 2>&1
}

start_sshd() {
  if [[ ! -x /usr/sbin/sshd ]]; then
    echo "sshd executable not found" >&2
    exit 1
  fi

  mkdir -p /run/sshd
  ssh-keygen -A >/dev/null
  sshd -t

  local pid_file="/run/sshd.pid"
  if [[ -s "${pid_file}" ]]; then
    local sshd_pid
    sshd_pid="$(cat "${pid_file}")"
    if [[ "${sshd_pid}" =~ ^[0-9]+$ ]] && kill -0 "${sshd_pid}" >/dev/null 2>&1; then
      return
    fi
    rm -f "${pid_file}"
  fi

  /usr/sbin/sshd
}

wait_for_daemon() {
  for _ in {1..30}; do
    if daemon_is_running; then
      return 0
    fi
    sleep 1
  done

  return 1
}

cleanup_stale_daemon_state() {
  local control_dir="${codex_home}/app-server-control"
  if daemon_is_running || [[ ! -d "${control_dir}" ]]; then
    return
  fi

  rm -f \
    "${control_dir}/app-server-control.sock" \
    "${control_dir}/desktop-ssh-websocket-v0.sock" \
    "${control_dir}/app-server-startup.lock"
}

stop_daemon() {
  trap - INT TERM
  codex remote-control stop >/dev/null 2>&1 || codex app-server daemon stop >/dev/null 2>&1 || true
  cleanup_stale_daemon_state
}

start_daemon() {
  if codex remote-control start; then
    return 0
  fi

  echo "Initial Codex remote-control start failed; stopping stale daemon state and retrying" >&2
  codex remote-control stop >/dev/null 2>&1 || codex app-server daemon stop >/dev/null 2>&1 || true
  cleanup_stale_daemon_state
  sleep 1
  codex remote-control start
}

ensure_daemon_started() {
  local attempt
  for attempt in {1..12}; do
    if start_daemon; then
      return 0
    fi

    echo "Codex remote-control start failed; retrying in 5 seconds" >&2
    sleep 5
  done

  return 1
}

trap 'stop_daemon; exit 0' INT TERM

ensure_standalone_codex
start_sshd
ensure_daemon_started

if ! wait_for_daemon; then
  echo "Codex remote-control daemon did not become ready" >&2
  exit 1
fi

while true; do
  if ! daemon_is_running; then
    echo "Codex remote-control daemon stopped; restarting without stopping SSH" >&2
    start_daemon || echo "Codex remote-control restart failed; retrying" >&2
  fi

  sleep 5 &
  wait "$!"
done

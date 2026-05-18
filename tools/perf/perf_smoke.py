#!/usr/bin/env python3
"""Lightweight local performance and regression smoke gate for Cryptad."""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_OUT_DIR = Path("build/perf-smoke")
DEFAULT_BASELINE = Path("tools/perf/baselines/performance-smoke.json")
DEFAULT_DIST_DIR = Path("build/cryptad-dist")
DEFAULT_FNP_PORT = 29601
DEFAULT_FCP_PORT = 29602
DEFAULT_WEB_PORT = 29603
DEFAULT_TIMEOUT_SECONDS = 300
DEFAULT_STARTUP_TIMEOUT_SECONDS = 120
DEFAULT_REQUEST_TIMEOUT_SECONDS = 30
BASELINE_SCHEMA_VERSION = 1
TOOL_NAME = "perf_smoke"
MIN_PYTHON_VERSION = (3, 12)
OUTPUT_MARKER = ".cryptad-perf-smoke-output"
FIRST_PARTY_APP_SIZE_TARGETS = (
    ("feed_reader", "feed-reader"),
    ("queue_manager", "queue-manager"),
    ("publisher", "publisher"),
    ("profile_publisher", "profile-publisher"),
    ("site_publisher", "site-publisher"),
    ("trust_graph", "trust-graph"),
)
SENSITIVE_KEY_PATTERN = (
    r"[A-Za-z0-9_.-]*(?:token|password|passwd|secret|credential|authorization|cookie|"
    r"api[_-]?key|access[_-]?key|private[_-]?key|insert[_-]?uri|private[_-]?uri|"
    r"splitfile[_-]?crypto[_-]?key)[A-Za-z0-9_.-]*|formPassword"
)
SENSITIVE_KEY_RE = re.compile(SENSITIVE_KEY_PATTERN, re.IGNORECASE)
SENSITIVE_HEADER_RE = re.compile(
    rf"(?im)^(?P<prefix>\s*(?:{SENSITIVE_KEY_PATTERN})\s*:\s*).*$"
)
SENSITIVE_ASSIGNMENT_RE = re.compile(
    rf"(?i)(?P<prefix>['\"]?(?:{SENSITIVE_KEY_PATTERN})['\"]?\s*[:=]\s*)"
    r"(?P<value>\"[^\"]*\"|'[^']*'|bearer\s+[^\s&;,}\]]+|[^\s&;,}\]]+)"
)
PRIVATE_URI_RE = re.compile(r"\b(?:SSK|USK)@[^\s'\"<>()\[\]{}]+")
URL_USERINFO_RE = re.compile(r"(https?://)[^/@\s]+@")


class PerfFailure(RuntimeError):
    """Raised when the harness cannot complete a required operation."""


@dataclass(frozen=True)
class Settings:
    """Resolved runner settings from CLI arguments and environment variables."""

    workspace_root: Path
    out_dir: Path
    baseline_path: Path
    cryptad_dist_dir: Path
    mode: str
    skip_build: bool
    update_baseline: bool
    fail_on_regression: bool
    timeout_seconds: int
    startup_timeout_seconds: int
    request_timeout_seconds: int
    fcp_port: int
    web_port: int
    fnp_port: int


@dataclass(frozen=True)
class Layout:
    """Filesystem layout for one perf run."""

    out_dir: Path
    artifacts_dir: Path
    logs_dir: Path
    work_dir: Path


@dataclass
class NodeRuntime:
    """Running packaged node process and the files used by the smoke harness."""

    process: subprocess.Popen[bytes]
    stdout_path: Path
    stderr_path: Path
    stdout_handle: Any
    stderr_handle: Any
    config_file: Path
    node_dir: Path
    spawn_ms: int


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def ensure_supported_python() -> None:
    if sys.version_info < MIN_PYTHON_VERSION:
        minimum = ".".join(str(part) for part in MIN_PYTHON_VERSION)
        current = platform.python_version()
        raise PerfFailure(f"Python {minimum}+ is required; current interpreter is {current}")


def monotonic_ms() -> int:
    return time.monotonic_ns() // 1_000_000


def env_flag(env: dict[str, str], name: str, default: bool = False) -> bool:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


def env_int(env: dict[str, str], name: str, default: int) -> int:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw, 10)
    except ValueError as exc:
        raise PerfFailure(f"{name} must be an integer, got {raw!r}") from exc


def resolve_path(workspace_root: Path, value: str | Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = workspace_root / path
    return path


def display_path(path: Path, workspace_root: Path) -> str:
    try:
        return str(path.resolve().relative_to(workspace_root.resolve()))
    except ValueError:
        return str(path)


def is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="run parser/comparator self-tests")
    parser.add_argument("--workspace-root", type=Path, default=Path.cwd())
    parser.add_argument("--cryptad-dist-dir", type=Path)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--mode", choices=("smoke", "collect"))
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--update-baseline", action="store_true")
    parser.add_argument("--fail-on-regression", action="store_true")
    parser.add_argument("--timeout-seconds", type=int)
    parser.add_argument("--startup-timeout-seconds", type=int)
    parser.add_argument("--request-timeout-seconds", type=int)
    parser.add_argument("--fcp-port", type=int)
    parser.add_argument("--web-port", type=int)
    parser.add_argument("--fnp-port", type=int)
    return parser


def settings_from_args(args: argparse.Namespace, env: dict[str, str]) -> Settings:
    workspace_root = args.workspace_root.expanduser().resolve()
    env_mode = env.get("PERF_MODE", "smoke").strip().lower() or "smoke"
    if env_mode not in {"smoke", "collect"}:
        raise PerfFailure(f"PERF_MODE must be smoke or collect, got: {env_mode}")
    mode = "self-test" if args.self_test else (args.mode or env_mode)
    out_dir_value = args.out_dir or env.get("PERF_OUT_DIR") or DEFAULT_OUT_DIR
    baseline_value = args.baseline or env.get("PERF_BASELINE") or DEFAULT_BASELINE
    dist_value = args.cryptad_dist_dir or env.get("CRYPTAD_DIST_DIR") or DEFAULT_DIST_DIR
    return Settings(
        workspace_root=workspace_root,
        out_dir=resolve_path(workspace_root, out_dir_value),
        baseline_path=resolve_path(workspace_root, baseline_value),
        cryptad_dist_dir=resolve_path(workspace_root, dist_value),
        mode=mode,
        skip_build=args.skip_build or env_flag(env, "PERF_SKIP_BUILD", False),
        update_baseline=args.update_baseline or env_flag(env, "PERF_UPDATE_BASELINE", False),
        fail_on_regression=args.fail_on_regression
        or env_flag(env, "PERF_FAIL_ON_REGRESSION", False),
        timeout_seconds=args.timeout_seconds
        if args.timeout_seconds is not None
        else env_int(env, "PERF_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS),
        startup_timeout_seconds=args.startup_timeout_seconds
        if args.startup_timeout_seconds is not None
        else env_int(env, "PERF_STARTUP_TIMEOUT_SECONDS", DEFAULT_STARTUP_TIMEOUT_SECONDS),
        request_timeout_seconds=args.request_timeout_seconds
        if args.request_timeout_seconds is not None
        else env_int(env, "PERF_REQUEST_TIMEOUT_SECONDS", DEFAULT_REQUEST_TIMEOUT_SECONDS),
        fcp_port=args.fcp_port
        if args.fcp_port is not None
        else env_int(env, "CRYPTAD_FCP_PORT", DEFAULT_FCP_PORT),
        web_port=args.web_port
        if args.web_port is not None
        else env_int(env, "CRYPTAD_WEB_PORT", DEFAULT_WEB_PORT),
        fnp_port=args.fnp_port
        if args.fnp_port is not None
        else env_int(env, "CRYPTAD_FNP_PORT", DEFAULT_FNP_PORT),
    )


def failure_settings_from_args(args: argparse.Namespace, env: dict[str, str]) -> Settings:
    workspace_root = args.workspace_root.expanduser().resolve()
    raw_mode = (args.mode or env.get("PERF_MODE") or "smoke").strip() or "smoke"
    mode = "self-test" if args.self_test else raw_mode
    out_dir_value = args.out_dir or env.get("PERF_OUT_DIR") or DEFAULT_OUT_DIR
    baseline_value = args.baseline or env.get("PERF_BASELINE") or DEFAULT_BASELINE
    dist_value = args.cryptad_dist_dir or env.get("CRYPTAD_DIST_DIR") or DEFAULT_DIST_DIR
    return Settings(
        workspace_root=workspace_root,
        out_dir=resolve_path(workspace_root, out_dir_value),
        baseline_path=resolve_path(workspace_root, baseline_value),
        cryptad_dist_dir=resolve_path(workspace_root, dist_value),
        mode=mode,
        skip_build=args.skip_build or env_flag(env, "PERF_SKIP_BUILD", False),
        update_baseline=args.update_baseline or env_flag(env, "PERF_UPDATE_BASELINE", False),
        fail_on_regression=args.fail_on_regression
        or env_flag(env, "PERF_FAIL_ON_REGRESSION", False),
        timeout_seconds=args.timeout_seconds or DEFAULT_TIMEOUT_SECONDS,
        startup_timeout_seconds=args.startup_timeout_seconds or DEFAULT_STARTUP_TIMEOUT_SECONDS,
        request_timeout_seconds=args.request_timeout_seconds or DEFAULT_REQUEST_TIMEOUT_SECONDS,
        fcp_port=args.fcp_port or DEFAULT_FCP_PORT,
        web_port=args.web_port or DEFAULT_WEB_PORT,
        fnp_port=args.fnp_port or DEFAULT_FNP_PORT,
    )


def prepare_layout(settings: Settings, *, clean: bool) -> Layout:
    out_dir = settings.out_dir.resolve()
    forbidden = {Path("/").resolve(), settings.workspace_root.resolve()}
    home = Path.home().resolve()
    if out_dir in forbidden or out_dir == home:
        raise PerfFailure("Refusing to use unsafe PERF_OUT_DIR")
    if out_dir.exists():
        if not out_dir.is_dir():
            raise PerfFailure(
                "Refusing to use non-directory PERF_OUT_DIR: "
                f"{display_path(out_dir, settings.workspace_root)}"
            )
        if not can_clean_output_dir(out_dir, settings.workspace_root):
            action = "clean" if clean else "write existing"
            raise PerfFailure(
                f"Refusing to {action} PERF_OUT_DIR outside build/ without "
                f"{OUTPUT_MARKER}: {display_path(out_dir, settings.workspace_root)}"
            )
    if clean and out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir = out_dir / "artifacts"
    logs_dir = artifacts_dir / "logs"
    work_dir = out_dir / "work"
    logs_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)
    write_output_marker(out_dir)
    return Layout(out_dir=out_dir, artifacts_dir=artifacts_dir, logs_dir=logs_dir, work_dir=work_dir)


def safe_prepare_layout(settings: Settings) -> Layout:
    return prepare_layout(settings, clean=True)


def preserve_layout(settings: Settings) -> Layout:
    return prepare_layout(settings, clean=False)


def can_clean_output_dir(out_dir: Path, workspace_root: Path) -> bool:
    build_dir = (workspace_root / "build").resolve()
    if (out_dir / OUTPUT_MARKER).is_file():
        return True
    if out_dir == build_dir:
        return False
    return is_relative_to(out_dir, build_dir)


def write_output_marker(out_dir: Path) -> None:
    (out_dir / OUTPUT_MARKER).write_text(
        "Generated by tools/perf/perf_smoke.py. This directory may be cleaned by the perf harness.\n",
        encoding="utf-8",
    )


def redact_text(text: str) -> str:
    redacted = URL_USERINFO_RE.sub(r"\1<redacted>@", text)
    redacted = SENSITIVE_HEADER_RE.sub(lambda m: f"{m.group('prefix')}<redacted>", redacted)
    redacted = SENSITIVE_ASSIGNMENT_RE.sub(redact_assignment_match, redacted)
    redacted = PRIVATE_URI_RE.sub("<redacted-uri>", redacted)
    return redacted


def redact_assignment_match(match: re.Match[str]) -> str:
    value = match.group("value")
    if len(value) >= 2 and value[0] in {"'", '"'} and value[-1] == value[0]:
        redacted_value = f"{value[0]}<redacted>{value[-1]}"
    else:
        redacted_value = "<redacted>"
    return f"{match.group('prefix')}{redacted_value}"


def scrub_local_paths(text: str, settings: Settings) -> str:
    scrubbed = text
    replacements = (
        (settings.workspace_root.resolve(), "<workspace>"),
        (Path.home().resolve(), "<home>"),
    )
    for path, label in replacements:
        value = str(path)
        if value and value != os.sep:
            scrubbed = scrubbed.replace(value, label)
    return scrubbed


def sanitize_artifact_logs(logs_dir: Path, settings: Settings) -> None:
    if not logs_dir.is_dir():
        return
    for path in sorted(logs_dir.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        sanitized = scrub_local_paths(redact_text(text), settings)
        if sanitized != text:
            path.write_text(sanitized, encoding="utf-8")


def redact_value(value: Any, key_hint: str = "") -> Any:
    if SENSITIVE_KEY_RE.search(key_hint):
        return "<redacted>"
    if isinstance(value, dict):
        return {str(k): redact_value(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(item, key_hint) for item in value]
    if isinstance(value, tuple):
        return [redact_value(item, key_hint) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def write_json(path: Path, value: Any, *, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(redact_value(value), indent=2, sort_keys=True, allow_nan=False) + "\n"
    path.write_text(text, encoding="utf-8")
    if mode is not None:
        path.chmod(mode)


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(redact_text(value), encoding="utf-8")


def metric_collected(value: int | float | bool, unit: str, **details: Any) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "collected", "unit": unit, "value": value}
    result.update(details)
    return result


def metric_skipped(reason: str, unit: str | None = None, **details: Any) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "skipped", "reason": reason}
    if unit is not None:
        result["unit"] = unit
    result.update(details)
    return result


def metric_failed(reason: str, unit: str | None = None, **details: Any) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "failed", "reason": reason}
    if unit is not None:
        result["unit"] = unit
    result.update(details)
    return result


def metric_readiness_timeout(reason: str, settings: Settings, **details: Any) -> dict[str, Any]:
    return metric_failed(
        reason,
        "ms",
        value=settings.startup_timeout_seconds * 1000,
        timeout_seconds=settings.startup_timeout_seconds,
        **details,
    )


def is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def directory_size_bytes(path: Path, excluded_top_level: set[str] | None = None) -> int:
    excluded = excluded_top_level or set()
    total = 0
    if path.is_file():
        return path.stat().st_size
    for child in path.rglob("*"):
        try:
            relative_parts = child.relative_to(path).parts
        except ValueError:
            relative_parts = ()
        if relative_parts and relative_parts[0] in excluded:
            continue
        if child.is_file() and not child.is_symlink():
            total += child.stat().st_size
    return total


def first_party_app_size_metric_names() -> tuple[str, ...]:
    return tuple(
        metric_name
        for metric_prefix, _ in FIRST_PARTY_APP_SIZE_TARGETS
        for metric_name in (
            f"apps.{metric_prefix}_static_bytes",
            f"apphost.{metric_prefix}_staged_bundle_bytes",
        )
    )


def collect_file_size(
    metrics: dict[str, dict[str, Any]],
    metric_name: str,
    path: Path,
    workspace_root: Path,
) -> None:
    if path.is_file():
        metrics[metric_name] = metric_collected(
            path.stat().st_size,
            "bytes",
            source=display_path(path, workspace_root),
        )
    else:
        metrics[metric_name] = metric_skipped(
            f"file not found: {display_path(path, workspace_root)}",
            "bytes",
            source=display_path(path, workspace_root),
        )


def collect_directory_size(
    metrics: dict[str, dict[str, Any]],
    metric_name: str,
    path: Path,
    workspace_root: Path,
) -> None:
    if path.is_dir():
        metrics[metric_name] = metric_collected(
            directory_size_bytes(path),
            "bytes",
            source=display_path(path, workspace_root),
        )
    else:
        metrics[metric_name] = metric_skipped(
            f"directory not found: {display_path(path, workspace_root)}",
            "bytes",
            source=display_path(path, workspace_root),
        )


def collect_asset_metrics(settings: Settings, metrics: dict[str, dict[str, Any]]) -> None:
    root = settings.workspace_root
    collect_file_size(
        metrics,
        "web_shell.index_html_bytes",
        root / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/index.html",
        root,
    )
    collect_file_size(
        metrics,
        "web_shell.web_shell_js_bytes",
        root
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js",
        root,
    )
    collect_file_size(
        metrics,
        "web_shell.web_shell_css_bytes",
        root
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.css",
        root,
    )
    collect_file_size(
        metrics,
        "platform_sdk.crypta_platform_js_bytes",
        root
        / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js",
        root,
    )
    for metric_prefix, app_directory in FIRST_PARTY_APP_SIZE_TARGETS:
        collect_directory_size(
            metrics,
            f"apps.{metric_prefix}_static_bytes",
            root / "apps" / app_directory / "src/staged/static",
            root,
        )
    for metric_prefix, app_directory in FIRST_PARTY_APP_SIZE_TARGETS:
        collect_directory_size(
            metrics,
            f"apphost.{metric_prefix}_staged_bundle_bytes",
            root / "apps" / app_directory / "build/cryptad-app" / app_directory,
            root,
        )


def collect_distribution_metrics(
    settings: Settings, metrics: dict[str, dict[str, Any]], build_ms: int | None
) -> None:
    dist_dir = settings.cryptad_dist_dir
    exists = dist_dir.is_dir()
    metrics["distribution.exists"] = metric_collected(
        exists,
        "boolean",
        source=display_path(dist_dir, settings.workspace_root),
    )
    if exists:
        metrics["distribution.size_bytes"] = metric_collected(
            directory_size_bytes(dist_dir, {"logs", "tmp"}),
            "bytes",
            source=display_path(dist_dir, settings.workspace_root),
            excluded_top_level=["logs", "tmp"],
        )
    else:
        metrics["distribution.size_bytes"] = metric_skipped(
            f"distribution directory not found: {display_path(dist_dir, settings.workspace_root)}",
            "bytes",
            source=display_path(dist_dir, settings.workspace_root),
        )
    if build_ms is None:
        metrics["distribution.build_ms"] = metric_skipped(
            "PERF_SKIP_BUILD=1 or self-test mode did not run the Gradle distribution task",
            "ms",
        )
    else:
        metrics["distribution.build_ms"] = metric_collected(build_ms, "ms")


def gradle_wrapper_path(settings: Settings, system_name: str | None = None) -> Path:
    current_system = system_name or platform.system()
    wrapper_name = "gradlew.bat" if current_system == "Windows" else "gradlew"
    return settings.workspace_root / wrapper_name


def run_distribution_build(settings: Settings, layout: Layout) -> tuple[int | None, bool]:
    if settings.mode == "self-test" or settings.skip_build:
        return None, True
    gradlew = gradle_wrapper_path(settings)
    if not gradlew.is_file():
        return None, False
    stdout_path = layout.logs_dir / "assembleCryptadDist.stdout.log"
    stderr_path = layout.logs_dir / "assembleCryptadDist.stderr.log"
    start = monotonic_ms()
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        result = subprocess.run(
            [str(gradlew), "assembleCryptadDist"],
            cwd=settings.workspace_root,
            stdout=stdout,
            stderr=stderr,
            check=False,
            timeout=settings.timeout_seconds,
        )
    elapsed = monotonic_ms() - start
    return elapsed, result.returncode == 0


def java_version() -> str:
    java = shutil.which("java")
    if java is None:
        return "not_found"
    try:
        result = subprocess.run(
            [java, "-version"],
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return "unavailable"
    first_line = (result.stderr or result.stdout).splitlines()
    return first_line[0].strip() if first_line else "unavailable"


def environment_snapshot() -> dict[str, str]:
    return {
        "os": platform.system() or "unknown",
        "arch": platform.machine() or "unknown",
        "java_version": java_version(),
        "python_version": platform.python_version(),
    }


def ensure_tcp_port_available(port: int) -> None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        probe.bind(("127.0.0.1", port))
    except OSError as exc:
        raise PerfFailure(f"TCP port 127.0.0.1:{port} is already in use") from exc
    finally:
        probe.close()


def ensure_udp_port_available(port: int) -> None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind(("127.0.0.1", port))
    except OSError as exc:
        raise PerfFailure(f"UDP port 127.0.0.1:{port} is already in use") from exc
    finally:
        probe.close()


def tcp_connects(port: int, timeout_seconds: float = 0.5) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout_seconds):
            return True
    except OSError:
        return False


def make_cryptad_config(settings: Settings, node_dir: Path) -> Path:
    paths = (
        node_dir / "config",
        node_dir / "data" / "node",
        node_dir / "data" / "user",
        node_dir / "data" / "store",
        node_dir / "data" / "downloads",
        node_dir / "cache" / "tmp",
        node_dir / "cache" / "persistent-temp",
        node_dir / "run",
        node_dir / "logs",
    )
    for path in paths:
        path.mkdir(parents=True, exist_ok=True)
    config_file = node_dir / "config" / "cryptad.ini"
    config_file.write_text(
        f"""node.install.cfgDir={node_dir / 'config'}
node.install.nodeDir={node_dir / 'data' / 'node'}
node.install.userDir={node_dir / 'data' / 'user'}
node.install.runDir={node_dir / 'run'}
node.install.storeDir={node_dir / 'data' / 'store'}
node.install.tempDir={node_dir / 'cache' / 'tmp'}
node.install.persistentTempDir={node_dir / 'cache' / 'persistent-temp'}
node.downloadsDir={node_dir / 'data' / 'downloads'}
logger.dirname={node_dir / 'logs'}
logger.priority=NORMAL
node.updater.enabled=false
node.updater.autoupdate=false
node.updater.updateInstallers=false
node.opennet.enabled=false
node.ipAddressOverride=127.0.0.1
node.allowBindToLocalhost=true
node.bindTo=127.0.0.1
node.listenPort={settings.fnp_port}
node.maxHTL=5
node.disableProbabilisticHTLs=true
node.enableARKs=false
node.storeSize=67108864
node.clientCacheSize=1048576
node.slashdotCacheSize=0
node.outputBandwidthLimit=262144
node.throttleLocalTraffic=false
node.alwaysAllowLocalAddresses=true
node.includeLocalAddressesInNoderefs=false
fcp.enabled=true
fcp.port={settings.fcp_port}
fcp.bindTo=127.0.0.1
fcp.allowedHosts=127.0.0.1
fcp.allowedHostsFullAccess=127.0.0.1
fcp.ssl=false
fproxy.enabled=true
fproxy.port={settings.web_port}
fproxy.bindTo=127.0.0.1
fproxy.allowedHosts=127.0.0.1
fproxy.allowedHostsFullAccess=127.0.0.1
fproxy.ssl=false
fproxy.javascriptEnabled=true
fproxy.hasCompletedWizard=true
console.enabled=false
End
""",
        encoding="utf-8",
    )
    return config_file


def cryptad_launcher_path(settings: Settings, system_name: str | None = None) -> Path:
    current_system = system_name or platform.system()
    launcher_name = "cryptad.bat" if current_system == "Windows" else "cryptad"
    return settings.cryptad_dist_dir / "bin" / launcher_name


def launch_cryptad(settings: Settings, layout: Layout) -> NodeRuntime:
    launcher = cryptad_launcher_path(settings)
    if not launcher.is_file():
        raise PerfFailure(f"Cryptad launcher not found: {display_path(launcher, settings.workspace_root)}")
    if platform.system() != "Windows" and not os.access(launcher, os.X_OK):
        raise PerfFailure(f"Cryptad launcher is not executable: {display_path(launcher, settings.workspace_root)}")
    node_dir = layout.work_dir / "cryptad"
    config_file = make_cryptad_config(settings, node_dir)
    node_args = [
        "--config-file",
        str(config_file),
        "--config-dir",
        str(node_dir / "config"),
        "--data-dir",
        str(node_dir / "data"),
        "--cache-dir",
        str(node_dir / "cache"),
        "--run-dir",
        str(node_dir / "run"),
        "--logs-dir",
        str(node_dir / "logs"),
    ]
    command = [str(launcher)]
    command.extend(
        f"wrapper.app.parameter.{index}={value}" for index, value in enumerate(node_args, start=1)
    )
    stdout_path = layout.logs_dir / "cryptad.stdout.log"
    stderr_path = layout.logs_dir / "cryptad.stderr.log"
    stdout_handle = stdout_path.open("wb")
    stderr_handle = stderr_path.open("wb")
    environment = os.environ.copy()
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        environment["CRYPTAD_ALLOW_ROOT"] = "1"
    start = monotonic_ms()
    process = subprocess.Popen(
        command,
        cwd=node_dir,
        stdout=stdout_handle,
        stderr=stderr_handle,
        env=environment,
        start_new_session=True,
    )
    spawn_ms = monotonic_ms() - start
    return NodeRuntime(
        process=process,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        stdout_handle=stdout_handle,
        stderr_handle=stderr_handle,
        config_file=config_file,
        node_dir=node_dir,
        spawn_ms=spawn_ms,
    )


def terminate_node(runtime: NodeRuntime | None) -> int | None:
    if runtime is None:
        return None
    process = runtime.process
    try:
        if process.poll() is None:
            signal_node_process(process, force=False)
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                signal_node_process(process, force=True)
                process.wait(timeout=10)
        return process.poll()
    finally:
        runtime.stdout_handle.close()
        runtime.stderr_handle.close()


def signal_node_process(process: subprocess.Popen[bytes], *, force: bool) -> None:
    try:
        if hasattr(os, "killpg"):
            os.killpg(process.pid, signal.SIGKILL if force else signal.SIGTERM)
        elif force:
            process.kill()
        else:
            process.terminate()
    except ProcessLookupError:
        pass


def parse_properties(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def http_latency_ms(path: str, settings: Settings) -> tuple[dict[str, Any], int | None]:
    url = f"http://127.0.0.1:{settings.web_port}{path}"
    request = Request(url, headers={"Accept": "application/json"})
    start = monotonic_ms()
    try:
        with urlopen(request, timeout=settings.request_timeout_seconds) as response:
            response.read()
            elapsed = monotonic_ms() - start
            status_code = response.getcode()
    except HTTPError as exc:
        elapsed = monotonic_ms() - start
        return (
            metric_failed(
                f"HTTP {exc.code} from {path}",
                "ms",
                path=path,
                status_code=exc.code,
            ),
            elapsed,
        )
    except (OSError, URLError) as exc:
        return metric_failed(f"request failed for {path}: {exc}", "ms", path=path), None
    if 200 <= status_code < 300:
        return metric_collected(elapsed, "ms", path=path, status_code=status_code), elapsed
    return metric_failed(f"HTTP {status_code} from {path}", "ms", path=path, status_code=status_code), elapsed


def probe_succeeded(metric: dict[str, Any]) -> bool:
    return metric.get("status") == "collected"


def wait_for_node_readiness(
    settings: Settings,
    runtime: NodeRuntime,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    start = monotonic_ms()
    deadline = time.monotonic() + settings.startup_timeout_seconds
    fcp_ready_ms: int | None = None
    platform_ready_ms: int | None = None
    readiness_payload: dict[str, str] | None = None
    readiness_file = runtime.node_dir / "run" / "platform-ui.properties"
    last_error = ""
    while time.monotonic() < deadline:
        exit_code = runtime.process.poll()
        if exit_code is not None:
            reason = f"Cryptad exited before readiness checks completed (exit={exit_code})"
            return (
                {
                    "node.startup_to_fcp_ready_ms": metric_failed(reason, "ms"),
                    "node.startup_to_platform_readiness_ms": metric_failed(reason, "ms"),
                },
                {
                    "process_exit_code": exit_code,
                    "readiness_file": display_path(readiness_file, settings.workspace_root),
                },
            )
        elapsed = monotonic_ms() - start
        if fcp_ready_ms is None and tcp_connects(settings.fcp_port):
            fcp_ready_ms = elapsed
        if readiness_payload is None and readiness_file.is_file():
            try:
                parsed = parse_properties(readiness_file)
                if parsed.get("state") == "ready":
                    readiness_payload = parsed
            except OSError as exc:
                last_error = str(exc)
        if platform_ready_ms is None and tcp_connects(settings.web_port):
            metric, latency = http_latency_ms("/api/v1/node/greeting", settings)
            if probe_succeeded(metric) and latency is not None:
                platform_ready_ms = elapsed + latency
            elif metric["status"] == "failed":
                last_error = metric.get("reason", "")
        if fcp_ready_ms is not None and platform_ready_ms is not None:
            break
        time.sleep(0.5)

    node_metrics: dict[str, dict[str, Any]] = {
        "node.startup_to_process_spawn_ms": metric_collected(runtime.spawn_ms, "ms")
    }
    if platform_ready_ms is None:
        node_metrics["node.startup_to_platform_readiness_ms"] = metric_readiness_timeout(
            "Platform API readiness was not observed before timeout"
            + (f": {last_error}" if last_error else ""),
            settings,
            readiness_file_observed=readiness_payload is not None,
        )
    else:
        node_metrics["node.startup_to_platform_readiness_ms"] = metric_collected(
            platform_ready_ms,
            "ms",
            readiness_file_observed=readiness_payload is not None,
        )
    if fcp_ready_ms is None:
        node_metrics["node.startup_to_fcp_ready_ms"] = metric_readiness_timeout(
            "FCP listener was not observed before timeout",
            settings,
        )
    else:
        node_metrics["node.startup_to_fcp_ready_ms"] = metric_collected(fcp_ready_ms, "ms")
    raw = {
        "readiness_file": display_path(readiness_file, settings.workspace_root),
        "readiness_payload": readiness_payload or {},
        "process_exit_code": runtime.process.poll(),
    }
    return node_metrics, raw


def read_fcp_frame(handle: Any) -> tuple[str, dict[str, str]]:
    name_line = handle.readline()
    if not name_line:
        raise PerfFailure("FCP connection closed before a response frame was received")
    name = name_line.decode("utf-8", errors="replace").strip()
    fields: dict[str, str] = {}
    while True:
        raw_line = handle.readline()
        if not raw_line:
            raise PerfFailure("FCP connection closed before End")
        line = raw_line.decode("utf-8", errors="replace").strip()
        if line == "EndMessage":
            return name, fields
        if line == "Data":
            return name, fields
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key] = value


def fcp_client_hello(settings: Settings) -> dict[str, Any]:
    start = monotonic_ms()
    try:
        with socket.create_connection(("127.0.0.1", settings.fcp_port), timeout=settings.request_timeout_seconds) as sock:
            sock.settimeout(settings.request_timeout_seconds)
            handle = sock.makefile("rwb")
            handle.write(
                b"ClientHello\n"
                b"Name=cryptad-performance-smoke\n"
                b"ExpectedVersion=2.0\n"
                b"EndMessage\n"
            )
            handle.flush()
            frame_name, fields = read_fcp_frame(handle)
    except (OSError, PerfFailure) as exc:
        return metric_failed(f"FCP ClientHello failed: {exc}", "ms")
    elapsed = monotonic_ms() - start
    if frame_name != "NodeHello":
        return metric_failed(f"expected NodeHello, got {frame_name}", "ms")
    return metric_collected(
        elapsed,
        "ms",
        response=frame_name,
        node=fields.get("Node", "<unknown>"),
        build=fields.get("Build", "<unknown>"),
    )


def collect_platform_api_metrics(settings: Settings) -> dict[str, dict[str, Any]]:
    endpoints = {
        "platform_api.node_ms": "/api/v1/node/greeting",
        "platform_api.peers_ms": "/api/v1/peers",
        "platform_api.apps_ms": "/api/v1/apps",
        "platform_api.diagnostics_ms": "/api/v1/diagnostics",
    }
    result: dict[str, dict[str, Any]] = {}
    for metric_name, path in endpoints.items():
        metric, _ = http_latency_ms(path, settings)
        result[metric_name] = metric
    return result


def collect_node_metrics(
    settings: Settings,
    layout: Layout,
    metrics: dict[str, dict[str, Any]],
    raw: dict[str, Any],
) -> str | None:
    if not settings.cryptad_dist_dir.is_dir():
        reason = "packaged Cryptad distribution is not available"
        mark_node_metrics_skipped(metrics, reason)
        return reason
    if shutil.which("java") is None:
        reason = "java executable is not available on PATH"
        mark_node_metrics_skipped(metrics, reason)
        return reason
    try:
        ensure_tcp_port_available(settings.fcp_port)
        ensure_tcp_port_available(settings.web_port)
        ensure_udp_port_available(settings.fnp_port)
    except PerfFailure as exc:
        reason = str(exc)
        mark_node_metrics_skipped(metrics, reason)
        return reason

    runtime: NodeRuntime | None = None
    try:
        try:
            runtime = launch_cryptad(settings, layout)
        except (PerfFailure, OSError) as exc:
            reason = str(exc)
            mark_node_metrics_failed(metrics, reason)
            raw["node_failure_reason"] = reason
            return None
        startup_metrics, startup_raw = wait_for_node_readiness(settings, runtime)
        metrics.update(startup_metrics)
        raw["node_startup"] = startup_raw
        if metrics.get("node.startup_to_fcp_ready_ms", {}).get("status") == "collected":
            metrics["fcp.client_hello_ms"] = fcp_client_hello(settings)
        else:
            metrics["fcp.client_hello_ms"] = metric_skipped("FCP listener was not ready", "ms")
        if metrics.get("node.startup_to_platform_readiness_ms", {}).get("status") == "collected":
            metrics.update(collect_platform_api_metrics(settings))
        else:
            mark_platform_api_metrics_skipped(metrics, "Platform API was not ready")
    except PerfFailure as exc:
        reason = str(exc)
        mark_node_metrics_failed(metrics, reason)
        raw["node_failure_reason"] = reason
        return None
    finally:
        exit_code = terminate_node(runtime)
        raw["node_exit_code"] = exit_code
    return None


def mark_node_metrics_skipped(metrics: dict[str, dict[str, Any]], reason: str) -> None:
    for name in (
        "node.startup_to_process_spawn_ms",
        "node.startup_to_platform_readiness_ms",
        "node.startup_to_fcp_ready_ms",
        "fcp.client_hello_ms",
    ):
        metrics[name] = metric_skipped(reason, "ms")
    mark_platform_api_metrics_skipped(metrics, reason)


def mark_node_metrics_failed(metrics: dict[str, dict[str, Any]], reason: str) -> None:
    for name in (
        "node.startup_to_process_spawn_ms",
        "node.startup_to_platform_readiness_ms",
        "node.startup_to_fcp_ready_ms",
        "fcp.client_hello_ms",
    ):
        metrics[name] = metric_failed(reason, "ms")
    mark_platform_api_metrics_failed(metrics, reason)


def mark_platform_api_metrics_skipped(metrics: dict[str, dict[str, Any]], reason: str) -> None:
    for name in (
        "platform_api.node_ms",
        "platform_api.peers_ms",
        "platform_api.apps_ms",
        "platform_api.diagnostics_ms",
    ):
        metrics[name] = metric_skipped(reason, "ms")


def mark_platform_api_metrics_failed(metrics: dict[str, dict[str, Any]], reason: str) -> None:
    for name in (
        "platform_api.node_ms",
        "platform_api.peers_ms",
        "platform_api.apps_ms",
        "platform_api.diagnostics_ms",
    ):
        metrics[name] = metric_failed(reason, "ms")


def load_baseline(path: Path, *, allow_missing: bool = False) -> dict[str, Any]:
    if not path.is_file():
        if not allow_missing:
            raise PerfFailure(f"Baseline JSON is required but was not found: {path}")
        return {"version": BASELINE_SCHEMA_VERSION, "metrics": {}}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PerfFailure(f"Baseline JSON is invalid: {path}: {exc}") from exc
    if value.get("version") != BASELINE_SCHEMA_VERSION:
        raise PerfFailure(
            f"Unsupported baseline version {value.get('version')!r}; expected {BASELINE_SCHEMA_VERSION}"
        )
    if not isinstance(value.get("metrics"), dict):
        raise PerfFailure("Baseline JSON must contain a metrics object")
    return value


def threshold_label(rule: dict[str, Any], level: str) -> str:
    if level == "fail":
        return ", ".join(
            str(rule[key])
            for key in ("fail_ratio", "fail_ms", "max_bytes")
            if key in rule
        )
    return ", ".join(str(rule[key]) for key in ("warn_ratio", "warn_ms") if key in rule)


def compare_metric(
    name: str,
    metric: dict[str, Any],
    rule: dict[str, Any],
    *,
    fail_on_regression: bool,
) -> tuple[str, dict[str, Any] | None]:
    if metric.get("status") == "skipped":
        entry = {
            "metric": name,
            "reason": metric.get("reason", "metric skipped"),
            "status": "skipped",
        }
        if rule.get("required", False):
            entry["reason"] = f"required baseline metric was skipped: {entry['reason']}"
            return "fail", entry
        return "skipped", entry
    if metric.get("status") == "failed":
        return "fail", {
            "metric": name,
            "reason": metric.get("reason", "metric failed to collect"),
            "status": "failed",
        }
    value = metric.get("value")
    if not is_number(value):
        return "not_compared", {
            "metric": name,
            "reason": "metric is not numeric",
            "status": metric.get("status", "unknown"),
        }
    unit = metric.get("unit")
    baseline_value = rule.get("baseline")
    warn = False
    fail = False
    reasons: list[str] = []
    if rule.get("unit") and unit != rule.get("unit"):
        return "fail", {
            "metric": name,
            "value": value,
            "unit": unit,
            "reason": f"unit mismatch: expected {rule.get('unit')}, got {unit}",
        }
    if "max_bytes" in rule and value > rule["max_bytes"]:
        fail = True
        reasons.append(f"value {value} exceeds max_bytes {rule['max_bytes']}")
    if "fail_ms" in rule and value >= rule["fail_ms"]:
        fail = True
        reasons.append(f"value {value}ms crosses fail_ms {rule['fail_ms']}")
    if "warn_ms" in rule and value >= rule["warn_ms"]:
        warn = True
        reasons.append(f"value {value}ms crosses warn_ms {rule['warn_ms']}")
    if is_number(baseline_value) and baseline_value > 0:
        ratio = value / baseline_value
        if "fail_ratio" in rule and ratio >= rule["fail_ratio"]:
            fail = True
            reasons.append(
                f"value ratio {ratio:.3f} crosses fail_ratio {rule['fail_ratio']}"
            )
        elif "warn_ratio" in rule and ratio >= rule["warn_ratio"]:
            warn = True
            reasons.append(
                f"value ratio {ratio:.3f} crosses warn_ratio {rule['warn_ratio']}"
            )
    elif "warn_ratio" in rule or "fail_ratio" in rule:
        return "warn", {
            "metric": name,
            "value": value,
            "unit": unit,
            "reason": "ratio threshold configured but baseline is missing or zero",
        }
    if not fail and not warn:
        return "pass", None
    entry = {
        "metric": name,
        "value": value,
        "unit": unit,
        "baseline": baseline_value,
        "threshold": threshold_label(rule, "fail" if fail else "warn"),
        "reason": "; ".join(reasons),
    }
    fail_by_default = bool(rule.get("fail_on_regression", False))
    if fail:
        return ("fail" if fail_by_default or fail_on_regression else "warn"), entry
    return "warn", entry


def compare_to_baseline(
    metrics: dict[str, dict[str, Any]],
    baseline: dict[str, Any],
    *,
    fail_on_regression: bool,
) -> dict[str, Any]:
    rules = baseline.get("metrics", {})
    if not rules:
        return {
            "status": "not_compared",
            "regressions": [],
            "warnings": [{"reason": "baseline contains no metric rules"}],
            "skipped": [],
            "not_compared": [],
        }
    regressions: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    not_compared: list[dict[str, Any]] = []
    for name, metric in metrics.items():
        rule = rules.get(name)
        if rule is None:
            if metric.get("status") == "collected" and is_number(metric.get("value")):
                not_compared.append({"metric": name, "reason": "no baseline rule"})
            continue
        level, entry = compare_metric(name, metric, rule, fail_on_regression=fail_on_regression)
        if entry is None:
            continue
        if level == "fail":
            regressions.append(entry)
        elif level == "warn":
            warnings.append(entry)
        elif level == "skipped":
            skipped.append(entry)
        elif level == "not_compared":
            not_compared.append(entry)
    for name, rule in rules.items():
        if name not in metrics and rule.get("required", False):
            regressions.append({"metric": name, "reason": "required baseline metric was not collected"})
    if regressions:
        status = "fail"
    elif warnings:
        status = "warn"
    else:
        status = "pass"
    return {
        "status": status,
        "regressions": regressions,
        "warnings": warnings,
        "skipped": skipped,
        "not_compared": not_compared,
    }


def update_baseline_file(path: Path, baseline: dict[str, Any], metrics: dict[str, dict[str, Any]]) -> None:
    updated = json.loads(json.dumps(baseline))
    updated.setdefault("version", BASELINE_SCHEMA_VERSION)
    updated.setdefault("metrics", {})
    updated["updated_at"] = utc_now()
    for name, metric in metrics.items():
        if metric.get("status") != "collected" or not is_number(metric.get("value")):
            continue
        rule = updated["metrics"].setdefault(
            name,
            {
                "baseline": metric["value"],
                "unit": metric.get("unit"),
                "warn_ratio": 1.25,
                "fail_ratio": 2.0,
                "fail_on_regression": False,
            },
        )
        rule["baseline"] = metric["value"]
        rule["unit"] = metric.get("unit")
    write_json(path, updated)


def make_summary(
    settings: Settings,
    environment: dict[str, str],
    baseline: dict[str, Any],
    metrics: dict[str, dict[str, Any]],
    comparison: dict[str, Any],
    started_at: str,
    finished_at: str,
    duration_ms: int,
    status: str,
) -> dict[str, Any]:
    return {
        "status": status,
        "mode": settings.mode,
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_ms": duration_ms,
        "environment": environment,
        "baseline": {
            "path": display_path(settings.baseline_path, settings.workspace_root),
            "version": baseline.get("version", BASELINE_SCHEMA_VERSION),
            "updated": settings.update_baseline,
        },
        "metrics": metrics,
        "comparison": {
            "status": comparison.get("status", "not_compared"),
            "regressions": comparison.get("regressions", []),
            "warnings": comparison.get("warnings", []),
            "skipped": comparison.get("skipped", []),
            "not_compared": comparison.get("not_compared", []),
        },
    }


def report_metric_value(metric: dict[str, Any]) -> str:
    if metric.get("status") != "collected":
        return ""
    value = metric.get("value")
    unit = metric.get("unit", "")
    return f"{value} {unit}".strip()


def comparison_reason_for(name: str, comparison: dict[str, Any]) -> str:
    for group in ("regressions", "warnings", "skipped", "not_compared"):
        for entry in comparison.get(group, []):
            if entry.get("metric") == name:
                return str(entry.get("reason", ""))
    return ""


def generate_report(summary: dict[str, Any], comparison: dict[str, Any]) -> str:
    lines = [
        "# Performance smoke report",
        "",
        f"- Status: `{summary['status']}`",
        f"- Mode: `{summary['mode']}`",
        f"- Duration: `{summary['duration_ms']} ms`",
        f"- Comparison: `{comparison.get('status', 'not_compared')}`",
        "",
        "| Metric | Status | Value | Notes |",
        "| --- | --- | --- | --- |",
    ]
    metrics = summary.get("metrics", {})
    for name in sorted(metrics):
        metric = metrics[name]
        notes = metric.get("reason") or comparison_reason_for(name, comparison)
        source = metric.get("source")
        if source and not notes:
            notes = source
        escaped_notes = str(notes).replace("|", "\\|")
        lines.append(
            f"| `{name}` | `{metric.get('status', 'unknown')}` | "
            f"{report_metric_value(metric)} | {escaped_notes} |"
        )
    lines.extend(
        [
            "",
            "Skipped metrics are explicit so missing node, toolchain, or credential prerequisites "
            "do not look like successful measurements.",
            "",
        ]
    )
    return "\n".join(lines)


def smoke_has_skipped_runtime_metrics(metrics: dict[str, dict[str, Any]]) -> bool:
    runtime_prefixes = ("node.", "fcp.", "platform_api.")
    for name, metric in metrics.items():
        if name == "distribution.size_bytes" or name.startswith(runtime_prefixes):
            if metric.get("status") == "skipped":
                return True
    return False


def determine_status(
    settings: Settings,
    comparison: dict[str, Any],
    build_ok: bool,
    metrics: dict[str, dict[str, Any]],
) -> str:
    if not build_ok:
        return "failure"
    if settings.mode == "collect" or settings.update_baseline:
        return "warning" if comparison.get("status") in {"warn", "fail"} else "success"
    if comparison.get("status") == "fail":
        return "failure"
    if comparison.get("status") in {"warn", "not_compared"}:
        return "warning"
    if settings.mode == "smoke" and smoke_has_skipped_runtime_metrics(metrics):
        return "warning"
    return "success"


def run_perf(settings: Settings) -> tuple[dict[str, Any], int]:
    layout = safe_prepare_layout(settings)
    started_at = utc_now()
    started_ms = monotonic_ms()
    environment = environment_snapshot()
    metrics: dict[str, dict[str, Any]] = {}
    raw: dict[str, Any] = {
        "tool": TOOL_NAME,
        "mode": settings.mode,
        "ports": {
            "fnp": settings.fnp_port,
            "fcp": settings.fcp_port,
            "web": settings.web_port,
        },
    }
    build_ms, build_ok = run_distribution_build(settings, layout)
    collect_asset_metrics(settings, metrics)
    collect_distribution_metrics(settings, metrics, build_ms)
    if not build_ok:
        metrics["distribution.build_ms"] = metric_failed(
            "Gradle assembleCryptadDist failed or timed out; see artifacts/logs",
            "ms",
            value=build_ms,
        )
    if settings.mode in {"smoke", "collect"} and build_ok:
        node_skip_reason = collect_node_metrics(settings, layout, metrics, raw)
        if node_skip_reason:
            raw["node_skip_reason"] = node_skip_reason
    sanitize_artifact_logs(layout.logs_dir, settings)
    baseline = load_baseline(
        settings.baseline_path,
        allow_missing=settings.mode == "collect" or settings.update_baseline,
    )
    comparison = compare_to_baseline(
        metrics, baseline, fail_on_regression=settings.fail_on_regression
    )
    if settings.update_baseline:
        update_baseline_file(settings.baseline_path, baseline, metrics)
        baseline = load_baseline(settings.baseline_path)
    finished_at = utc_now()
    duration_ms = monotonic_ms() - started_ms
    status = determine_status(settings, comparison, build_ok, metrics)
    summary = make_summary(
        settings,
        environment,
        baseline,
        metrics,
        comparison,
        started_at,
        finished_at,
        duration_ms,
        status,
    )
    raw["metrics"] = metrics
    raw["environment"] = environment
    write_json(layout.artifacts_dir / "raw-metrics.json", raw)
    write_json(layout.artifacts_dir / "baseline-comparison.json", comparison)
    write_text(layout.artifacts_dir / "perf-report.md", generate_report(summary, comparison))
    write_json(layout.out_dir / "summary.json", summary)
    exit_code = 1 if status == "failure" else 0
    return summary, exit_code


def assert_no_secret(value: Any) -> None:
    encoded = json.dumps(value, sort_keys=True)
    forbidden = (
        "super-secret",
        "token-value",
        "formPassword=hunter2",
        "USK@private",
        "crypto-secret",
        "bearer-secret",
        "json-secret",
        "assign-bearer-secret",
        "cookie-secret",
    )
    for needle in forbidden:
        assert needle not in encoded, f"redaction leaked {needle}"


def run_self_test(settings: Settings) -> tuple[dict[str, Any], int]:
    layout = safe_prepare_layout(settings)
    started_at = utc_now()
    started_ms = monotonic_ms()
    fixture_baseline_path = settings.workspace_root / "tools/perf/fixtures/self-test-baseline.json"
    fixture_summary_path = settings.workspace_root / "tools/perf/fixtures/self-test-summary.json"
    assert (layout.out_dir / OUTPUT_MARKER).is_file()
    unsafe_output_settings = Settings(
        workspace_root=settings.workspace_root,
        out_dir=settings.workspace_root / "docs",
        baseline_path=settings.baseline_path,
        cryptad_dist_dir=settings.cryptad_dist_dir,
        mode=settings.mode,
        skip_build=settings.skip_build,
        update_baseline=settings.update_baseline,
        fail_on_regression=settings.fail_on_regression,
        timeout_seconds=settings.timeout_seconds,
        startup_timeout_seconds=settings.startup_timeout_seconds,
        request_timeout_seconds=settings.request_timeout_seconds,
        fcp_port=settings.fcp_port,
        web_port=settings.web_port,
        fnp_port=settings.fnp_port,
    )
    try:
        safe_prepare_layout(unsafe_output_settings)
    except PerfFailure as exc:
        assert "Refusing to clean PERF_OUT_DIR" in str(exc), exc
    else:
        raise AssertionError("unsafe output directory was not rejected")
    missing_baseline_path = layout.work_dir / "missing-baseline.json"
    try:
        load_baseline(missing_baseline_path)
    except PerfFailure as exc:
        assert "Baseline JSON is required" in str(exc), exc
    else:
        raise AssertionError("missing smoke baseline was not rejected")
    assert load_baseline(missing_baseline_path, allow_missing=True)["metrics"] == {}
    baseline = load_baseline(fixture_baseline_path)
    default_baseline = load_baseline(settings.workspace_root / DEFAULT_BASELINE)
    default_baseline_metrics = default_baseline.get("metrics", {})
    for metric_name in first_party_app_size_metric_names():
        assert metric_name in default_baseline_metrics, metric_name
    fixture_summary = json.loads(fixture_summary_path.read_text(encoding="utf-8"))
    pass_metrics = fixture_summary["metrics"]
    pass_comparison = compare_to_baseline(pass_metrics, baseline, fail_on_regression=True)
    assert pass_comparison["status"] == "pass", pass_comparison

    warn_metrics = {
        "fixture.latency_ms": metric_collected(125, "ms"),
        "fixture.payload_bytes": metric_collected(1000, "bytes"),
        "fixture.skipped_ms": metric_skipped("optional check disabled", "ms"),
    }
    warn_comparison = compare_to_baseline(warn_metrics, baseline, fail_on_regression=True)
    assert warn_comparison["status"] == "warn", warn_comparison

    fail_metrics = {
        "fixture.latency_ms": metric_collected(175, "ms"),
        "fixture.payload_bytes": metric_collected(1000, "bytes"),
        "fixture.skipped_ms": metric_skipped("optional check disabled", "ms"),
    }
    fail_comparison = compare_to_baseline(fail_metrics, baseline, fail_on_regression=True)
    assert fail_comparison["status"] == "fail", fail_comparison

    skipped_metrics = {
        "fixture.latency_ms": metric_skipped("missing local node", "ms"),
        "fixture.payload_bytes": metric_collected(1000, "bytes"),
        "fixture.skipped_ms": metric_skipped("optional check disabled", "ms"),
    }
    skipped_comparison = compare_to_baseline(skipped_metrics, baseline, fail_on_regression=True)
    assert skipped_comparison["status"] == "pass", skipped_comparison
    assert skipped_comparison["skipped"], skipped_comparison

    required_skipped_metrics = {
        "fixture.latency_ms": metric_collected(100, "ms"),
        "fixture.payload_bytes": metric_skipped("missing required asset", "bytes"),
        "fixture.skipped_ms": metric_skipped("optional check disabled", "ms"),
    }
    required_skipped_comparison = compare_to_baseline(
        required_skipped_metrics, baseline, fail_on_regression=True
    )
    assert required_skipped_comparison["status"] == "fail", required_skipped_comparison
    assert required_skipped_comparison["regressions"], required_skipped_comparison

    failed_probe_metrics = {
        "fixture.latency_ms": metric_failed("probe failed", "ms"),
        "fixture.payload_bytes": metric_collected(1000, "bytes"),
        "fixture.skipped_ms": metric_skipped("optional check disabled", "ms"),
    }
    failed_probe_comparison = compare_to_baseline(
        failed_probe_metrics, baseline, fail_on_regression=False
    )
    assert failed_probe_comparison["status"] == "fail", failed_probe_comparison
    launcher_failure_metrics: dict[str, dict[str, Any]] = {}
    mark_node_metrics_failed(launcher_failure_metrics, "Cryptad launcher not found")
    launcher_failure_baseline = {
        "version": BASELINE_SCHEMA_VERSION,
        "metrics": {
            "node.startup_to_process_spawn_ms": {"baseline": 100, "unit": "ms"},
            "fcp.client_hello_ms": {"baseline": 100, "unit": "ms"},
            "platform_api.node_ms": {"baseline": 100, "unit": "ms"},
        },
    }
    launcher_failure_comparison = compare_to_baseline(
        launcher_failure_metrics, launcher_failure_baseline, fail_on_regression=False
    )
    assert launcher_failure_comparison["status"] == "fail", launcher_failure_comparison
    assert launcher_failure_comparison["regressions"], launcher_failure_comparison
    readiness_timeout_metric = metric_readiness_timeout("readiness timeout", settings)
    assert readiness_timeout_metric["status"] == "failed"
    assert readiness_timeout_metric["value"] == settings.startup_timeout_seconds * 1000
    smoke_settings = Settings(
        workspace_root=settings.workspace_root,
        out_dir=settings.out_dir,
        baseline_path=fixture_baseline_path,
        cryptad_dist_dir=settings.cryptad_dist_dir,
        mode="smoke",
        skip_build=True,
        update_baseline=False,
        fail_on_regression=False,
        timeout_seconds=settings.timeout_seconds,
        startup_timeout_seconds=settings.startup_timeout_seconds,
        request_timeout_seconds=settings.request_timeout_seconds,
        fcp_port=settings.fcp_port,
        web_port=settings.web_port,
        fnp_port=settings.fnp_port,
    )
    assert (
        determine_status(smoke_settings, failed_probe_comparison, True, failed_probe_metrics)
        == "failure"
    )
    assert (
        determine_status(
            smoke_settings,
            launcher_failure_comparison,
            True,
            launcher_failure_metrics,
        )
        == "failure"
    )
    readiness_timeout_comparison = compare_to_baseline(
        {"fixture.latency_ms": readiness_timeout_metric},
        baseline,
        fail_on_regression=True,
    )
    assert readiness_timeout_comparison["status"] == "fail", readiness_timeout_comparison
    assert (
        determine_status(
            smoke_settings,
            readiness_timeout_comparison,
            True,
            {"fixture.latency_ms": readiness_timeout_metric},
        )
        == "failure"
    )
    assert probe_succeeded(metric_collected(1, "ms"))
    assert not probe_succeeded(metric_failed("HTTP 503 from readiness probe", "ms", value=10))
    assert cryptad_launcher_path(settings, "Windows").name == "cryptad.bat"
    assert cryptad_launcher_path(settings, "Linux").name == "cryptad"
    assert cryptad_launcher_path(settings, "Darwin").name == "cryptad"
    assert gradle_wrapper_path(settings, "Windows").name == "gradlew.bat"
    assert gradle_wrapper_path(settings, "Linux").name == "gradlew"
    assert gradle_wrapper_path(settings, "Darwin").name == "gradlew"

    defaults = settings_from_args(build_parser().parse_args(["--self-test"]), {})
    assert defaults.mode == "self-test"
    assert defaults.out_dir.name == DEFAULT_OUT_DIR.name
    parsed_env = settings_from_args(
        build_parser().parse_args([]),
        {"PERF_MODE": "collect", "PERF_OUT_DIR": "build/custom-perf", "PERF_SKIP_BUILD": "1"},
    )
    assert parsed_env.mode == "collect"
    assert parsed_env.skip_build
    assert parsed_env.out_dir.name == "custom-perf"

    redacted = redact_value(
        {
            "TOKEN": "token-value",
            "nested": {"formPassword": "hunter2"},
            "reason": "failed with formPassword=hunter2 and USK@private/abc",
            "safe": "visible",
        }
    )
    assert_no_secret(redacted)
    assert redacted["safe"] == "visible"

    leaky_log = layout.logs_dir / "leaky.log"
    leaky_log.write_text(
        f"{settings.workspace_root}/node.log token=token-value formPassword=hunter2 "
        "SplitfileCryptoKey=crypto-secret\n"
        "Authorization: Bearer bearer-secret\n"
        "Cookie: session=cookie-secret\n"
        "{\"token\":\"json-secret\"} Authorization=Bearer assign-bearer-secret",
        encoding="utf-8",
    )
    sanitize_artifact_logs(layout.logs_dir, settings)
    sanitized_log = leaky_log.read_text(encoding="utf-8")
    assert str(settings.workspace_root) not in sanitized_log
    assert_no_secret(sanitized_log)
    assert "SplitfileCryptoKey=<redacted>" in sanitized_log
    assert "Authorization: <redacted>" in sanitized_log
    assert "Cookie: <redacted>" in sanitized_log
    assert '"token":"<redacted>"' in sanitized_log
    assert "Authorization=<redacted>" in sanitized_log

    settings_failure_out = layout.work_dir / "settings-failure"
    settings_failure_out.mkdir(parents=True)
    stale_summary = {"status": "success", "mode": "smoke"}
    write_json(settings_failure_out / "summary.json", stale_summary)
    bad_env = {"PERF_MODE": "bogus", "PERF_OUT_DIR": str(settings_failure_out)}
    try:
        settings_from_args(build_parser().parse_args([]), bad_env)
    except PerfFailure as exc:
        fallback_settings = failure_settings_from_args(build_parser().parse_args([]), bad_env)
        write_failure_summary(fallback_settings, exc)
    else:
        raise AssertionError("invalid PERF_MODE was not rejected")
    failure_summary = json.loads((settings_failure_out / "summary.json").read_text(encoding="utf-8"))
    assert failure_summary["status"] == "failure", failure_summary
    assert failure_summary["comparison"]["regressions"], failure_summary

    finished_at = utc_now()
    duration_ms = monotonic_ms() - started_ms
    metrics = {
        "self_test.assertions": metric_collected(41, "count"),
        "fixture.latency_ms": metric_collected(100, "ms"),
        "fixture.payload_bytes": metric_collected(1000, "bytes"),
        "fixture.skipped_ms": metric_skipped("optional check disabled", "ms"),
    }
    comparison = compare_to_baseline(metrics, baseline, fail_on_regression=True)
    summary = make_summary(
        Settings(
            workspace_root=settings.workspace_root,
            out_dir=settings.out_dir,
            baseline_path=fixture_baseline_path,
            cryptad_dist_dir=settings.cryptad_dist_dir,
            mode="self-test",
            skip_build=True,
            update_baseline=False,
            fail_on_regression=True,
            timeout_seconds=settings.timeout_seconds,
            startup_timeout_seconds=settings.startup_timeout_seconds,
            request_timeout_seconds=settings.request_timeout_seconds,
            fcp_port=settings.fcp_port,
            web_port=settings.web_port,
            fnp_port=settings.fnp_port,
        ),
        environment_snapshot(),
        baseline,
        metrics,
        comparison,
        started_at,
        finished_at,
        duration_ms,
        "success",
    )
    for required_key in (
        "status",
        "mode",
        "started_at",
        "finished_at",
        "duration_ms",
        "environment",
        "baseline",
        "metrics",
        "comparison",
    ):
        assert required_key in summary, required_key
    report = generate_report(summary, comparison)
    assert "Performance smoke report" in report
    assert "fixture.latency_ms" in report
    write_json(layout.artifacts_dir / "raw-metrics.json", {"self_test": "passed", "metrics": metrics})
    write_json(layout.artifacts_dir / "baseline-comparison.json", comparison)
    write_text(layout.artifacts_dir / "perf-report.md", report)
    write_json(layout.out_dir / "summary.json", summary)
    return summary, 0


def write_failure_summary(settings: Settings, exc: BaseException) -> None:
    try:
        layout = preserve_layout(settings)
    except Exception:
        return
    sanitize_artifact_logs(layout.logs_dir, settings)
    now = utc_now()
    comparison = {
        "status": "fail",
        "regressions": [{"reason": str(exc)}],
        "warnings": [],
        "skipped": [],
        "not_compared": [],
    }
    summary = {
        "status": "failure",
        "mode": settings.mode,
        "started_at": now,
        "finished_at": now,
        "duration_ms": 0,
        "environment": environment_snapshot(),
        "baseline": {
            "path": display_path(settings.baseline_path, settings.workspace_root),
            "version": BASELINE_SCHEMA_VERSION,
        },
        "metrics": {},
        "comparison": comparison,
    }
    write_json(layout.artifacts_dir / "baseline-comparison.json", comparison)
    write_text(layout.artifacts_dir / "perf-report.md", generate_report(summary, comparison))
    write_json(layout.artifacts_dir / "raw-metrics.json", {"failure": str(exc)})
    write_json(layout.out_dir / "summary.json", summary)


def main(argv: list[str] | None = None) -> int:
    try:
        ensure_supported_python()
    except PerfFailure as exc:
        print(f"performance smoke failed: {exc}", file=sys.stderr)
        return 1
    parser = build_parser()
    args = parser.parse_args(argv)
    env = dict(os.environ)
    try:
        settings = settings_from_args(args, env)
        if args.self_test:
            _, exit_code = run_self_test(settings)
        else:
            _, exit_code = run_perf(settings)
        return exit_code
    except (AssertionError, PerfFailure, subprocess.TimeoutExpired, OSError) as exc:
        if "settings" not in locals():
            settings = failure_settings_from_args(args, env)
        write_failure_summary(settings, exc)
        print(f"performance smoke failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

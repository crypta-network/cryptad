#!/usr/bin/env python3
"""Hyphanet/Cryptad interoperability gate for CI and release validation."""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import io
import json
import os
import re
import select
import shutil
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from typing import BinaryIO, Iterable
from urllib.parse import urlparse
from urllib.request import urlretrieve


DEFAULT_CRYPTAD_FNP_PORT = 19401
DEFAULT_CRYPTAD_FCP_PORT = 19402
DEFAULT_HYPHANET_FNP_PORT = 19501
DEFAULT_HYPHANET_FCP_PORT = 19502
DEFAULT_INTEROP_MAX_HTL = 5
DEFAULT_PEER_TIMEOUT_SECONDS = 120
DEFAULT_REQUEST_TIMEOUT_SECONDS = 300
DEFAULT_STARTUP_TIMEOUT_SECONDS = 180
DEFAULT_SUITE_TIMEOUT_SECONDS = 900
DEFAULT_FETCH_ATTEMPT_TIMEOUT_SECONDS = 120
DEFAULT_SOAK_DURATION_SECONDS = 300
DEFAULT_SOAK_POLL_INTERVAL_SECONDS = 15
SMOKE_FLOW_NAMES = (
    "handshake",
    "peer_exchange",
    "chk_cross_fetch",
    "ssk_cross_fetch",
    "usk_smoke",
    "restart_recovery",
)
EXTENDED_FLOW_NAMES = (
    "usk_subscribe_soak",
    "persistent_request_replay",
)
OPTIONAL_FLOW_NAMES = ("opennet_optional",)
FLOW_NAMES = SMOKE_FLOW_NAMES + EXTENDED_FLOW_NAMES + OPTIONAL_FLOW_NAMES
SENSITIVE_FIELDS = {
    "InsertURI",
    "PrivateURI",
    "SplitfileCryptoKey",
    "OverrideSplitfileCryptoKey",
}
SENSITIVE_FIELD_KEY_NORMALS = {
    "inserturi",
    "privateuri",
    "splitfilecryptokey",
    "overridesplitfilecryptokey",
}
SENSITIVE_TEXT_KEY_NORMALS = {
    "error",
    "failurereason",
    "reason",
}
POTENTIALLY_PRIVATE_URI_PREFIXES = ("SSK@", "USK@")
HYPHANET_VERSIONED_JAR_RE = re.compile(
    r"^(?P<base>.+)-"
    r"(?P<version>\d+(?:\.\d+)+[0-9A-Za-z._-]*)"
    r"\+(?P<build>[0-9A-Za-z._-]+)\.jar$"
)
POTENTIALLY_PRIVATE_URI_TEXT_RE = re.compile(r"\b(?:SSK|USK)@[^\s'\"<>()\[\]{}]+")
FLOW_STARTS: dict[str, float] = {}


class InteropFailure(RuntimeError):
    """Raised when a smoke-flow invariant fails."""


@dataclass
class FcpFrame:
    name: str
    fields: dict[str, str]
    payload: bytes | None = None


@dataclass
class Ports:
    cryptad_fnp: int
    cryptad_fcp: int
    hyphanet_fnp: int
    hyphanet_fcp: int


@dataclass
class Layout:
    out_dir: Path
    downloads_dir: Path
    cryptad_dir: Path
    hyphanet_dir: Path
    logs_dir: Path
    transcripts_dir: Path
    artifacts_dir: Path


@dataclass
class Baseline:
    version: str
    asset_path: Path
    kind: str
    extract_root: Path | None = None


@dataclass
class NodeRuntime:
    name: str
    base_dir: Path
    config_file: Path
    stdout_path: Path
    stderr_path: Path
    process: subprocess.Popen[bytes]
    stdout_handle: BinaryIO
    stderr_handle: BinaryIO


def env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw, 10)
    except ValueError as exc:
        raise InteropFailure(f"{name} must be an integer, got {raw!r}") from exc


def env_flag_or_none(name: str) -> bool | None:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return None
    return raw.lower() in {"1", "true", "yes", "on"}


def sha256sum(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ensure_clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_json(path: Path, value: object, *, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if mode is not None:
        path.chmod(mode)


def relative_artifact(layout: Layout, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(layout.out_dir.resolve()))
    except ValueError:
        return str(path)


def add_artifact(summary: dict[str, object], layout: Layout, path: Path) -> None:
    artifacts = summary.setdefault("artifacts", [])
    if isinstance(artifacts, list):
        rel = relative_artifact(layout, path)
        if rel not in artifacts:
            artifacts.append(rel)


def record_json_artifact(
    summary: dict[str, object], layout: Layout, relative_path: str, value: object
) -> Path:
    path = layout.artifacts_dir / relative_path
    write_json(path, redacted_summary_value(value))
    add_artifact(summary, layout, path)
    return path


def record_text_artifact(
    summary: dict[str, object], layout: Layout, relative_path: str, value: str
) -> Path:
    path = layout.artifacts_dir / relative_path
    write_text(path, value)
    add_artifact(summary, layout, path)
    return path


def format_field_set(fields: dict[str, str]) -> str:
    body = "".join(f"{key}={value}\n" for key, value in fields.items())
    return body + "End\n"


def normalized_summary_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def is_sensitive_summary_field(key: str) -> bool:
    normalized = normalized_summary_key(key)
    return (
        normalized in SENSITIVE_FIELD_KEY_NORMALS
        or normalized.endswith("inserturi")
        or normalized.endswith("privateuri")
        or normalized.endswith("splitfilecryptokey")
    )


def redacted_value(key: str, value: str) -> str:
    if key in SENSITIVE_FIELDS or is_sensitive_summary_field(key):
        return "<redacted>"
    if key == "URI" and value.startswith(POTENTIALLY_PRIVATE_URI_PREFIXES):
        return "<redacted-uri>"
    return value


def redacted_fields(fields: dict[str, str]) -> dict[str, str]:
    return {key: redacted_value(key, value) for key, value in fields.items()}


def redacted_summary_value(value: object, parent_key: str = "") -> object:
    if isinstance(value, dict):
        return {key: redacted_summary_value(item, key) for key, item in value.items()}
    if isinstance(value, list):
        return [redacted_summary_value(item, parent_key) for item in value]
    if isinstance(value, str):
        redacted = redacted_value(parent_key, value)
        if redacted != value:
            return redacted
        if normalized_summary_key(parent_key) in SENSITIVE_TEXT_KEY_NORMALS:
            return redacted_report_text(value)
        return value
    return value


def redacted_report_text(value: object) -> str:
    text = str(value)
    for field in SENSITIVE_FIELDS:
        field_re = re.compile(
            rf"(?P<prefix>['\"]?{re.escape(field)}['\"]?\s*[:=]\s*['\"]?)"
            r"(?P<value>[^'\"\s}]+)"
        )
        text = field_re.sub(lambda match: match.group("prefix") + "<redacted>", text)
    return POTENTIALLY_PRIVATE_URI_TEXT_RE.sub("<redacted-uri>", text)


def fcp_bool(value: bool) -> str:
    return "true" if value else "false"


def payload_transcript(payload: bytes | None) -> str:
    if payload is None:
        return ""
    encoded = base64.b64encode(payload).decode("ascii")
    return f"PayloadLength={len(payload)}\nPayloadBase64={encoded}\n"


def read_exact(file: BinaryIO, length: int) -> bytes:
    remaining = length
    chunks: list[bytes] = []
    while remaining > 0:
        chunk = file.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_fcp_frame_from_file(file: BinaryIO) -> FcpFrame:
    name_bytes = file.readline()
    if not name_bytes:
        raise EOFError("FCP connection closed")
    name = name_bytes.decode("utf-8").rstrip("\n")
    fields: dict[str, str] = {}

    while True:
        line_bytes = file.readline()
        if not line_bytes:
            raise EOFError(f"FCP connection closed while reading {name}")
        line = line_bytes.decode("utf-8").rstrip("\n")
        if line == "EndMessage":
            return FcpFrame(name, fields, None)
        if line == "Data":
            if "DataLength" not in fields:
                raise InteropFailure(f"{name} used Data without DataLength")
            length = int(fields["DataLength"])
            payload = read_exact(file, length)
            if len(payload) != length:
                raise EOFError(
                    f"FCP connection closed while reading {name} payload "
                    f"({len(payload)}/{length} bytes)"
                )
            return FcpFrame(name, fields, payload)
        if "=" not in line:
            raise InteropFailure(f"{name} contained malformed FCP line {line!r}")
        key, value = line.split("=", 1)
        fields[key] = value


def encode_fcp_frame(name: str, fields: dict[str, str], payload: bytes | None = None) -> bytes:
    marker = "Data" if payload is not None else "EndMessage"
    lines = [name, *(f"{key}={value}" for key, value in fields.items()), marker]
    header = ("\n".join(lines) + "\n").encode("utf-8")
    if payload is None:
        return header
    return header + payload


class FcpClient:
    def __init__(self, host: str, port: int, name: str, transcript_path: Path):
        self.host = host
        self.port = port
        self.name = name
        self.transcript_path = transcript_path
        sock = socket.create_connection((host, port), timeout=10)
        try:
            file = sock.makefile("rwb", buffering=0)
        except Exception:
            sock.close()
            raise
        self.sock = sock
        self.file = file
        self.hello: FcpFrame | None = None
        try:
            self._log_text(f"CONNECT {host}:{port}\n")
            self.send("ClientHello", {"Name": name, "ExpectedVersion": "2.0"})
            hello = self.read_message(timeout=30)
            if hello.name != "NodeHello":
                raise InteropFailure(f"{name} expected NodeHello, got {hello.name}")
            self.hello = hello
        except Exception:
            try:
                file.close()
            finally:
                sock.close()
            raise

    def close(self) -> None:
        try:
            self.file.close()
        finally:
            self.sock.close()

    def send(self, name: str, fields: dict[str, object], payload: bytes | None = None) -> None:
        normalized = {key: str(value) for key, value in fields.items()}
        self.file.write(encode_fcp_frame(name, normalized, payload))
        self._log_message("SEND", FcpFrame(name, normalized, payload))

    def read_message(self, timeout: float) -> FcpFrame:
        self.sock.settimeout(timeout)
        frame = read_fcp_frame_from_file(self.file)
        self._log_message("RECV", frame)
        return frame

    def wait_readable(self, timeout: float) -> bool:
        readable, _, _ = select.select([self.sock], [], [], timeout)
        return bool(readable)

    def read_until(
        self,
        timeout: float,
        target_names: Iterable[str],
        error_names: Iterable[str] = ("ProtocolError",),
    ) -> FcpFrame:
        wanted = set(target_names)
        errors = set(error_names)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"{self.name} timed out waiting for {sorted(wanted)}")
            frame = self.read_message(min(remaining, timeout))
            if frame.name in errors:
                raise InteropFailure(f"{self.name} received {frame.name}: {frame.fields}")
            if frame.name in wanted:
                return frame

    def read_until_after_send(
        self,
        name: str,
        fields: dict[str, object],
        target_names: Iterable[str],
        payload: bytes | None = None,
    ) -> FcpFrame:
        self.send(name, fields, payload)
        return self.read_until(DEFAULT_REQUEST_TIMEOUT_SECONDS, target_names)

    def _log_text(self, text: str) -> None:
        self.transcript_path.parent.mkdir(parents=True, exist_ok=True)
        with self.transcript_path.open("a", encoding="utf-8") as handle:
            handle.write(text)

    def _log_message(self, direction: str, frame: FcpFrame) -> None:
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        fields = redacted_fields(frame.fields)
        body = "".join(f"{key}={value}\n" for key, value in fields.items())
        if frame.payload is None:
            marker = "EndMessage\n"
        else:
            marker = "Data\n" + payload_transcript(frame.payload)
        self._log_text(f"[{timestamp}] {direction} {frame.name}\n{body}{marker}\n")


def ensure_udp_port_available(port: int) -> None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind(("127.0.0.1", port))
    except OSError as exc:
        raise InteropFailure(f"UDP port 127.0.0.1:{port} is already in use") from exc
    finally:
        probe.close()


def ensure_tcp_port_available(port: int) -> None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        probe.bind(("127.0.0.1", port))
    except OSError as exc:
        raise InteropFailure(f"TCP port 127.0.0.1:{port} is already in use") from exc
    finally:
        probe.close()


def ensure_distinct_node_ports(ports: Ports) -> None:
    duplicate_bindings: list[str] = []
    if ports.cryptad_fnp == ports.hyphanet_fnp:
        duplicate_bindings.append(f"FNP UDP {ports.cryptad_fnp}")
    if ports.cryptad_fcp == ports.hyphanet_fcp:
        duplicate_bindings.append(f"FCP TCP {ports.cryptad_fcp}")
    if duplicate_bindings:
        raise InteropFailure(
            "Cryptad and Hyphanet must use distinct node ports: "
            + ", ".join(duplicate_bindings)
        )


def ensure_ports_available(ports: Ports) -> None:
    ensure_distinct_node_ports(ports)
    ensure_udp_port_available(ports.cryptad_fnp)
    ensure_tcp_port_available(ports.cryptad_fcp)
    ensure_udp_port_available(ports.hyphanet_fnp)
    ensure_tcp_port_available(ports.hyphanet_fcp)


def wait_for_fcp(
    host: str,
    port: int,
    timeout_seconds: int,
    watched_nodes: Iterable[NodeRuntime],
) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        for node in watched_nodes:
            exit_code = node.process.poll()
            if exit_code is not None:
                raise InteropFailure(
                    f"{node.name} exited before FCP {host}:{port} became ready "
                    f"(exit={exit_code}); see {node.stderr_path}"
                )
        try:
            with socket.create_connection((host, port), timeout=1):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(1)
    raise TimeoutError(f"Timed out waiting for FCP {host}:{port}: {last_error}")


def resolve_dist_path(dist_root: Path, entry: str) -> Path:
    normalized = entry.replace("\\", "/")
    if normalized.endswith("/*"):
        normalized = normalized[:-2]
    if normalized.startswith("/"):
        return dist_root / normalized.lstrip("/")
    return dist_root / normalized


def parse_wrapper_conf(conf_path: Path, dist_root: Path) -> tuple[str, list[str], list[str]]:
    additional: dict[int, str] = {}
    classpath: dict[int, str] = {}
    main_class: str | None = None

    for raw_line in conf_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.startswith("wrapper.java.additional."):
            additional[int(key.rsplit(".", 1)[1])] = value
        elif key.startswith("wrapper.java.classpath."):
            classpath[int(key.rsplit(".", 1)[1])] = value
        elif key == "wrapper.java.mainclass":
            main_class = value

    if main_class is None:
        raise InteropFailure(f"wrapper.java.mainclass missing in {conf_path}")

    classpath_entries: list[str] = []
    for _, entry in sorted(classpath.items()):
        resolved_base = resolve_dist_path(dist_root, entry)
        if entry.endswith("*"):
            classpath_entries.extend(str(path) for path in sorted(resolved_base.glob("*.jar")))
        else:
            classpath_entries.append(str(resolved_base))

    if not classpath_entries:
        raise InteropFailure(f"No classpath entries resolved from {conf_path}")

    additional_args = [value for _, value in sorted(additional.items())]
    return main_class, additional_args, classpath_entries


def make_cryptad_config(base_dir: Path, ports: Ports, *, enable_opennet: bool = False) -> Path:
    for path in (
        base_dir / "config",
        base_dir / "data" / "node",
        base_dir / "data" / "user",
        base_dir / "data" / "store",
        base_dir / "cache" / "tmp",
        base_dir / "cache" / "persistent-temp",
        base_dir / "run",
        base_dir / "logs",
    ):
        path.mkdir(parents=True, exist_ok=True)
    config_file = base_dir / "config" / "cryptad.ini"
    write_text(
        config_file,
        f"""node.install.cfgDir={base_dir / 'config'}
node.install.nodeDir={base_dir / 'data' / 'node'}
node.install.userDir={base_dir / 'data' / 'user'}
node.install.runDir={base_dir / 'run'}
node.install.storeDir={base_dir / 'data' / 'store'}
node.install.tempDir={base_dir / 'cache' / 'tmp'}
node.install.persistentTempDir={base_dir / 'cache' / 'persistent-temp'}
node.downloadsDir={base_dir / 'data' / 'downloads'}
logger.dirname={base_dir / 'logs'}
logger.priority=NORMAL
node.updater.enabled=false
node.updater.autoupdate=false
node.updater.updateInstallers=false
node.opennet.enabled={fcp_bool(enable_opennet)}
node.ipAddressOverride=127.0.0.1
node.allowBindToLocalhost=true
node.bindTo=127.0.0.1
node.listenPort={ports.cryptad_fnp}
node.maxHTL={DEFAULT_INTEROP_MAX_HTL}
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
fcp.port={ports.cryptad_fcp}
fcp.bindTo=127.0.0.1
fcp.allowedHosts=127.0.0.1
fcp.allowedHostsFullAccess=127.0.0.1
fcp.ssl=false
fproxy.enabled=false
console.enabled=false
End
""",
    )
    return config_file


def make_hyphanet_config(base_dir: Path, ports: Ports, *, enable_opennet: bool = False) -> Path:
    for path in (
        base_dir / "work" / "etc" / "freenet" / "noderef",
        base_dir / "work" / "var" / "lib" / "freenet" / "state",
        base_dir / "work" / "var" / "lib" / "freenet" / "store",
        base_dir / "work" / "var" / "lib" / "freenet" / "plugins",
        base_dir / "work" / "var" / "lib" / "freenet" / "complete",
        base_dir / "work" / "var" / "run" / "freenet",
        base_dir / "work" / "var" / "log" / "freenet",
        base_dir / "work" / "tmp",
    ):
        path.mkdir(parents=True, exist_ok=True)
    config_dir = base_dir / "work" / "etc" / "freenet"
    config_file = config_dir / "freenet.ini"
    write_text(
        config_file,
        f"""node.install.nodeDir={config_dir / 'noderef'}
node.install.cfgDir={config_dir}
node.install.userDir={base_dir / 'work' / 'var' / 'lib' / 'freenet' / 'state'}
node.install.runDir={base_dir / 'work' / 'var' / 'run' / 'freenet'}
node.install.storeDir={base_dir / 'work' / 'var' / 'lib' / 'freenet' / 'store'}
node.install.pluginDir={base_dir / 'work' / 'var' / 'lib' / 'freenet' / 'plugins'}
node.install.tempDir={base_dir / 'work' / 'tmp'}
node.downloadsDir={base_dir / 'work' / 'var' / 'lib' / 'freenet' / 'complete'}
logger.dirname={base_dir / 'work' / 'var' / 'log' / 'freenet'}
logger.priority=NORMAL
node.updater.enabled=false
node.updater.autoupdate=false
node.updater.updateInstallers=false
node.opennet.enabled={fcp_bool(enable_opennet)}
node.ipAddressOverride=127.0.0.1
node.allowBindToLocalhost=true
node.bindTo=127.0.0.1
node.listenPort={ports.hyphanet_fnp}
node.maxHTL={DEFAULT_INTEROP_MAX_HTL}
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
fcp.port={ports.hyphanet_fcp}
fcp.bindTo=127.0.0.1
fcp.allowedHosts=127.0.0.1
fcp.allowedHostsFullAccess=127.0.0.1
fcp.ssl=false
fproxy.enabled=false
console.enabled=false
End
""",
    )
    return config_file


def baseline_version() -> str:
    return (
        os.environ.get("HYPHANET_BASELINE_VERSION")
        or os.environ.get("HYPHANET_BUILD")
        or os.environ.get("HYPHANET_VERSION")
        or ""
    )


def reserve_download_temp_path(asset_path: Path) -> Path:
    with NamedTemporaryFile(
        dir=asset_path.parent,
        prefix=asset_path.name + ".",
        suffix=".download",
        delete=False,
    ) as temp_asset:
        return Path(temp_asset.name)


def verified_download(url: str, expected_sha256: str, cache_dir: Path) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    parsed_name = Path(urlparse(url).path).name
    if not parsed_name:
        raise InteropFailure(f"Cannot determine baseline asset name from URL: {url}")
    asset_path = cache_dir / parsed_name

    def download_asset() -> None:
        temp_asset_path = reserve_download_temp_path(asset_path)
        try:
            urlretrieve(url, temp_asset_path)
            downloaded_sha256 = sha256sum(temp_asset_path)
            if downloaded_sha256 != expected_sha256:
                raise InteropFailure(
                    f"Hyphanet baseline checksum mismatch for {url}: "
                    f"expected {expected_sha256}, got {downloaded_sha256}"
                )
            temp_asset_path.replace(asset_path)
        except Exception:
            temp_asset_path.unlink(missing_ok=True)
            raise

    if asset_path.exists():
        actual_sha256 = sha256sum(asset_path)
        if actual_sha256 != expected_sha256:
            asset_path.unlink(missing_ok=True)
            download_asset()
    else:
        download_asset()
    return asset_path


def materialize_hyphanet_java_symlinks(extract_root: Path) -> None:
    java_dir = extract_root / "usr" / "share" / "java"
    if not java_dir.is_dir():
        return

    for jar_path in java_dir.glob("*.jar"):
        match = HYPHANET_VERSIONED_JAR_RE.match(jar_path.name)
        if match is None:
            continue
        target_name = match.group("base") + ".jar"
        target_path = java_dir / target_name
        if not target_path.exists():
            target_path.symlink_to(jar_path.name)


def prepare_hyphanet_baseline(layout: Layout, cache_dir: Path) -> Baseline:
    jar_override = os.environ.get("HYPHANET_BASELINE_JAR")
    version = baseline_version()
    if jar_override:
        jar_path = Path(jar_override).expanduser().resolve()
        if not jar_path.is_file():
            raise InteropFailure(f"HYPHANET_BASELINE_JAR does not exist: {jar_path}")
        return Baseline(version=version, asset_path=jar_path, kind="jar")

    url = os.environ.get("HYPHANET_BASELINE_URL") or os.environ.get("HYPHANET_RELEASE_URL")
    expected_sha256 = os.environ.get("HYPHANET_BASELINE_SHA256") or os.environ.get(
        "HYPHANET_DEB_SHA256"
    )
    if not url or not expected_sha256:
        raise InteropFailure(
            "Hyphanet baseline is not configured. Set HYPHANET_BASELINE_JAR to a local "
            "baseline jar, or set both HYPHANET_BASELINE_URL and HYPHANET_BASELINE_SHA256. "
            "The harness never downloads an unverified remote jar or package."
        )

    asset_path = verified_download(url, expected_sha256, cache_dir)
    if asset_path.suffix == ".jar":
        return Baseline(version=version, asset_path=asset_path, kind="jar")
    if asset_path.suffix == ".deb":
        if shutil.which("dpkg-deb") is None:
            raise InteropFailure("dpkg-deb is required to extract a Hyphanet .deb baseline")
        extract_root = layout.downloads_dir / "hyphanet-root"
        if extract_root.exists():
            shutil.rmtree(extract_root)
        subprocess.run(["dpkg-deb", "-x", str(asset_path), str(extract_root)], check=True)
        materialize_hyphanet_java_symlinks(extract_root)
        return Baseline(version=version, asset_path=asset_path, kind="deb", extract_root=extract_root)
    raise InteropFailure(
        f"Unsupported Hyphanet baseline asset {asset_path}. Use a .jar path or a verified .deb URL."
    )


def launch_cryptad(
    cryptad_dist_dir: Path,
    node_dir: Path,
    layout: Layout,
    ports: Ports,
    label: str = "cryptad",
    *,
    enable_opennet: bool = False,
) -> NodeRuntime:
    config_file = make_cryptad_config(node_dir, ports, enable_opennet=enable_opennet)
    launcher = cryptad_dist_dir / "bin" / "cryptad"
    if not launcher.is_file():
        raise InteropFailure(f"Cryptad launcher not found: {launcher}")
    if not os.access(launcher, os.X_OK):
        raise InteropFailure(f"Cryptad launcher is not executable: {launcher}")

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
    stdout_path = layout.logs_dir / f"{label}.stdout.log"
    stderr_path = layout.logs_dir / f"{label}.stderr.log"
    stdout_handle = stdout_path.open("wb")
    stderr_handle = stderr_path.open("wb")
    environment = os.environ.copy()
    if os.geteuid() == 0:
        environment["CRYPTAD_ALLOW_ROOT"] = "1"
    process = subprocess.Popen(
        command,
        cwd=node_dir,
        stdout=stdout_handle,
        stderr=stderr_handle,
        env=environment,
        start_new_session=True,
    )
    return NodeRuntime(label, node_dir, config_file, stdout_path, stderr_path, process, stdout_handle, stderr_handle)


def hyphanet_command_from_deb(baseline: Baseline, config_file: Path) -> list[str]:
    if baseline.extract_root is None:
        raise InteropFailure("Internal error: deb baseline missing extract_root")
    wrapper_conf = baseline.extract_root / "usr" / "share" / "freenet" / "wrapper.conf"
    main_class, wrapper_jvm_args, classpath_entries = parse_wrapper_conf(
        wrapper_conf, baseline.extract_root
    )
    return [
        "java",
        "--enable-native-access=ALL-UNNAMED",
        *wrapper_jvm_args,
        "-cp",
        os.pathsep.join(classpath_entries),
        main_class,
        str(config_file),
    ]


def hyphanet_command_from_jar(baseline: Baseline, config_file: Path) -> list[str]:
    java_bin = os.environ.get("HYPHANET_BASELINE_JAVA", "java")
    extra_args = os.environ.get("HYPHANET_BASELINE_JAVA_ARGS", "").split()
    classpath = os.environ.get("HYPHANET_BASELINE_CLASSPATH")
    main_class = os.environ.get("HYPHANET_BASELINE_MAIN_CLASS")
    if classpath or main_class:
        cp_entries = [str(baseline.asset_path)]
        if classpath:
            cp_entries.append(classpath)
        return [
            java_bin,
            "--enable-native-access=ALL-UNNAMED",
            *extra_args,
            "-cp",
            os.pathsep.join(cp_entries),
            main_class or "freenet.node.NodeStarter",
            str(config_file),
        ]
    return [
        java_bin,
        "--enable-native-access=ALL-UNNAMED",
        *extra_args,
        "-jar",
        str(baseline.asset_path),
        str(config_file),
    ]


def launch_hyphanet(
    baseline: Baseline,
    node_dir: Path,
    layout: Layout,
    ports: Ports,
    label: str = "hyphanet",
    *,
    enable_opennet: bool = False,
) -> NodeRuntime:
    config_file = make_hyphanet_config(node_dir, ports, enable_opennet=enable_opennet)
    if baseline.kind == "deb":
        if baseline.extract_root is None:
            raise InteropFailure("Internal error: deb baseline missing extract_root")
        seedsrc = baseline.extract_root / "usr" / "share" / "freenet" / "seednodes.fref"
        seeddst = config_file.parent / "noderef" / "seednodes.fref"
        if seedsrc.is_file():
            seeddst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(seedsrc, seeddst)
        command = hyphanet_command_from_deb(baseline, config_file)
    else:
        command = hyphanet_command_from_jar(baseline, config_file)

    runtime_work_dir = node_dir / "work" / "var" / "lib" / "freenet"
    runtime_work_dir.mkdir(parents=True, exist_ok=True)
    (runtime_work_dir / "tmp").mkdir(parents=True, exist_ok=True)
    stdout_path = layout.logs_dir / f"{label}.stdout.log"
    stderr_path = layout.logs_dir / f"{label}.stderr.log"
    stdout_handle = stdout_path.open("wb")
    stderr_handle = stderr_path.open("wb")
    process = subprocess.Popen(
        command,
        cwd=runtime_work_dir,
        stdout=stdout_handle,
        stderr=stderr_handle,
        start_new_session=True,
    )
    return NodeRuntime(label, node_dir, config_file, stdout_path, stderr_path, process, stdout_handle, stderr_handle)


def terminate_node(node: NodeRuntime, timeout_seconds: int = 20) -> int | None:
    process = node.process
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=timeout_seconds)
    try:
        node.stdout_handle.close()
    finally:
        node.stderr_handle.close()
    return process.poll()


def get_node_reference(client: FcpClient, identifier: str) -> dict[str, str]:
    client.send(
        "GetNode",
        {
            "Identifier": identifier,
            "GiveOpennetRef": "false",
            "WithPrivate": "false",
            "WithVolatile": "false",
        },
    )
    frame = client.read_until(DEFAULT_REQUEST_TIMEOUT_SECONDS, {"NodeData"})
    return dict(frame.fields)


def add_peer(client: FcpClient, identifier: str, reference_fields: dict[str, str]) -> dict[str, str]:
    add_fields = dict(reference_fields)
    add_fields["Identifier"] = identifier
    add_fields["Trust"] = "NORMAL"
    add_fields["Visibility"] = "YES"
    frame = client.read_until_after_send("AddPeer", add_fields, {"Peer"})
    return dict(frame.fields)


def remove_peer(client: FcpClient, identifier: str, node_identifier: str) -> dict[str, str]:
    client.send("RemovePeer", {"Identifier": identifier, "NodeIdentifier": node_identifier})
    frame = client.read_until(DEFAULT_REQUEST_TIMEOUT_SECONDS, {"PeerRemoved", "UnknownNodeIdentifier"})
    if frame.name == "UnknownNodeIdentifier":
        raise InteropFailure(f"{client.name} could not remove unknown peer {node_identifier}")
    return dict(frame.fields)


def modify_peer(
    client: FcpClient, identifier: str, node_identifier: str, fields: dict[str, object]
) -> dict[str, str]:
    update_fields = {"Identifier": identifier, "NodeIdentifier": node_identifier}
    update_fields.update(fields)
    client.send("ModifyPeer", update_fields)
    frame = client.read_until(DEFAULT_REQUEST_TIMEOUT_SECONDS, {"Peer", "UnknownNodeIdentifier"})
    if frame.name == "UnknownNodeIdentifier":
        raise InteropFailure(f"{client.name} could not modify unknown peer {node_identifier}")
    return dict(frame.fields)


def list_peers(client: FcpClient, identifier: str) -> list[dict[str, str]]:
    client.send(
        "ListPeers",
        {"Identifier": identifier, "WithMetadata": "true", "WithVolatile": "true"},
    )
    peers: list[dict[str, str]] = []
    while True:
        frame = client.read_message(DEFAULT_REQUEST_TIMEOUT_SECONDS)
        if frame.name == "EndListPeers":
            return peers
        if frame.name == "ProtocolError":
            raise InteropFailure(f"{client.name} received ProtocolError during ListPeers: {frame.fields}")
        if frame.name == "Peer":
            peers.append(dict(frame.fields))


def peer_status(peer: dict[str, str]) -> str:
    return peer.get("volatile.status") or peer.get("status") or peer.get("Status") or ""


def find_peer_by_identity(peers: list[dict[str, str]], identity: str) -> dict[str, str] | None:
    for peer in peers:
        if peer.get("identity") == identity or peer.get("Identity") == identity:
            return peer
    return None


def wait_for_peer_absent(
    client: FcpClient,
    identity: str,
    timeout_seconds: int,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        peers = list_peers(client, "wait-peer-absent")
        if find_peer_by_identity(peers, identity) is None:
            return
        time.sleep(1)
    raise InteropFailure(f"Peer {identity} was still listed after removal")


def wait_for_peer_connection(
    cryptad_client: FcpClient,
    hyphanet_client: FcpClient,
    cryptad_identity: str,
    hyphanet_identity: str,
    timeout_seconds: int,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    deadline = time.monotonic() + timeout_seconds
    last_status = "no peer lists yet"
    while time.monotonic() < deadline:
        cryptad_peers = list_peers(cryptad_client, "cryptad-list")
        hyphanet_peers = list_peers(hyphanet_client, "hyphanet-list")
        cryptad_peer = find_peer_by_identity(cryptad_peers, hyphanet_identity)
        hyphanet_peer = find_peer_by_identity(hyphanet_peers, cryptad_identity)
        cryptad_status = peer_status(cryptad_peer or {})
        hyphanet_status = peer_status(hyphanet_peer or {})
        last_status = f"cryptad={cryptad_status or '<missing>'}, hyphanet={hyphanet_status or '<missing>'}"
        if cryptad_peer and hyphanet_peer:
            if cryptad_status == "CONNECTED" and hyphanet_status == "CONNECTED":
                return cryptad_peers, hyphanet_peers
        time.sleep(2)
    raise InteropFailure(f"Darknet peers did not reach CONNECTED on both nodes: {last_status}")


def ensure_content_peers_connected(
    cryptad_client: FcpClient,
    hyphanet_client: FcpClient,
    cryptad_reference: dict[str, str],
    hyphanet_reference: dict[str, str],
    timeout_seconds: int,
    label: str,
) -> None:
    log_progress(f"Ensuring peers are connected for {label}...")
    wait_for_peer_connection(
        cryptad_client,
        hyphanet_client,
        str(cryptad_reference["identity"]),
        str(hyphanet_reference["identity"]),
        timeout_seconds,
    )


def build_client_put_fields(
    identifier: str,
    uri: str,
    payload: bytes,
    content_type: str | None,
    *,
    local_request_only: bool,
) -> dict[str, object]:
    fields: dict[str, object] = {
        "Identifier": identifier,
        "URI": uri,
        "UploadFrom": "direct",
        "DataLength": len(payload),
        "Persistence": "connection",
        "Verbosity": "256",
        "ConsecutiveRNFsCountAsSuccess": "0",
        "DontCompress": "true",
        "ExtraInsertsSingleBlock": "0",
        "ExtraInsertsSplitfileHeaderBlock": "0",
        "MaxRetries": "3",
        "RealTimeFlag": "true",
        "IgnoreUSKDatehints": "true",
    }
    if content_type is not None:
        fields["Metadata.ContentType"] = content_type
    if local_request_only:
        fields["LocalRequestOnly"] = "true"
    return fields


def build_client_get_fields(
    identifier: str, uri: str, *, ignore_ds: bool = False
) -> dict[str, object]:
    fields: dict[str, object] = {
        "Identifier": identifier,
        "URI": uri,
        "ReturnType": "direct",
        "Persistence": "connection",
        "Verbosity": "256",
        "MaxRetries": "3",
        "MaxSize": "1048576",
        "IgnoreUSKDatehints": "true",
    }
    if ignore_ds:
        fields["IgnoreDS"] = "true"
    return fields


def put_and_wait_for_success(
    client: FcpClient,
    identifier: str,
    uri: str,
    payload: bytes,
    content_type: str | None,
    *,
    local_request_only: bool = False,
    uri_fallback: str | None = None,
) -> str:
    client.send(
        "ClientPut",
        build_client_put_fields(
            identifier,
            uri,
            payload,
            content_type,
            local_request_only=local_request_only,
        ),
        payload=payload,
    )

    generated_uri = uri_fallback
    while True:
        frame = client.read_message(DEFAULT_REQUEST_TIMEOUT_SECONDS)
        if frame.name in {"URIGenerated", "PutFetchable", "PutSuccessful"}:
            uri_value = frame.fields.get("URI")
            if uri_value:
                generated_uri = uri_value
        if frame.name == "PutSuccessful":
            if generated_uri is None:
                raise InteropFailure(f"{client.name} PutSuccessful did not include a URI: {frame.fields}")
            return generated_uri
        if frame.name in {"PutFailed", "ProtocolError"}:
            raise InteropFailure(f"{client.name} put failed with {frame.name}: {frame.fields}")


def fetch_direct(
    client: FcpClient,
    identifier: str,
    uri: str,
    timeout_seconds: int | None = None,
    *,
    ignore_ds: bool = False,
) -> bytes:
    read_timeout = timeout_seconds or DEFAULT_REQUEST_TIMEOUT_SECONDS
    client.send("ClientGet", build_client_get_fields(identifier, uri, ignore_ds=ignore_ds))
    while True:
        frame = client.read_message(read_timeout)
        if frame.name == "AllData":
            if frame.payload is None:
                raise InteropFailure(f"{client.name} AllData payload missing")
            return frame.payload
        if frame.name in {"GetFailed", "ProtocolError"}:
            raise InteropFailure(f"{client.name} fetch failed with {frame.name}: {frame.fields}")


def fetch_direct_until_available(
    host: str,
    port: int,
    client_name: str,
    transcript_path: Path,
    identifier_prefix: str,
    uri: str,
    timeout_seconds: int,
    *,
    ignore_ds: bool = False,
) -> bytes:
    deadline = time.monotonic() + timeout_seconds
    attempt_timeout = min(
        DEFAULT_FETCH_ATTEMPT_TIMEOUT_SECONDS,
        DEFAULT_REQUEST_TIMEOUT_SECONDS,
        max(30, timeout_seconds),
    )
    attempt = 0
    last_error: str | None = None
    while time.monotonic() < deadline:
        attempt += 1
        client: FcpClient | None = None
        try:
            client = FcpClient(host, port, f"{client_name}-{attempt}", transcript_path)
            return fetch_direct(
                client,
                f"{identifier_prefix}-{attempt}",
                uri,
                attempt_timeout,
                ignore_ds=ignore_ds,
            )
        except (OSError, EOFError, InteropFailure, TimeoutError, socket.timeout) as exc:
            last_error = str(exc)
            time.sleep(2)
        finally:
            if client is not None:
                client.close()
    raise InteropFailure(f"Timed out waiting for {uri} to become fetchable; last error: {last_error}")


def generate_ssk(client: FcpClient, identifier: str) -> tuple[str, str]:
    client.send("GenerateSSK", {"Identifier": identifier})
    frame = client.read_until(DEFAULT_REQUEST_TIMEOUT_SECONDS, {"SSKKeypair"})
    return frame.fields["InsertURI"], frame.fields["RequestURI"]


def ssk_with_name(uri: str, name: str) -> str:
    return f"{uri.split('/', 1)[0]}/{name}"


def usk_from_ssk(uri: str, site_name: str, edition: int) -> str:
    key_part = uri.split("/", 1)[0]
    if not key_part.startswith("SSK@"):
        raise InteropFailure(f"Cannot derive USK from non-SSK URI: {uri}")
    return f"USK@{key_part.removeprefix('SSK@')}/{site_name}/{edition}"


def ssk_for_usk(uri: str) -> str:
    parts = uri.split("/")
    if len(parts) != 3 or not parts[0].startswith("USK@"):
        raise InteropFailure(f"Cannot derive edition SSK from non-edition USK URI: {uri}")
    try:
        edition = abs(int(parts[2], 10))
    except ValueError as exc:
        raise InteropFailure(f"Cannot derive edition SSK from USK with invalid edition: {uri}") from exc
    return f"SSK@{parts[0].removeprefix('USK@')}/{parts[1]}-{edition}"


def record_uri(summary: dict[str, object], flow: str, direction: str, uri_type: str, uri: str) -> None:
    uris = summary.setdefault("uris", [])
    if isinstance(uris, list):
        uris.append({"flow": flow, "direction": direction, "type": uri_type, "uri": uri})


def list_persistent_requests(client: FcpClient, identifier: str) -> list[dict[str, object]]:
    client.send("ListPersistentRequests", {"Identifier": identifier})
    requests: list[dict[str, object]] = []
    while True:
        frame = client.read_message(DEFAULT_REQUEST_TIMEOUT_SECONDS)
        if frame.name == "EndListPersistentRequests":
            return requests
        if frame.name == "ProtocolError":
            raise InteropFailure(
                f"{client.name} received ProtocolError during ListPersistentRequests: {frame.fields}"
            )
        if frame.name in {"PersistentPut", "PersistentGet"}:
            requests.append({"name": frame.name, "fields": dict(frame.fields)})


def remove_persistent_request(client: FcpClient, identifier: str, *, global_queue: bool = False) -> str:
    client.send("RemoveRequest", {"Identifier": identifier, "Global": fcp_bool(global_queue)})
    try:
        frame = client.read_until(
            10,
            {"PersistentRequestRemoved", "ProtocolError"},
            error_names=(),
        )
    except (TimeoutError, socket.timeout):
        return "no-removal-ack"
    if frame.name == "ProtocolError":
        return f"protocol-error:{frame.fields.get('Code', 'unknown')}"
    return "removed"


def read_get_payload(client: FcpClient, identifier: str, timeout_seconds: int) -> bytes:
    while True:
        frame = client.read_message(timeout_seconds)
        if frame.name == "AllData" and frame.fields.get("Identifier") == identifier:
            if frame.payload is None:
                raise InteropFailure(f"{client.name} AllData payload missing")
            return frame.payload
        if frame.name in {"GetFailed", "ProtocolError"} and frame.fields.get("Identifier") in {
            identifier,
            None,
        }:
            raise InteropFailure(f"{client.name} get failed with {frame.name}: {frame.fields}")


def build_get_request_status_fields(
    identifier: str, *, global_queue: bool = False, only_data: bool = False
) -> dict[str, object]:
    fields: dict[str, object] = {
        "Identifier": identifier,
        "Global": fcp_bool(global_queue),
    }
    if only_data:
        fields["OnlyData"] = "true"
    return fields


def request_persistent_get_data(client: FcpClient, identifier: str) -> None:
    client.send(
        "GetRequestStatus",
        build_get_request_status_fields(identifier, only_data=True),
    )


def read_persistent_get_payload(client: FcpClient, identifier: str, timeout_seconds: int) -> bytes:
    deadline = time.monotonic() + timeout_seconds
    requested_payload = False
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"{client.name} timed out waiting for persistent AllData")
        frame = client.read_message(min(remaining, timeout_seconds))
        if frame.name == "AllData" and frame.fields.get("Identifier") == identifier:
            if frame.payload is None:
                raise InteropFailure(f"{client.name} AllData payload missing")
            return frame.payload
        if frame.name == "DataFound" and frame.fields.get("Identifier") == identifier:
            if not requested_payload:
                request_persistent_get_data(client, identifier)
                requested_payload = True
            continue
        if frame.name in {"GetFailed", "ProtocolError"} and frame.fields.get("Identifier") in {
            identifier,
            None,
        }:
            raise InteropFailure(f"{client.name} get failed with {frame.name}: {frame.fields}")


def find_persistent_request(
    requests: list[dict[str, object]], identifier: str
) -> dict[str, object] | None:
    for request in requests:
        fields = request.get("fields")
        if isinstance(fields, dict) and fields.get("Identifier") == identifier:
            return request
    return None


def wait_for_persistent_request_present(
    client: FcpClient,
    identifier: str,
    timeout_seconds: int,
) -> list[dict[str, object]]:
    deadline = time.monotonic() + timeout_seconds
    latest: list[dict[str, object]] = []
    while time.monotonic() < deadline:
        latest = list_persistent_requests(client, f"list-{identifier}")
        if find_persistent_request(latest, identifier) is not None:
            return latest
        time.sleep(1)
    raise InteropFailure(f"Persistent request {identifier} was not listed before timeout")


def build_persistent_replay_get_fields(identifier: str, uri: str) -> dict[str, object]:
    fields = build_client_get_fields(identifier, uri, ignore_ds=True)
    fields.update(
        {
            "Persistence": "forever",
            "Global": "false",
            "ClientToken": "interop-persistent-request-replay",
            "MaxRetries": "-1",
            "PriorityClass": "2",
            "RealTimeFlag": "true",
        }
    )
    return fields


def start_persistent_request_replay(
    layout: Layout,
    ports: Ports,
    hyphanet_client: FcpClient,
    payload_seed: str,
    request_timeout_seconds: int,
) -> dict[str, object]:
    transcript_path = layout.transcripts_dir / "cryptad-persistent-request-replay.fcp.txt"
    identifier = "cryptad-persistent-request-replay-get"
    client_name = "cryptad-interop-persistent-request-replay"
    site = "interop-persistent-request-replay"
    target_edition = 0
    payload = (
        f"Crypta interop persistent replay USK edition {target_edition} payload "
        f"hyphanet-to-cryptad seed={payload_seed}\n"
    ).encode()
    insert_base, request_base = generate_ssk(
        hyphanet_client, "hyphanet-generate-persistent-replay-usk"
    )
    insert_uri = usk_from_ssk(insert_base, site, target_edition)
    request_uri = usk_from_ssk(request_base, site, target_edition)
    starter_client: FcpClient | None = None
    try:
        starter_client = FcpClient("127.0.0.1", ports.cryptad_fcp, client_name, transcript_path)
        starter_client.send("ClientGet", build_persistent_replay_get_fields(identifier, request_uri))
        before_restart = wait_for_persistent_request_present(
            starter_client,
            identifier,
            min(30, request_timeout_seconds),
        )
        return {
            "implementation": "future USK ClientGet with Persistence=forever",
            "transcript": relative_artifact(layout, transcript_path),
            "request_identifier": identifier,
            "client_name": client_name,
            "target_edition": target_edition,
            "request_uri": request_uri,
            "insert_uri": insert_uri,
            "expected_payload_sha256": hashlib.sha256(payload).hexdigest(),
            "expected_payload": payload,
            "present_before_restart": find_persistent_request(before_restart, identifier)
            is not None,
            "before_restart_requests": before_restart,
        }
    finally:
        if starter_client is not None:
            try:
                starter_client.close()
            except Exception:
                pass


def list_persistent_replay_requests(
    layout: Layout,
    ports: Ports,
    replay: dict[str, object],
    identifier: str,
) -> list[dict[str, object]]:
    transcript_path = layout.transcripts_dir / "cryptad-persistent-request-replay.fcp.txt"
    client: FcpClient | None = None
    try:
        client = FcpClient(
            "127.0.0.1",
            ports.cryptad_fcp,
            str(replay["client_name"]),
            transcript_path,
        )
        return list_persistent_requests(client, identifier)
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def complete_persistent_request_replay(
    layout: Layout,
    ports: Ports,
    hyphanet_client: FcpClient,
    replay: dict[str, object],
    request_timeout_seconds: int,
) -> dict[str, object]:
    transcript_path = layout.transcripts_dir / "cryptad-persistent-request-replay.fcp.txt"
    identifier = str(replay["request_identifier"])
    client_name = str(replay["client_name"])
    expected_payload = replay["expected_payload"]
    if not isinstance(expected_payload, bytes):
        raise InteropFailure("Internal error: persistent replay payload is not bytes")
    completion_client: FcpClient | None = None
    started = time.monotonic()
    try:
        completion_client = FcpClient("127.0.0.1", ports.cryptad_fcp, client_name, transcript_path)
        put_and_wait_for_success(
            hyphanet_client,
            "hyphanet-put-persistent-request-replay",
            str(replay["insert_uri"]),
            expected_payload,
            None,
            local_request_only=False,
            uri_fallback=str(replay["request_uri"]),
        )
        payload = read_persistent_get_payload(
            completion_client,
            identifier,
            request_timeout_seconds * 2,
        )
        assert_payload("Cryptad persistent replay completion", payload, expected_payload)
        after_completion = list_persistent_requests(
            completion_client, "cryptad-list-persistent-after-completion"
        )
        removal = remove_persistent_request(completion_client, identifier)
        return {
            "completed_after_restart": True,
            "duration_seconds": round(time.monotonic() - started, 3),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "after_completion_requests": after_completion,
            "present_after_completion": find_persistent_request(after_completion, identifier)
            is not None,
            "remove_result": removal,
        }
    finally:
        if completion_client is not None:
            try:
                completion_client.close()
            except Exception:
                pass


def edition_from_subscription_frame(frame: FcpFrame) -> int | None:
    for key in ("Edition", "edition"):
        value = frame.fields.get(key)
        if value is not None:
            try:
                return int(value, 10)
            except ValueError:
                return None
    uri = frame.fields.get("URI")
    if uri:
        try:
            return int(uri.rsplit("/", 1)[1], 10)
        except (IndexError, ValueError):
            return None
    return None


def wait_for_subscription_update(
    client: FcpClient,
    subscription_id: str,
    target_edition: int,
    duration_seconds: int,
    poll_interval_seconds: int,
) -> tuple[int | None, dict[str, int], list[str]]:
    observed_messages: dict[str, int] = {}
    observed_frames: list[str] = []
    deadline = time.monotonic() + duration_seconds
    while time.monotonic() < deadline:
        timeout = min(poll_interval_seconds, max(0.1, deadline - time.monotonic()))
        if not client.wait_readable(timeout):
            continue
        remaining = max(1.0, deadline - time.monotonic())
        frame = client.read_message(min(DEFAULT_REQUEST_TIMEOUT_SECONDS, remaining))
        observed_messages[frame.name] = observed_messages.get(frame.name, 0) + 1
        observed_frames.append(frame.name)
        if frame.fields.get("Identifier") not in {None, subscription_id}:
            continue
        if frame.name in {"SubscribedUSK", "SubscribedUSKUpdate"}:
            edition = edition_from_subscription_frame(frame)
            if edition is not None and edition >= target_edition:
                return edition, observed_messages, observed_frames
        if frame.name in {"ProtocolError", "GetFailed"}:
            raise InteropFailure(f"SubscribeUSK soak received {frame.name}: {frame.fields}")
    return None, observed_messages, observed_frames


def run_usk_subscribe_soak(
    layout: Layout,
    ports: Ports,
    insert_base: str,
    request_base: str,
    site: str,
    payload_seed: str,
    duration_seconds: int,
    poll_interval_seconds: int,
    request_timeout_seconds: int,
) -> dict[str, object]:
    subscription_id = "hyphanet-usk-subscribe-soak"
    initial_edition = 0
    target_edition = 1
    soak_site = f"{site}-subscribe-soak"
    initial_payload = (
        f"Crypta interop USK subscribe soak edition {initial_edition} payload "
        f"cryptad-to-hyphanet seed={payload_seed}\n"
    ).encode()
    target_payload = (
        f"Crypta interop USK subscribe soak edition {target_edition} payload "
        f"cryptad-to-hyphanet seed={payload_seed}\n"
    ).encode()
    initial_insert_uri = usk_from_ssk(insert_base, soak_site, initial_edition)
    subscription_uri = usk_from_ssk(request_base, soak_site, initial_edition)
    target_insert_uri = usk_from_ssk(insert_base, soak_site, target_edition)
    target_request_uri = usk_from_ssk(request_base, soak_site, target_edition)
    source_transcript = layout.transcripts_dir / "cryptad-usk-subscribe-soak.fcp.txt"
    subscriber_transcript = layout.transcripts_dir / "hyphanet-usk-subscribe-soak.fcp.txt"
    source_client: FcpClient | None = None
    subscriber_client: FcpClient | None = None
    started = time.monotonic()
    try:
        source_client = FcpClient(
            "127.0.0.1",
            ports.cryptad_fcp,
            "cryptad-interop-usk-subscribe-soak",
            source_transcript,
        )
        subscriber_client = FcpClient(
            "127.0.0.1",
            ports.hyphanet_fcp,
            "hyphanet-interop-usk-subscribe-soak",
            subscriber_transcript,
        )
        put_and_wait_for_success(
            source_client,
            "cryptad-put-usk-subscribe-soak-0",
            initial_insert_uri,
            initial_payload,
            None,
            local_request_only=True,
            uri_fallback=subscription_uri,
        )
        fetched = fetch_direct_until_available(
            "127.0.0.1",
            ports.hyphanet_fcp,
            "hyphanet-fetch-cryptad-usk-subscribe-soak-0",
            subscriber_transcript,
            "hyphanet-fetch-cryptad-usk-subscribe-soak-0",
            subscription_uri,
            request_timeout_seconds,
        )
        assert_payload("Hyphanet fetched Cryptad USK soak initial edition", fetched, initial_payload)
        subscriber_client.send(
            "SubscribeUSK",
            {
                "Identifier": subscription_id,
                "URI": subscription_uri,
                "DontPoll": "false",
                "SparsePoll": "true",
                "PriorityClass": "2",
                "PriorityClassProgress": "1",
                "RealTimeFlag": "true",
                "IgnoreUSKDatehints": "true",
            },
        )
        ack = subscriber_client.read_until(DEFAULT_REQUEST_TIMEOUT_SECONDS, {"SubscribedUSK"})

        put_and_wait_for_success(
            source_client,
            "cryptad-put-usk-subscribe-soak-2",
            target_insert_uri,
            target_payload,
            None,
            local_request_only=True,
            uri_fallback=target_request_uri,
        )
        observed_edition, observed_messages, observed_frames = wait_for_subscription_update(
            subscriber_client,
            subscription_id,
            target_edition,
            duration_seconds,
            poll_interval_seconds,
        )
        fallback_used = False
        if observed_edition is None:
            fetched = fetch_direct_until_available(
                "127.0.0.1",
                ports.hyphanet_fcp,
                "hyphanet-fetch-cryptad-usk-subscribe-soak-2",
                subscriber_transcript,
                "hyphanet-fetch-cryptad-usk-subscribe-soak-2",
                target_request_uri,
                request_timeout_seconds,
            )
            assert_payload("Hyphanet fetched Cryptad USK soak edition", fetched, target_payload)
            observed_edition = target_edition
            fallback_used = True
        subscriber_client.send("UnsubscribeUSK", {"Identifier": subscription_id})
        limitations: list[str] = []
        if fallback_used:
            limitations.append(
                "SubscribeUSK was accepted, but the pinned baseline did not emit a target "
                "SubscribedUSKUpdate before the soak timeout; the harness verified the new "
                "edition with a bounded FCP fetch fallback."
            )
        duration = round(time.monotonic() - started, 3)
        return {
            "source": "cryptad",
            "subscriber": "hyphanet",
            "initial_edition": initial_edition,
            "observed_edition": observed_edition,
            "duration_seconds": duration,
            "subscription_identifier": subscription_id,
            "poll_interval_seconds": poll_interval_seconds,
            "subscription_update_observed": not fallback_used,
            "fallback_used": fallback_used,
            "subscribed_ack_fields": redacted_summary_value(dict(ack.fields)),
            "observed_messages": observed_messages,
            "observed_frames": observed_frames,
            "transcripts": {
                "source": relative_artifact(layout, source_transcript),
                "subscriber": relative_artifact(layout, subscriber_transcript),
            },
            "limitations": limitations,
        }
    finally:
        for active_client in (subscriber_client, source_client):
            if active_client is not None:
                try:
                    active_client.close()
                except Exception:
                    pass


def log_progress(message: str) -> None:
    print(message, flush=True)


def begin_flow(summary: dict[str, object], flow_name: str) -> None:
    FLOW_STARTS[flow_name] = time.monotonic()
    flows = summary["flows"]
    assert isinstance(flows, dict)
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    flows[flow_name] = {
        "status": "running",
        "started_at": started_at,
    }
    results = summary.setdefault("flow_results", {})
    assert isinstance(results, dict)
    results[flow_name] = {
        "status": "running",
        "started_at": started_at,
    }


def finish_flow(
    summary: dict[str, object],
    flow_name: str,
    status: str,
    *,
    details: dict[str, object] | None = None,
) -> None:
    flows = summary["flows"]
    assert isinstance(flows, dict)
    results = summary.setdefault("flow_results", {})
    assert isinstance(results, dict)
    existing = flows.get(flow_name)
    result = dict(existing) if isinstance(existing, dict) else {}
    result["status"] = status
    if details:
        result.update(details)
    started = FLOW_STARTS.pop(flow_name, None)
    if started is not None:
        result["duration_seconds"] = round(time.monotonic() - started, 3)
    result["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    flows[flow_name] = result
    results[flow_name] = dict(result)


def flow_success(
    summary: dict[str, object], flow_name: str, details: dict[str, object] | None = None
) -> None:
    finish_flow(summary, flow_name, "passed", details=details)


def flow_failure(
    summary: dict[str, object], flow_name: str, details: dict[str, object] | None = None
) -> None:
    finish_flow(summary, flow_name, "failed", details=details)


def flow_skipped(summary: dict[str, object], flow_name: str, reason: str) -> None:
    flows = summary["flows"]
    assert isinstance(flows, dict)
    flow_value = {"status": "skipped", "reason": reason}
    flows[flow_name] = flow_value
    skipped = summary.setdefault("skipped_flows", {})
    assert isinstance(skipped, dict)
    skipped[flow_name] = reason
    results = summary.setdefault("flow_results", {})
    assert isinstance(results, dict)
    results[flow_name] = dict(flow_value)


def fail_running_flows(summary: dict[str, object], reason: str) -> None:
    flows = summary.get("flows", {})
    if not isinstance(flows, dict):
        return
    for flow_name, value in list(flows.items()):
        if isinstance(value, dict) and value.get("status") == "running":
            flow_failure(summary, flow_name, {"error": reason})


def write_summary(layout: Layout, summary: dict[str, object]) -> None:
    write_json(layout.out_dir / "summary.json", redacted_summary_value(summary))


def build_transcript_refs(layout: Layout) -> dict[str, str]:
    return {
        "cryptad": relative_artifact(layout, layout.transcripts_dir / "cryptad.fcp.txt"),
        "hyphanet": relative_artifact(layout, layout.transcripts_dir / "hyphanet.fcp.txt"),
        "usk_subscribe_soak_source": relative_artifact(
            layout, layout.transcripts_dir / "cryptad-usk-subscribe-soak.fcp.txt"
        ),
        "usk_subscribe_soak_subscriber": relative_artifact(
            layout, layout.transcripts_dir / "hyphanet-usk-subscribe-soak.fcp.txt"
        ),
        "persistent_request_replay": relative_artifact(
            layout, layout.transcripts_dir / "cryptad-persistent-request-replay.fcp.txt"
        ),
    }


def write_interop_report(layout: Layout, summary: dict[str, object]) -> Path:
    hyphanet = summary.get("hyphanet", {})
    if not isinstance(hyphanet, dict):
        hyphanet = {}
    flows = summary.get("flows", {})
    if not isinstance(flows, dict):
        flows = {}
    skipped = summary.get("skipped_flows", {})
    if not isinstance(skipped, dict):
        skipped = {}

    lines = [
        "# Interop Report",
        "",
        f"- Status: {summary.get('status', 'unknown')}",
        f"- Mode: {summary.get('mode', 'smoke')}",
        f"- Elapsed seconds: {summary.get('elapsed_seconds', 'n/a')}",
        f"- Hyphanet baseline version: {hyphanet.get('baseline_version') or 'unknown'}",
        f"- Hyphanet baseline kind: {hyphanet.get('baseline_kind') or 'unknown'}",
        f"- Hyphanet baseline SHA-256: {hyphanet.get('baseline_sha256') or 'unknown'}",
        "",
        "## Enabled Flows",
        "",
    ]
    for flow in summary.get("enabled_flows", []):
        lines.append(f"- {flow}")
    if not summary.get("enabled_flows"):
        lines.append("- none")

    lines.extend(["", "## Flow Results", "", "| Flow | Status | Duration | Notes |", "| --- | --- | ---: | --- |"])
    for flow in FLOW_NAMES:
        result = flows.get(flow, {})
        if not isinstance(result, dict):
            result = {"status": result}
        duration = result.get("duration_seconds", "")
        notes = []
        if "reason" in result:
            notes.append(redacted_report_text(result["reason"]))
        limitations = result.get("limitations")
        if isinstance(limitations, list) and limitations:
            notes.append("limitations recorded in summary.json")
        lines.append(
            f"| {flow} | {result.get('status', 'skipped')} | {duration} | "
            f"{'; '.join(notes) if notes else ''} |"
        )

    lines.extend(["", "## Skipped Flows", ""])
    if skipped:
        for flow, reason in skipped.items():
            lines.append(f"- {flow}: {redacted_report_text(reason)}")
    else:
        lines.append("- none")

    lines.extend(["", "## Transcripts", ""])
    transcript_refs = summary.get("transcript_refs", {})
    if isinstance(transcript_refs, dict):
        for name, ref in transcript_refs.items():
            lines.append(f"- {name}: `{ref}`")
    else:
        lines.append("- none")

    if summary.get("failure_reason"):
        lines.extend(["", "## Failure", "", redacted_report_text(summary["failure_reason"])])

    path = layout.artifacts_dir / "interop-report.md"
    write_text(path, "\n".join(lines) + "\n")
    add_artifact(summary, layout, path)
    return path


def process_statuses(nodes: Iterable[NodeRuntime]) -> dict[str, dict[str, int | None | str]]:
    return {
        node.name: {
            "pid": node.process.pid,
            "exit_code": node.process.poll(),
            "stdout": str(node.stdout_path),
            "stderr": str(node.stderr_path),
        }
        for node in nodes
    }


def build_layout(out_dir: Path) -> Layout:
    return Layout(
        out_dir=out_dir,
        downloads_dir=out_dir / "downloads",
        cryptad_dir=out_dir / "cryptad",
        hyphanet_dir=out_dir / "hyphanet",
        logs_dir=out_dir / "logs",
        transcripts_dir=out_dir / "transcripts",
        artifacts_dir=out_dir / "artifacts",
    )


def resolve_flow_enabled(
    mode_default: bool,
    env_value: bool | None,
    cli_enabled: bool,
    cli_disabled: bool,
) -> bool:
    if cli_enabled:
        return True
    if cli_disabled:
        return False
    if env_value is not None:
        return env_value
    return mode_default


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a Hyphanet/Cryptad interop gate.")
    env_mode = os.environ.get("INTEROP_MODE", "smoke")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--mode",
        choices=("smoke", "extended"),
        default=env_mode,
    )
    parser.add_argument("--enable-usk-subscribe-soak", action="store_true")
    parser.add_argument("--disable-usk-subscribe-soak", action="store_true")
    parser.add_argument("--enable-persistent-replay", action="store_true")
    parser.add_argument("--disable-persistent-replay", action="store_true")
    parser.add_argument("--enable-opennet", action="store_true")
    parser.add_argument(
        "--soak-duration-seconds",
        type=int,
        default=env_int("INTEROP_SOAK_DURATION_SECONDS", DEFAULT_SOAK_DURATION_SECONDS),
    )
    parser.add_argument(
        "--soak-poll-interval-seconds",
        type=int,
        default=env_int(
            "INTEROP_SOAK_POLL_INTERVAL_SECONDS", DEFAULT_SOAK_POLL_INTERVAL_SECONDS
        ),
    )
    parser.add_argument("--workspace-root", type=Path)
    parser.add_argument("--cryptad-dist-dir", type=Path)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--download-cache-dir", type=Path)
    parser.add_argument("--suite-timeout-seconds", type=int, default=DEFAULT_SUITE_TIMEOUT_SECONDS)
    parser.add_argument("--startup-timeout-seconds", type=int, default=DEFAULT_STARTUP_TIMEOUT_SECONDS)
    parser.add_argument("--peer-timeout-seconds", type=int, default=DEFAULT_PEER_TIMEOUT_SECONDS)
    parser.add_argument("--request-timeout-seconds", type=int, default=DEFAULT_REQUEST_TIMEOUT_SECONDS)
    parser.add_argument("--cryptad-fnp-port", type=int, default=DEFAULT_CRYPTAD_FNP_PORT)
    parser.add_argument("--cryptad-fcp-port", type=int, default=DEFAULT_CRYPTAD_FCP_PORT)
    parser.add_argument("--hyphanet-fnp-port", type=int, default=DEFAULT_HYPHANET_FNP_PORT)
    parser.add_argument("--hyphanet-fcp-port", type=int, default=DEFAULT_HYPHANET_FCP_PORT)
    parser.add_argument("--keep-workdir", action="store_true")
    if env_mode not in {"smoke", "extended"}:
        parser.error(f"INTEROP_MODE must be smoke or extended, got: {env_mode}")
    args = parser.parse_args(argv)
    if args.enable_usk_subscribe_soak and args.disable_usk_subscribe_soak:
        parser.error("cannot pass both --enable-usk-subscribe-soak and --disable-usk-subscribe-soak")
    if args.enable_persistent_replay and args.disable_persistent_replay:
        parser.error("cannot pass both --enable-persistent-replay and --disable-persistent-replay")
    usk_env = env_flag_or_none("INTEROP_ENABLE_USK_SUBSCRIBE_SOAK")
    persistent_env = env_flag_or_none("INTEROP_ENABLE_PERSISTENT_REPLAY")
    opennet_env = env_flag_or_none("INTEROP_ENABLE_OPENNET")
    extended_mode = args.mode == "extended"
    args.enable_usk_subscribe_soak = resolve_flow_enabled(
        extended_mode,
        usk_env,
        args.enable_usk_subscribe_soak,
        args.disable_usk_subscribe_soak,
    )
    args.enable_persistent_replay = resolve_flow_enabled(
        extended_mode,
        persistent_env,
        args.enable_persistent_replay,
        args.disable_persistent_replay,
    )
    args.enable_opennet = args.enable_opennet or bool(opennet_env)
    if args.soak_duration_seconds < 0:
        parser.error("--soak-duration-seconds must be >= 0")
    if args.soak_poll_interval_seconds <= 0:
        parser.error("--soak-poll-interval-seconds must be > 0")
    if not args.self_test:
        missing = [
            name
            for name in ("workspace_root", "cryptad_dist_dir", "out_dir", "download_cache_dir")
            if getattr(args, name) is None
        ]
        if missing:
            parser.error(f"missing required arguments: {', '.join('--' + item.replace('_', '-') for item in missing)}")
    return args


def selected_flows(args: argparse.Namespace) -> tuple[list[str], dict[str, str]]:
    enabled = list(SMOKE_FLOW_NAMES)
    skipped: dict[str, str] = {}

    if args.enable_usk_subscribe_soak:
        enabled.append("usk_subscribe_soak")
    else:
        skipped["usk_subscribe_soak"] = "disabled for this run"

    if args.enable_persistent_replay:
        enabled.append("persistent_request_replay")
    else:
        skipped["persistent_request_replay"] = "disabled for this run"

    if not args.enable_opennet:
        skipped["opennet_optional"] = "disabled; pass --enable-opennet for optional opennet plumbing"
    else:
        skipped["opennet_optional"] = (
            "requested and node configs were launched with opennet enabled, but deterministic "
            "opennet path validation is not implemented for the pinned Linux baseline"
        )

    return enabled, skipped


def require_linux() -> None:
    if sys.platform != "linux":
        raise InteropFailure("This interoperability gate is Linux-only")


def require_tool(name: str) -> None:
    if shutil.which(name) is None:
        raise InteropFailure(f"Required tool not found on PATH: {name}")


def suite_timeout_handler(signum: int, frame: object) -> None:
    raise TimeoutError("Interop suite exceeded INTEROP_TIMEOUT_SECONDS")


def assert_payload(label: str, actual: bytes, expected: bytes) -> None:
    if actual != expected:
        raise InteropFailure(f"{label} payload mismatch: expected {len(expected)} bytes, got {len(actual)}")


def self_test() -> int:
    simple = io.BytesIO(b"NodeHello\nFCPVersion=2.0\nNode=interop\nEndMessage\n")
    frame = read_fcp_frame_from_file(simple)
    assert frame.name == "NodeHello"
    assert frame.fields["FCPVersion"] == "2.0"
    payload = b"abc\n123"
    encoded = encode_fcp_frame("AllData", {"Identifier": "x", "DataLength": str(len(payload))}, payload)
    frame = read_fcp_frame_from_file(io.BytesIO(encoded))
    assert frame.name == "AllData"
    assert frame.payload == payload
    try:
        read_fcp_frame_from_file(io.BytesIO(b"AllData\nIdentifier=x\nData\nabc"))
    except InteropFailure:
        pass
    else:
        raise AssertionError("missing DataLength was not rejected")
    assert redacted_fields({"InsertURI": "SSK@private", "RequestURI": "SSK@public"}) == {
        "InsertURI": "<redacted>",
        "RequestURI": "SSK@public",
    }
    assert redacted_fields({"URI": "SSK@private", "CHK": "CHK@public"}) == {
        "URI": "<redacted-uri>",
        "CHK": "CHK@public",
    }
    assert "IgnoreDS" not in build_client_get_fields("fetch-default", "CHK@sample")
    assert (
        build_client_get_fields("fetch-network", "CHK@sample", ignore_ds=True)["IgnoreDS"]
        == "true"
    )
    assert build_get_request_status_fields("persistent-id", only_data=True) == {
        "Identifier": "persistent-id",
        "Global": "false",
        "OnlyData": "true",
    }

    class StubPersistentGetClient:
        name = "stub-persistent-get"

        def __init__(self) -> None:
            self.sent: list[tuple[str, dict[str, object], bytes | None]] = []
            self.frames = [
                FcpFrame("PersistentGet", {"Identifier": "persistent-id"}),
                FcpFrame("DataFound", {"Identifier": "persistent-id"}),
                FcpFrame(
                    "AllData",
                    {"Identifier": "persistent-id", "DataLength": "7"},
                    b"payload",
                ),
            ]

        def send(
            self, name: str, fields: dict[str, object], payload: bytes | None = None
        ) -> None:
            self.sent.append((name, fields, payload))

        def read_message(self, timeout: float) -> FcpFrame:
            return self.frames.pop(0)

    stub_client = StubPersistentGetClient()
    assert read_persistent_get_payload(stub_client, "persistent-id", 10) == b"payload"
    assert stub_client.sent == [
        (
            "GetRequestStatus",
            {"Identifier": "persistent-id", "Global": "false", "OnlyData": "true"},
            None,
        )
    ]

    class StubSubscriptionClient:
        name = "stub-subscription"

        def __init__(self) -> None:
            self.readiness = [False, True]
            self.frames = [
                FcpFrame(
                    "SubscribedUSKUpdate",
                    {"Identifier": "subscription-id", "Edition": "1"},
                )
            ]
            self.read_count = 0

        def wait_readable(self, timeout: float) -> bool:
            return self.readiness.pop(0)

        def read_message(self, timeout: float) -> FcpFrame:
            self.read_count += 1
            return self.frames.pop(0)

    subscription_client = StubSubscriptionClient()
    observed_edition, observed_messages, observed_frames = wait_for_subscription_update(
        subscription_client,
        "subscription-id",
        1,
        10,
        5,
    )
    assert observed_edition == 1
    assert observed_messages == {"SubscribedUSKUpdate": 1}
    assert observed_frames == ["SubscribedUSKUpdate"]
    assert subscription_client.read_count == 1
    ensure_distinct_node_ports(Ports(19401, 19402, 19501, 19502))
    try:
        ensure_distinct_node_ports(Ports(19401, 19402, 19401, 19502))
    except InteropFailure:
        pass
    else:
        raise AssertionError("duplicate FNP ports were not rejected")
    try:
        ensure_distinct_node_ports(Ports(19401, 19402, 19501, 19402))
    except InteropFailure:
        pass
    else:
        raise AssertionError("duplicate FCP ports were not rejected")
    with TemporaryDirectory() as temp_root:
        asset_path = Path(temp_root) / "baseline.deb"
        temp_path_1 = reserve_download_temp_path(asset_path)
        temp_path_2 = reserve_download_temp_path(asset_path)
        try:
            assert temp_path_1 != temp_path_2
            assert temp_path_1.parent == asset_path.parent
            assert temp_path_2.parent == asset_path.parent
            assert temp_path_1.name.startswith(asset_path.name + ".")
            assert temp_path_2.name.startswith(asset_path.name + ".")
            assert temp_path_1.name.endswith(".download")
            assert temp_path_2.name.endswith(".download")
        finally:
            temp_path_1.unlink(missing_ok=True)
            temp_path_2.unlink(missing_ok=True)
    assert (
        ssk_for_usk("USK@pub,crypto,AQACAAE/site/1")
        == "SSK@pub,crypto,AQACAAE/site-1"
    )
    assert (
        ssk_for_usk("USK@pub,crypto,AQACAAE/site/-2")
        == "SSK@pub,crypto,AQACAAE/site-2"
    )
    try:
        ssk_for_usk("USK@pub,crypto,AQACAAE/site/not-an-edition")
    except InteropFailure:
        pass
    else:
        raise AssertionError("invalid USK edition was not rejected")
    with TemporaryDirectory() as temp_root:
        extract_root = Path(temp_root)
        java_dir = extract_root / "usr" / "share" / "java"
        java_dir.mkdir(parents=True)
        (java_dir / "freenet-0.8.0+1600.jar").touch()
        (java_dir / "bcprov-jdk15on-1.70-0.8.0+1600.jar").touch()
        (java_dir / "unversioned.jar").touch()
        (java_dir / "already.jar").write_text("existing", encoding="utf-8")
        (java_dir / "already-0.8.0+1600.jar").touch()

        materialize_hyphanet_java_symlinks(extract_root)

        assert (java_dir / "freenet.jar").is_symlink()
        assert os.readlink(java_dir / "freenet.jar") == "freenet-0.8.0+1600.jar"
        assert (java_dir / "bcprov-jdk15on-1.70.jar").is_symlink()
        assert (
            os.readlink(java_dir / "bcprov-jdk15on-1.70.jar")
            == "bcprov-jdk15on-1.70-0.8.0+1600.jar"
        )
        assert not (java_dir / "unversioned.jar").is_symlink()
        assert not (java_dir / "already.jar").is_symlink()
    with TemporaryDirectory() as temp_root:
        ports = Ports(
            cryptad_fnp=19401,
            cryptad_fcp=19402,
            hyphanet_fnp=19501,
            hyphanet_fcp=19502,
        )
        temp_path = Path(temp_root)
        cryptad_config = make_cryptad_config(
            temp_path / "cryptad",
            ports,
            enable_opennet=True,
        )
        hyphanet_config = make_hyphanet_config(
            temp_path / "hyphanet",
            ports,
            enable_opennet=True,
        )
        assert "node.opennet.enabled=true\n" in cryptad_config.read_text(encoding="utf-8")
        assert "node.opennet.enabled=true\n" in hyphanet_config.read_text(encoding="utf-8")
    env_names = (
        "INTEROP_MODE",
        "INTEROP_ENABLE_USK_SUBSCRIBE_SOAK",
        "INTEROP_ENABLE_PERSISTENT_REPLAY",
        "INTEROP_ENABLE_OPENNET",
        "INTEROP_SOAK_DURATION_SECONDS",
        "INTEROP_SOAK_POLL_INTERVAL_SECONDS",
    )
    saved_env = {name: os.environ.pop(name, None) for name in env_names}
    try:
        smoke_args = parse_args(["--self-test", "--mode", "smoke"])
        smoke_enabled, smoke_skipped = selected_flows(smoke_args)
        assert list(SMOKE_FLOW_NAMES) == smoke_enabled
        assert smoke_skipped["usk_subscribe_soak"] == "disabled for this run"
        assert smoke_skipped["persistent_request_replay"] == "disabled for this run"
        extended_args = parse_args(["--self-test", "--mode", "extended"])
        extended_enabled, extended_skipped = selected_flows(extended_args)
        assert "usk_subscribe_soak" in extended_enabled
        assert "persistent_request_replay" in extended_enabled
        assert "opennet_optional" in extended_skipped
        opennet_args = parse_args(["--self-test", "--mode", "extended", "--enable-opennet"])
        _, opennet_skipped = selected_flows(opennet_args)
        assert "opennet_optional" in opennet_skipped
        assert "node configs were launched with opennet enabled" in opennet_skipped[
            "opennet_optional"
        ]
        disabled_args = parse_args(
            [
                "--self-test",
                "--mode",
                "extended",
                "--disable-usk-subscribe-soak",
                "--disable-persistent-replay",
            ]
        )
        disabled_enabled, disabled_skipped = selected_flows(disabled_args)
        assert "usk_subscribe_soak" not in disabled_enabled
        assert "persistent_request_replay" not in disabled_enabled
        assert disabled_skipped["usk_subscribe_soak"] == "disabled for this run"
        os.environ["INTEROP_ENABLE_USK_SUBSCRIBE_SOAK"] = "1"
        env_enabled_disabled_args = parse_args(
            ["--self-test", "--mode", "extended", "--disable-usk-subscribe-soak"]
        )
        env_enabled_disabled, _ = selected_flows(env_enabled_disabled_args)
        assert "usk_subscribe_soak" not in env_enabled_disabled
        os.environ["INTEROP_MODE"] = "extendd"
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                parse_args(["--self-test"])
        except SystemExit as exc:
            assert exc.code == 2
        else:
            raise AssertionError("invalid INTEROP_MODE was not rejected")
    finally:
        for name, value in saved_env.items():
            if value is not None:
                os.environ[name] = value
            else:
                os.environ.pop(name, None)
    with TemporaryDirectory() as temp_root:
        layout = build_layout(Path(temp_root))
        layout.artifacts_dir.mkdir(parents=True)
        layout.transcripts_dir.mkdir(parents=True)
        summary: dict[str, object] = {
            "status": "success",
            "mode": "extended",
            "enabled_flows": ["handshake"],
            "skipped_flows": {},
            "flows": {name: {"status": "skipped", "reason": "not reached"} for name in FLOW_NAMES},
            "flow_results": {},
            "hyphanet": {"baseline_version": "self-test", "baseline_kind": "jar"},
            "artifacts": [],
            "elapsed_seconds": 0,
            "transcript_refs": build_transcript_refs(layout),
            "failure_reason": (
                "PutFailed {'URI': 'USK@private,crypto/site/0', "
                "'InsertURI': 'SSK@secret,crypto/site', "
                "'SplitfileCryptoKey': 'abc123'}"
            ),
        }
        flow_skipped(summary, "opennet_optional", "self-test")
        begin_flow(summary, "handshake")
        flow_success(summary, "handshake", {"transcripts": {"cryptad": "transcripts/x.fcp.txt"}})
        flows = summary["flows"]
        assert isinstance(flows, dict)
        handshake = flows["handshake"]
        assert isinstance(handshake, dict)
        assert handshake["status"] == "passed"
        assert "duration_seconds" in handshake
        skipped = flows["opennet_optional"]
        assert isinstance(skipped, dict)
        assert skipped["status"] == "skipped"
        assert redacted_summary_value({"URI": "USK@private/site/0"}) == {
            "URI": "<redacted-uri>"
        }
        assert redacted_summary_value({"insert_uri": "SSK@secret/site"}) == {
            "insert_uri": "<redacted>"
        }
        redacted_error = redacted_summary_value(
            {
                "error": (
                    "ProtocolError {'URI': 'USK@private,crypto/site/0', "
                    "'InsertURI': 'SSK@secret,crypto/site', "
                    "'SplitfileCryptoKey': 'def456'}"
                )
            }
        )
        assert isinstance(redacted_error, dict)
        assert "USK@private" not in str(redacted_error)
        assert "SSK@secret" not in str(redacted_error)
        assert "def456" not in str(redacted_error)
        assert redacted_report_text("URI=SSK@private,crypto/site InsertURI=USK@secret/site") == (
            "URI=<redacted-uri> InsertURI=<redacted>"
        )
        summary["flows"]["persistent_request_replay"] = redacted_error
        write_summary(layout, summary)
        summary_text = (layout.out_dir / "summary.json").read_text(encoding="utf-8")
        assert "USK@private" not in summary_text
        assert "SSK@secret" not in summary_text
        assert "abc123" not in summary_text
        assert "def456" not in summary_text
        assert "<redacted-uri>" in summary_text
        redacted_artifact = record_json_artifact(
            summary,
            layout,
            "redaction-check.json",
            {
                "InsertURI": "SSK@artifact-secret/site",
                "error": "PutFailed URI=USK@artifact-private/site",
            },
        )
        artifact_text = redacted_artifact.read_text(encoding="utf-8")
        assert "SSK@artifact-secret" not in artifact_text
        assert "USK@artifact-private" not in artifact_text
        report_path = write_interop_report(layout, summary)
        report_text = report_path.read_text(encoding="utf-8")
        assert report_path.is_file()
        assert "USK@private" not in report_text
        assert "SSK@secret" not in report_text
        assert "abc123" not in report_text
        assert "<redacted-uri>" in report_text
    print("interop_smoke.py self-test passed")
    return 0


def run() -> int:
    args = parse_args()
    if args.self_test:
        return self_test()

    require_linux()
    require_tool("java")
    signal.signal(signal.SIGALRM, suite_timeout_handler)
    signal.alarm(args.suite_timeout_seconds)

    global DEFAULT_REQUEST_TIMEOUT_SECONDS
    DEFAULT_REQUEST_TIMEOUT_SECONDS = args.request_timeout_seconds

    out_dir = args.out_dir.resolve()
    ensure_clean_dir(out_dir)
    layout = build_layout(out_dir)
    for path in (
        layout.downloads_dir,
        layout.cryptad_dir,
        layout.hyphanet_dir,
        layout.logs_dir,
        layout.transcripts_dir,
        layout.artifacts_dir,
    ):
        path.mkdir(parents=True, exist_ok=True)

    ports = Ports(
        cryptad_fnp=args.cryptad_fnp_port,
        cryptad_fcp=args.cryptad_fcp_port,
        hyphanet_fnp=args.hyphanet_fnp_port,
        hyphanet_fcp=args.hyphanet_fcp_port,
    )
    ensure_ports_available(ports)

    enabled_flows, skipped_flow_reasons = selected_flows(args)
    started_at = time.time()
    summary: dict[str, object] = {
        "status": "failure",
        "mode": args.mode,
        "enabled_flows": enabled_flows,
        "skipped_flows": {},
        "flows": {
            name: {"status": "skipped", "reason": "not reached"} for name in FLOW_NAMES
        },
        "flow_results": {},
        "crypta": {"fcp_port": ports.cryptad_fcp, "fnp_port": ports.cryptad_fnp},
        "cryptad": {"fcp_port": ports.cryptad_fcp, "fnp_port": ports.cryptad_fnp},
        "hyphanet": {
            "fcp_port": ports.hyphanet_fcp,
            "fnp_port": ports.hyphanet_fnp,
            "baseline_version": baseline_version(),
        },
        "uris": [],
        "artifacts": [],
        "transcript_refs": build_transcript_refs(layout),
        "workspace_root": str(args.workspace_root.resolve()),
        "cryptad_dist_dir": str(args.cryptad_dist_dir.resolve()),
        "ports": {
            "cryptad_fnp": ports.cryptad_fnp,
            "cryptad_fcp": ports.cryptad_fcp,
            "hyphanet_fnp": ports.hyphanet_fnp,
            "hyphanet_fcp": ports.hyphanet_fcp,
        },
        "restart_recovery_level": "restart-and-refetch",
        "extended": {
            "usk_subscribe_soak_enabled": args.enable_usk_subscribe_soak,
            "persistent_replay_enabled": args.enable_persistent_replay,
            "opennet_requested": args.enable_opennet,
            "opennet_enabled": args.enable_opennet,
            "soak_duration_seconds": args.soak_duration_seconds,
            "soak_poll_interval_seconds": args.soak_poll_interval_seconds,
        },
    }
    for skipped_flow, reason in skipped_flow_reasons.items():
        flow_skipped(summary, skipped_flow, reason)

    nodes: list[NodeRuntime] = []
    cryptad_client: FcpClient | None = None
    hyphanet_client: FcpClient | None = None
    private_keys: list[dict[str, str]] = []
    cryptad_reference: dict[str, str] = {}
    hyphanet_reference: dict[str, str] = {}
    chk_uri_from_cryptad = ""
    chk_uri_from_hyphanet = ""
    ssk_request_from_cryptad = ""
    ssk_request_from_hyphanet = ""
    usk_request_from_cryptad_ed1 = ""
    usk_request_from_hyphanet_ed1 = ""
    usk_insert_base_from_cryptad = ""
    usk_request_base_from_cryptad = ""
    usk_site_from_cryptad = ""
    persistent_replay: dict[str, object] | None = None

    try:
        write_summary(layout, summary)
        baseline = prepare_hyphanet_baseline(layout, args.download_cache_dir.resolve())
        add_artifact(summary, layout, baseline.asset_path)
        summary["hyphanet"] = {
            "fcp_port": ports.hyphanet_fcp,
            "fnp_port": ports.hyphanet_fnp,
            "baseline_version": baseline.version,
            "baseline_kind": baseline.kind,
            "baseline_asset": str(baseline.asset_path),
            "baseline_sha256": sha256sum(baseline.asset_path),
        }
        summary["baseline"] = {
            "name": "hyphanet",
            "version": baseline.version,
            "kind": baseline.kind,
            "asset": str(baseline.asset_path),
            "sha256": sha256sum(baseline.asset_path),
        }
        record_json_artifact(
            summary,
            layout,
            "port-assignments.json",
            summary["ports"],
        )

        log_progress("Starting Cryptad node...")
        cryptad_runtime = launch_cryptad(
            args.cryptad_dist_dir.resolve(),
            layout.cryptad_dir,
            layout,
            ports,
            enable_opennet=args.enable_opennet,
        )
        nodes.append(cryptad_runtime)
        add_artifact(summary, layout, cryptad_runtime.stdout_path)
        add_artifact(summary, layout, cryptad_runtime.stderr_path)
        add_artifact(summary, layout, cryptad_runtime.config_file)

        log_progress("Starting Hyphanet node...")
        hyphanet_runtime = launch_hyphanet(
            baseline,
            layout.hyphanet_dir,
            layout,
            ports,
            enable_opennet=args.enable_opennet,
        )
        nodes.append(hyphanet_runtime)
        add_artifact(summary, layout, hyphanet_runtime.stdout_path)
        add_artifact(summary, layout, hyphanet_runtime.stderr_path)
        add_artifact(summary, layout, hyphanet_runtime.config_file)

        log_progress("Waiting for FCP listeners...")
        wait_for_fcp("127.0.0.1", ports.cryptad_fcp, args.startup_timeout_seconds, nodes)
        wait_for_fcp("127.0.0.1", ports.hyphanet_fcp, args.startup_timeout_seconds, nodes)

        flow = "handshake"
        try:
            begin_flow(summary, flow)
            log_progress("Running FCP handshake and node-info flow...")
            cryptad_client = FcpClient(
                "127.0.0.1",
                ports.cryptad_fcp,
                "cryptad-interop-handshake",
                layout.transcripts_dir / "cryptad.fcp.txt",
            )
            hyphanet_client = FcpClient(
                "127.0.0.1",
                ports.hyphanet_fcp,
                "hyphanet-interop-handshake",
                layout.transcripts_dir / "hyphanet.fcp.txt",
            )
            add_artifact(summary, layout, layout.transcripts_dir / "cryptad.fcp.txt")
            add_artifact(summary, layout, layout.transcripts_dir / "hyphanet.fcp.txt")
            cryptad_reference = get_node_reference(cryptad_client, "cryptad-getnode")
            hyphanet_reference = get_node_reference(hyphanet_client, "hyphanet-getnode")
            record_json_artifact(summary, layout, "cryptad-node-hello.json", cryptad_client.hello.fields if cryptad_client.hello else {})
            record_json_artifact(summary, layout, "hyphanet-node-hello.json", hyphanet_client.hello.fields if hyphanet_client.hello else {})
            record_json_artifact(summary, layout, "cryptad-node-reference.json", cryptad_reference)
            record_json_artifact(summary, layout, "hyphanet-node-reference.json", hyphanet_reference)
            record_text_artifact(summary, layout, "cryptad-node-reference.fref", format_field_set(cryptad_reference))
            record_text_artifact(summary, layout, "hyphanet-node-reference.fref", format_field_set(hyphanet_reference))
            summary["node_references"] = {
                "cryptad_identity": cryptad_reference.get("identity"),
                "hyphanet_identity": hyphanet_reference.get("identity"),
            }
            flow_success(summary, flow)
            write_summary(layout, summary)
        except Exception:
            flow_failure(summary, flow)
            raise

        flow = "peer_exchange"
        try:
            begin_flow(summary, flow)
            log_progress("Importing peers on both nodes...")
            add_peer(cryptad_client, "cryptad-add-peer", hyphanet_reference)
            add_peer(hyphanet_client, "hyphanet-add-peer", cryptad_reference)
            cryptad_peers, hyphanet_peers = wait_for_peer_connection(
                cryptad_client,
                hyphanet_client,
                str(cryptad_reference["identity"]),
                str(hyphanet_reference["identity"]),
                args.peer_timeout_seconds,
            )
            record_json_artifact(summary, layout, "cryptad-peers-after-add.json", cryptad_peers)
            record_json_artifact(summary, layout, "hyphanet-peers-after-add.json", hyphanet_peers)

            peer_mutation_mode = os.environ.get("INTEROP_VALIDATE_PEER_MUTATION", "modify")
            if peer_mutation_mode == "modify":
                log_progress("Validating ModifyPeer disable/re-enable on Cryptad...")
                disabled_peer = modify_peer(
                    cryptad_client,
                    "cryptad-disable-hyphanet",
                    str(hyphanet_reference["identity"]),
                    {"IsDisabled": "true"},
                )
                record_json_artifact(
                    summary, layout, "cryptad-peer-after-disable.json", disabled_peer
                )
                enabled_peer = modify_peer(
                    cryptad_client,
                    "cryptad-enable-hyphanet",
                    str(hyphanet_reference["identity"]),
                    {"IsDisabled": "false"},
                )
                record_json_artifact(
                    summary, layout, "cryptad-peer-after-enable.json", enabled_peer
                )
                cryptad_peers, hyphanet_peers = wait_for_peer_connection(
                    cryptad_client,
                    hyphanet_client,
                    str(cryptad_reference["identity"]),
                    str(hyphanet_reference["identity"]),
                    args.peer_timeout_seconds,
                )
                record_json_artifact(
                    summary, layout, "cryptad-peers-after-modify-enable.json", cryptad_peers
                )
            elif peer_mutation_mode == "remove-readd":
                log_progress("Validating RemovePeer and re-add on Cryptad...")
                remove_peer(cryptad_client, "cryptad-remove-hyphanet", str(hyphanet_reference["identity"]))
                wait_for_peer_absent(cryptad_client, str(hyphanet_reference["identity"]), 30)
                add_peer(cryptad_client, "cryptad-readd-hyphanet", hyphanet_reference)
                cryptad_peers, hyphanet_peers = wait_for_peer_connection(
                    cryptad_client,
                    hyphanet_client,
                    str(cryptad_reference["identity"]),
                    str(hyphanet_reference["identity"]),
                    args.peer_timeout_seconds,
                )
                record_json_artifact(summary, layout, "cryptad-peers-after-readd.json", cryptad_peers)
            elif peer_mutation_mode not in {"0", "false", "none", "skip"}:
                raise InteropFailure(
                    "INTEROP_VALIDATE_PEER_MUTATION must be modify, remove-readd, none, or 0"
                )
            summary["peer_exchange"] = {"mutation_validation": peer_mutation_mode}
            flow_success(summary, flow)
            write_summary(layout, summary)
        except Exception:
            flow_failure(summary, flow)
            raise

        log_progress("Reconnecting fresh FCP sessions for content flows...")
        cryptad_client.close()
        hyphanet_client.close()
        cryptad_client = FcpClient(
            "127.0.0.1",
            ports.cryptad_fcp,
            "cryptad-interop-content",
            layout.transcripts_dir / "cryptad.fcp.txt",
        )
        hyphanet_client = FcpClient(
            "127.0.0.1",
            ports.hyphanet_fcp,
            "hyphanet-interop-content",
            layout.transcripts_dir / "hyphanet.fcp.txt",
        )
        payload_seed = hashlib.sha256(
            (str(cryptad_reference["identity"]) + str(hyphanet_reference["identity"])).encode(
                "utf-8"
            )
        ).hexdigest()[:16]
        summary["payload_seed"] = payload_seed
        chk_payload_from_cryptad = (
            f"Crypta interop CHK payload cryptad-to-hyphanet seed={payload_seed}\n".encode()
        )
        chk_payload_from_hyphanet = (
            f"Crypta interop CHK payload hyphanet-to-cryptad seed={payload_seed}\n".encode()
        )
        ssk_payload_from_cryptad = (
            f"Crypta interop SSK payload cryptad-to-hyphanet seed={payload_seed}\n".encode()
        )
        ssk_payload_from_hyphanet = (
            f"Crypta interop SSK payload hyphanet-to-cryptad seed={payload_seed}\n".encode()
        )
        usk_payloads_from_cryptad = (
            (
                0,
                f"Crypta interop USK edition 0 payload cryptad-to-hyphanet seed={payload_seed}\n".encode(),
            ),
            (
                1,
                f"Crypta interop USK edition 1 payload cryptad-to-hyphanet seed={payload_seed}\n".encode(),
            ),
        )
        usk_payload_from_cryptad_ed1 = usk_payloads_from_cryptad[1][1]
        usk_payloads_from_hyphanet = (
            (
                0,
                f"Crypta interop USK edition 0 payload hyphanet-to-cryptad seed={payload_seed}\n".encode(),
            ),
            (
                1,
                f"Crypta interop USK edition 1 payload hyphanet-to-cryptad seed={payload_seed}\n".encode(),
            ),
        )

        flow = "chk_cross_fetch"
        try:
            begin_flow(summary, flow)
            log_progress("Running CHK cross-node put/get in both directions...")
            payload = chk_payload_from_cryptad
            chk_uri_from_cryptad = put_and_wait_for_success(
                cryptad_client,
                "cryptad-put-chk",
                "CHK@",
                payload,
                None,
                local_request_only=True,
            )
            ensure_content_peers_connected(
                cryptad_client,
                hyphanet_client,
                cryptad_reference,
                hyphanet_reference,
                args.peer_timeout_seconds,
                "Hyphanet CHK fetch from Cryptad",
            )
            fetched = fetch_direct_until_available(
                "127.0.0.1",
                ports.hyphanet_fcp,
                "hyphanet-fetch-cryptad-chk",
                layout.transcripts_dir / "hyphanet.fcp.txt",
                "hyphanet-fetch-cryptad-chk",
                chk_uri_from_cryptad,
                args.request_timeout_seconds,
            )
            assert_payload("Hyphanet fetched Cryptad CHK", fetched, payload)
            record_uri(summary, flow, "cryptad-to-hyphanet", "CHK", chk_uri_from_cryptad)

            payload = chk_payload_from_hyphanet
            chk_uri_from_hyphanet = put_and_wait_for_success(
                hyphanet_client,
                "hyphanet-put-chk",
                "CHK@",
                payload,
                None,
                local_request_only=False,
            )
            ensure_content_peers_connected(
                cryptad_client,
                hyphanet_client,
                cryptad_reference,
                hyphanet_reference,
                args.peer_timeout_seconds,
                "Cryptad CHK fetch from Hyphanet",
            )
            fetched = fetch_direct_until_available(
                "127.0.0.1",
                ports.cryptad_fcp,
                "cryptad-fetch-hyphanet-chk",
                layout.transcripts_dir / "cryptad.fcp.txt",
                "cryptad-fetch-hyphanet-chk",
                chk_uri_from_hyphanet,
                args.request_timeout_seconds,
            )
            assert_payload("Cryptad fetched Hyphanet CHK", fetched, payload)
            record_uri(summary, flow, "hyphanet-to-cryptad", "CHK", chk_uri_from_hyphanet)
            flow_success(summary, flow)
            write_summary(layout, summary)
        except Exception:
            flow_failure(summary, flow)
            raise

        flow = "ssk_cross_fetch"
        try:
            begin_flow(summary, flow)
            log_progress("Running SSK cross-node put/get in both directions...")
            insert_uri, request_uri = generate_ssk(
                hyphanet_client, "hyphanet-generate-ssk-for-cryptad-put"
            )
            private_keys.append(
                {
                    "flow": flow,
                    "node": "hyphanet",
                    "purpose": "cryptad-to-hyphanet",
                    "insert_uri": insert_uri,
                    "request_uri": request_uri,
                }
            )
            ssk_insert = ssk_with_name(insert_uri, "interop-ssk-cryptad")
            ssk_request_from_cryptad = ssk_with_name(request_uri, "interop-ssk-cryptad")
            payload = ssk_payload_from_cryptad
            put_and_wait_for_success(
                cryptad_client,
                "cryptad-put-ssk",
                ssk_insert,
                payload,
                None,
                local_request_only=True,
                uri_fallback=ssk_request_from_cryptad,
            )
            ensure_content_peers_connected(
                cryptad_client,
                hyphanet_client,
                cryptad_reference,
                hyphanet_reference,
                args.peer_timeout_seconds,
                "Hyphanet SSK fetch from Cryptad",
            )
            fetched = fetch_direct_until_available(
                "127.0.0.1",
                ports.hyphanet_fcp,
                "hyphanet-fetch-cryptad-ssk",
                layout.transcripts_dir / "hyphanet.fcp.txt",
                "hyphanet-fetch-cryptad-ssk",
                ssk_request_from_cryptad,
                args.request_timeout_seconds,
            )
            assert_payload("Hyphanet fetched Cryptad SSK", fetched, payload)
            record_uri(summary, flow, "cryptad-to-hyphanet", "SSK", ssk_request_from_cryptad)

            insert_uri, request_uri = generate_ssk(
                cryptad_client, "cryptad-generate-ssk-for-hyphanet-put"
            )
            private_keys.append(
                {
                    "flow": flow,
                    "node": "cryptad",
                    "purpose": "hyphanet-to-cryptad",
                    "insert_uri": insert_uri,
                    "request_uri": request_uri,
                }
            )
            ssk_insert = ssk_with_name(insert_uri, "interop-ssk-hyphanet")
            ssk_request_from_hyphanet = ssk_with_name(request_uri, "interop-ssk-hyphanet")
            payload = ssk_payload_from_hyphanet
            put_and_wait_for_success(
                hyphanet_client,
                "hyphanet-put-ssk",
                ssk_insert,
                payload,
                None,
                local_request_only=False,
                uri_fallback=ssk_request_from_hyphanet,
            )
            ensure_content_peers_connected(
                cryptad_client,
                hyphanet_client,
                cryptad_reference,
                hyphanet_reference,
                args.peer_timeout_seconds,
                "Cryptad SSK fetch from Hyphanet",
            )
            fetched = fetch_direct_until_available(
                "127.0.0.1",
                ports.cryptad_fcp,
                "cryptad-fetch-hyphanet-ssk",
                layout.transcripts_dir / "cryptad.fcp.txt",
                "cryptad-fetch-hyphanet-ssk",
                ssk_request_from_hyphanet,
                args.request_timeout_seconds,
            )
            assert_payload("Cryptad fetched Hyphanet SSK", fetched, payload)
            record_uri(summary, flow, "hyphanet-to-cryptad", "SSK", ssk_request_from_hyphanet)
            flow_success(summary, flow)
            write_summary(layout, summary)
        except Exception:
            flow_failure(summary, flow)
            raise

        flow = "usk_smoke"
        try:
            begin_flow(summary, flow)
            log_progress("Running USK edition smoke in both directions...")
            insert_uri, request_uri = generate_ssk(
                hyphanet_client, "hyphanet-generate-usk-for-cryptad-put"
            )
            private_keys.append(
                {
                    "flow": flow,
                    "node": "hyphanet",
                    "purpose": "cryptad-to-hyphanet",
                    "insert_uri": insert_uri,
                    "request_uri": request_uri,
                }
            )
            site = "interop-usk-cryptad"
            usk_insert_base_from_cryptad = insert_uri
            usk_request_base_from_cryptad = request_uri
            usk_site_from_cryptad = site
            for edition, text in usk_payloads_from_cryptad:
                put_and_wait_for_success(
                    cryptad_client,
                    f"cryptad-put-usk-{edition}",
                    usk_from_ssk(insert_uri, site, edition),
                    text,
                    None,
                    local_request_only=True,
                    uri_fallback=usk_from_ssk(request_uri, site, edition),
                )
                ensure_content_peers_connected(
                    cryptad_client,
                    hyphanet_client,
                    cryptad_reference,
                    hyphanet_reference,
                    args.peer_timeout_seconds,
                    f"Hyphanet USK edition {edition} fetch from Cryptad",
                )
                fetched = fetch_direct_until_available(
                    "127.0.0.1",
                    ports.hyphanet_fcp,
                    f"hyphanet-fetch-cryptad-usk-{edition}",
                    layout.transcripts_dir / "hyphanet.fcp.txt",
                    f"hyphanet-fetch-cryptad-usk-{edition}",
                    usk_from_ssk(request_uri, site, edition),
                    args.request_timeout_seconds,
                )
                assert_payload(f"Hyphanet fetched Cryptad USK edition {edition}", fetched, text)
            usk_request_from_cryptad_ed1 = usk_from_ssk(request_uri, site, 1)
            record_uri(summary, flow, "cryptad-to-hyphanet", "USK", usk_request_from_cryptad_ed1)

            insert_uri, request_uri = generate_ssk(
                cryptad_client, "cryptad-generate-usk-for-hyphanet-put"
            )
            private_keys.append(
                {
                    "flow": flow,
                    "node": "cryptad",
                    "purpose": "hyphanet-to-cryptad",
                    "insert_uri": insert_uri,
                    "request_uri": request_uri,
                }
            )
            site = "interop-usk-hyphanet"
            for edition, text in usk_payloads_from_hyphanet:
                put_and_wait_for_success(
                    hyphanet_client,
                    f"hyphanet-put-usk-{edition}",
                    usk_from_ssk(insert_uri, site, edition),
                    text,
                    None,
                    local_request_only=False,
                    uri_fallback=usk_from_ssk(request_uri, site, edition),
                )
                ensure_content_peers_connected(
                    cryptad_client,
                    hyphanet_client,
                    cryptad_reference,
                    hyphanet_reference,
                    args.peer_timeout_seconds,
                    f"Cryptad USK edition {edition} fetch from Hyphanet",
                )
                fetched = fetch_direct_until_available(
                    "127.0.0.1",
                    ports.cryptad_fcp,
                    f"cryptad-fetch-hyphanet-usk-{edition}",
                    layout.transcripts_dir / "cryptad.fcp.txt",
                    f"cryptad-fetch-hyphanet-usk-{edition}",
                    usk_from_ssk(request_uri, site, edition),
                    args.request_timeout_seconds,
                )
                assert_payload(f"Cryptad fetched Hyphanet USK edition {edition}", fetched, text)
            usk_request_from_hyphanet_ed1 = usk_from_ssk(request_uri, site, 1)
            record_uri(summary, flow, "hyphanet-to-cryptad", "USK", usk_request_from_hyphanet_ed1)
            flow_success(summary, flow)
            write_summary(layout, summary)
        except Exception:
            flow_failure(summary, flow)
            raise

        if "usk_subscribe_soak" in enabled_flows:
            flow = "usk_subscribe_soak"
            try:
                begin_flow(summary, flow)
                if not (
                    usk_insert_base_from_cryptad
                    and usk_request_base_from_cryptad
                    and usk_site_from_cryptad
                ):
                    raise InteropFailure("USK smoke did not produce a reusable Cryptad USK key")
                log_progress("Running extended SubscribeUSK soak flow...")
                soak_details = run_usk_subscribe_soak(
                    layout,
                    ports,
                    usk_insert_base_from_cryptad,
                    usk_request_base_from_cryptad,
                    usk_site_from_cryptad,
                    payload_seed,
                    args.soak_duration_seconds,
                    args.soak_poll_interval_seconds,
                    args.request_timeout_seconds,
                )
                soak_artifact = record_json_artifact(
                    summary, layout, "usk-subscribe-soak.json", soak_details
                )
                transcripts = soak_details.get("transcripts", {})
                if isinstance(transcripts, dict):
                    for transcript in transcripts.values():
                        add_artifact(summary, layout, layout.out_dir / str(transcript))
                soak_details["artifact"] = relative_artifact(layout, soak_artifact)
                flow_success(summary, flow, soak_details)
                write_summary(layout, summary)
            except Exception as exc:
                flow_failure(summary, flow, {"error": str(exc)})
                write_summary(layout, summary)
                raise

        if "persistent_request_replay" in enabled_flows:
            flow = "persistent_request_replay"
            try:
                begin_flow(summary, flow)
                log_progress("Starting extended persistent request replay before restart...")
                persistent_replay = start_persistent_request_replay(
                    layout,
                    ports,
                    hyphanet_client,
                    payload_seed,
                    args.request_timeout_seconds,
                )
                private_keys.append(
                    {
                        "flow": flow,
                        "node": "hyphanet",
                        "purpose": "persistent-replay-publish-after-restart",
                        "insert_uri": str(persistent_replay["insert_uri"]),
                        "request_uri": str(persistent_replay["request_uri"]),
                    }
                )
                record_json_artifact(
                    summary,
                    layout,
                    "persistent-requests-before-restart.json",
                    persistent_replay["before_restart_requests"],
                )
                add_artifact(
                    summary,
                    layout,
                    layout.out_dir / str(persistent_replay["transcript"]),
                )
                persistent_flow = summary["flows"][flow]
                assert isinstance(persistent_flow, dict)
                persistent_flow.update(
                    {
                        "request_identifier": persistent_replay["request_identifier"],
                        "present_before_restart": persistent_replay[
                            "present_before_restart"
                        ],
                        "present_after_restart": False,
                        "completed_after_restart": False,
                        "transcript": persistent_replay["transcript"],
                    }
                )
                write_summary(layout, summary)
            except Exception as exc:
                flow_failure(summary, flow, {"error": str(exc)})
                write_summary(layout, summary)
                raise

        flow = "restart_recovery"
        try:
            begin_flow(summary, flow)
            log_progress("Running Cryptad restart and recovery flow...")
            persistent_before = list_persistent_requests(cryptad_client, "cryptad-list-persistent-before-restart")
            record_json_artifact(summary, layout, "cryptad-persistent-requests-before-restart.json", persistent_before)
            cryptad_client.close()
            cryptad_client = None
            terminate_node(cryptad_runtime)
            log_progress("Restarting Cryptad node...")
            cryptad_runtime = launch_cryptad(
                args.cryptad_dist_dir.resolve(),
                layout.cryptad_dir,
                layout,
                ports,
                label="cryptad-restart",
                enable_opennet=args.enable_opennet,
            )
            nodes.append(cryptad_runtime)
            add_artifact(summary, layout, cryptad_runtime.stdout_path)
            add_artifact(summary, layout, cryptad_runtime.stderr_path)
            wait_for_fcp(
                "127.0.0.1",
                ports.cryptad_fcp,
                args.startup_timeout_seconds,
                [cryptad_runtime, hyphanet_runtime],
            )
            cryptad_client = FcpClient(
                "127.0.0.1",
                ports.cryptad_fcp,
                "cryptad-interop-after-restart",
                layout.transcripts_dir / "cryptad.fcp.txt",
            )
            restarted_reference = get_node_reference(cryptad_client, "cryptad-getnode-after-restart")
            if restarted_reference.get("identity") != cryptad_reference.get("identity"):
                raise InteropFailure("Cryptad identity changed after restart")
            cryptad_peers, hyphanet_peers = wait_for_peer_connection(
                cryptad_client,
                hyphanet_client,
                str(cryptad_reference["identity"]),
                str(hyphanet_reference["identity"]),
                args.peer_timeout_seconds,
            )
            record_json_artifact(summary, layout, "cryptad-peers-after-restart.json", cryptad_peers)
            record_json_artifact(summary, layout, "hyphanet-peers-after-cryptad-restart.json", hyphanet_peers)
            persistent_after = list_persistent_requests(cryptad_client, "cryptad-list-persistent-after-restart")
            record_json_artifact(summary, layout, "cryptad-persistent-requests-after-restart.json", persistent_after)
            if persistent_replay is not None:
                persistent_replay_after = list_persistent_replay_requests(
                    layout,
                    ports,
                    persistent_replay,
                    "cryptad-list-persistent-replay-after-restart",
                )
                record_json_artifact(
                    summary,
                    layout,
                    "persistent-requests-after-restart.json",
                    persistent_replay_after,
                )
                persistent_replay["after_restart_requests"] = persistent_replay_after
                persistent_replay["present_after_restart"] = (
                    find_persistent_request(
                        persistent_replay_after, str(persistent_replay["request_identifier"])
                    )
                    is not None
                )
                persistent_flow = summary["flows"]["persistent_request_replay"]
                assert isinstance(persistent_flow, dict)
                persistent_flow["present_after_restart"] = persistent_replay[
                    "present_after_restart"
                ]
                write_summary(layout, summary)

            restart_fetch_timeout = args.request_timeout_seconds * 2
            if chk_uri_from_cryptad:
                payload = fetch_direct_until_available(
                    "127.0.0.1",
                    ports.hyphanet_fcp,
                    "hyphanet-refetch-cryptad-chk-after-restart",
                    layout.transcripts_dir / "hyphanet.fcp.txt",
                    "hyphanet-refetch-cryptad-chk-after-restart",
                    chk_uri_from_cryptad,
                    restart_fetch_timeout,
                    ignore_ds=True,
                )
                assert_payload(
                    "Hyphanet refetched Cryptad CHK after restart",
                    payload,
                    chk_payload_from_cryptad,
                )
            if ssk_request_from_cryptad:
                payload = fetch_direct_until_available(
                    "127.0.0.1",
                    ports.hyphanet_fcp,
                    "hyphanet-refetch-cryptad-ssk-after-restart",
                    layout.transcripts_dir / "hyphanet.fcp.txt",
                    "hyphanet-refetch-cryptad-ssk-after-restart",
                    ssk_request_from_cryptad,
                    restart_fetch_timeout,
                    ignore_ds=True,
                )
                assert_payload(
                    "Hyphanet refetched Cryptad SSK after restart",
                    payload,
                    ssk_payload_from_cryptad,
                )
            if usk_request_from_cryptad_ed1:
                usk_edition_ssk_from_cryptad = ssk_for_usk(usk_request_from_cryptad_ed1)
                payload = fetch_direct_until_available(
                    "127.0.0.1",
                    ports.hyphanet_fcp,
                    "hyphanet-refetch-cryptad-usk-ssk-after-restart",
                    layout.transcripts_dir / "hyphanet.fcp.txt",
                    "hyphanet-refetch-cryptad-usk-ssk-after-restart",
                    usk_edition_ssk_from_cryptad,
                    restart_fetch_timeout,
                    ignore_ds=True,
                )
                assert_payload(
                    "Hyphanet refetched Cryptad USK edition 1 after restart",
                    payload,
                    usk_payload_from_cryptad_ed1,
                )
            summary["restart_recovery_checks"] = [
                "cryptad_fcp_reconnected",
                "cryptad_identity_stable",
                "peer_relationship_reconnected",
                "persistent_requests_listed_before_and_after_restart",
                "hyphanet_refetched_cryptad_chk_after_restart",
                "hyphanet_refetched_cryptad_ssk_after_restart",
                "hyphanet_refetched_cryptad_usk_after_restart",
            ]
            if persistent_replay is not None:
                try:
                    log_progress("Completing extended persistent request replay after restart...")
                    completion = complete_persistent_request_replay(
                        layout,
                        ports,
                        hyphanet_client,
                        persistent_replay,
                        args.request_timeout_seconds,
                    )
                    persistent_replay.update(completion)
                    record_json_artifact(
                        summary,
                        layout,
                        "persistent-requests-after-completion.json",
                        completion["after_completion_requests"],
                    )
                    replay_artifact_value = {
                        "request_identifier": persistent_replay["request_identifier"],
                        "present_before_restart": persistent_replay[
                            "present_before_restart"
                        ],
                        "present_after_restart": persistent_replay[
                            "present_after_restart"
                        ],
                        "completed_after_restart": completion[
                            "completed_after_restart"
                        ],
                        "duration_seconds": completion["duration_seconds"],
                        "target_edition": persistent_replay["target_edition"],
                        "payload_sha256": completion["payload_sha256"],
                        "transcript": persistent_replay["transcript"],
                        "remove_result": completion["remove_result"],
                    }
                    replay_artifact = record_json_artifact(
                        summary,
                        layout,
                        "persistent-request-replay.json",
                        replay_artifact_value,
                    )
                    replay_artifact_value["artifact"] = relative_artifact(
                        layout, replay_artifact
                    )
                    flow_success(
                        summary,
                        "persistent_request_replay",
                        replay_artifact_value,
                    )
                except Exception as exc:
                    flow_failure(
                        summary,
                        "persistent_request_replay",
                        {"error": str(exc)},
                    )
                    write_summary(layout, summary)
                    raise
            flow_success(summary, flow)
            write_summary(layout, summary)
        except Exception:
            flow_failure(summary, flow)
            raise

        private_keys_path = layout.artifacts_dir / "private-insert-uris.json"
        write_json(private_keys_path, private_keys, mode=0o600)
        add_artifact(summary, layout, private_keys_path)
        summary["status"] = "success"
        summary["elapsed_seconds"] = round(time.time() - started_at, 3)
        summary["processes"] = process_statuses(nodes)
        write_interop_report(layout, summary)
        write_summary(layout, summary)
        print(f"Interop {args.mode} passed in {summary['elapsed_seconds']}s")
        print(f"Diagnostics directory: {layout.out_dir}")
        return 0
    except Exception as exc:
        summary["status"] = "failure"
        summary["failure_reason"] = str(exc)
        fail_running_flows(summary, str(exc))
        summary["elapsed_seconds"] = round(time.time() - started_at, 3)
        summary["processes"] = process_statuses(nodes)
        if private_keys:
            private_keys_path = layout.artifacts_dir / "private-insert-uris.json"
            write_json(private_keys_path, private_keys, mode=0o600)
            add_artifact(summary, layout, private_keys_path)
        write_interop_report(layout, summary)
        write_summary(layout, summary)
        print(f"Interop {args.mode} failed: {exc}", file=sys.stderr)
        print(f"Diagnostics directory: {layout.out_dir}", file=sys.stderr)
        return 1
    finally:
        signal.alarm(0)
        for client in (cryptad_client, hyphanet_client):
            if client is not None:
                try:
                    client.close()
                except Exception:
                    pass
        if not args.keep_workdir:
            for node in reversed(nodes):
                try:
                    terminate_node(node)
                except Exception:
                    pass
        else:
            pid_file = layout.artifacts_dir / "kept-processes.json"
            write_json(pid_file, process_statuses(nodes))
        try:
            summary["processes"] = process_statuses(nodes)
            write_summary(layout, summary)
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(run())

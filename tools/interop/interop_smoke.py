#!/usr/bin/env python3
"""Hyphanet/Cryptad interoperability gate for CI and release validation."""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
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
FLOW_NAMES = (
    "handshake",
    "peer_exchange",
    "chk_cross_fetch",
    "ssk_cross_fetch",
    "usk_smoke",
    "restart_recovery",
)
SENSITIVE_FIELDS = {
    "InsertURI",
    "PrivateURI",
    "SplitfileCryptoKey",
    "OverrideSplitfileCryptoKey",
}
POTENTIALLY_PRIVATE_URI_PREFIXES = ("SSK@", "USK@")
HYPHANET_VERSIONED_JAR_RE = re.compile(
    r"^(?P<base>.+)-"
    r"(?P<version>\d+(?:\.\d+)+[0-9A-Za-z._-]*)"
    r"\+(?P<build>[0-9A-Za-z._-]+)\.jar$"
)


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
    write_json(path, value)
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


def redacted_value(key: str, value: str) -> str:
    if key in SENSITIVE_FIELDS:
        return "<redacted>"
    if key == "URI" and value.startswith(POTENTIALLY_PRIVATE_URI_PREFIXES):
        return "<redacted-uri>"
    return value


def redacted_fields(fields: dict[str, str]) -> dict[str, str]:
    return {key: redacted_value(key, value) for key, value in fields.items()}


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


def ensure_ports_available(ports: Ports) -> None:
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


def make_cryptad_config(base_dir: Path, ports: Ports) -> Path:
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
node.opennet.enabled=false
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


def make_hyphanet_config(base_dir: Path, ports: Ports) -> Path:
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
node.opennet.enabled=false
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


def verified_download(url: str, expected_sha256: str, cache_dir: Path) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    parsed_name = Path(urlparse(url).path).name
    if not parsed_name:
        raise InteropFailure(f"Cannot determine baseline asset name from URL: {url}")
    asset_path = cache_dir / parsed_name
    temp_asset_path = asset_path.with_name(asset_path.name + ".download")

    def download_asset() -> None:
        temp_asset_path.unlink(missing_ok=True)
        urlretrieve(url, temp_asset_path)
        downloaded_sha256 = sha256sum(temp_asset_path)
        if downloaded_sha256 != expected_sha256:
            temp_asset_path.unlink(missing_ok=True)
            raise InteropFailure(
                f"Hyphanet baseline checksum mismatch for {url}: "
                f"expected {expected_sha256}, got {downloaded_sha256}"
            )
        temp_asset_path.replace(asset_path)

    if asset_path.exists():
        actual_sha256 = sha256sum(asset_path)
        if actual_sha256 != expected_sha256:
            asset_path.unlink()
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
        extract_root = cache_dir / "hyphanet-root"
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
) -> NodeRuntime:
    config_file = make_cryptad_config(node_dir, ports)
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
) -> NodeRuntime:
    config_file = make_hyphanet_config(node_dir, ports)
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


def log_progress(message: str) -> None:
    print(message, flush=True)


def flow_success(summary: dict[str, object], flow_name: str) -> None:
    flows = summary["flows"]
    assert isinstance(flows, dict)
    flows[flow_name] = "success"


def flow_failure(summary: dict[str, object], flow_name: str) -> None:
    flows = summary["flows"]
    assert isinstance(flows, dict)
    flows[flow_name] = "failure"


def write_summary(layout: Layout, summary: dict[str, object]) -> None:
    write_json(layout.out_dir / "summary.json", summary)


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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a Hyphanet/Cryptad interop gate.")
    parser.add_argument("--self-test", action="store_true")
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
    args = parser.parse_args()
    if not args.self_test:
        missing = [
            name
            for name in ("workspace_root", "cryptad_dist_dir", "out_dir", "download_cache_dir")
            if getattr(args, name) is None
        ]
        if missing:
            parser.error(f"missing required arguments: {', '.join('--' + item.replace('_', '-') for item in missing)}")
    return args


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

    started_at = time.time()
    summary: dict[str, object] = {
        "status": "failure",
        "flows": {name: "skipped" for name in FLOW_NAMES},
        "crypta": {"fcp_port": ports.cryptad_fcp, "fnp_port": ports.cryptad_fnp},
        "hyphanet": {
            "fcp_port": ports.hyphanet_fcp,
            "fnp_port": ports.hyphanet_fnp,
            "baseline_version": baseline_version(),
        },
        "uris": [],
        "artifacts": [],
        "workspace_root": str(args.workspace_root.resolve()),
        "cryptad_dist_dir": str(args.cryptad_dist_dir.resolve()),
        "ports": {
            "cryptad_fnp": ports.cryptad_fnp,
            "cryptad_fcp": ports.cryptad_fcp,
            "hyphanet_fnp": ports.hyphanet_fnp,
            "hyphanet_fcp": ports.hyphanet_fcp,
        },
        "restart_recovery_level": "restart-and-refetch",
    }

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
        record_json_artifact(
            summary,
            layout,
            "port-assignments.json",
            summary["ports"],
        )

        log_progress("Starting Cryptad node...")
        cryptad_runtime = launch_cryptad(args.cryptad_dist_dir.resolve(), layout.cryptad_dir, layout, ports)
        nodes.append(cryptad_runtime)
        add_artifact(summary, layout, cryptad_runtime.stdout_path)
        add_artifact(summary, layout, cryptad_runtime.stderr_path)
        add_artifact(summary, layout, cryptad_runtime.config_file)

        log_progress("Starting Hyphanet node...")
        hyphanet_runtime = launch_hyphanet(baseline, layout.hyphanet_dir, layout, ports)
        nodes.append(hyphanet_runtime)
        add_artifact(summary, layout, hyphanet_runtime.stdout_path)
        add_artifact(summary, layout, hyphanet_runtime.stderr_path)
        add_artifact(summary, layout, hyphanet_runtime.config_file)

        log_progress("Waiting for FCP listeners...")
        wait_for_fcp("127.0.0.1", ports.cryptad_fcp, args.startup_timeout_seconds, nodes)
        wait_for_fcp("127.0.0.1", ports.hyphanet_fcp, args.startup_timeout_seconds, nodes)

        flow = "handshake"
        try:
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

        flow = "restart_recovery"
        try:
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
        write_summary(layout, summary)
        print(f"Interop smoke passed in {summary['elapsed_seconds']}s")
        print(f"Diagnostics directory: {layout.out_dir}")
        return 0
    except Exception as exc:
        summary["status"] = "failure"
        summary["failure_reason"] = str(exc)
        summary["elapsed_seconds"] = round(time.time() - started_at, 3)
        summary["processes"] = process_statuses(nodes)
        if private_keys:
            private_keys_path = layout.artifacts_dir / "private-insert-uris.json"
            write_json(private_keys_path, private_keys, mode=0o600)
            add_artifact(summary, layout, private_keys_path)
        write_summary(layout, summary)
        print(f"Interop smoke failed: {exc}", file=sys.stderr)
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

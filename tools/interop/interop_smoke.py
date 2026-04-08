#!/usr/bin/env python3
"""Linux-only Hyphanet/Cryptad interoperability smoke harness."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable
from urllib.request import urlretrieve


DEFAULT_CRYPTAD_FNP_PORT = 19401
DEFAULT_CRYPTAD_FCP_PORT = 19402
DEFAULT_HYPHANET_FNP_PORT = 19501
DEFAULT_HYPHANET_FCP_PORT = 19502
DEFAULT_INTEROP_MAX_HTL = 5
DEFAULT_PEER_TIMEOUT_SECONDS = 120
DEFAULT_REQUEST_TIMEOUT_SECONDS = 120


def load_env_required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


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
        raise RuntimeError(f"wrapper.java.mainclass missing in {conf_path}")

    classpath_entries: list[str] = []
    for _, entry in sorted(classpath.items()):
        resolved_base = resolve_dist_path(dist_root, entry)
        if entry.endswith("*"):
            classpath_entries.extend(str(path) for path in sorted(resolved_base.glob("*.jar")))
        else:
            classpath_entries.append(str(resolved_base))

    if not classpath_entries:
        raise RuntimeError(f"No classpath entries resolved from {conf_path}")

    additional_args = [value for _, value in sorted(additional.items())]
    return main_class, additional_args, classpath_entries


def resolve_dist_path(dist_root: Path, entry: str) -> Path:
    if entry.startswith("/"):
        return dist_root / entry.lstrip("/")
    normalized = entry.replace("\\", "/")
    if normalized.endswith("/*"):
        return dist_root / normalized[:-2]
    return dist_root / normalized


def expand_transcript_payload(payload: bytes | None) -> str:
    if payload is None:
        return ""
    encoded = base64.b64encode(payload).decode("ascii")
    return f"PayloadLength={len(payload)}\nPayloadBase64={encoded}\n"


@dataclass
class NodeRuntime:
    name: str
    base_dir: Path
    config_file: Path
    stdout_path: Path
    stderr_path: Path
    process: subprocess.Popen[bytes]


class FcpClient:
    def __init__(self, host: str, port: int, name: str, transcript_path: Path):
        self.host = host
        self.port = port
        self.name = name
        self.transcript_path = transcript_path
        self.sock = socket.create_connection((host, port), timeout=10)
        self.file = self.sock.makefile("rwb", buffering=0)
        self._log_text(f"CONNECT {host}:{port}\n")
        self.send("ClientHello", {"Name": name, "ExpectedVersion": "2.0"})
        hello = self.read_message(timeout=30)
        if hello["name"] != "NodeHello":
            raise RuntimeError(f"{name} expected NodeHello, got {hello['name']}")

    def close(self) -> None:
        try:
            self.file.close()
        finally:
            self.sock.close()

    def send(self, name: str, fields: Dict[str, str], payload: bytes | None = None) -> None:
        marker = "Data" if payload is not None else "EndMessage"
        self.file.write((name + "\n").encode("utf-8"))
        for key, value in fields.items():
            self.file.write((f"{key}={value}\n").encode("utf-8"))
        self.file.write((marker + "\n").encode("utf-8"))
        if payload is not None:
            self.file.write(payload)
        self._log_message("SEND", name, fields, payload)

    def _read_exact(self, length: int) -> bytes:
        remaining = length
        chunks: list[bytes] = []
        while remaining > 0:
            chunk = self.file.read(remaining)
            if not chunk:
                raise EOFError(
                    f"{self.name} connection closed while reading payload "
                    f"({length - remaining}/{length} bytes received)"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def read_message(self, timeout: int) -> dict[str, object]:
        self.sock.settimeout(timeout)
        name_bytes = self.file.readline()
        if not name_bytes:
            raise EOFError(f"{self.name} connection closed")
        name = name_bytes.decode("utf-8").rstrip("\n")
        fields: dict[str, str] = {}

        while True:
            line_bytes = self.file.readline()
            if not line_bytes:
                raise EOFError(f"{self.name} connection closed mid-message")
            line = line_bytes.decode("utf-8").rstrip("\n")
            if line == "EndMessage":
                message = {"name": name, "fields": fields, "payload": None}
                self._log_message("RECV", name, fields, None)
                return message
            if line == "Data":
                try:
                    length = int(fields["DataLength"])
                except KeyError as exc:
                    raise RuntimeError(f"{self.name} received Data marker without DataLength") from exc
                payload = self._read_exact(length)
                message = {"name": name, "fields": fields, "payload": payload}
                self._log_message("RECV", name, fields, payload)
                return message
            if "=" not in line:
                raise RuntimeError(f"{self.name} received malformed FCP line: {line!r}")
            key, value = line.split("=", 1)
            fields[key] = value

    def read_until(
        self,
        timeout: int,
        target_names: Iterable[str],
        error_names: Iterable[str] = ("ProtocolError",),
    ) -> dict[str, object]:
        wanted = set(target_names)
        errors = set(error_names)
        while True:
            message = self.read_message(timeout)
            if message["name"] in errors:
                raise RuntimeError(f"{self.name} received error message: {message}")
            if message["name"] in wanted:
                return message

    def _log_text(self, text: str) -> None:
        self.transcript_path.parent.mkdir(parents=True, exist_ok=True)
        with self.transcript_path.open("a", encoding="utf-8") as handle:
            handle.write(text)

    def _log_message(
        self,
        direction: str,
        name: str,
        fields: Dict[str, str],
        payload: bytes | None,
    ) -> None:
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        body = "".join(f"{key}={value}\n" for key, value in fields.items())
        if payload is None:
            marker = "EndMessage\n"
        else:
            marker = "Data\n" + expand_transcript_payload(payload)
        self._log_text(f"[{timestamp}] {direction} {name}\n{body}{marker}\n")


def wait_for_fcp(host: str, port: int, timeout_seconds: int) -> None:
    deadline = time.time() + timeout_seconds
    last_error: OSError | None = None
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(1)
    raise RuntimeError(f"Timed out waiting for {host}:{port}: {last_error}")


def ensure_udp_port_available(port: int) -> None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind(("127.0.0.1", port))
    except OSError as exc:
        raise RuntimeError(f"UDP port 127.0.0.1:{port} is already in use") from exc
    finally:
        probe.close()


def ensure_tcp_port_available(port: int) -> None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        probe.bind(("127.0.0.1", port))
    except OSError as exc:
        raise RuntimeError(f"TCP port 127.0.0.1:{port} is already in use") from exc
    finally:
        probe.close()


def ensure_deterministic_ports_available() -> None:
    ensure_udp_port_available(DEFAULT_CRYPTAD_FNP_PORT)
    ensure_tcp_port_available(DEFAULT_CRYPTAD_FCP_PORT)
    ensure_udp_port_available(DEFAULT_HYPHANET_FNP_PORT)
    ensure_tcp_port_available(DEFAULT_HYPHANET_FCP_PORT)


def make_cryptad_config(base_dir: Path, fnp_port: int, fcp_port: int) -> Path:
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
node.listenPort={fnp_port}
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
fcp.port={fcp_port}
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


def make_hyphanet_config(base_dir: Path, fnp_port: int, fcp_port: int) -> Path:
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
node.listenPort={fnp_port}
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
fcp.port={fcp_port}
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


def ensure_hyphanet_asset(cache_dir: Path) -> tuple[Path, Path]:
    release_url = load_env_required("HYPHANET_RELEASE_URL")
    asset_name = load_env_required("HYPHANET_DEB_ASSET")
    expected_sha256 = load_env_required("HYPHANET_DEB_SHA256")

    cache_dir.mkdir(parents=True, exist_ok=True)
    asset_path = cache_dir / asset_name
    temp_asset_path = asset_path.with_name(asset_path.name + ".download")

    def download_asset() -> None:
        if temp_asset_path.exists():
            temp_asset_path.unlink()
        urlretrieve(release_url, temp_asset_path)
        downloaded_sha256 = sha256sum(temp_asset_path)
        if downloaded_sha256 != expected_sha256:
            temp_asset_path.unlink(missing_ok=True)
            raise RuntimeError(
                f"Hyphanet asset checksum mismatch for downloaded {asset_path}: "
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

    extract_root = cache_dir / "hyphanet-root"
    if extract_root.exists():
        shutil.rmtree(extract_root)
    subprocess.run(["dpkg-deb", "-x", str(asset_path), str(extract_root)], check=True)
    materialize_hyphanet_java_symlinks(extract_root)
    return asset_path, extract_root


def materialize_hyphanet_java_symlinks(extract_root: Path) -> None:
    java_dir = extract_root / "usr" / "share" / "java"
    if not java_dir.is_dir():
        return

    version = re.escape(load_env_required("HYPHANET_VERSION"))
    build = re.escape(load_env_required("HYPHANET_BUILD"))
    suffix_pattern = re.compile(rf"-{version}\+{build}\.jar$")
    for jar_path in java_dir.glob("*.jar"):
        match = suffix_pattern.search(jar_path.name)
        if match is None:
            continue
        target_name = jar_path.name[: match.start()] + ".jar"
        target_path = java_dir / target_name
        if not target_path.exists():
            target_path.symlink_to(jar_path.name)


def launch_cryptad(cryptad_dist_dir: Path, node_dir: Path) -> NodeRuntime:
    config_file = make_cryptad_config(node_dir, DEFAULT_CRYPTAD_FNP_PORT, DEFAULT_CRYPTAD_FCP_PORT)
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
    command = [str(cryptad_dist_dir / "bin" / "cryptad")]
    command.extend(
        f"wrapper.app.parameter.{index}={value}" for index, value in enumerate(node_args, start=1)
    )
    stdout_path = node_dir / "stdout.log"
    stderr_path = node_dir / "stderr.log"
    stdout_handle = stdout_path.open("wb")
    stderr_handle = stderr_path.open("wb")
    environment = os.environ.copy()
    if os.geteuid() == 0:
        # The packaged launcher refuses interactive root runs unless explicitly allowed.
        environment["CRYPTAD_ALLOW_ROOT"] = "1"
    process = subprocess.Popen(
        command,
        cwd=node_dir,
        stdout=stdout_handle,
        stderr=stderr_handle,
        env=environment,
        start_new_session=True,
    )
    process._stdout_handle = stdout_handle  # type: ignore[attr-defined]
    process._stderr_handle = stderr_handle  # type: ignore[attr-defined]
    return NodeRuntime("cryptad", node_dir, config_file, stdout_path, stderr_path, process)


def launch_hyphanet(extract_root: Path, node_dir: Path) -> NodeRuntime:
    config_file = make_hyphanet_config(node_dir, DEFAULT_HYPHANET_FNP_PORT, DEFAULT_HYPHANET_FCP_PORT)
    seedsrc = extract_root / "usr" / "share" / "freenet" / "seednodes.fref"
    seeddst = config_file.parent / "noderef" / "seednodes.fref"
    seeddst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(seedsrc, seeddst)

    wrapper_conf = extract_root / "usr" / "share" / "freenet" / "wrapper.conf"
    main_class, wrapper_jvm_args, classpath_entries = parse_wrapper_conf(wrapper_conf, extract_root)
    command = [
        "java",
        "--enable-native-access=ALL-UNNAMED",
        *wrapper_jvm_args,
        "-cp",
        os.pathsep.join(classpath_entries),
        main_class,
        str(config_file),
    ]
    runtime_work_dir = node_dir / "work" / "var" / "lib" / "freenet"
    runtime_work_dir.mkdir(parents=True, exist_ok=True)
    (runtime_work_dir / "tmp").mkdir(parents=True, exist_ok=True)
    stdout_path = node_dir / "stdout.log"
    stderr_path = node_dir / "stderr.log"
    stdout_handle = stdout_path.open("wb")
    stderr_handle = stderr_path.open("wb")
    process = subprocess.Popen(
        command,
        cwd=runtime_work_dir,
        stdout=stdout_handle,
        stderr=stderr_handle,
        start_new_session=True,
    )
    process._stdout_handle = stdout_handle  # type: ignore[attr-defined]
    process._stderr_handle = stderr_handle  # type: ignore[attr-defined]
    return NodeRuntime("hyphanet", node_dir, config_file, stdout_path, stderr_path, process)


def terminate_node(node: NodeRuntime) -> None:
    process = node.process
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=20)
    process._stdout_handle.close()  # type: ignore[attr-defined]
    process._stderr_handle.close()  # type: ignore[attr-defined]


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
    message = client.read_until(DEFAULT_REQUEST_TIMEOUT_SECONDS, {"NodeData"})
    return dict(message["fields"])  # type: ignore[arg-type]


def add_peer(client: FcpClient, identifier: str, reference_fields: Dict[str, str]) -> None:
    add_fields = dict(reference_fields)
    add_fields["Identifier"] = identifier
    add_fields["Trust"] = "NORMAL"
    add_fields["Visibility"] = "YES"
    client.send("AddPeer", add_fields)
    client.read_until(DEFAULT_REQUEST_TIMEOUT_SECONDS, {"Peer"})


def list_peers(client: FcpClient, identifier: str) -> list[dict[str, str]]:
    client.send(
        "ListPeers",
        {"Identifier": identifier, "WithMetadata": "true", "WithVolatile": "true"},
    )
    peers: list[dict[str, str]] = []
    while True:
        message = client.read_message(DEFAULT_REQUEST_TIMEOUT_SECONDS)
        name = message["name"]
        if name == "EndListPeers":
            return peers
        if name == "ProtocolError":
            raise RuntimeError(f"{client.name} received ProtocolError during ListPeers: {message}")
        if name == "Peer":
            peers.append(dict(message["fields"]))  # type: ignore[arg-type]


def wait_for_peer_connection(
    cryptad_client: FcpClient,
    hyphanet_client: FcpClient,
    cryptad_identity: str,
    hyphanet_identity: str,
    timeout_seconds: int,
) -> None:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        cryptad_peers = list_peers(cryptad_client, "cryptad-list")
        hyphanet_peers = list_peers(hyphanet_client, "hyphanet-list")

        cryptad_connected = any(
            peer.get("identity") == hyphanet_identity and peer.get("volatile.status") == "CONNECTED"
            for peer in cryptad_peers
        )
        hyphanet_connected = any(
            peer.get("identity") == cryptad_identity and peer.get("volatile.status") == "CONNECTED"
            for peer in hyphanet_peers
        )
        if cryptad_connected and hyphanet_connected:
            return
        time.sleep(2)

    raise RuntimeError("Darknet peers did not reach CONNECTED on both nodes within timeout")


def build_client_put_fields(
    identifier: str,
    uri: str,
    payload: bytes,
    content_type: str | None,
    *,
    local_request_only: bool = False,
    get_chk_only: bool = False,
) -> dict[str, str]:
    fields = {
        "Identifier": identifier,
        "URI": uri,
        "UploadFrom": "direct",
        "DataLength": str(len(payload)),
        "Persistence": "connection",
        "Verbosity": "256",
        "DontCompress": "true",
        "ExtraInsertsSingleBlock": "0",
        "ExtraInsertsSplitfileHeaderBlock": "0",
    }
    if content_type is not None:
        fields["Metadata.ContentType"] = content_type
    if local_request_only:
        fields["LocalRequestOnly"] = "true"
    if get_chk_only:
        fields["GetCHKOnly"] = "true"
    return fields


def request_put_uri(
    client: FcpClient,
    identifier: str,
    uri: str,
    payload: bytes,
    content_type: str | None,
    *,
    local_request_only: bool = False,
) -> str:
    client.send(
        "ClientPut",
        build_client_put_fields(
            identifier,
            uri,
            payload,
            content_type,
            local_request_only=local_request_only,
            get_chk_only=True,
        ),
        payload=payload,
    )

    generated_uri: str | None = None
    while True:
        message = client.read_message(DEFAULT_REQUEST_TIMEOUT_SECONDS)
        name = message["name"]
        if name in {"URIGenerated", "PutFetchable", "PutSuccessful"}:
            uri_value = message["fields"].get("URI")
            if uri_value is not None:
                generated_uri = str(uri_value)
        if name == "PutSuccessful":
            if generated_uri is None:
                raise RuntimeError(
                    f"{client.name} GetCHKOnly put completed without a URI: {message}"
                )
            return generated_uri
        if name in {"PutFailed", "ProtocolError"}:
            raise RuntimeError(f"{client.name} GetCHKOnly put failed: {message}")


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
    saw_generated_metadata = False
    while True:
        message = client.read_message(DEFAULT_REQUEST_TIMEOUT_SECONDS)
        name = message["name"]
        if name in {"URIGenerated", "PutFetchable", "PutSuccessful"}:
            uri_value = message["fields"].get("URI")
            if uri_value is not None:
                generated_uri = str(uri_value)
        if name == "GeneratedMetadata":
            saw_generated_metadata = True
        if name == "PutSuccessful":
            if generated_uri is None:
                if saw_generated_metadata:
                    raise RuntimeError(
                        f"{client.name} PutSuccessful completed without a URI after "
                        f"GeneratedMetadata; use GetCHKOnly preflight when a metadata-wrapped "
                        f"put needs a fetch URI: {message}"
                    )
                raise RuntimeError(
                    f"{client.name} PutSuccessful did not include a URI: {message}"
                )
            return generated_uri
        if name in {"PutFailed", "ProtocolError"}:
            raise RuntimeError(f"{client.name} put failed: {message}")


def fetch_direct(client: FcpClient, identifier: str, uri: str) -> bytes:
    client.send(
        "ClientGet",
        {
            "Identifier": identifier,
            "URI": uri,
            "ReturnType": "direct",
            "Persistence": "connection",
        },
    )
    while True:
        message = client.read_message(DEFAULT_REQUEST_TIMEOUT_SECONDS)
        name = message["name"]
        if name == "AllData":
            payload = message["payload"]
            if not isinstance(payload, bytes):
                raise RuntimeError(f"{client.name} AllData payload missing")
            return payload
        if name in {"GetFailed", "ProtocolError"}:
            raise RuntimeError(f"{client.name} fetch failed: {message}")


def fetch_direct_until_available(
    host: str,
    port: int,
    client_name: str,
    transcript_path: Path,
    identifier_prefix: str,
    uri: str,
    timeout_seconds: int,
) -> bytes:
    deadline = time.time() + timeout_seconds
    attempt = 0
    last_error: str | None = None
    while time.time() < deadline:
        attempt += 1
        client: FcpClient | None = None
        try:
            client = FcpClient(host, port, f"{client_name}-{attempt}", transcript_path)
            return fetch_direct(client, f"{identifier_prefix}-{attempt}", uri)
        except (OSError, EOFError, RuntimeError) as exc:
            last_error = str(exc)
            time.sleep(2)
        finally:
            if client is not None:
                client.close()
    raise RuntimeError(
        f"Timed out waiting for {uri} to become fetchable; last fetch error: {last_error}"
    )


def generate_ssk(client: FcpClient, identifier: str) -> tuple[str, str]:
    client.send("GenerateSSK", {"Identifier": identifier})
    message = client.read_until(DEFAULT_REQUEST_TIMEOUT_SECONDS, {"SSKKeypair"})
    fields = message["fields"]
    return str(fields["InsertURI"]), str(fields["RequestURI"])  # type: ignore[index]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a Linux-only Hyphanet/Cryptad interop smoke.")
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--cryptad-dist-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--download-cache-dir", type=Path, required=True)
    parser.add_argument(
        "--peer-timeout-seconds", type=int, default=DEFAULT_PEER_TIMEOUT_SECONDS
    )
    parser.add_argument(
        "--request-timeout-seconds", type=int, default=DEFAULT_REQUEST_TIMEOUT_SECONDS
    )
    return parser.parse_args()


def write_summary(path: Path, summary: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def require_linux() -> None:
    if sys.platform != "linux":
        raise RuntimeError("This interoperability smoke harness is Linux-only")


def require_tool(name: str) -> None:
    if shutil.which(name) is None:
        raise RuntimeError(f"Required tool not found on PATH: {name}")


def log_progress(message: str) -> None:
    print(message, flush=True)


def main() -> int:
    require_linux()
    require_tool("dpkg-deb")
    args = parse_args()

    global DEFAULT_REQUEST_TIMEOUT_SECONDS
    DEFAULT_REQUEST_TIMEOUT_SECONDS = args.request_timeout_seconds

    out_dir = args.out_dir.resolve()
    cache_dir = args.download_cache_dir.resolve()
    cryptad_dist_dir = args.cryptad_dist_dir.resolve()
    ensure_clean_dir(out_dir)
    ensure_deterministic_ports_available()

    started_at = time.time()
    summary: dict[str, object] = {
        "startedAtEpochSeconds": started_at,
        "workspaceRoot": str(args.workspace_root.resolve()),
        "cryptadDistDir": str(cryptad_dist_dir),
        "downloadCacheDir": str(cache_dir),
        "hyphanetBuild": load_env_required("HYPHANET_BUILD"),
        "hyphanetVersion": load_env_required("HYPHANET_VERSION"),
        "hyphanetReleaseTag": load_env_required("HYPHANET_RELEASE_TAG"),
        "ports": {
            "cryptadFnp": DEFAULT_CRYPTAD_FNP_PORT,
            "cryptadFcp": DEFAULT_CRYPTAD_FCP_PORT,
            "hyphanetFnp": DEFAULT_HYPHANET_FNP_PORT,
            "hyphanetFcp": DEFAULT_HYPHANET_FCP_PORT,
        },
    }

    cryptad_node_dir = out_dir / "nodes" / "cryptad"
    hyphanet_node_dir = out_dir / "nodes" / "hyphanet"
    transcripts_dir = out_dir / "transcripts"
    nodes: list[NodeRuntime] = []
    cryptad_client: FcpClient | None = None
    hyphanet_client: FcpClient | None = None

    try:
        asset_path, hyphanet_extract_root = ensure_hyphanet_asset(cache_dir)
        summary["hyphanetAsset"] = str(asset_path)
        summary["hyphanetAssetSha256"] = sha256sum(asset_path)

        log_progress("Starting Cryptad node...")
        cryptad_runtime = launch_cryptad(cryptad_dist_dir, cryptad_node_dir)
        nodes.append(cryptad_runtime)

        log_progress("Starting Hyphanet node...")
        hyphanet_runtime = launch_hyphanet(hyphanet_extract_root, hyphanet_node_dir)
        nodes.append(hyphanet_runtime)

        log_progress("Waiting for FCP listeners...")
        wait_for_fcp("127.0.0.1", DEFAULT_CRYPTAD_FCP_PORT, DEFAULT_REQUEST_TIMEOUT_SECONDS)
        wait_for_fcp("127.0.0.1", DEFAULT_HYPHANET_FCP_PORT, DEFAULT_REQUEST_TIMEOUT_SECONDS)

        cryptad_client = FcpClient(
            "127.0.0.1",
            DEFAULT_CRYPTAD_FCP_PORT,
            "cryptad-interop-peering",
            transcripts_dir / "cryptad.fcp.txt",
        )
        hyphanet_client = FcpClient(
            "127.0.0.1",
            DEFAULT_HYPHANET_FCP_PORT,
            "hyphanet-interop-peering",
            transcripts_dir / "hyphanet.fcp.txt",
        )

        log_progress("Exporting darknet noderefs...")
        cryptad_reference = get_node_reference(cryptad_client, "cryptad-getnode")
        hyphanet_reference = get_node_reference(hyphanet_client, "hyphanet-getnode")
        summary["nodeReferences"] = {
            "cryptadIdentity": cryptad_reference.get("identity"),
            "cryptadPhysicalUdp": cryptad_reference.get("physical.udp"),
            "hyphanetIdentity": hyphanet_reference.get("identity"),
            "hyphanetPhysicalUdp": hyphanet_reference.get("physical.udp"),
        }

        log_progress("Importing peers on both nodes...")
        add_peer(cryptad_client, "cryptad-add-peer", hyphanet_reference)
        add_peer(hyphanet_client, "hyphanet-add-peer", cryptad_reference)
        log_progress("Waiting for darknet peers to reach CONNECTED...")
        wait_for_peer_connection(
            cryptad_client,
            hyphanet_client,
            str(cryptad_reference["identity"]),
            str(hyphanet_reference["identity"]),
            args.peer_timeout_seconds,
        )

        log_progress("Reconnecting fresh FCP sessions for data-path smoke...")
        cryptad_client.close()
        cryptad_client = FcpClient(
            "127.0.0.1",
            DEFAULT_CRYPTAD_FCP_PORT,
            "cryptad-interop-data",
            transcripts_dir / "cryptad.fcp.txt",
        )
        hyphanet_client.close()
        hyphanet_client = FcpClient(
            "127.0.0.1",
            DEFAULT_HYPHANET_FCP_PORT,
            "hyphanet-interop-data",
            transcripts_dir / "hyphanet.fcp.txt",
        )

        log_progress("Running CHK insert/fetch: Cryptad -> Hyphanet...")
        chk_payload_from_cryptad = b"cryptad-to-hyphanet-chk\n"
        chk_uri_from_cryptad = put_and_wait_for_success(
            cryptad_client,
            "cryptad-put-chk",
            "CHK@",
            chk_payload_from_cryptad,
            None,
            local_request_only=True,
        )
        fetched_from_hyphanet = fetch_direct_until_available(
            "127.0.0.1",
            DEFAULT_HYPHANET_FCP_PORT,
            "hyphanet-chk-fetch",
            transcripts_dir / "hyphanet.fcp.txt",
            "hyphanet-fetch-chk",
            chk_uri_from_cryptad,
            DEFAULT_REQUEST_TIMEOUT_SECONDS,
        )
        if fetched_from_hyphanet != chk_payload_from_cryptad:
            raise RuntimeError("Hyphanet fetched CHK payload did not match Cryptad insert")

        log_progress("Running CHK insert/fetch: Hyphanet -> Cryptad...")
        chk_payload_from_hyphanet = b"hyphanet-to-cryptad-chk\n"
        chk_uri_from_hyphanet = put_and_wait_for_success(
            hyphanet_client,
            "hyphanet-put-chk",
            "CHK@",
            chk_payload_from_hyphanet,
            None,
            local_request_only=False,
        )
        fetched_from_cryptad = fetch_direct_until_available(
            "127.0.0.1",
            DEFAULT_CRYPTAD_FCP_PORT,
            "cryptad-chk-fetch",
            transcripts_dir / "cryptad.fcp.txt",
            "cryptad-fetch-chk",
            chk_uri_from_hyphanet,
            DEFAULT_REQUEST_TIMEOUT_SECONDS,
        )
        if fetched_from_cryptad != chk_payload_from_hyphanet:
            raise RuntimeError("Cryptad fetched CHK payload did not match Hyphanet insert")

        log_progress("Running SSK keypair/insert/fetch: Hyphanet -> Cryptad...")
        ssk_insert_uri, ssk_request_uri = generate_ssk(hyphanet_client, "hyphanet-generate-ssk")
        ssk_payload = b"hyphanet-to-cryptad-ssk\n"
        put_and_wait_for_success(
            hyphanet_client,
            "hyphanet-put-ssk",
            ssk_insert_uri,
            ssk_payload,
            None,
            local_request_only=False,
        )
        fetched_ssk = fetch_direct_until_available(
            "127.0.0.1",
            DEFAULT_CRYPTAD_FCP_PORT,
            "cryptad-ssk-fetch",
            transcripts_dir / "cryptad.fcp.txt",
            "cryptad-fetch-ssk",
            ssk_request_uri,
            DEFAULT_REQUEST_TIMEOUT_SECONDS,
        )
        if fetched_ssk != ssk_payload:
            raise RuntimeError("Cryptad fetched SSK payload did not match Hyphanet insert")

        summary["artifacts"] = {
            "cryptadStdout": str(cryptad_runtime.stdout_path),
            "cryptadStderr": str(cryptad_runtime.stderr_path),
            "hyphanetStdout": str(hyphanet_runtime.stdout_path),
            "hyphanetStderr": str(hyphanet_runtime.stderr_path),
            "transcriptsDir": str(transcripts_dir),
        }
        summary["results"] = {
            "peerConnection": "ok",
            "chkCryptadToHyphanet": chk_uri_from_cryptad,
            "chkHyphanetToCryptad": chk_uri_from_hyphanet,
            "sskRequestUri": ssk_request_uri,
        }
        summary["status"] = "passed"
        summary["elapsedSeconds"] = round(time.time() - started_at, 3)
        write_summary(out_dir / "summary.json", summary)
        print(f"Interop smoke passed in {summary['elapsedSeconds']}s")
        print(f"Diagnostics directory: {out_dir}")
        return 0
    except Exception as exc:
        summary["status"] = "failed"
        summary["error"] = str(exc)
        summary["elapsedSeconds"] = round(time.time() - started_at, 3)
        write_summary(out_dir / "summary.json", summary)
        print(f"Interop smoke failed: {exc}", file=sys.stderr)
        print(f"Diagnostics directory: {out_dir}", file=sys.stderr)
        return 1
    finally:
        if cryptad_client is not None:
            try:
                cryptad_client.close()
            except Exception:
                pass
        if hyphanet_client is not None:
            try:
                hyphanet_client.close()
            except Exception:
                pass
        for node in nodes:
            terminate_node(node)


if __name__ == "__main__":
    sys.exit(main())

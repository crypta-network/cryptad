#!/usr/bin/env python3
"""Seal and open authenticated Stable backport handoffs for Actions transport."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
from typing import BinaryIO


_ARCHIVE_NAME = "stable-1.0-protected-handoff.tar"
_CIPHERTEXT_NAME = "stable-1.0-protected-handoff.enc"
_MANIFEST_NAME = "stable-1.0-protected-handoff.json"
_KIND = "stable-1.0-protected-handoff"
_MAX_FILES = 64
_MAX_FILE_BYTES = 16 * 1024 * 1024
_MAX_TOTAL_BYTES = 64 * 1024 * 1024
_MAX_MANIFEST_BYTES = 32 * 1024
_PBKDF2_ITERATIONS = 600_000
_MAC_DOMAIN = b"cryptad-stable-backport-protected-handoff-mac-v1\0"
_KEY_DOMAIN = b"cryptad-stable-backport-protected-handoff-mac-key-v1"
_SAFE_FILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_SAFE_BINDING_KEY = re.compile(r"[A-Za-z][A-Za-z0-9]{0,63}")
_SAFE_ENV = re.compile(r"[A-Z][A-Z0-9_]{0,127}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


class HandoffError(RuntimeError):
    """Bounded failure at the protected handoff confidentiality boundary."""


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _load_binding(path: Path) -> dict[str, str]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise HandoffError("protected-handoff-binding-invalid") from exc
    if (
        not isinstance(value, dict)
        or not value
        or len(value) > 32
        or any(
            not isinstance(key, str)
            or _SAFE_BINDING_KEY.fullmatch(key) is None
            or not isinstance(item, str)
            or not item
            or len(item) > 256
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in item)
            for key, item in value.items()
        )
    ):
        raise HandoffError("protected-handoff-binding-invalid")
    return dict(sorted(value.items()))


def _load_key(environment_name: str) -> tuple[str, bytes]:
    if _SAFE_ENV.fullmatch(environment_name) is None:
        raise HandoffError("protected-handoff-key-environment-invalid")
    encoded = os.environ.pop(environment_name, "")
    try:
        key = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise HandoffError("protected-handoff-key-invalid") from exc
    if len(key) != 32 or base64.b64encode(key).decode("ascii") != encoded:
        raise HandoffError("protected-handoff-key-invalid")
    return encoded, key


def _safe_file_name(value: str) -> bool:
    return _SAFE_FILE.fullmatch(value) is not None and value not in {".", ".."}


def _source_files(source: Path) -> list[Path]:
    if source.is_symlink() or not source.is_dir():
        raise HandoffError("protected-handoff-source-invalid")
    files: list[Path] = []
    portable_names: set[str] = set()
    total = 0
    try:
        entries = sorted(source.iterdir(), key=lambda path: path.name)
    except OSError as exc:
        raise HandoffError("protected-handoff-source-invalid") from exc
    for entry in entries:
        try:
            metadata = entry.stat(follow_symlinks=False)
            mode = metadata.st_mode
            size = metadata.st_size
        except OSError as exc:
            raise HandoffError("protected-handoff-source-invalid") from exc
        if (
            not _safe_file_name(entry.name)
            or entry.name.casefold() in portable_names
            or not stat.S_ISREG(mode)
            or entry.is_symlink()
            or metadata.st_nlink != 1
            or size <= 0
            or size > _MAX_FILE_BYTES
        ):
            raise HandoffError("protected-handoff-source-entry-unsafe")
        total += size
        if total > _MAX_TOTAL_BYTES:
            raise HandoffError("protected-handoff-source-too-large")
        files.append(entry)
        portable_names.add(entry.name.casefold())
    if not files or len(files) > _MAX_FILES:
        raise HandoffError("protected-handoff-source-count-invalid")
    return files


def _write_archive(source: Path, destination: Path) -> None:
    files = _source_files(source)
    try:
        with tarfile.open(destination, "x", format=tarfile.USTAR_FORMAT) as archive:
            for path in files:
                information = tarfile.TarInfo(path.name)
                information.size = path.stat(follow_symlinks=False).st_size
                information.mode = 0o600
                information.mtime = 0
                information.uid = 0
                information.gid = 0
                information.uname = ""
                information.gname = ""
                with path.open("rb") as stream:
                    archive.addfile(information, stream)
    except (OSError, tarfile.TarError) as exc:
        raise HandoffError("protected-handoff-archive-write-failed") from exc
    if destination.stat().st_size > _MAX_TOTAL_BYTES + 1024 * 1024:
        raise HandoffError("protected-handoff-archive-too-large")


def _openssl() -> str:
    executable = shutil.which("openssl", path="/usr/bin:/bin")
    if executable is None:
        raise HandoffError("protected-handoff-openssl-unavailable")
    resolved = Path(executable).resolve(strict=True)
    if resolved.parent not in {Path("/usr/bin"), Path("/bin"), Path("/usr/lib/ssl")}:
        raise HandoffError("protected-handoff-openssl-untrusted")
    return str(resolved)


def _crypt(
    source: Path,
    destination: Path,
    encoded_key: str,
    *,
    decrypt: bool,
) -> None:
    try:
        source_path = source.resolve(strict=True)
        destination_path = destination.resolve(strict=False)
    except OSError as exc:
        raise HandoffError("protected-handoff-crypt-path-invalid") from exc
    arguments = [
        _openssl(),
        "enc",
        "-aes-256-ctr",
    ]
    if decrypt:
        arguments.append("-d")
    arguments.extend(
        [
            "-pbkdf2",
            "-iter",
            str(_PBKDF2_ITERATIONS),
            "-md",
            "sha256",
            "-salt",
            "-pass",
            "stdin",
            "-in",
            str(source_path),
            "-out",
            str(destination_path),
        ]
    )
    try:
        completed = subprocess.run(
            arguments,
            input=(encoded_key + "\n").encode("ascii"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=source_path.parent,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        destination.unlink(missing_ok=True)
        raise HandoffError("protected-handoff-crypt-failed") from exc
    if completed.returncode != 0:
        destination.unlink(missing_ok=True)
        raise HandoffError("protected-handoff-crypt-failed")


def _authenticated_document(
    binding: dict[str, str],
    ciphertext_digest: str,
) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "kind": _KIND,
        "binding": binding,
        "cipher": {
            "algorithm": "aes-256-ctr",
            "kdf": "pbkdf2-hmac-sha256",
            "iterations": _PBKDF2_ITERATIONS,
            "format": "openssl-salted",
            "ciphertextFile": _CIPHERTEXT_NAME,
            "ciphertextDigest": ciphertext_digest,
        },
    }


def _tag(
    key: bytes,
    document: dict[str, object],
    ciphertext: bytes,
) -> str:
    mac_key = hmac.new(key, _KEY_DOMAIN, hashlib.sha256).digest()
    value = hmac.new(
        mac_key,
        _MAC_DOMAIN + _canonical_bytes(document) + ciphertext,
        hashlib.sha256,
    ).hexdigest()
    return f"sha256:{value}"


def _seal(source: Path, destination: Path, binding_path: Path, key_env: str) -> None:
    if destination.exists() or destination.is_symlink():
        raise HandoffError("protected-handoff-destination-exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    binding = _load_binding(binding_path)
    encoded_key, key = _load_key(key_env)
    with tempfile.TemporaryDirectory(
        prefix=".stable-backport-seal-",
        dir=destination.parent,
    ) as temporary:
        root = Path(temporary)
        archive = root / _ARCHIVE_NAME
        ciphertext_path = root / _CIPHERTEXT_NAME
        sealed = root / "sealed"
        sealed.mkdir()
        _write_archive(source, archive)
        _crypt(archive, ciphertext_path, encoded_key, decrypt=False)
        ciphertext = ciphertext_path.read_bytes()
        if not ciphertext or len(ciphertext) > _MAX_TOTAL_BYTES + 1024 * 1024:
            raise HandoffError("protected-handoff-ciphertext-size-invalid")
        document = _authenticated_document(binding, _digest(ciphertext))
        manifest = {
            **document,
            "authentication": {
                "algorithm": "hmac-sha256",
                "scope": "binding-and-ciphertext",
                "tag": _tag(key, document, ciphertext),
            },
        }
        (sealed / _MANIFEST_NAME).write_bytes(_canonical_bytes(manifest))
        shutil.copyfile(ciphertext_path, sealed / _CIPHERTEXT_NAME)
        os.replace(sealed, destination)


def _read_sealed(
    source: Path,
    expected_binding: dict[str, str],
    key: bytes,
) -> tuple[Path, bytes]:
    if source.is_symlink() or not source.is_dir():
        raise HandoffError("protected-handoff-bundle-invalid")
    try:
        entries = sorted(source.iterdir(), key=lambda path: path.name)
    except OSError as exc:
        raise HandoffError("protected-handoff-bundle-invalid") from exc
    if [entry.name for entry in entries] != [_CIPHERTEXT_NAME, _MANIFEST_NAME]:
        raise HandoffError("protected-handoff-bundle-file-set-invalid")
    if any(
        entry.is_symlink()
        or not entry.is_file()
        or entry.stat(follow_symlinks=False).st_nlink != 1
        for entry in entries
    ):
        raise HandoffError("protected-handoff-bundle-entry-unsafe")
    manifest_path = source / _MANIFEST_NAME
    ciphertext_path = source / _CIPHERTEXT_NAME
    try:
        if (
            manifest_path.stat(follow_symlinks=False).st_size > _MAX_MANIFEST_BYTES
            or ciphertext_path.stat(follow_symlinks=False).st_size
            > _MAX_TOTAL_BYTES + 1024 * 1024
        ):
            raise HandoffError("protected-handoff-bundle-size-invalid")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        ciphertext = ciphertext_path.read_bytes()
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise HandoffError("protected-handoff-bundle-invalid") from exc
    if (
        not ciphertext
        or len(ciphertext) > _MAX_TOTAL_BYTES + 1024 * 1024
        or not isinstance(manifest, dict)
        or set(manifest) != {
            "schemaVersion",
            "kind",
            "binding",
            "cipher",
            "authentication",
        }
        or manifest.get("schemaVersion") != 1
        or manifest.get("kind") != _KIND
        or manifest.get("binding") != expected_binding
    ):
        raise HandoffError("protected-handoff-bundle-invalid")
    cipher = manifest.get("cipher")
    authentication = manifest.get("authentication")
    if (
        not isinstance(cipher, dict)
        or cipher
        != {
            "algorithm": "aes-256-ctr",
            "kdf": "pbkdf2-hmac-sha256",
            "iterations": _PBKDF2_ITERATIONS,
            "format": "openssl-salted",
            "ciphertextFile": _CIPHERTEXT_NAME,
            "ciphertextDigest": _digest(ciphertext),
        }
        or not isinstance(authentication, dict)
        or set(authentication) != {"algorithm", "scope", "tag"}
        or authentication.get("algorithm") != "hmac-sha256"
        or authentication.get("scope") != "binding-and-ciphertext"
        or not isinstance(authentication.get("tag"), str)
        or _DIGEST.fullmatch(str(authentication.get("tag"))) is None
    ):
        raise HandoffError("protected-handoff-bundle-invalid")
    document = _authenticated_document(expected_binding, _digest(ciphertext))
    if not hmac.compare_digest(
        str(authentication["tag"]),
        _tag(key, document, ciphertext),
    ):
        raise HandoffError("protected-handoff-authentication-failed")
    return ciphertext_path, ciphertext


def _copy_member(source: BinaryIO, destination: Path, expected_size: int) -> None:
    written = 0
    with destination.open("xb") as output:
        while chunk := source.read(64 * 1024):
            written += len(chunk)
            if written > expected_size or written > _MAX_FILE_BYTES:
                raise HandoffError("protected-handoff-member-size-invalid")
            output.write(chunk)
    if written != expected_size:
        raise HandoffError("protected-handoff-member-size-invalid")


def _extract_archive(archive_path: Path, destination: Path) -> None:
    try:
        with tarfile.open(archive_path, "r:") as archive:
            members = archive.getmembers()
            if not members or len(members) > _MAX_FILES:
                raise HandoffError("protected-handoff-member-count-invalid")
            names: set[str] = set()
            portable_names: set[str] = set()
            total = 0
            for member in members:
                if (
                    not member.isfile()
                    or not _safe_file_name(member.name)
                    or member.name in names
                    or member.name.casefold() in portable_names
                    or member.size <= 0
                    or member.size > _MAX_FILE_BYTES
                ):
                    raise HandoffError("protected-handoff-member-unsafe")
                names.add(member.name)
                portable_names.add(member.name.casefold())
                total += member.size
                if total > _MAX_TOTAL_BYTES:
                    raise HandoffError("protected-handoff-expanded-too-large")
            destination.mkdir(mode=0o700)
            for member in members:
                source = archive.extractfile(member)
                if source is None:
                    raise HandoffError("protected-handoff-member-unsafe")
                with source:
                    _copy_member(source, destination / member.name, member.size)
                (destination / member.name).chmod(0o600)
    except HandoffError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise HandoffError("protected-handoff-archive-invalid") from exc


def _open(source: Path, destination: Path, binding_path: Path, key_env: str) -> None:
    if destination.exists() or destination.is_symlink():
        raise HandoffError("protected-handoff-destination-exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    expected_binding = _load_binding(binding_path)
    encoded_key, key = _load_key(key_env)
    ciphertext_path, _ciphertext = _read_sealed(source, expected_binding, key)
    with tempfile.TemporaryDirectory(
        prefix=".stable-backport-open-",
        dir=destination.parent,
    ) as temporary:
        root = Path(temporary)
        archive = root / _ARCHIVE_NAME
        extracted = root / "extracted"
        _crypt(ciphertext_path, archive, encoded_key, decrypt=True)
        _extract_archive(archive, extracted)
        os.replace(extracted, destination)


def main() -> int:
    """Seal or open one exact authenticated protected handoff."""

    parser = argparse.ArgumentParser(allow_abbrev=False)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    for operation in ("seal", "open"):
        subparser = subparsers.add_parser(operation, allow_abbrev=False)
        subparser.add_argument(
            "--source" if operation == "seal" else "--bundle",
            required=True,
            type=Path,
        )
        subparser.add_argument("--out", required=True, type=Path)
        subparser.add_argument("--binding", required=True, type=Path)
        subparser.add_argument("--key-env", required=True)
    arguments = parser.parse_args()
    if arguments.operation == "seal":
        _seal(arguments.source, arguments.out, arguments.binding, arguments.key_env)
    else:
        _open(arguments.bundle, arguments.out, arguments.binding, arguments.key_env)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HandoffError as error:
        print(f"stable backport protected handoff failed closed: {error}")
        raise SystemExit(1) from None

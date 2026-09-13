"""Exact runtime transfer construction; never opens encrypted private metadata.

These helpers establish local byte integrity only. Original artifact/member authentication and
private semantic admission belong to the protected caller. A sanitized input tree deliberately
cannot reconstruct private selection authority without separately provisioned original proof.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
import tempfile
import unicodedata

from maintenance_runtime_metadata import MANIFEST_FILE, MEMBER_NAMES, validate_runtime_metadata

SEALED_NAMES = frozenset({"runtime-companion.json", "runtime-companion.cms"})
MAX_FILE = 1024 * 1024 * 1024
MAX_TOTAL = 2 * MAX_FILE
MAX_FILES = 4096


class RuntimeTransferError(ValueError):
    """Bounded transfer diagnostic containing no selected input values."""


def _deny():
    raise RuntimeTransferError("runtime-metadata-transfer-invalid")


def _path(path: Path) -> Path:
    path = Path(path).absolute()
    if any(item.is_symlink() for item in (path, *path.parents)):
        _deny()
    return path


def _bytes(path: Path) -> bytes:
    path = _path(path)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_FILE:
        _deny()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(MAX_FILE + 1)
        after = os.fstat(stream.fileno())
    final = path.stat()
    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    if (len(raw) != before.st_size or any(getattr(before, key) != getattr(info, key)
            for key in fields for info in (opened, after, final))):
        _deny()
    return raw


def _validate(freeze, root, package_path):
    if freeze.get("schemaVersion") == 3:
        import maintenance_runtime_companion as companion
        companion.inspect(freeze, root)
        names = SEALED_NAMES
    elif freeze.get("schemaVersion") == 2:
        validate_runtime_metadata(freeze, root, package_path=package_path)
        names = frozenset({MANIFEST_FILE, *MEMBER_NAMES.values()})
    else:
        _deny()
    if not root.is_dir() or {path.name for path in root.iterdir()} != names:
        _deny()
    return names


def _destination(source, destination):
    source, destination = _path(source), _path(destination)
    if (not source.is_dir() or destination.exists() or not destination.parent.is_dir()
            or destination.is_relative_to(source) or source.is_relative_to(destination)):
        _deny()
    return source, destination


def copy_runtime(freeze: dict, source: Path, destination: Path, package_path: Path | None = None) -> None:
    """Atomically retain the validated exact roster; retries cannot replace an existing tree."""
    temporary = None
    try:
        source, destination = _destination(source, destination)
        names = _validate(freeze, source, package_path)
        temporary = Path(tempfile.mkdtemp(prefix=".runtime-transfer-", dir=destination.parent))
        for name in sorted(names):
            target = temporary / name
            target.write_bytes(_bytes(source / name))
            target.chmod(0o600)
        _validate(freeze, temporary, package_path)
        # Recheck the producer roster and bytes after copying; copied bytes are independently bound.
        _validate(freeze, source, package_path)
        for name in names:
            if _bytes(source / name) != _bytes(temporary / name):
                _deny()
        if destination.exists() or destination.is_symlink():
            _deny()
        temporary.rename(destination)
        temporary = None
    except (ValueError, OSError, KeyError, TypeError):
        raise RuntimeTransferError("runtime-metadata-transfer-invalid") from None
    finally:
        if temporary is not None:
            shutil.rmtree(temporary, ignore_errors=True)


def stage_protected_inputs(freeze: dict, manifest: dict, source: Path, destination: Path) -> None:
    """Construct referenced inputs, replacing prospective private runtime inputs with sealed bytes.

    Existing non-runtime input disclosure policy remains the caller's responsibility. Unreferenced
    files are never copied. A reference into private runtime inputs through another key is rejected.
    All paths in the manifest retain their existing source-relative locations in the staged tree.
    """
    temporary = None
    try:
        source, destination = _destination(source, destination)
        if freeze.get("schemaVersion") != 3:
            _deny()
        inputs = manifest["inputs"]
        runtime = _path(Path(inputs["maintenanceRuntimeInputs"]))
        relative_runtime = runtime.relative_to(source)
        if not relative_runtime.parts:
            _deny()
        roster = {}
        total = 0
        aliases = set()
        for key, value in sorted(inputs.items()):
            if not isinstance(value, str):
                _deny()
            selected = _path(Path(value))
            # Other source families can be authenticated separately outside this staging root.
            if not selected.is_relative_to(source):
                continue
            if selected == runtime or selected.is_relative_to(runtime):
                if key != "maintenanceRuntimeInputs" or selected != runtime:
                    _deny()
                continue
            if runtime.is_relative_to(selected):
                _deny()
            paths = sorted(selected.rglob("*")) if selected.is_dir() else [selected]
            for path in paths:
                path = _path(path)
                if path.is_dir():
                    continue
                relative = path.relative_to(source)
                alias = unicodedata.normalize("NFC", str(relative)).casefold()
                if relative in roster:
                    continue
                if alias in aliases:
                    _deny()
                raw = _bytes(path)
                total += len(raw)
                if total > MAX_TOTAL or len(roster) >= MAX_FILES:
                    _deny()
                aliases.add(alias)
                roster[relative] = raw
        temporary = Path(tempfile.mkdtemp(prefix=".input-transfer-", dir=destination.parent))
        for relative, raw in roster.items():
            target = temporary / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(raw)
            target.chmod(0o600)
        target_runtime = temporary / relative_runtime
        target_runtime.mkdir(mode=0o700, parents=True)
        copy_runtime(freeze, runtime / "runtime", target_runtime / "runtime")
        if destination.exists() or destination.is_symlink():
            _deny()
        temporary.rename(destination)
        temporary = None
    except (ValueError, OSError, KeyError, TypeError):
        raise RuntimeTransferError("runtime-metadata-transfer-invalid") from None
    finally:
        if temporary is not None:
            shutil.rmtree(temporary, ignore_errors=True)


def copy_frozen_tree(freeze: dict, source: Path, destination: Path) -> None:
    """Retain an exact prospective freeze roster, including unchanged approved public assets.

    This validates local identities only. The caller must authenticate the original freeze artifact
    before invoking this helper; a later artifact retains bytes without becoming their producer.
    """
    from maintenance_runtime_metadata import digest_bytes, read_json, semantic_digest
    from cryptad_certification.schema_validation import validate_schema
    temporary = None
    try:
        source, destination = _destination(source, destination)
        if freeze.get("schemaVersion") != 3 or validate_schema(
                freeze, "stable-1.0-maintenance-candidate-freeze-v3.schema.json"):
            _deny()
        freeze_name = "stable-1.0-maintenance-candidate-freeze.json"
        if {path.name for path in source.iterdir()} != {freeze_name, "checksums.txt", "assets", "runtime"}:
            _deny()
        raw_freeze = _bytes(source / freeze_name)
        checksums = _bytes(source / "checksums.txt")
        rows = freeze["assets"]
        names = [row["fileName"] for row in rows]
        if (read_json(raw_freeze) != freeze or digest_bytes(checksums) != freeze["checksumsDigest"]
                or semantic_digest(sorted(rows, key=lambda row: row["fileName"])) != freeze["assetSetDigest"]
                or len(set(names)) != len(names) or len(names) > MAX_FILES
                or any(Path(name).name != name or name in {".", ".."} for name in names)
                or {path.name for path in (source / "assets").iterdir()} != set(names)
                or len({unicodedata.normalize("NFC", name).casefold() for name in names}) != len(names)):
            _deny()
        temporary = Path(tempfile.mkdtemp(prefix=".freeze-transfer-", dir=destination.parent))
        (temporary / freeze_name).write_bytes(raw_freeze)
        (temporary / "checksums.txt").write_bytes(checksums)
        (temporary / "assets").mkdir(mode=0o700)
        total = 0
        for row in sorted(rows, key=lambda row: row["fileName"]):
            raw = _bytes(source / "assets" / row["fileName"])
            total += len(raw)
            if (row["publicAsset"] is not True or digest_bytes(raw) != row["digest"]
                    or len(raw) != row["sizeBytes"] or total > MAX_TOTAL):
                _deny()
            target = temporary / "assets" / row["fileName"]
            target.write_bytes(raw)
            target.chmod(0o600)
            if _bytes(target) != raw:
                _deny()
        copy_runtime(freeze, source / "runtime", temporary / "runtime")
        if (_bytes(source / freeze_name) != raw_freeze or _bytes(source / "checksums.txt") != checksums
                or {path.name for path in source.iterdir()} != {freeze_name, "checksums.txt", "assets", "runtime"}
                or {path.name for path in (source / "assets").iterdir()} != set(names)
                or destination.exists() or destination.is_symlink()):
            _deny()
        for name in names:
            if _bytes(source / "assets" / name) != _bytes(temporary / "assets" / name):
                _deny()
        temporary.rename(destination)
        temporary = None
    except (ValueError, OSError, KeyError, TypeError):
        raise RuntimeTransferError("runtime-metadata-transfer-invalid") from None
    finally:
        if temporary is not None:
            shutil.rmtree(temporary, ignore_errors=True)

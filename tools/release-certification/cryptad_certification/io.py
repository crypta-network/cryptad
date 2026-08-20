"""Deterministic JSON and text I/O helpers."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any


def read_json_bytes(value: bytes, label: str) -> Any:
    """Decode one strict UTF-8 JSON document from authenticated bytes.

    Certification inputs reject duplicate object keys and the non-standard
    ``NaN``/``Infinity`` numeric tokens accepted by Python's default decoder.
    Both forms make digest-bound evidence ambiguous across JSON
    implementations.
    """

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"JSON document contains duplicate field {key!r}: {label}")
            value[key] = item
        return value

    def reject_non_finite_number(value: str) -> None:
        raise ValueError(f"JSON document contains non-finite number {value!r}: {label}")

    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"JSON document is not strict UTF-8: {label}") from exc

    return json.loads(
        text,
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=reject_non_finite_number,
    )


def read_json(path: Path) -> Any:
    """Read one strict UTF-8 JSON document from a regular input path."""

    return read_json_bytes(path.read_bytes(), str(path))


def _write_utf8(path: Path, value: str) -> None:
    """Atomically write one regular file without following a symlinked target."""

    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError(f"refusing to write through a symlinked output file: {path}")
    existing_mode: int | None = None
    if path.exists():
        if not path.is_file():
            raise ValueError(f"refusing to replace a non-file output path: {path}")
        existing_mode = stat.S_IMODE(path.stat(follow_symlinks=False).st_mode)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(value)
        os.chmod(temporary, existing_mode if existing_mode is not None else 0o644)
        if path.is_symlink():
            raise ValueError(f"refusing to write through a symlinked output file: {path}")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_json(path: Path, value: Any) -> None:
    """Write stable, newline-terminated UTF-8 JSON."""

    _write_utf8(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def write_text(path: Path, value: str) -> None:
    """Write newline-terminated UTF-8 text."""

    _write_utf8(path, value.rstrip() + "\n")


def write_bytes(path: Path, value: bytes) -> None:
    """Atomically write exact bytes without following a symlinked target."""

    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError(f"refusing to write through a symlinked output file: {path}")
    existing_mode: int | None = None
    if path.exists():
        if not path.is_file():
            raise ValueError(f"refusing to replace a non-file output path: {path}")
        existing_mode = stat.S_IMODE(path.stat(follow_symlinks=False).st_mode)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
        os.chmod(temporary, existing_mode if existing_mode is not None else 0o644)
        if path.is_symlink():
            raise ValueError(f"refusing to write through a symlinked output file: {path}")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()

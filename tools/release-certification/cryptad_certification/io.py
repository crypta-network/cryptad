"""Deterministic JSON and text I/O helpers."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any


def read_json(path: Path) -> Any:
    """Read one UTF-8 JSON document."""

    return json.loads(path.read_text(encoding="utf-8"))


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

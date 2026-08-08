"""Canonical, path-independent fingerprints for Stable builder JDK installations."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Any

JDK_INSTALLATION_DIGEST_ALGORITHM = "crypta-jdk-installed-tree-sha256-v1"
MAXIMUM_JDK_ENTRIES = 100_000
MAXIMUM_JDK_FILE_BYTES = 2_000_000_000


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _file_digest_and_size(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(block)
            if size > MAXIMUM_JDK_FILE_BYTES:
                raise ValueError("JDK installation file exceeds the fingerprint byte bound")
            digest.update(block)
    return "sha256:" + digest.hexdigest(), size


def _safe_symlink_target(root: Path, path: Path, target: str) -> None:
    if not target or "\x00" in target or Path(target).is_absolute():
        raise ValueError("JDK installation contains an unsafe symbolic link")
    resolved = (path.parent / target).resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("JDK installation contains an escaping symbolic link") from exc


def jdk_installation_identity(java_home: Path) -> dict[str, str]:
    """Fingerprint one observed JDK tree without serializing its host path or timestamps."""

    if java_home.is_symlink() or not java_home.is_dir():
        raise ValueError("observed Java home is not a safe installation directory")
    root = java_home.resolve(strict=True)
    entries: list[dict[str, Any]] = []
    folded: set[str] = set()
    paths = sorted(root.rglob("*"), key=lambda value: value.relative_to(root).as_posix())
    if not paths or len(paths) > MAXIMUM_JDK_ENTRIES:
        raise ValueError("JDK installation exceeds the fingerprint entry bound")
    for path in paths:
        relative = path.relative_to(root).as_posix()
        pure = PurePosixPath(relative)
        folded_path = relative.casefold()
        if pure.is_absolute() or ".." in pure.parts or folded_path in folded:
            raise ValueError("JDK installation contains an unsafe or colliding path")
        folded.add(folded_path)
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            target = os.readlink(path)
            _safe_symlink_target(root, path, target)
            row = {
                "digest": None,
                "kind": "symlink",
                "path": relative,
                "size": 0,
                "target": target,
            }
        elif stat.S_ISDIR(mode):
            row = {
                "digest": None,
                "kind": "directory",
                "path": relative,
                "size": 0,
                "target": None,
            }
        elif stat.S_ISREG(mode):
            digest, size = _file_digest_and_size(path)
            row = {
                "digest": digest,
                "kind": "file",
                "path": relative,
                "size": size,
                "target": None,
            }
        else:
            raise ValueError("JDK installation contains a special file")
        entries.append(row)
    release_file = root / "release"
    if release_file.is_symlink() or not release_file.is_file():
        raise ValueError("JDK installation lacks a safe release identity file")
    release_digest, _ = _file_digest_and_size(release_file)
    manifest = {
        "algorithm": JDK_INSTALLATION_DIGEST_ALGORITHM,
        "entries": entries,
    }
    return {
        "installationManifestDigest": "sha256:"
        + hashlib.sha256(_canonical_json_bytes(manifest)).hexdigest(),
        "releaseFileDigest": release_digest,
    }

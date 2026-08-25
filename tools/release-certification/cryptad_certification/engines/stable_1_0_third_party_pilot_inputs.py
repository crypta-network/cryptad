"""Authenticate and confine one protected pilot evidence artifact.

This module is intentionally transport-agnostic. The protected workflow owns
download authentication; this boundary verifies the exact archive bytes before
reading its member table and materializes only flat regular files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tempfile
import zipfile


MAX_ARCHIVE_BYTES = 768 * 1024 * 1024
MAX_EXPANDED_BYTES = 640 * 1024 * 1024
MAX_MEMBER_BYTES = 256 * 1024 * 1024
MAX_MEMBERS = 256
ALLOWED_SUFFIXES = frozenset({".json", ".zip"})


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _safe_member(info: zipfile.ZipInfo) -> bool:
    path = PurePosixPath(info.filename)
    mode = info.external_attr >> 16
    file_type = stat.S_IFMT(mode)
    return (
        not info.is_dir()
        and not info.flag_bits & 1
        and info.create_system in {0, 3}
        and len(path.parts) == 1
        and not path.is_absolute()
        and path.name not in {"", ".", "..", ".DS_Store"}
        and not path.name.startswith("._")
        and path.suffix.casefold() in ALLOWED_SUFFIXES
        and "\\" not in info.filename
        and "\x00" not in info.filename
        and not stat.S_ISLNK(mode)
        and file_type in {0, stat.S_IFREG}
        and info.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
        and 0 <= info.file_size <= MAX_MEMBER_BYTES
    )


def _contract_bound_members(source: zipfile.ZipFile) -> set[str]:
    """Derive the only members an aggregate pilot artifact may retain."""

    try:
        contract = json.loads(source.read("execution.json"))
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("pilot evidence archive lacks a valid execution.json") from exc
    evidence = contract.get("evidence") if isinstance(contract, dict) else None
    if not isinstance(evidence, dict):
        raise ValueError("pilot evidence execution contract lacks closed evidence bindings")
    expected = {"execution.json"}
    for binding in evidence.values():
        if binding is None:
            continue
        if not isinstance(binding, dict) or not isinstance(binding.get("fileName"), str):
            raise ValueError("pilot evidence execution contract has a malformed binding")
        expected.add(binding["fileName"])
    handoff_binding = evidence.get("externalHandoff")
    if not isinstance(handoff_binding, dict):
        raise ValueError("pilot evidence archive does not bind an external handoff")
    try:
        handoff = json.loads(source.read(handoff_binding["fileName"]))
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("pilot evidence archive lacks its valid bound external handoff") from exc
    cohort = handoff.get("cohort") if isinstance(handoff, dict) else None
    if not isinstance(cohort, list) or not cohort:
        raise ValueError("pilot external handoff lacks its bounded cohort")
    for row in cohort:
        if not isinstance(row, dict):
            raise ValueError("pilot external handoff cohort is malformed")
        for field in ("submissionFile", "bundleFile"):
            name = row.get(field)
            if not isinstance(name, str):
                raise ValueError("pilot external handoff cohort has a malformed file binding")
            expected.add(name)
    return expected


def assemble(
    archive_path: Path,
    expected_digest: str,
    expected_size: int,
    output_dir: Path,
) -> None:
    """Verify exact archive bytes, then atomically materialize safe members."""

    archive = archive_path.resolve()
    if archive_path.is_symlink() or not archive.is_file():
        raise ValueError("pilot evidence archive is missing or unsafe")
    metadata = archive.stat(follow_symlinks=False)
    if metadata.st_nlink != 1:
        raise ValueError("pilot evidence archive has ambiguous hard-link identity")
    if metadata.st_size != expected_size or not 1 <= expected_size <= MAX_ARCHIVE_BYTES:
        raise ValueError("pilot evidence archive size differs from protected coordinates")
    if _digest_file(archive) != expected_digest:
        raise ValueError("pilot evidence archive digest differs from protected coordinates")
    output = output_dir.resolve()
    if output_dir.is_symlink() or output.exists():
        raise ValueError("pilot evidence output must be a new non-symlink path")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{output.name}-assembly-", dir=output.parent)
    )
    try:
        with zipfile.ZipFile(archive) as source:
            infos = source.infolist()
            names = [info.filename for info in infos]
            if source.comment or not infos or len(infos) > MAX_MEMBERS:
                raise ValueError("pilot evidence archive has an invalid member table")
            if names != sorted(names) or len(names) != len(set(names)):
                raise ValueError("pilot evidence archive has duplicate or non-canonical members")
            if len(names) != len({name.casefold() for name in names}):
                raise ValueError("pilot evidence archive has case-colliding members")
            if any(not _safe_member(info) for info in infos):
                raise ValueError("pilot evidence archive contains an unsafe member")
            if set(names) != _contract_bound_members(source):
                raise ValueError("pilot evidence archive contains missing or unbound members")
            if sum(info.file_size for info in infos) > MAX_EXPANDED_BYTES:
                raise ValueError("pilot evidence archive exceeds its expanded byte bound")
            for info in infos:
                target = temporary / info.filename
                with source.open(info) as input_stream, target.open("xb") as output_stream:
                    copied = shutil.copyfileobj(input_stream, output_stream, 1024 * 1024)
                    del copied
                if target.stat().st_size != info.file_size:
                    raise ValueError("pilot evidence member changed while copied")
                os.chmod(target, 0o600)
        os.replace(temporary, output)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError("pilot evidence archive is malformed or unreadable") from exc
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def main(argv: list[str] | None = None) -> int:
    """Run the protected artifact confinement boundary."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--expected-digest", required=True)
    parser.add_argument("--expected-size", type=int, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        assemble(
            arguments.archive,
            arguments.expected_digest,
            arguments.expected_size,
            arguments.output_dir,
        )
    except ValueError as exc:
        print(f"pilot-inputs: {exc}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

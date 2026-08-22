"""Assemble exact authenticated PR-293 operation members from Actions artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
import zipfile

from ..io import read_json


MAX_ARTIFACTS = 16
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
MAX_TOTAL_ARCHIVE_BYTES = 4 * 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 20_000
MAX_EVIDENCE_MEMBER_BYTES = 16 * 1024 * 1024
MAX_EVIDENCE_BYTES = 32 * 1024 * 1024
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


class AssemblyError(RuntimeError):
    """Bounded failure at the authenticated operation-assembly boundary."""


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _safe_member_name(value: str) -> PurePosixPath:
    if (
        not value
        or len(value) > 1024
        or "\\" in value
        or re.fullmatch(r"[A-Za-z0-9._/-]+", value) is None
    ):
        raise AssemblyError("catalog-authority-input-member-name-invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise AssemblyError("catalog-authority-input-member-name-invalid")
    return path


def _regular_zip_member(member: zipfile.ZipInfo) -> bool:
    mode = member.external_attr >> 16
    file_type = stat.S_IFMT(mode)
    return (
        not member.is_dir()
        and not member.flag_bits & 1
        and not stat.S_ISLNK(mode)
        and file_type in {0, stat.S_IFREG}
    )


def _validate_archive(archive: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    members = archive.infolist()
    if archive.comment or not members or len(members) > MAX_ARCHIVE_MEMBERS:
        raise AssemblyError("catalog-authority-input-archive-shape-invalid")
    by_name: dict[str, zipfile.ZipInfo] = {}
    folded: set[str] = set()
    for member in members:
        name = _safe_member_name(member.filename.rstrip("/"))
        if any(
            part.casefold() in {".ds_store", "__macosx"} or part.startswith("._")
            for part in name.parts
        ):
            raise AssemblyError("catalog-authority-input-archive-metadata-forbidden")
        canonical = name.as_posix()
        portable = canonical.casefold()
        if canonical in by_name or portable in folded:
            raise AssemblyError("catalog-authority-input-archive-path-collision")
        folded.add(portable)
        by_name[canonical] = member
        mode = member.external_attr >> 16
        file_type = stat.S_IFMT(mode)
        if member.flag_bits & 1 or stat.S_ISLNK(mode) or file_type not in {
            0,
            stat.S_IFREG,
            stat.S_IFDIR,
        }:
            raise AssemblyError("catalog-authority-input-archive-member-unsafe")
    return by_name


def assemble(coordinates_path: Path, archives_root: Path, output: Path) -> None:
    """Verify downloaded archives and materialize only reviewed evidence members."""

    coordinates = read_json(coordinates_path)
    if (
        not isinstance(coordinates, dict)
        or set(coordinates) != {"schemaVersion", "artifacts"}
        or coordinates.get("schemaVersion") != 1
        or not isinstance(coordinates.get("artifacts"), list)
        or not 1 <= len(coordinates["artifacts"]) <= MAX_ARTIFACTS
    ):
        raise AssemblyError("catalog-authority-input-coordinates-invalid")
    if output.exists() or output.is_symlink():
        raise AssemblyError("catalog-authority-input-output-already-exists")
    expected_targets: set[str] = set()
    selected_members: dict[str, bytes] = {}
    total_written = 0
    total_archive_bytes = 0
    seen_artifacts: set[tuple[object, ...]] = set()
    try:
        for index, coordinate in enumerate(coordinates["artifacts"]):
            expected_coordinate_fields = {
                "artifactDigest",
                "artifactId",
                "artifactName",
                "artifactSize",
                "members",
                "runAttempt",
                "runId",
                "workflowPath",
            }
            if not isinstance(coordinate, dict) or set(coordinate) != expected_coordinate_fields:
                raise AssemblyError("catalog-authority-input-coordinate-shape-invalid")
            expected_archive_digest = coordinate["artifactDigest"]
            if not isinstance(expected_archive_digest, str) or DIGEST.fullmatch(
                expected_archive_digest
            ) is None:
                raise AssemblyError("catalog-authority-input-artifact-digest-invalid")
            artifact_identity = (
                coordinate["workflowPath"],
                coordinate["runId"],
                coordinate["runAttempt"],
                coordinate["artifactName"],
                coordinate["artifactId"],
                expected_archive_digest,
            )
            if artifact_identity in seen_artifacts:
                raise AssemblyError("catalog-authority-input-artifact-duplicate")
            seen_artifacts.add(artifact_identity)
            expected_archive_size = coordinate["artifactSize"]
            if (
                not isinstance(expected_archive_size, int)
                or isinstance(expected_archive_size, bool)
                or not 1 <= expected_archive_size <= MAX_ARCHIVE_BYTES
            ):
                raise AssemblyError("catalog-authority-input-artifact-size-invalid")
            total_archive_bytes += expected_archive_size
            if total_archive_bytes > MAX_TOTAL_ARCHIVE_BYTES:
                raise AssemblyError("catalog-authority-input-total-archive-size-invalid")
            members = coordinate["members"]
            if not isinstance(members, list) or not 1 <= len(members) <= 16:
                raise AssemblyError("catalog-authority-input-member-selection-invalid")
            archive_path = archives_root / f"artifact-{index:02d}.zip"
            if (
                archive_path.is_symlink()
                or not archive_path.is_file()
                or archive_path.stat(follow_symlinks=False).st_nlink != 1
                or archive_path.stat(follow_symlinks=False).st_size
                != expected_archive_size
            ):
                raise AssemblyError("catalog-authority-input-artifact-unsafe")
            if _digest_file(archive_path) != expected_archive_digest:
                raise AssemblyError("catalog-authority-input-artifact-digest-mismatch")
            with zipfile.ZipFile(archive_path) as archive:
                by_name = _validate_archive(archive)
                for selection in members:
                    if not isinstance(selection, dict) or set(selection) != {
                        "digest",
                        "sourcePath",
                        "targetName",
                    }:
                        raise AssemblyError("catalog-authority-input-member-selection-invalid")
                    source = _safe_member_name(selection["sourcePath"]).as_posix()
                    target_path = _safe_member_name(selection["targetName"])
                    if len(target_path.parts) != 1:
                        raise AssemblyError("catalog-authority-input-target-name-invalid")
                    target = target_path.as_posix()
                    expected_digest = selection["digest"]
                    if not isinstance(expected_digest, str) or DIGEST.fullmatch(expected_digest) is None:
                        raise AssemblyError("catalog-authority-input-member-digest-invalid")
                    if target.casefold() in {item.casefold() for item in expected_targets}:
                        raise AssemblyError("catalog-authority-input-target-collision")
                    member = by_name.get(source)
                    if member is None or not _regular_zip_member(member):
                        raise AssemblyError("catalog-authority-input-required-member-missing")
                    if member.file_size <= 0 or member.file_size > MAX_EVIDENCE_MEMBER_BYTES:
                        raise AssemblyError("catalog-authority-input-member-size-invalid")
                    value = archive.read(member)
                    if len(value) != member.file_size or _digest_bytes(value) != expected_digest:
                        raise AssemblyError("catalog-authority-input-member-digest-mismatch")
                    total_written += len(value)
                    if total_written > MAX_EVIDENCE_BYTES:
                        raise AssemblyError("catalog-authority-input-expanded-size-invalid")
                    selected_members[target] = value
                    expected_targets.add(target)
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix=f".{output.name}-assembly-",
            dir=output.parent,
        ) as temporary:
            staged_output = Path(temporary) / "assembled"
            staged_output.mkdir(mode=0o700)
            for target, value in selected_members.items():
                destination = staged_output / target
                destination.write_bytes(value)
                destination.chmod(0o600)
            actual_targets = {
                path.name
                for path in staged_output.iterdir()
                if path.is_file() and not path.is_symlink()
            }
            if actual_targets != expected_targets or len(actual_targets) != len(expected_targets):
                raise AssemblyError("catalog-authority-input-output-members-invalid")
            if output.exists() or output.is_symlink():
                raise AssemblyError("catalog-authority-input-output-already-exists")
            os.replace(staged_output, output)
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
        if isinstance(exc, AssemblyError):
            raise
        raise AssemblyError("catalog-authority-input-archive-invalid") from exc


def main() -> int:
    """Parse command-line paths and assemble the protected evidence directory."""

    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--coordinates", required=True, type=Path)
    parser.add_argument("--archives-root", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    arguments = parser.parse_args()
    assemble(
        arguments.coordinates.resolve(),
        arguments.archives_root.resolve(),
        arguments.out.resolve(),
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssemblyError as error:
        print(f"Stable catalog-authority input assembly failed closed: {error}")
        raise SystemExit(1) from None

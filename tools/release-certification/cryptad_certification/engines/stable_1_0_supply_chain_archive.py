"""Safe actual-byte inspection for Stable supply-chain archive subjects."""

from __future__ import annotations

import hashlib
import io
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

from .stable_1_0_supply_chain_core import (
    canonical_json_bytes,
    file_digest,
    semantic_digest,
    sha256_digest,
)

ARCHIVE_PACKAGE_TYPES = frozenset({"app-zip", "jar", "tar", "wheel", "zip"})
_NESTED_SUFFIXES = (".jar", ".tar", ".tar.gz", ".tgz", ".whl", ".zip")
_READ_CHUNK = 1024 * 1024
_MAX_NESTED_ARCHIVE_BYTES = 100_000_000


def build_archive_payload_manifest(
    subject_path: Path,
    subject_key: str,
    subject_class: str,
    component_ids: list[str],
    normalization_rule: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    """Derive a canonical manifest from actual archive entries and an approved component set."""

    subject = {"subjectClass": subject_class}
    package_type = _package_type(subject_path, subject)
    if package_type not in normalization_rule.get("packageTypes", []):
        raise ValueError("archive subject uses the wrong policy content rule")
    maximum_entries = int(policy["publicArtifactBounds"]["maximumPayloadEntries"])
    maximum_expanded = int(policy["publicArtifactBounds"]["maximumExpandedBytes"])
    entries, metadata, totals = _inspect_path(
        subject_path,
        package_type,
        maximum_entries=maximum_entries,
        maximum_expanded=maximum_expanded,
    )
    canonical_components = sorted(set(component_ids))
    mapped_entries = [
        {**entry, "componentIds": canonical_components}
        for entry in entries
    ]
    value = {
        "schemaVersion": 1,
        "kind": "stable-1.0-payload-manifest",
        "subjectKey": subject_key,
        "publishedSubjectDigest": file_digest(subject_path),
        "packageType": package_type,
        "normalizationRuleId": normalization_rule["id"],
        "normalizationRuleVersion": normalization_rule["version"],
        "preSigningPayloadDigest": sha256_digest(canonical_json_bytes(entries)),
        "packageMetadataDigest": sha256_digest(canonical_json_bytes(metadata)),
        "entries": mapped_entries,
        "ignoredPaths": [],
        "limits": totals,
        "manifestDigest": "sha256:" + "0" * 64,
    }
    value["manifestDigest"] = semantic_digest(value, "manifestDigest")
    return value


def archive_subject_errors(
    subject_path: Path,
    manifest: dict[str, Any],
    subject: dict[str, Any],
    components: dict[str, dict[str, Any]],
    policy: dict[str, Any],
) -> list[str]:
    """Compare one supplied content manifest with safe inspection of exact archive bytes."""

    package_type = manifest.get("packageType")
    if package_type not in ARCHIVE_PACKAGE_TYPES:
        return []
    errors: list[str] = []
    expected_type = _package_type(subject_path, subject)
    if package_type != expected_type:
        errors.append("archive payload manifest uses the wrong package type")
        return errors
    if file_digest(subject_path) != manifest.get("publishedSubjectDigest"):
        errors.append("archive payload manifest binds different published subject bytes")
    maximum_entries = int(policy.get("publicArtifactBounds", {}).get("maximumPayloadEntries", 0))
    maximum_expanded = int(policy.get("publicArtifactBounds", {}).get("maximumExpandedBytes", 0))
    if maximum_entries < 1 or maximum_expanded < 1:
        return errors + ["archive inspection policy bounds are absent"]
    try:
        actual, metadata, totals = _inspect_path(
            subject_path,
            package_type,
            maximum_entries=maximum_entries,
            maximum_expanded=maximum_expanded,
        )
    except (OSError, tarfile.TarError, zipfile.BadZipFile, ValueError) as exc:
        return errors + [f"archive subject is unsafe or malformed: {type(exc).__name__}"]

    supplied_entries = manifest.get("entries", [])
    supplied_by_path = {
        row.get("path"): row for row in supplied_entries if isinstance(row, dict)
    }
    if len(supplied_by_path) != len(supplied_entries):
        errors.append("archive payload manifest contains duplicate paths")
    actual_by_path = {row["path"]: row for row in actual}
    if set(supplied_by_path) != set(actual_by_path):
        errors.append("actual archive entries and payload manifest entries differ")
    subject_component_ids = set(subject.get("componentIds", []))
    mapped_component_ids: set[str] = set()
    actual_file_digests: set[str] = set()
    for path in sorted(set(supplied_by_path).intersection(actual_by_path)):
        supplied = supplied_by_path[path]
        actual_row = actual_by_path[path]
        supplied_view = {
            key: supplied.get(key)
            for key in ("path", "kind", "digest", "size", "modeClass", "symlinkTarget")
        }
        if supplied_view != actual_row:
            errors.append(f"actual archive entry differs from payload manifest: {path}")
        component_ids = supplied.get("componentIds")
        if not isinstance(component_ids, list) or not component_ids:
            errors.append(f"archive payload entry is not mapped to a component: {path}")
            continue
        if component_ids != sorted(set(component_ids)):
            errors.append(f"archive payload component mapping is not canonical: {path}")
        unknown = set(component_ids).difference(subject_component_ids)
        if unknown:
            errors.append(f"archive payload entry maps outside its release subject: {path}")
        mapped_component_ids.update(component_ids)
        digest = supplied.get("digest")
        if isinstance(digest, str):
            actual_file_digests.add(digest)
    if mapped_component_ids != subject_component_ids:
        errors.append("archive payload does not map every subject component to actual bytes")

    for component_id in sorted(subject_component_ids):
        component = components.get(component_id)
        if component is None:
            continue
        digest = component.get("digest")
        kind = component.get("componentKind")
        if (
            isinstance(digest, str)
            and kind in {"maven", "gradle-plugin", "native", "vendored-binary", "web-asset"}
            and digest not in actual_file_digests
            and digest != subject.get("digest")
        ):
            errors.append(
                f"archive does not contain the exact bytes of component {component_id}"
            )

    limits = manifest.get("limits", {})
    if limits.get("entryCount") != totals["entryCount"]:
        errors.append("archive payload entry-count bound differs from actual expansion")
    if limits.get("expandedBytes") != totals["expandedBytes"]:
        errors.append("archive payload expanded-byte bound differs from actual expansion")
    if limits.get("nestedArchiveDepth") != totals["nestedArchiveDepth"]:
        errors.append("archive payload nested-depth bound differs from actual contents")
    metadata_digest = sha256_digest(canonical_json_bytes(metadata))
    if manifest.get("packageMetadataDigest") != metadata_digest:
        errors.append("archive package metadata digest differs from actual container metadata")
    payload_digest = sha256_digest(canonical_json_bytes(actual))
    if manifest.get("preSigningPayloadDigest") != payload_digest:
        errors.append("archive canonical payload digest differs from actual entries")
    return errors


def _package_type(path: Path, subject: dict[str, Any]) -> str:
    name = path.name.lower()
    if name.endswith(".jar"):
        return "jar"
    if name.endswith(".whl"):
        return "wheel"
    if name.endswith((".tar", ".tar.gz", ".tgz")):
        return "tar"
    if name.endswith(".zip"):
        return "app-zip" if subject.get("subjectClass") == "first-party-app" else "zip"
    raise ValueError("unsupported actual-byte archive subject")


def _inspect_path(
    path: Path,
    package_type: str,
    *,
    maximum_entries: int,
    maximum_expanded: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    totals = {"entryCount": 0, "expandedBytes": 0, "nestedArchiveDepth": 0}
    if package_type in {"app-zip", "jar", "wheel", "zip"}:
        with zipfile.ZipFile(path) as archive:
            entries, metadata = _inspect_zip(
                archive,
                totals,
                depth=0,
                maximum_entries=maximum_entries,
                maximum_expanded=maximum_expanded,
            )
    else:
        with tarfile.open(path, mode="r:*") as archive:
            entries, metadata = _inspect_tar(
                archive,
                totals,
                depth=0,
                maximum_entries=maximum_entries,
                maximum_expanded=maximum_expanded,
            )
    return entries, metadata, totals


def _inspect_zip(
    archive: zipfile.ZipFile,
    totals: dict[str, int],
    *,
    depth: int,
    maximum_entries: int,
    maximum_expanded: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if archive.comment:
        raise ValueError("ZIP archive comment is prohibited")
    entries: list[dict[str, Any]] = []
    metadata: list[dict[str, Any]] = []
    seen: set[str] = set()
    folded: set[str] = set()
    for info in archive.infolist():
        path = _safe_archive_path(info.filename)
        _register_path(path, seen, folded)
        totals["entryCount"] += 1
        totals["expandedBytes"] += int(info.file_size)
        _check_totals(totals, maximum_entries, maximum_expanded, depth)
        mode = (info.external_attr >> 16) & 0xFFFF
        is_symlink = stat.S_ISLNK(mode)
        is_directory = info.is_dir()
        if mode and not (is_symlink or is_directory or stat.S_ISREG(mode)):
            raise ValueError("ZIP archive contains a special file")
        if is_directory:
            row = _entry(path, "directory", None, 0, "directory", None)
        elif is_symlink:
            target_bytes = _read_zip_entry(archive, info, maximum_expanded)
            target = target_bytes.decode("utf-8", "strict")
            _safe_symlink_target(path, target)
            row = _entry(path, "symlink", None, 0, "symlink", target)
        else:
            digest, data = _digest_zip_entry(archive, info, maximum_expanded)
            mode_class = canonical_mode_class(mode)
            row = _entry(path, "file", digest, int(info.file_size), mode_class, None)
            _inspect_nested_if_needed(
                path,
                data,
                totals,
                depth,
                maximum_entries,
                maximum_expanded,
            )
        entries.append(row)
        metadata.append(
            {
                "path": path,
                "dateTime": list(info.date_time),
                "compressType": int(info.compress_type),
                "crc": int(info.CRC),
                "externalAttributes": int(info.external_attr),
                "extraDigest": sha256_digest(info.extra),
                "commentDigest": sha256_digest(info.comment),
            }
        )
    return sorted(entries, key=lambda row: row["path"]), metadata


def _inspect_tar(
    archive: tarfile.TarFile,
    totals: dict[str, int],
    *,
    depth: int,
    maximum_entries: int,
    maximum_expanded: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    entries: list[dict[str, Any]] = []
    metadata: list[dict[str, Any]] = []
    seen: set[str] = set()
    folded: set[str] = set()
    for member in archive.getmembers():
        path = _safe_archive_path(member.name)
        _register_path(path, seen, folded)
        totals["entryCount"] += 1
        totals["expandedBytes"] += int(member.size if member.isfile() else 0)
        _check_totals(totals, maximum_entries, maximum_expanded, depth)
        if member.isdir():
            row = _entry(path, "directory", None, 0, "directory", None)
        elif member.issym():
            _safe_symlink_target(path, member.linkname)
            row = _entry(path, "symlink", None, 0, "symlink", member.linkname)
        elif member.isfile():
            extracted = archive.extractfile(member)
            if extracted is None:
                raise ValueError("TAR regular file cannot be read")
            digest, data = _digest_stream(
                extracted,
                int(member.size),
                maximum_expanded,
                retain=path.lower().endswith(_NESTED_SUFFIXES),
            )
            row = _entry(
                path,
                "file",
                digest,
                int(member.size),
                canonical_mode_class(member.mode),
                None,
            )
            _inspect_nested_if_needed(
                path,
                data,
                totals,
                depth,
                maximum_entries,
                maximum_expanded,
            )
        else:
            raise ValueError("TAR archive contains a hardlink or special file")
        entries.append(row)
        metadata.append(
            {
                "path": path,
                "mode": int(member.mode),
                "mtime": int(member.mtime),
                "uid": int(member.uid),
                "gid": int(member.gid),
                "uname": member.uname,
                "gname": member.gname,
                "paxDigest": sha256_digest(canonical_json_bytes(dict(sorted(member.pax_headers.items())))),
            }
        )
    return sorted(entries, key=lambda row: row["path"]), metadata


def _inspect_nested_if_needed(
    path: str,
    data: bytes | None,
    totals: dict[str, int],
    depth: int,
    maximum_entries: int,
    maximum_expanded: int,
) -> None:
    if data is None or not path.lower().endswith(_NESTED_SUFFIXES):
        return
    nested_depth = depth + 1
    if nested_depth > 8:
        raise ValueError("nested archive depth exceeds the closed bound")
    totals["nestedArchiveDepth"] = max(totals["nestedArchiveDepth"], nested_depth)
    stream = io.BytesIO(data)
    if path.lower().endswith((".jar", ".whl", ".zip")):
        with zipfile.ZipFile(stream) as nested:
            _inspect_zip(
                nested,
                totals,
                depth=nested_depth,
                maximum_entries=maximum_entries,
                maximum_expanded=maximum_expanded,
            )
    else:
        with tarfile.open(fileobj=stream, mode="r:*") as nested:
            _inspect_tar(
                nested,
                totals,
                depth=nested_depth,
                maximum_entries=maximum_entries,
                maximum_expanded=maximum_expanded,
            )


def _safe_archive_path(value: str) -> str:
    if not value or "\\" in value or "\x00" in value:
        raise ValueError("archive path is malformed")
    normalized = value[:-1] if value.endswith("/") else value
    path = PurePosixPath(normalized)
    if (
        path.is_absolute()
        or normalized != path.as_posix()
        or "//" in normalized
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("archive path is absolute or traversing")
    if len(normalized.encode("utf-8")) > 1024:
        raise ValueError("archive path exceeds the closed bound")
    for part in path.parts:
        if part in {"__MACOSX", ".DS_Store"} or part.startswith("._"):
            raise ValueError("archive contains prohibited host metadata")
    return path.as_posix()


def _register_path(path: str, seen: set[str], folded: set[str]) -> None:
    folded_path = path.casefold()
    if path in seen:
        raise ValueError("archive contains duplicate normalized paths")
    if folded_path in folded:
        raise ValueError("archive contains case-fold-colliding paths")
    seen.add(path)
    folded.add(folded_path)


def _safe_symlink_target(member_path: str, target: str) -> None:
    if not target or "\\" in target or "\x00" in target:
        raise ValueError("archive symlink target is malformed")
    link = PurePosixPath(target)
    if link.is_absolute():
        raise ValueError("archive symlink target is absolute")
    stack = list(PurePosixPath(member_path).parent.parts)
    for part in link.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not stack:
                raise ValueError("archive symlink escapes its root")
            stack.pop()
        else:
            stack.append(part)


def _entry(
    path: str,
    kind: str,
    digest: str | None,
    size: int,
    mode_class: str,
    symlink_target: str | None,
) -> dict[str, Any]:
    return {
        "path": path,
        "kind": kind,
        "digest": digest,
        "size": size,
        "modeClass": mode_class,
        "symlinkTarget": symlink_target,
    }


def canonical_mode_class(mode: int) -> str:
    """Return the policy mode class while preserving writable regular files."""

    permissions = stat.S_IMODE(mode)
    if permissions & 0o111:
        return "executable"
    if permissions and not permissions & 0o222:
        return "read-only"
    return "regular"


def _digest_zip_entry(
    archive: zipfile.ZipFile, info: zipfile.ZipInfo, maximum_expanded: int
) -> tuple[str, bytes | None]:
    with archive.open(info, "r") as stream:
        return _digest_stream(
            stream,
            int(info.file_size),
            maximum_expanded,
            retain=info.filename.lower().endswith(_NESTED_SUFFIXES),
        )


def _read_zip_entry(
    archive: zipfile.ZipFile, info: zipfile.ZipInfo, maximum_expanded: int
) -> bytes:
    if info.file_size > maximum_expanded:
        raise ValueError("ZIP entry exceeds the expansion bound")
    with archive.open(info, "r") as stream:
        data = stream.read(4097)
    if len(data) != info.file_size or len(data) > 4096:
        raise ValueError("ZIP entry size differs or exceeds the expansion bound")
    return data


def _digest_stream(
    stream: BinaryIO,
    expected_size: int,
    maximum_expanded: int,
    *,
    retain: bool = False,
) -> tuple[str, bytes | None]:
    if expected_size < 0 or expected_size > maximum_expanded:
        raise ValueError("archive entry exceeds the expansion bound")
    if retain and expected_size > _MAX_NESTED_ARCHIVE_BYTES:
        raise ValueError("nested archive exceeds the bounded inspection size")
    digest = hashlib.sha256()
    total = 0
    retained = bytearray() if retain else None
    while True:
        chunk = stream.read(_READ_CHUNK)
        if not chunk:
            break
        total += len(chunk)
        if total > expected_size or total > maximum_expanded:
            raise ValueError("archive entry expands beyond its declared size")
        digest.update(chunk)
        if retained is not None:
            retained.extend(chunk)
    if total != expected_size:
        raise ValueError("archive entry size differs from its declared size")
    return "sha256:" + digest.hexdigest(), bytes(retained) if retained is not None else None


def _check_totals(
    totals: dict[str, int], maximum_entries: int, maximum_expanded: int, depth: int
) -> None:
    if totals["entryCount"] > maximum_entries:
        raise ValueError("archive entry count exceeds the policy bound")
    if totals["expandedBytes"] > maximum_expanded:
        raise ValueError("archive expansion exceeds the policy bound")
    if depth > 8:
        raise ValueError("nested archive depth exceeds the closed bound")

"""Safe actual-byte inspection for Stable supply-chain archive subjects."""

from __future__ import annotations

import bz2
import hashlib
import io
import lzma
import stat
import tarfile
import zipfile
import zlib
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
_ZIP_LOCAL_SIGNATURE = b"PK\x03\x04"
_ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP_EOCD_MINIMUM_BYTES = 22
_ZIP_MAXIMUM_COMMENT_BYTES = 65_535
_ZIP_TAIL_BYTES = _ZIP_EOCD_MINIMUM_BYTES + _ZIP_MAXIMUM_COMMENT_BYTES


def inspect_archive_safety(
    subject_path: Path,
    *,
    maximum_entries: int,
    maximum_expanded_bytes: int,
    reject_links: bool = True,
    reject_nested_archives: bool = True,
) -> dict[str, int]:
    """Inspect archive bytes with the canonical Stable supply-chain hygiene rules.

    The protected-release preflight intentionally applies a stricter dispatch-package
    boundary than the general supply-chain payload inspector: symbolic links and nested
    archives are rejected instead of being represented in a payload manifest.  Keeping
    this small public adapter here ensures both callers use the same canonical path,
    duplicate, case-fold collision, metadata, and expansion-bound checks.
    """

    package_type = _package_type(subject_path, {})
    try:
        entries, _metadata, totals = _inspect_path(
            subject_path,
            package_type,
            maximum_entries=maximum_entries,
            maximum_expanded=maximum_expanded_bytes,
            detect_nested_by_content=reject_nested_archives,
        )
    except ValueError:
        raise
    except (
        EOFError,
        NotImplementedError,
        RuntimeError,
        tarfile.TarError,
        zipfile.BadZipFile,
    ) as exc:
        raise ValueError(f"archive reader rejected input: {type(exc).__name__}") from exc
    if reject_links and any(row.get("kind") == "symlink" for row in entries):
        raise ValueError("archive contains a symbolic link")
    if reject_nested_archives and totals["nestedArchiveDepth"] != 0:
        raise ValueError("archive contains a nested archive")
    return totals


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
    detect_nested_by_content: bool = False,
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
                detect_nested_by_content=detect_nested_by_content,
            )
    else:
        with tarfile.open(path, mode="r:*") as archive:
            entries, metadata = _inspect_tar(
                archive,
                totals,
                depth=0,
                maximum_entries=maximum_entries,
                maximum_expanded=maximum_expanded,
                detect_nested_by_content=detect_nested_by_content,
            )
    return entries, metadata, totals


def _inspect_zip(
    archive: zipfile.ZipFile,
    totals: dict[str, int],
    *,
    depth: int,
    maximum_entries: int,
    maximum_expanded: int,
    detect_nested_by_content: bool = False,
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
            digest, data = _digest_zip_entry(
                archive,
                info,
                maximum_expanded,
                detect_nested_by_content=detect_nested_by_content,
            )
            mode_class = canonical_mode_class(mode)
            row = _entry(path, "file", digest, int(info.file_size), mode_class, None)
            _inspect_nested_if_needed(
                path,
                data,
                totals,
                depth,
                maximum_entries,
                maximum_expanded,
                detect_nested_by_content,
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
    detect_nested_by_content: bool = False,
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
                detect_archive=detect_nested_by_content,
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
                detect_nested_by_content,
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
    detect_nested_by_content: bool,
) -> None:
    if data is None:
        return
    archive_kind = _nested_archive_kind(path, data)
    if archive_kind is None:
        return
    nested_depth = depth + 1
    if nested_depth > 8:
        raise ValueError("nested archive depth exceeds the closed bound")
    totals["nestedArchiveDepth"] = max(totals["nestedArchiveDepth"], nested_depth)
    stream = io.BytesIO(data)
    if archive_kind == "zip":
        with zipfile.ZipFile(stream) as nested:
            _inspect_zip(
                nested,
                totals,
                depth=nested_depth,
                maximum_entries=maximum_entries,
                maximum_expanded=maximum_expanded,
                detect_nested_by_content=detect_nested_by_content,
            )
    else:
        with tarfile.open(fileobj=stream, mode="r:*") as nested:
            _inspect_tar(
                nested,
                totals,
                depth=nested_depth,
                maximum_entries=maximum_entries,
                maximum_expanded=maximum_expanded,
                detect_nested_by_content=detect_nested_by_content,
            )


def _nested_archive_kind(path: str, data: bytes) -> str | None:
    """Identify a supported nested container by declared name or exact bytes."""

    lowered = path.lower()
    if lowered.endswith((".jar", ".whl", ".zip")):
        return "zip"
    if lowered.endswith((".tar", ".tar.gz", ".tgz")):
        return "tar"
    return _archive_stream_kind(io.BytesIO(data))


def _archive_stream_kind(stream: BinaryIO) -> str | None:
    """Identify exact ZIP/JAR or TAR/TAR.GZ bytes without trusting a filename."""

    original_position = stream.tell()
    try:
        stream.seek(0)
        if zipfile.is_zipfile(stream):
            return "zip"
        stream.seek(0)
        try:
            with tarfile.open(fileobj=stream, mode="r:*") as archive:
                return "tar" if archive.next() is not None else None
        except (EOFError, OSError, tarfile.TarError):
            return None
    finally:
        stream.seek(original_position)


class _StreamingArchiveDetector:
    """Detect nested containers without retaining an ordinary entry's full bytes."""

    def __init__(self) -> None:
        self._raw_prefix = bytearray()
        self._zip_overlap = b""
        self._zip_local_header_seen = False
        self._zip_tail = bytearray()
        self._compression_pending = bytearray()
        self._compression_kind: str | None = None
        self._decompressor: Any | bool | None = None
        self._decompressed_prefix = bytearray()
        self._decompression_failed = False

    def feed(self, chunk: bytes) -> None:
        if len(self._raw_prefix) < 512:
            self._raw_prefix.extend(chunk[: 512 - len(self._raw_prefix)])

        scan = self._zip_overlap + chunk
        if _ZIP_LOCAL_SIGNATURE in scan:
            self._zip_local_header_seen = True
        self._zip_overlap = scan[-3:]
        self._zip_tail.extend(chunk)
        if len(self._zip_tail) > _ZIP_TAIL_BYTES:
            del self._zip_tail[:-_ZIP_TAIL_BYTES]

        if self._decompressor is None:
            self._compression_pending.extend(chunk)
            if len(self._compression_pending) >= 6:
                self._initialize_decompressor()
        elif self._decompressor is not False:
            self._feed_decompressor(chunk)

    def kind(self) -> str | None:
        if self._decompressor is None:
            self._initialize_decompressor()
        if _tar_header_has_member(bytes(self._raw_prefix)) or _tar_header_has_member(
            bytes(self._decompressed_prefix)
        ):
            return "tar"
        if _zip_tail_has_eocd(
            bytes(self._zip_tail),
            local_header_seen=self._zip_local_header_seen,
        ):
            return "zip"
        return None

    def _initialize_decompressor(self) -> None:
        pending = bytes(self._compression_pending)
        self._compression_pending.clear()
        if pending.startswith(b"\x1f\x8b"):
            self._compression_kind = "gzip"
            self._decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif pending.startswith(b"BZh"):
            self._compression_kind = "bzip2"
            self._decompressor = bz2.BZ2Decompressor()
        elif pending.startswith(b"\xfd7zXZ\x00"):
            self._compression_kind = "xz"
            self._decompressor = lzma.LZMADecompressor()
        else:
            self._decompressor = False
            return
        self._feed_decompressor(pending)

    def _feed_decompressor(self, chunk: bytes) -> None:
        if self._decompression_failed or len(self._decompressed_prefix) >= 512:
            return
        remaining = 512 - len(self._decompressed_prefix)
        try:
            decompressor = self._decompressor
            if self._compression_kind == "gzip":
                output = decompressor.decompress(chunk, remaining)
            else:
                output = decompressor.decompress(chunk, max_length=remaining)  # type: ignore[union-attr]
        except (EOFError, OSError, ValueError, zlib.error):
            self._decompression_failed = True
            return
        self._decompressed_prefix.extend(output)


def _tar_header_has_member(data: bytes) -> bool:
    if len(data) < 512:
        return False
    try:
        with tarfile.open(fileobj=io.BytesIO(data[:512]), mode="r:") as archive:
            return archive.next() is not None
    except (EOFError, OSError, tarfile.TarError):
        return False


def _zip_tail_has_eocd(tail: bytes, *, local_header_seen: bool) -> bool:
    position = tail.rfind(_ZIP_EOCD_SIGNATURE)
    while position >= 0:
        if len(tail) - position >= _ZIP_EOCD_MINIMUM_BYTES:
            comment_length = int.from_bytes(tail[position + 20 : position + 22], "little")
            if position + _ZIP_EOCD_MINIMUM_BYTES + comment_length == len(tail):
                entry_count = int.from_bytes(tail[position + 10 : position + 12], "little")
                directory_size = int.from_bytes(tail[position + 12 : position + 16], "little")
                return local_header_seen or (entry_count == 0 and directory_size == 0)
        position = tail.rfind(_ZIP_EOCD_SIGNATURE, 0, position)
    return False


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
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    maximum_expanded: int,
    *,
    detect_nested_by_content: bool = False,
) -> tuple[str, bytes | None]:
    with archive.open(info, "r") as stream:
        return _digest_stream(
            stream,
            int(info.file_size),
            maximum_expanded,
            retain=info.filename.lower().endswith(_NESTED_SUFFIXES),
            detect_archive=detect_nested_by_content,
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
    detect_archive: bool = False,
) -> tuple[str, bytes | None]:
    if expected_size < 0 or expected_size > maximum_expanded:
        raise ValueError("archive entry exceeds the expansion bound")
    if retain and not detect_archive and expected_size > _MAX_NESTED_ARCHIVE_BYTES:
        raise ValueError("archive entry exceeds the bounded content inspection size")
    digest = hashlib.sha256()
    total = 0
    retained = bytearray() if retain and not detect_archive else None
    detector = _StreamingArchiveDetector() if detect_archive else None
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
        if detector is not None:
            detector.feed(chunk)
    if total != expected_size:
        raise ValueError("archive entry size differs from its declared size")
    if detect_archive and (retain or detector is not None and detector.kind() is not None):
        raise ValueError("archive contains a nested archive")
    if retained is None:
        return "sha256:" + digest.hexdigest(), None
    data = bytes(retained)
    return "sha256:" + digest.hexdigest(), data


def _check_totals(
    totals: dict[str, int], maximum_entries: int, maximum_expanded: int, depth: int
) -> None:
    if totals["entryCount"] > maximum_entries:
        raise ValueError("archive entry count exceeds the policy bound")
    if totals["expandedBytes"] > maximum_expanded:
        raise ValueError("archive expansion exceeds the policy bound")
    if depth > 8:
        raise ValueError("nested archive depth exceeds the closed bound")

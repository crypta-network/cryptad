"""Shared fail-closed scanning for v2 manifests and migrated JSON evidence."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import unquote, urlsplit

PRIVATE_URI_RE = re.compile(r"\b(?:SSK|USK)@[A-Za-z0-9~_-]+,[A-Za-z0-9~_-]+,AQECAAE/")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")
AUTH_RE = re.compile(
    r"(?i)\b(?:authorization\s*[:=]\s*(?:bearer|basic)"
    r"|bearer\s+[A-Za-z0-9._~+/=-]{12,}"
    r"|basic\s+(?:(?:[A-Za-z0-9+/]{4})+"
    r"|(?:[A-Za-z0-9+/]{4})*[A-Za-z0-9+/]{2}=="
    r"|(?:[A-Za-z0-9+/]{4})*[A-Za-z0-9+/]{3}=)"
    r"(?![A-Za-z0-9+/=]))"
)
SECRET_ASSIGNMENT_RE = re.compile(r"(?i)\b(?:password|token|secret|private[_-]?key)\s*[:=]\s*[^<\s][^\s,;]{3,}")
UNIX_PATH_RE = re.compile(r"(?<![A-Za-z0-9:/])/(?!/)[^\s\"'<>]+")
WINDOWS_PATH_RE = re.compile(r"(?i)(?<![A-Za-z0-9])[A-Z]:[\\/][^\s\"'<>]+")
WINDOWS_UNC_PATH_RE = re.compile(r"(?i)(?<![A-Za-z0-9])\\\\[^\\\s\"'<>]+\\[^\s\"'<>]+")
SAFE_PUBLIC_ROUTE_ROOTS = ("/api/v1", "/apps", "/app/node", "/core-update")
PUBLIC_ROUTE_FIELD_MARKERS = ("route", "endpoint", "url", "href")
LOCAL_PATH_FIELD_MARKERS = (
    "archive",
    "artifact",
    "directory",
    "file",
    "output",
    "report",
    "root",
    "source",
    "summary",
    "workspace",
)
PUBLIC_ROUTE_FRAGMENT_RE = re.compile(r"[A-Za-z0-9._~-]+")
REPO_PLACEHOLDER_PREFIX = "<repo>/"
REPO_PATH_SEGMENT_RE = re.compile(r"[A-Za-z0-9._+@=-]+")
SENSITIVE_FIELD_FRAGMENTS = (
    "authorization",
    "cookie",
    "credential",
    "password",
    "privateinserturi",
    "privatekey",
    "rawappdata",
    "rawbody",
    "rawcontent",
    "rawdata",
    "rawdiagnostic",
    "rawfeed",
    "rawrequest",
    "rawresponse",
    "rawsignature",
    "rawsocial",
    "rawsupportbundle",
    "rawtrust",
    "rawupdaterollback",
    "requestbody",
    "responsebody",
    "secret",
    "token",
)
SAFE_SENSITIVE_FIELD_MARKERS = (
    "digest",
    "excluded",
    "fingerprint",
    "notincluded",
    "notpersisted",
    "notstored",
    "redacted",
    "sanitized",
)
SAFE_SENSITIVE_FIELD_SUFFIXES = (
    "bytes",
    "count",
    "counts",
    "hash",
    "id",
    "ids",
    "length",
    "sha256",
    "shape",
    "size",
    "status",
)
SAFE_BOOLEAN_FIELD_MARKERS = (
    "checked",
    "enabled",
    "failon",
    "present",
    "provided",
    "required",
)
MANIFEST_PRIVATE_MARKER_RE = re.compile(
    r"\b(?:SSK|USK)@|-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"
)
MANIFEST_CREDENTIAL_RE = re.compile(
    r"(?i)(?:\b(?:authorization|cookie|set-cookie|password|token|secret|private[_-]?key|credential|api[_-]?key)"
    r"\s*[:=]\s*[^\s,;]{3,}|\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,})"
)
URL_CREDENTIAL_RE = re.compile(
    r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@"
)


def _normalized_field_name(value: Any) -> str:
    """Return a case-insensitive field name without punctuation or separators."""

    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def _field_can_contain_sensitive_payload(key: Any, value: Any) -> bool:
    """Return whether a JSON field name and value can carry publishable private material."""

    normalized = _normalized_field_name(key)
    if not any(fragment in normalized for fragment in SENSITIVE_FIELD_FRAGMENTS):
        return False
    if value is None or value is False:
        return False
    if any(marker in normalized for marker in SAFE_SENSITIVE_FIELD_MARKERS):
        return False
    if normalized.endswith(SAFE_SENSITIVE_FIELD_SUFFIXES):
        return False
    if (
        isinstance(value, dict)
        and value.get("const") is False
        and normalized.endswith(("included", "persisted", "present", "stored"))
    ):
        return False
    if isinstance(value, bool) and any(
        marker in normalized for marker in SAFE_BOOLEAN_FIELD_MARKERS
    ):
        return False
    return True


def _contains_sensitive_field(value: Any) -> bool:
    """Inspect nested JSON keys without copying field values into findings."""

    if isinstance(value, dict):
        return any(
            _field_can_contain_sensitive_payload(key, child)
            or _contains_sensitive_field(child)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return any(_contains_sensitive_field(child) for child in value)
    return False


def _string_contexts(
    value: Any,
    field_path: tuple[Any, ...] = (),
    parent: dict[Any, Any] | None = None,
):
    """Yield nested strings with their field path and nearest containing object."""

    if isinstance(value, str):
        yield field_path, parent, value
    elif isinstance(value, dict):
        for key, child in value.items():
            yield from _string_contexts(child, field_path + (key,), value)
    elif isinstance(value, list):
        for child in value:
            yield from _string_contexts(child, field_path, parent)


def _is_safe_repo_placeholder(value: str) -> bool:
    """Return whether one complete string is a canonical redacted repository path."""

    if not value.startswith(REPO_PLACEHOLDER_PREFIX):
        return False
    relative = value.removeprefix(REPO_PLACEHOLDER_PREFIX)
    if relative in {"", "."}:
        return True
    if relative.endswith("/"):
        relative = relative[:-1]
    if not relative or relative.startswith("/") or "\\" in relative or "\x00" in relative:
        return False
    return all(
        part not in {"", ".", ".."}
        and REPO_PATH_SEGMENT_RE.fullmatch(part) is not None
        for part in relative.split("/")
    )


def _field_allows_public_route(
    field_path: tuple[Any, ...],
    parent: dict[Any, Any] | None,
) -> bool:
    """Return whether the JSON field context explicitly represents a public route."""

    normalized = tuple(_normalized_field_name(field) for field in field_path)
    if normalized and any(marker in normalized[-1] for marker in LOCAL_PATH_FIELD_MARKERS):
        return False
    if any(
        marker in field
        for field in normalized
        for marker in PUBLIC_ROUTE_FIELD_MARKERS
    ):
        return True
    return bool(
        normalized
        and normalized[-1] == "path"
        and isinstance(parent, dict)
        and isinstance(parent.get("method"), str)
    )


def _is_normalized_public_route(
    field_path: tuple[Any, ...],
    parent: dict[Any, Any] | None,
    value: str,
) -> bool:
    """Return whether a context-bound string is one canonical public HTTP route."""

    if not _field_allows_public_route(field_path, parent):
        return False
    if not value.startswith("/") or "\\" in value or "\x00" in value or any(
        character.isspace() for character in value
    ):
        return False
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or parsed.query:
        return False
    decoded_path = parsed.path
    while True:
        unquoted = unquote(decoded_path)
        if unquoted == decoded_path:
            break
        decoded_path = unquoted
    if "\\" in decoded_path or "\x00" in decoded_path:
        return False
    segments = decoded_path.split("/")[1:]
    if segments and segments[-1] == "":
        segments.pop()
    if any(segment in {"", ".", ".."} for segment in segments):
        return False
    if parsed.fragment and PUBLIC_ROUTE_FRAGMENT_RE.fullmatch(parsed.fragment) is None:
        return False
    return any(
        decoded_path == route or decoded_path.startswith(f"{route}/")
        for route in SAFE_PUBLIC_ROUTE_ROOTS
    )


def _contains_local_absolute_path(value: Any) -> tuple[bool, bool]:
    """Return whether nested strings contain POSIX or Windows filesystem paths."""

    unix_found = False
    windows_found = False
    for field_path, parent, text in _string_contexts(value):
        if _is_safe_repo_placeholder(text):
            continue
        if text.startswith(REPO_PLACEHOLDER_PREFIX):
            unix_found = True
        if _is_normalized_public_route(field_path, parent, text):
            continue
        if UNIX_PATH_RE.search(text):
            unix_found = True
        if WINDOWS_PATH_RE.search(text) or WINDOWS_UNC_PATH_RE.search(text):
            windows_found = True
        if unix_found and windows_found:
            break
    return unix_found, windows_found


def scan_value(value: Any) -> list[dict[str, str]]:
    """Return finding categories without copying sensitive matched values."""

    text = json.dumps(value, sort_keys=True, ensure_ascii=False)
    checks = (
        ("private-insert-uri", PRIVATE_URI_RE),
        ("private-key", PRIVATE_KEY_RE),
        ("authorization", AUTH_RE),
        ("secret-assignment", SECRET_ASSIGNMENT_RE),
    )
    categories = {category for category, pattern in checks if pattern.search(text)}
    if _contains_sensitive_field(value):
        categories.add("sensitive-field")
    unix_path, windows_path = _contains_local_absolute_path(value)
    if unix_path:
        categories.add("absolute-path")
    if windows_path:
        categories.add("windows-path")
    return [
        {"category": category, "summary": f"{category} material is not allowed in v2 evidence"}
        for category in sorted(categories)
    ]


def scan_manifest_scalar(value: str) -> list[dict[str, str]]:
    """Find secret material in one manifest string without treating paths as evidence leaks."""

    findings = {
        finding["category"]: finding
        for finding in scan_value(value)
        if finding["category"] not in {"absolute-path", "windows-path"}
    }
    if MANIFEST_PRIVATE_MARKER_RE.search(value):
        findings["private-material"] = {
            "category": "private-material",
            "summary": "private material is not allowed in a v2 manifest",
        }
    if MANIFEST_CREDENTIAL_RE.search(value) or URL_CREDENTIAL_RE.search(value):
        findings["credential"] = {
            "category": "credential",
            "summary": "credential material is not allowed in a v2 manifest",
        }
    return [findings[key] for key in sorted(findings)]

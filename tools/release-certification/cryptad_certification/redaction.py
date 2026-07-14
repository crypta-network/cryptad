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
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(?<![a-z0-9])"
    r"(?:[a-z][a-z0-9_-]*)?"
    r"(?:password|passphrase|token|secret|private[_-]?key|api[_-]?key|credential)"
    r"\s*[:=]\s*(?!<|redacted\b)[^\s,;]{3,}"
)
COOKIE_HEADER_RE = re.compile(
    r"(?i)\b(?:cookie|set-cookie)\s*:\s*"
    r"[^\s=;,]+\s*=\s*(?!<|redacted\b)[^\s;,]{3,}"
)
# A colon is intentionally not excluded: labels such as ``workspace:/home/...`` must not hide a
# local path. Normal URLs remain excluded by their ``://`` authority separator and by the
# alphanumeric lookbehind on later URL path segments. Colon-adjacent matches are rejected before
# public-route exemptions are considered below.
UNIX_PATH_RE = re.compile(r"(?<![A-Za-z0-9/.}\]])/(?!/)[^\s\"'<>]*")
UNIX_REPEATED_SEPARATOR_RE = re.compile(
    r"(?<![A-Za-z0-9:/.}\]])/{2,}[^\s\"'<>]*"
)
WINDOWS_PATH_RE = re.compile(r"(?i)(?<![A-Za-z0-9])[A-Z]:[\\/][^\s\"'<>]*")
WINDOWS_UNC_PATH_RE = re.compile(r"(?i)(?<![A-Za-z0-9])\\\\[^\\\s\"'<>]+\\[^\s\"'<>]+")
FILE_URI_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9+.-])file:(?://[^/\\\s\"'<>]*)?[/\\][^\s\"'<>]*"
)
SAFE_PUBLIC_ROUTE_ROOTS = (
    "/api/v1",
    "/apps",
    "/app/node",
    "/app-data",
    "/app-vault",
    "/content",
    "/core-update",
    "/filterfile",
    "/identity-vault",
    "/operator",
    "/platform",
    "/queue",
    "/trust-graph",
    "/.well-known",
    "/{CHK,SSK,USK,KSK}@...",
)
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
REPO_PATH_SEGMENT_RE = re.compile(r"[A-Za-z0-9._+@={}-]+")
SANITIZED_PATH_PLACEHOLDER_RE = re.compile(
    r"(?:file://)?<(?:repo|home|workdir|path)>[^\s\"'<>),;:\]]*"
)
SAFE_REDACTED_VALUES = {
    "<redacted>",
    "<redacted-private-artifact>",
    "<redacted-private-key>",
    "<redacted-uri>",
    "<token-redacted>",
    "redacted",
}
SAFE_ABSENCE_VALUES = {
    "absent",
    "disabled",
    "missing",
    "none",
    "not-observed",
    "not-provided",
    "unavailable",
}
SAFE_NEGATIVE_FINDING_LABELS = {
    "authorization-header",
    "cookie",
    "credential-or-path marker",
    "local path",
    "local-absolute-path",
    "migration-raw-artifact",
    "partial-redaction",
    "private insert URI",
    "private-insert-uri",
    "private-key-assignment",
    "private-key-block",
    "raw migration artifact",
    "token-assignment",
}
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
SAFE_BOOLEAN_FIELD_MARKERS = (
    "checked",
    "covered",
    "enabled",
    "failon",
    "present",
    "provided",
    "required",
)
SHA256_METADATA_RE = re.compile(r"(?:sha256:)?[0-9a-fA-F]{64}")
SAFE_METADATA_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,127}")
SAFE_METADATA_STATUS_VALUES = {
    "clean",
    "fail",
    "failed",
    "pass",
    "passed",
    "redacted",
    "safe",
    "skipped",
    "warn",
    "warning",
}
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


def _is_safe_sensitive_metadata(normalized: str, value: Any) -> bool:
    """Recognize scalar safety metadata without exempting nested payloads."""

    if isinstance(value, (dict, list)):
        return False
    if any(
        marker in normalized
        for marker in ("excluded", "notincluded", "notpersisted", "notstored")
    ):
        return value is True
    if any(marker in normalized for marker in ("redacted", "sanitized")):
        return value is True or value in SAFE_REDACTED_VALUES
    if normalized.endswith(("hash", "sha256")) or any(
        marker in normalized for marker in ("digest", "fingerprint")
    ):
        return isinstance(value, str) and SHA256_METADATA_RE.fullmatch(value) is not None
    if normalized.endswith(("bytes", "count", "counts", "length", "size")):
        return isinstance(value, int) and not isinstance(value, bool) and value >= 0
    if normalized.endswith(("id", "ids", "shape")):
        return (
            isinstance(value, str)
            and SAFE_METADATA_IDENTIFIER_RE.fullmatch(value) is not None
        )
    if normalized.endswith("status"):
        return isinstance(value, str) and value.lower() in (
            SAFE_METADATA_STATUS_VALUES | SAFE_ABSENCE_VALUES
        )
    return False


def _field_can_contain_sensitive_payload(key: Any, value: Any) -> bool:
    """Return whether a JSON field name and value can carry publishable private material."""

    normalized = _normalized_field_name(key)
    if not any(fragment in normalized for fragment in SENSITIVE_FIELD_FRAGMENTS):
        return False
    if value is None or value is False:
        return False
    if isinstance(value, str) and value in SAFE_REDACTED_VALUES:
        return False
    if (
        isinstance(value, str)
        and value in SAFE_ABSENCE_VALUES
        and normalized.endswith(("source", "status"))
    ):
        return False
    if isinstance(key, str) and key.endswith(".json") and _is_safe_negative_fixture_result(value):
        return False
    if (
        isinstance(value, dict)
        and set(value) == {"const"}
        and value.get("const") is False
        and normalized.endswith(("included", "persisted", "present", "stored"))
    ):
        return False
    if isinstance(value, bool) and any(
        marker in normalized for marker in SAFE_BOOLEAN_FIELD_MARKERS
    ):
        return False
    if _is_safe_sensitive_metadata(normalized, value):
        return False
    return True


def _is_safe_negative_fixture_result(value: Any) -> bool:
    """Recognize sanitized negative-test outcomes without accepting fixture payloads."""

    if isinstance(value, str):
        return value in SAFE_REDACTED_VALUES
    if isinstance(value, list):
        return bool(value) and all(item in SAFE_NEGATIVE_FINDING_LABELS for item in value)
    if not isinstance(value, dict) or set(value) != {"detectedKinds", "expectedKind", "passes"}:
        return False
    detected = value.get("detectedKinds")
    expected = value.get("expectedKind")
    return (
        value.get("passes") is True
        and isinstance(detected, list)
        and bool(detected)
        and all(item in SAFE_NEGATIVE_FINDING_LABELS for item in detected)
        and expected in SAFE_NEGATIVE_FINDING_LABELS
        and expected in detected
    )


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


def _is_safe_path_placeholder(value: str) -> bool:
    """Return whether one complete string is a canonical sanitized filesystem placeholder."""

    candidate = value.removeprefix("file://")
    match = re.fullmatch(r"<(repo|home|workdir|path)>(.*)", candidate)
    if match is None:
        return False
    relative = match.group(2)
    if relative == "":
        return True
    if not relative.startswith("/"):
        return False
    relative = relative[1:]
    if relative == ".":
        return match.group(1) == "repo"
    if relative.endswith("/"):
        relative = relative[:-1]
    if not relative or "\\" in relative or "\x00" in relative:
        return False
    return all(
        part not in {"", ".", ".."}
        and REPO_PATH_SEGMENT_RE.fullmatch(part) is not None
        for part in relative.split("/")
    )


def _is_safe_repo_placeholder(value: str) -> bool:
    """Return whether one complete string is a canonical redacted repository path."""

    return value.startswith("<repo>") and _is_safe_path_placeholder(value)


def _strip_safe_path_placeholders(value: str) -> tuple[str, bool]:
    """Remove canonical placeholders and report malformed placeholder-shaped values."""

    malformed = False

    def replace(match: re.Match[str]) -> str:
        nonlocal malformed
        candidate = match.group(0)
        if _is_safe_path_placeholder(candidate):
            return "<sanitized-path>"
        malformed = True
        return candidate

    return SANITIZED_PATH_PLACEHOLDER_RE.sub(replace, value), malformed


def _field_allows_public_route(
    field_path: tuple[Any, ...],
    parent: dict[Any, Any] | None,
) -> bool:
    """Return whether the JSON field context explicitly represents a public route."""

    normalized = tuple(_normalized_field_name(field) for field in field_path)
    last_has_public_marker = bool(
        normalized
        and any(marker in normalized[-1] for marker in PUBLIC_ROUTE_FIELD_MARKERS)
    )
    ancestor_has_public_marker = any(
        marker in field
        for field in normalized[:-1]
        for marker in PUBLIC_ROUTE_FIELD_MARKERS
    )
    if (
        normalized
        and any(marker in normalized[-1] for marker in LOCAL_PATH_FIELD_MARKERS)
        and not last_has_public_marker
        and not ancestor_has_public_marker
    ):
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
        scan_text, malformed_placeholder = _strip_safe_path_placeholders(text)
        if malformed_placeholder or FILE_URI_RE.search(scan_text):
            unix_found = True
        if UNIX_REPEATED_SEPARATOR_RE.search(scan_text):
            unix_found = True
        for match in UNIX_PATH_RE.finditer(scan_text):
            colon_prefixed = match.start() > 0 and scan_text[match.start() - 1] == ":"
            if colon_prefixed or not _is_normalized_public_route(
                field_path, parent, match.group(0)
            ):
                unix_found = True
        if WINDOWS_PATH_RE.search(scan_text) or WINDOWS_UNC_PATH_RE.search(scan_text):
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
        ("cookie", COOKIE_HEADER_RE),
        ("secret-assignment", SECRET_ASSIGNMENT_RE),
        ("url-credential", URL_CREDENTIAL_RE),
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

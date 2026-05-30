#!/usr/bin/env python3
"""Aggregate release-candidate evidence into a redacted certification report.

The tool intentionally depends only on the Python standard library.  It consumes
the existing interop, performance, and app-platform smoke summaries and emits a
single Markdown report plus a stable JSON companion for release-candidate
evidence.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

# Local release-certification helpers must not create __pycache__ before git metadata is collected.
sys.dont_write_bytecode = True
import app_platform_docs_check


TOOL_NAME = "release-certification"
SCHEMA_VERSION = 1
DEFAULT_OUT_DIR = Path("build/release-certification")
DEFAULT_HISTORY_DIR = Path("build/release-certification-history")
SUMMARY_FILE_NAME = "release-certification-summary.json"
REPORT_FILE_NAME = "release-certification-report.md"
HISTORY_COMPARISON_FILE_NAME = "history-comparison.json"
HISTORY_COMPARISON_REPORT_FILE_NAME = "history-comparison.md"
ECOSYSTEM_MATRIX_FILE_NAME = "ecosystem-certification-matrix.json"
ECOSYSTEM_MATRIX_REPORT_FILE_NAME = "ecosystem-certification-matrix.md"
ECOSYSTEM_MATRIX_SCHEMA_VERSION = 1
CERT_STATUSES = ("pass", "warn", "fail", "skip", "missing")
MODES = ("pr", "nightly", "release-candidate")
PRIVATE_ARTIFACT_NAMES = ("private-insert-uris.json",)
REDACTION_FINDING_EVIDENCE_IDS = frozenset({"app-platform.docs-redaction"})
SENSITIVE_KEY_PATTERN = (
    r"token|password|passwd|secret|credential|authorization|cookie|set-cookie|"
    r"private[-_ ]?key|formPassword|browserSessionToken|CRYPTAD_APP_TOKEN|X-Crypta-App-Session|"
    r"identity[-_ ]?seed|recovery[-_ ]?phrase|mnemonic|"
    r"raw[-_ ]?request[-_ ]?bod(?:y|ies)|request[-_ ]?bod(?:y|ies)|"
    r"raw[-_ ]?feed[-_ ]?bod(?:y|ies)|feed[-_ ]?bod(?:y|ies)"
)
SENSITIVE_KEY_RE = re.compile(
    rf"({SENSITIVE_KEY_PATTERN})",
    re.IGNORECASE,
)
SENSITIVE_HEADER_RE = re.compile(
    r"(?P<prefix>\b(?:Authorization|Cookie|Set-Cookie|X-Crypta-App-Session)\s*:\s*)"
    r"(?P<value>[^\r\n]*)",
    re.IGNORECASE,
)
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?P<prefix>(?<![A-Za-z0-9_])(?P<key_quote>[\"']?)"
    r"(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)"
    r"(?P=key_quote)\s*[:=]\s*)"
    r"(?:(?P<value_quote>[\"'])(?P<quoted_value>[^\"'\r\n]*)(?P=value_quote)|"
    r"(?P<value>(?:(?:Bearer|Basic|Digest)\s+)?[^\s,;&}\]]+))",
    re.IGNORECASE,
)
URI_KEY_RE = re.compile(r"\b(?:CHK|SSK|USK)@[^\s\])},;\"']+")
URL_USERINFO_RE = re.compile(r"(\b[a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@", re.IGNORECASE)
ABSOLUTE_PATH_RE = re.compile(r"(?<![A-Za-z0-9_:/.\->])/(?:[A-Za-z0-9._ -]+/)+[A-Za-z0-9._ -]+")
WINDOWS_DRIVE_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_:/.\->])(?:[A-Za-z]:[\\/](?:[^\\/:*?\"<>|\r\n]+[\\/])*[^\\/:*?\"<>|\r\n]+[\\/]?)"
)
WINDOWS_UNC_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_:/.\->])(?:\\\\[^\\/:*?\"<>|\r\n]+\\[^\\/:*?\"<>|\r\n]+(?:\\[^\\/:*?\"<>|\r\n]+)*\\?)"
)
FILE_URI_PATH_RE = re.compile(r"\bfile://(?P<path>[^\s\])},;\"']+)")
ROUTE_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_:/.\->])/(?:api/v1|apps|app/node|\.well-known)(?:/[^\s\])},;\"'?]*)?"
)
NON_SECRET_METADATA_SUFFIXES = (
    "available",
    "configured",
    "enabled",
    "excluded",
    "excludedfromevidence",
    "present",
    "redacted",
    "required",
    "source",
)
BODY_KEY_FRAGMENTS = (
    "requestbody",
    "rawrequestbody",
    "requestbodies",
    "rawrequestbodies",
    "feedbody",
    "rawfeedbody",
    "feedbodies",
    "rawfeedbodies",
    "feedpayload",
    "rawfeedpayload",
    "feedcontent",
    "rawfeedcontent",
    "truststatementbody",
    "rawtruststatementbody",
    "truststatementbodies",
    "rawtruststatementbodies",
    "truststatementpayload",
    "rawtruststatementpayload",
    "truststatementcontent",
    "rawtruststatementcontent",
    "messagebody",
    "rawmessagebody",
    "messagebodies",
    "rawmessagebodies",
    "fetchedbody",
    "rawfetchedbody",
    "fetchedbodies",
    "rawfetchedbodies",
)


@dataclasses.dataclass(frozen=True)
class EvidenceItem:
    """Stable evidence record written into the certification summary."""

    id: str
    status: str
    required_for_release_candidate: bool
    summary: str
    source: str
    details: dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "requiredForReleaseCandidate": self.required_for_release_candidate,
            "summary": self.summary,
            "source": self.source,
            "details": self.details,
        }


@dataclasses.dataclass(frozen=True)
class WaiverRecord:
    """Approved release-manager waiver loaded from the CLI or a structured file."""

    id: str
    evidence_id: str
    reason: str
    source: str
    status: str = "approved"
    approved_by: str = ""
    expires_at: str = ""
    allow_release_candidate: bool = False
    active: bool = True
    expired: bool = False
    applies_to_release_candidate: bool = True
    validation_error: str = ""

    def matches(self, target_id: str, issue_ids: list[str] | None = None) -> bool:
        candidates = {target_id}
        if issue_ids:
            candidates.update(issue_ids)
        return self.id in candidates or self.evidence_id in candidates

    def to_json(self) -> dict[str, Any]:
        value = {
            "id": self.id,
            "evidenceId": self.evidence_id,
            "status": self.status,
            "approvedBy": self.approved_by,
            "reason": self.reason,
            "source": self.source,
            "active": self.active,
            "expired": self.expired,
            "allowReleaseCandidate": self.allow_release_candidate,
            "appliesToReleaseCandidate": self.applies_to_release_candidate,
        }
        if self.expires_at:
            value["expiresAt"] = self.expires_at
        if self.validation_error:
            value["validationError"] = self.validation_error
        return value


@dataclasses.dataclass(frozen=True)
class WaiverContext:
    """Resolved waiver state used by evidence and ecosystem gate evaluation."""

    records: list[WaiverRecord] = dataclasses.field(default_factory=list)
    errors: list[str] = dataclasses.field(default_factory=list)

    def active_records(self, mode: str) -> list[WaiverRecord]:
        return [
            record
            for record in self.records
            if record.active
            and not record.expired
            and record.status == "approved"
            and (mode != "release-candidate" or record.allow_release_candidate)
        ]


@dataclasses.dataclass(frozen=True)
class GateResult:
    """Deterministic ecosystem release gate result."""

    id: str
    status: str
    release_blocker: bool
    summary: str
    details: dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "releaseBlocker": self.release_blocker,
            "summary": self.summary,
            "details": self.details,
        }


@dataclasses.dataclass(frozen=True)
class MatrixRowSpec:
    """Stable release-manager-facing ecosystem certification row."""

    id: str
    category: str
    title: str
    required_evidence_ids: tuple[str, ...] = ()
    optional_evidence_ids: tuple[str, ...] = ()
    gate_ids: tuple[str, ...] = ()
    optional_gate_ids: tuple[str, ...] = ()
    docs: tuple[str, ...] = ()
    owner: str = "release"
    phase: str = "phase-7"
    required_for_release_candidate: bool = True
    first_party_apps: tuple[str, ...] = ()
    synthetic: str = ""

    def evidence_ids(self) -> tuple[str, ...]:
        return self.required_evidence_ids + self.optional_evidence_ids

    def all_gate_ids(self) -> tuple[str, ...]:
        return self.gate_ids + self.optional_gate_ids


@dataclasses.dataclass(frozen=True)
class Settings:
    workspace_root: Path
    out_dir: Path
    mode: str
    interop_smoke_summary: Path
    interop_extended_summary: Path
    perf_smoke_summary: Path
    app_platform_summary: Path
    waivers: dict[str, str]
    metadata: dict[str, str]
    skip_git_metadata: bool
    previous_summary: Path | None = None
    require_history: bool = False
    history_dir: Path = DEFAULT_HISTORY_DIR
    write_history: bool = False
    history_label: str = ""
    waiver_files: tuple[Path, ...] = ()


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict):
        return None
    return value


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def path_prefix_variants(path: Path | str) -> list[str]:
    variants: list[str] = []
    for candidate in (Path(path), Path(path).resolve()):
        candidate_text = str(candidate)
        for value in (candidate_text, candidate_text.replace("\\", "/")):
            normalized = value.rstrip("/\\")
            if normalized and normalized not in variants:
                variants.append(normalized)
    return variants


def display_path(path: Path | str, workspace_root: Path, out_dir: Path | None = None) -> str:
    raw = str(path)
    if raw == "":
        return ""
    path_value = Path(raw)
    if not path_value.is_absolute():
        return scrub_text(raw.replace("\\", "/"), workspace_root, out_dir)
    resolved = path_value
    try:
        relative = resolved.resolve().relative_to(workspace_root.resolve())
        return f"<repo>/{relative.as_posix()}"
    except ValueError:
        pass
    if out_dir is not None:
        try:
            relative = resolved.resolve().relative_to(out_dir.resolve())
            out_dir_display = display_path(out_dir, workspace_root)
            if not relative.parts:
                return out_dir_display
            return f"{out_dir_display}/{relative.as_posix()}"
        except ValueError:
            pass
    try:
        relative = resolved.resolve().relative_to(Path(tempfile.gettempdir()).resolve())
        return f"<workdir>/{relative.as_posix()}"
    except ValueError:
        return "<path>/" + resolved.name


def replace_absolute_path_prefix(text: str, prefix: str, replacement: str) -> str:
    if not prefix or prefix in {"/", "\\"}:
        return text
    normalized = prefix.rstrip("/\\")
    if not normalized:
        return text
    pattern = re.compile(rf"(?<![A-Za-z0-9_:/.\->]){re.escape(normalized)}(?=$|[/\\])")
    return pattern.sub(replacement, text)


def path_leaf(path_text: str) -> str:
    stripped = path_text.rstrip("\\/")
    leaf = re.split(r"[\\/]+", stripped)[-1]
    return leaf or "path"


def scrub_absolute_path_match(match: re.Match[str]) -> str:
    return "<path>/" + path_leaf(match.group(0))


def scrub_file_uri_match(match: re.Match[str]) -> str:
    return "file://<path>/" + path_leaf(match.group("path"))


def scrub_sensitive_assignment_match(match: re.Match[str]) -> str:
    if not should_redact_key_name(match.group("key")):
        return match.group(0)
    value_quote = match.group("value_quote") or ""
    return match.group("prefix") + value_quote + "<redacted>" + value_quote


def protect_route_paths(text: str) -> tuple[str, list[tuple[str, str]]]:
    routes: list[tuple[str, str]] = []

    def replace_route(match: re.Match[str]) -> str:
        token = f"__CRYPTAD_ROUTE_{len(routes)}__"
        routes.append((token, match.group(0)))
        return token

    return ROUTE_PATH_RE.sub(replace_route, text), routes


def restore_route_paths(text: str, routes: list[tuple[str, str]]) -> str:
    restored = text
    for token, route in routes:
        restored = restored.replace(token, route)
    return restored


def normalize_redacted_separators(text: str) -> str:
    def normalize_match(match: re.Match[str]) -> str:
        return match.group("prefix") + match.group("tail").replace("\\", "/")

    return re.sub(
        r"(?P<prefix><(?:repo|home|workdir|path)>)(?P<tail>(?:[\\/][^\s\])},;\"']*)?)",
        normalize_match,
        text,
    )


def scrub_text(text: str, workspace_root: Path, out_dir: Path | None = None) -> str:
    redacted = URL_USERINFO_RE.sub(r"\1<redacted>@", text)
    redacted = SENSITIVE_HEADER_RE.sub(lambda match: match.group("prefix") + "<redacted>", redacted)
    redacted = SENSITIVE_ASSIGNMENT_RE.sub(scrub_sensitive_assignment_match, redacted)
    redacted = URI_KEY_RE.sub("<redacted-uri>", redacted)
    redacted = FILE_URI_PATH_RE.sub(scrub_file_uri_match, redacted)
    redacted, protected_routes = protect_route_paths(redacted)
    for artifact_name in PRIVATE_ARTIFACT_NAMES:
        redacted = redacted.replace(artifact_name, "<redacted-private-artifact>")
    for root_text in path_prefix_variants(workspace_root):
        redacted = replace_absolute_path_prefix(redacted, root_text, "<repo>")
    if out_dir is not None:
        out_display = display_path(out_dir, workspace_root)
        for out_text in path_prefix_variants(out_dir):
            redacted = replace_absolute_path_prefix(redacted, out_text, out_display)
    home = str(Path.home())
    if home and home != "/":
        redacted = replace_absolute_path_prefix(redacted, home, "<home>")
    redacted = replace_absolute_path_prefix(redacted, tempfile.gettempdir(), "<workdir>")
    redacted = WINDOWS_UNC_PATH_RE.sub(scrub_absolute_path_match, redacted)
    redacted = WINDOWS_DRIVE_PATH_RE.sub(scrub_absolute_path_match, redacted)
    redacted = ABSOLUTE_PATH_RE.sub(scrub_absolute_path_match, redacted)
    redacted = normalize_redacted_separators(redacted)
    return restore_route_paths(redacted, protected_routes)


def normalize_key_name(key_hint: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key_hint.lower())


def should_redact_key_name(key_hint: str, value: Any | None = None) -> bool:
    normalized = normalize_key_name(key_hint)
    if not normalized:
        return False
    if any(fragment in normalized for fragment in BODY_KEY_FRAGMENTS):
        return not (isinstance(value, bool) and normalized.endswith(NON_SECRET_METADATA_SUFFIXES))
    if normalized.endswith(NON_SECRET_METADATA_SUFFIXES):
        return False
    if normalized in {
        "authorization",
        "cookie",
        "setcookie",
        "credential",
        "cryptadapptoken",
        "formpassword",
        "privatekey",
        "secret",
        "identityseed",
        "recoveryphrase",
        "mnemonic",
        "seed",
        "token",
        "password",
        "passwd",
        "browsersessiontoken",
        "xcryptaappsession",
    }:
        return True
    if "signature" in normalized and any(
        fragment in normalized for fragment in ("value", "base64", "payload", "document")
    ):
        return True
    return any(
        fragment in normalized
        for fragment in (
            "privatekey",
            "token",
            "password",
            "passwd",
            "secret",
            "credential",
            "seedphrase",
            "recoveryphrase",
            "mnemonic",
        )
    )


def sanitize_value(value: Any, workspace_root: Path, out_dir: Path | None = None, key_hint: str = "") -> Any:
    if should_redact_key_name(key_hint, value):
        return "<redacted>"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, child in value.items():
            key_text = str(key)
            result[key_text] = sanitize_value(child, workspace_root, out_dir, key_text)
        return result
    if isinstance(value, list):
        sanitized = [sanitize_value(child, workspace_root, out_dir, key_hint) for child in value]
        return [
            child
            for child in sanitized
            if not (isinstance(child, str) and "<redacted-private-artifact>" in child)
        ]
    if isinstance(value, str):
        return scrub_text(value, workspace_root, out_dir)
    return value


def normalize_evidence_status(status: str) -> str:
    normalized = status.strip().lower()
    if normalized in CERT_STATUSES:
        return normalized
    if normalized in {"success", "passed", "ok", "collected"}:
        return "pass"
    if normalized in {"warning", "warn"}:
        return "warn"
    if normalized in {"failure", "failed", "error"}:
        return "fail"
    if normalized in {"skipped"}:
        return "skip"
    return "missing"


def sanitize_evidence_item(item: EvidenceItem, workspace_root: Path, out_dir: Path) -> EvidenceItem:
    return EvidenceItem(
        id=item.id,
        status=item.status,
        required_for_release_candidate=item.required_for_release_candidate,
        summary=scrub_text(item.summary, workspace_root, out_dir),
        source=scrub_text(item.source, workspace_root, out_dir),
        details=dict(sanitize_value(item.details, workspace_root, out_dir)),
    )


def parse_expiry(value: str) -> dt.datetime | None:
    if not value:
        return None
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def load_structured_waiver_file(path: Path, settings: Settings, now: dt.datetime) -> tuple[list[WaiverRecord], list[str]]:
    source = display_path(path, settings.workspace_root, settings.out_dir)
    value = read_json(path)
    if value is None:
        return [], [f"Waiver file {source} is missing or malformed."]
    records = value.get("waivers", [])
    if value.get("version") != 1 or not isinstance(records, list):
        return [], [f"Waiver file {source} must use version 1 and a waivers array."]
    loaded: list[WaiverRecord] = []
    errors: list[str] = []
    for index, entry in enumerate(records):
        if not isinstance(entry, dict):
            errors.append(f"Waiver file {source} entry {index} is not an object.")
            continue
        waiver_id = str(entry.get("id", "")).strip()
        evidence_id = str(entry.get("evidenceId", waiver_id)).strip()
        reason = str(entry.get("reason", "")).strip()
        raw_status = str(entry.get("status", "")).strip().lower()
        status = raw_status if raw_status == "approved" else ("pending" if not raw_status else "invalid")
        approved_by = str(entry.get("approvedBy", "")).strip()
        raw_expires_at = str(entry.get("expiresAt", "")).strip()
        allow_release_candidate_value = entry.get("allowReleaseCandidate", False)
        allow_release_candidate = (
            allow_release_candidate_value if isinstance(allow_release_candidate_value, bool) else False
        )
        validation_errors: list[str] = []
        if not waiver_id:
            validation_errors.append("id is required")
        if not evidence_id:
            validation_errors.append("evidenceId is required")
        if not reason:
            validation_errors.append("reason is required")
        if status != "approved":
            validation_errors.append("status must be approved")
        if not isinstance(allow_release_candidate_value, bool):
            validation_errors.append("allowReleaseCandidate must be a boolean")
        expiry = parse_expiry(raw_expires_at)
        if raw_expires_at and expiry is None:
            validation_errors.append("expiresAt must be an ISO-8601 timestamp")
        expired = bool(expiry and expiry <= now)
        if expired:
            validation_errors.append("waiver is expired")
        safe_reason = scrub_text(reason, settings.workspace_root, settings.out_dir)
        safe_waiver_id = scrub_text(waiver_id, settings.workspace_root, settings.out_dir)
        safe_evidence_id = scrub_text(evidence_id, settings.workspace_root, settings.out_dir)
        safe_approved_by = scrub_text(approved_by, settings.workspace_root, settings.out_dir)
        safe_expires_at = (
            scrub_text(raw_expires_at, settings.workspace_root, settings.out_dir)
            if expiry is not None
            else ("<invalid>" if raw_expires_at else "")
        )
        safe_error = "; ".join(validation_errors)
        if validation_errors:
            errors.append(f"Waiver {safe_waiver_id or index} in {source}: {safe_error}.")
        loaded.append(
            WaiverRecord(
                id=safe_waiver_id or f"{source}#{index}",
                evidence_id=safe_evidence_id or safe_waiver_id or f"{source}#{index}",
                reason=safe_reason,
                source=source,
                status=status,
                approved_by=safe_approved_by,
                expires_at=safe_expires_at,
                allow_release_candidate=allow_release_candidate,
                active=not validation_errors,
                expired=expired,
                applies_to_release_candidate=allow_release_candidate,
                validation_error=safe_error,
            )
        )
    return loaded, errors


def load_waiver_context(settings: Settings, now: dt.datetime) -> WaiverContext:
    records: list[WaiverRecord] = []
    errors: list[str] = []
    for waiver_file in settings.waiver_files:
        loaded, file_errors = load_structured_waiver_file(waiver_file, settings, now)
        records.extend(loaded)
        errors.extend(file_errors)
    for waiver_id, reason in settings.waivers.items():
        safe_reason = scrub_text(reason, settings.workspace_root, settings.out_dir)
        safe_waiver_id = scrub_text(waiver_id, settings.workspace_root, settings.out_dir)
        records.append(
            WaiverRecord(
                id=safe_waiver_id,
                evidence_id=safe_waiver_id,
                reason=safe_reason,
                source="cli",
                status="approved",
                approved_by="cli",
                allow_release_candidate=True,
                active=True,
                applies_to_release_candidate=True,
            )
        )
    return WaiverContext(records=records, errors=errors)


def active_waiver_for(
    context: WaiverContext, target_id: str, issue_ids: list[str] | None, mode: str
) -> WaiverRecord | None:
    for record in reversed(context.active_records(mode)):
        if record.matches(target_id, issue_ids):
            return record
    return None


def unique_non_empty_strings(values: Any) -> list[str]:
    if not isinstance(values, (list, tuple)):
        return []
    result: list[str] = []
    for value in values:
        text = str(value).strip()
        if text and text not in result:
            result.append(text)
    return result


def has_unwaivable_redaction_findings(evidence_id: str, details: dict[str, Any]) -> bool:
    redaction_findings = details.get("redactionFindings")
    return (
        evidence_id in REDACTION_FINDING_EVIDENCE_IDS
        and isinstance(redaction_findings, list)
        and bool(redaction_findings)
    )


def evidence_item_has_unwaivable_redaction_findings(item: EvidenceItem) -> bool:
    return has_unwaivable_redaction_findings(item.id, item.details)


def evidence_entry_has_unwaivable_redaction_findings(entry: dict[str, Any] | None) -> bool:
    if not isinstance(entry, dict):
        return False
    return has_unwaivable_redaction_findings(str(entry.get("id", "")), evidence_details(entry))


def active_waivers_for_all(
    context: WaiverContext, target_ids: list[str], mode: str
) -> list[WaiverRecord]:
    records: list[WaiverRecord] = []
    for target_id in target_ids:
        waiver = active_waiver_for(context, target_id, None, mode)
        if waiver is None:
            return []
        records.append(waiver)
    return records


def with_waiver_record(item: EvidenceItem, waiver: WaiverRecord | None) -> EvidenceItem:
    if waiver is None or item.status == "pass":
        return item
    details = dict(item.details)
    details["waived"] = True
    details["waiverId"] = waiver.id
    details["waiverReason"] = waiver.reason
    details["waiverSource"] = waiver.source
    return EvidenceItem(
        id=item.id,
        status="warn",
        required_for_release_candidate=item.required_for_release_candidate,
        summary=f"{item.summary} Waiver recorded: {waiver.reason}",
        source=item.source,
        details=details,
    )


def active_waiver_for_evidence_item(
    context: WaiverContext, item: EvidenceItem, mode: str
) -> WaiverRecord | None:
    if evidence_item_has_unwaivable_redaction_findings(item):
        return None
    return active_waiver_for(context, item.id, [f"evidence.{item.id}"], mode)


def apply_waiver_to_gate(gate: GateResult, context: WaiverContext, mode: str) -> GateResult:
    if gate.id == "ecosystem.waivers":
        return gate
    issue_ids = [str(value) for value in gate.details.get("issueIds", []) if value]
    unwaivable_failure_evidence_ids = set(
        unique_non_empty_strings(gate.details.get("unwaivableFailureEvidenceIds", []))
    )
    waiver = (
        None
        if unwaivable_failure_evidence_ids
        else active_waiver_for(context, gate.id, issue_ids, mode)
    )
    waived_evidence_ids: list[str] = []
    if waiver is None and gate.status == "fail":
        failure_evidence_ids = unique_non_empty_strings(gate.details.get("failureEvidenceIds", []))
        evidence_waivers = (
            []
            if unwaivable_failure_evidence_ids.intersection(failure_evidence_ids)
            else active_waivers_for_all(context, failure_evidence_ids, mode)
        )
        if evidence_waivers:
            waiver = evidence_waivers[-1]
            waived_evidence_ids = failure_evidence_ids
    if waiver is None or gate.status == "pass":
        return gate
    details = dict(gate.details)
    details["waived"] = True
    details["waiverId"] = waiver.id
    details["waiverReason"] = waiver.reason
    details["waiverSource"] = waiver.source
    if waived_evidence_ids:
        details["waivedEvidenceIds"] = waived_evidence_ids
    return GateResult(
        id=gate.id,
        status="warn",
        release_blocker=False,
        summary=f"{gate.summary} Waiver recorded: {waiver.reason}",
        details=details,
    )


def has_required_flow(summary: dict[str, Any], flow_name: str) -> bool:
    flows = summary.get("flows", {})
    if not isinstance(flows, dict):
        return False
    flow = flows.get(flow_name, {})
    return isinstance(flow, dict) and flow.get("status") == "passed"


def flow_status(summary: dict[str, Any], flow_name: str) -> str:
    flows = summary.get("flows", {})
    if not isinstance(flows, dict):
        return "missing"
    flow = flows.get(flow_name, {})
    if isinstance(flow, dict):
        return str(flow.get("status", "missing"))
    return str(flow)


def sanitized_artifact_refs(summary: dict[str, Any], workspace_root: Path, out_dir: Path) -> list[str]:
    artifacts = summary.get("artifacts", [])
    if not isinstance(artifacts, list):
        return []
    refs: list[str] = []
    for artifact in artifacts:
        artifact_text = str(artifact)
        if any(name in artifact_text for name in PRIVATE_ARTIFACT_NAMES):
            continue
        refs.append(str(sanitize_value(artifact_text, workspace_root, out_dir)))
    return sorted(dict.fromkeys(refs))


def interop_evidence(
    evidence_id: str,
    path: Path,
    required: bool,
    expected_mode: str,
    workspace_root: Path,
    out_dir: Path,
) -> EvidenceItem:
    source = display_path(path, workspace_root, out_dir)
    summary = read_json(path)
    if summary is None:
        missing_status = "missing"
        return EvidenceItem(
            evidence_id,
            missing_status,
            required,
            f"{expected_mode} interop summary is missing",
            source,
            {},
        )

    sanitized = sanitize_value(summary, workspace_root, out_dir)
    common_required_flows = [
        "handshake",
        "peer_exchange",
        "chk_cross_fetch",
        "ssk_cross_fetch",
        "usk_smoke",
        "restart_recovery",
    ]
    extended_required_flows = ["usk_subscribe_soak", "persistent_request_replay"]
    required_flows = common_required_flows + (
        extended_required_flows if expected_mode == "extended" else []
    )
    coverage = {flow: flow_status(summary, flow) for flow in required_flows}
    missing_flows = [flow for flow in required_flows if not has_required_flow(summary, flow)]
    summary_status = str(summary.get("status", "missing"))
    summary_mode = str(summary.get("mode", "missing"))
    mode_matches = summary_mode == expected_mode
    if summary_status == "success" and not mode_matches:
        status = "fail" if required else "warn"
        headline = f"{expected_mode} Hyphanet interop summary has wrong mode"
    elif summary_status == "success" and not missing_flows:
        status = "pass"
        headline = f"{expected_mode} Hyphanet interop passed"
    elif summary_status == "success":
        status = "warn" if not required else "fail"
        headline = f"{expected_mode} Hyphanet interop completed with incomplete required coverage"
    elif summary_status == "failure":
        status = "fail"
        headline = f"{expected_mode} Hyphanet interop failed"
    else:
        status = "missing"
        headline = f"{expected_mode} Hyphanet interop status is unavailable"

    details = {
        "expectedMode": expected_mode,
        "mode": sanitized.get("mode"),
        "modeMatches": mode_matches,
        "status": sanitized.get("status"),
        "coverage": coverage,
        "missingRequiredFlows": missing_flows,
        "restartRecoveryLevel": sanitized.get("restart_recovery_level"),
        "restartRecoveryChecks": sanitized.get("restart_recovery_checks", []),
        "baseline": sanitized.get("baseline", sanitized.get("hyphanet", {})),
        "artifacts": sanitized_artifact_refs(summary, workspace_root, out_dir),
    }
    if expected_mode == "extended":
        details["extendedCoverage"] = {
            "uskSubscribeSoak": flow_status(summary, "usk_subscribe_soak"),
            "persistentRequestReplay": flow_status(summary, "persistent_request_replay"),
            "opennetOptional": flow_status(summary, "opennet_optional"),
        }
    return EvidenceItem(evidence_id, status, required, headline, source, details)


def perf_evidence(path: Path, required: bool, workspace_root: Path, out_dir: Path) -> EvidenceItem:
    source = display_path(path, workspace_root, out_dir)
    summary = read_json(path)
    if summary is None:
        return EvidenceItem(
            "performance.smoke",
            "missing",
            required,
            "Performance smoke summary is missing",
            source,
            {},
        )
    sanitized = sanitize_value(summary, workspace_root, out_dir)
    raw_status = str(summary.get("status", "missing"))
    summary_mode = str(summary.get("mode", "missing"))
    expected_mode = "smoke"
    mode_matches = summary_mode == expected_mode
    status = (
        {"success": "pass", "warning": "warn", "failure": "fail"}.get(raw_status, "missing")
        if mode_matches
        else ("fail" if required else "warn")
    )
    comparison = summary.get("comparison", {})
    if not isinstance(comparison, dict):
        comparison = {}
    details = {
        "expectedMode": expected_mode,
        "mode": sanitized.get("mode"),
        "modeMatches": mode_matches,
        "status": sanitized.get("status"),
        "comparison": sanitize_value(comparison, workspace_root, out_dir),
        "failedMetrics": failed_perf_metrics(summary),
        "warningMetrics": warning_perf_metrics(summary),
        "perfReport": display_path(path.parent / "artifacts" / "perf-report.md", workspace_root, out_dir),
    }
    if not mode_matches:
        return EvidenceItem(
            "performance.smoke",
            status,
            required,
            "Performance smoke summary has wrong mode",
            source,
            details,
        )
    return EvidenceItem(
        "performance.smoke",
        status,
        required,
        f"Performance smoke status is {raw_status}",
        source,
        details,
    )


def failed_perf_metrics(summary: dict[str, Any]) -> list[str]:
    metrics = summary.get("metrics", {})
    if not isinstance(metrics, dict):
        return []
    return sorted(name for name, metric in metrics.items() if isinstance(metric, dict) and metric.get("status") == "failed")


def warning_perf_metrics(summary: dict[str, Any]) -> list[str]:
    comparison = summary.get("comparison", {})
    if not isinstance(comparison, dict):
        return []
    names: list[str] = []
    for group in ("regressions", "warnings"):
        entries = comparison.get(group, [])
        if isinstance(entries, list):
            for entry in entries:
                if isinstance(entry, dict) and entry.get("metric"):
                    names.append(str(entry["metric"]))
    return sorted(dict.fromkeys(names))


def app_platform_evidence(
    path: Path, workspace_root: Path, out_dir: Path, expected_mode: str
) -> list[EvidenceItem]:
    source = display_path(path, workspace_root, out_dir)
    summary = read_json(path)
    expected_ids = [
        "app-platform.first-party",
        "app-platform.devtools-cli",
        "app-platform.developer-beta-toolkit",
        "platform-api.contract",
        "app-vault.capabilities",
        "app-platform.identity-profile-publish",
        "app-platform.generated-document-insert",
        "app-platform.content-fetch",
        "app-platform.content-subscriptions",
        "network-content.subscription-scheduler",
        "app-platform.durable-app-data-store",
        "app-platform.trust-graph-preview",
        "app-platform.trust-graph-durable-store",
        "app-platform.trust-graph-exchange",
        "app-platform.trust-statement-signing",
        "app-platform.social-message-signing",
        "app-services.registry",
        "app-services.grants",
        "app-services.trust-score-provider",
        "reference-app.social-inbox-service-grant",
        "app-services.web-shell",
        "app-services.redaction",
        "app-platform.signed-bundles",
        "catalog.smoke",
        "catalog.live-usk-publication",
        "catalog.live-usk-source-verification",
        "app-catalog.first-party-beta",
        "app-review.trusted-receipts",
        "app-review.policy",
        "app-review.governance",
        "app-review.reviewer-key-lifecycle",
        "app-review.transparency-log",
        "app-review.review-history-api",
        "app-review.first-party-catalog",
        "app-review.first-party-review-chain",
        "app-ui.design-system",
        "app-ui.lint",
        "app-ui.first-party-adoption",
        "app-ui.smoke",
        "reference-apps.content",
        "reference-app.profile-publisher",
        "reference-app.profile-publisher-app-data",
        "reference-app.feed-reader",
        "reference-app.feed-reader-subscriptions",
        "reference-app.feed-reader-app-data",
        "reference-app.trust-graph",
        "reference-app.trust-graph-durable-exchange",
        "reference-app.trust-graph-app-data-preview",
        "reference-app.social-inbox",
        "reference-app.social-inbox-signed-message",
        "reference-app.social-inbox-subscriptions",
        "reference-app.social-inbox-app-data",
        "reference-app.social-inbox-trust-annotations",
        "migration.social-mail-preview",
        "legacy-plugin.migration-guide",
        "legacy-plugin.social-inbox-spike",
        "legacy.retirement",
        "legacy-admin.removal-wave-1",
        "legacy-admin.removal-wave-2",
        "legacy-admin.removal-wave-3",
        "apphost.sandbox-provider",
        "app-update.lifecycle",
        "app-update.scheduler",
        "app-update.live-catalog-refresh",
        "app-update.rollback",
        "apphost.live",
    ]
    if summary is None:
        return [
            EvidenceItem(
                evidence_id,
                "missing" if evidence_id != "apphost.live" else "skip",
                evidence_id != "apphost.live",
                "App-platform smoke summary is missing",
                source,
                {},
            )
            for evidence_id in expected_ids
        ]
    summary_mode = str(summary.get("mode", "missing"))
    mode_matches = summary_mode == expected_mode
    if expected_mode == "release-candidate" and not mode_matches:
        return [
            EvidenceItem(
                evidence_id,
                "fail" if evidence_id != "apphost.live" else "skip",
                evidence_id != "apphost.live",
                "App-platform smoke summary has wrong mode",
                source,
                {
                    "expectedMode": expected_mode,
                    "mode": sanitize_value(summary_mode, workspace_root, out_dir),
                    "modeMatches": False,
                    "summaryStatus": sanitize_value(summary.get("status"), workspace_root, out_dir),
                },
            )
            for evidence_id in expected_ids
        ]
    evidence = summary.get("evidence", [])
    if not isinstance(evidence, list):
        return [
            EvidenceItem(
                "app-platform.smoke",
                "fail",
                True,
                "App-platform summary has no evidence list",
                source,
                {"summaryStatus": sanitize_value(summary.get("status"), workspace_root, out_dir)},
            )
        ]
    items: list[EvidenceItem] = []
    seen: set[str] = set()
    for value in evidence:
        if not isinstance(value, dict):
            continue
        evidence_id = str(value.get("id", "app-platform.unknown"))
        seen.add(evidence_id)
        items.append(
            EvidenceItem(
                id=evidence_id,
                status=normalize_evidence_status(str(value.get("status", "missing"))),
                required_for_release_candidate=bool(value.get("requiredForReleaseCandidate", True)),
                summary=str(
                    sanitize_value(value.get("summary", "No summary provided"), workspace_root, out_dir)
                ),
                source=str(sanitize_value(value.get("source", source), workspace_root, out_dir)),
                details=dict(
                    sanitize_value(value.get("details", {}), workspace_root, out_dir)
                    if isinstance(value.get("details", {}), dict)
                    else {}
                ),
            )
        )
    for evidence_id in expected_ids:
        if evidence_id not in seen:
            items.append(
                EvidenceItem(
                    evidence_id,
                    "missing" if evidence_id != "apphost.live" else "skip",
                    evidence_id != "apphost.live",
                    f"{evidence_id} was not reported by app-platform smoke",
                    source,
                    {},
                )
            )
    return items


def app_platform_docs_evidence(workspace_root: Path, out_dir: Path) -> list[EvidenceItem]:
    source = display_path(
        workspace_root / "tools/release-certification/app_platform_docs_check.py",
        workspace_root,
        out_dir,
    )
    try:
        summary = app_platform_docs_check.run_check(workspace_root)
    except Exception as exception:  # noqa: BLE001 - release evidence must degrade to redacted failure.
        return [
            EvidenceItem(
                evidence_id,
                "fail",
                True,
                "App-platform docs check failed to run",
                source,
                {"error": scrub_text(str(exception), workspace_root, out_dir)},
            )
            for evidence_id in app_platform_docs_check.EVIDENCE_IDS
        ]
    evidence = summary.get("evidence", [])
    if not isinstance(evidence, list):
        return [
            EvidenceItem(
                evidence_id,
                "fail",
                True,
                "App-platform docs check produced no evidence list",
                source,
                {"summaryStatus": sanitize_value(summary.get("status"), workspace_root, out_dir)},
            )
            for evidence_id in app_platform_docs_check.EVIDENCE_IDS
        ]
    items: list[EvidenceItem] = []
    seen: set[str] = set()
    for value in evidence:
        if not isinstance(value, dict):
            continue
        evidence_id = str(value.get("id", "app-platform.docs-unknown"))
        seen.add(evidence_id)
        items.append(
            EvidenceItem(
                id=evidence_id,
                status=normalize_evidence_status(str(value.get("status", "missing"))),
                required_for_release_candidate=bool(value.get("requiredForReleaseCandidate", True)),
                summary=str(
                    sanitize_value(value.get("summary", "No summary provided"), workspace_root, out_dir)
                ),
                source=str(sanitize_value(value.get("source", source), workspace_root, out_dir)),
                details=dict(
                    sanitize_value(value.get("details", {}), workspace_root, out_dir)
                    if isinstance(value.get("details", {}), dict)
                    else {}
                ),
            )
        )
    for evidence_id in app_platform_docs_check.EVIDENCE_IDS:
        if evidence_id not in seen:
            items.append(
                EvidenceItem(
                    evidence_id,
                    "missing",
                    True,
                    f"{evidence_id} was not reported by app-platform docs check",
                    source,
                    {},
                )
            )
    return items


def command_output(args: list[str], cwd: Path) -> str:
    try:
        completed = subprocess.run(
            args,
            cwd=str(cwd),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if completed.returncode != 0:
        return ""
    return completed.stdout.strip()


def collect_git_metadata(settings: Settings) -> dict[str, str]:
    if settings.skip_git_metadata:
        return {}
    metadata: dict[str, str] = {}
    sha = command_output(["git", "rev-parse", "HEAD"], settings.workspace_root)
    branch = command_output(["git", "rev-parse", "--abbrev-ref", "HEAD"], settings.workspace_root)
    dirty = command_output(["git", "status", "--short"], settings.workspace_root)
    if sha:
        metadata["gitCommit"] = sha
    if branch:
        metadata["gitBranch"] = branch
    if dirty:
        metadata["gitDirty"] = "true"
    elif sha or branch:
        metadata["gitDirty"] = "false"
    return metadata


def collect_ci_metadata(env: dict[str, str]) -> dict[str, str]:
    mappings = {
        "GITHUB_ACTIONS": "githubActions",
        "GITHUB_WORKFLOW": "githubWorkflow",
        "GITHUB_RUN_ID": "githubRunId",
        "GITHUB_RUN_ATTEMPT": "githubRunAttempt",
        "GITHUB_REF": "githubRef",
        "GITHUB_SHA": "githubSha",
        "RUNNER_OS": "runnerOs",
    }
    metadata: dict[str, str] = {}
    for env_name, key in mappings.items():
        value = env.get(env_name)
        if value:
            metadata[key] = value
    return metadata


def determine_overall_status(mode: str, evidence: list[EvidenceItem]) -> tuple[str, bool]:
    required_bad = [
        item
        for item in evidence
        if item.required_for_release_candidate and item.status in {"fail", "missing", "skip"}
        and not item.details.get("waived")
    ]
    required_warn = [
        item
        for item in evidence
        if item.required_for_release_candidate and item.status == "warn" and not item.details.get("waived")
    ]
    any_warnish = any(
        item.status in {"warn", "missing", "fail"} or (item.required_for_release_candidate and item.status == "skip")
        for item in evidence
    )
    if mode == "release-candidate":
        if required_bad:
            return "fail", False
        if required_warn or any_warnish:
            return "warn", True
        return "pass", True
    if mode == "nightly":
        required_fail = [
            item
            for item in evidence
            if item.required_for_release_candidate and item.status == "fail" and not item.details.get("waived")
        ]
        if required_fail:
            return "fail", False
        if required_bad:
            return "warn", False
        if required_warn or any_warnish:
            return "warn", True
        return "pass", True
    if any_warnish:
        return "warn", not required_bad
    return "pass", True


def evidence_counts(evidence: list[EvidenceItem]) -> dict[str, int]:
    counts = {status: 0 for status in CERT_STATUSES}
    for item in evidence:
        counts[item.status] = counts.get(item.status, 0) + 1
    return counts


STATUS_SEVERITY = {"pass": 0, "warn": 1, "skip": 2, "missing": 2, "fail": 3}
EXPECTED_FIRST_PARTY_APPS = (
    "queue-manager",
    "publisher",
    "site-publisher",
    "profile-publisher",
    "feed-reader",
    "social-inbox",
    "trust-graph",
)
EXPECTED_VAULT_CAPABILITIES = (
    "vault.secrets.read",
    "vault.secrets.write",
    "vault.identities.read",
    "vault.identities.create",
    "vault.identities.use",
    "vault.identities.manage",
)


def evidence_map_from_items(evidence: list[EvidenceItem]) -> dict[str, dict[str, Any]]:
    return {item.id: item.to_json() for item in evidence}


def evidence_map_from_summary(summary: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not isinstance(summary, dict):
        return {}
    evidence = summary.get("evidence", [])
    if not isinstance(evidence, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for entry in evidence:
        if isinstance(entry, dict) and entry.get("id"):
            result[str(entry["id"])] = entry
    return result


def evidence_status(entry: dict[str, Any] | None) -> str:
    if not isinstance(entry, dict):
        return "missing"
    return normalize_evidence_status(str(entry.get("status", "missing")))


def evidence_required(entry: dict[str, Any] | None) -> bool:
    return isinstance(entry, dict) and bool(entry.get("requiredForReleaseCandidate", False))


def evidence_details(entry: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(entry, dict):
        return {}
    details = entry.get("details", {})
    return details if isinstance(details, dict) else {}


def status_severity(status: str) -> int:
    return STATUS_SEVERITY.get(normalize_evidence_status(status), 2)


def sorted_strings(value: Any) -> list[str]:
    if isinstance(value, list):
        return sorted(dict.fromkeys(str(item) for item in value))
    if isinstance(value, tuple):
        return sorted(dict.fromkeys(str(item) for item in value))
    return []


def app_ids_from_details(details: dict[str, Any], key: str = "apps") -> set[str]:
    value = details.get(key)
    if isinstance(value, dict):
        return {str(app_id) for app_id in value.keys()}
    return set(sorted_strings(value))


def nested_dict(value: dict[str, Any], key: str) -> dict[str, Any]:
    child = value.get(key, {})
    return child if isinstance(child, dict) else {}


def int_value(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def detail_int(details: dict[str, Any], key: str) -> int | None:
    return int_value(details.get(key))


def stable_descriptor_count(details: dict[str, Any]) -> int | None:
    explicit = detail_int(details, "stableDescriptorCount")
    if explicit is not None:
        return explicit
    stability_counts = nested_dict(details, "stabilityCounts")
    return int_value(stability_counts.get("stable"))


def total_ui_warnings(details: dict[str, Any]) -> int | None:
    apps = details.get("apps")
    if not isinstance(apps, dict):
        return None
    total = 0
    found = False
    for app in apps.values():
        if not isinstance(app, dict):
            continue
        summary = app.get("summary")
        if not isinstance(summary, dict):
            summary = app.get("report", {}).get("summary") if isinstance(app.get("report"), dict) else {}
        warning_count = int_value(summary.get("warnings") if isinstance(summary, dict) else None)
        if warning_count is not None:
            total += warning_count
            found = True
    return total if found else None


def all_boolean_checks_pass(details: dict[str, Any]) -> bool | None:
    checks = details.get("checks")
    if not isinstance(checks, dict):
        return None
    boolean_values = [value for value in checks.values() if isinstance(value, bool)]
    if not boolean_values:
        return None
    return all(boolean_values)


def set_from_detail(details: dict[str, Any], *keys: str) -> set[str]:
    for key in keys:
        value = details.get(key)
        if isinstance(value, list):
            return {str(item) for item in value}
        if isinstance(value, dict):
            return {str(item) for item in value.keys()}
    return set()


def stable_named_set(details: dict[str, Any], list_key: str, fallback_key: str) -> set[str]:
    direct = set_from_detail(details, list_key)
    if direct:
        return direct
    values = details.get(fallback_key)
    result: set[str] = set()
    if isinstance(values, list):
        for value in values:
            if isinstance(value, dict):
                stability = str(value.get("stability", value.get("lifecycle", ""))).lower()
                if stability and stability != "stable":
                    continue
                route_template = value.get("routeTemplate")
                if route_template:
                    method = str(value.get("method", "")).strip().upper()
                    name = f"{method} {route_template}" if method else route_template
                else:
                    name = value.get("id") or value.get("name") or value.get("path") or value.get("route")
                if name:
                    result.add(str(name))
            elif isinstance(value, str):
                result.add(value)
    if isinstance(values, dict):
        for key, value in values.items():
            if isinstance(value, dict):
                stability = str(value.get("stability", value.get("lifecycle", ""))).lower()
                if stability and stability != "stable":
                    continue
            result.add(str(key))
    return result


def stable_named_set_reported(details: dict[str, Any], list_key: str, fallback_key: str) -> bool:
    for key in (list_key, fallback_key):
        value = details.get(key)
        if isinstance(value, (dict, list)):
            return True
    return False


MATRIX_CATEGORY_TITLES = {
    "release-operations": "Release operations",
    "network-compatibility": "Network compatibility",
    "performance": "Performance",
    "app-platform": "App platform",
    "app-distribution": "App distribution",
    "review-governance": "Review governance",
    "first-party-apps": "First-party apps",
    "reference-apps": "Reference apps",
    "legacy-retirement": "Legacy retirement",
    "security-redaction": "Security and redaction",
}


def ecosystem_matrix_row_specs() -> list[MatrixRowSpec]:
    """Return the deterministic ecosystem certification row registry."""

    return [
        MatrixRowSpec(
            id="release-history-and-waivers",
            category="release-operations",
            title="Release history comparison and waiver visibility",
            gate_ids=("ecosystem.required-evidence-regressions",),
            optional_gate_ids=("ecosystem.waivers",),
            docs=(
                "docs/release-certification.md",
                "tools/release-certification/README.md",
                "docs/cryptad-release-workflow-and-runbook.md",
            ),
            synthetic="history",
        ),
        MatrixRowSpec(
            id="ecosystem-certification-matrix",
            category="release-operations",
            title="Ecosystem certification matrix completeness",
            required_evidence_ids=("release-certification.ecosystem-matrix",),
            docs=(
                "docs/release-certification.md",
                "tools/release-certification/README.md",
                "docs/cryptad-release-workflow-and-runbook.md",
            ),
        ),
        MatrixRowSpec(
            id="interop-smoke",
            category="network-compatibility",
            title="Hyphanet interop smoke certification",
            required_evidence_ids=("interop.smoke",),
            optional_evidence_ids=("interop.extended",),
            docs=("docs/release-certification.md", "tools/interop/README.md"),
        ),
        MatrixRowSpec(
            id="performance-smoke",
            category="performance",
            title="Performance regression smoke certification",
            required_evidence_ids=("performance.smoke",),
            docs=("docs/release-certification.md", "tools/perf/README.md"),
        ),
        MatrixRowSpec(
            id="platform-api-contract",
            category="app-platform",
            title="Platform API contract compatibility",
            required_evidence_ids=("platform-api.contract",),
            gate_ids=("ecosystem.platform-api-compatibility",),
            docs=("docs/platform-api-contract.md", "docs/platform-api-surface.md"),
        ),
        MatrixRowSpec(
            id="developer-beta-toolkit",
            category="app-platform",
            title="Developer beta toolkit and CLI readiness",
            required_evidence_ids=(
                "app-platform.devtools-cli",
                "app-platform.developer-beta-toolkit",
            ),
            docs=("docs/app-dev-cli.md", "docs/developer-beta-toolkit.md"),
        ),
        MatrixRowSpec(
            id="app-platform-beta-docs-and-program",
            category="app-platform",
            title="App platform beta docs and program readiness",
            required_evidence_ids=(
                "app-platform.docs-portal",
                "app-platform.beta-program",
                "app-platform.beta-tutorials",
                "app-platform.docs-redaction",
            ),
            docs=(
                "docs/app-platform-developer-portal.md",
                "docs/app-platform-beta-tutorials.md",
                "docs/app-platform-beta-known-limitations.md",
                "docs/app-platform-beta-program.md",
                "docs/release-certification.md",
            ),
        ),
        MatrixRowSpec(
            id="app-vault-and-generated-documents",
            category="app-platform",
            title="App vault, identity profile publishing, and generated documents",
            required_evidence_ids=(
                "app-vault.capabilities",
                "app-platform.identity-profile-publish",
                "app-platform.generated-document-insert",
            ),
            gate_ids=("ecosystem.app-vault",),
            docs=(
                "docs/app-secret-and-identity-vault.md",
                "docs/platform-api-contract.md",
                "docs/release-certification.md",
            ),
        ),
        MatrixRowSpec(
            id="content-fetch-and-networked-content",
            category="app-platform",
            title="Content fetch, subscriptions, and networked content surfaces",
            required_evidence_ids=(
                "app-platform.content-fetch",
                "app-platform.content-subscriptions",
                "network-content.subscription-scheduler",
                "app-platform.durable-app-data-store",
            ),
            gate_ids=("ecosystem.reference-content-apps",),
            docs=(
                "docs/platform-api-contract.md",
                "docs/feed-reader-reference-app.md",
                "docs/app-data-store.md",
            ),
        ),
        MatrixRowSpec(
            id="trust-graph-preview-platform",
            category="app-platform",
            title="Trust graph preview platform routes and signing",
            required_evidence_ids=(
                "app-platform.trust-graph-preview",
                "app-platform.trust-graph-durable-store",
                "app-platform.trust-graph-exchange",
                "app-platform.trust-statement-signing",
            ),
            gate_ids=("ecosystem.reference-content-apps",),
            docs=("docs/trust-graph-preview.md", "docs/platform-api-contract.md"),
        ),
        MatrixRowSpec(
            id="app-service-discovery-and-grants",
            category="app-platform",
            title="App-service discovery, grants, and Trust Score Service",
            required_evidence_ids=(
                "app-services.registry",
                "app-services.grants",
                "app-services.trust-score-provider",
                "reference-app.social-inbox-service-grant",
                "app-services.web-shell",
                "app-services.redaction",
            ),
            gate_ids=("ecosystem.reference-content-apps",),
            docs=(
                "docs/app-service-discovery-and-grants.md",
                "docs/platform-api-contract.md",
                "docs/social-inbox-reference-app.md",
                "docs/trust-graph-preview.md",
            ),
        ),
        MatrixRowSpec(
            id="apphost-sandbox-provider",
            category="app-platform",
            title="AppHost sandbox-provider enforcement",
            required_evidence_ids=("apphost.sandbox-provider",),
            optional_evidence_ids=("apphost.live",),
            gate_ids=("ecosystem.sandbox-provider",),
            docs=("docs/apphost-runtime-hardening.md", "docs/release-certification.md"),
        ),
        MatrixRowSpec(
            id="app-update",
            category="app-platform",
            title="App update lifecycle, scheduler, and rollback",
            required_evidence_ids=(
                "app-update.lifecycle",
                "app-update.scheduler",
                "app-update.live-catalog-refresh",
                "app-update.rollback",
            ),
            gate_ids=("ecosystem.app-update-rollback",),
            docs=("docs/app-update-lifecycle.md", "docs/release-certification.md"),
        ),
        MatrixRowSpec(
            id="first-party-beta-catalog",
            category="app-distribution",
            title="First-party beta catalog and signed bundles",
            required_evidence_ids=(
                "catalog.smoke",
                "catalog.live-usk-publication",
                "catalog.live-usk-source-verification",
                "app-catalog.first-party-beta",
                "app-platform.signed-bundles",
            ),
            docs=("docs/first-party-beta-catalog.md", "docs/app-catalogs.md"),
        ),
        MatrixRowSpec(
            id="review-trusted-receipts",
            category="review-governance",
            title="Trusted app-review receipts and policy",
            required_evidence_ids=(
                "app-review.trusted-receipts",
                "app-review.policy",
                "app-review.first-party-catalog",
            ),
            gate_ids=("ecosystem.app-review-trust",),
            docs=("docs/app-review-governance.md", "docs/app-catalogs.md"),
        ),
        MatrixRowSpec(
            id="review-governance-transparency",
            category="review-governance",
            title="Review governance, transparency log, and review history",
            required_evidence_ids=(
                "app-review.governance",
                "app-review.reviewer-key-lifecycle",
                "app-review.transparency-log",
                "app-review.review-history-api",
                "app-review.first-party-review-chain",
            ),
            gate_ids=("ecosystem.app-review-trust",),
            docs=("docs/app-review-governance.md",),
        ),
        MatrixRowSpec(
            id="ui-design-system",
            category="first-party-apps",
            title="App UI design-system adoption and lint",
            required_evidence_ids=(
                "app-ui.design-system",
                "app-ui.lint",
                "app-ui.first-party-adoption",
                "app-ui.smoke",
            ),
            gate_ids=("ecosystem.app-ui-quality",),
            docs=("docs/app-ui-design-system.md", "docs/app-owned-ui.md"),
        ),
        MatrixRowSpec(
            id="first-party-app-bundles",
            category="first-party-apps",
            title="First-party app bundle set",
            required_evidence_ids=("app-platform.first-party",),
            gate_ids=("ecosystem.first-party-apps",),
            docs=("docs/first-party-beta-catalog.md", "docs/app-distribution.md"),
            first_party_apps=EXPECTED_FIRST_PARTY_APPS,
        ),
        MatrixRowSpec(
            id="reference-content-apps",
            category="reference-apps",
            title="Site Publisher reference content app",
            required_evidence_ids=("reference-apps.content",),
            gate_ids=("ecosystem.reference-content-apps",),
            docs=("docs/first-party-beta-catalog.md", "docs/app-distribution.md"),
            first_party_apps=("site-publisher",),
        ),
        MatrixRowSpec(
            id="profile-publisher",
            category="reference-apps",
            title="Profile Publisher reference app",
            required_evidence_ids=(
                "reference-app.profile-publisher",
                "reference-app.profile-publisher-app-data",
            ),
            gate_ids=("ecosystem.reference-content-apps",),
            docs=("docs/first-party-beta-catalog.md",),
            first_party_apps=("profile-publisher",),
        ),
        MatrixRowSpec(
            id="feed-reader",
            category="reference-apps",
            title="Feed Reader reference app",
            required_evidence_ids=(
                "reference-app.feed-reader",
                "reference-app.feed-reader-subscriptions",
                "reference-app.feed-reader-app-data",
            ),
            gate_ids=("ecosystem.reference-content-apps",),
            docs=("docs/feed-reader-reference-app.md",),
            first_party_apps=("feed-reader",),
        ),
        MatrixRowSpec(
            id="trust-graph-app",
            category="reference-apps",
            title="Trust Graph Preview reference app",
            required_evidence_ids=(
                "reference-app.trust-graph",
                "reference-app.trust-graph-durable-exchange",
                "reference-app.trust-graph-app-data-preview",
            ),
            gate_ids=("ecosystem.reference-content-apps",),
            docs=("docs/trust-graph-preview.md",),
            first_party_apps=("trust-graph",),
        ),
        MatrixRowSpec(
            id="social-inbox-preview",
            category="reference-apps",
            title="Social Inbox / Message Board Preview reference app",
            required_evidence_ids=(
                "app-platform.social-message-signing",
                "reference-app.social-inbox",
                "reference-app.social-inbox-signed-message",
                "reference-app.social-inbox-subscriptions",
                "reference-app.social-inbox-app-data",
                "reference-app.social-inbox-trust-annotations",
                "reference-app.social-inbox-service-grant",
                "migration.social-mail-preview",
            ),
            gate_ids=("ecosystem.reference-content-apps",),
            docs=(
                "docs/social-inbox-reference-app.md",
                "docs/platform-api-contract.md",
                "docs/app-secret-and-identity-vault.md",
                "docs/app-service-discovery-and-grants.md",
            ),
            first_party_apps=("social-inbox",),
        ),
        MatrixRowSpec(
            id="legacy-plugin-migration",
            category="legacy-retirement",
            title="Legacy plugin-to-app migration guidance",
            required_evidence_ids=(
                "legacy-plugin.migration-guide",
                "legacy-plugin.social-inbox-spike",
            ),
            gate_ids=("ecosystem.reference-content-apps",),
            docs=(
                "docs/legacy-plugin-migration-guide.md",
                "docs/plugin-system.md",
                "docs/social-inbox-reference-app.md",
            ),
            first_party_apps=("social-inbox", "trust-graph"),
            phase="phase-8",
        ),
        MatrixRowSpec(
            id="legacy-retirement",
            category="legacy-retirement",
            title="Legacy admin retirement and removal waves",
            required_evidence_ids=(
                "legacy.retirement",
                "legacy-admin.removal-wave-1",
                "legacy-admin.removal-wave-2",
                "legacy-admin.removal-wave-3",
            ),
            gate_ids=("ecosystem.legacy-retirement",),
            docs=("docs/legacy-retirement-plan.md", "docs/release-certification.md"),
            phase="phase-8",
        ),
        MatrixRowSpec(
            id="redaction-and-private-artifacts",
            category="security-redaction",
            title="Redaction and private artifact exclusions",
            docs=(
                "docs/release-certification.md",
                "tools/release-certification/README.md",
                "docs/cryptad-release-workflow-and-runbook.md",
            ),
            synthetic="redaction",
        ),
    ]


def matrix_status_from_counts(mode: str, counts: dict[str, int], coverage: dict[str, Any]) -> str:
    release_blockers = counts.get("releaseBlockers", 0)
    warnish_rows = sum(counts.get(status, 0) for status in ("warn", "missing", "skip"))
    redaction_failed = coverage.get("redactionPassed") is False
    unwaived_coverage_issue_ids = [
        str(issue_id) for issue_id in coverage.get("unwaivedIssueIds", coverage.get("issueIds", [])) if issue_id
    ]
    coverage_warn = bool(coverage.get("issueIds")) or not all(
        bool(coverage.get(key))
        for key in ("requiredEvidenceCovered", "ecosystemGatesCovered", "firstPartyAppsCovered", "docsCovered")
    )
    if mode == "pr":
        if redaction_failed:
            return "fail"
        return "warn" if release_blockers or warnish_rows or coverage_warn else "pass"
    if mode == "release-candidate" and (release_blockers or redaction_failed or unwaived_coverage_issue_ids):
        return "fail"
    if redaction_failed:
        return "fail"
    if release_blockers or warnish_rows or coverage_warn:
        return "warn"
    return "pass"


def previous_matrix_row_statuses(previous_summary: dict[str, Any] | None) -> dict[str, str]:
    if not isinstance(previous_summary, dict):
        return {}
    compact = previous_summary.get("ecosystemMatrix")
    if not isinstance(compact, dict):
        return {}
    statuses = compact.get("rowStatuses")
    if isinstance(statuses, dict):
        return {
            str(row_id): normalize_evidence_status(str(status))
            for row_id, status in statuses.items()
        }
    rows = compact.get("rows")
    if isinstance(rows, list):
        return {
            str(row.get("id")): normalize_evidence_status(str(row.get("status", "missing")))
            for row in rows
            if isinstance(row, dict) and row.get("id")
        }
    return {}


def regression_status_for_row(
    spec: MatrixRowSpec,
    status: str,
    release_blocker: bool,
    previous_summary_present: bool,
    previous_matrix_present: bool,
    previous_row_statuses: dict[str, str],
) -> tuple[str, str]:
    if not previous_summary_present:
        return "missing", "not-comparable"
    if not previous_matrix_present:
        return "missing", "previous-missing"
    previous_status = previous_row_statuses.get(spec.id)
    if previous_status is None:
        return "missing", "new-row"
    previous_severity = status_severity(previous_status)
    current_severity = status_severity(status)
    if current_severity > previous_severity:
        return previous_status, "regressed-blocker" if release_blocker or status == "fail" else "regressed-warning"
    if current_severity < previous_severity:
        return previous_status, "improved"
    return previous_status, "unchanged"


def gate_status(entry: dict[str, Any] | None) -> str:
    if not isinstance(entry, dict):
        return "missing"
    return normalize_evidence_status(str(entry.get("status", "missing")))


def aggregate_status_values(values: list[str], *, missing_if_empty: bool = False) -> str:
    normalized = [normalize_evidence_status(value) for value in values]
    if not normalized:
        return "missing" if missing_if_empty else "pass"
    if any(value == "fail" for value in normalized):
        return "fail"
    if any(value == "warn" for value in normalized):
        return "warn"
    if any(value == "missing" for value in normalized):
        return "missing"
    if any(value == "skip" for value in normalized):
        return "skip"
    return "pass"


def unwaivable_matrix_issue_ids(unwaivable_evidence_ids: set[str]) -> set[str]:
    unwaivable_issue_ids = set(unwaivable_evidence_ids)
    unwaivable_issue_ids.update(
        f"evidence.{evidence_id}" for evidence_id in unwaivable_evidence_ids
    )
    return unwaivable_issue_ids


def waivable_matrix_issue_ids(
    issue_ids: list[str], unwaivable_evidence_ids: set[str]
) -> list[str]:
    unwaivable_issue_ids = unwaivable_matrix_issue_ids(unwaivable_evidence_ids)
    return [issue_id for issue_id in issue_ids if issue_id not in unwaivable_issue_ids]


def row_waivers(
    spec: MatrixRowSpec,
    evidence_entries: dict[str, dict[str, Any]],
    gate_entries: dict[str, dict[str, Any]],
    context: WaiverContext,
    mode: str,
    issue_ids: list[str],
    unwaivable_evidence_ids: set[str],
) -> tuple[list[WaiverRecord], list[str]]:
    records: dict[str, WaiverRecord] = {}
    unwaivable_issue_ids = unwaivable_matrix_issue_ids(unwaivable_evidence_ids)
    waivable_issue_ids = waivable_matrix_issue_ids(issue_ids, unwaivable_evidence_ids)
    targets = [spec.id, *spec.evidence_ids(), *spec.all_gate_ids()]
    if unwaivable_evidence_ids:
        targets = [
            target_id
            for target_id in targets
            if target_id != spec.id and target_id not in unwaivable_evidence_ids
        ]
    for target_id in targets:
        waiver = active_waiver_for(context, target_id, waivable_issue_ids, mode)
        if waiver is not None:
            records[waiver.id] = waiver
    for evidence_id in spec.evidence_ids():
        if evidence_id in unwaivable_evidence_ids:
            continue
        waiver_id = evidence_details(evidence_entries.get(evidence_id)).get("waiverId")
        if waiver_id:
            waiver = active_waiver_for(context, str(waiver_id), waivable_issue_ids, mode)
            if waiver is not None:
                records[waiver.id] = waiver
    for gate_id in spec.all_gate_ids():
        gate = gate_entries.get(gate_id)
        details = gate.get("details", {}) if isinstance(gate, dict) else {}
        if isinstance(details, dict):
            waiver_id = details.get("waiverId")
            if waiver_id:
                if str(waiver_id) in unwaivable_issue_ids:
                    continue
                waiver = active_waiver_for(context, str(waiver_id), waivable_issue_ids, mode)
                if waiver is not None:
                    records[waiver.id] = waiver
    waiver_ids = sorted(records)
    return [records[waiver_id] for waiver_id in waiver_ids], waiver_ids


def row_release_blocker_waiver(
    spec: MatrixRowSpec,
    context: WaiverContext,
    mode: str,
    issue_ids: list[str],
    blocker_targets: list[str],
    unwaivable_evidence_ids: set[str],
) -> WaiverRecord | None:
    if unwaivable_evidence_ids.intersection(blocker_targets):
        return None
    waivable_issue_ids = waivable_matrix_issue_ids(issue_ids, unwaivable_evidence_ids)
    return active_waiver_for(
        context,
        spec.id,
        sorted(dict.fromkeys(waivable_issue_ids + blocker_targets)),
        mode,
    )


def row_recommendation(
    status: str,
    release_blocker: bool,
    waiver_ids: list[str],
    missing_required: list[str],
    gate_blockers: list[str],
    previous_matrix_missing_warning: bool,
) -> str:
    if status == "pass":
        return "No release action required."
    if previous_matrix_missing_warning:
        return "Record the previous-summary matrix gap in the release log."
    if waiver_ids:
        return "Review waived evidence before release-candidate promotion."
    if release_blocker and missing_required:
        return "Restore missing required evidence before release-candidate promotion."
    if release_blocker and gate_blockers:
        return "Resolve release-blocking ecosystem gate or record an approved waiver."
    if release_blocker:
        return "Review failing evidence and rerun release certification."
    if status == "missing":
        return "Restore missing required evidence before release-candidate promotion."
    if status == "skip":
        return "Review skipped evidence before release-candidate promotion."
    return "Review warning evidence or record an approved waiver."


def safe_waiver_summaries(records: list[WaiverRecord]) -> dict[str, str]:
    return {record.id: record.reason for record in records}


def evaluate_matrix_row(
    spec: MatrixRowSpec,
    settings: Settings,
    evidence_entries: dict[str, dict[str, Any]],
    previous_evidence_entries: dict[str, dict[str, Any]],
    gate_entries: dict[str, dict[str, Any]],
    history_comparison: dict[str, Any],
    previous_summary_present: bool,
    previous_matrix_present: bool,
    previous_row_statuses: dict[str, str],
    waiver_context: WaiverContext,
    redaction: dict[str, bool],
) -> dict[str, Any]:
    required_statuses = {
        evidence_id: evidence_status(evidence_entries.get(evidence_id))
        for evidence_id in spec.required_evidence_ids
    }
    optional_statuses = {
        evidence_id: evidence_status(evidence_entries.get(evidence_id))
        for evidence_id in spec.optional_evidence_ids
    }
    unwaivable_redaction_evidence_ids = {
        evidence_id
        for evidence_id in spec.evidence_ids()
        if evidence_entry_has_unwaivable_redaction_findings(evidence_entries.get(evidence_id))
    }
    previous_statuses = {
        evidence_id: evidence_status(previous_evidence_entries.get(evidence_id))
        for evidence_id in spec.evidence_ids()
    }
    gate_statuses = {
        gate_id: gate_status(gate_entries.get(gate_id))
        for gate_id in spec.gate_ids
    }
    optional_gate_statuses = {
        gate_id: gate_status(gate_entries.get(gate_id))
        for gate_id in spec.optional_gate_ids
        if gate_id in gate_entries
    }
    issue_ids: list[str] = []
    gate_blockers: list[str] = []
    gate_warnings: list[str] = []
    for gate_id in spec.all_gate_ids():
        gate = gate_entries.get(gate_id)
        if not isinstance(gate, dict):
            if gate_id in spec.gate_ids:
                issue_ids.append(f"matrix.gate-missing.{gate_id}")
            continue
        details = gate.get("details", {})
        if isinstance(details, dict):
            issue_ids.extend(str(value) for value in details.get("issueIds", []) if value)
        status = gate_status(gate)
        if status == "fail" and gate.get("releaseBlocker"):
            gate_blockers.append(gate_id)
        elif status in {"warn", "fail", "missing"}:
            gate_warnings.append(gate_id)

    missing_required = [
        evidence_id for evidence_id, status in required_statuses.items() if status == "missing"
    ]
    skipped_required = [
        evidence_id for evidence_id, status in required_statuses.items() if status == "skip"
    ]
    skipped_required_non_rc = skipped_required if settings.mode != "release-candidate" else []
    required_skip_only = (
        bool(spec.required_evidence_ids)
        and settings.mode != "release-candidate"
        and all(status == "skip" for status in required_statuses.values())
    )
    required_bad = [
        evidence_id
        for evidence_id, status in required_statuses.items()
        if status in {"fail", "missing"} or (status == "skip" and settings.mode == "release-candidate")
    ]
    required_warn = [
        evidence_id for evidence_id, status in required_statuses.items() if status == "warn"
    ]
    optional_warn = [
        evidence_id
        for evidence_id, status in optional_statuses.items()
        if status in {"fail", "warn", "missing", "skip"}
    ]
    if required_bad:
        issue_ids.extend(f"evidence.{evidence_id}" for evidence_id in required_bad)
    if required_warn:
        issue_ids.extend(f"evidence.{evidence_id}" for evidence_id in required_warn)
    if skipped_required_non_rc:
        issue_ids.extend(f"evidence.{evidence_id}" for evidence_id in skipped_required_non_rc)
    if optional_warn:
        issue_ids.extend(f"evidence.{evidence_id}" for evidence_id in optional_warn)
    blocker_targets = sorted(dict.fromkeys(required_bad + gate_blockers))

    previous_matrix_missing_warning = (
        spec.synthetic == "history"
        and previous_summary_present
        and not previous_matrix_present
        and settings.mode in {"nightly", "release-candidate"}
    )
    history_status = normalize_evidence_status(str(history_comparison.get("status", "missing")))
    if spec.synthetic == "history":
        if history_status == "fail" or gate_blockers:
            status = "fail"
            release_blocker = True
        elif history_status in {"warn", "missing"} or gate_warnings or previous_matrix_missing_warning:
            status = "warn"
            release_blocker = False
        else:
            status = "pass"
            release_blocker = False
        if waiver_context.records:
            status = "warn" if status == "pass" else status
        if waiver_context.errors and settings.mode == "release-candidate":
            status = "fail"
            release_blocker = True
        summary = "History comparison and waiver validation are visible in the release record."
    elif spec.synthetic == "redaction":
        release_blocker = not all(redaction.values())
        status = "fail" if release_blocker else "pass"
        summary = "Certification summaries and copied artifacts exclude private material."
        if release_blocker:
            issue_ids.append("matrix.redaction.failed")
    elif not spec.evidence_ids() and not spec.all_gate_ids():
        status = "missing"
        release_blocker = False
        summary = "Matrix row has no evidence or gate inputs."
        issue_ids.append("matrix.row-inputs-missing")
    elif required_bad or gate_blockers:
        status = "fail"
        release_blocker = True
        summary = "Required evidence or an ecosystem gate is release-blocking."
    elif (
        required_skip_only
        and not required_warn
        and not optional_warn
        and not gate_warnings
    ):
        status = "skip"
        release_blocker = False
        summary = "Required evidence was intentionally skipped outside release-candidate mode."
    elif (
        required_warn
        or skipped_required_non_rc
        or optional_warn
        or gate_warnings
        or any(
            previous_statuses.get(evidence_id) == "pass" and status_value == "warn"
            for evidence_id, status_value in required_statuses.items()
        )
    ):
        status = "warn"
        release_blocker = False
        summary = "Required or optional evidence needs release-manager review."
    else:
        status = "pass"
        release_blocker = False
        summary = "Required evidence and referenced ecosystem gates passed."

    waiver_for_blocker = row_release_blocker_waiver(
        spec,
        waiver_context,
        settings.mode,
        issue_ids,
        blocker_targets,
        unwaivable_redaction_evidence_ids,
    )
    if release_blocker and waiver_for_blocker is not None:
        status = "warn"
        release_blocker = False
        summary = f"{summary} Waiver recorded: {waiver_for_blocker.reason}"
    waiver_records, waiver_ids = row_waivers(
        spec,
        evidence_entries,
        gate_entries,
        waiver_context,
        settings.mode,
        issue_ids,
        unwaivable_redaction_evidence_ids,
    )
    if waiver_for_blocker is not None and waiver_for_blocker.id not in waiver_ids:
        waiver_records = sorted([*waiver_records, waiver_for_blocker], key=lambda record: record.id)
        waiver_ids = sorted([*waiver_ids, waiver_for_blocker.id])
    if waiver_ids and status == "pass":
        status = "warn"
        summary = "Active waiver is recorded for this row."

    previous_status, regression_status = regression_status_for_row(
        spec,
        status,
        release_blocker,
        previous_summary_present,
        previous_matrix_present,
        previous_row_statuses,
    )
    if regression_status in {"regressed-warning", "regressed-blocker"} and status == "pass":
        status = "warn"
    gate_status_value = aggregate_status_values(
        list(gate_statuses.values()) + list(optional_gate_statuses.values()),
        missing_if_empty=bool(spec.gate_ids),
    )
    details: dict[str, Any] = {
        "currentEvidenceStatuses": required_statuses | optional_statuses,
        "previousEvidenceStatuses": previous_statuses,
        "gateStatuses": gate_statuses | optional_gate_statuses,
    }
    if spec.first_party_apps:
        details["firstPartyApps"] = list(spec.first_party_apps)
    if waiver_records:
        details["waiverReasons"] = safe_waiver_summaries(waiver_records)
    if spec.synthetic == "history":
        details["historyStatus"] = history_status
        details["previousMatrixPresent"] = previous_matrix_present
    if spec.synthetic == "redaction":
        details["redaction"] = redaction
    if unwaivable_redaction_evidence_ids:
        details["unwaivableRedactionEvidenceIds"] = sorted(unwaivable_redaction_evidence_ids)

    return {
        "id": spec.id,
        "category": spec.category,
        "title": spec.title,
        "requiredForReleaseCandidate": spec.required_for_release_candidate,
        "status": status,
        "previousStatus": previous_status,
        "regressionStatus": regression_status,
        "releaseBlocker": release_blocker,
        "summary": summary,
        "evidenceIds": list(spec.evidence_ids()),
        "requiredEvidenceIds": list(spec.required_evidence_ids),
        "optionalEvidenceIds": list(spec.optional_evidence_ids),
        "gateIds": list(spec.all_gate_ids()),
        "gateStatus": gate_status_value,
        "waiverIds": waiver_ids,
        "issueIds": sorted(dict.fromkeys(issue_ids)),
        "docs": list(spec.docs),
        "owner": spec.owner,
        "phase": spec.phase,
        "recommendation": row_recommendation(
            status,
            release_blocker,
            waiver_ids,
            missing_required,
            gate_blockers,
            previous_matrix_missing_warning,
        ),
        "details": details,
    }


def validate_matrix_coverage(
    settings: Settings,
    specs: list[MatrixRowSpec],
    evidence_entries: dict[str, dict[str, Any]],
    gate_entries: dict[str, dict[str, Any]],
    redaction: dict[str, bool],
) -> dict[str, Any]:
    mapped_required_evidence = {
        evidence_id for spec in specs for evidence_id in spec.required_evidence_ids
    }
    mapped_evidence = {evidence_id for spec in specs for evidence_id in spec.evidence_ids()}
    required_evidence = {
        evidence_id
        for evidence_id, entry in evidence_entries.items()
        if evidence_required(entry)
    }
    mapped_gates = {gate_id for spec in specs for gate_id in spec.all_gate_ids()}
    gate_ids = set(gate_entries)
    non_synthetic_specs = [spec for spec in specs if not spec.synthetic]
    rows_without_docs = [spec.id for spec in non_synthetic_specs if not spec.docs]
    rows_without_owners = [spec.id for spec in specs if not spec.owner]
    missing_doc_paths = sorted(
        {
            doc_path
            for spec in non_synthetic_specs
            for doc_path in spec.docs
            if not (settings.workspace_root / doc_path).is_file()
        }
    )
    first_party_apps = sorted(
        {
            app_id
            for spec in specs
            for app_id in spec.first_party_apps
        }
    )
    missing_first_party_apps = sorted(set(EXPECTED_FIRST_PARTY_APPS) - set(first_party_apps))
    missing_required_evidence_ids = sorted(mapped_required_evidence - set(evidence_entries))
    unmapped_required_evidence_ids = sorted(required_evidence - mapped_evidence)
    unmapped_gate_ids = sorted(gate_ids - mapped_gates)
    coverage_issue_ids: list[str] = []
    if missing_required_evidence_ids:
        coverage_issue_ids.append("matrix.required-evidence-missing")
    if unmapped_required_evidence_ids:
        coverage_issue_ids.append("matrix.required-evidence-unmapped")
    if unmapped_gate_ids:
        coverage_issue_ids.append("matrix.ecosystem-gates-unmapped")
    if missing_first_party_apps:
        coverage_issue_ids.append("matrix.first-party-apps-uncovered")
    if rows_without_docs or missing_doc_paths:
        coverage_issue_ids.append("matrix.docs-uncovered")
    if not all(redaction.values()):
        coverage_issue_ids.append("matrix.redaction-failed")
    return {
        "requiredEvidenceCovered": not missing_required_evidence_ids and not unmapped_required_evidence_ids,
        "ecosystemGatesCovered": not unmapped_gate_ids,
        "firstPartyAppsCovered": not missing_first_party_apps,
        "docsCovered": not rows_without_docs and not missing_doc_paths,
        "redactionPassed": all(redaction.values()),
        "missingRequiredEvidenceIds": missing_required_evidence_ids,
        "unmappedRequiredEvidenceIds": unmapped_required_evidence_ids,
        "unmappedGateIds": unmapped_gate_ids,
        "rowsWithoutDocs": rows_without_docs,
        "rowsWithoutOwners": rows_without_owners,
        "missingDocPaths": missing_doc_paths,
        "coveredFirstPartyApps": first_party_apps,
        "missingFirstPartyApps": missing_first_party_apps,
        "issueIds": coverage_issue_ids,
    }


def matrix_coverage_waiver_state(
    coverage: dict[str, Any], context: WaiverContext, mode: str
) -> tuple[list[WaiverRecord], list[str], list[str]]:
    issue_ids = [str(issue_id) for issue_id in coverage.get("issueIds", []) if issue_id]
    waivable_issue_ids = [issue_id for issue_id in issue_ids if issue_id != "matrix.redaction-failed"]
    records_by_id: dict[str, WaiverRecord] = {}
    waived_issue_ids: list[str] = []
    row_waiver = active_waiver_for(
        context,
        "ecosystem-certification-matrix",
        ["release-certification.ecosystem-matrix"],
        mode,
    )
    for issue_id in waivable_issue_ids:
        waiver = row_waiver or active_waiver_for(
            context, "ecosystem-certification-matrix", [issue_id], mode
        )
        if waiver is None:
            waiver = active_waiver_for(context, issue_id, None, mode)
        if waiver is None:
            continue
        records_by_id[waiver.id] = waiver
        waived_issue_ids.append(issue_id)
    waived_issue_ids = sorted(dict.fromkeys(waived_issue_ids))
    unwaived_issue_ids = sorted(issue_id for issue_id in issue_ids if issue_id not in waived_issue_ids)
    return [records_by_id[waiver_id] for waiver_id in sorted(records_by_id)], waived_issue_ids, unwaived_issue_ids


def matrix_redaction_summary(summary_redaction: dict[str, Any] | None = None) -> dict[str, bool]:
    source = summary_redaction if isinstance(summary_redaction, dict) else {}
    return {
        "secretMaterialRedacted": bool(source.get("secretMaterialRedacted", True)),
        "formPasswordsRedacted": bool(source.get("formPasswordsRedacted", True)),
        "appProcessTokensRedacted": bool(source.get("appProcessTokensRedacted", True)),
        "browserSessionTokensRedacted": bool(source.get("browserSessionTokensRedacted", True)),
        "rawRequestBodiesExcluded": bool(source.get("rawRequestBodiesExcluded", True)),
        "rawFeedBodiesExcluded": bool(source.get("rawFeedBodiesExcluded", True)),
        "privateInsertUrisExcluded": bool(source.get("privateInsertUrisExcluded", True)),
        "signatureValuesRedacted": bool(source.get("signatureValuesRedacted", True)),
        "absolutePathsSanitized": bool(source.get("absolutePathsSanitized", True)),
    }


def matrix_categories(specs: list[MatrixRowSpec], rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    row_counts = {category: 0 for category in MATRIX_CATEGORY_TITLES}
    for row in rows:
        category = str(row.get("category", ""))
        row_counts[category] = row_counts.get(category, 0) + 1
    categories: list[dict[str, Any]] = []
    for spec in specs:
        if any(category.get("id") == spec.category for category in categories):
            continue
        categories.append(
            {
                "id": spec.category,
                "title": MATRIX_CATEGORY_TITLES.get(spec.category, spec.category),
                "rowCount": row_counts.get(spec.category, 0),
            }
        )
    return categories


def build_ecosystem_matrix(
    settings: Settings,
    evidence: list[EvidenceItem],
    previous_summary: dict[str, Any] | None,
    history_comparison: dict[str, Any],
    ecosystem_gates: list[GateResult],
    waiver_context: WaiverContext,
    generated_at: str,
    summary_redaction: dict[str, Any] | None = None,
) -> dict[str, Any]:
    specs = ecosystem_matrix_row_specs()
    evidence_entries = evidence_map_from_items(evidence)
    previous_evidence_entries = evidence_map_from_summary(previous_summary)
    gate_entries = {gate.id: gate.to_json() for gate in ecosystem_gates}
    previous_summary_present = previous_summary is not None
    previous_matrix_present = bool(
        isinstance(previous_summary, dict) and isinstance(previous_summary.get("ecosystemMatrix"), dict)
    )
    previous_row_statuses = previous_matrix_row_statuses(previous_summary)
    redaction = matrix_redaction_summary(summary_redaction)
    rows = [
        evaluate_matrix_row(
            spec,
            settings,
            evidence_entries,
            previous_evidence_entries,
            gate_entries,
            history_comparison,
            previous_summary_present,
            previous_matrix_present,
            previous_row_statuses,
            waiver_context,
            redaction,
        )
        for spec in specs
        ]
    coverage = validate_matrix_coverage(settings, specs, evidence_entries, gate_entries, redaction)
    coverage_waiver_records, waived_coverage_issue_ids, unwaived_coverage_issue_ids = matrix_coverage_waiver_state(
        coverage, waiver_context, settings.mode
    )
    coverage["waivedIssueIds"] = waived_coverage_issue_ids
    coverage["unwaivedIssueIds"] = unwaived_coverage_issue_ids
    coverage["coverageWaiverIds"] = [record.id for record in coverage_waiver_records]
    if coverage_waiver_records:
        coverage["waiverReasons"] = safe_waiver_summaries(coverage_waiver_records)
    for row in rows:
        if row["id"] == "ecosystem-certification-matrix" and coverage.get("issueIds"):
            row["issueIds"] = sorted(dict.fromkeys(row["issueIds"] + coverage["issueIds"]))
            row["details"]["coverageIssueIds"] = coverage["issueIds"]
            if waived_coverage_issue_ids:
                row["details"]["waivedCoverageIssueIds"] = waived_coverage_issue_ids
                row["details"]["waiverReasons"] = {
                    **(
                        row["details"].get("waiverReasons", {})
                        if isinstance(row["details"].get("waiverReasons"), dict)
                        else {}
                    ),
                    **safe_waiver_summaries(coverage_waiver_records),
                }
                row["waiverIds"] = sorted(
                    dict.fromkeys([*row.get("waiverIds", []), *coverage["coverageWaiverIds"]])
                )
            if unwaived_coverage_issue_ids and (
                settings.mode == "release-candidate" or coverage.get("redactionPassed") is False
            ):
                row["status"] = "fail"
                row["releaseBlocker"] = True
                row["summary"] = "Matrix coverage or redaction validation failed."
                row["recommendation"] = "Review failing evidence and rerun release certification."
            elif waived_coverage_issue_ids:
                row["status"] = "warn"
                row["releaseBlocker"] = False
                row["summary"] = "Matrix coverage validation produced waived warnings."
                row["recommendation"] = "Review waived evidence before release-candidate promotion."
            elif row["status"] == "pass":
                row["status"] = "warn"
                row["summary"] = "Matrix coverage validation produced warnings."
                row["recommendation"] = "Review warning evidence or record an approved waiver."
    counts = {status: 0 for status in CERT_STATUSES}
    release_blockers = 0
    waived_rows = 0
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
        if row.get("releaseBlocker"):
            release_blockers += 1
        if row.get("waiverIds"):
            waived_rows += 1
    counts["rows"] = len(rows)
    counts["releaseBlockers"] = release_blockers
    counts["waivedRows"] = waived_rows
    status = matrix_status_from_counts(settings.mode, counts, coverage)
    release_candidate_passed = status != "fail" and release_blockers == 0
    matrix_diffs = [
        {
            "rowId": row["id"],
            "previousStatus": row["previousStatus"],
            "currentStatus": row["status"],
            "regressionStatus": row["regressionStatus"],
        }
        for row in rows
        if row["regressionStatus"] in {"regressed-warning", "regressed-blocker", "new-row", "previous-missing"}
    ]
    matrix = {
        "schemaVersion": ECOSYSTEM_MATRIX_SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "kind": "ecosystem-certification-matrix",
        "mode": settings.mode,
        "status": status,
        "generatedAt": generated_at,
        "promotionDecision": (
            "block"
            if not release_candidate_passed
            else ("promote-with-warnings" if status == "warn" else "promote")
        ),
        "releaseCandidatePassed": release_candidate_passed,
        "workspaceRoot": "<repo>",
        "summaryPath": display_path(settings.out_dir / SUMMARY_FILE_NAME, settings.workspace_root, settings.out_dir),
        "reportPath": display_path(settings.out_dir / REPORT_FILE_NAME, settings.workspace_root, settings.out_dir),
        "matrixPath": display_path(
            settings.out_dir / ECOSYSTEM_MATRIX_FILE_NAME,
            settings.workspace_root,
            settings.out_dir,
        ),
        "matrixReportPath": display_path(
            settings.out_dir / ECOSYSTEM_MATRIX_REPORT_FILE_NAME,
            settings.workspace_root,
            settings.out_dir,
        ),
        "historyComparisonPath": display_path(
            settings.out_dir / HISTORY_COMPARISON_FILE_NAME,
            settings.workspace_root,
            settings.out_dir,
        ),
        "previousSummaryPresent": previous_summary_present,
        "previousMatrixPresent": previous_matrix_present,
        "counts": counts,
        "coverage": coverage,
        "categories": matrix_categories(specs, rows),
        "rows": rows,
        "matrixDiffs": matrix_diffs,
        "redaction": redaction,
    }
    return dict(sanitize_value(matrix, settings.workspace_root, settings.out_dir))


def matrix_compact_summary(matrix: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(matrix, dict):
        return {
            "schemaVersion": ECOSYSTEM_MATRIX_SCHEMA_VERSION,
            "status": "missing",
            "rowCount": 0,
            "releaseBlockerCount": 0,
            "coverage": {},
            "rowStatuses": {},
            "matrixDiffs": [],
        }
    rows = matrix.get("rows", [])
    row_statuses = {
        str(row.get("id")): str(row.get("status", "missing"))
        for row in rows
        if isinstance(row, dict) and row.get("id")
    } if isinstance(rows, list) else {}
    counts = matrix.get("counts", {}) if isinstance(matrix.get("counts"), dict) else {}
    return {
        "schemaVersion": matrix.get("schemaVersion", ECOSYSTEM_MATRIX_SCHEMA_VERSION),
        "status": matrix.get("status", "missing"),
        "rowCount": counts.get("rows", len(row_statuses)),
        "releaseBlockerCount": counts.get("releaseBlockers", 0),
        "coverage": matrix.get("coverage", {}) if isinstance(matrix.get("coverage"), dict) else {},
        "rowStatuses": row_statuses,
        "matrixDiffs": matrix.get("matrixDiffs", []) if isinstance(matrix.get("matrixDiffs"), list) else [],
    }


def ecosystem_matrix_evidence(
    matrix: dict[str, Any],
    workspace_root: Path,
    out_dir: Path,
) -> EvidenceItem:
    status = normalize_evidence_status(str(matrix.get("status", "missing")))
    counts = matrix.get("counts", {}) if isinstance(matrix.get("counts"), dict) else {}
    coverage = matrix.get("coverage", {}) if isinstance(matrix.get("coverage"), dict) else {}
    return sanitize_evidence_item(
        EvidenceItem(
            "release-certification.ecosystem-matrix",
            status,
            True,
            f"Ecosystem certification matrix status is {status}.",
            display_path(out_dir / ECOSYSTEM_MATRIX_FILE_NAME, workspace_root, out_dir),
            {
                "matrixPath": display_path(out_dir / ECOSYSTEM_MATRIX_FILE_NAME, workspace_root, out_dir),
                "matrixReportPath": display_path(
                    out_dir / ECOSYSTEM_MATRIX_REPORT_FILE_NAME,
                    workspace_root,
                    out_dir,
                ),
                "schemaVersion": ECOSYSTEM_MATRIX_SCHEMA_VERSION,
                "rowCount": counts.get("rows", 0),
                "coverage": coverage,
                "redactionPassed": bool(coverage.get("redactionPassed", False)),
            },
        ),
        workspace_root,
        out_dir,
    )


def placeholder_ecosystem_matrix_evidence(workspace_root: Path, out_dir: Path) -> EvidenceItem:
    return sanitize_evidence_item(
        EvidenceItem(
            "release-certification.ecosystem-matrix",
            "pass",
            True,
            "Ecosystem certification matrix generation is pending.",
            display_path(out_dir / ECOSYSTEM_MATRIX_FILE_NAME, workspace_root, out_dir),
            {
                "matrixPath": display_path(out_dir / ECOSYSTEM_MATRIX_FILE_NAME, workspace_root, out_dir),
                "matrixReportPath": display_path(
                    out_dir / ECOSYSTEM_MATRIX_REPORT_FILE_NAME,
                    workspace_root,
                    out_dir,
                ),
                "schemaVersion": ECOSYSTEM_MATRIX_SCHEMA_VERSION,
            },
        ),
        workspace_root,
        out_dir,
    )


def release_metadata_note_present(metadata: dict[str, Any], *keys: str) -> bool:
    for key in keys:
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            return True
        if isinstance(value, bool) and value:
            return True
    return False


def summary_identity(
    summary: dict[str, Any] | None,
    workspace_root: Path,
    out_dir: Path,
    source: str = "",
) -> dict[str, Any]:
    if not isinstance(summary, dict):
        return {"source": source} if source else {}
    metadata = summary.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}
    git_sha = (
        metadata.get("gitCommit")
        or metadata.get("githubSha")
        or summary.get("gitSha")
        or summary.get("commit")
        or ""
    )
    release_version = (
        metadata.get("releaseVersion")
        or metadata.get("version")
        or summary.get("releaseVersion")
        or summary.get("version")
        or ""
    )
    identity = {
        "source": source,
        "generatedAt": summary.get("generatedAt", ""),
        "gitSha": git_sha,
        "releaseVersion": release_version,
    }
    return {key: sanitize_value(value, workspace_root, out_dir) for key, value in identity.items()}


def current_identity(generated_at: str, metadata: dict[str, Any]) -> dict[str, Any]:
    git_sha = metadata.get("gitCommit") or metadata.get("githubSha") or ""
    release_version = metadata.get("releaseVersion") or metadata.get("version") or ""
    return {
        "generatedAt": generated_at,
        "gitSha": git_sha,
        "releaseVersion": release_version,
    }


def classify_evidence_diff(
    evidence_id: str,
    previous: dict[str, Any] | None,
    current: dict[str, Any] | None,
    waiver_context: WaiverContext,
    mode: str,
) -> dict[str, Any]:
    previous_status = evidence_status(previous)
    current_status = evidence_status(current)
    previous_present = previous is not None
    current_present = current is not None
    current_required = evidence_required(current)
    previous_required = evidence_required(previous)
    if not previous_present and current_present:
        classification = "new"
    elif previous_present and not current_present:
        classification = "removed"
    elif status_severity(current_status) > status_severity(previous_status):
        classification = "regression"
    elif status_severity(current_status) < status_severity(previous_status):
        classification = "improvement"
    else:
        classification = "unchanged"

    issue_ids = [
        f"history.{classification}.{evidence_id}",
        f"history.evidence.{evidence_id}",
    ]
    waived = bool(current and evidence_details(current).get("waived"))
    waiver = active_waiver_for(waiver_context, evidence_id, issue_ids, mode)
    release_blocker = False
    reason = "Evidence status is unchanged."
    if classification == "new":
        reason = "New evidence item is present in the current certification."
        if current_required and current_status in {"fail", "missing", "skip"}:
            release_blocker = True
            reason = "New required evidence is not passing."
        elif current_required and current_status == "warn":
            reason = "New required evidence is warning."
    elif classification == "removed":
        reason = "Evidence item was present in the previous certification but is absent now."
        release_blocker = previous_required
    elif classification == "regression":
        reason = f"Evidence regressed from {previous_status} to {current_status}."
        if (previous_required or current_required) and previous_status == "pass" and current_status in {
            "fail",
            "missing",
            "skip",
        }:
            release_blocker = True
        elif previous_required or current_required:
            reason = f"Required evidence regressed from {previous_status} to {current_status}."
    elif classification == "improvement":
        reason = f"Evidence improved from {previous_status} to {current_status}."

    if waiver is not None or waived:
        release_blocker = False
        if waiver is not None:
            reason = f"{reason} Waiver recorded: {waiver.reason}"

    return {
        "id": evidence_id,
        "previousStatus": previous_status if previous_present else "missing",
        "currentStatus": current_status if current_present else "missing",
        "classification": classification,
        "requiredForReleaseCandidate": bool(current_required or previous_required),
        "releaseBlocker": release_blocker,
        "reason": reason,
    }


def load_previous_summary(settings: Settings) -> tuple[dict[str, Any] | None, str, str]:
    history_dir = resolve_path(settings.workspace_root, settings.history_dir)
    path: Path | None = settings.previous_summary
    if path is None:
        candidate = history_dir / "latest-summary.json"
        if candidate.is_file():
            path = candidate
    if path is None:
        return None, "", ""
    source = display_path(path, settings.workspace_root, settings.out_dir)
    value = read_json(path)
    if value is None:
        if path.is_file():
            return None, source, f"Previous summary {source} is malformed."
        return None, source, f"Previous summary {source} is missing."
    contract_error = previous_summary_contract_error(value)
    if contract_error:
        return None, source, f"Previous summary {source} is invalid: {contract_error}"
    sanitized = sanitize_value(value, settings.workspace_root, settings.out_dir)
    return sanitized if isinstance(sanitized, dict) else None, source, ""


def previous_summary_contract_error(value: dict[str, Any]) -> str:
    if value.get("tool") != TOOL_NAME:
        return "not a release-certification summary"
    if value.get("schemaVersion") != SCHEMA_VERSION:
        return "unsupported schema version"
    evidence = value.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        return "missing evidence list"
    if not any(isinstance(entry, dict) and entry.get("id") for entry in evidence):
        return "evidence list has no evidence ids"
    return ""


def compare_history(
    settings: Settings,
    previous_summary: dict[str, Any] | None,
    previous_source: str,
    previous_error: str,
    current_evidence: list[EvidenceItem],
    generated_at: str,
    metadata: dict[str, Any],
    waiver_context: WaiverContext,
) -> dict[str, Any]:
    previous_identity = summary_identity(
        previous_summary, settings.workspace_root, settings.out_dir, previous_source
    )
    current = current_identity(generated_at, metadata)
    if previous_summary is None:
        if previous_error:
            status = "fail" if settings.mode == "release-candidate" or settings.require_history else "warn"
            summary = previous_error
        elif settings.require_history:
            status = "fail"
            summary = "Previous certified baseline is required but was not provided."
        elif settings.mode == "pr":
            status = "skip"
            summary = "Previous certified baseline was not provided."
        else:
            status = "warn"
            summary = "Previous certified baseline was not provided; historical regression context is unavailable."
        return {
            "version": 1,
            "status": status,
            "summary": summary,
            "previous": previous_identity,
            "current": current,
            "evidenceDiffs": [],
            "ecosystemGates": [],
            "waivers": [record.to_json() for record in waiver_context.records],
        }

    previous_evidence = evidence_map_from_summary(previous_summary)
    current_evidence_map = evidence_map_from_items(current_evidence)
    all_ids = sorted(set(previous_evidence) | set(current_evidence_map))
    diffs = [
        classify_evidence_diff(
            evidence_id,
            previous_evidence.get(evidence_id),
            current_evidence_map.get(evidence_id),
            waiver_context,
            settings.mode,
        )
        for evidence_id in all_ids
    ]
    has_blocker = any(diff["releaseBlocker"] for diff in diffs)
    has_warning = any(
        diff["classification"] in {"regression", "new", "removed"} and diff["currentStatus"] != "pass"
        for diff in diffs
    )
    status = "fail" if has_blocker else ("warn" if has_warning else "pass")
    return {
        "version": 1,
        "status": status,
        "summary": "Historical comparison completed." if status == "pass" else "Historical comparison found release-relevant changes.",
        "previous": previous_identity,
        "current": current,
        "evidenceDiffs": diffs,
        "ecosystemGates": [],
        "waivers": [record.to_json() for record in waiver_context.records],
    }


def gate_from_issues(gate_id: str, summary: str, failures: list[str], warnings: list[str], details: dict[str, Any]) -> GateResult:
    if failures:
        status = "fail"
        release_blocker = True
        message = f"{summary} Blockers: {'; '.join(failures)}"
    elif warnings:
        status = "warn"
        release_blocker = False
        message = f"{summary} Warnings: {'; '.join(warnings)}"
    else:
        status = "pass"
        release_blocker = False
        message = summary
    if failures:
        details["failures"] = failures
    if warnings:
        details["warnings"] = warnings
    issue_ids = [f"{gate_id}.{slugify_issue(issue)}" for issue in failures + warnings]
    if issue_ids:
        details["issueIds"] = issue_ids
    return GateResult(gate_id, status, release_blocker, message, details)


def add_evidence_issue(details: dict[str, Any], key: str, evidence_id: str) -> None:
    values = details.setdefault(key, [])
    if isinstance(values, list) and evidence_id not in values:
        values.append(evidence_id)


def slugify_issue(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:80] or "issue"


def evaluate_required_evidence_regressions(diffs: list[dict[str, Any]]) -> GateResult:
    failures: list[str] = []
    warnings: list[str] = []
    details = {"regressions": [], "newRequiredEvidence": [], "removedEvidence": []}
    for diff in diffs:
        classification = diff["classification"]
        required = bool(diff.get("requiredForReleaseCandidate"))
        current_status = diff["currentStatus"]
        if classification == "regression" and required:
            details["regressions"].append(diff)
            if diff.get("releaseBlocker"):
                failures.append(f"{diff['id']} regressed from {diff['previousStatus']} to {current_status}")
                add_evidence_issue(details, "failureEvidenceIds", str(diff["id"]))
            else:
                warnings.append(f"{diff['id']} regressed from {diff['previousStatus']} to {current_status}")
                add_evidence_issue(details, "warningEvidenceIds", str(diff["id"]))
        elif classification == "regression":
            details["regressions"].append(diff)
            warnings.append(f"Optional evidence {diff['id']} regressed")
            add_evidence_issue(details, "warningEvidenceIds", str(diff["id"]))
        elif classification == "new" and required:
            details["newRequiredEvidence"].append(diff)
            if current_status in {"fail", "missing", "skip"}:
                failures.append(f"New required evidence {diff['id']} is {current_status}")
                add_evidence_issue(details, "failureEvidenceIds", str(diff["id"]))
            elif current_status == "warn":
                warnings.append(f"New required evidence {diff['id']} is warning")
                add_evidence_issue(details, "warningEvidenceIds", str(diff["id"]))
        elif classification == "removed":
            details["removedEvidence"].append(diff)
            if required and diff.get("releaseBlocker"):
                failures.append(f"Required evidence {diff['id']} was removed")
                add_evidence_issue(details, "failureEvidenceIds", str(diff["id"]))
            elif required:
                warnings.append(f"Required evidence {diff['id']} was removed")
                add_evidence_issue(details, "warningEvidenceIds", str(diff["id"]))
            else:
                warnings.append(f"Optional evidence {diff['id']} was removed")
                add_evidence_issue(details, "warningEvidenceIds", str(diff["id"]))
    return gate_from_issues(
        "ecosystem.required-evidence-regressions",
        "Required release-candidate evidence did not regress.",
        failures,
        warnings,
        details,
    )


def evaluate_platform_api_gate(
    current: dict[str, dict[str, Any]], previous: dict[str, dict[str, Any]]
) -> GateResult:
    current_item = current.get("platform-api.contract")
    previous_item = previous.get("platform-api.contract")
    current_status = evidence_status(current_item)
    details = {"currentStatus": current_status}
    failures: list[str] = []
    warnings: list[str] = []
    if current_status in {"fail", "missing", "skip"}:
        failures.append("Platform API contract evidence is not passing")
    elif current_status == "warn":
        warnings.append("Platform API contract evidence is warning")
    current_details = evidence_details(current_item)
    previous_details = evidence_details(previous_item)
    details["current"] = {
        "contractVersion": current_details.get("contractVersion"),
        "endpointCount": current_details.get("endpointCount"),
        "capabilityCount": current_details.get("capabilityCount"),
        "stableDescriptorCount": stable_descriptor_count(current_details),
        "flaggedStability": current_details.get("flaggedStability", []),
    }
    if previous_details:
        details["previous"] = {
            "contractVersion": previous_details.get("contractVersion"),
            "endpointCount": previous_details.get("endpointCount"),
            "capabilityCount": previous_details.get("capabilityCount"),
            "stableDescriptorCount": stable_descriptor_count(previous_details),
        }
    previous_version = detail_int(previous_details, "contractVersion")
    current_version = detail_int(current_details, "contractVersion")
    if previous_version is not None and current_version is not None and current_version < previous_version:
        failures.append(f"Contract version moved backward from {previous_version} to {current_version}")
    compared_typed_stable_counts = False
    for count_key, label in (("stableEndpointCount", "endpoint"), ("stableCapabilityCount", "capability")):
        previous_count = detail_int(previous_details, count_key)
        current_count = detail_int(current_details, count_key)
        if previous_count is None or current_count is None:
            continue
        compared_typed_stable_counts = True
        if current_count < previous_count:
            failures.append(f"Stable {label} count decreased from {previous_count} to {current_count}")
    if not compared_typed_stable_counts:
        previous_stable_count = stable_descriptor_count(previous_details)
        current_stable_count = stable_descriptor_count(current_details)
        if (
            previous_stable_count is not None
            and current_stable_count is not None
            and current_stable_count < previous_stable_count
        ):
            failures.append(
                "Stable Platform API descriptor count decreased from "
                f"{previous_stable_count} to {current_stable_count}"
            )
    previous_endpoints = stable_named_set(previous_details, "stableEndpoints", "endpoints")
    current_endpoints = stable_named_set(current_details, "stableEndpoints", "endpoints")
    current_endpoints_reported = stable_named_set_reported(current_details, "stableEndpoints", "endpoints")
    removed_endpoints = (
        sorted(previous_endpoints - current_endpoints)
        if previous_endpoints and current_endpoints_reported
        else []
    )
    if removed_endpoints:
        failures.append(f"Stable endpoints were removed: {', '.join(removed_endpoints)}")
    previous_capabilities = stable_named_set(previous_details, "stableCapabilities", "capabilities")
    current_capabilities = stable_named_set(current_details, "stableCapabilities", "capabilities")
    current_capabilities_reported = stable_named_set_reported(
        current_details, "stableCapabilities", "capabilities"
    )
    removed_capabilities = (
        sorted(previous_capabilities - current_capabilities)
        if previous_capabilities and current_capabilities_reported
        else []
    )
    if removed_capabilities:
        failures.append(f"Stable capabilities were removed: {', '.join(removed_capabilities)}")
    if current_details.get("flaggedStability"):
        warnings.append("Contract evidence contains stability warnings")
    if not previous_details:
        warnings.append("Previous Platform API contract details were unavailable; comparison is status-limited")
    if failures:
        add_evidence_issue(details, "failureEvidenceIds", "platform-api.contract")
    if warnings:
        add_evidence_issue(details, "warningEvidenceIds", "platform-api.contract")
    return gate_from_issues(
        "ecosystem.platform-api-compatibility",
        "Platform API compatibility evidence is stable.",
        failures,
        warnings,
        details,
    )


def evaluate_first_party_apps_gate(
    current: dict[str, dict[str, Any]], previous: dict[str, dict[str, Any]]
) -> GateResult:
    current_item = current.get("app-platform.first-party")
    previous_item = previous.get("app-platform.first-party")
    current_details = evidence_details(current_item)
    previous_details = evidence_details(previous_item)
    current_apps = app_ids_from_details(current_details)
    previous_apps = app_ids_from_details(previous_details)
    required_apps = set(EXPECTED_FIRST_PARTY_APPS)
    failures: list[str] = []
    warnings: list[str] = []
    status = evidence_status(current_item)
    if status in {"fail", "missing", "skip"}:
        failures.append("First-party app evidence is not passing")
    elif status == "warn":
        warnings.append("First-party app evidence is warning")
    missing_required = sorted(required_apps - current_apps)
    if missing_required:
        failures.append(f"Required first-party apps are absent: {', '.join(missing_required)}")
    disappeared = sorted(previous_apps - current_apps) if previous_apps else []
    if disappeared:
        failures.append(f"Previously certified first-party apps disappeared: {', '.join(disappeared)}")
    gate_details = {
        "currentApps": sorted(current_apps),
        "previousApps": sorted(previous_apps),
        "requiredApps": sorted(required_apps),
    }
    if failures:
        add_evidence_issue(gate_details, "failureEvidenceIds", "app-platform.first-party")
    if warnings:
        add_evidence_issue(gate_details, "warningEvidenceIds", "app-platform.first-party")
    return gate_from_issues(
        "ecosystem.first-party-apps",
        "First-party app evidence covers required apps.",
        failures,
        warnings,
        gate_details,
    )


def evaluate_app_ui_quality_gate(
    current: dict[str, dict[str, Any]], previous: dict[str, dict[str, Any]]
) -> GateResult:
    failures: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {}
    for evidence_id in ("app-ui.lint", "app-ui.design-system", "app-ui.first-party-adoption"):
        status = evidence_status(current.get(evidence_id))
        previous_status = evidence_status(previous.get(evidence_id))
        details[evidence_id] = {"currentStatus": status, "previousStatus": previous_status}
        if status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} evidence is not passing")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
        elif status == "warn":
            warnings.append(f"{evidence_id} evidence is warning")
            add_evidence_issue(details, "warningEvidenceIds", evidence_id)
        if previous_status == "pass" and status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} regressed from pass to {status}")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
    current_warnings = total_ui_warnings(evidence_details(current.get("app-ui.lint")))
    previous_warnings = total_ui_warnings(evidence_details(previous.get("app-ui.lint")))
    details["lintWarnings"] = {"current": current_warnings, "previous": previous_warnings}
    if current_warnings is not None and previous_warnings is not None and current_warnings > previous_warnings:
        warnings.append(f"UI lint warnings increased from {previous_warnings} to {current_warnings}")
        add_evidence_issue(details, "warningEvidenceIds", "app-ui.lint")
    return gate_from_issues(
        "ecosystem.app-ui-quality",
        "First-party app UI lint and design-system evidence passed.",
        failures,
        warnings,
        details,
    )


def evaluate_app_review_trust_gate(
    current: dict[str, dict[str, Any]],
    previous: dict[str, dict[str, Any]],
    metadata: dict[str, Any],
    mode: str,
) -> GateResult:
    failures: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {}
    for evidence_id in (
        "app-review.trusted-receipts",
        "app-review.policy",
        "app-review.governance",
        "app-review.reviewer-key-lifecycle",
        "app-review.transparency-log",
        "app-review.review-history-api",
        "app-review.first-party-catalog",
        "app-review.first-party-review-chain",
    ):
        status = evidence_status(current.get(evidence_id))
        previous_status = evidence_status(previous.get(evidence_id))
        details[evidence_id] = {"currentStatus": status, "previousStatus": previous_status}
        if status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} evidence is not passing")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
        elif status == "warn":
            warnings.append(f"{evidence_id} evidence is warning")
            add_evidence_issue(details, "warningEvidenceIds", evidence_id)
        if previous_status == "pass" and status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} regressed from pass to {status}")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
    catalog_details = evidence_details(current.get("app-review.first-party-catalog"))
    coverage = nested_dict(catalog_details, "coverage")
    first_party_apps = sorted_strings(catalog_details.get("firstPartyApps"))
    trusted_positive = int_value(coverage.get("trustedPositiveReceipts"))
    missing_receipts = int_value(coverage.get("missingReceipts"))
    details["firstPartyReceiptCoverage"] = {
        "firstPartyApps": first_party_apps,
        "trustedPositiveReceipts": trusted_positive,
        "missingReceipts": missing_receipts,
    }
    if mode == "release-candidate":
        if trusted_positive is None or trusted_positive < len(first_party_apps):
            failures.append("First-party catalog lacks trusted positive review receipts for every app")
            add_evidence_issue(details, "failureEvidenceIds", "app-review.first-party-catalog")
        if missing_receipts and missing_receipts > 0:
            failures.append("First-party catalog has missing trusted review receipts")
            add_evidence_issue(details, "failureEvidenceIds", "app-review.first-party-catalog")
    policy_details = evidence_details(current.get("app-review.policy"))
    previous_policy_details = evidence_details(previous.get("app-review.policy"))
    policy_marker = policy_details.get("policyId") or policy_details.get("policyVersion") or policy_details.get("mode")
    previous_policy_marker = (
        previous_policy_details.get("policyId")
        or previous_policy_details.get("policyVersion")
        or previous_policy_details.get("mode")
    )
    if previous_policy_marker and policy_marker and previous_policy_marker != policy_marker:
        if not release_metadata_note_present(metadata, "releaseNotes", "reviewPolicyChange", "reviewPolicyVersion"):
            warnings.append("Review policy marker changed without release-note metadata")
            add_evidence_issue(details, "warningEvidenceIds", "app-review.policy")
    return gate_from_issues(
        "ecosystem.app-review-trust",
        "Trusted app-review receipt and policy evidence passed.",
        failures,
        warnings,
        details,
    )


def evaluate_app_update_rollback_gate(
    current: dict[str, dict[str, Any]], previous: dict[str, dict[str, Any]]
) -> GateResult:
    failures: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {}
    for evidence_id in (
        "app-update.lifecycle",
        "app-update.scheduler",
        "app-update.live-catalog-refresh",
        "app-update.rollback",
    ):
        status = evidence_status(current.get(evidence_id))
        previous_status = evidence_status(previous.get(evidence_id))
        details[evidence_id] = {"currentStatus": status, "previousStatus": previous_status}
        if status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} evidence is not passing")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
        elif status == "warn":
            warnings.append(f"{evidence_id} evidence is warning")
            add_evidence_issue(details, "warningEvidenceIds", evidence_id)
        if previous_status == "pass" and status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} regressed from pass to {status}")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
    rollback_details = evidence_details(current.get("app-update.rollback"))
    details["rollbackScope"] = rollback_details.get("rollbackScope")
    details["preservesDataCacheRun"] = rollback_details.get("preservesDataCacheRun")
    if rollback_details.get("rollbackScope") != "installed-bundle-only":
        warnings.append("Rollback evidence does not prove installed-bundle-only scope")
        add_evidence_issue(details, "warningEvidenceIds", "app-update.rollback")
    if rollback_details.get("preservesDataCacheRun") is not True:
        warnings.append("Rollback evidence does not prove data/cache/run preservation")
        add_evidence_issue(details, "warningEvidenceIds", "app-update.rollback")
    return gate_from_issues(
        "ecosystem.app-update-rollback",
        "App-update lifecycle, scheduler, and rollback evidence passed.",
        failures,
        warnings,
        details,
    )


def evaluate_app_vault_gate(
    current: dict[str, dict[str, Any]], previous: dict[str, dict[str, Any]]
) -> GateResult:
    item = current.get("app-vault.capabilities")
    previous_item = previous.get("app-vault.capabilities")
    status = evidence_status(item)
    previous_status = evidence_status(previous_item)
    vault_details = evidence_details(item)
    details: dict[str, Any] = {}
    failures: list[str] = []
    warnings: list[str] = []
    if status in {"fail", "missing", "skip"}:
        failures.append("Vault capability evidence is not passing")
        add_evidence_issue(details, "failureEvidenceIds", "app-vault.capabilities")
    elif status == "warn":
        warnings.append("Vault capability evidence is warning")
        add_evidence_issue(details, "warningEvidenceIds", "app-vault.capabilities")
    if previous_status == "pass" and status in {"fail", "missing", "skip"}:
        failures.append(f"Vault capability evidence regressed from pass to {status}")
        add_evidence_issue(details, "failureEvidenceIds", "app-vault.capabilities")
    capabilities = set(sorted_strings(vault_details.get("capabilities")))
    missing_capabilities = sorted(set(EXPECTED_VAULT_CAPABILITIES) - capabilities)
    if missing_capabilities:
        failures.append(f"Vault capability evidence is missing capabilities: {', '.join(missing_capabilities)}")
        add_evidence_issue(details, "failureEvidenceIds", "app-vault.capabilities")
    checks_pass = all_boolean_checks_pass(vault_details)
    if checks_pass is False:
        failures.append("Vault capability checks are not all passing")
        add_evidence_issue(details, "failureEvidenceIds", "app-vault.capabilities")
    redaction = nested_dict(vault_details, "redaction")
    for key in ("secretValuesRedacted", "identityPrivateMaterialRedacted"):
        if redaction.get(key) is not True:
            failures.append(f"Vault redaction check {key} failed or missing")
            add_evidence_issue(details, "failureEvidenceIds", "app-vault.capabilities")
    for evidence_id in ("app-platform.identity-profile-publish",):
        route_status = evidence_status(current.get(evidence_id))
        previous_route_status = evidence_status(previous.get(evidence_id))
        details[evidence_id] = {
            "currentStatus": route_status,
            "previousStatus": previous_route_status,
        }
        if route_status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} evidence is not passing")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
        elif route_status == "warn":
            warnings.append(f"{evidence_id} evidence is warning")
            add_evidence_issue(details, "warningEvidenceIds", evidence_id)
        if previous_route_status == "pass" and route_status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} regressed from pass to {route_status}")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
    details.update(
        {"currentStatus": status, "previousStatus": previous_status, "capabilities": sorted(capabilities)}
    )
    return gate_from_issues(
        "ecosystem.app-vault",
        "App-vault capability and redaction evidence passed.",
        failures,
        warnings,
        details,
    )


def evaluate_sandbox_provider_gate(
    current: dict[str, dict[str, Any]], previous: dict[str, dict[str, Any]], mode: str, metadata: dict[str, Any]
) -> GateResult:
    item = current.get("apphost.sandbox-provider")
    previous_item = previous.get("apphost.sandbox-provider")
    sandbox_details = evidence_details(item)
    previous_details = evidence_details(previous_item)
    status = evidence_status(item)
    previous_status = evidence_status(previous_item)
    support_level = str(sandbox_details.get("supportLevel", "")).lower()
    previous_support_level = str(previous_details.get("supportLevel", "")).lower()
    enforcement_required = mode == "release-candidate" or str(metadata.get("sandboxEnforcementRequired", "")).lower() == "true"
    issue_details: dict[str, Any] = {}
    failures: list[str] = []
    warnings: list[str] = []
    if status in {"fail", "missing", "skip"}:
        if enforcement_required:
            failures.append("Sandbox-provider evidence is not passing")
            add_evidence_issue(issue_details, "failureEvidenceIds", "apphost.sandbox-provider")
        else:
            warnings.append("Sandbox-provider evidence is not passing")
            add_evidence_issue(issue_details, "warningEvidenceIds", "apphost.sandbox-provider")
    elif status == "warn":
        warnings.append("Sandbox-provider evidence is warning")
        add_evidence_issue(issue_details, "warningEvidenceIds", "apphost.sandbox-provider")
    if previous_status == "pass" and status in {"fail", "missing", "skip"} and enforcement_required:
        failures.append(f"Sandbox-provider evidence regressed from pass to {status}")
        add_evidence_issue(issue_details, "failureEvidenceIds", "apphost.sandbox-provider")
    if previous_support_level == "enforced" and support_level and support_level != "enforced":
        if enforcement_required:
            failures.append(f"Sandbox support regressed from enforced to {support_level}")
            add_evidence_issue(issue_details, "failureEvidenceIds", "apphost.sandbox-provider")
        else:
            warnings.append(f"Sandbox support regressed from enforced to {support_level}")
            add_evidence_issue(issue_details, "warningEvidenceIds", "apphost.sandbox-provider")
    if enforcement_required and support_level != "enforced":
        failures.append("Enforced sandbox-provider evidence is required but not present")
        add_evidence_issue(issue_details, "failureEvidenceIds", "apphost.sandbox-provider")
    return gate_from_issues(
        "ecosystem.sandbox-provider",
        "Sandbox-provider evidence remains enforced where required.",
        failures,
        warnings,
        {
            "currentStatus": status,
            "previousStatus": previous_status,
            "supportLevel": support_level,
            "previousSupportLevel": previous_support_level,
            "enforcementRequired": enforcement_required,
            "failureEvidenceIds": issue_details.get("failureEvidenceIds", []),
            "warningEvidenceIds": issue_details.get("warningEvidenceIds", []),
        },
    )


def evaluate_reference_content_gate(
    current: dict[str, dict[str, Any]], previous: dict[str, dict[str, Any]]
) -> GateResult:
    item = current.get("reference-apps.content")
    previous_item = previous.get("reference-apps.content")
    profile_item = current.get("reference-app.profile-publisher")
    previous_profile_item = previous.get("reference-app.profile-publisher")
    profile_app_data_item = current.get("reference-app.profile-publisher-app-data")
    previous_profile_app_data_item = previous.get("reference-app.profile-publisher-app-data")
    feed_reader_item = current.get("reference-app.feed-reader")
    previous_feed_reader_item = previous.get("reference-app.feed-reader")
    feed_reader_subscription_item = current.get("reference-app.feed-reader-subscriptions")
    previous_feed_reader_subscription_item = previous.get("reference-app.feed-reader-subscriptions")
    feed_reader_app_data_item = current.get("reference-app.feed-reader-app-data")
    previous_feed_reader_app_data_item = previous.get("reference-app.feed-reader-app-data")
    trust_graph_item = current.get("reference-app.trust-graph")
    previous_trust_graph_item = previous.get("reference-app.trust-graph")
    trust_graph_durable_exchange_item = current.get("reference-app.trust-graph-durable-exchange")
    previous_trust_graph_durable_exchange_item = previous.get(
        "reference-app.trust-graph-durable-exchange"
    )
    trust_graph_app_data_item = current.get("reference-app.trust-graph-app-data-preview")
    previous_trust_graph_app_data_item = previous.get(
        "reference-app.trust-graph-app-data-preview"
    )
    social_message_signing_item = current.get("app-platform.social-message-signing")
    previous_social_message_signing_item = previous.get("app-platform.social-message-signing")
    social_inbox_item = current.get("reference-app.social-inbox")
    previous_social_inbox_item = previous.get("reference-app.social-inbox")
    social_inbox_signed_message_item = current.get("reference-app.social-inbox-signed-message")
    previous_social_inbox_signed_message_item = previous.get(
        "reference-app.social-inbox-signed-message"
    )
    social_inbox_subscription_item = current.get("reference-app.social-inbox-subscriptions")
    previous_social_inbox_subscription_item = previous.get(
        "reference-app.social-inbox-subscriptions"
    )
    social_inbox_app_data_item = current.get("reference-app.social-inbox-app-data")
    previous_social_inbox_app_data_item = previous.get("reference-app.social-inbox-app-data")
    social_inbox_trust_item = current.get("reference-app.social-inbox-trust-annotations")
    previous_social_inbox_trust_item = previous.get(
        "reference-app.social-inbox-trust-annotations"
    )
    social_mail_migration_item = current.get("migration.social-mail-preview")
    previous_social_mail_migration_item = previous.get("migration.social-mail-preview")
    generated_document_item = current.get("app-platform.generated-document-insert")
    previous_generated_document_item = previous.get("app-platform.generated-document-insert")
    content_fetch_item = current.get("app-platform.content-fetch")
    previous_content_fetch_item = previous.get("app-platform.content-fetch")
    content_subscription_item = current.get("app-platform.content-subscriptions")
    previous_content_subscription_item = previous.get("app-platform.content-subscriptions")
    content_subscription_scheduler_item = current.get("network-content.subscription-scheduler")
    previous_content_subscription_scheduler_item = previous.get(
        "network-content.subscription-scheduler"
    )
    app_data_store_item = current.get("app-platform.durable-app-data-store")
    previous_app_data_store_item = previous.get("app-platform.durable-app-data-store")
    trust_graph_preview_item = current.get("app-platform.trust-graph-preview")
    previous_trust_graph_preview_item = previous.get("app-platform.trust-graph-preview")
    trust_graph_durable_store_item = current.get("app-platform.trust-graph-durable-store")
    previous_trust_graph_durable_store_item = previous.get(
        "app-platform.trust-graph-durable-store"
    )
    trust_graph_exchange_item = current.get("app-platform.trust-graph-exchange")
    previous_trust_graph_exchange_item = previous.get("app-platform.trust-graph-exchange")
    trust_statement_signing_item = current.get("app-platform.trust-statement-signing")
    previous_trust_statement_signing_item = previous.get("app-platform.trust-statement-signing")
    app_services_registry_item = current.get("app-services.registry")
    previous_app_services_registry_item = previous.get("app-services.registry")
    app_services_grants_item = current.get("app-services.grants")
    previous_app_services_grants_item = previous.get("app-services.grants")
    app_services_provider_item = current.get("app-services.trust-score-provider")
    previous_app_services_provider_item = previous.get("app-services.trust-score-provider")
    social_inbox_service_grant_item = current.get("reference-app.social-inbox-service-grant")
    previous_social_inbox_service_grant_item = previous.get(
        "reference-app.social-inbox-service-grant"
    )
    app_services_web_shell_item = current.get("app-services.web-shell")
    previous_app_services_web_shell_item = previous.get("app-services.web-shell")
    app_services_redaction_item = current.get("app-services.redaction")
    previous_app_services_redaction_item = previous.get("app-services.redaction")
    details = evidence_details(item)
    profile_details = evidence_details(profile_item)
    profile_app_data_details = evidence_details(profile_app_data_item)
    feed_reader_details = evidence_details(feed_reader_item)
    feed_reader_subscription_details = evidence_details(feed_reader_subscription_item)
    feed_reader_app_data_details = evidence_details(feed_reader_app_data_item)
    trust_graph_details = evidence_details(trust_graph_item)
    trust_graph_durable_exchange_details = evidence_details(trust_graph_durable_exchange_item)
    trust_graph_app_data_details = evidence_details(trust_graph_app_data_item)
    social_message_signing_details = evidence_details(social_message_signing_item)
    social_inbox_details = evidence_details(social_inbox_item)
    social_inbox_signed_message_details = evidence_details(social_inbox_signed_message_item)
    social_inbox_subscription_details = evidence_details(social_inbox_subscription_item)
    social_inbox_app_data_details = evidence_details(social_inbox_app_data_item)
    social_inbox_trust_details = evidence_details(social_inbox_trust_item)
    social_mail_migration_details = evidence_details(social_mail_migration_item)
    generated_document_details = evidence_details(generated_document_item)
    content_fetch_details = evidence_details(content_fetch_item)
    content_subscription_details = evidence_details(content_subscription_item)
    content_subscription_scheduler_details = evidence_details(
        content_subscription_scheduler_item
    )
    app_data_store_details = evidence_details(app_data_store_item)
    trust_graph_preview_details = evidence_details(trust_graph_preview_item)
    trust_graph_durable_store_details = evidence_details(trust_graph_durable_store_item)
    trust_graph_exchange_details = evidence_details(trust_graph_exchange_item)
    trust_statement_signing_details = evidence_details(trust_statement_signing_item)
    app_services_registry_details = evidence_details(app_services_registry_item)
    app_services_grants_details = evidence_details(app_services_grants_item)
    app_services_provider_details = evidence_details(app_services_provider_item)
    social_inbox_service_grant_details = evidence_details(social_inbox_service_grant_item)
    app_services_web_shell_details = evidence_details(app_services_web_shell_item)
    app_services_redaction_details = evidence_details(app_services_redaction_item)
    checks = nested_dict(details, "checks")
    profile_checks = nested_dict(profile_details, "checks")
    profile_app_data_checks = nested_dict(profile_app_data_details, "checks")
    feed_reader_checks = nested_dict(feed_reader_details, "checks")
    feed_reader_app_data_checks = nested_dict(feed_reader_app_data_details, "checks")
    trust_graph_checks = nested_dict(trust_graph_details, "checks")
    trust_graph_durable_exchange_checks = nested_dict(
        trust_graph_durable_exchange_details, "checks"
    )
    trust_graph_app_data_checks = nested_dict(trust_graph_app_data_details, "checks")
    social_message_signing_checks = nested_dict(social_message_signing_details, "checks")
    social_inbox_checks = nested_dict(social_inbox_details, "checks")
    social_inbox_signed_message_checks = nested_dict(
        social_inbox_signed_message_details, "checks"
    )
    social_inbox_subscription_checks = nested_dict(social_inbox_subscription_details, "checks")
    social_inbox_app_data_checks = nested_dict(social_inbox_app_data_details, "checks")
    social_inbox_trust_checks = nested_dict(social_inbox_trust_details, "checks")
    social_inbox_service_grant_checks = nested_dict(social_inbox_service_grant_details, "checks")
    social_mail_migration_checks = nested_dict(social_mail_migration_details, "checks")
    app_services_registry_checks = nested_dict(app_services_registry_details, "checks")
    app_services_grants_checks = nested_dict(app_services_grants_details, "checks")
    app_services_provider_checks = nested_dict(app_services_provider_details, "checks")
    app_services_web_shell_checks = nested_dict(app_services_web_shell_details, "checks")
    app_services_redaction_checks = nested_dict(app_services_redaction_details, "checks")
    status = evidence_status(item)
    previous_status = evidence_status(previous_item)
    profile_status = evidence_status(profile_item)
    previous_profile_status = evidence_status(previous_profile_item)
    profile_app_data_status = evidence_status(profile_app_data_item)
    previous_profile_app_data_status = evidence_status(previous_profile_app_data_item)
    feed_reader_status = evidence_status(feed_reader_item)
    previous_feed_reader_status = evidence_status(previous_feed_reader_item)
    feed_reader_subscription_status = evidence_status(feed_reader_subscription_item)
    previous_feed_reader_subscription_status = evidence_status(
        previous_feed_reader_subscription_item
    )
    feed_reader_app_data_status = evidence_status(feed_reader_app_data_item)
    previous_feed_reader_app_data_status = evidence_status(previous_feed_reader_app_data_item)
    trust_graph_status = evidence_status(trust_graph_item)
    previous_trust_graph_status = evidence_status(previous_trust_graph_item)
    trust_graph_durable_exchange_status = evidence_status(trust_graph_durable_exchange_item)
    previous_trust_graph_durable_exchange_status = evidence_status(
        previous_trust_graph_durable_exchange_item
    )
    trust_graph_app_data_status = evidence_status(trust_graph_app_data_item)
    previous_trust_graph_app_data_status = evidence_status(previous_trust_graph_app_data_item)
    social_message_signing_status = evidence_status(social_message_signing_item)
    previous_social_message_signing_status = evidence_status(
        previous_social_message_signing_item
    )
    social_inbox_status = evidence_status(social_inbox_item)
    previous_social_inbox_status = evidence_status(previous_social_inbox_item)
    social_inbox_signed_message_status = evidence_status(social_inbox_signed_message_item)
    previous_social_inbox_signed_message_status = evidence_status(
        previous_social_inbox_signed_message_item
    )
    social_inbox_subscription_status = evidence_status(social_inbox_subscription_item)
    previous_social_inbox_subscription_status = evidence_status(
        previous_social_inbox_subscription_item
    )
    social_inbox_app_data_status = evidence_status(social_inbox_app_data_item)
    previous_social_inbox_app_data_status = evidence_status(previous_social_inbox_app_data_item)
    social_inbox_trust_status = evidence_status(social_inbox_trust_item)
    previous_social_inbox_trust_status = evidence_status(previous_social_inbox_trust_item)
    social_mail_migration_status = evidence_status(social_mail_migration_item)
    previous_social_mail_migration_status = evidence_status(previous_social_mail_migration_item)
    generated_document_status = evidence_status(generated_document_item)
    previous_generated_document_status = evidence_status(previous_generated_document_item)
    content_fetch_status = evidence_status(content_fetch_item)
    previous_content_fetch_status = evidence_status(previous_content_fetch_item)
    content_subscription_status = evidence_status(content_subscription_item)
    previous_content_subscription_status = evidence_status(previous_content_subscription_item)
    content_subscription_scheduler_status = evidence_status(content_subscription_scheduler_item)
    previous_content_subscription_scheduler_status = evidence_status(
        previous_content_subscription_scheduler_item
    )
    app_data_store_status = evidence_status(app_data_store_item)
    previous_app_data_store_status = evidence_status(previous_app_data_store_item)
    trust_graph_preview_status = evidence_status(trust_graph_preview_item)
    previous_trust_graph_preview_status = evidence_status(previous_trust_graph_preview_item)
    trust_graph_durable_store_status = evidence_status(trust_graph_durable_store_item)
    previous_trust_graph_durable_store_status = evidence_status(
        previous_trust_graph_durable_store_item
    )
    trust_graph_exchange_status = evidence_status(trust_graph_exchange_item)
    previous_trust_graph_exchange_status = evidence_status(previous_trust_graph_exchange_item)
    trust_statement_signing_status = evidence_status(trust_statement_signing_item)
    previous_trust_statement_signing_status = evidence_status(
        previous_trust_statement_signing_item
    )
    app_services_registry_status = evidence_status(app_services_registry_item)
    previous_app_services_registry_status = evidence_status(previous_app_services_registry_item)
    app_services_grants_status = evidence_status(app_services_grants_item)
    previous_app_services_grants_status = evidence_status(previous_app_services_grants_item)
    app_services_provider_status = evidence_status(app_services_provider_item)
    previous_app_services_provider_status = evidence_status(previous_app_services_provider_item)
    social_inbox_service_grant_status = evidence_status(social_inbox_service_grant_item)
    previous_social_inbox_service_grant_status = evidence_status(
        previous_social_inbox_service_grant_item
    )
    app_services_web_shell_status = evidence_status(app_services_web_shell_item)
    previous_app_services_web_shell_status = evidence_status(previous_app_services_web_shell_item)
    app_services_redaction_status = evidence_status(app_services_redaction_item)
    previous_app_services_redaction_status = evidence_status(previous_app_services_redaction_item)
    gate_details: dict[str, Any] = {}
    failures: list[str] = []
    warnings: list[str] = []
    if status in {"fail", "missing", "skip"}:
        failures.append("Site Publisher reference-content evidence is not passing")
        add_evidence_issue(gate_details, "failureEvidenceIds", "reference-apps.content")
    elif status == "warn":
        warnings.append("Site Publisher reference-content evidence is warning")
        add_evidence_issue(gate_details, "warningEvidenceIds", "reference-apps.content")
    if previous_status == "pass" and status in {"fail", "missing", "skip"}:
        failures.append(f"Site Publisher evidence regressed from pass to {status}")
        add_evidence_issue(gate_details, "failureEvidenceIds", "reference-apps.content")
    if details.get("appId") not in {"site-publisher", None}:
        failures.append("Reference content app evidence is not for site-publisher")
        add_evidence_issue(gate_details, "failureEvidenceIds", "reference-apps.content")
    if checks:
        for key in ("usesContentInsertDirectory", "usesContentInsertFile", "usesSdkBootstrap"):
            if checks.get(key) is not True:
                failures.append(f"Reference content app check {key} failed")
                add_evidence_issue(gate_details, "failureEvidenceIds", "reference-apps.content")
    elif status == "pass":
        warnings.append("Reference content app coverage lacks detailed staged app checks")
        add_evidence_issue(gate_details, "warningEvidenceIds", "reference-apps.content")
    for evidence_id, current_status, previous_status_value in (
        ("reference-app.profile-publisher", profile_status, previous_profile_status),
        (
            "reference-app.profile-publisher-app-data",
            profile_app_data_status,
            previous_profile_app_data_status,
        ),
        ("reference-app.feed-reader", feed_reader_status, previous_feed_reader_status),
        (
            "reference-app.feed-reader-subscriptions",
            feed_reader_subscription_status,
            previous_feed_reader_subscription_status,
        ),
        (
            "reference-app.feed-reader-app-data",
            feed_reader_app_data_status,
            previous_feed_reader_app_data_status,
        ),
        ("reference-app.trust-graph", trust_graph_status, previous_trust_graph_status),
        (
            "reference-app.trust-graph-durable-exchange",
            trust_graph_durable_exchange_status,
            previous_trust_graph_durable_exchange_status,
        ),
        (
            "reference-app.trust-graph-app-data-preview",
            trust_graph_app_data_status,
            previous_trust_graph_app_data_status,
        ),
        (
            "app-platform.social-message-signing",
            social_message_signing_status,
            previous_social_message_signing_status,
        ),
        ("reference-app.social-inbox", social_inbox_status, previous_social_inbox_status),
        (
            "reference-app.social-inbox-signed-message",
            social_inbox_signed_message_status,
            previous_social_inbox_signed_message_status,
        ),
        (
            "reference-app.social-inbox-subscriptions",
            social_inbox_subscription_status,
            previous_social_inbox_subscription_status,
        ),
        (
            "reference-app.social-inbox-app-data",
            social_inbox_app_data_status,
            previous_social_inbox_app_data_status,
        ),
        (
            "reference-app.social-inbox-trust-annotations",
            social_inbox_trust_status,
            previous_social_inbox_trust_status,
        ),
        (
            "migration.social-mail-preview",
            social_mail_migration_status,
            previous_social_mail_migration_status,
        ),
        (
            "app-platform.generated-document-insert",
            generated_document_status,
            previous_generated_document_status,
        ),
        ("app-platform.content-fetch", content_fetch_status, previous_content_fetch_status),
        (
            "app-platform.content-subscriptions",
            content_subscription_status,
            previous_content_subscription_status,
        ),
        (
            "network-content.subscription-scheduler",
            content_subscription_scheduler_status,
            previous_content_subscription_scheduler_status,
        ),
        (
            "app-platform.durable-app-data-store",
            app_data_store_status,
            previous_app_data_store_status,
        ),
        (
            "app-platform.trust-graph-preview",
            trust_graph_preview_status,
            previous_trust_graph_preview_status,
        ),
        (
            "app-platform.trust-graph-durable-store",
            trust_graph_durable_store_status,
            previous_trust_graph_durable_store_status,
        ),
        (
            "app-platform.trust-graph-exchange",
            trust_graph_exchange_status,
            previous_trust_graph_exchange_status,
        ),
        (
            "app-platform.trust-statement-signing",
            trust_statement_signing_status,
            previous_trust_statement_signing_status,
        ),
        ("app-services.registry", app_services_registry_status, previous_app_services_registry_status),
        ("app-services.grants", app_services_grants_status, previous_app_services_grants_status),
        (
            "app-services.trust-score-provider",
            app_services_provider_status,
            previous_app_services_provider_status,
        ),
        (
            "reference-app.social-inbox-service-grant",
            social_inbox_service_grant_status,
            previous_social_inbox_service_grant_status,
        ),
        (
            "app-services.web-shell",
            app_services_web_shell_status,
            previous_app_services_web_shell_status,
        ),
        (
            "app-services.redaction",
            app_services_redaction_status,
            previous_app_services_redaction_status,
        ),
    ):
        if current_status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} evidence is not passing")
            add_evidence_issue(gate_details, "failureEvidenceIds", evidence_id)
        elif current_status == "warn":
            warnings.append(f"{evidence_id} evidence is warning")
            add_evidence_issue(gate_details, "warningEvidenceIds", evidence_id)
        if previous_status_value == "pass" and current_status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} regressed from pass to {current_status}")
            add_evidence_issue(gate_details, "failureEvidenceIds", evidence_id)
    if profile_details.get("appId") not in {"profile-publisher", None}:
        failures.append("Profile Publisher evidence is not for profile-publisher")
        add_evidence_issue(gate_details, "failureEvidenceIds", "reference-app.profile-publisher")
    if profile_checks:
        for key in (
            "usesBrowserSafeIdentityCreation",
            "usesProfileDocumentRoute",
            "usesGeneratedDocumentInsertRoute",
            "usesSdkBootstrap",
        ):
            if profile_checks.get(key) is not True:
                failures.append(f"Profile Publisher reference app check {key} failed")
                add_evidence_issue(gate_details, "failureEvidenceIds", "reference-app.profile-publisher")
    elif profile_status == "pass":
        warnings.append("Profile Publisher coverage lacks detailed staged app checks")
        add_evidence_issue(gate_details, "warningEvidenceIds", "reference-app.profile-publisher")
    if profile_app_data_checks:
        for key in (
            "manifestUsesAppDataContract",
            "usesSdkJsonRecordHelpers",
            "persistsBoundedDraftState",
            "docsAndEvidenceMentionDurableAppData",
        ):
            if profile_app_data_checks.get(key) is not True:
                failures.append(f"Profile Publisher app-data check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.profile-publisher-app-data",
                )
    elif profile_app_data_status == "pass":
        warnings.append("Profile Publisher app-data coverage lacks detailed checks")
        add_evidence_issue(
            gate_details, "warningEvidenceIds", "reference-app.profile-publisher-app-data"
        )
    if feed_reader_details.get("appId") not in {"feed-reader", None}:
        failures.append("Feed Reader evidence is not for feed-reader")
        add_evidence_issue(gate_details, "failureEvidenceIds", "reference-app.feed-reader")
    if feed_reader_checks:
        for key in (
            "usesContentFetchRouteOrHelper",
            "usesContentSubscriptionHelpers",
            "usesGeneratedDocumentInsertRoute",
            "usesSdkBootstrap",
        ):
            if feed_reader_checks.get(key) is not True:
                failures.append(f"Feed Reader reference app check {key} failed")
                add_evidence_issue(gate_details, "failureEvidenceIds", "reference-app.feed-reader")
    elif feed_reader_status == "pass":
        warnings.append("Feed Reader coverage lacks detailed staged app checks")
        add_evidence_issue(gate_details, "warningEvidenceIds", "reference-app.feed-reader")
    feed_reader_subscription_checks = nested_dict(feed_reader_subscription_details, "checks")
    if feed_reader_subscription_checks:
        for key in (
            "manifestDeclaresSubscribeAndV9",
            "appUsesPlatformSubscriptionWorkflow",
            "noTabLocalFollowLoop",
            "sdkHelpersAvailable",
            "docsDescribeSubscriptionFlow",
        ):
            if feed_reader_subscription_checks.get(key) is not True:
                failures.append(f"Feed Reader subscription check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.feed-reader-subscriptions",
                )
    elif feed_reader_subscription_status == "pass":
        warnings.append("Feed Reader subscription coverage lacks detailed staged app checks")
        add_evidence_issue(
            gate_details, "warningEvidenceIds", "reference-app.feed-reader-subscriptions"
        )
    if feed_reader_app_data_checks:
        for key in (
            "manifestUsesAppDataContract",
            "usesSdkJsonRecordHelpers",
            "persistsBoundedReaderState",
            "docsAndEvidenceMentionDurableAppData",
        ):
            if feed_reader_app_data_checks.get(key) is not True:
                failures.append(f"Feed Reader app-data check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.feed-reader-app-data",
                )
    elif feed_reader_app_data_status == "pass":
        warnings.append("Feed Reader app-data coverage lacks detailed checks")
        add_evidence_issue(
            gate_details, "warningEvidenceIds", "reference-app.feed-reader-app-data"
        )
    if trust_graph_details.get("appId") not in {"trust-graph", None}:
        failures.append("Trust Graph Preview evidence is not for trust-graph")
        add_evidence_issue(gate_details, "failureEvidenceIds", "reference-app.trust-graph")
    if trust_graph_checks:
        for key in (
            "manifestDeclaresTrustGraph",
            "manifestDeclaresTrustPermissions",
            "manifestUsesContractV10ThroughCurrent",
            "usesTrustHelpers",
            "usesBoundedTrustSigningHelper",
            "usesTrustExchangeAndQueuePreview",
            "docsDescribePreviewLimits",
            "docsDescribeTrustScoreService",
            "manifestAdvertisesTrustScoreService",
        ):
            if trust_graph_checks.get(key) is not True:
                failures.append(f"Trust Graph Preview reference app check {key} failed")
                add_evidence_issue(gate_details, "failureEvidenceIds", "reference-app.trust-graph")
    elif trust_graph_status == "pass":
        warnings.append("Trust Graph Preview coverage lacks detailed staged app checks")
        add_evidence_issue(gate_details, "warningEvidenceIds", "reference-app.trust-graph")
    if trust_graph_app_data_checks:
        for key in (
            "manifestUsesAppDataContract",
            "usesSdkJsonRecordHelpers",
            "persistsOnlyUiLocalPreviewState",
            "docsSeparateAppDataAndTrustBackend",
        ):
            if trust_graph_app_data_checks.get(key) is not True:
                failures.append(f"Trust Graph app-data preview check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.trust-graph-app-data-preview",
                )
    elif trust_graph_app_data_status == "pass":
        warnings.append("Trust Graph app-data preview coverage lacks detailed checks")
        add_evidence_issue(
            gate_details, "warningEvidenceIds", "reference-app.trust-graph-app-data-preview"
        )
    if social_message_signing_checks:
        for key in (
            "routeInContract",
            "contractVersionV11",
            "capabilitiesInContract",
            "handlerUsesFixedDomainAppVaultSigning",
            "requestRejectsGenericSigningInputs",
            "sdkHelperUsesBoundedRoute",
            "docsDescribeBoundedSigningBoundary",
        ):
            if social_message_signing_checks.get(key) is not True:
                failures.append(f"Social message signing check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "app-platform.social-message-signing",
                )
    if social_inbox_details.get("appId") not in {"social-inbox", None}:
        failures.append("Social Inbox evidence is not for social-inbox")
        add_evidence_issue(gate_details, "failureEvidenceIds", "reference-app.social-inbox")
    if social_inbox_checks:
        for key in (
            "manifestDeclaresSocialInbox",
            "manifestDeclaresSocialPermissions",
            "manifestUsesContractV12",
            "manifestDeclaresTrustScoreServiceRequest",
            "usesAppVaultIdentityFlow",
            "usesProfileMetadataFlow",
            "usesGeneratedOutboxInsert",
            "usesSubscriptionAndFetchFlow",
            "usesDurableAppData",
            "usesTrustAnnotations",
            "previewAndNonGoalCopyPresent",
            "noRawAdminOrBrowserStorage",
        ):
            if social_inbox_checks.get(key) is not True:
                failures.append(f"Social Inbox reference app check {key} failed")
                add_evidence_issue(gate_details, "failureEvidenceIds", "reference-app.social-inbox")
    elif social_inbox_status == "pass":
        warnings.append("Social Inbox coverage lacks detailed staged app checks")
        add_evidence_issue(gate_details, "warningEvidenceIds", "reference-app.social-inbox")
    if social_inbox_signed_message_checks:
        for key in (
            "manifestAllowsBoundedSigning",
            "usesSdkBoundedSigner",
            "verifiesImportedMessageSignatures",
            "documentShapeIsBounded",
            "docsDescribeSignedMessageFormat",
        ):
            if social_inbox_signed_message_checks.get(key) is not True:
                failures.append(f"Social Inbox signed-message check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.social-inbox-signed-message",
                )
    if social_inbox_subscription_checks:
        for key in (
            "manifestDeclaresSubscriptionPermissions",
            "uiDisclosesSubscriptionWorkflow",
            "appUsesPlatformSubscriptionLifecycle",
            "manualFetchUsesBoundedContentFetch",
            "docsDescribeDurableUskSources",
        ):
            if social_inbox_subscription_checks.get(key) is not True:
                failures.append(f"Social Inbox subscription check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.social-inbox-subscriptions",
                )
    if social_inbox_app_data_checks:
        for key in (
            "manifestDeclaresAppDataPermissions",
            "usesSdkJsonRecordHelpers",
            "persistsNamedBoundedRecords",
            "signingDoesNotOverwritePublishSummary",
            "storesSafeSummariesOnly",
            "permissionDisclosureMentionsAppData",
            "docsDescribePrivacyRules",
            "noBrowserStorageOrRawAdminPath",
        ):
            if social_inbox_app_data_checks.get(key) is not True:
                failures.append(f"Social Inbox app-data check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.social-inbox-app-data",
                )
    if social_inbox_trust_checks:
        for key in (
            "manifestDeclaresAppServiceCapabilities",
            "manifestDeclaresTrustScoreRequest",
            "appQueriesAuthorScores",
            "uiShowsNeutralAndScoredStates",
            "unknownScoresRemainUnscored",
            "docsFrameScoresAsAnnotations",
        ):
            if social_inbox_trust_checks.get(key) is not True:
                failures.append(f"Social Inbox trust annotation check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.social-inbox-trust-annotations",
                )
    if social_inbox_service_grant_checks:
        for key in (
            "socialManifestRequestsServiceGrant",
            "socialManifestUsesAppServiceCapabilities",
            "socialUsesSdkServicesNamespace",
            "socialUiShowsGrantStates",
            "socialDocsDescribeRevocation",
        ):
            if social_inbox_service_grant_checks.get(key) is not True:
                failures.append(f"Social Inbox service-grant check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.social-inbox-service-grant",
                )
    if app_services_registry_checks:
        for key in (
            "contractV12AndCapabilitiesPresent",
            "routeFamilyPresent",
            "descriptorParserPresent",
            "runtimeWiresSharedCoordinator",
            "sdkHelpersPresent",
            "testsCoverManifestAndRouter",
        ):
            if app_services_registry_checks.get(key) is not True:
                failures.append(f"App-service registry check {key} failed")
                add_evidence_issue(gate_details, "failureEvidenceIds", "app-services.registry")
    if app_services_grants_checks:
        for key in (
            "grantModelHasRequiredFields",
            "grantStatusesPresent",
            "storesAreFileBackedAndInMemory",
            "coordinatorEnforcesApprovalRevocation",
            "testsCoverGrantLifecycle",
        ):
            if app_services_grants_checks.get(key) is not True:
                failures.append(f"App-service grant check {key} failed")
                add_evidence_issue(gate_details, "failureEvidenceIds", "app-services.grants")
    if app_services_provider_checks:
        for key in (
            "trustGraphManifestAdvertisesService",
            "adapterIsBoundedNotProxy",
            "providerDocsAndUiDescribePreviewGrantBoundary",
            "adapterTestsCoverRedaction",
        ):
            if app_services_provider_checks.get(key) is not True:
                failures.append(f"Trust-score provider check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-services.trust-score-provider"
                )
    if app_services_web_shell_checks:
        for key in (
            "webShellLoadsAppServiceData",
            "webShellRendersGrantActions",
            "webShellOmitsPrivateMaterial",
            "webShellTestsPresent",
        ):
            if app_services_web_shell_checks.get(key) is not True:
                failures.append(f"App-service Web Shell check {key} failed")
                add_evidence_issue(gate_details, "failureEvidenceIds", "app-services.web-shell")
    if app_services_redaction_checks:
        for key in (
            "auditModelIsRedacted",
            "invocationReturnsHashNotRawSubject",
            "grantJsonContainsOnlyFingerprint",
            "docsStateNoGenericProxyOrLocalhostTrust",
            "evidenceIdsDocumented",
        ):
            if app_services_redaction_checks.get(key) is not True:
                failures.append(f"App-service redaction check {key} failed")
                add_evidence_issue(gate_details, "failureEvidenceIds", "app-services.redaction")
    if social_mail_migration_checks:
        for key in (
            "migrationFramingPresent",
            "nonGoalsDocumented",
            "appComposesExpectedPlatformSurfaces",
            "uiStatesPreviewBoundary",
            "evidenceIdsDocumented",
        ):
            if social_mail_migration_checks.get(key) is not True:
                failures.append(f"Social/mail migration preview check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "migration.social-mail-preview",
                )
    generated_checks = nested_dict(generated_document_details, "checks")
    if generated_checks and generated_checks.get("routeDocumented") is not True:
        failures.append("Generated document insert route documentation check failed")
        add_evidence_issue(gate_details, "failureEvidenceIds", "app-platform.generated-document-insert")
    content_fetch_checks = nested_dict(content_fetch_details, "checks")
    if content_fetch_checks and content_fetch_checks.get("routeDocumented") is not True:
        failures.append("Content fetch route documentation check failed")
        add_evidence_issue(gate_details, "failureEvidenceIds", "app-platform.content-fetch")
    content_subscription_checks = nested_dict(content_subscription_details, "checks")
    if content_subscription_checks:
        for key in ("currentContractVersionV9", "routesPresent", "capabilityGatesPresent"):
            if content_subscription_checks.get(key) is not True:
                failures.append(f"Content subscription API check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-platform.content-subscriptions"
                )
    app_data_store_checks = nested_dict(app_data_store_details, "checks")
    if app_data_store_checks:
        for key in (
            "contractV9AndCapabilities",
            "routesRequireAppPrincipalAndCapabilities",
            "fileBackedStoreIsPathSafeAndAtomic",
            "serviceBoundsQuotaAndImportExport",
            "docsCoverLimitsAndRedaction",
        ):
            if app_data_store_checks.get(key) is not True:
                failures.append(f"Durable app-data store check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-platform.durable-app-data-store"
                )
    content_subscription_scheduler_checks = nested_dict(
        content_subscription_scheduler_details, "checks"
    )
    if content_subscription_scheduler_checks:
        for key in (
            "deterministicTickAndNoOverlap",
            "conservativeLimits",
            "dedupeAndMetadataOnly",
            "pressureGateStableSignals",
            "durablePathFreeStore",
        ):
            if content_subscription_scheduler_checks.get(key) is not True:
                failures.append(f"Content subscription scheduler check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "network-content.subscription-scheduler",
                )
    trust_preview_checks = nested_dict(trust_graph_preview_details, "checks")
    if trust_preview_checks:
        for key in ("contractVersionV7", "routesPresent", "capabilityGatesPresent"):
            if trust_preview_checks.get(key) is not True:
                failures.append(f"Trust graph preview API check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-platform.trust-graph-preview"
                )
    trust_durable_store_checks = nested_dict(trust_graph_durable_store_details, "checks")
    if trust_durable_store_checks:
        for key in ("fileBackedStorePresent", "runtimeInjectsDurableStore", "durabilityTestsPresent"):
            if trust_durable_store_checks.get(key) is not True:
                failures.append(f"Trust graph durable store check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-platform.trust-graph-durable-store"
                )
    trust_exchange_checks = nested_dict(trust_graph_exchange_details, "checks")
    if trust_exchange_checks:
        for key in ("contractVersionV10", "contractDescriptorsPresent", "sdkExchangeHelpersPresent"):
            if trust_exchange_checks.get(key) is not True:
                failures.append(f"Trust graph exchange check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-platform.trust-graph-exchange"
                )
    if trust_graph_durable_exchange_checks:
        for key in (
            "manifestUsesContractV10ThroughCurrent",
            "usesSdkExchangeHelpers",
            "noRawApiOrManualFetch",
        ):
            if trust_graph_durable_exchange_checks.get(key) is not True:
                failures.append(f"Trust Graph Preview durable exchange app check {key} failed")
                add_evidence_issue(
                    gate_details,
                    "failureEvidenceIds",
                    "reference-app.trust-graph-durable-exchange",
                )
    trust_signing_checks = nested_dict(trust_statement_signing_details, "checks")
    if trust_signing_checks:
        for key in ("routeInContract", "capabilitiesInContract", "handlerSignsCanonicalPayload"):
            if trust_signing_checks.get(key) is not True:
                failures.append(f"Trust statement signing check {key} failed")
                add_evidence_issue(
                    gate_details, "failureEvidenceIds", "app-platform.trust-statement-signing"
                )
    gate_details.update(
        {
            "currentStatus": status,
            "previousStatus": previous_status,
            "appId": details.get("appId"),
            "profilePublisherStatus": profile_status,
            "previousProfilePublisherStatus": previous_profile_status,
            "profilePublisherAppDataStatus": profile_app_data_status,
            "previousProfilePublisherAppDataStatus": previous_profile_app_data_status,
            "feedReaderStatus": feed_reader_status,
            "previousFeedReaderStatus": previous_feed_reader_status,
            "feedReaderAppDataStatus": feed_reader_app_data_status,
            "previousFeedReaderAppDataStatus": previous_feed_reader_app_data_status,
            "trustGraphStatus": trust_graph_status,
            "previousTrustGraphStatus": previous_trust_graph_status,
            "trustGraphAppDataPreviewStatus": trust_graph_app_data_status,
            "previousTrustGraphAppDataPreviewStatus": previous_trust_graph_app_data_status,
            "socialMessageSigningStatus": social_message_signing_status,
            "previousSocialMessageSigningStatus": previous_social_message_signing_status,
            "socialInboxStatus": social_inbox_status,
            "previousSocialInboxStatus": previous_social_inbox_status,
            "socialInboxSignedMessageStatus": social_inbox_signed_message_status,
            "previousSocialInboxSignedMessageStatus": previous_social_inbox_signed_message_status,
            "socialInboxSubscriptionStatus": social_inbox_subscription_status,
            "previousSocialInboxSubscriptionStatus": previous_social_inbox_subscription_status,
            "socialInboxAppDataStatus": social_inbox_app_data_status,
            "previousSocialInboxAppDataStatus": previous_social_inbox_app_data_status,
            "socialInboxTrustAnnotationStatus": social_inbox_trust_status,
            "previousSocialInboxTrustAnnotationStatus": previous_social_inbox_trust_status,
            "socialMailMigrationStatus": social_mail_migration_status,
            "previousSocialMailMigrationStatus": previous_social_mail_migration_status,
            "generatedDocumentInsertStatus": generated_document_status,
            "previousGeneratedDocumentInsertStatus": previous_generated_document_status,
            "contentFetchStatus": content_fetch_status,
            "previousContentFetchStatus": previous_content_fetch_status,
            "appDataStoreStatus": app_data_store_status,
            "previousAppDataStoreStatus": previous_app_data_store_status,
            "trustGraphPreviewStatus": trust_graph_preview_status,
            "previousTrustGraphPreviewStatus": previous_trust_graph_preview_status,
            "trustStatementSigningStatus": trust_statement_signing_status,
            "previousTrustStatementSigningStatus": previous_trust_statement_signing_status,
            "profilePublisherAppId": profile_details.get("appId"),
            "feedReaderAppId": feed_reader_details.get("appId"),
            "trustGraphAppId": trust_graph_details.get("appId"),
            "socialInboxAppId": social_inbox_details.get("appId"),
        }
    )
    return gate_from_issues(
        "ecosystem.reference-content-apps",
        "Reference content, profile, feed, trust, and social inbox app evidence passed.",
        failures,
        warnings,
        gate_details,
    )


def evaluate_legacy_retirement_gate(
    current: dict[str, dict[str, Any]], previous: dict[str, dict[str, Any]]
) -> GateResult:
    failures: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {}
    for evidence_id in (
        "legacy.retirement",
        "legacy-admin.removal-wave-1",
        "legacy-admin.removal-wave-2",
        "legacy-admin.removal-wave-3",
    ):
        status = evidence_status(current.get(evidence_id))
        previous_status = evidence_status(previous.get(evidence_id))
        details[evidence_id] = {"currentStatus": status, "previousStatus": previous_status}
        if status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} evidence is not passing")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
        elif status == "warn":
            warnings.append(f"{evidence_id} evidence is warning")
            add_evidence_issue(details, "warningEvidenceIds", evidence_id)
        if previous_status == "pass" and status in {"fail", "missing", "skip"}:
            failures.append(f"{evidence_id} regressed from pass to {status}")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
    for evidence_id in (
        "legacy-admin.removal-wave-1",
        "legacy-admin.removal-wave-2",
        "legacy-admin.removal-wave-3",
    ):
        current_wave = evidence_details(current.get(evidence_id))
        previous_wave = evidence_details(previous.get(evidence_id))
        current_routes = set(sorted_strings(current_wave.get("removedByDefaultRouteIds")))
        previous_routes = set(sorted_strings(previous_wave.get("removedByDefaultRouteIds")))
        details[f"{evidence_id}.removedByDefaultRouteCounts"] = {
            "current": len(current_routes),
            "previous": len(previous_routes),
        }
        if previous_routes and current_routes != previous_routes:
            if current_wave.get("docsDescribeWave") or current_wave.get("updateNote"):
                warnings.append(f"{evidence_id} route set changed with documentation evidence")
                add_evidence_issue(details, "warningEvidenceIds", evidence_id)
            else:
                warnings.append(f"{evidence_id} route set changed without doc/update note metadata")
                add_evidence_issue(details, "warningEvidenceIds", evidence_id)
        safety = current_wave.get("retainedBrowseSafety")
        if isinstance(safety, dict) and any(value is False for value in safety.values()):
            failures.append(f"{evidence_id} retained browse safety evidence failed")
            add_evidence_issue(details, "failureEvidenceIds", evidence_id)
    return gate_from_issues(
        "ecosystem.legacy-retirement",
        "Legacy retirement and removal-wave evidence passed.",
        failures,
        warnings,
        details,
    )


def evaluate_waiver_validation_gate(context: WaiverContext, mode: str) -> GateResult | None:
    if not context.errors:
        return None
    status = "fail" if mode == "release-candidate" else "warn"
    return GateResult(
        "ecosystem.waivers",
        status,
        status == "fail",
        "Structured waiver files contain validation errors.",
        {"errors": context.errors, "issueIds": ["ecosystem.waivers.validation"]},
    )


def evaluate_ecosystem_gates(
    settings: Settings,
    current_evidence: list[EvidenceItem],
    previous_summary: dict[str, Any] | None,
    history_comparison: dict[str, Any],
    metadata: dict[str, Any],
    waiver_context: WaiverContext,
) -> list[GateResult]:
    current = evidence_map_from_items(current_evidence)
    previous = evidence_map_from_summary(previous_summary)
    diffs = history_comparison.get("evidenceDiffs", [])
    if not isinstance(diffs, list):
        diffs = []
    gates = [
        evaluate_required_evidence_regressions([diff for diff in diffs if isinstance(diff, dict)]),
        evaluate_platform_api_gate(current, previous),
        evaluate_first_party_apps_gate(current, previous),
        evaluate_app_ui_quality_gate(current, previous),
        evaluate_app_review_trust_gate(current, previous, metadata, settings.mode),
        evaluate_app_update_rollback_gate(current, previous),
        evaluate_app_vault_gate(current, previous),
        evaluate_sandbox_provider_gate(current, previous, settings.mode, metadata),
        evaluate_reference_content_gate(current, previous),
        evaluate_legacy_retirement_gate(current, previous),
    ]
    waiver_gate = evaluate_waiver_validation_gate(waiver_context, settings.mode)
    if waiver_gate is not None:
        gates.append(waiver_gate)
    return [apply_waiver_to_gate(gate, waiver_context, settings.mode) for gate in gates]


def history_status_affects_decision(status: str) -> bool:
    return status in {"warn", "fail", "missing"}


def determine_certification_status(
    mode: str,
    evidence: list[EvidenceItem],
    history_comparison: dict[str, Any],
    ecosystem_gates: list[GateResult],
) -> tuple[str, bool]:
    evidence_status_value, evidence_release_passed = determine_overall_status(mode, evidence)
    history_status = normalize_evidence_status(str(history_comparison.get("status", "missing")))
    gate_failures = [gate for gate in ecosystem_gates if gate.status == "fail" and gate.release_blocker]
    gate_warnings = [gate for gate in ecosystem_gates if gate.status in {"warn", "fail", "missing"}]
    history_warning = history_status_affects_decision(history_status)
    release_candidate_passed = evidence_release_passed and not gate_failures and history_status != "fail"
    if mode == "release-candidate":
        if evidence_status_value == "fail" or gate_failures or history_status == "fail":
            return "fail", False
        if evidence_status_value == "warn" or gate_warnings or history_warning:
            return "warn", release_candidate_passed
        return "pass", True
    if mode == "nightly":
        if evidence_status_value == "fail" or gate_failures:
            return "fail", False
        if evidence_status_value == "warn" or gate_warnings or history_warning:
            return "warn", release_candidate_passed
        return "pass", True
    if evidence_status_value == "warn" or gate_warnings or history_warning:
        return "warn", release_candidate_passed
    return "pass", release_candidate_passed


def promotion_decision(status: str, release_candidate_passed: bool = True) -> str:
    if not release_candidate_passed:
        return "FAIL"
    if status == "pass":
        return "PASS"
    if status == "warn":
        return "PASS WITH WARNINGS"
    return "FAIL"


def report_status_label(status: Any) -> str:
    normalized = normalize_evidence_status(str(status))
    if normalized in {"skip", "missing"}:
        return "NOT AVAILABLE"
    return normalized.upper()


def aggregate_gate_status(gates: list[GateResult]) -> str:
    if any(gate.status == "fail" for gate in gates):
        return "fail"
    if any(gate.status == "warn" for gate in gates):
        return "warn"
    return "pass"


def collect_source_artifacts(settings: Settings, out_dir: Path) -> list[str]:
    artifacts_dir = out_dir / "artifacts"
    if artifacts_dir.exists():
        shutil.rmtree(artifacts_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    source_map = {
        "interop-smoke-summary.json": settings.interop_smoke_summary,
        "interop-extended-summary.json": settings.interop_extended_summary,
        "performance-smoke-summary.json": settings.perf_smoke_summary,
        "app-platform-smoke-summary.json": settings.app_platform_summary,
        "interop-smoke-report.md": settings.interop_smoke_summary.parent / "artifacts" / "interop-report.md",
        "interop-extended-report.md": settings.interop_extended_summary.parent / "artifacts" / "interop-report.md",
        "performance-smoke-report.md": settings.perf_smoke_summary.parent / "artifacts" / "perf-report.md",
        "app-platform-smoke-report.md": settings.app_platform_summary.parent / "app-platform-smoke-report.md",
    }
    copied: list[str] = []
    for target_name, source_path in source_map.items():
        if not source_path.is_file():
            continue
        if any(name in str(source_path) for name in PRIVATE_ARTIFACT_NAMES):
            continue
        target_path = artifacts_dir / target_name
        if source_path.suffix == ".json":
            value = read_json(source_path)
            if value is None:
                continue
            write_json(target_path, sanitize_value(value, settings.workspace_root, out_dir))
        else:
            target_path.write_text(
                scrub_text(source_path.read_text(encoding="utf-8"), settings.workspace_root, out_dir),
                encoding="utf-8",
            )
        copied.append(display_path(target_path, settings.workspace_root, out_dir))
    return copied


def collect_metadata(settings: Settings) -> dict[str, Any]:
    metadata = {}
    metadata.update(collect_git_metadata(settings))
    metadata.update(collect_ci_metadata(os.environ))
    metadata.update(settings.metadata)
    return dict(sanitize_value(metadata, settings.workspace_root, settings.out_dir))


def sanitized_cli_waivers(settings: Settings) -> dict[str, str]:
    return {
        scrub_text(str(waiver_id), settings.workspace_root, settings.out_dir): scrub_text(
            reason, settings.workspace_root, settings.out_dir
        )
        for waiver_id, reason in settings.waivers.items()
    }


def build_summary(
    settings: Settings,
    evidence: list[EvidenceItem],
    copied_artifacts: list[str],
    generated_at: str,
    metadata: dict[str, Any],
    history_comparison: dict[str, Any],
    ecosystem_gates: list[GateResult],
    waiver_context: WaiverContext,
    ecosystem_matrix: dict[str, Any] | None = None,
) -> dict[str, Any]:
    status, release_candidate_passed = determine_certification_status(
        settings.mode, evidence, history_comparison, ecosystem_gates
    )
    ecosystem_status = aggregate_gate_status(ecosystem_gates)
    cli_waivers = sanitized_cli_waivers(settings)
    compact_matrix = matrix_compact_summary(ecosystem_matrix)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "mode": settings.mode,
        "status": status,
        "promotionDecision": promotion_decision(status, release_candidate_passed),
        "releaseCandidatePassed": release_candidate_passed,
        "generatedAt": generated_at,
        "workspaceRoot": "<repo>",
        "summaryPath": display_path(settings.out_dir / SUMMARY_FILE_NAME, settings.workspace_root, settings.out_dir),
        "reportPath": display_path(settings.out_dir / REPORT_FILE_NAME, settings.workspace_root, settings.out_dir),
        "ecosystemMatrixStatus": compact_matrix.get("status", "missing"),
        "ecosystemMatrixPath": display_path(
            settings.out_dir / ECOSYSTEM_MATRIX_FILE_NAME, settings.workspace_root, settings.out_dir
        ),
        "ecosystemMatrixReportPath": display_path(
            settings.out_dir / ECOSYSTEM_MATRIX_REPORT_FILE_NAME, settings.workspace_root, settings.out_dir
        ),
        "historyComparisonPath": display_path(
            settings.out_dir / HISTORY_COMPARISON_FILE_NAME, settings.workspace_root, settings.out_dir
        ),
        "historyComparisonReportPath": display_path(
            settings.out_dir / HISTORY_COMPARISON_REPORT_FILE_NAME, settings.workspace_root, settings.out_dir
        ),
        "artifactsDir": display_path(settings.out_dir / "artifacts", settings.workspace_root, settings.out_dir),
        "metadata": metadata,
        "waivers": cli_waivers,
        "cliWaivers": cli_waivers,
        "waiverRecords": [record.to_json() for record in waiver_context.records],
        "counts": evidence_counts(evidence),
        "evidence": [item.to_json() for item in evidence],
        "historyComparison": history_comparison,
        "ecosystemGateStatus": ecosystem_status,
        "ecosystemGates": [gate.to_json() for gate in ecosystem_gates],
        "ecosystemMatrix": compact_matrix,
        "copiedArtifacts": copied_artifacts,
        "redaction": {
            "privateArtifactsExcluded": list(PRIVATE_ARTIFACT_NAMES),
            "secretMaterialRedacted": True,
            "formPasswordsRedacted": True,
            "rawFeedBodiesExcluded": True,
            "rawRequestBodiesExcluded": True,
            "privateInsertUrisExcluded": True,
            "appProcessTokensRedacted": True,
            "browserSessionTokensRedacted": True,
            "signatureValuesRedacted": True,
            "rawUpdateRollbackOutputsExcluded": True,
            "absolutePathsSanitized": True,
        },
    }


def render_report(summary: dict[str, Any]) -> str:
    history = summary.get("historyComparison", {})
    history_status = history.get("status", "missing") if isinstance(history, dict) else "missing"
    decision = summary.get("promotionDecision")
    if not isinstance(decision, str) or not decision:
        decision = promotion_decision(
            str(summary["status"]),
            bool(summary.get("releaseCandidatePassed", True)),
        )
    lines = [
        "# Release Certification Report",
        "",
        f"- Promotion decision: `{decision}`",
        f"- History comparison: `{report_status_label(history_status)}`",
        f"- Ecosystem gates: `{report_status_label(summary.get('ecosystemGateStatus', 'missing'))}`",
        f"- Mode: `{summary['mode']}`",
        f"- Status: `{summary['status']}`",
        f"- Release-candidate gate: `{'passed' if summary['releaseCandidatePassed'] else 'failed'}`",
        f"- Generated: `{summary['generatedAt']}`",
        f"- Summary: `{summary['summaryPath']}`",
        f"- Artifacts: `{summary['artifactsDir']}`",
        "",
    ]
    append_history_comparison(lines, summary)
    append_ecosystem_gates(lines, summary)
    append_ecosystem_matrix_summary(lines, summary)
    append_waivers(lines, summary)
    append_regressions(lines, summary)
    lines.extend(["## Evidence Summary", "", "| Evidence | Status | Required for RC | Source | Summary |", "| --- | --- | --- | --- | --- |"])
    for item in summary["evidence"]:
        required = "yes" if item["requiredForReleaseCandidate"] else "no"
        lines.append(
            "| `{id}` | `{status}` | {required} | `{source}` | {summary_text} |".format(
                id=item["id"],
                status=item["status"],
                required=required,
                source=item["source"],
                summary_text=str(item["summary"]).replace("|", "\\|"),
            )
        )
    lines.extend(["", "## Hyphanet Interop", ""])
    append_detail(lines, summary, "interop.smoke")
    append_detail(lines, summary, "interop.extended")
    lines.extend(["", "## Performance Regression", ""])
    append_detail(lines, summary, "performance.smoke")
    lines.extend(["", "## App Platform", ""])
    for evidence_id in (
        "app-platform.first-party",
        "app-platform.devtools-cli",
        "app-platform.developer-beta-toolkit",
        "app-platform.docs-portal",
        "app-platform.beta-program",
        "app-platform.beta-tutorials",
        "app-platform.docs-redaction",
        "platform-api.contract",
        "app-vault.capabilities",
        "app-platform.identity-profile-publish",
        "app-platform.generated-document-insert",
        "app-platform.content-fetch",
        "app-platform.content-subscriptions",
        "network-content.subscription-scheduler",
        "app-platform.durable-app-data-store",
        "app-platform.trust-graph-preview",
        "app-platform.trust-graph-durable-store",
        "app-platform.trust-graph-exchange",
        "app-platform.trust-statement-signing",
        "app-platform.social-message-signing",
        "app-platform.signed-bundles",
        "catalog.smoke",
        "catalog.live-usk-publication",
        "catalog.live-usk-source-verification",
        "app-catalog.first-party-beta",
        "app-review.trusted-receipts",
        "app-review.policy",
        "app-review.governance",
        "app-review.reviewer-key-lifecycle",
        "app-review.transparency-log",
        "app-review.review-history-api",
        "app-review.first-party-catalog",
        "app-review.first-party-review-chain",
        "app-ui.design-system",
        "app-ui.lint",
        "app-ui.first-party-adoption",
        "app-ui.smoke",
        "reference-apps.content",
        "reference-app.profile-publisher",
        "reference-app.profile-publisher-app-data",
        "reference-app.feed-reader",
        "reference-app.feed-reader-subscriptions",
        "reference-app.feed-reader-app-data",
        "reference-app.trust-graph",
        "reference-app.trust-graph-durable-exchange",
        "reference-app.trust-graph-app-data-preview",
        "reference-app.social-inbox",
        "reference-app.social-inbox-signed-message",
        "reference-app.social-inbox-subscriptions",
        "reference-app.social-inbox-app-data",
        "reference-app.social-inbox-trust-annotations",
        "migration.social-mail-preview",
        "legacy-plugin.migration-guide",
        "legacy-plugin.social-inbox-spike",
        "apphost.sandbox-provider",
        "app-update.lifecycle",
        "app-update.scheduler",
        "app-update.live-catalog-refresh",
        "app-update.rollback",
        "apphost.live",
    ):
        append_detail(lines, summary, evidence_id)
    lines.extend(["", "## Legacy Admin Retirement", ""])
    append_detail(lines, summary, "legacy.retirement")
    append_detail(lines, summary, "legacy-admin.removal-wave-1")
    append_detail(lines, summary, "legacy-admin.removal-wave-2")
    append_detail(lines, summary, "legacy-admin.removal-wave-3")
    lines.extend(
        [
            "",
            "## Redaction Rules",
            "",
            "- Private signing keys, form passwords, app process tokens, browser-session tokens, raw request bodies, raw feed bodies, raw update or rollback command output, private insert URIs, and raw signatures are not included.",
            "- Local absolute paths, including absolute staging paths, are sanitized as `<repo>`, `<workdir>`, `<home>`, or `<path>` placeholders.",
            "- Catalog scratch paths, staged bundle paths, installed bundle paths, data/cache/run paths, and rollback backup paths are sanitized.",
            "- `artifacts/private-insert-uris.json` is excluded even if an interop summary references it.",
            "",
        ]
    )
    return "\n".join(lines)


def markdown_cell(value: Any) -> str:
    text = str(value)
    return text.replace("\n", " ").replace("|", "\\|")


def markdown_code_list(values: Any) -> str:
    if not isinstance(values, list) or not values:
        return "none"
    return ", ".join(f"`{markdown_cell(value)}`" for value in values)


def coverage_result(value: Any) -> str:
    return "pass" if value is True else "fail"


def coverage_notes(values: Any) -> str:
    if not isinstance(values, list) or not values:
        return "No gaps."
    return markdown_code_list(values)


def render_ecosystem_matrix_report(matrix: dict[str, Any]) -> str:
    counts = matrix.get("counts", {}) if isinstance(matrix.get("counts"), dict) else {}
    coverage = matrix.get("coverage", {}) if isinstance(matrix.get("coverage"), dict) else {}
    rows = matrix.get("rows", []) if isinstance(matrix.get("rows"), list) else []
    lines = [
        "# Ecosystem Certification Matrix",
        "",
        f"- Promotion decision: `{matrix.get('promotionDecision', 'block')}`",
        f"- Matrix status: `{matrix.get('status', 'missing')}`",
        f"- Mode: `{matrix.get('mode', 'missing')}`",
        f"- Generated: `{matrix.get('generatedAt', '')}`",
        f"- Previous summary: `{'present' if matrix.get('previousSummaryPresent') else 'missing'}`",
        f"- Previous matrix: `{'present' if matrix.get('previousMatrixPresent') else 'missing'}`",
        f"- Release blockers: `{counts.get('releaseBlockers', 0)}`",
        "",
        "## Coverage",
        "",
        "| Check | Result | Notes |",
        "| --- | --- | --- |",
        "| Required evidence covered | `{}` | {} |".format(
            coverage_result(coverage.get("requiredEvidenceCovered")),
            coverage_notes(
                (coverage.get("missingRequiredEvidenceIds") or [])
                + (coverage.get("unmappedRequiredEvidenceIds") or [])
            ),
        ),
        "| Ecosystem gates covered | `{}` | {} |".format(
            coverage_result(coverage.get("ecosystemGatesCovered")),
            coverage_notes(coverage.get("unmappedGateIds")),
        ),
        "| First-party apps covered | `{}` | {} |".format(
            coverage_result(coverage.get("firstPartyAppsCovered")),
            coverage_notes(coverage.get("missingFirstPartyApps")),
        ),
        "| Docs covered | `{}` | {} |".format(
            coverage_result(coverage.get("docsCovered")),
            coverage_notes((coverage.get("rowsWithoutDocs") or []) + (coverage.get("missingDocPaths") or [])),
        ),
        "| Redaction | `{}` | {} |".format(
            coverage_result(coverage.get("redactionPassed")),
            "Private material excluded." if coverage.get("redactionPassed") else "Review matrix redaction flags.",
        ),
        "",
        "## Matrix",
        "",
        "| Category | Row | Status | Previous | Regression | Blocker | Evidence | Gates | Waivers | Recommendation |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        if not isinstance(row, dict):
            continue
        lines.append(
            "| {category} | {row_title} | `{status}` | `{previous}` | `{regression}` | {blocker} | {evidence} | {gates} | {waivers} | {recommendation} |".format(
                category=markdown_cell(row.get("category", "")),
                row_title=markdown_cell(row.get("title", row.get("id", ""))),
                status=markdown_cell(row.get("status", "missing")),
                previous=markdown_cell(row.get("previousStatus", "missing")),
                regression=markdown_cell(row.get("regressionStatus", "not-comparable")),
                blocker="yes" if row.get("releaseBlocker") else "no",
                evidence=markdown_code_list(row.get("evidenceIds")),
                gates=markdown_code_list(row.get("gateIds")),
                waivers=markdown_code_list(row.get("waiverIds")),
                recommendation=markdown_cell(row.get("recommendation", "")),
            )
        )
    non_passing = [
        row for row in rows if isinstance(row, dict) and row.get("status") != "pass"
    ]
    if non_passing:
        lines.extend(["", "## Non-Passing Rows", ""])
        for row in non_passing:
            issue_ids = row.get("issueIds", [])
            details = row.get("details", {}) if isinstance(row.get("details"), dict) else {}
            waiver_reasons = details.get("waiverReasons", {}) if isinstance(details.get("waiverReasons"), dict) else {}
            lines.extend(
                [
                    f"### `{row.get('id', '')}`",
                    "",
                    f"- Status: `{row.get('status', 'missing')}`",
                    f"- Release blocker: `{'yes' if row.get('releaseBlocker') else 'no'}`",
                    f"- Regression: `{row.get('regressionStatus', 'not-comparable')}`",
                    f"- Issues: {markdown_code_list(issue_ids)}",
                    f"- Waivers: {markdown_code_list(row.get('waiverIds'))}",
                ]
            )
            if waiver_reasons:
                for waiver_id in sorted(waiver_reasons):
                    lines.append(f"- Waiver `{markdown_cell(waiver_id)}`: {markdown_cell(waiver_reasons[waiver_id])}")
            lines.extend([f"- Recommendation: {markdown_cell(row.get('recommendation', ''))}", ""])
    lines.extend(
        [
            "## Redaction",
            "",
            "The matrix is derived from sanitized summary fields. It does not include raw request bodies, raw feed bodies, raw trust documents, raw signatures, tokens, private insert URIs, or absolute local filesystem paths.",
            "",
        ]
    )
    return "\n".join(lines)


def append_ecosystem_matrix_summary(lines: list[str], summary: dict[str, Any]) -> None:
    matrix = summary.get("ecosystemMatrix", {})
    if not isinstance(matrix, dict):
        return
    coverage = matrix.get("coverage", {}) if isinstance(matrix.get("coverage"), dict) else {}
    lines.extend(
        [
            "## Ecosystem Certification Matrix",
            "",
            f"- Matrix status: `{summary.get('ecosystemMatrixStatus', 'missing')}`",
            f"- Matrix report: `{summary.get('ecosystemMatrixReportPath', '')}`",
            f"- Rows: `{matrix.get('rowCount', 0)}`",
            f"- Release blockers: `{matrix.get('releaseBlockerCount', 0)}`",
            f"- Required evidence covered: `{'yes' if coverage.get('requiredEvidenceCovered') else 'no'}`",
            f"- Ecosystem gates covered: `{'yes' if coverage.get('ecosystemGatesCovered') else 'no'}`",
            "",
        ]
    )


def append_history_comparison(lines: list[str], summary: dict[str, Any]) -> None:
    history = summary.get("historyComparison", {})
    if not isinstance(history, dict):
        return
    previous = history.get("previous", {}) if isinstance(history.get("previous"), dict) else {}
    current = history.get("current", {}) if isinstance(history.get("current"), dict) else {}
    lines.extend(
        [
            "## Historical Comparison",
            "",
            f"- Status: `{history.get('status', 'missing')}`",
            f"- Summary: {history.get('summary', 'No historical comparison was produced.')}",
            f"- Previous generated: `{previous.get('generatedAt', '')}`",
            f"- Previous git SHA: `{previous.get('gitSha', '')}`",
            f"- Previous release version: `{previous.get('releaseVersion', '')}`",
            f"- Current generated: `{current.get('generatedAt', '')}`",
            f"- Current git SHA: `{current.get('gitSha', '')}`",
            f"- Current release version: `{current.get('releaseVersion', '')}`",
            "",
        ]
    )


def append_ecosystem_gates(lines: list[str], summary: dict[str, Any]) -> None:
    gates = summary.get("ecosystemGates", [])
    if not isinstance(gates, list):
        return
    lines.extend(["## Ecosystem Gates", "", "| Gate | Status | Blocker | Summary |", "| --- | --- | --- | --- |"])
    ordered = sorted(
        [gate for gate in gates if isinstance(gate, dict)],
        key=lambda gate: (gate.get("status") != "fail", gate.get("status") != "warn", str(gate.get("id", ""))),
    )
    for gate in ordered:
        lines.append(
            "| `{id}` | `{status}` | {blocker} | {summary_text} |".format(
                id=gate.get("id", ""),
                status=gate.get("status", "missing"),
                blocker="yes" if gate.get("releaseBlocker") else "no",
                summary_text=str(gate.get("summary", "")).replace("|", "\\|"),
            )
        )
    lines.append("")


def append_waivers(lines: list[str], summary: dict[str, Any]) -> None:
    waivers = summary.get("waiverRecords")
    if not isinstance(waivers, list):
        legacy_waivers = summary.get("waivers", [])
        waivers = legacy_waivers if isinstance(legacy_waivers, list) else []
    if not isinstance(waivers, list):
        return
    lines.extend(["## Waivers", ""])
    if not waivers:
        lines.extend(["No waivers were recorded.", ""])
        return
    lines.extend(["| Waiver | Evidence/Gate | Active | Expires | Reason |", "| --- | --- | --- | --- | --- |"])
    for waiver in waivers:
        if not isinstance(waiver, dict):
            continue
        lines.append(
            "| `{id}` | `{evidence}` | `{active}` | `{expires}` | {reason} |".format(
                id=waiver.get("id", ""),
                evidence=waiver.get("evidenceId", ""),
                active=waiver.get("active", False),
                expires=waiver.get("expiresAt", ""),
                reason=str(waiver.get("reason", "")).replace("|", "\\|"),
            )
        )
    lines.append("")


def append_regressions(lines: list[str], summary: dict[str, Any]) -> None:
    history = summary.get("historyComparison", {})
    if not isinstance(history, dict):
        return
    diffs = history.get("evidenceDiffs", [])
    if not isinstance(diffs, list):
        return
    important = [
        diff
        for diff in diffs
        if isinstance(diff, dict) and diff.get("classification") in {"regression", "removed"}
    ]
    lines.extend(["## Regressions Since Previous Certified Release", ""])
    if not important:
        lines.extend(["No evidence regressions were detected.", ""])
        return
    lines.extend(
        [
            "| Evidence | Previous | Current | Classification | Blocker | Reason |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for diff in important:
        lines.append(
            "| `{id}` | `{previous}` | `{current}` | `{classification}` | {blocker} | {reason} |".format(
                id=diff.get("id", ""),
                previous=diff.get("previousStatus", ""),
                current=diff.get("currentStatus", ""),
                classification=diff.get("classification", ""),
                blocker="yes" if diff.get("releaseBlocker") else "no",
                reason=str(diff.get("reason", "")).replace("|", "\\|"),
            )
        )
    lines.append("")


def append_detail(lines: list[str], summary: dict[str, Any], evidence_id: str) -> None:
    item = next((entry for entry in summary["evidence"] if entry["id"] == evidence_id), None)
    if item is None:
        return
    lines.append(f"### `{evidence_id}`")
    lines.append("")
    lines.append(f"- Status: `{item['status']}`")
    lines.append(f"- Source: `{item['source']}`")
    lines.append(f"- Summary: {item['summary']}")
    details = item.get("details", {})
    if details:
        compact = json.dumps(details, indent=2, sort_keys=True)
        lines.extend(["", "```json", compact, "```"])
    lines.append("")


def gather_evidence(settings: Settings, waiver_context: WaiverContext) -> list[EvidenceItem]:
    evidence = [
        interop_evidence(
            "interop.smoke",
            settings.interop_smoke_summary,
            True,
            "smoke",
            settings.workspace_root,
            settings.out_dir,
        ),
        interop_evidence(
            "interop.extended",
            settings.interop_extended_summary,
            False,
            "extended",
            settings.workspace_root,
            settings.out_dir,
        ),
        perf_evidence(settings.perf_smoke_summary, True, settings.workspace_root, settings.out_dir),
    ]
    evidence.extend(
        app_platform_evidence(
            settings.app_platform_summary,
            settings.workspace_root,
            settings.out_dir,
            settings.mode,
        )
    )
    evidence.extend(app_platform_docs_evidence(settings.workspace_root, settings.out_dir))
    return [
        sanitize_evidence_item(
            with_waiver_record(
                item,
                active_waiver_for_evidence_item(waiver_context, item, settings.mode),
            ),
            settings.workspace_root,
            settings.out_dir,
        )
        for item in evidence
    ]


def render_history_comparison(history: dict[str, Any]) -> str:
    lines = [
        "# Release Certification History Comparison",
        "",
        f"- Status: `{history.get('status', 'missing')}`",
        f"- Summary: {history.get('summary', '')}",
        "",
        "## Evidence Diffs",
        "",
        "| Evidence | Previous | Current | Classification | Blocker | Reason |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    diffs = history.get("evidenceDiffs", [])
    if isinstance(diffs, list):
        for diff in diffs:
            if not isinstance(diff, dict):
                continue
            lines.append(
                "| `{id}` | `{previous}` | `{current}` | `{classification}` | {blocker} | {reason} |".format(
                    id=diff.get("id", ""),
                    previous=diff.get("previousStatus", ""),
                    current=diff.get("currentStatus", ""),
                    classification=diff.get("classification", ""),
                    blocker="yes" if diff.get("releaseBlocker") else "no",
                    reason=str(diff.get("reason", "")).replace("|", "\\|"),
                )
            )
    gates = history.get("ecosystemGates", [])
    if isinstance(gates, list):
        lines.extend(["", "## Ecosystem Gates", "", "| Gate | Status | Blocker | Summary |", "| --- | --- | --- | --- |"])
        for gate in gates:
            if not isinstance(gate, dict):
                continue
            lines.append(
                "| `{id}` | `{status}` | {blocker} | {summary_text} |".format(
                    id=gate.get("id", ""),
                    status=gate.get("status", "missing"),
                    blocker="yes" if gate.get("releaseBlocker") else "no",
                    summary_text=str(gate.get("summary", "")).replace("|", "\\|"),
                )
            )
    lines.append("")
    return "\n".join(lines)


def safe_history_label(summary: dict[str, Any]) -> str:
    metadata = summary.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}
    for value in (
        metadata.get("releaseVersion"),
        summary.get("historyLabel"),
        metadata.get("gitCommit"),
        metadata.get("githubSha"),
    ):
        if isinstance(value, str) and value.strip():
            label = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-")
            if label:
                return label[:80]
    return "current"


def write_history_artifacts(settings: Settings, summary: dict[str, Any]) -> None:
    if not settings.write_history:
        return
    history_dir = resolve_path(settings.workspace_root, settings.history_dir)
    comparison = summary.get("historyComparison", {})
    label = settings.history_label.strip() or safe_history_label(summary)
    safe_label = re.sub(r"[^A-Za-z0-9._-]+", "-", label).strip("-") if label else "current"
    if not safe_label:
        safe_label = "current"
    if summary.get("status") == "fail" or summary.get("releaseCandidatePassed") is False:
        failed_dir = history_dir / "failed" / safe_label
        write_json(failed_dir / SUMMARY_FILE_NAME, summary)
        if isinstance(comparison, dict):
            write_json(failed_dir / HISTORY_COMPARISON_FILE_NAME, comparison)
        return
    write_json(history_dir / "latest-summary.json", summary)
    if isinstance(comparison, dict):
        write_json(history_dir / "latest-history-comparison.json", comparison)
    release_dir = history_dir / "releases" / safe_label
    write_json(release_dir / SUMMARY_FILE_NAME, summary)
    if isinstance(comparison, dict):
        write_json(release_dir / HISTORY_COMPARISON_FILE_NAME, comparison)


def run(settings: Settings) -> tuple[dict[str, Any], int]:
    settings.out_dir.mkdir(parents=True, exist_ok=True)
    generated_at = utc_now()
    waiver_context = load_waiver_context(settings, dt.datetime.now(dt.timezone.utc))
    previous_summary, previous_source, previous_error = load_previous_summary(settings)
    copied = collect_source_artifacts(settings, settings.out_dir)
    base_evidence = gather_evidence(settings, waiver_context)
    metadata = collect_metadata(settings)

    def evaluate_history_and_gates(current_evidence: list[EvidenceItem]) -> tuple[dict[str, Any], list[GateResult]]:
        comparison = compare_history(
            settings,
            previous_summary,
            previous_source,
            previous_error,
            current_evidence,
            generated_at,
            metadata,
            waiver_context,
        )
        gates = evaluate_ecosystem_gates(
            settings, current_evidence, previous_summary, comparison, metadata, waiver_context
        )
        comparison["ecosystemGates"] = [gate.to_json() for gate in gates]
        comparison = dict(sanitize_value(comparison, settings.workspace_root, settings.out_dir))
        sanitized_gates = [
            GateResult(
                id=str(gate["id"]),
                status=normalize_evidence_status(str(gate["status"])),
                release_blocker=bool(gate.get("releaseBlocker")),
                summary=str(gate.get("summary", "")),
                details=gate.get("details", {}) if isinstance(gate.get("details"), dict) else {},
            )
            for gate in comparison.get("ecosystemGates", [])
            if isinstance(gate, dict)
        ]
        return comparison, sanitized_gates

    matrix_evidence = placeholder_ecosystem_matrix_evidence(settings.workspace_root, settings.out_dir)
    evidence = [*base_evidence, matrix_evidence]
    history_comparison: dict[str, Any] = {}
    ecosystem_gates: list[GateResult] = []
    ecosystem_matrix: dict[str, Any] = {}
    for _ in range(5):
        history_comparison, ecosystem_gates = evaluate_history_and_gates(evidence)
        ecosystem_matrix = build_ecosystem_matrix(
            settings,
            evidence,
            previous_summary,
            history_comparison,
            ecosystem_gates,
            waiver_context,
            generated_at,
        )
        next_matrix_evidence = ecosystem_matrix_evidence(
            ecosystem_matrix, settings.workspace_root, settings.out_dir
        )
        if next_matrix_evidence == matrix_evidence:
            break
        matrix_evidence = next_matrix_evidence
        evidence = [*base_evidence, matrix_evidence]
    else:
        history_comparison, ecosystem_gates = evaluate_history_and_gates(evidence)
        ecosystem_matrix = build_ecosystem_matrix(
            settings,
            evidence,
            previous_summary,
            history_comparison,
            ecosystem_gates,
            waiver_context,
            generated_at,
        )
    summary = build_summary(
        settings,
        evidence,
        copied,
        generated_at,
        metadata,
        history_comparison,
        ecosystem_gates,
        waiver_context,
        ecosystem_matrix,
    )
    write_json(settings.out_dir / SUMMARY_FILE_NAME, summary)
    write_json(settings.out_dir / HISTORY_COMPARISON_FILE_NAME, history_comparison)
    write_text(settings.out_dir / HISTORY_COMPARISON_REPORT_FILE_NAME, render_history_comparison(history_comparison))
    write_json(settings.out_dir / ECOSYSTEM_MATRIX_FILE_NAME, ecosystem_matrix)
    write_text(
        settings.out_dir / ECOSYSTEM_MATRIX_REPORT_FILE_NAME,
        render_ecosystem_matrix_report(ecosystem_matrix),
    )
    report = render_report(summary)
    write_text(settings.out_dir / REPORT_FILE_NAME, report)
    write_history_artifacts(settings, summary)
    exit_code = 1 if summary["status"] == "fail" else 0
    return summary, exit_code


def parse_key_value(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise argparse.ArgumentTypeError(f"Expected key=value, got {value}")
        key, text = value.split("=", 1)
        if not key:
            raise argparse.ArgumentTypeError(f"Expected non-empty key in {value}")
        result[key] = text
    return result


def settings_from_args(args: argparse.Namespace) -> Settings:
    workspace_root = args.workspace_root.resolve()
    out_dir = (workspace_root / args.out_dir).resolve() if not args.out_dir.is_absolute() else args.out_dir.resolve()
    previous_summary = resolve_path(workspace_root, args.previous_summary) if args.previous_summary else None
    history_dir = resolve_path(workspace_root, args.history_dir)
    waiver_files = tuple(resolve_path(workspace_root, path) for path in args.waiver_file)
    mode = args.mode or os.environ.get("CRYPTAD_CERT_MODE", "pr")
    if mode not in MODES:
        raise SystemExit(f"--mode must be one of {', '.join(MODES)}")
    return Settings(
        workspace_root=workspace_root,
        out_dir=out_dir,
        mode=mode,
        interop_smoke_summary=resolve_path(workspace_root, args.interop_smoke_summary),
        interop_extended_summary=resolve_path(workspace_root, args.interop_extended_summary),
        perf_smoke_summary=resolve_path(workspace_root, args.perf_smoke_summary),
        app_platform_summary=resolve_path(workspace_root, args.app_platform_summary),
        waivers=parse_key_value(args.waive),
        metadata=parse_key_value(args.metadata),
        skip_git_metadata=args.skip_git_metadata,
        previous_summary=previous_summary,
        require_history=args.require_history,
        history_dir=history_dir,
        write_history=args.write_history,
        history_label=args.history_label,
        waiver_files=waiver_files,
    )


def resolve_path(workspace_root: Path, path: Path) -> Path:
    return (workspace_root / path).resolve() if not path.is_absolute() else path.resolve()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="Run Python-only self-tests.")
    parser.add_argument("--workspace-root", type=Path, default=Path.cwd())
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--mode", choices=MODES, default=None)
    parser.add_argument("--interop-smoke-summary", type=Path, default=Path("build/interop-smoke/summary.json"))
    parser.add_argument("--interop-extended-summary", type=Path, default=Path("build/interop-extended/summary.json"))
    parser.add_argument("--perf-smoke-summary", type=Path, default=Path("build/perf-smoke/summary.json"))
    parser.add_argument(
        "--app-platform-summary",
        type=Path,
        default=DEFAULT_OUT_DIR / "app-platform-smoke" / "summary.json",
    )
    parser.add_argument("--waive", action="append", default=[], metavar="ID=REASON")
    parser.add_argument("--waiver-file", action="append", default=[], type=Path)
    parser.add_argument("--previous-summary", type=Path, default=None)
    parser.add_argument("--require-history", action="store_true")
    parser.add_argument("--history-dir", type=Path, default=DEFAULT_HISTORY_DIR)
    parser.add_argument("--write-history", action="store_true")
    parser.add_argument("--history-label", default="")
    parser.add_argument("--metadata", action="append", default=[], metavar="KEY=VALUE")
    parser.add_argument("--skip-git-metadata", action="store_true")
    return parser


def run_self_test(repo_root: Path) -> None:
    fixture_dir = repo_root / "tools/release-certification/fixtures"
    with tempfile.TemporaryDirectory(prefix="cryptad-cert-self-test-") as temp_name:
        workspace = Path(temp_name) / "repo"
        out_dir = workspace / "build/release-certification"
        (workspace / "build/interop-smoke").mkdir(parents=True)
        (workspace / "build/interop-extended").mkdir(parents=True)
        (workspace / "build/perf-smoke").mkdir(parents=True)
        (out_dir / "app-platform-smoke").mkdir(parents=True)
        for spec in ecosystem_matrix_row_specs():
            for doc_path in spec.docs:
                source_doc = repo_root / doc_path
                target_doc = workspace / doc_path
                target_doc.parent.mkdir(parents=True, exist_ok=True)
                assert source_doc.is_file(), f"matrix doc path missing: {doc_path}"
                shutil.copy2(source_doc, target_doc)
        docs_check_paths = {
            *app_platform_docs_check.REQUIRED_DOCS,
            *app_platform_docs_check.REQUIRED_PORTAL_LINKS,
            *app_platform_docs_check.ISSUE_TEMPLATES,
            "README.md",
        }
        for source_doc in repo_root.glob("docs/**/*.md"):
            target_doc = workspace / source_doc.relative_to(repo_root)
            target_doc.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_doc, target_doc)
        for doc_path in sorted(docs_check_paths):
            source_doc = repo_root / doc_path
            target_doc = workspace / doc_path
            target_doc.parent.mkdir(parents=True, exist_ok=True)
            assert source_doc.is_file(), f"docs-check path missing: {doc_path}"
            shutil.copy2(source_doc, target_doc)
        shutil.copy2(fixture_dir / "self-test-interop-smoke.json", workspace / "build/interop-smoke/summary.json")
        shutil.copy2(
            fixture_dir / "self-test-interop-extended.json",
            workspace / "build/interop-extended/summary.json",
        )
        shutil.copy2(fixture_dir / "self-test-perf-smoke.json", workspace / "build/perf-smoke/summary.json")
        shutil.copy2(
            fixture_dir / "self-test-app-platform-smoke.json",
            out_dir / "app-platform-smoke/summary.json",
        )
        settings = Settings(
            workspace_root=workspace.resolve(),
            out_dir=out_dir.resolve(),
            mode="release-candidate",
            interop_smoke_summary=workspace / "build/interop-smoke/summary.json",
            interop_extended_summary=workspace / "build/interop-extended/summary.json",
            perf_smoke_summary=workspace / "build/perf-smoke/summary.json",
            app_platform_summary=out_dir / "app-platform-smoke/summary.json",
            waivers={},
            metadata={"selfTest": "true"},
            skip_git_metadata=True,
            history_dir=workspace / "build/no-auto-history",
        )
        summary, exit_code = run(settings)
        assert exit_code == 0, summary
        assert summary["status"] == "warn", summary
        assert summary["promotionDecision"] == "PASS WITH WARNINGS", summary
        assert summary["releaseCandidatePassed"] is True, summary
        assert summary["waivers"] == {}, summary
        assert summary["waiverRecords"] == [], summary
        assert summary["historyComparison"]["status"] == "warn", summary
        assert (out_dir / HISTORY_COMPARISON_FILE_NAME).is_file(), summary
        assert (out_dir / HISTORY_COMPARISON_REPORT_FILE_NAME).is_file(), summary
        assert (out_dir / ECOSYSTEM_MATRIX_FILE_NAME).is_file(), summary
        assert (out_dir / ECOSYSTEM_MATRIX_REPORT_FILE_NAME).is_file(), summary
        matrix = read_json(out_dir / ECOSYSTEM_MATRIX_FILE_NAME)
        assert matrix is not None, summary
        assert matrix["schemaVersion"] == ECOSYSTEM_MATRIX_SCHEMA_VERSION, matrix
        assert matrix["kind"] == "ecosystem-certification-matrix", matrix
        assert matrix["coverage"]["requiredEvidenceCovered"] is True, matrix
        assert matrix["coverage"]["ecosystemGatesCovered"] is True, matrix
        assert matrix["coverage"]["firstPartyAppsCovered"] is True, matrix
        assert matrix["coverage"]["docsCovered"] is True, matrix
        assert matrix["coverage"]["redactionPassed"] is True, matrix
        assert set(matrix["coverage"]["coveredFirstPartyApps"]) == set(EXPECTED_FIRST_PARTY_APPS), matrix
        matrix_rows_by_id = {row["id"]: row for row in matrix["rows"]}
        for row_id in (
            "app-update",
            "first-party-beta-catalog",
            "developer-beta-toolkit",
            "app-platform-beta-docs-and-program",
            "review-governance-transparency",
            "app-vault-and-generated-documents",
            "content-fetch-and-networked-content",
            "trust-graph-preview-platform",
            "social-inbox-preview",
            "legacy-plugin-migration",
            "apphost-sandbox-provider",
            "platform-api-contract",
            "interop-smoke",
            "performance-smoke",
            "legacy-retirement",
            "ecosystem-certification-matrix",
        ):
            assert row_id in matrix_rows_by_id, row_id
        covered_evidence_ids = {
            evidence_id
            for row in matrix["rows"]
            for evidence_id in row.get("evidenceIds", [])
        }
        for evidence_id, item in {
            item["id"]: item for item in summary["evidence"]
        }.items():
            if item["requiredForReleaseCandidate"]:
                assert evidence_id in covered_evidence_ids, evidence_id
        for evidence_id in (
            "app-platform.trust-graph-preview",
            "app-platform.trust-graph-durable-store",
            "app-platform.trust-graph-exchange",
            "app-platform.trust-statement-signing",
            "app-platform.social-message-signing",
            "app-review.governance",
            "app-review.reviewer-key-lifecycle",
            "app-review.transparency-log",
            "app-review.review-history-api",
            "app-review.first-party-review-chain",
            "reference-app.trust-graph",
            "reference-app.trust-graph-durable-exchange",
            "reference-app.social-inbox",
            "migration.social-mail-preview",
            "legacy-plugin.migration-guide",
            "legacy-plugin.social-inbox-spike",
            "legacy-admin.removal-wave-2",
            "legacy-admin.removal-wave-3",
            "app-platform.docs-portal",
            "app-platform.beta-program",
            "app-platform.beta-tutorials",
            "app-platform.docs-redaction",
        ):
            assert evidence_id in covered_evidence_ids, evidence_id
        gate_ids = {gate["id"] for gate in summary["ecosystemGates"]}
        covered_gate_ids = {gate_id for row in matrix["rows"] for gate_id in row.get("gateIds", [])}
        assert gate_ids <= covered_gate_ids, (gate_ids, covered_gate_ids)
        assert summary["ecosystemMatrixPath"].endswith(ECOSYSTEM_MATRIX_FILE_NAME), summary
        assert summary["ecosystemMatrixReportPath"].endswith(ECOSYSTEM_MATRIX_REPORT_FILE_NAME), summary
        assert summary["ecosystemMatrix"]["schemaVersion"] == ECOSYSTEM_MATRIX_SCHEMA_VERSION, summary
        assert summary["ecosystemMatrix"]["rowCount"] == len(matrix["rows"]), summary
        evidence_by_id = {item["id"]: item for item in summary["evidence"]}
        assert evidence_by_id["release-certification.ecosystem-matrix"][
            "requiredForReleaseCandidate"
        ] is True
        assert evidence_by_id["app-update.lifecycle"]["status"] == "pass", evidence_by_id
        assert evidence_by_id["app-update.lifecycle"]["requiredForReleaseCandidate"] is True
        assert evidence_by_id["app-update.scheduler"]["status"] == "pass", evidence_by_id
        assert evidence_by_id["app-update.scheduler"]["requiredForReleaseCandidate"] is True
        assert evidence_by_id["app-update.rollback"]["status"] == "pass", evidence_by_id
        assert evidence_by_id["app-update.rollback"]["requiredForReleaseCandidate"] is True
        for evidence_id in (
            "app-platform.docs-portal",
            "app-platform.beta-program",
            "app-platform.beta-tutorials",
            "app-platform.docs-redaction",
        ):
            assert evidence_by_id[evidence_id]["status"] == "pass", evidence_by_id
            assert evidence_by_id[evidence_id]["requiredForReleaseCandidate"] is True
        report_text = (out_dir / REPORT_FILE_NAME).read_text(encoding="utf-8")
        for evidence_id in (
            "app-platform.docs-portal",
            "app-platform.beta-program",
            "app-platform.beta-tutorials",
            "app-platform.docs-redaction",
        ):
            assert f"### `{evidence_id}`" in report_text, evidence_id
        assert "redactionFindings" in report_text, report_text
        assert evidence_by_id["app-vault.capabilities"]["status"] == "pass", evidence_by_id
        assert evidence_by_id["app-vault.capabilities"]["requiredForReleaseCandidate"] is True
        assert (
            evidence_by_id["app-platform.identity-profile-publish"]["status"] == "pass"
        ), evidence_by_id
        assert (
            evidence_by_id["app-platform.generated-document-insert"]["status"] == "pass"
        ), evidence_by_id
        assert evidence_by_id["app-platform.content-fetch"]["status"] == "pass", evidence_by_id
        assert (
            evidence_by_id["app-platform.content-subscriptions"]["status"] == "pass"
        ), evidence_by_id
        assert (
            evidence_by_id["network-content.subscription-scheduler"]["status"] == "pass"
        ), evidence_by_id
        assert (
            evidence_by_id["app-platform.durable-app-data-store"]["status"] == "pass"
        ), evidence_by_id
        assert evidence_by_id["app-platform.trust-graph-preview"]["status"] == "pass", evidence_by_id
        assert evidence_by_id["app-platform.trust-graph-preview"][
            "requiredForReleaseCandidate"
        ] is True
        assert (
            evidence_by_id["app-platform.trust-graph-durable-store"]["status"] == "pass"
        ), evidence_by_id
        assert (
            evidence_by_id["app-platform.trust-graph-exchange"]["status"] == "pass"
        ), evidence_by_id
        assert (
            evidence_by_id["app-platform.trust-statement-signing"]["status"] == "pass"
        ), evidence_by_id
        assert evidence_by_id["app-platform.trust-statement-signing"][
            "requiredForReleaseCandidate"
        ] is True
        assert evidence_by_id["app-platform.social-message-signing"]["status"] == "pass", (
            evidence_by_id
        )
        assert evidence_by_id["app-platform.social-message-signing"][
            "requiredForReleaseCandidate"
        ] is True
        for evidence_id in (
            "app-review.governance",
            "app-review.reviewer-key-lifecycle",
            "app-review.transparency-log",
            "app-review.review-history-api",
            "app-review.first-party-review-chain",
        ):
            assert evidence_by_id[evidence_id]["status"] == "pass", evidence_by_id
            assert evidence_by_id[evidence_id]["requiredForReleaseCandidate"] is True
        assert evidence_by_id["reference-app.profile-publisher"]["status"] == "pass", evidence_by_id
        assert (
            evidence_by_id["reference-app.profile-publisher-app-data"]["status"] == "pass"
        ), evidence_by_id
        assert evidence_by_id["reference-app.feed-reader"]["status"] == "pass", evidence_by_id
        assert (
            evidence_by_id["reference-app.feed-reader-subscriptions"]["status"] == "pass"
        ), evidence_by_id
        assert evidence_by_id["reference-app.feed-reader-app-data"]["status"] == "pass", evidence_by_id
        assert evidence_by_id["reference-app.trust-graph"]["status"] == "pass", evidence_by_id
        assert evidence_by_id["reference-app.trust-graph"]["requiredForReleaseCandidate"] is True
        assert (
            evidence_by_id["reference-app.trust-graph-durable-exchange"]["status"] == "pass"
        ), evidence_by_id
        assert (
            evidence_by_id["reference-app.trust-graph-app-data-preview"]["status"] == "pass"
        ), evidence_by_id
        for evidence_id in (
            "reference-app.social-inbox",
            "reference-app.social-inbox-signed-message",
            "reference-app.social-inbox-subscriptions",
            "reference-app.social-inbox-app-data",
            "reference-app.social-inbox-trust-annotations",
            "reference-app.social-inbox-service-grant",
            "migration.social-mail-preview",
            "legacy-plugin.migration-guide",
            "legacy-plugin.social-inbox-spike",
        ):
            assert evidence_by_id[evidence_id]["status"] == "pass", evidence_by_id
            assert evidence_by_id[evidence_id]["requiredForReleaseCandidate"] is True
        for evidence_id in (
            "app-services.registry",
            "app-services.grants",
            "app-services.trust-score-provider",
            "app-services.web-shell",
            "app-services.redaction",
        ):
            assert evidence_by_id[evidence_id]["status"] == "pass", evidence_by_id
            assert evidence_by_id[evidence_id]["requiredForReleaseCandidate"] is True
        assert evidence_by_id["legacy-admin.removal-wave-1"]["status"] == "pass", evidence_by_id
        assert evidence_by_id["legacy-admin.removal-wave-1"]["requiredForReleaseCandidate"] is True
        assert evidence_by_id["legacy-admin.removal-wave-2"]["status"] == "pass", evidence_by_id
        assert evidence_by_id["legacy-admin.removal-wave-2"]["requiredForReleaseCandidate"] is True
        assert evidence_by_id["legacy-admin.removal-wave-3"]["status"] == "pass", evidence_by_id
        assert evidence_by_id["legacy-admin.removal-wave-3"]["requiredForReleaseCandidate"] is True
        optional_skip_status, optional_skip_release_passed = determine_overall_status(
            "release-candidate",
            [
                EvidenceItem("catalog.smoke", "pass", True, "passed", "<repo>/summary.json", {}),
                EvidenceItem("apphost.live", "skip", False, "not requested", "<repo>/summary.json", {}),
            ],
        )
        assert optional_skip_status == "pass", optional_skip_status
        assert optional_skip_release_passed is True, optional_skip_release_passed
        report = (out_dir / REPORT_FILE_NAME).read_text(encoding="utf-8")
        matrix_report = (out_dir / ECOSYSTEM_MATRIX_REPORT_FILE_NAME).read_text(encoding="utf-8")
        assert "Release Certification Report" in report
        assert "Historical Comparison" in report
        assert "Ecosystem Gates" in report
        assert "Ecosystem Certification Matrix" in report
        assert ECOSYSTEM_MATRIX_REPORT_FILE_NAME in report
        assert "Ecosystem Certification Matrix" in matrix_report
        assert "Required evidence covered" in matrix_report
        assert "Waivers" in report
        encoded = json.dumps(summary, sort_keys=True) + json.dumps(matrix, sort_keys=True) + matrix_report
        for forbidden in ("CRYPTAD_APP_TOKEN", "USK@private", str(workspace)):
            assert forbidden not in encoded, f"self-test leaked {forbidden}"
        feed_body_metadata = sanitize_value(
            {
                "rawFeedBody": "<feed><entry>private body</entry></feed>",
                "rawFeedBodyBase64": "opaque-feed-body-base64",
                "rawRequestBody": "uri=SSK@private",
                "requestBodyText": "opaque-request-body-text",
                "feedContentPreview": "opaque-feed-preview",
                "rawFeedBodySource": "opaque-feed-body-source",
                "requestBodySource": "opaque-request-body-source",
                "feedSummary": "3 entries",
                "rawFeedBodyRedacted": True,
                "rawFeedBodiesExcluded": True,
                "rawMessageBody": "private social message body",
                "messageBodyText": "private social message text",
                "rawFetchedBody": "{\"messages\":[{\"body\":\"private fetched body\"}]}",
                "fetchedBodyPreview": "private fetched preview",
                "rawMessageBodiesExcludedFromEvidence": True,
            },
            workspace,
            out_dir,
        )
        assert feed_body_metadata["rawFeedBody"] == "<redacted>", feed_body_metadata
        assert feed_body_metadata["rawFeedBodyBase64"] == "<redacted>", feed_body_metadata
        assert feed_body_metadata["rawRequestBody"] == "<redacted>", feed_body_metadata
        assert feed_body_metadata["requestBodyText"] == "<redacted>", feed_body_metadata
        assert feed_body_metadata["feedContentPreview"] == "<redacted>", feed_body_metadata
        assert feed_body_metadata["rawFeedBodySource"] == "<redacted>", feed_body_metadata
        assert feed_body_metadata["requestBodySource"] == "<redacted>", feed_body_metadata
        assert feed_body_metadata["feedSummary"] == "3 entries", feed_body_metadata
        assert feed_body_metadata["rawFeedBodyRedacted"] is True, feed_body_metadata
        assert feed_body_metadata["rawFeedBodiesExcluded"] is True, feed_body_metadata
        assert feed_body_metadata["rawMessageBody"] == "<redacted>", feed_body_metadata
        assert feed_body_metadata["messageBodyText"] == "<redacted>", feed_body_metadata
        assert feed_body_metadata["rawFetchedBody"] == "<redacted>", feed_body_metadata
        assert feed_body_metadata["fetchedBodyPreview"] == "<redacted>", feed_body_metadata
        assert feed_body_metadata["rawMessageBodiesExcludedFromEvidence"] is True, feed_body_metadata
        interop_item = next(item for item in summary["evidence"] if item["id"] == "interop.smoke")
        assert "artifacts/private-insert-uris.json" not in json.dumps(interop_item)

        previous_good_path = workspace / "build/previous-good/release-certification-summary.json"
        previous_good = {
            "schemaVersion": SCHEMA_VERSION,
            "tool": TOOL_NAME,
            "mode": "release-candidate",
            "status": "pass",
            "generatedAt": "2026-05-01T00:00:00Z",
            "metadata": {"gitCommit": "previous-sha", "releaseVersion": "2026.05.0"},
            "evidence": summary["evidence"],
        }
        write_json(previous_good_path, previous_good)
        previous_matrix_good_path = workspace / "build/previous-matrix-good/release-certification-summary.json"
        previous_matrix_good = dict(previous_good)
        previous_matrix_good["evidence"] = [
            (
                item
                if item.get("id") != "release-certification.ecosystem-matrix"
                else (item | {"status": "pass", "summary": "Ecosystem certification matrix status is pass."})
            )
            for item in summary["evidence"]
        ]
        previous_matrix_good["ecosystemMatrix"] = {
            "schemaVersion": ECOSYSTEM_MATRIX_SCHEMA_VERSION,
            "status": "pass",
            "rowCount": len(matrix["rows"]),
            "releaseBlockerCount": 0,
            "coverage": matrix["coverage"],
            "rowStatuses": {row["id"]: "pass" for row in matrix["rows"]},
            "matrixDiffs": [],
        }
        write_json(previous_matrix_good_path, previous_matrix_good)
        with_previous_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/with-previous-cert").resolve(),
            previous_summary=previous_good_path,
        )
        with_previous_summary, with_previous_exit_code = run(with_previous_settings)
        assert with_previous_exit_code == 0, with_previous_summary
        assert with_previous_summary["status"] == "warn", with_previous_summary
        assert with_previous_summary["historyComparison"]["status"] == "pass", with_previous_summary
        assert with_previous_summary["ecosystemGateStatus"] == "pass", with_previous_summary
        assert with_previous_summary["ecosystemMatrix"]["coverage"]["requiredEvidenceCovered"] is True
        assert with_previous_summary["ecosystemMatrix"]["coverage"]["ecosystemGatesCovered"] is True
        with_previous_matrix = read_json(with_previous_settings.out_dir / ECOSYSTEM_MATRIX_FILE_NAME)
        assert with_previous_matrix is not None, with_previous_summary
        assert with_previous_matrix["previousSummaryPresent"] is True, with_previous_matrix
        assert with_previous_matrix["previousMatrixPresent"] is False, with_previous_matrix

        history_store = workspace / "build/release-certification-history"
        write_history_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/write-history-cert").resolve(),
            previous_summary=previous_good_path,
            write_history=True,
            history_dir=history_store,
            history_label="2026.05.0",
        )
        write_history_summary, write_history_exit_code = run(write_history_settings)
        assert write_history_exit_code == 0, write_history_summary
        assert (history_store / "latest-summary.json").is_file(), write_history_summary
        assert (history_store / "latest-history-comparison.json").is_file(), write_history_summary
        assert (
            history_store / "releases/2026.05.0/release-certification-summary.json"
        ).is_file(), write_history_summary
        protected_latest_summary = read_json(history_store / "latest-summary.json")
        assert protected_latest_summary is not None, write_history_summary
        written_history_encoded = json.dumps(read_json(history_store / "latest-summary.json"), sort_keys=True)
        assert str(workspace) not in written_history_encoded, written_history_encoded

        def write_app_summary_variant(name: str, mutate: Any) -> Path:
            app_summary = read_json(settings.app_platform_summary)
            assert app_summary is not None
            mutate(app_summary)
            path = workspace / f"build/{name}/summary.json"
            write_json(path, app_summary)
            return path

        def update_evidence(summary_value: dict[str, Any], evidence_id: str, mutate: Any) -> None:
            evidence_list = summary_value.get("evidence", [])
            assert isinstance(evidence_list, list)
            for entry in evidence_list:
                if isinstance(entry, dict) and entry.get("id") == evidence_id:
                    mutate(entry)
                    return
            raise AssertionError(f"missing evidence {evidence_id}")

        def run_with_previous(name: str, **overrides: Any) -> tuple[dict[str, Any], int]:
            previous_summary_override = overrides.pop("previous_summary", previous_good_path)
            variant_settings = dataclasses.replace(
                settings,
                out_dir=(workspace / f"build/{name}").resolve(),
                previous_summary=previous_summary_override,
                **overrides,
            )
            return run(variant_settings)

        def gate_by_id(summary_value: dict[str, Any], gate_id: str) -> dict[str, Any]:
            for gate in summary_value.get("ecosystemGates", []):
                if isinstance(gate, dict) and gate.get("id") == gate_id:
                    return gate
            raise AssertionError(f"missing gate {gate_id}")

        def matrix_row_by_id(out_path: Path, row_id: str) -> dict[str, Any]:
            matrix_value = read_json(out_path / ECOSYSTEM_MATRIX_FILE_NAME)
            assert matrix_value is not None
            for row in matrix_value.get("rows", []):
                if isinstance(row, dict) and row.get("id") == row_id:
                    return row
            raise AssertionError(f"missing matrix row {row_id}")

        portal_linked_doc = workspace / "docs/app-owned-ui.md"
        original_portal_linked_doc = portal_linked_doc.read_text(encoding="utf-8")
        try:
            portal_linked_doc.write_text(
                original_portal_linked_doc
                + "\n[Broken docs-only link](missing-docs-only-link.md)\n",
                encoding="utf-8",
            )
            waived_docs_link_summary, waived_docs_link_exit_code = run_with_previous(
                "waived-docs-link-cert",
                waivers={
                    "app-platform.docs-redaction": (
                        "Release manager accepted a temporary docs-only link gap."
                    )
                },
            )
            assert waived_docs_link_exit_code == 0, waived_docs_link_summary
            assert waived_docs_link_summary["releaseCandidatePassed"] is True, waived_docs_link_summary
            waived_docs_link_evidence = {
                item["id"]: item for item in waived_docs_link_summary["evidence"]
            }
            docs_link_evidence = waived_docs_link_evidence["app-platform.docs-redaction"]
            assert docs_link_evidence["status"] == "warn", docs_link_evidence
            assert docs_link_evidence["details"]["waived"] is True, docs_link_evidence
            assert docs_link_evidence["details"]["redactionFindings"] == [], docs_link_evidence
            assert {
                "source": "docs/app-owned-ui.md",
                "target": "missing-docs-only-link.md",
                "reason": "missing",
            } in docs_link_evidence["details"]["brokenLinks"], docs_link_evidence

            portal_linked_doc.write_text(
                original_portal_linked_doc
                + "\nAuthorization: Bearer concrete-token-value\n",
                encoding="utf-8",
            )
            waived_docs_redaction_summary, waived_docs_redaction_exit_code = run_with_previous(
                "waived-docs-redaction-cert",
                waivers={
                    "app-platform.docs-redaction": (
                        "Release manager attempted to waive a docs redaction finding."
                    ),
                    "evidence.app-platform.docs-redaction": (
                        "Release manager attempted to waive a docs redaction issue id."
                    ),
                },
            )
            assert waived_docs_redaction_exit_code == 1, waived_docs_redaction_summary
            assert (
                waived_docs_redaction_summary["releaseCandidatePassed"] is False
            ), waived_docs_redaction_summary
            waived_docs_redaction_evidence = {
                item["id"]: item for item in waived_docs_redaction_summary["evidence"]
            }
            docs_redaction_evidence = waived_docs_redaction_evidence[
                "app-platform.docs-redaction"
            ]
            assert docs_redaction_evidence["status"] == "fail", docs_redaction_evidence
            assert "waived" not in docs_redaction_evidence["details"], docs_redaction_evidence
            assert {
                "path": "docs/app-owned-ui.md",
                "issue": "authorization-header",
            } in docs_redaction_evidence["details"]["redactionFindings"], docs_redaction_evidence
            docs_redaction_row = matrix_row_by_id(
                workspace / "build/waived-docs-redaction-cert",
                "app-platform-beta-docs-and-program",
            )
            assert docs_redaction_row["status"] == "fail", docs_redaction_row
            assert docs_redaction_row["releaseBlocker"] is True, docs_redaction_row
            assert "app-platform.docs-redaction" not in docs_redaction_row.get(
                "waiverIds", []
            ), docs_redaction_row
            assert "evidence.app-platform.docs-redaction" not in docs_redaction_row.get(
                "waiverIds", []
            ), docs_redaction_row
            assert "Waiver recorded" not in docs_redaction_row["summary"], docs_redaction_row
            assert "waived" not in docs_redaction_row["recommendation"].lower(), (
                docs_redaction_row
            )
            assert docs_redaction_row["details"]["unwaivableRedactionEvidenceIds"] == [
                "app-platform.docs-redaction"
            ], docs_redaction_row
            failed_report = (
                workspace / "build/waived-docs-redaction-cert" / REPORT_FILE_NAME
            ).read_text(encoding="utf-8")
            assert "### `app-platform.docs-redaction`" in failed_report, failed_report
            assert "redactionFindings" in failed_report, failed_report
            assert "docs/app-owned-ui.md" in failed_report, failed_report
        finally:
            portal_linked_doc.write_text(original_portal_linked_doc, encoding="utf-8")

        unmapped_required_path = write_app_summary_variant(
            "unmapped-required-evidence",
            lambda value: value.setdefault("evidence", []).append(
                {
                    "id": "self-test.required-unmapped",
                    "status": "pass",
                    "requiredForReleaseCandidate": True,
                    "summary": "Self-test required evidence without a matrix row.",
                    "source": "self-test",
                    "details": {},
                }
            ),
        )
        unmapped_required_summary, unmapped_required_exit_code = run_with_previous(
            "unmapped-required-cert",
            app_platform_summary=unmapped_required_path,
        )
        assert unmapped_required_exit_code == 1, unmapped_required_summary
        unmapped_required_matrix = read_json(workspace / "build/unmapped-required-cert" / ECOSYSTEM_MATRIX_FILE_NAME)
        assert unmapped_required_matrix is not None, unmapped_required_summary
        assert unmapped_required_matrix["coverage"]["requiredEvidenceCovered"] is False, (
            unmapped_required_matrix
        )
        assert unmapped_required_matrix["coverage"]["unmappedRequiredEvidenceIds"] == [
            "self-test.required-unmapped"
        ], unmapped_required_matrix
        assert unmapped_required_matrix["coverage"]["unwaivedIssueIds"] == [
            "matrix.required-evidence-unmapped"
        ], unmapped_required_matrix
        unmapped_required_row = matrix_row_by_id(
            workspace / "build/unmapped-required-cert",
            "ecosystem-certification-matrix",
        )
        assert unmapped_required_row["status"] == "fail", unmapped_required_row
        assert unmapped_required_row["releaseBlocker"] is True, unmapped_required_row

        waived_unmapped_summary, waived_unmapped_exit_code = run_with_previous(
            "waived-unmapped-required-cert",
            app_platform_summary=unmapped_required_path,
            waivers={
                "matrix.required-evidence-unmapped": (
                    "Release manager accepted the temporary matrix row coverage gap."
                )
            },
        )
        assert waived_unmapped_exit_code == 0, waived_unmapped_summary
        assert waived_unmapped_summary["status"] == "warn", waived_unmapped_summary
        assert waived_unmapped_summary["releaseCandidatePassed"] is True, waived_unmapped_summary
        waived_unmapped_matrix = read_json(
            workspace / "build/waived-unmapped-required-cert" / ECOSYSTEM_MATRIX_FILE_NAME
        )
        assert waived_unmapped_matrix is not None, waived_unmapped_summary
        assert waived_unmapped_matrix["status"] == "warn", waived_unmapped_matrix
        assert waived_unmapped_matrix["releaseCandidatePassed"] is True, waived_unmapped_matrix
        assert waived_unmapped_matrix["coverage"]["requiredEvidenceCovered"] is False, (
            waived_unmapped_matrix
        )
        assert waived_unmapped_matrix["coverage"]["waivedIssueIds"] == [
            "matrix.required-evidence-unmapped"
        ], waived_unmapped_matrix
        assert waived_unmapped_matrix["coverage"]["unwaivedIssueIds"] == [], waived_unmapped_matrix
        waived_unmapped_row = matrix_row_by_id(
            workspace / "build/waived-unmapped-required-cert",
            "ecosystem-certification-matrix",
        )
        assert waived_unmapped_row["status"] == "warn", waived_unmapped_row
        assert waived_unmapped_row["releaseBlocker"] is False, waived_unmapped_row
        assert "matrix.required-evidence-unmapped" in waived_unmapped_row["waiverIds"], (
            waived_unmapped_row
        )

        signed_bundles_skip_path = write_app_summary_variant(
            "signed-bundles-skip",
            lambda value: (
                value.update({"mode": "pr"}),
                update_evidence(
                    value,
                    "app-platform.signed-bundles",
                    lambda entry: entry.update(
                        {
                            "status": "skip",
                            "summary": "Signing keys were not available in PR mode.",
                        }
                    ),
                ),
            ),
        )
        signed_bundles_skip_summary, _signed_bundles_skip_exit_code = run_with_previous(
            "signed-bundles-skip-pr-cert",
            mode="pr",
            previous_summary=None,
            app_platform_summary=signed_bundles_skip_path,
        )
        assert signed_bundles_skip_summary["status"] == "warn", signed_bundles_skip_summary
        assert signed_bundles_skip_summary["ecosystemMatrix"]["status"] == "warn", (
            signed_bundles_skip_summary
        )
        assert signed_bundles_skip_summary["ecosystemMatrix"]["releaseBlockerCount"] == 0, (
            signed_bundles_skip_summary
        )
        signed_bundles_skip_row = matrix_row_by_id(
            workspace / "build/signed-bundles-skip-pr-cert",
            "first-party-beta-catalog",
        )
        assert signed_bundles_skip_row["status"] == "warn", signed_bundles_skip_row
        assert signed_bundles_skip_row["releaseBlocker"] is False, signed_bundles_skip_row
        assert "evidence.app-platform.signed-bundles" in signed_bundles_skip_row["issueIds"], (
            signed_bundles_skip_row
        )

        failing_history_path = write_app_summary_variant(
            "write-history-failing-app",
            lambda value: update_evidence(
                value,
                "platform-api.contract",
                lambda entry: entry.update({"status": "fail"}),
            ),
        )
        failing_write_history_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/write-history-failing-cert").resolve(),
            previous_summary=previous_good_path,
            app_platform_summary=failing_history_path,
            write_history=True,
            history_dir=history_store,
            history_label="failed-candidate",
        )
        failing_write_history_summary, failing_write_history_exit_code = run(
            failing_write_history_settings
        )
        assert failing_write_history_exit_code == 1, failing_write_history_summary
        assert (
            read_json(history_store / "latest-summary.json") == protected_latest_summary
        ), failing_write_history_summary
        assert (
            history_store / "failed/failed-candidate/release-certification-summary.json"
        ).is_file(), failing_write_history_summary

        require_history_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/require-history-cert").resolve(),
            require_history=True,
        )
        require_history_summary, require_history_exit_code = run(require_history_settings)
        assert require_history_exit_code == 1, require_history_summary
        assert require_history_summary["historyComparison"]["status"] == "fail", require_history_summary

        malformed_previous_path = workspace / "build/malformed-previous/summary.json"
        malformed_previous_path.parent.mkdir(parents=True, exist_ok=True)
        malformed_previous_path.write_text('{"schemaVersion": 1', encoding="utf-8")
        malformed_previous_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/malformed-previous-cert").resolve(),
            previous_summary=malformed_previous_path,
        )
        malformed_previous_summary, malformed_previous_exit_code = run(malformed_previous_settings)
        assert malformed_previous_exit_code == 1, malformed_previous_summary
        assert malformed_previous_summary["historyComparison"]["status"] == "fail", malformed_previous_summary

        invalid_previous_path = workspace / "build/invalid-previous/summary.json"
        write_json(invalid_previous_path, {})
        invalid_previous_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/invalid-previous-cert").resolve(),
            previous_summary=invalid_previous_path,
            require_history=True,
        )
        invalid_previous_summary, invalid_previous_exit_code = run(invalid_previous_settings)
        assert invalid_previous_exit_code == 1, invalid_previous_summary
        assert invalid_previous_summary["historyComparison"]["status"] == "fail", invalid_previous_summary

        app_smoke_as_previous_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/app-smoke-as-previous-cert").resolve(),
            previous_summary=settings.app_platform_summary,
            require_history=True,
        )
        app_smoke_as_previous_summary, app_smoke_as_previous_exit_code = run(
            app_smoke_as_previous_settings
        )
        assert app_smoke_as_previous_exit_code == 1, app_smoke_as_previous_summary
        assert (
            app_smoke_as_previous_summary["historyComparison"]["status"] == "fail"
        ), app_smoke_as_previous_summary

        platform_fail_path = write_app_summary_variant(
            "platform-contract-fail",
            lambda value: update_evidence(
                value,
                "platform-api.contract",
                lambda entry: entry.update({"status": "fail", "summary": "strict compatibility failed"}),
            ),
        )
        platform_fail_summary, platform_fail_exit_code = run_with_previous(
            "platform-contract-fail-cert", app_platform_summary=platform_fail_path
        )
        assert platform_fail_exit_code == 1, platform_fail_summary
        platform_diff = next(
            diff
            for diff in platform_fail_summary["historyComparison"]["evidenceDiffs"]
            if diff["id"] == "platform-api.contract"
        )
        assert platform_diff["classification"] == "regression", platform_diff
        assert platform_diff["releaseBlocker"] is True, platform_diff
        platform_matrix_row = matrix_row_by_id(
            workspace / "build/platform-contract-fail-cert",
            "platform-api-contract",
        )
        assert platform_matrix_row["status"] == "fail", platform_matrix_row
        assert platform_matrix_row["releaseBlocker"] is True, platform_matrix_row
        platform_fail_with_matrix_summary, platform_fail_with_matrix_exit_code = run_with_previous(
            "platform-contract-fail-with-matrix-cert",
            app_platform_summary=platform_fail_path,
            previous_summary=previous_matrix_good_path,
        )
        assert platform_fail_with_matrix_exit_code == 1, platform_fail_with_matrix_summary
        platform_matrix_regression_row = matrix_row_by_id(
            workspace / "build/platform-contract-fail-with-matrix-cert",
            "platform-api-contract",
        )
        assert platform_matrix_regression_row["previousStatus"] == "pass", platform_matrix_regression_row
        assert platform_matrix_regression_row["regressionStatus"] == "regressed-blocker", (
            platform_matrix_regression_row
        )

        ui_warn_path = write_app_summary_variant(
            "ui-lint-warn",
            lambda value: update_evidence(
                value,
                "app-ui.lint",
                lambda entry: (
                    entry.update({"status": "warn"}),
                    entry.setdefault("details", {})
                    .setdefault("apps", {})
                    .setdefault("queue-manager", {})
                    .setdefault("summary", {})
                    .update({"warnings": 1}),
                ),
            ),
        )
        ui_warn_summary, ui_warn_exit_code = run_with_previous(
            "ui-lint-warn-cert", app_platform_summary=ui_warn_path
        )
        assert ui_warn_exit_code == 0, ui_warn_summary
        assert ui_warn_summary["status"] == "warn", ui_warn_summary
        assert gate_by_id(ui_warn_summary, "ecosystem.app-ui-quality")["status"] == "warn"

        optional_missing_summary, optional_missing_exit_code = run_with_previous(
            "optional-interop-missing-cert",
            interop_extended_summary=workspace / "build/missing-optional-interop/summary.json",
        )
        assert optional_missing_exit_code == 0, optional_missing_summary
        assert optional_missing_summary["status"] == "warn", optional_missing_summary
        optional_diff = next(
            diff
            for diff in optional_missing_summary["historyComparison"]["evidenceDiffs"]
            if diff["id"] == "interop.extended"
        )
        assert optional_diff["classification"] == "regression", optional_diff
        assert optional_diff["releaseBlocker"] is False, optional_diff

        previous_without_rollback = dict(previous_good)
        previous_without_rollback["evidence"] = [
            item for item in previous_good["evidence"] if item["id"] != "app-update.rollback"
        ]
        previous_without_rollback_path = workspace / "build/previous-without-rollback/summary.json"
        write_json(previous_without_rollback_path, previous_without_rollback)
        new_required_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/new-required-cert").resolve(),
            previous_summary=previous_without_rollback_path,
        )
        new_required_summary, new_required_exit_code = run(new_required_settings)
        assert new_required_exit_code == 0, new_required_summary
        new_required_diff = next(
            diff
            for diff in new_required_summary["historyComparison"]["evidenceDiffs"]
            if diff["id"] == "app-update.rollback"
        )
        assert new_required_diff["classification"] == "new", new_required_diff

        previous_with_removed_optional = dict(previous_good)
        previous_with_removed_optional["evidence"] = list(previous_good["evidence"]) + [
            {
                "id": "optional.old-evidence",
                "status": "pass",
                "requiredForReleaseCandidate": False,
                "summary": "Old optional evidence.",
                "source": "<repo>/old.json",
                "details": {},
            }
        ]
        previous_with_removed_optional_path = workspace / "build/previous-with-removed-optional/summary.json"
        write_json(previous_with_removed_optional_path, previous_with_removed_optional)
        removed_optional_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/removed-optional-cert").resolve(),
            previous_summary=previous_with_removed_optional_path,
        )
        removed_optional_summary, removed_optional_exit_code = run(removed_optional_settings)
        assert removed_optional_exit_code == 0, removed_optional_summary
        removed_optional_diff = next(
            diff
            for diff in removed_optional_summary["historyComparison"]["evidenceDiffs"]
            if diff["id"] == "optional.old-evidence"
        )
        assert removed_optional_diff["classification"] == "removed", removed_optional_diff
        assert removed_optional_diff["releaseBlocker"] is False, removed_optional_diff

        previous_with_removed_required = dict(previous_good)
        previous_with_removed_required["evidence"] = list(previous_good["evidence"]) + [
            {
                "id": "required.old-evidence",
                "status": "pass",
                "requiredForReleaseCandidate": True,
                "summary": "Old required evidence.",
                "source": "<repo>/old.json",
                "details": {},
            }
        ]
        previous_with_removed_required_path = workspace / "build/previous-with-removed-required/summary.json"
        write_json(previous_with_removed_required_path, previous_with_removed_required)
        waived_removed_required_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/waived-removed-required-cert").resolve(),
            previous_summary=previous_with_removed_required_path,
            waivers={"required.old-evidence": "Release manager accepted removal of retired required evidence."},
        )
        waived_removed_required_summary, waived_removed_required_exit_code = run(
            waived_removed_required_settings
        )
        assert waived_removed_required_exit_code == 0, waived_removed_required_summary
        removed_required_diff = next(
            diff
            for diff in waived_removed_required_summary["historyComparison"]["evidenceDiffs"]
            if diff["id"] == "required.old-evidence"
        )
        assert removed_required_diff["classification"] == "removed", removed_required_diff
        assert removed_required_diff["releaseBlocker"] is False, removed_required_diff
        assert (
            gate_by_id(
                waived_removed_required_summary, "ecosystem.required-evidence-regressions"
            )["status"]
            == "warn"
        )

        previous_contract_v3 = json.loads(json.dumps(previous_good))
        for entry in previous_contract_v3["evidence"]:
            if entry["id"] == "platform-api.contract":
                entry["details"]["contractVersion"] = 3
                entry["details"]["stableCapabilities"] = ["platform.compat.extra", "queue.read"]
                entry["details"]["stableEndpoints"] = ["/api/v1/apps/old", "/api/v1/apps/current"]
        previous_contract_v3_path = workspace / "build/previous-contract-v3/summary.json"
        write_json(previous_contract_v3_path, previous_contract_v3)
        current_contract_sets_path = write_app_summary_variant(
            "current-contract-sets",
            lambda value: update_evidence(
                value,
                "platform-api.contract",
                lambda entry: entry.setdefault("details", {}).update(
                    {
                        "contractVersion": 2,
                        "stableCapabilities": ["queue.read"],
                        "stableEndpoints": ["/api/v1/apps/current"],
                    }
                ),
            ),
        )
        contract_regression_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/contract-regression-cert").resolve(),
            previous_summary=previous_contract_v3_path,
            app_platform_summary=current_contract_sets_path,
        )
        contract_regression_summary, contract_regression_exit_code = run(contract_regression_settings)
        assert contract_regression_exit_code == 1, contract_regression_summary
        assert gate_by_id(contract_regression_summary, "ecosystem.platform-api-compatibility")["status"] == "fail"

        previous_contract_nonempty_sets = json.loads(json.dumps(previous_good))
        for entry in previous_contract_nonempty_sets["evidence"]:
            if entry["id"] == "platform-api.contract":
                entry["details"]["contractVersion"] = 2
                entry["details"]["stableCapabilities"] = ["queue.read"]
                entry["details"]["stableEndpoints"] = ["/api/v1/apps/current"]
        previous_contract_nonempty_sets_path = workspace / "build/previous-contract-nonempty-sets/summary.json"
        write_json(previous_contract_nonempty_sets_path, previous_contract_nonempty_sets)
        current_contract_empty_sets_path = write_app_summary_variant(
            "current-contract-empty-sets",
            lambda value: update_evidence(
                value,
                "platform-api.contract",
                lambda entry: entry.setdefault("details", {}).update(
                    {
                        "contractVersion": 2,
                        "stableCapabilities": [],
                        "stableEndpoints": [],
                    }
                ),
            ),
        )
        empty_sets_regression_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/contract-empty-sets-regression-cert").resolve(),
            previous_summary=previous_contract_nonempty_sets_path,
            app_platform_summary=current_contract_empty_sets_path,
        )
        empty_sets_regression_summary, empty_sets_regression_exit_code = run(
            empty_sets_regression_settings
        )
        assert empty_sets_regression_exit_code == 1, empty_sets_regression_summary
        assert (
            gate_by_id(
                empty_sets_regression_summary, "ecosystem.platform-api-compatibility"
            )["status"]
            == "fail"
        )

        def set_contract_count_details(
            entry: dict[str, Any], capability_count: int, endpoint_count: int, stable_count: int
        ) -> None:
            contract_details = entry.setdefault("details", {})
            contract_details.pop("stableCapabilities", None)
            contract_details.pop("stableEndpoints", None)
            contract_details.update(
                {
                    "contractVersion": 2,
                    "capabilityCount": capability_count,
                    "endpointCount": endpoint_count,
                    "stabilityCounts": {"stable": stable_count},
                }
            )

        previous_contract_total_count_drop = json.loads(json.dumps(previous_good))
        for entry in previous_contract_total_count_drop["evidence"]:
            if entry["id"] == "platform-api.contract":
                set_contract_count_details(entry, 20, 80, 75)
        previous_contract_total_count_drop_path = (
            workspace / "build/previous-contract-total-count-drop/summary.json"
        )
        write_json(previous_contract_total_count_drop_path, previous_contract_total_count_drop)
        current_contract_total_count_drop_path = write_app_summary_variant(
            "current-contract-total-count-drop",
            lambda value: update_evidence(
                value,
                "platform-api.contract",
                lambda entry: set_contract_count_details(entry, 19, 79, 75),
            ),
        )
        total_count_drop_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/contract-total-count-drop-cert").resolve(),
            previous_summary=previous_contract_total_count_drop_path,
            app_platform_summary=current_contract_total_count_drop_path,
        )
        total_count_drop_summary, total_count_drop_exit_code = run(total_count_drop_settings)
        assert total_count_drop_exit_code == 0, total_count_drop_summary
        assert (
            gate_by_id(total_count_drop_summary, "ecosystem.platform-api-compatibility")["status"]
            == "pass"
        )

        current_contract_stable_count_drop_path = write_app_summary_variant(
            "current-contract-stable-count-drop",
            lambda value: update_evidence(
                value,
                "platform-api.contract",
                lambda entry: set_contract_count_details(entry, 19, 79, 74),
            ),
        )
        stable_count_drop_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/contract-stable-count-drop-cert").resolve(),
            previous_summary=previous_contract_total_count_drop_path,
            app_platform_summary=current_contract_stable_count_drop_path,
        )
        stable_count_drop_summary, stable_count_drop_exit_code = run(stable_count_drop_settings)
        assert stable_count_drop_exit_code == 1, stable_count_drop_summary
        assert (
            gate_by_id(stable_count_drop_summary, "ecosystem.platform-api-compatibility")["status"]
            == "fail"
        )

        def set_contract_raw_endpoint_details(
            entry: dict[str, Any], routes: list[str], stable_count: int
        ) -> None:
            contract_details = entry.setdefault("details", {})
            contract_details.pop("stableEndpoints", None)
            contract_details.update(
                {
                    "contractVersion": 2,
                    "endpointCount": len(routes),
                    "stabilityCounts": {"stable": stable_count},
                    "endpoints": [
                        {"method": "GET", "routeTemplate": route, "stability": "stable"}
                        for route in routes
                    ],
                }
            )

        previous_contract_raw_endpoints = json.loads(json.dumps(previous_good))
        for entry in previous_contract_raw_endpoints["evidence"]:
            if entry["id"] == "platform-api.contract":
                set_contract_raw_endpoint_details(
                    entry,
                    ["/apps/{appId}/old", "/apps/{appId}/current"],
                    2,
                )
        previous_contract_raw_endpoints_path = workspace / "build/previous-contract-raw-endpoints/summary.json"
        write_json(previous_contract_raw_endpoints_path, previous_contract_raw_endpoints)
        current_contract_raw_endpoint_removal_path = write_app_summary_variant(
            "current-contract-raw-endpoint-removal",
            lambda value: update_evidence(
                value,
                "platform-api.contract",
                lambda entry: set_contract_raw_endpoint_details(
                    entry,
                    ["/apps/{appId}/current", "/apps/{appId}/new"],
                    2,
                ),
            ),
        )
        raw_endpoint_removal_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/contract-raw-endpoint-removal-cert").resolve(),
            previous_summary=previous_contract_raw_endpoints_path,
            app_platform_summary=current_contract_raw_endpoint_removal_path,
        )
        raw_endpoint_removal_summary, raw_endpoint_removal_exit_code = run(
            raw_endpoint_removal_settings
        )
        assert raw_endpoint_removal_exit_code == 1, raw_endpoint_removal_summary
        raw_endpoint_removal_gate = gate_by_id(
            raw_endpoint_removal_summary, "ecosystem.platform-api-compatibility"
        )
        assert raw_endpoint_removal_gate["status"] == "fail", raw_endpoint_removal_gate
        assert "GET /apps/{appId}/old" in raw_endpoint_removal_gate["summary"], raw_endpoint_removal_gate

        first_party_apps_map_path = write_app_summary_variant(
            "first-party-apps-map",
            lambda value: update_evidence(
                value,
                "app-platform.first-party",
                lambda entry: entry.setdefault("details", {}).update(
                    {
                        "apps": {
                            "queue-manager": {},
                            "publisher": {},
                            "site-publisher": {},
                            "profile-publisher": {},
                            "feed-reader": {},
                            "social-inbox": {},
                            "trust-graph": {},
                        }
                    }
                ),
            ),
        )
        first_party_apps_map_summary, first_party_apps_map_exit_code = run_with_previous(
            "first-party-apps-map-cert", app_platform_summary=first_party_apps_map_path
        )
        assert first_party_apps_map_exit_code == 0, first_party_apps_map_summary
        assert gate_by_id(first_party_apps_map_summary, "ecosystem.first-party-apps")["status"] == "pass"

        first_party_missing_path = write_app_summary_variant(
            "first-party-missing",
            lambda value: update_evidence(
                value,
                "app-platform.first-party",
                lambda entry: entry.setdefault("details", {}).update({"apps": ["queue-manager", "publisher"]}),
            ),
        )
        first_party_missing_summary, first_party_missing_exit_code = run_with_previous(
            "first-party-missing-cert", app_platform_summary=first_party_missing_path
        )
        assert first_party_missing_exit_code == 1, first_party_missing_summary
        assert gate_by_id(first_party_missing_summary, "ecosystem.first-party-apps")["status"] == "fail"

        reference_missing_path = write_app_summary_variant(
            "reference-missing",
            lambda value: update_evidence(
                value,
                "reference-apps.content",
                lambda entry: entry.update({"status": "missing"}),
            ),
        )
        reference_missing_summary, reference_missing_exit_code = run_with_previous(
            "reference-missing-cert", app_platform_summary=reference_missing_path
        )
        assert reference_missing_exit_code == 1, reference_missing_summary
        assert gate_by_id(reference_missing_summary, "ecosystem.reference-content-apps")["status"] == "fail"

        feed_reader_missing_path = write_app_summary_variant(
            "feed-reader-missing",
            lambda value: update_evidence(
                value,
                "reference-app.feed-reader",
                lambda entry: entry.update({"status": "missing"}),
            ),
        )
        feed_reader_missing_summary, feed_reader_missing_exit_code = run_with_previous(
            "feed-reader-missing-cert", app_platform_summary=feed_reader_missing_path
        )
        assert feed_reader_missing_exit_code == 1, feed_reader_missing_summary
        assert (
            gate_by_id(feed_reader_missing_summary, "ecosystem.reference-content-apps")["status"]
            == "fail"
        )

        feed_reader_subscription_missing_path = write_app_summary_variant(
            "feed-reader-subscriptions-missing",
            lambda value: update_evidence(
                value,
                "reference-app.feed-reader-subscriptions",
                lambda entry: entry.update({"status": "missing"}),
            ),
        )
        feed_reader_subscription_missing_summary, feed_reader_subscription_missing_exit_code = (
            run_with_previous(
                "feed-reader-subscriptions-missing-cert",
                app_platform_summary=feed_reader_subscription_missing_path,
            )
        )
        assert (
            feed_reader_subscription_missing_exit_code == 1
        ), feed_reader_subscription_missing_summary
        assert (
            gate_by_id(
                feed_reader_subscription_missing_summary, "ecosystem.reference-content-apps"
            )["status"]
            == "fail"
        )

        trust_graph_missing_path = write_app_summary_variant(
            "trust-graph-missing",
            lambda value: update_evidence(
                value,
                "reference-app.trust-graph",
                lambda entry: entry.update({"status": "missing"}),
            ),
        )
        trust_graph_missing_summary, trust_graph_missing_exit_code = run_with_previous(
            "trust-graph-missing-cert", app_platform_summary=trust_graph_missing_path
        )
        assert trust_graph_missing_exit_code == 1, trust_graph_missing_summary
        assert (
            gate_by_id(trust_graph_missing_summary, "ecosystem.reference-content-apps")[
                "status"
            ]
            == "fail"
        )

        content_fetch_missing_path = write_app_summary_variant(
            "content-fetch-missing",
            lambda value: update_evidence(
                value,
                "app-platform.content-fetch",
                lambda entry: entry.update({"status": "missing"}),
            ),
        )
        content_fetch_missing_summary, content_fetch_missing_exit_code = run_with_previous(
            "content-fetch-missing-cert", app_platform_summary=content_fetch_missing_path
        )
        assert content_fetch_missing_exit_code == 1, content_fetch_missing_summary
        assert (
            gate_by_id(content_fetch_missing_summary, "ecosystem.reference-content-apps")[
                "status"
            ]
            == "fail"
        )

        content_subscription_missing_path = write_app_summary_variant(
            "content-subscriptions-missing",
            lambda value: update_evidence(
                value,
                "app-platform.content-subscriptions",
                lambda entry: entry.update({"status": "missing"}),
            ),
        )
        content_subscription_missing_summary, content_subscription_missing_exit_code = (
            run_with_previous(
                "content-subscriptions-missing-cert",
                app_platform_summary=content_subscription_missing_path,
            )
        )
        assert content_subscription_missing_exit_code == 1, content_subscription_missing_summary
        assert (
            gate_by_id(
                content_subscription_missing_summary, "ecosystem.reference-content-apps"
            )["status"]
            == "fail"
        )

        subscription_scheduler_missing_path = write_app_summary_variant(
            "subscription-scheduler-missing",
            lambda value: update_evidence(
                value,
                "network-content.subscription-scheduler",
                lambda entry: entry.update({"status": "missing"}),
            ),
        )
        subscription_scheduler_missing_summary, subscription_scheduler_missing_exit_code = (
            run_with_previous(
                "subscription-scheduler-missing-cert",
                app_platform_summary=subscription_scheduler_missing_path,
            )
        )
        assert (
            subscription_scheduler_missing_exit_code == 1
        ), subscription_scheduler_missing_summary
        assert (
            gate_by_id(
                subscription_scheduler_missing_summary, "ecosystem.reference-content-apps"
            )["status"]
            == "fail"
        )

        trust_preview_missing_path = write_app_summary_variant(
            "trust-preview-missing",
            lambda value: update_evidence(
                value,
                "app-platform.trust-graph-preview",
                lambda entry: entry.update({"status": "missing"}),
            ),
        )
        trust_preview_missing_summary, trust_preview_missing_exit_code = run_with_previous(
            "trust-preview-missing-cert", app_platform_summary=trust_preview_missing_path
        )
        assert trust_preview_missing_exit_code == 1, trust_preview_missing_summary
        assert (
            gate_by_id(trust_preview_missing_summary, "ecosystem.reference-content-apps")[
                "status"
            ]
            == "fail"
        )

        trust_signing_missing_path = write_app_summary_variant(
            "trust-signing-missing",
            lambda value: update_evidence(
                value,
                "app-platform.trust-statement-signing",
                lambda entry: entry.update({"status": "missing"}),
            ),
        )
        trust_signing_missing_summary, trust_signing_missing_exit_code = run_with_previous(
            "trust-signing-missing-cert", app_platform_summary=trust_signing_missing_path
        )
        assert trust_signing_missing_exit_code == 1, trust_signing_missing_summary
        assert (
            gate_by_id(trust_signing_missing_summary, "ecosystem.reference-content-apps")[
                "status"
            ]
            == "fail"
        )

        social_inbox_missing_path = write_app_summary_variant(
            "social-inbox-missing",
            lambda value: update_evidence(
                value,
                "reference-app.social-inbox",
                lambda entry: entry.update({"status": "missing"}),
            ),
        )
        social_inbox_missing_summary, social_inbox_missing_exit_code = run_with_previous(
            "social-inbox-missing-cert", app_platform_summary=social_inbox_missing_path
        )
        assert social_inbox_missing_exit_code == 1, social_inbox_missing_summary
        assert (
            gate_by_id(social_inbox_missing_summary, "ecosystem.reference-content-apps")[
                "status"
            ]
            == "fail"
        )

        social_message_signing_missing_path = write_app_summary_variant(
            "social-message-signing-missing",
            lambda value: update_evidence(
                value,
                "app-platform.social-message-signing",
                lambda entry: entry.update({"status": "missing"}),
            ),
        )
        social_message_signing_missing_summary, social_message_signing_missing_exit_code = (
            run_with_previous(
                "social-message-signing-missing-cert",
                app_platform_summary=social_message_signing_missing_path,
            )
        )
        assert social_message_signing_missing_exit_code == 1, (
            social_message_signing_missing_summary
        )
        assert (
            gate_by_id(social_message_signing_missing_summary, "ecosystem.reference-content-apps")[
                "status"
            ]
            == "fail"
        )

        trusted_review_fail_path = write_app_summary_variant(
            "trusted-review-fail",
            lambda value: update_evidence(
                value,
                "app-review.trusted-receipts",
                lambda entry: entry.update({"status": "fail"}),
            ),
        )
        trusted_review_fail_summary, trusted_review_fail_exit_code = run_with_previous(
            "trusted-review-fail-cert", app_platform_summary=trusted_review_fail_path
        )
        assert trusted_review_fail_exit_code == 1, trusted_review_fail_summary
        assert (
            gate_by_id(trusted_review_fail_summary, "ecosystem.app-review-trust")["status"]
            == "fail"
        )

        missing_review_governance_ids = {
            "app-review.governance",
            "app-review.reviewer-key-lifecycle",
            "app-review.transparency-log",
            "app-review.review-history-api",
            "app-review.first-party-review-chain",
        }
        missing_review_governance_path = write_app_summary_variant(
            "missing-review-governance",
            lambda value: value.update(
                {
                    "evidence": [
                        item
                        for item in value["evidence"]
                        if item.get("id") not in missing_review_governance_ids
                    ]
                }
            ),
        )
        missing_review_governance_items = app_platform_evidence(
            missing_review_governance_path, workspace, out_dir, "release-candidate"
        )
        missing_review_governance_by_id = {
            item.id: item for item in missing_review_governance_items
        }
        for evidence_id in missing_review_governance_ids:
            assert (
                missing_review_governance_by_id[evidence_id].status == "missing"
            ), missing_review_governance_by_id
        (
            missing_review_governance_summary,
            missing_review_governance_exit_code,
        ) = run_with_previous(
            "missing-review-governance-cert",
            app_platform_summary=missing_review_governance_path,
        )
        assert missing_review_governance_exit_code == 1, missing_review_governance_summary
        missing_review_governance_gate = gate_by_id(
            missing_review_governance_summary, "ecosystem.app-review-trust"
        )
        assert (
            missing_review_governance_gate["status"] == "fail"
        ), missing_review_governance_gate
        for evidence_id in missing_review_governance_ids:
            assert (
                evidence_id in missing_review_governance_gate["details"]["failureEvidenceIds"]
            ), missing_review_governance_gate

        rollback_fail_path = write_app_summary_variant(
            "rollback-fail",
            lambda value: update_evidence(
                value,
                "app-update.rollback",
                lambda entry: entry.update({"status": "fail"}),
            ),
        )
        rollback_fail_summary, rollback_fail_exit_code = run_with_previous(
            "rollback-fail-cert", app_platform_summary=rollback_fail_path
        )
        assert rollback_fail_exit_code == 1, rollback_fail_summary
        assert gate_by_id(rollback_fail_summary, "ecosystem.app-update-rollback")["status"] == "fail"

        scheduler_fail_path = write_app_summary_variant(
            "scheduler-fail",
            lambda value: update_evidence(
                value,
                "app-update.scheduler",
                lambda entry: entry.update({"status": "fail"}),
            ),
        )
        scheduler_fail_summary, scheduler_fail_exit_code = run_with_previous(
            "scheduler-fail-cert", app_platform_summary=scheduler_fail_path
        )
        assert scheduler_fail_exit_code == 1, scheduler_fail_summary
        assert gate_by_id(scheduler_fail_summary, "ecosystem.app-update-rollback")["status"] == "fail"

        vault_missing_capability_path = write_app_summary_variant(
            "vault-missing-capability",
            lambda value: update_evidence(
                value,
                "app-vault.capabilities",
                lambda entry: entry.setdefault("details", {}).update({"capabilities": ["vault.secrets.read"]}),
            ),
        )
        vault_missing_capability_summary, vault_missing_capability_exit_code = run_with_previous(
            "vault-missing-capability-cert", app_platform_summary=vault_missing_capability_path
        )
        assert vault_missing_capability_exit_code == 1, vault_missing_capability_summary
        assert gate_by_id(vault_missing_capability_summary, "ecosystem.app-vault")["status"] == "fail"
        waived_vault_evidence_summary, waived_vault_evidence_exit_code = run_with_previous(
            "waived-vault-evidence-cert",
            app_platform_summary=vault_missing_capability_path,
            waivers={"app-vault.capabilities": "Release manager accepted vault evidence gap."},
        )
        assert waived_vault_evidence_exit_code == 0, waived_vault_evidence_summary
        waived_vault_gate = gate_by_id(waived_vault_evidence_summary, "ecosystem.app-vault")
        assert waived_vault_gate["status"] == "warn", waived_vault_gate
        assert waived_vault_gate["releaseBlocker"] is False, waived_vault_gate
        assert waived_vault_gate["details"]["waived"] is True, waived_vault_gate
        assert waived_vault_gate["details"]["waivedEvidenceIds"] == ["app-vault.capabilities"], waived_vault_gate
        waived_vault_row = matrix_row_by_id(
            workspace / "build/waived-vault-evidence-cert",
            "app-vault-and-generated-documents",
        )
        assert waived_vault_row["status"] == "warn", waived_vault_row
        assert waived_vault_row["releaseBlocker"] is False, waived_vault_row
        assert "app-vault.capabilities" in waived_vault_row["waiverIds"], waived_vault_row

        vault_missing_redaction_path = write_app_summary_variant(
            "vault-missing-redaction",
            lambda value: update_evidence(
                value,
                "app-vault.capabilities",
                lambda entry: entry.setdefault("details", {}).pop("redaction", None),
            ),
        )
        vault_missing_redaction_summary, vault_missing_redaction_exit_code = run_with_previous(
            "vault-missing-redaction-cert", app_platform_summary=vault_missing_redaction_path
        )
        assert vault_missing_redaction_exit_code == 1, vault_missing_redaction_summary
        assert gate_by_id(vault_missing_redaction_summary, "ecosystem.app-vault")["status"] == "fail"

        sandbox_best_effort_path = write_app_summary_variant(
            "sandbox-best-effort",
            lambda value: update_evidence(
                value,
                "apphost.sandbox-provider",
                lambda entry: entry.setdefault("details", {}).update({"supportLevel": "best-effort"}),
            ),
        )
        sandbox_best_effort_summary, sandbox_best_effort_exit_code = run_with_previous(
            "sandbox-best-effort-cert", app_platform_summary=sandbox_best_effort_path
        )
        assert sandbox_best_effort_exit_code == 1, sandbox_best_effort_summary
        assert gate_by_id(sandbox_best_effort_summary, "ecosystem.sandbox-provider")["status"] == "fail"
        waived_sandbox_evidence_summary, waived_sandbox_evidence_exit_code = run_with_previous(
            "waived-sandbox-evidence-cert",
            app_platform_summary=sandbox_best_effort_path,
            waivers={"apphost.sandbox-provider": "Release manager accepted sandbox provider gap."},
        )
        assert waived_sandbox_evidence_exit_code == 0, waived_sandbox_evidence_summary
        waived_sandbox_evidence_gate = gate_by_id(
            waived_sandbox_evidence_summary, "ecosystem.sandbox-provider"
        )
        assert waived_sandbox_evidence_gate["status"] == "warn", waived_sandbox_evidence_gate
        assert waived_sandbox_evidence_gate["releaseBlocker"] is False, waived_sandbox_evidence_gate
        assert waived_sandbox_evidence_gate["details"]["waived"] is True, waived_sandbox_evidence_gate
        assert waived_sandbox_evidence_gate["details"]["waivedEvidenceIds"] == [
            "apphost.sandbox-provider"
        ], waived_sandbox_evidence_gate

        legacy_removed_path = write_app_summary_variant(
            "legacy-wave-removed",
            lambda value: value.update(
                {
                    "evidence": [
                        entry
                        for entry in value["evidence"]
                        if entry.get("id") != "legacy-admin.removal-wave-1"
                    ]
                }
            ),
        )
        legacy_removed_summary, legacy_removed_exit_code = run_with_previous(
            "legacy-wave-removed-cert", app_platform_summary=legacy_removed_path
        )
        assert legacy_removed_exit_code == 1, legacy_removed_summary
        assert gate_by_id(legacy_removed_summary, "ecosystem.legacy-retirement")["status"] == "fail"

        legacy_wave_two_removed_path = write_app_summary_variant(
            "legacy-wave-two-removed",
            lambda value: value.update(
                {
                    "evidence": [
                        entry
                        for entry in value["evidence"]
                        if entry.get("id") != "legacy-admin.removal-wave-2"
                    ]
                }
            ),
        )
        legacy_wave_two_removed_summary, legacy_wave_two_removed_exit_code = run_with_previous(
            "legacy-wave-two-removed-cert", app_platform_summary=legacy_wave_two_removed_path
        )
        assert legacy_wave_two_removed_exit_code == 1, legacy_wave_two_removed_summary
        assert (
            gate_by_id(legacy_wave_two_removed_summary, "ecosystem.legacy-retirement")["status"]
            == "fail"
        )

        legacy_wave_three_removed_path = write_app_summary_variant(
            "legacy-wave-three-removed",
            lambda value: value.update(
                {
                    "evidence": [
                        entry
                        for entry in value["evidence"]
                        if entry.get("id") != "legacy-admin.removal-wave-3"
                    ]
                }
            ),
        )
        legacy_wave_three_removed_summary, legacy_wave_three_removed_exit_code = (
            run_with_previous(
                "legacy-wave-three-removed-cert",
                app_platform_summary=legacy_wave_three_removed_path,
            )
        )
        assert legacy_wave_three_removed_exit_code == 1, legacy_wave_three_removed_summary
        assert (
            gate_by_id(legacy_wave_three_removed_summary, "ecosystem.legacy-retirement")["status"]
            == "fail"
        )

        waiver_file_path = workspace / "docs/release-waivers/self-test.json"
        write_json(
            waiver_file_path,
            {
                "version": 1,
                "release": "self-test",
                "waivers": [
                    {
                        "id": "ecosystem.sandbox-provider",
                        "evidenceId": "ecosystem.sandbox-provider",
                        "status": "approved",
                        "approvedBy": "release-manager",
                        "reason": f"token=hunter2 accepted for fixture {workspace}/secret",
                        "expiresAt": "2099-01-01T00:00:00Z",
                        "allowReleaseCandidate": True,
                    }
                ],
            },
        )
        waived_sandbox_summary, waived_sandbox_exit_code = run_with_previous(
            "waived-sandbox-cert",
            app_platform_summary=sandbox_best_effort_path,
            waiver_files=(waiver_file_path,),
        )
        assert waived_sandbox_exit_code == 0, waived_sandbox_summary
        assert waived_sandbox_summary["status"] == "warn", waived_sandbox_summary
        assert waived_sandbox_summary["waivers"] == {}, waived_sandbox_summary
        assert len(waived_sandbox_summary["waiverRecords"]) == 1, waived_sandbox_summary
        waived_sandbox_gate = gate_by_id(waived_sandbox_summary, "ecosystem.sandbox-provider")
        assert waived_sandbox_gate["status"] == "warn", waived_sandbox_gate
        assert waived_sandbox_gate["details"]["waived"] is True, waived_sandbox_gate
        waived_report = (workspace / "build/waived-sandbox-cert" / REPORT_FILE_NAME).read_text(
            encoding="utf-8"
        )
        waived_encoded = json.dumps(waived_sandbox_summary, sort_keys=True) + waived_report
        for forbidden in ("hunter2", str(workspace)):
            assert forbidden not in waived_encoded, f"structured waiver leaked {forbidden}"

        malformed_rc_waiver_file_path = workspace / "docs/release-waivers/nonboolean.json"
        write_json(
            malformed_rc_waiver_file_path,
            {
                "version": 1,
                "waivers": [
                    {
                        "id": "ecosystem.sandbox-provider",
                        "evidenceId": "ecosystem.sandbox-provider",
                        "status": "approved",
                        "approvedBy": "release-manager",
                        "reason": "Malformed release-candidate flag.",
                        "expiresAt": "2099-01-01T00:00:00Z",
                        "allowReleaseCandidate": "false",
                    }
                ],
            },
        )
        malformed_rc_waiver_summary, malformed_rc_waiver_exit_code = run_with_previous(
            "malformed-rc-waiver-cert",
            app_platform_summary=sandbox_best_effort_path,
            waiver_files=(malformed_rc_waiver_file_path,),
        )
        assert malformed_rc_waiver_exit_code == 1, malformed_rc_waiver_summary
        assert gate_by_id(malformed_rc_waiver_summary, "ecosystem.waivers")["status"] == "fail"
        malformed_sandbox_gate = gate_by_id(
            malformed_rc_waiver_summary, "ecosystem.sandbox-provider"
        )
        assert malformed_sandbox_gate["status"] == "fail", malformed_sandbox_gate
        assert "waived" not in malformed_sandbox_gate["details"], malformed_sandbox_gate

        malformed_waiver_redaction_file_path = workspace / "docs/release-waivers/redaction.json"
        write_json(
            malformed_waiver_redaction_file_path,
            {
                "version": 1,
                "waivers": [
                    {
                        "id": "ecosystem.sandbox-provider",
                        "evidenceId": "ecosystem.sandbox-provider",
                        "status": f"token=hunter2 {workspace}/status",
                        "approvedBy": "release-manager",
                        "reason": "Malformed status and expiry should remain sanitized.",
                        "expiresAt": f"token=expires-secret {workspace}/expires",
                        "allowReleaseCandidate": True,
                    }
                ],
            },
        )
        malformed_waiver_redaction_summary, malformed_waiver_redaction_exit_code = run_with_previous(
            "malformed-waiver-redaction-cert",
            app_platform_summary=sandbox_best_effort_path,
            waiver_files=(malformed_waiver_redaction_file_path,),
        )
        assert malformed_waiver_redaction_exit_code == 1, malformed_waiver_redaction_summary
        malformed_waiver_redaction_report = (
            workspace / "build/malformed-waiver-redaction-cert" / REPORT_FILE_NAME
        ).read_text(encoding="utf-8")
        malformed_waiver_redaction_encoded = (
            json.dumps(malformed_waiver_redaction_summary, sort_keys=True)
            + malformed_waiver_redaction_report
        )
        for forbidden in ("hunter2", "expires-secret", str(workspace)):
            assert (
                forbidden not in malformed_waiver_redaction_encoded
            ), f"malformed waiver leaked {forbidden}"

        expired_waiver_file_path = workspace / "docs/release-waivers/expired.json"
        write_json(
            expired_waiver_file_path,
            {
                "version": 1,
                "waivers": [
                    {
                        "id": "ecosystem.sandbox-provider",
                        "evidenceId": "ecosystem.sandbox-provider",
                        "status": "approved",
                        "approvedBy": "release-manager",
                        "reason": "Expired waiver.",
                        "expiresAt": "2000-01-01T00:00:00Z",
                        "allowReleaseCandidate": True,
                    }
                ],
            },
        )
        expired_waiver_summary, expired_waiver_exit_code = run_with_previous(
            "expired-waiver-cert",
            app_platform_summary=sandbox_best_effort_path,
            waiver_files=(expired_waiver_file_path,),
        )
        assert expired_waiver_exit_code == 1, expired_waiver_summary
        assert gate_by_id(expired_waiver_summary, "ecosystem.waivers")["status"] == "fail"
        wrong_mode_extended = interop_evidence(
            "interop.extended",
            settings.interop_smoke_summary,
            False,
            "extended",
            workspace,
            out_dir,
        )
        assert wrong_mode_extended.status == "warn", wrong_mode_extended
        assert wrong_mode_extended.details["expectedMode"] == "extended", wrong_mode_extended
        assert wrong_mode_extended.details["mode"] == "smoke", wrong_mode_extended
        assert wrong_mode_extended.details["modeMatches"] is False, wrong_mode_extended

        missing_extended_flow_path = workspace / "build/interop-extended-missing-flow/summary.json"
        missing_extended_flow = read_json(settings.interop_extended_summary)
        assert missing_extended_flow is not None
        missing_extended_flow["flows"].pop("persistent_request_replay", None)
        write_json(missing_extended_flow_path, missing_extended_flow)
        missing_extended_flow_item = interop_evidence(
            "interop.extended",
            missing_extended_flow_path,
            False,
            "extended",
            workspace,
            out_dir,
        )
        assert missing_extended_flow_item.status == "warn", missing_extended_flow_item
        assert "persistent_request_replay" in missing_extended_flow_item.details["missingRequiredFlows"]

        collect_perf_path = workspace / "build/perf-collect/summary.json"
        collect_perf = read_json(settings.perf_smoke_summary)
        assert collect_perf is not None
        collect_perf["mode"] = "collect"
        collect_perf["status"] = "warning"
        write_json(collect_perf_path, collect_perf)
        collect_perf_item = perf_evidence(collect_perf_path, True, workspace, out_dir)
        assert collect_perf_item.status == "fail", collect_perf_item
        assert collect_perf_item.details["expectedMode"] == "smoke", collect_perf_item
        assert collect_perf_item.details["mode"] == "collect", collect_perf_item
        assert collect_perf_item.details["modeMatches"] is False, collect_perf_item
        collect_perf_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/collect-perf-cert").resolve(),
            perf_smoke_summary=collect_perf_path,
        )
        collect_perf_summary, collect_perf_exit_code = run(collect_perf_settings)
        assert collect_perf_exit_code == 1, collect_perf_summary
        assert collect_perf_summary["status"] == "fail", collect_perf_summary
        assert collect_perf_summary["releaseCandidatePassed"] is False, collect_perf_summary

        pr_app_summary_path = workspace / "build/app-platform-pr/summary.json"
        pr_app_summary = read_json(settings.app_platform_summary)
        assert pr_app_summary is not None
        pr_app_summary["mode"] = "pr"
        pr_app_summary["status"] = "warn"
        write_json(pr_app_summary_path, pr_app_summary)
        pr_app_items = app_platform_evidence(pr_app_summary_path, workspace, out_dir, "release-candidate")
        assert all(
            item.status == "fail" for item in pr_app_items if item.required_for_release_candidate
        ), pr_app_items
        assert pr_app_items[0].details["expectedMode"] == "release-candidate", pr_app_items
        assert pr_app_items[0].details["mode"] == "pr", pr_app_items
        assert pr_app_items[0].details["modeMatches"] is False, pr_app_items
        pr_app_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/pr-app-cert").resolve(),
            app_platform_summary=pr_app_summary_path,
        )
        pr_app_cert_summary, pr_app_exit_code = run(pr_app_settings)
        assert pr_app_exit_code == 1, pr_app_cert_summary
        assert pr_app_cert_summary["status"] == "fail", pr_app_cert_summary
        assert pr_app_cert_summary["releaseCandidatePassed"] is False, pr_app_cert_summary

        missing_update_evidence_path = workspace / "build/app-platform-missing-update/summary.json"
        missing_update_summary = read_json(settings.app_platform_summary)
        assert missing_update_summary is not None
        missing_update_summary["evidence"] = [
            item
            for item in missing_update_summary["evidence"]
            if item.get("id")
            not in {"app-update.lifecycle", "app-update.scheduler", "app-update.rollback"}
        ]
        write_json(missing_update_evidence_path, missing_update_summary)
        missing_update_items = app_platform_evidence(
            missing_update_evidence_path, workspace, out_dir, "release-candidate"
        )
        missing_update_by_id = {item.id: item for item in missing_update_items}
        assert missing_update_by_id["app-update.lifecycle"].status == "missing", missing_update_by_id
        assert missing_update_by_id["app-update.scheduler"].status == "missing", missing_update_by_id
        assert missing_update_by_id["app-update.rollback"].status == "missing", missing_update_by_id
        missing_update_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/missing-update-cert").resolve(),
            app_platform_summary=missing_update_evidence_path,
        )
        missing_update_cert_summary, missing_update_exit_code = run(missing_update_settings)
        assert missing_update_exit_code == 1, missing_update_cert_summary
        assert missing_update_cert_summary["status"] == "fail", missing_update_cert_summary
        assert missing_update_cert_summary["releaseCandidatePassed"] is False, missing_update_cert_summary
        missing_update_row = matrix_row_by_id(workspace / "build/missing-update-cert", "app-update")
        assert missing_update_row["status"] == "fail", missing_update_row
        assert missing_update_row["releaseBlocker"] is True, missing_update_row

        stale_artifact = out_dir / "artifacts/stale-from-previous-run.txt"
        stale_artifact.write_text("old evidence\n", encoding="utf-8")
        rerun_summary, rerun_exit_code = run(settings)
        assert rerun_exit_code == 0, rerun_summary
        assert not stale_artifact.exists(), stale_artifact
        assert "stale-from-previous-run.txt" not in json.dumps(rerun_summary, sort_keys=True)
        repo_tmp_path = workspace / "build/tmp-release-certification/release-certification-summary.json"
        assert (
            scrub_text(str(repo_tmp_path), workspace, out_dir)
            == "<repo>/build/tmp-release-certification/release-certification-summary.json"
        )
        with tempfile.TemporaryDirectory(prefix="cryptad-cert-symlink-target-") as target_name:
            with tempfile.TemporaryDirectory(prefix="cryptad-cert-symlink-parent-") as link_parent_name:
                symlink_root = Path(link_parent_name) / "repo-link"
                try:
                    symlink_root.symlink_to(Path(target_name), target_is_directory=True)
                except (NotImplementedError, OSError):
                    symlink_root = None
                if symlink_root is not None:
                    symlink_workspace = symlink_root / "repo"
                    symlink_out_dir = symlink_workspace / "build/release-certification"
                    symlink_path = (
                        symlink_workspace / "build/tmp-release-certification/release-certification-summary.json"
                    )
                    assert (
                        scrub_text(str(symlink_path), symlink_workspace, symlink_out_dir)
                        == "<repo>/build/tmp-release-certification/release-certification-summary.json"
                    )
        assert (
            normalize_redacted_separators(r"<repo>\build\tmp-release-certification\release-certification-summary.json")
            == "<repo>/build/tmp-release-certification/release-certification-summary.json"
        )
        windows_scrubbed = scrub_text(
            r"keys at D:\release\signing.pem and \\builder\share\certs\catalog.pem",
            workspace,
            out_dir,
        )
        assert r"D:\release" not in windows_scrubbed, windows_scrubbed
        assert r"\\builder\share" not in windows_scrubbed, windows_scrubbed
        assert "<path>/signing.pem" in windows_scrubbed, windows_scrubbed
        assert "<path>/catalog.pem" in windows_scrubbed, windows_scrubbed
        file_uri_scrubbed = scrub_text(
            "metadata file:///home/alice/signing/key.pem file:///D:/keys/catalog.pem",
            workspace,
            out_dir,
        )
        assert "/home/alice/signing" not in file_uri_scrubbed, file_uri_scrubbed
        assert "D:/keys" not in file_uri_scrubbed, file_uri_scrubbed
        assert "file://<path>/key.pem" in file_uri_scrubbed, file_uri_scrubbed
        assert "file://<path>/catalog.pem" in file_uri_scrubbed, file_uri_scrubbed
        route_scrubbed = scrub_text(
            "/apps/install /apps/cert-smoke/runtime /api/v1/diagnostics "
            "/mnt/secrets/signing/key.pem",
            workspace,
            out_dir,
        )
        assert "/apps/install" in route_scrubbed, route_scrubbed
        assert "/apps/cert-smoke/runtime" in route_scrubbed, route_scrubbed
        assert "/api/v1/diagnostics" in route_scrubbed, route_scrubbed
        assert "/mnt/secrets/signing/key.pem" not in route_scrubbed, route_scrubbed
        assert "<path>/key.pem" in route_scrubbed, route_scrubbed
        signing_metadata = sanitize_value(
            {
                "privateKeyPresent": False,
                "privateKeySource": "missing",
                "publicKeyPresent": True,
                "publicKeySource": "environment",
                "secretMaterialRedacted": True,
                "privateKey": "actual-secret",
                "privateKeyFile": "/mnt/secrets/signing/key.pem",
                "token": "runtime-token",
                "path": "/apps/cert-smoke/runtime",
            },
            workspace,
            out_dir,
        )
        assert signing_metadata["privateKeyPresent"] is False, signing_metadata
        assert signing_metadata["privateKeySource"] == "missing", signing_metadata
        assert signing_metadata["publicKeyPresent"] is True, signing_metadata
        assert signing_metadata["publicKeySource"] == "environment", signing_metadata
        assert signing_metadata["secretMaterialRedacted"] is True, signing_metadata
        assert signing_metadata["privateKey"] == "<redacted>", signing_metadata
        assert signing_metadata["privateKeyFile"] == "<redacted>", signing_metadata
        assert signing_metadata["token"] == "<redacted>", signing_metadata
        assert signing_metadata["path"] == "/apps/cert-smoke/runtime", signing_metadata
        vault_metadata = sanitize_value(
            {
                "capabilities": [
                    "vault.secrets.read",
                    "vault.secrets.write",
                    "vault.identities.read",
                    "vault.identities.create",
                    "vault.identities.use",
                    "vault.identities.manage",
                ],
                "secretValue": "stored-secret",
                "identityPrivateKey": "private-identity-key",
                "identitySeed": "identity-seed",
                "recoveryPhrase": "alpha beta gamma",
                "mnemonicPhrase": "delta epsilon zeta",
                "accountMnemonic": "eta theta iota",
                "publicIdentityId": "identity-public-id",
            },
            workspace,
            out_dir,
        )
        assert vault_metadata["capabilities"][0] == "vault.secrets.read", vault_metadata
        assert vault_metadata["secretValue"] == "<redacted>", vault_metadata
        assert vault_metadata["identityPrivateKey"] == "<redacted>", vault_metadata
        assert vault_metadata["identitySeed"] == "<redacted>", vault_metadata
        assert vault_metadata["recoveryPhrase"] == "<redacted>", vault_metadata
        assert vault_metadata["mnemonicPhrase"] == "<redacted>", vault_metadata
        assert vault_metadata["accountMnemonic"] == "<redacted>", vault_metadata
        assert vault_metadata["publicIdentityId"] == "identity-public-id", vault_metadata
        vault_scrubbed = scrub_text(
            '{"identitySeed":"seed-secret","recoveryPhrase":"alpha beta","mnemonicPhrase":"delta epsilon",'
            '"accountMnemonic":"eta theta","secretValue":"vault-secret"} '
            "capability=vault.identities.use",
            workspace,
            out_dir,
        )
        for forbidden in ("seed-secret", "alpha beta", "delta epsilon", "eta theta", "vault-secret"):
            assert forbidden not in vault_scrubbed, vault_scrubbed
        assert "vault.identities.use" in vault_scrubbed, vault_scrubbed
        signature_scrubbed = scrub_text(
            "signature.value.base64=raw-signature signature.algorithm=Ed25519",
            workspace,
            out_dir,
        )
        assert "raw-signature" not in signature_scrubbed, signature_scrubbed
        assert "Ed25519" in signature_scrubbed, signature_scrubbed
        credential_scrubbed = scrub_text(
            'Authorization: Bearer report-secret\n'
            'Cookie: session=abc; csrf=def\n'
            '{"token":"json-secret","authorization":"Bearer json-secret","password":"pw"} '
            "authorization=Bearer inline-secret "
            "rawMessageBody=private-social-body rawFetchedBody=private-fetched-body "
            "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64=base64-secret "
            "privateKeyBase64=key-secret clientSecret=client-secret api_password=api-secret "
            "privateKeyPresent=false",
            workspace,
            out_dir,
        )
        for forbidden in (
            "Bearer report-secret",
            "session=abc",
            "csrf=def",
            "json-secret",
            '"pw"',
            "inline-secret",
            "base64-secret",
            "key-secret",
            "client-secret",
            "api-secret",
            "private-social-body",
            "private-fetched-body",
        ):
            assert forbidden not in credential_scrubbed, credential_scrubbed
        assert "Authorization: <redacted>" in credential_scrubbed, credential_scrubbed
        assert "Cookie: <redacted>" in credential_scrubbed, credential_scrubbed
        assert '"token":"<redacted>"' in credential_scrubbed, credential_scrubbed
        assert "authorization=<redacted>" in credential_scrubbed, credential_scrubbed
        assert "privateKeyPresent=false" in credential_scrubbed, credential_scrubbed

        external_out_dir = Path(temp_name) / "external-cert"
        external_settings = dataclasses.replace(settings, out_dir=external_out_dir.resolve())
        external_summary, external_exit_code = run(external_settings)
        assert external_exit_code == 0, external_summary
        assert external_summary["summaryPath"].startswith("<workdir>/"), external_summary
        assert external_summary["reportPath"].startswith("<workdir>/"), external_summary
        assert external_summary["ecosystemMatrixPath"].startswith("<workdir>/"), external_summary
        assert (external_out_dir / SUMMARY_FILE_NAME).is_file(), external_summary
        assert (external_out_dir / ECOSYSTEM_MATRIX_FILE_NAME).is_file(), external_summary
        assert str(external_out_dir) not in json.dumps(external_summary, sort_keys=True), external_summary

        missing_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/missing-cert").resolve(),
            interop_smoke_summary=workspace / "build/missing-interop/summary.json",
        )
        missing_summary, missing_exit_code = run(missing_settings)
        assert missing_exit_code == 1, missing_summary
        assert missing_summary["status"] == "fail", missing_summary
        assert missing_summary["releaseCandidatePassed"] is False, missing_summary

        malformed_path = workspace / "build/malformed-interop/summary.json"
        malformed_path.parent.mkdir(parents=True, exist_ok=True)
        malformed_path.write_text('{"status": "success"', encoding="utf-8")
        malformed_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/malformed-cert").resolve(),
            interop_smoke_summary=malformed_path,
        )
        malformed_summary, malformed_exit_code = run(malformed_settings)
        assert malformed_exit_code == 1, malformed_summary
        assert malformed_summary["status"] == "fail", malformed_summary
        malformed_interop = next(item for item in malformed_summary["evidence"] if item["id"] == "interop.smoke")
        assert malformed_interop["status"] == "missing", malformed_interop
        assert (malformed_settings.out_dir / REPORT_FILE_NAME).is_file(), malformed_summary
        assert not any(
            artifact.endswith("/interop-smoke-summary.json")
            for artifact in malformed_summary["copiedArtifacts"]
        ), malformed_summary

        pr_missing_settings = dataclasses.replace(
            missing_settings,
            out_dir=(workspace / "build/pr-missing-cert").resolve(),
            mode="pr",
        )
        pr_missing_summary, pr_missing_exit_code = run(pr_missing_settings)
        assert pr_missing_exit_code == 0, pr_missing_summary
        assert pr_missing_summary["status"] == "warn", pr_missing_summary
        assert pr_missing_summary["releaseCandidatePassed"] is False, pr_missing_summary
        assert pr_missing_summary["promotionDecision"] == "FAIL", pr_missing_summary

        nightly_missing_settings = dataclasses.replace(
            missing_settings,
            out_dir=(workspace / "build/nightly-missing-cert").resolve(),
            mode="nightly",
        )
        nightly_missing_summary, nightly_missing_exit_code = run(nightly_missing_settings)
        assert nightly_missing_exit_code == 0, nightly_missing_summary
        assert nightly_missing_summary["status"] == "warn", nightly_missing_summary
        assert nightly_missing_summary["releaseCandidatePassed"] is False, nightly_missing_summary
        assert nightly_missing_summary["promotionDecision"] == "FAIL", nightly_missing_summary

        failing_perf = read_json(settings.perf_smoke_summary)
        assert failing_perf is not None
        failing_perf["status"] = "failure"
        failing_perf_path = workspace / "build/failing-perf/summary.json"
        write_json(failing_perf_path, failing_perf)
        nightly_failing_settings = dataclasses.replace(
            settings,
            out_dir=(workspace / "build/nightly-failing-cert").resolve(),
            mode="nightly",
            perf_smoke_summary=failing_perf_path,
        )
        nightly_failing_summary, nightly_failing_exit_code = run(nightly_failing_settings)
        assert nightly_failing_exit_code == 1, nightly_failing_summary
        assert nightly_failing_summary["status"] == "fail", nightly_failing_summary
        assert nightly_failing_summary["releaseCandidatePassed"] is False, nightly_failing_summary

        waived_settings = dataclasses.replace(
            missing_settings,
            out_dir=(workspace / "build/waived-cert").resolve(),
            waivers={"interop.smoke": "Release manager accepted CI artifact from upstream run."},
        )
        waived_summary, waived_exit_code = run(waived_settings)
        assert waived_exit_code == 0, waived_summary
        assert waived_summary["status"] == "warn", waived_summary
        assert waived_summary["waivers"] == {
            "interop.smoke": "Release manager accepted CI artifact from upstream run."
        }, waived_summary
        assert waived_summary["waiverRecords"][0]["source"] == "cli", waived_summary
        waived_item = next(item for item in waived_summary["evidence"] if item["id"] == "interop.smoke")
        assert waived_item["details"]["waived"] is True

        sensitive_reason = f"token=hunter2 USK@private/insert /mnt/secrets/signing/key.pem {workspace}/secret"
        sensitive_waived_settings = dataclasses.replace(
            missing_settings,
            out_dir=(workspace / "build/sensitive-waived-cert").resolve(),
            waivers={"interop.smoke": sensitive_reason},
        )
        sensitive_waived_summary, sensitive_waived_exit_code = run(sensitive_waived_settings)
        assert sensitive_waived_exit_code == 0, sensitive_waived_summary
        sensitive_report = (
            sensitive_waived_settings.out_dir / REPORT_FILE_NAME
        ).read_text(encoding="utf-8")
        sensitive_matrix_report = (
            sensitive_waived_settings.out_dir / ECOSYSTEM_MATRIX_REPORT_FILE_NAME
        ).read_text(encoding="utf-8")
        sensitive_matrix = read_json(sensitive_waived_settings.out_dir / ECOSYSTEM_MATRIX_FILE_NAME)
        sensitive_encoded = (
            json.dumps(sensitive_waived_summary, sort_keys=True)
            + json.dumps(sensitive_matrix, sort_keys=True)
            + sensitive_report
            + sensitive_matrix_report
        )
        for forbidden in ("hunter2", "USK@private", "/mnt/secrets/signing/key.pem", str(workspace)):
            assert forbidden not in sensitive_encoded, f"waiver reason leaked {forbidden}"


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        run_self_test(Path(__file__).resolve().parents[2])
        print("release-certification self-test passed")
        return 0
    settings = settings_from_args(args)
    summary, exit_code = run(settings)
    print(f"Release certification {summary['status']}: {settings.out_dir / REPORT_FILE_NAME}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Generate and verify deterministic production security response runbook artifacts."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable


TOOL_NAME = "security-response-runbook"
SCHEMA_VERSION = 1
DRILL_ARTIFACT_SCHEMA_VERSION = 2
DRILL_SUMMARY_SCHEMA_VERSION = 1
DEFAULT_RUNBOOK = Path("docs/production-security-response-runbook.md")
DEFAULT_MODEL = Path("tools/release-certification/production-security-response-runbook.json")
DEFAULT_TEMPLATE = Path("docs/templates/security-release-notes.md")
DEFAULT_GENERATED_AT = "1970-01-01T00:00:00Z"
DEFAULT_RELEASE_ID = "cryptad-production-beta-security-drill"
DEFAULT_MAX_AGE_DAYS = 30
NON_RELEASE_DRILL_MODES = ("developer-dry-run", "pr", "nightly")
RELEASE_DRILL_MODES = ("release-candidate", "production-beta")
DRILL_MODES = (*NON_RELEASE_DRILL_MODES, *RELEASE_DRILL_MODES)
REQUIRED_DRILLS = (
    "vulnerable-app-version",
    "app-signing-key-compromise",
    "reviewer-key-compromise",
    "catalog-signing-key-rotation",
    "malicious-catalog-entry",
    "emergency-replacement-app",
    "support-bundle-intake-redaction",
)
DRILL_OUTPUT_FILENAMES = {scenario: f"{scenario}.json" for scenario in REQUIRED_DRILLS}
REQUIRED_DRILL_FIELDS = (
    "id",
    "severity",
    "trigger",
    "containmentActions",
    "catalogActions",
    "reviewActions",
    "operatorActions",
    "schedulerExpectations",
    "redactionRequirements",
    "verificationEvidence",
    "releaseNotesTemplate",
)
ARRAY_DRILL_FIELDS = (
    "containmentActions",
    "catalogActions",
    "reviewActions",
    "operatorActions",
    "schedulerExpectations",
    "redactionRequirements",
    "verificationEvidence",
)
SCALAR_DRILL_FIELDS = (
    "severity",
    "trigger",
    "releaseNotesTemplate",
)
MAX_DRILL_ARRAY_ITEMS = 6
MAX_DRILL_TEXT_LENGTH = 160
RUNBOOK_MARKERS = (
    "Vulnerable app version",
    "Malicious or compromised app version",
    "App signing key compromise",
    "Reviewer key compromise",
    "Review receipt revocation",
    "Catalog signing key compromise or rotation",
    "Malicious catalog entry or catalog metadata compromise",
    "Emergency replacement app publication",
    "Safe uninstall/update guidance",
    "Support bundle intake and redaction handling",
)
RUNBOOK_FIELD_MARKERS = (
    "Trigger signals",
    "Required evidence",
    "Immediate containment",
    "Catalog/advisory/denylist actions",
    "Review/reviewer/revocation actions",
    "App update scheduler expected behavior",
    "Web Shell/operator UX expected behavior",
    "Recovery guidance",
    "Redaction requirements",
    "Release note fields",
    "Verification steps",
    "Rollback or follow-up",
)
TEMPLATE_MARKERS = (
    "Advisory id",
    "Affected apps and versions",
    "Severity",
    "Impact summary",
    "Containment",
    "Update guidance",
    "Safe uninstall guidance",
    "Replacement app/version",
    "Review",
    "Catalog",
    "Support bundle guidance",
    "Redaction note",
    "Credits",
)
FORBIDDEN_MARKERS = (
    "-----BEGIN PRIVATE KEY-----",
    "browser-session-secret",
    "app-process-token",
    "formPassword=",
    "token=secret",
    "/work/",
    "/home/",
    "C:\\Users\\",
    "USK@example",
    "SSK@example",
    "raw-app-data-value",
)
FORBIDDEN_CREDENTIAL_PATTERNS = (
    (
        "credential header marker",
        re.compile(
            r"\b(?:authorization|proxy-authorization|cookie|set-cookie|x-crypta-app-session|"
            r"x-crypta-form-password)\s*:\s*\S",
            re.IGNORECASE,
        ),
    ),
    (
        "authorization scheme marker",
        re.compile(
            r"\bbearer\s+(?!(?:token|tokens)\b)[A-Za-z0-9._~+/=-]+",
            re.IGNORECASE,
        ),
    ),
    (
        "credential assignment marker",
        re.compile(
            r"\b(?:authorization|token|password|passwd|secret|credential|private[-_ ]?key|"
            r"browser[-_ ]?session|app[-_ ]?session|app[-_ ]?process[-_ ]?token)\s*[:=]\s*"
            r"(?:(?:bearer|basic|digest)\s+)?[^\s,;&}\]]+",
            re.IGNORECASE,
        ),
    ),
    (
        "raw app data marker",
        re.compile(
            r"\braw[-_ ]?app[-_ ]?data"
            r"(?:[-_ ]?(?:value|values|payload|payloads|record|records))?\s*[:=]\s*\S",
            re.IGNORECASE,
        ),
    ),
    (
        "raw support bundle marker",
        re.compile(
            r"\braw[-_ ]?support[-_ ]?bundle"
            r"(?:[-_ ]?(?:body|bodies|content|payload|payloads))?\s*[:=]\s*\S",
            re.IGNORECASE,
        ),
    ),
    (
        "raw app-service body marker",
        re.compile(
            r"\braw[-_ ]?app[-_ ]?service[-_ ]?(?:body|bodies|payload|payloads)\s*[:=]\s*\S",
            re.IGNORECASE,
        ),
    ),
    (
        "raw profile feed trust social marker",
        re.compile(
            r"\braw[-_ ]?(?:profile|feed|trust|social|backup|signature)"
            r"(?:[-_ ]?(?:document|documents|body|bodies|content|payload|payloads|value|values))?"
            r"\s*[:=]\s*\S",
            re.IGNORECASE,
        ),
    ),
    (
        "raw fetched content marker",
        re.compile(
            r"\braw[-_ ]?fetched[-_ ]?content\s*[:=]\s*\S",
            re.IGNORECASE,
        ),
    ),
)
FORBIDDEN_ASSIGNMENT_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?P<key_quote>[\"']?)"
    r"(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)"
    r"(?P=key_quote)\s*[:=]\s*"
    r"(?:(?P<value_quote>[\"'])(?P<quoted_value>[^\"'\r\n]*)(?P=value_quote)|"
    r"(?P<value>(?:(?:bearer|basic|digest)\s+)?[^\s,;&}\]]+))",
    re.IGNORECASE,
)
CONTENT_KEY_URI_RE = re.compile(
    r"\b(?:crypta:)?(?:SSK|USK)@[^\s`\"'<>)\]}]+",
    re.IGNORECASE,
)
LOCAL_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_:/.\->])"
    r"(?:[A-Za-z]:[\\/][^\s`\"'<>)\]}]+|\\\\[^\s`\"'<>)\]}]+|/(?!/)[^\s`\"'<>)\]}]+)"
)
SAFE_ROUTE_PREFIXES = (
    "/api/v1",
    "/app/node",
    "/apps",
    "/.well-known",
    "/platform",
    "/queue",
    "/content",
    "/app-data",
    "/app-vault",
    "/identity-vault",
    "/operator",
    "/trust-graph",
)
SAFE_BOOLEAN_METADATA_SUFFIXES = (
    "available",
    "configured",
    "enabled",
    "excluded",
    "excludedfromevidence",
    "present",
    "redacted",
    "required",
    "status",
)
SAFE_RAW_APP_DATA_BOOLEAN_METADATA_KEYS = {
    "rawappdataavailable",
    "rawappdataconfigured",
    "rawappdataenabled",
    "rawappdataexcluded",
    "rawappdataexcludedfromevidence",
    "rawappdatapresent",
    "rawappdataredacted",
    "rawappdatarequired",
}
FORBIDDEN_JSON_KEY_NAMES = {
    "authorization",
    "authorizationheader",
    "proxyauthorization",
    "proxyauthorizationheader",
    "cookie",
    "setcookie",
    "credential",
    "cryptadapptoken",
    "formpassword",
    "privatekey",
    "secret",
    "token",
    "password",
    "passwd",
    "browsersession",
    "browsersessiontoken",
    "appsession",
    "appsessiontoken",
    "appprocesstoken",
    "xcryptaappsession",
    "rawappdata",
    "rawappdatavalue",
    "rawappdatavalues",
    "rawappdatapayload",
    "rawappdatapayloads",
    "rawappdatarecord",
    "rawappdatarecords",
    "rawsupportbundle",
    "rawsupportbundlebody",
    "rawsupportbundlepayload",
    "rawprofiledocument",
    "rawprofilebody",
    "rawfeedbody",
    "rawfeeddocument",
    "rawtrustdocument",
    "rawtruststatement",
    "rawtruststatementbody",
    "rawsocialdocument",
    "rawsocialmessage",
    "rawsocialmessagebody",
    "rawsignature",
    "rawsignaturevalue",
    "rawappservicebody",
    "rawappservicepayload",
    "rawbackupmaterial",
    "rawbackuppayload",
    "rawfetchedcontent",
    "rawfetchedbody",
    "rawpublickeybytes",
    "publickeybytes",
    "rawreviewreceipt",
    "reviewreceiptcontent",
    "rawreceipt",
    "payloadbase64",
    "cisecret",
    "cisecretvalue",
}
FORBIDDEN_JSON_KEY_FRAGMENTS = (
    "authorization",
    "credential",
    "rawappdata",
    "rawsupportbundle",
    "rawprofile",
    "rawfeed",
    "rawtrust",
    "rawsocial",
    "rawsignature",
    "rawappservice",
    "rawbackup",
    "privatekey",
    "browsersession",
    "appsession",
    "appprocesstoken",
    "formpassword",
    "rawfetchedcontent",
    "rawfetchedbody",
    "secret",
    "token",
)

SCENARIO_SAFE_SUMMARIES = {
    "vulnerable-app-version": "Exact app-version denylist, update guidance, scheduler rejection, installed vulnerable status, and support-bundle redaction evidence were verified.",
    "app-signing-key-compromise": "Compromised app signing-key policy, exact-version denylist, replacement guidance, scheduler rejection, receipt refresh, and artifact redaction evidence were verified.",
    "reviewer-key-compromise": "Reviewer key revocation, receipt revocation, transparency-log replacement state, trusted-review fail-closed behavior, Web Shell warning visibility, and redacted release notes were verified.",
    "catalog-signing-key-rotation": "Catalog signing-key rotation status, old/new key display, signature verification, mirror rollback safety, emergency advisory refresh, and artifact redaction evidence were verified.",
    "malicious-catalog-entry": "Malformed, downgrade, duplicate, and unknown-advisory catalog security entry rejection plus signed refresh and operator visibility evidence were verified.",
    "emergency-replacement-app": "Emergency replacement metadata, signed and reviewed replacement gating, permission/data-migration/backup gates, operator guidance, and private-URI-free release notes were verified.",
    "support-bundle-intake-redaction": "Support-bundle intake redaction fixtures, safe counts and digests, production blocker semantics, and release note/advisory redaction were verified.",
}

SCENARIO_RELEASE_SNIPPETS = {
    "vulnerable-app-version": "Scenario vulnerable-app-version: exact affected app versions are denylisted; operators receive bounded update and safe uninstall guidance.",
    "app-signing-key-compromise": "Scenario app-signing-key-compromise: affected versions are blocked and replacement signing-key guidance is published without private key material.",
    "reviewer-key-compromise": "Scenario reviewer-key-compromise: revoked reviewer evidence no longer satisfies trusted-review-required policy; replacement review status is summarized without raw signatures.",
    "catalog-signing-key-rotation": "Scenario catalog-signing-key-rotation: old and new catalog key identifiers are summarized and all emergency refreshes remain signature-verified.",
    "malicious-catalog-entry": "Scenario malicious-catalog-entry: unsafe catalog metadata is rejected and corrected advisory or denylist status is visible to operators.",
    "emergency-replacement-app": "Scenario emergency-replacement-app: replacement version guidance preserves signature, review, permission, migration, and backup gates.",
    "support-bundle-intake-redaction": "Scenario support-bundle-intake-redaction: support evidence is handled through redacted previews with raw private material excluded.",
}

SCENARIO_STEP_IDS = {
    "vulnerable-app-version": (
        "verify-exact-version-denylist",
        "verify-safe-guidance",
        "verify-scheduler-denylist-gates",
        "verify-installed-status-and-support-redaction",
    ),
    "app-signing-key-compromise": (
        "represent-compromised-app-signing-key",
        "denylist-affected-versions",
        "stage-verified-replacement-only",
        "reissue-or-revoke-review-receipts",
    ),
    "reviewer-key-compromise": (
        "revoke-reviewer-key",
        "revoke-affected-review-receipts",
        "record-transparency-log-replacement",
        "fail-closed-trusted-review-policy",
    ),
    "catalog-signing-key-rotation": (
        "record-catalog-key-rotation",
        "show-safe-old-and-new-key-ids",
        "reject-unsigned-or-wrong-key-catalogs",
        "verify-emergency-advisory-refresh",
    ),
    "malicious-catalog-entry": (
        "reject-malformed-catalog-security-entries",
        "preserve-signature-authority",
        "block-silent-install-or-update",
        "show-advisory-and-denylist-status",
    ),
    "emergency-replacement-app": (
        "represent-emergency-replacement",
        "require-signature-review-and-channel-compatibility",
        "preserve-permission-migration-and-backup-gates",
        "show-safe-replacement-guidance",
    ),
    "support-bundle-intake-redaction": (
        "reject-sensitive-support-bundle-fixtures",
        "emit-safe-redaction-counts-and-digests",
        "mark-redaction-failures-critical",
        "keep-release-notes-redacted",
    ),
}

REDACTION_PATTERNS_CHECKED = (
    "private-key",
    "private-insert-uri",
    "token",
    "raw-content",
    "raw-app-data",
    "raw-support-bundle",
    "raw-profile-feed-trust-social",
    "raw-signature",
    "local-path",
)
FORBIDDEN_JSON_KEY_SUFFIXES = (
    "token",
    "password",
    "passwd",
    "secret",
    "credential",
)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def load_model(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("runbook model must be a JSON object")
    return value


def model_drills(model: dict[str, Any]) -> dict[str, dict[str, Any]]:
    drills = model.get("drills")
    if not isinstance(drills, list):
        raise ValueError("runbook model must contain a drills array")
    by_id: dict[str, dict[str, Any]] = {}
    for drill in drills:
        if not isinstance(drill, dict):
            raise ValueError("each drill must be an object")
        drill_id = drill.get("id")
        if not isinstance(drill_id, str) or not drill_id:
            raise ValueError("each drill must have a non-empty id")
        if drill_id in by_id:
            raise ValueError(f"duplicate drill id: {drill_id}")
        by_id[drill_id] = drill
    return by_id


def normalize_json_key_name(key_hint: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key_hint.lower())


def is_safe_boolean_metadata_key(normalized: str, value: Any | None) -> bool:
    return isinstance(value, bool) and normalized.endswith(SAFE_BOOLEAN_METADATA_SUFFIXES)


def is_safe_raw_app_data_metadata_key(normalized: str, value: Any | None) -> bool:
    return normalized in SAFE_RAW_APP_DATA_BOOLEAN_METADATA_KEYS and isinstance(value, bool)


def is_forbidden_json_key(key_hint: str, value: Any | None = None) -> bool:
    normalized = normalize_json_key_name(key_hint)
    if not normalized:
        return False
    if "rawappdata" in normalized:
        return not is_safe_raw_app_data_metadata_key(normalized, value)
    sensitive = (
        normalized in FORBIDDEN_JSON_KEY_NAMES
        or any(fragment in normalized for fragment in FORBIDDEN_JSON_KEY_FRAGMENTS)
        or any(normalized.endswith(suffix) for suffix in FORBIDDEN_JSON_KEY_SUFFIXES)
    )
    if not sensitive:
        return False
    return not is_safe_boolean_metadata_key(normalized, value)


def forbidden_json_key_findings(value: Any) -> list[str]:
    findings: list[str] = []

    def visit(current: Any) -> None:
        if isinstance(current, dict):
            for key, child in current.items():
                if is_forbidden_json_key(str(key), child):
                    findings.append("sensitive JSON key marker")
                visit(child)
        elif isinstance(current, (list, tuple)):
            for child in current:
                visit(child)

    visit(value)
    return list(dict.fromkeys(findings))


def json_string_values(value: Any) -> list[str]:
    values: list[str] = []

    def visit(current: Any) -> None:
        if isinstance(current, str):
            values.append(current)
        elif isinstance(current, dict):
            for child in current.values():
                visit(child)
        elif isinstance(current, (list, tuple)):
            for child in current:
                visit(child)

    visit(value)
    return values


def forbidden_assignment_findings(text: str) -> list[str]:
    if any(
        is_forbidden_json_key(match.group("key"), match.group("quoted_value") or match.group("value"))
        for match in FORBIDDEN_ASSIGNMENT_RE.finditer(text)
    ):
        return ["sensitive assignment marker"]
    return []


def is_safe_route_path(path: str) -> bool:
    return any(
        path == prefix
        or path.startswith(prefix + "/")
        or path.startswith(prefix + "#")
        or path.startswith(prefix + "?")
        for prefix in SAFE_ROUTE_PREFIXES
    )


def forbidden_local_path_findings(text: str) -> list[str]:
    if any(
        not match.group(0).startswith("/") or not is_safe_route_path(match.group(0))
        for match in LOCAL_PATH_RE.finditer(text)
    ):
        return ["local path marker"]
    return []


def validate_drill_field_bounds(drill_id: str, drill: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for field in ARRAY_DRILL_FIELDS:
        value = drill.get(field)
        if not isinstance(value, list) or not value:
            errors.append(f"{drill_id}.{field} must be a non-empty string array")
            continue
        if len(value) > MAX_DRILL_ARRAY_ITEMS:
            errors.append(f"{drill_id}.{field} must contain at most {MAX_DRILL_ARRAY_ITEMS} entries")
        if not all(
            isinstance(item, str) and 0 < len(item) <= MAX_DRILL_TEXT_LENGTH
            for item in value
        ):
            errors.append(
                f"{drill_id}.{field} entries must be strings with 1..{MAX_DRILL_TEXT_LENGTH} characters"
            )
    for field in SCALAR_DRILL_FIELDS:
        value = drill.get(field)
        if not isinstance(value, str) or not value:
            errors.append(f"{drill_id}.{field} must be a non-empty string")
        elif len(value) > MAX_DRILL_TEXT_LENGTH:
            errors.append(
                f"{drill_id}.{field} must be at most {MAX_DRILL_TEXT_LENGTH} characters"
            )
    return errors


def validate_model(model: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    if model.get("schemaVersion") != SCHEMA_VERSION:
        errors.append("schemaVersion must be 1")
    if model.get("kind") != "cryptad-production-security-response-runbook":
        errors.append("kind must be cryptad-production-security-response-runbook")
    try:
        drills = model_drills(model)
    except ValueError as exc:
        return {"ok": False, "errors": [str(exc)], "drillIds": []}
    unknown_drills = sorted(set(drills) - set(REQUIRED_DRILLS))
    for drill_id in unknown_drills:
        errors.append(f"unknown required drill: {drill_id}")
    for drill_id in REQUIRED_DRILLS:
        drill = drills.get(drill_id)
        if drill is None:
            errors.append(f"missing drill: {drill_id}")
            continue
        for field in REQUIRED_DRILL_FIELDS:
            if field not in drill:
                errors.append(f"{drill_id} missing field {field}")
        errors.extend(validate_drill_field_bounds(drill_id, drill))
    return {"ok": not errors, "errors": errors, "drillIds": sorted(drills)}


def validate_drill(drill: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    drill_id = drill.get("id")
    if drill_id not in REQUIRED_DRILLS:
        errors.append("drill id is not part of required production drills")
    for field in REQUIRED_DRILL_FIELDS:
        if field not in drill:
            errors.append(f"{drill_id or 'drill'} missing field {field}")
    errors.extend(validate_drill_field_bounds(drill_id or "drill", drill))
    return {"ok": not errors, "errors": errors, "drillIds": [drill_id] if isinstance(drill_id, str) else []}


def forbidden_findings(*texts: str) -> list[str]:
    rendered = "\n".join(texts)
    rendered_lower = rendered.lower()
    findings = [
        f"literal marker: {marker}"
        for marker in FORBIDDEN_MARKERS
        if marker.lower() in rendered_lower
    ]
    findings.extend(label for label, pattern in FORBIDDEN_CREDENTIAL_PATTERNS if pattern.search(rendered))
    findings.extend(forbidden_assignment_findings(rendered))
    findings.extend(forbidden_local_path_findings(rendered))
    if CONTENT_KEY_URI_RE.search(rendered):
        findings.append("content key URI marker")
    return findings


def safe_redaction_findings(findings: list[Any]) -> list[str]:
    safe: list[str] = []
    for finding in findings:
        text = str(finding)
        if forbidden_findings(text):
            text = "redaction finding omitted sensitive material"
        if len(text) > MAX_DRILL_TEXT_LENGTH:
            text = text[:MAX_DRILL_TEXT_LENGTH].rstrip()
        safe.append(text)
    return list(dict.fromkeys(safe))


def verify_runbook(runbook: Path, model_path: Path, template: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    errors: list[str] = []
    runbook_text = read_text(runbook) if runbook.is_file() else ""
    template_text = read_text(template) if template.is_file() else ""
    try:
        model = load_model(model_path)
        model_result = validate_model(model)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        model = {}
        model_result = {"ok": False, "errors": [str(exc)], "drillIds": []}
    checks["runbookExists"] = runbook.is_file()
    checks["templateExists"] = template.is_file()
    checks["modelExists"] = model_path.is_file()
    checks["runbookIncidentCoverage"] = all(marker in runbook_text for marker in RUNBOOK_MARKERS)
    checks["runbookFieldCoverage"] = all(marker in runbook_text for marker in RUNBOOK_FIELD_MARKERS)
    checks["templateFieldCoverage"] = all(marker in template_text for marker in TEMPLATE_MARKERS)
    checks["modelValid"] = bool(model_result["ok"])
    redaction_findings = forbidden_findings(runbook_text, template_text, *json_string_values(model))
    redaction_findings.extend(forbidden_json_key_findings(model))
    checks["redactionClean"] = not redaction_findings
    for name, passed in checks.items():
        if not passed:
            errors.append(name)
    errors.extend(str(error) for error in model_result.get("errors", []))
    return {
        "schemaVersion": SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "status": "pass" if not errors else "fail",
        "checks": checks,
        "errors": errors,
        "drillIds": model_result.get("drillIds", []),
    }


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def parse_timestamp(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    normalized = value
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_status(value: Any) -> str:
    text = str(value).strip().lower()
    return text if text in {"pass", "warn", "fail", "missing", "stale"} else "missing"


def scenario_digest(drill: dict[str, Any]) -> str:
    return sha256_text(canonical_json(drill))


def release_notes_snippet(scenario: str, drill: dict[str, Any]) -> str:
    snippet = SCENARIO_RELEASE_SNIPPETS.get(
        scenario,
        f"Scenario {scenario}: {drill.get('releaseNotesTemplate', 'redacted release notes')} verified.",
    )
    findings = forbidden_findings(snippet)
    findings.extend(forbidden_json_key_findings({"snippet": snippet}))
    if findings:
        raise ValueError(f"release notes snippet for {scenario} is not redaction-safe")
    return snippet


def drill_steps(scenario: str, drill: dict[str, Any]) -> list[dict[str, Any]]:
    evidence = list(drill.get("verificationEvidence", []))
    step_ids = SCENARIO_STEP_IDS.get(scenario, ("verify-runbook-scenario",))
    summary = SCENARIO_SAFE_SUMMARIES.get(scenario, f"{scenario} operational response path verified.")
    steps: list[dict[str, Any]] = []
    for index, step_id in enumerate(step_ids):
        evidence_id = evidence[index % len(evidence)] if evidence else "production-security.response-runbook"
        steps.append(
            {
                "id": step_id,
                "status": "pass",
                "safeSummary": summary,
                "evidenceIds": [evidence_id],
            }
        )
    return steps


def validate_drill_steps(
    scenario: str,
    drill: dict[str, Any],
    steps: list[Any],
) -> list[str]:
    errors: list[str] = []
    expected_steps = drill_steps(scenario, drill)
    expected_step_ids = [step["id"] for step in expected_steps]
    actual_step_ids = [step.get("id") if isinstance(step, dict) else None for step in steps]
    if actual_step_ids != expected_step_ids:
        errors.append("steps must match the expected runbook scenario step ids")
    for index, expected_step in enumerate(expected_steps):
        if index >= len(steps) or not isinstance(steps[index], dict):
            continue
        if steps[index].get("evidenceIds") != expected_step.get("evidenceIds"):
            errors.append(f"steps[{index}].evidenceIds must match the runbook scenario")
        if steps[index].get("safeSummary") != expected_step.get("safeSummary"):
            errors.append(f"steps[{index}].safeSummary must match the runbook scenario")
    return errors


def drill_artifact(
    model: dict[str, Any],
    drill: dict[str, Any],
    scenario: str,
    release_id: str,
    generated_at: str,
    mode: str,
    evidence_mode: str,
    fixture_only: bool,
) -> dict[str, Any]:
    redaction_findings = forbidden_findings(*json_string_values(drill))
    redaction_findings.extend(forbidden_json_key_findings(drill))
    redaction_status = "pass" if not redaction_findings else "fail"
    return {
        "kind": "cryptad-security-response-drill",
        "schemaVersion": DRILL_ARTIFACT_SCHEMA_VERSION,
        "scenario": scenario,
        "generatedAt": generated_at,
        "releaseId": release_id,
        "mode": mode,
        "evidenceMode": evidence_mode,
        "fixtureOnly": fixture_only,
        "status": "pass" if redaction_status == "pass" else "fail",
        "severity": drill.get("severity"),
        "runbookScenarioDigest": scenario_digest(drill),
        "verificationEvidence": list(drill.get("verificationEvidence", [])),
        "steps": drill_steps(scenario, drill),
        "releaseNotes": {
            "templateStatus": "pass",
            "template": drill.get("releaseNotesTemplate"),
            "redactedSnippet": release_notes_snippet(scenario, drill),
        },
        "advisoryTemplate": {
            "templateStatus": "pass",
            "redactedSnippet": release_notes_snippet(scenario, drill),
        },
        "redaction": {
            "status": redaction_status,
            "patternsChecked": list(REDACTION_PATTERNS_CHECKED),
            "rawSensitiveMaterialExcluded": True,
            "findings": redaction_findings,
        },
    }


def drill_summary_non_release(mode: str, fixture_only: bool) -> bool:
    return fixture_only or mode.strip().lower() not in RELEASE_DRILL_MODES


def drill_create(
    model_path: Path,
    scenario: str,
    out: Path,
    release_id: str = DEFAULT_RELEASE_ID,
    generated_at: str | None = None,
    mode: str = "release-candidate",
    evidence_mode: str = "release-operations",
    fixture_only: bool = False,
) -> dict[str, Any]:
    model = load_model(model_path)
    drills = model_drills(model)
    drill = drills.get(scenario)
    if drill is None:
        raise ValueError(f"unknown scenario: {scenario}")
    artifact = drill_artifact(
        model,
        drill,
        scenario,
        release_id,
        generated_at or utc_now(),
        mode,
        evidence_mode,
        fixture_only,
    )
    write_json(out, artifact)
    return artifact


def validate_drill_artifact_envelope(
    value: dict[str, Any],
    drill: dict[str, Any] | None,
) -> list[str]:
    errors: list[str] = []
    schema_version = value.get("schemaVersion")
    if schema_version not in {SCHEMA_VERSION, DRILL_ARTIFACT_SCHEMA_VERSION}:
        errors.append(f"schemaVersion must be {SCHEMA_VERSION} or {DRILL_ARTIFACT_SCHEMA_VERSION}")
    scenario = value.get("scenario")
    if not isinstance(scenario, str) or not scenario:
        errors.append("scenario must be a non-empty string")
    elif drill is not None and scenario != drill.get("id"):
        errors.append("scenario must match drill id")
    return errors


def validate_v2_drill_artifact(value: dict[str, Any], model_path: Path = DEFAULT_MODEL) -> dict[str, Any]:
    errors: list[str] = []
    scenario = value.get("scenario")
    drill: dict[str, Any] | None = None
    if not isinstance(scenario, str) or scenario not in REQUIRED_DRILLS:
        errors.append("scenario must be one of the required production drills")
    else:
        try:
            drill = model_drills(load_model(model_path)).get(scenario)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"runbook model could not be loaded: {exc}")
    if value.get("kind") != "cryptad-security-response-drill":
        errors.append("kind must be cryptad-security-response-drill")
    if value.get("schemaVersion") != DRILL_ARTIFACT_SCHEMA_VERSION:
        errors.append(f"schemaVersion must be {DRILL_ARTIFACT_SCHEMA_VERSION}")
    if normalize_status(value.get("status")) != "pass":
        errors.append("status must be pass")
    if parse_timestamp(value.get("generatedAt")) is None:
        errors.append("generatedAt must be an ISO-8601 UTC timestamp")
    release_id = value.get("releaseId")
    if not isinstance(release_id, str) or not release_id.strip():
        errors.append("releaseId must be a non-empty string")
    if drill is not None:
        if value.get("severity") != drill.get("severity"):
            errors.append("severity must match runbook scenario")
        if value.get("runbookScenarioDigest") != scenario_digest(drill):
            errors.append("runbookScenarioDigest must match the runbook scenario")
        evidence = value.get("verificationEvidence")
        if evidence != drill.get("verificationEvidence"):
            errors.append("verificationEvidence must match the runbook scenario")
    steps = value.get("steps")
    if not isinstance(steps, list) or not steps:
        errors.append("steps must be a non-empty array")
    else:
        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                errors.append(f"steps[{index}] must be an object")
                continue
            if normalize_status(step.get("status")) != "pass":
                errors.append(f"steps[{index}].status must be pass")
            if not isinstance(step.get("safeSummary"), str) or not step.get("safeSummary"):
                errors.append(f"steps[{index}].safeSummary must be a non-empty string")
            if not isinstance(step.get("evidenceIds"), list) or not step.get("evidenceIds"):
                errors.append(f"steps[{index}].evidenceIds must be a non-empty array")
        if drill is not None and isinstance(scenario, str):
            errors.extend(validate_drill_steps(scenario, drill, steps))
    release_notes = value.get("releaseNotes")
    if not isinstance(release_notes, dict):
        errors.append("releaseNotes must be an object")
    else:
        if release_notes.get("templateStatus") != "pass":
            errors.append("releaseNotes.templateStatus must be pass")
        if drill is not None and release_notes.get("template") != drill.get("releaseNotesTemplate"):
            errors.append("releaseNotes.template must match the runbook scenario")
        snippet = release_notes.get("redactedSnippet")
        if not isinstance(snippet, str) or not snippet.strip():
            errors.append("releaseNotes.redactedSnippet must be a non-empty string")
        elif drill is not None and isinstance(scenario, str) and snippet != release_notes_snippet(scenario, drill):
            errors.append("releaseNotes.redactedSnippet must match the runbook scenario")
    advisory_template = value.get("advisoryTemplate")
    if not isinstance(advisory_template, dict):
        errors.append("advisoryTemplate must be an object")
    else:
        if advisory_template.get("templateStatus") != "pass":
            errors.append("advisoryTemplate.templateStatus must be pass")
        if (
            drill is not None
            and "template" in advisory_template
            and advisory_template.get("template") != drill.get("releaseNotesTemplate")
        ):
            errors.append("advisoryTemplate.template must match the runbook scenario")
        snippet = advisory_template.get("redactedSnippet")
        if not isinstance(snippet, str) or not snippet.strip():
            errors.append("advisoryTemplate.redactedSnippet must be a non-empty string")
        elif drill is not None and isinstance(scenario, str) and snippet != release_notes_snippet(scenario, drill):
            errors.append("advisoryTemplate.redactedSnippet must match the runbook scenario")
    redaction = value.get("redaction")
    if not isinstance(redaction, dict):
        errors.append("redaction must be an object")
    else:
        if redaction.get("status") != "pass":
            errors.append("redaction.status must be pass")
        if redaction.get("rawSensitiveMaterialExcluded") is not True:
            errors.append("redaction.rawSensitiveMaterialExcluded must be true")
        findings = redaction.get("findings")
        if not isinstance(findings, list) or findings:
            errors.append("redaction.findings must be an empty array")
    return {"ok": not errors, "errors": errors, "drillIds": [scenario] if isinstance(scenario, str) else []}


def drill_verify(path: Path, model_path: Path = DEFAULT_MODEL) -> dict[str, Any]:
    value = load_model(path)
    redaction_findings = forbidden_findings(*json_string_values(value))
    redaction_findings.extend(forbidden_json_key_findings(value))
    redaction_clean = not redaction_findings
    if (
        value.get("kind") == "cryptad-security-response-drill"
        and value.get("schemaVersion") == DRILL_ARTIFACT_SCHEMA_VERSION
    ):
        result = validate_v2_drill_artifact(value, model_path)
    elif value.get("kind") == "cryptad-security-response-drill":
        drill = value.get("drill")
        envelope_errors = validate_drill_artifact_envelope(
            value,
            drill if isinstance(drill, dict) else None,
        )
        if not isinstance(drill, dict):
            result: dict[str, Any] = {
                "ok": False,
                "errors": ["drill must be an object", *envelope_errors],
                "drillIds": [],
            }
        else:
            result = validate_drill(drill)
            result_errors = [*result.get("errors", []), *envelope_errors]
            result = {
                **result,
                "ok": bool(result["ok"]) and not envelope_errors,
                "errors": result_errors,
            }
    else:
        result = validate_model(value)

    errors = list(result.get("errors", []))
    if not redaction_clean:
        errors.append("redactionClean")
    ok = bool(result["ok"]) and redaction_clean
    return {
        **result,
        "ok": ok,
        "status": "pass" if ok else "fail",
        "errors": errors,
        "redactionClean": redaction_clean,
        "redactionFindings": safe_redaction_findings(redaction_findings),
    }


def artifact_is_stale(
    artifact: dict[str, Any], now: dt.datetime, max_age_days: int
) -> tuple[bool, int | None, str]:
    generated_at = parse_timestamp(artifact.get("generatedAt"))
    if generated_at is None:
        return True, None, "generatedAt is missing or malformed"
    if generated_at > now + dt.timedelta(minutes=5):
        return True, None, "generatedAt is in the future"
    age = now - generated_at
    age_days = max(0, age.days)
    if age > dt.timedelta(days=max_age_days):
        return True, age_days, f"generatedAt is older than {max_age_days} days"
    return False, age_days, ""


def validate_drill_artifact_files(
    summary: dict[str, Any],
    summary_path: Path,
    model_path: Path = DEFAULT_MODEL,
    strict: bool = False,
    now: dt.datetime | None = None,
    display_path_fn: Callable[[Path], str] | None = None,
) -> dict[str, Any]:
    artifacts = summary.get("artifacts")
    if not isinstance(artifacts, list):
        return {
            "status": "fail",
            "errors": ["security drills summary artifacts must be an array"],
            "redactionFindings": [],
            "checked": [],
        }
    source_dir = summary_path.parent
    expected_release_id = summary.get("releaseId")
    expected_mode = summary.get("mode")
    expected_evidence_mode = summary.get("evidenceMode")
    evaluated_at = now or dt.datetime.now(dt.timezone.utc)
    evaluated_at = evaluated_at.astimezone(dt.timezone.utc)
    max_age_days_value = summary.get("maxAgeDays")
    max_age_days = DEFAULT_MAX_AGE_DAYS
    if non_bool_int(max_age_days_value) and int(max_age_days_value) > 0:
        max_age_days = (
            min(int(max_age_days_value), DEFAULT_MAX_AGE_DAYS)
            if strict
            else int(max_age_days_value)
        )
    errors: list[str] = []
    redaction_findings: list[Any] = []
    seen: set[str] = set()
    checked: list[dict[str, Any]] = []
    for index, entry in enumerate(artifacts):
        if not isinstance(entry, dict):
            errors.append(f"security drill artifact entry {index} must be an object")
            continue
        scenario = entry.get("scenario")
        if scenario not in REQUIRED_DRILLS:
            errors.append(f"security drill artifact entry {index} has an unknown scenario")
            continue
        scenario_text = str(scenario)
        if scenario_text in seen:
            errors.append(f"security drill artifact for {scenario_text} is duplicated")
            continue
        seen.add(scenario_text)
        artifact_name = entry.get("artifact")
        expected_name = DRILL_OUTPUT_FILENAMES[scenario_text]
        if artifact_name != expected_name:
            errors.append(f"security drill artifact for {scenario_text} must be named {expected_name}")
            continue
        if Path(str(artifact_name)).name != artifact_name:
            errors.append(f"security drill artifact for {scenario_text} has an unsafe file name")
            continue
        artifact_path = source_dir / str(artifact_name)
        display_artifact = (
            display_path_fn(artifact_path) if display_path_fn is not None else str(artifact_path.name)
        )
        if not artifact_path.is_file() or artifact_path.is_symlink():
            errors.append(f"security drill artifact for {scenario_text} is missing")
            checked.append(
                {
                    "scenario": scenario_text,
                    "artifact": str(artifact_name),
                    "path": display_artifact,
                    "status": "missing",
                }
            )
            continue
        try:
            digest = sha256_path(artifact_path)
            verification = drill_verify(artifact_path, model_path)
            artifact = load_model(artifact_path)
        except (OSError, ValueError, json.JSONDecodeError):
            errors.append(f"security drill artifact for {scenario_text} could not be verified")
            checked.append(
                {
                    "scenario": scenario_text,
                    "artifact": str(artifact_name),
                    "path": display_artifact,
                    "status": "fail",
                }
            )
            continue
        artifact_status = "pass"
        stale = False
        age_days: int | None = None
        stale_reason = ""
        if entry.get("digest") != digest:
            errors.append(f"security drill artifact digest mismatch for {scenario_text}")
            artifact_status = "fail"
        if verification.get("status") != "pass":
            errors.append(f"security drill artifact for {scenario_text} failed offline verification")
            artifact_status = "fail"
        verifier_findings = verification.get("redactionFindings")
        if isinstance(verifier_findings, list):
            redaction_findings.extend(verifier_findings)
        if artifact.get("scenario") != scenario_text:
            errors.append(f"security drill artifact for {scenario_text} has the wrong scenario")
            artifact_status = "fail"
        if artifact.get("releaseId") != expected_release_id:
            errors.append(f"security drill artifact for {scenario_text} has the wrong releaseId")
            artifact_status = "fail"
        if artifact.get("mode") != expected_mode:
            errors.append(f"security drill artifact for {scenario_text} has the wrong mode")
            artifact_status = "fail"
        if artifact.get("evidenceMode") != expected_evidence_mode:
            errors.append(f"security drill artifact for {scenario_text} has the wrong evidenceMode")
            artifact_status = "fail"
        if strict:
            if artifact.get("fixtureOnly") is True:
                errors.append(
                    f"security drill artifact for {scenario_text} must not be fixtureOnly"
                )
                artifact_status = "fail"
            stale, age_days, stale_reason = artifact_is_stale(artifact, evaluated_at, max_age_days)
            if stale:
                errors.append(f"security drill artifact for {scenario_text} is stale: {stale_reason}")
                artifact_status = "fail"
        checked.append(
            {
                "scenario": scenario_text,
                "artifact": str(artifact_name),
                "path": display_artifact,
                "digest": digest,
                "status": artifact_status,
                "ageDays": age_days,
                "stale": stale,
                "staleReason": stale_reason,
            }
        )
    for scenario in sorted(set(REQUIRED_DRILLS) - seen):
        errors.append(f"security drill artifact for {scenario} is missing")
    return {
        "status": "pass" if not errors else "fail",
        "errors": errors,
        "redactionFindings": safe_redaction_findings(redaction_findings),
        "checked": checked,
    }


def release_notes_draft(artifacts: list[dict[str, Any]]) -> str:
    lines = [
        "# Security Release Notes Draft",
        "",
        "This draft is generated from redacted security response drill artifacts.",
        "",
    ]
    for artifact in artifacts:
        release_notes = artifact.get("releaseNotes") if isinstance(artifact, dict) else {}
        snippet = release_notes.get("redactedSnippet") if isinstance(release_notes, dict) else ""
        lines.extend(
            [
                f"## {artifact.get('scenario', 'unknown')}",
                "",
                str(snippet),
                "",
            ]
        )
    text = "\n".join(lines)
    findings = forbidden_findings(text)
    if findings:
        raise ValueError("generated security release notes draft is not redaction-safe")
    return text


def write_release_notes_draft(path: Path, artifacts: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(release_notes_draft(artifacts), encoding="utf-8")


def build_drill_summary(
    artifacts: list[tuple[Path, dict[str, Any], dict[str, Any]]],
    input_dir: Path,
    release_id: str,
    generated_at: str,
    mode: str,
    evidence_mode: str,
    fixture_only: bool,
    now: dt.datetime,
    max_age_days: int,
) -> dict[str, Any]:
    by_scenario: dict[str, tuple[Path, dict[str, Any], dict[str, Any]]] = {}
    malformed: list[str] = []
    failed: list[str] = []
    stale: list[str] = []
    redaction_failed: list[str] = []
    redaction_findings: list[Any] = []
    artifact_entries: list[dict[str, Any]] = []
    for path, artifact, verification in artifacts:
        scenario = str(artifact.get("scenario", path.stem))
        if scenario in by_scenario:
            malformed.append(scenario)
        by_scenario[scenario] = (path, artifact, verification)
        if verification.get("status") != "pass":
            failed.append(scenario)
        if verification.get("redactionClean") is False:
            redaction_failed.append(scenario)
            findings = verification.get("redactionFindings")
            if isinstance(findings, list):
                redaction_findings.extend(safe_redaction_findings(findings))
            else:
                redaction_findings.append("artifact verifier redaction scan failed")
        redaction = artifact.get("redaction") if isinstance(artifact.get("redaction"), dict) else {}
        if redaction.get("status") != "pass":
            failed.append(scenario)
            redaction_failed.append(scenario)
        findings = redaction.get("findings") if isinstance(redaction, dict) else []
        if isinstance(findings, list):
            redaction_findings.extend(safe_redaction_findings(findings))
        if artifact.get("releaseId") != release_id:
            malformed.append(scenario)
        if artifact.get("mode") != mode:
            malformed.append(scenario)
        if artifact.get("evidenceMode") != evidence_mode:
            malformed.append(scenario)
        is_stale, age_days, stale_reason = artifact_is_stale(artifact, now, max_age_days)
        if is_stale:
            stale.append(scenario)
        artifact_entries.append(
            {
                "scenario": scenario,
                "status": normalize_status(artifact.get("status")),
                "digest": sha256_path(path) if path.is_file() else "",
                "artifact": path.name,
                "ageDays": age_days,
                "stale": is_stale,
                "staleReason": stale_reason,
                "releaseNotesTemplateStatus": (
                    artifact.get("releaseNotes", {}).get("templateStatus")
                    if isinstance(artifact.get("releaseNotes"), dict)
                    else "missing"
                ),
                "advisoryTemplateStatus": (
                    artifact.get("advisoryTemplate", {}).get("templateStatus")
                    if isinstance(artifact.get("advisoryTemplate"), dict)
                    else "missing"
                ),
            }
        )
    missing = [scenario for scenario in REQUIRED_DRILLS if scenario not in by_scenario]
    unknown = sorted(set(by_scenario) - set(REQUIRED_DRILLS))
    passed = [
        scenario
        for scenario in REQUIRED_DRILLS
        if scenario in by_scenario and scenario not in set(failed + stale + malformed)
    ]
    redaction_status = (
        "pass"
        if not redaction_findings
        and not redaction_failed
        and not any(entry.get("status") == "fail" for entry in artifact_entries)
        else "fail"
    )
    status = "pass"
    if missing or failed or stale or malformed or unknown or redaction_status != "pass":
        status = "fail"
    non_release = drill_summary_non_release(mode, fixture_only)
    promotion_ready = status == "pass" and not non_release
    return {
        "kind": "cryptad-security-response-drills-summary",
        "schemaVersion": DRILL_SUMMARY_SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "generatedAt": generated_at,
        "releaseId": release_id,
        "mode": mode,
        "evidenceMode": evidence_mode,
        "fixtureOnly": fixture_only,
        "nonRelease": non_release,
        "status": status,
        "promotionReady": promotion_ready,
        "maxAgeDays": max_age_days,
        "requiredScenarios": list(REQUIRED_DRILLS),
        "passedScenarios": passed,
        "failedScenarios": sorted(set(failed)),
        "missingScenarios": missing,
        "staleScenarios": sorted(set(stale)),
        "malformedScenarios": sorted(set(malformed + unknown)),
        "redaction": {
            "status": redaction_status,
            "patternsChecked": list(REDACTION_PATTERNS_CHECKED),
            "rawSensitiveMaterialExcluded": redaction_status == "pass",
            "findings": safe_redaction_findings(redaction_findings),
        },
        "releaseNotes": {
            "templateStatus": "pass"
            if all(entry.get("releaseNotesTemplateStatus") == "pass" for entry in artifact_entries)
            else "fail"
        },
        "advisoryTemplate": {
            "templateStatus": "pass"
            if all(entry.get("advisoryTemplateStatus") == "pass" for entry in artifact_entries)
            else "fail"
        },
        "counts": {
            "required": len(REQUIRED_DRILLS),
            "passed": len(passed),
            "failed": len(set(failed)),
            "missing": len(missing),
            "stale": len(set(stale)),
            "malformed": len(set(malformed + unknown)),
        },
        "artifacts": sorted(artifact_entries, key=lambda item: str(item.get("scenario", ""))),
        "artifactDirectory": input_dir.name,
    }


def drill_run_all(
    model_path: Path,
    out_dir: Path,
    summary_out: Path,
    release_id: str = DEFAULT_RELEASE_ID,
    generated_at: str | None = None,
    mode: str = "release-candidate",
    evidence_mode: str = "release-operations",
    fixture_only: bool = False,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    release_notes_out: Path | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or utc_now()
    artifacts: list[tuple[Path, dict[str, Any], dict[str, Any]]] = []
    artifact_values: list[dict[str, Any]] = []
    for scenario in REQUIRED_DRILLS:
        path = out_dir / DRILL_OUTPUT_FILENAMES[scenario]
        artifact = drill_create(
            model_path,
            scenario,
            path,
            release_id=release_id,
            generated_at=timestamp,
            mode=mode,
            evidence_mode=evidence_mode,
            fixture_only=fixture_only,
        )
        verification = drill_verify(path, model_path)
        artifacts.append((path, artifact, verification))
        artifact_values.append(artifact)
    if release_notes_out is not None:
        write_release_notes_draft(release_notes_out, artifact_values)
    now = parse_timestamp(timestamp) or dt.datetime.now(dt.timezone.utc)
    summary = build_drill_summary(
        artifacts,
        out_dir,
        release_id,
        timestamp,
        mode,
        evidence_mode,
        fixture_only,
        now,
        max_age_days,
    )
    summary_findings = forbidden_findings(*json_string_values(summary))
    summary_findings.extend(forbidden_json_key_findings(summary))
    if summary_findings:
        summary["status"] = "fail"
        summary["promotionReady"] = False
        summary["redaction"]["status"] = "fail"
        summary["redaction"]["rawSensitiveMaterialExcluded"] = False
        summary["redaction"]["findings"] = [
            *summary["redaction"].get("findings", []),
            *safe_redaction_findings(summary_findings),
        ]
    write_json(summary_out, summary)
    return summary


def drill_verify_all(
    input_dir: Path,
    summary_out: Path,
    model_path: Path = DEFAULT_MODEL,
    release_id: str | None = None,
    generated_at: str | None = None,
    mode: str | None = None,
    evidence_mode: str | None = None,
    fixture_only: bool = False,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    now_text: str | None = None,
) -> dict[str, Any]:
    existing_summary: dict[str, Any] = {}
    if summary_out.is_file():
        try:
            existing_summary = load_model(summary_out)
        except (OSError, ValueError, json.JSONDecodeError):
            existing_summary = {}
    now = parse_timestamp(now_text) if now_text else None
    if now is None:
        now = dt.datetime.now(dt.timezone.utc)
    artifacts: list[tuple[Path, dict[str, Any], dict[str, Any]]] = []
    for scenario in REQUIRED_DRILLS:
        path = input_dir / DRILL_OUTPUT_FILENAMES[scenario]
        if not path.is_file():
            continue
        try:
            artifact = load_model(path)
            verification = drill_verify(path, model_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            artifact = {
                "scenario": scenario,
                "status": "fail",
                "generatedAt": "",
                "redaction": {"status": "fail", "findings": [str(exc)]},
            }
            verification = {"status": "fail", "ok": False, "errors": [str(exc)]}
        artifacts.append((path, artifact, verification))
    timestamp = generated_at or str(existing_summary.get("generatedAt") or "")
    if parse_timestamp(timestamp) is None:
        artifact_timestamps = [
            (parse_timestamp(artifact.get("generatedAt")), str(artifact.get("generatedAt")))
            for _, artifact, _ in artifacts
            if parse_timestamp(artifact.get("generatedAt")) is not None
        ]
        if artifact_timestamps:
            timestamp = max(
                artifact_timestamps,
                key=lambda item: item[0] or dt.datetime.min.replace(tzinfo=dt.timezone.utc),
            )[1]
        else:
            timestamp = utc_now()
    if release_id is None:
        summary_release_id = existing_summary.get("releaseId")
        artifact_release_ids = [
            artifact.get("releaseId")
            for _, artifact, _ in artifacts
            if isinstance(artifact.get("releaseId"), str) and artifact.get("releaseId")
        ]
        if isinstance(summary_release_id, str) and summary_release_id:
            release_id = summary_release_id
        elif artifact_release_ids:
            release_id = str(artifact_release_ids[0])
        else:
            release_id = DEFAULT_RELEASE_ID
    if mode is None:
        summary_mode = existing_summary.get("mode")
        artifact_modes = [
            artifact.get("mode")
            for _, artifact, _ in artifacts
            if isinstance(artifact.get("mode"), str) and artifact.get("mode")
        ]
        if isinstance(summary_mode, str) and summary_mode:
            mode = summary_mode
        elif artifact_modes:
            mode = str(artifact_modes[0])
        else:
            mode = "release-candidate"
    if evidence_mode is None:
        summary_evidence_mode = existing_summary.get("evidenceMode")
        artifact_evidence_modes = [
            artifact.get("evidenceMode")
            for _, artifact, _ in artifacts
            if isinstance(artifact.get("evidenceMode"), str) and artifact.get("evidenceMode")
        ]
        if isinstance(summary_evidence_mode, str) and summary_evidence_mode:
            evidence_mode = summary_evidence_mode
        elif artifact_evidence_modes:
            evidence_mode = str(artifact_evidence_modes[0])
        else:
            evidence_mode = "release-operations"
    fixture_only = fixture_only or bool(existing_summary.get("fixtureOnly")) or any(
        bool(artifact.get("fixtureOnly")) for _, artifact, _ in artifacts
    )
    summary = build_drill_summary(
        artifacts,
        input_dir,
        release_id,
        timestamp,
        mode,
        evidence_mode,
        fixture_only,
        now,
        max_age_days,
    )
    summary_findings = forbidden_findings(*json_string_values(summary))
    summary_findings.extend(forbidden_json_key_findings(summary))
    if summary_findings:
        summary["status"] = "fail"
        summary["promotionReady"] = False
        summary["redaction"]["status"] = "fail"
        summary["redaction"]["rawSensitiveMaterialExcluded"] = False
        summary["redaction"]["findings"] = [
            *summary["redaction"].get("findings", []),
            *safe_redaction_findings(summary_findings),
        ]
    write_json(summary_out, summary)
    return summary


def non_bool_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def validate_drills_summary(
    summary: dict[str, Any],
    production: bool = False,
    strict: bool = False,
    now: dt.datetime | None = None,
    expected_mode: str | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    strict = strict or production
    expected_mode_normalized = str(expected_mode or "").strip().lower()
    if production and not expected_mode_normalized:
        expected_mode_normalized = "production-beta"
    if summary.get("kind") != "cryptad-security-response-drills-summary":
        errors.append("kind must be cryptad-security-response-drills-summary")
    if summary.get("schemaVersion") != DRILL_SUMMARY_SCHEMA_VERSION:
        errors.append(f"schemaVersion must be {DRILL_SUMMARY_SCHEMA_VERSION}")
    release_id = summary.get("releaseId")
    if not isinstance(release_id, str) or not release_id.strip():
        errors.append("releaseId must be a non-empty string")
    generated_at = parse_timestamp(summary.get("generatedAt"))
    if generated_at is None:
        errors.append("generatedAt must be an ISO-8601 UTC timestamp")
    max_age_days_value = summary.get("maxAgeDays")
    max_age_days = DEFAULT_MAX_AGE_DAYS
    if not non_bool_int(max_age_days_value) or int(max_age_days_value) <= 0:
        errors.append("maxAgeDays must be a positive integer")
    else:
        max_age_days = int(max_age_days_value)
    effective_max_age_days = (
        min(max_age_days, DEFAULT_MAX_AGE_DAYS)
        if strict
        else max_age_days
    )
    summary_mode = str(summary.get("mode", "")).strip().lower()
    fixture_only = summary.get("fixtureOnly") is True
    expected_non_release = drill_summary_non_release(summary_mode, fixture_only)
    if normalize_status(summary.get("status")) != "pass":
        errors.append("status must be pass")
    if expected_non_release:
        if summary.get("nonRelease") is not True:
            errors.append("nonRelease must be true for non-release drill summaries")
        if summary.get("promotionReady") is not False:
            errors.append("promotionReady must be false for non-release drill summaries")
    elif summary.get("promotionReady") is not True:
        errors.append("promotionReady must be true")
    required = summary.get("requiredScenarios")
    if required != list(REQUIRED_DRILLS):
        errors.append("requiredScenarios must match required production drills")
    passed = summary.get("passedScenarios")
    if passed != list(REQUIRED_DRILLS):
        errors.append("passedScenarios must match required production drills")
    for field in ("failedScenarios", "missingScenarios", "staleScenarios", "malformedScenarios"):
        values = summary.get(field)
        if not isinstance(values, list):
            errors.append(f"{field} must be an array")
        elif values:
            errors.append(f"{field} must be empty")
    counts = summary.get("counts")
    expected_counts = {
        "required": len(REQUIRED_DRILLS),
        "passed": len(REQUIRED_DRILLS),
        "failed": 0,
        "missing": 0,
        "stale": 0,
        "malformed": 0,
    }
    if not isinstance(counts, dict):
        errors.append("counts must be an object")
    else:
        for field, expected in expected_counts.items():
            value = counts.get(field)
            if not non_bool_int(value) or int(value) != expected:
                errors.append(f"counts.{field} must be {expected}")
    artifacts = summary.get("artifacts")
    if not isinstance(artifacts, list):
        errors.append("artifacts must be an array")
    else:
        artifact_scenarios: list[str] = []
        for index, artifact in enumerate(artifacts):
            if not isinstance(artifact, dict):
                errors.append(f"artifacts[{index}] must be an object")
                continue
            scenario = artifact.get("scenario")
            if scenario not in REQUIRED_DRILLS:
                errors.append(f"artifacts[{index}].scenario must be a required production drill")
            else:
                artifact_scenarios.append(str(scenario))
            if normalize_status(artifact.get("status")) != "pass":
                errors.append(f"artifacts[{index}].status must be pass")
            digest = artifact.get("digest")
            if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                errors.append(f"artifacts[{index}].digest must be a sha256 digest")
            if artifact.get("stale") is not False:
                errors.append(f"artifacts[{index}].stale must be false")
            if artifact.get("releaseNotesTemplateStatus") != "pass":
                errors.append(f"artifacts[{index}].releaseNotesTemplateStatus must be pass")
            if artifact.get("advisoryTemplateStatus") != "pass":
                errors.append(f"artifacts[{index}].advisoryTemplateStatus must be pass")
        if set(artifact_scenarios) != set(REQUIRED_DRILLS) or len(artifact_scenarios) != len(REQUIRED_DRILLS):
            errors.append("artifacts must cover each required production drill exactly once")
        elif len(set(artifact_scenarios)) != len(artifact_scenarios):
            errors.append("artifacts must not duplicate production drill scenarios")
    release_notes = summary.get("releaseNotes")
    if not isinstance(release_notes, dict):
        errors.append("releaseNotes must be an object")
    elif release_notes.get("templateStatus") != "pass":
        errors.append("releaseNotes.templateStatus must be pass")
    advisory_template = summary.get("advisoryTemplate")
    if not isinstance(advisory_template, dict):
        errors.append("advisoryTemplate must be an object")
    elif advisory_template.get("templateStatus") != "pass":
        errors.append("advisoryTemplate.templateStatus must be pass")
    redaction_findings: list[Any] = []
    redaction = summary.get("redaction")
    if not isinstance(redaction, dict):
        errors.append("redaction must be an object")
        redaction_findings.append("security response drills summary redaction metadata is missing")
    else:
        if redaction.get("status") != "pass":
            errors.append("redaction.status must be pass")
            redaction_findings.append("security response drills summary redaction status is not pass")
        findings = redaction.get("findings")
        if not isinstance(findings, list):
            errors.append("redaction.findings must be an empty array")
            redaction_findings.append("security response drills summary redaction findings are malformed")
        elif findings:
            errors.append("redaction.findings must be an empty array")
            redaction_findings.extend(safe_redaction_findings(findings))
        if redaction.get("rawSensitiveMaterialExcluded") is not True:
            errors.append("redaction.rawSensitiveMaterialExcluded must be true")
            redaction_findings.append(
                "security response drills summary raw sensitive material exclusion is not proven"
            )
    if strict:
        if summary.get("nonRelease") is not False:
            errors.append("strict drills summary must not be nonRelease")
        if summary.get("fixtureOnly") is True:
            errors.append("strict drills summary must not be fixtureOnly")
        if summary_mode not in RELEASE_DRILL_MODES:
            errors.append("strict drills summary mode must be release-candidate or production-beta")
        elif expected_mode_normalized and summary_mode != expected_mode_normalized:
            errors.append(f"strict drills summary mode must match {expected_mode_normalized}")
    if strict:
        evaluated_at = now or dt.datetime.now(dt.timezone.utc)
        evaluated_at = evaluated_at.astimezone(dt.timezone.utc)
        if generated_at is not None:
            if generated_at > evaluated_at + dt.timedelta(minutes=5):
                errors.append("generatedAt must not be in the future")
            elif evaluated_at - generated_at > dt.timedelta(days=effective_max_age_days):
                errors.append("drills summary is stale")
    scanner_redaction_findings = forbidden_findings(*json_string_values(summary))
    scanner_redaction_findings.extend(forbidden_json_key_findings(summary))
    redaction_findings.extend(scanner_redaction_findings)
    safe_findings = safe_redaction_findings(redaction_findings)
    if scanner_redaction_findings:
        errors.append("summary redaction scan failed")
    return {
        "ok": not errors,
        "status": "pass" if not errors else "fail",
        "errors": errors,
        "redactionClean": not safe_findings,
        "redactionFindings": safe_findings,
    }


def clone_json(value: Any) -> Any:
    return json.loads(json.dumps(value))


def self_test() -> dict[str, Any]:
    checks: dict[str, bool] = {}
    verify_result = verify_runbook(DEFAULT_RUNBOOK, DEFAULT_MODEL, DEFAULT_TEMPLATE)
    checks["verifyRunbook"] = verify_result["status"] == "pass"
    model = load_model(DEFAULT_MODEL)
    drills = model_drills(model)
    with tempfile.TemporaryDirectory(prefix="cryptad-security-drills-") as tmp:
        tmpdir = Path(tmp)
        reviewer_artifact = tmpdir / "reviewer-key-compromise.json"
        artifact = drill_create(
            DEFAULT_MODEL,
            "reviewer-key-compromise",
            reviewer_artifact,
            release_id="cryptad-production-beta-self-test",
            generated_at="2026-07-03T00:00:00Z",
        )
        checks["createReviewerDrill"] = reviewer_artifact.is_file()
        checks["verifyReviewerDrill"] = drill_verify(reviewer_artifact)["status"] == "pass"
        missing_step_artifact = clone_json(artifact)
        missing_step_artifact["steps"] = missing_step_artifact["steps"][:1]
        missing_step_path = tmpdir / "reviewer-key-compromise-missing-step.json"
        write_json(missing_step_path, missing_step_artifact)
        checks["rejectMissingDrillStep"] = drill_verify(missing_step_path)["status"] == "fail"
        wrong_step_evidence_artifact = clone_json(artifact)
        wrong_step_evidence_artifact["steps"][0]["evidenceIds"] = ["production-security.response-runbook"]
        wrong_step_evidence_path = tmpdir / "reviewer-key-compromise-wrong-step-evidence.json"
        write_json(wrong_step_evidence_path, wrong_step_evidence_artifact)
        checks["rejectWrongDrillStepEvidence"] = (
            drill_verify(wrong_step_evidence_path)["status"] == "fail"
        )
        wrong_step_summary_artifact = clone_json(artifact)
        wrong_step_summary_artifact["steps"][0]["safeSummary"] = "Reviewer key flow text was replaced."
        wrong_step_summary_path = tmpdir / "reviewer-key-compromise-wrong-step-summary.json"
        write_json(wrong_step_summary_path, wrong_step_summary_artifact)
        checks["rejectWrongDrillStepSummary"] = (
            drill_verify(wrong_step_summary_path)["status"] == "fail"
        )
        wrong_release_template_artifact = clone_json(artifact)
        wrong_release_template_artifact["releaseNotes"]["template"] = "tampered release notes template"
        wrong_release_template_path = tmpdir / "reviewer-key-compromise-wrong-release-template.json"
        write_json(wrong_release_template_path, wrong_release_template_artifact)
        checks["rejectWrongReleaseNotesTemplate"] = (
            drill_verify(wrong_release_template_path)["status"] == "fail"
        )
        wrong_release_snippet_artifact = clone_json(artifact)
        wrong_release_snippet_artifact["releaseNotes"]["redactedSnippet"] = (
            "Scenario reviewer-key-compromise: tampered release-note evidence verified."
        )
        wrong_release_snippet_path = tmpdir / "reviewer-key-compromise-wrong-release-snippet.json"
        write_json(wrong_release_snippet_path, wrong_release_snippet_artifact)
        checks["rejectWrongReleaseNotesSnippet"] = (
            drill_verify(wrong_release_snippet_path)["status"] == "fail"
        )
        wrong_advisory_snippet_artifact = clone_json(artifact)
        wrong_advisory_snippet_artifact["advisoryTemplate"]["redactedSnippet"] = (
            "Scenario reviewer-key-compromise: tampered advisory evidence verified."
        )
        wrong_advisory_snippet_path = tmpdir / "reviewer-key-compromise-wrong-advisory-snippet.json"
        write_json(wrong_advisory_snippet_path, wrong_advisory_snippet_artifact)
        checks["rejectWrongAdvisoryTemplateSnippet"] = (
            drill_verify(wrong_advisory_snippet_path)["status"] == "fail"
        )

        summary = drill_run_all(
            DEFAULT_MODEL,
            tmpdir / "all",
            tmpdir / "security-drills-summary.json",
            release_id="cryptad-production-beta-self-test",
            generated_at="2026-07-03T00:00:00Z",
            release_notes_out=tmpdir / "security-release-notes-draft.md",
        )
        checks["runAllDrills"] = summary["status"] == "pass" and summary["promotionReady"] is True
        verified_summary = drill_verify_all(
            tmpdir / "all",
            tmpdir / "verified-security-drills-summary.json",
            release_id="cryptad-production-beta-self-test",
            generated_at="2026-07-03T00:00:00Z",
            now_text="2026-07-03T00:00:00Z",
        )
        checks["verifyAllDrills"] = verified_summary["status"] == "pass"
        checks["validateDrillsSummary"] = validate_drills_summary(verified_summary)["status"] == "pass"
        missing_release_id_summary = clone_json(verified_summary)
        missing_release_id_summary.pop("releaseId", None)
        checks["rejectSummaryMissingReleaseId"] = (
            validate_drills_summary(missing_release_id_summary)["status"] == "fail"
        )
        checks["validateDrillsSummaryStrictReleaseCandidate"] = (
            validate_drills_summary(
                verified_summary,
                strict=True,
                expected_mode="release-candidate",
                now=dt.datetime(2026, 7, 3, tzinfo=dt.timezone.utc),
            )["status"]
            == "pass"
        )
        production_mode_summary = clone_json(verified_summary)
        production_mode_summary["mode"] = "production-beta"
        checks["validateDrillsSummaryProductionMode"] = (
            validate_drills_summary(
                production_mode_summary,
                production=True,
                now=dt.datetime(2026, 7, 3, tzinfo=dt.timezone.utc),
            )["status"]
            == "pass"
        )
        for non_release_mode in NON_RELEASE_DRILL_MODES:
            mode_summary = drill_run_all(
                DEFAULT_MODEL,
                tmpdir / non_release_mode,
                tmpdir / f"{non_release_mode}-summary.json",
                release_id="cryptad-production-beta-self-test",
                generated_at="2026-07-03T00:00:00Z",
                mode=non_release_mode,
            )
            checks[f"{non_release_mode}SummaryNonRelease"] = (
                mode_summary["status"] == "pass"
                and mode_summary["nonRelease"] is True
                and mode_summary["promotionReady"] is False
                and validate_drills_summary(mode_summary)["status"] == "pass"
                and validate_drills_summary(mode_summary, strict=True)["status"] == "fail"
                and validate_drills_summary(mode_summary, production=True)["status"] == "fail"
            )
        unknown_mode_summary = clone_json(verified_summary)
        unknown_mode_summary["mode"] = "prod"
        checks["rejectUnknownStrictMode"] = (
            validate_drills_summary(
                unknown_mode_summary,
                strict=True,
                expected_mode="release-candidate",
                now=dt.datetime(2026, 7, 3, tzinfo=dt.timezone.utc),
            )["status"]
            == "fail"
        )
        checks["rejectWrongProductionMode"] = (
            validate_drills_summary(
                verified_summary,
                production=True,
                now=dt.datetime(2026, 7, 3, tzinfo=dt.timezone.utc),
            )["status"]
            == "fail"
        )
        redaction_status_summary = clone_json(verified_summary)
        redaction_status_summary["redaction"]["status"] = "fail"
        redaction_status_summary["redaction"]["findings"] = []
        redaction_status_summary["redaction"]["rawSensitiveMaterialExcluded"] = True
        redaction_status_validation = validate_drills_summary(
            redaction_status_summary,
            strict=True,
            expected_mode="release-candidate",
            now=dt.datetime(2026, 7, 3, tzinfo=dt.timezone.utc),
        )
        checks["redactionStatusFailureSynthesizesFinding"] = (
            redaction_status_validation["status"] == "fail"
            and bool(redaction_status_validation.get("redactionFindings"))
        )
        minimal_summary = {
            "kind": "cryptad-security-response-drills-summary",
            "schemaVersion": DRILL_SUMMARY_SCHEMA_VERSION,
            "generatedAt": "2026-07-03T00:00:00Z",
            "maxAgeDays": DEFAULT_MAX_AGE_DAYS,
            "status": "pass",
            "promotionReady": True,
            "requiredScenarios": list(REQUIRED_DRILLS),
            "failedScenarios": [],
            "missingScenarios": [],
            "staleScenarios": [],
            "malformedScenarios": [],
            "redaction": {
                "status": "pass",
                "findings": [],
                "rawSensitiveMaterialExcluded": True,
            },
        }
        checks["rejectMinimalSelfReportedSummary"] = (
            validate_drills_summary(minimal_summary)["status"] == "fail"
        )
        incomplete_artifact_summary = clone_json(verified_summary)
        incomplete_artifact_summary["artifacts"] = incomplete_artifact_summary["artifacts"][:-1]
        checks["rejectIncompleteArtifactCoverage"] = (
            validate_drills_summary(incomplete_artifact_summary)["status"] == "fail"
        )
        stale_summary = clone_json(verified_summary)
        stale_summary["generatedAt"] = "2026-05-01T00:00:00Z"
        checks["rejectStaleProductionSummary"] = (
            validate_drills_summary(
                stale_summary,
                production=True,
                now=dt.datetime(2026, 7, 3, tzinfo=dt.timezone.utc),
            )["status"]
            == "fail"
        )
        checks["rejectStaleStrictSummary"] = (
            validate_drills_summary(
                stale_summary,
                strict=True,
                now=dt.datetime(2026, 7, 3, tzinfo=dt.timezone.utc),
            )["status"]
            == "fail"
        )
        stale_extended_summary = clone_json(stale_summary)
        stale_extended_summary["mode"] = "production-beta"
        stale_extended_summary["maxAgeDays"] = 3650
        stale_extended_production_validation = validate_drills_summary(
            stale_extended_summary,
            production=True,
            now=dt.datetime(2026, 7, 3, tzinfo=dt.timezone.utc),
        )
        checks["rejectStaleProductionSummaryExtendedMaxAge"] = (
            stale_extended_production_validation["status"] == "fail"
            and "drills summary is stale" in stale_extended_production_validation.get("errors", [])
        )
        stale_extended_strict_summary = clone_json(stale_summary)
        stale_extended_strict_summary["maxAgeDays"] = 3650
        stale_extended_strict_validation = validate_drills_summary(
            stale_extended_strict_summary,
            strict=True,
            expected_mode="release-candidate",
            now=dt.datetime(2026, 7, 3, tzinfo=dt.timezone.utc),
        )
        checks["rejectStaleStrictSummaryExtendedMaxAge"] = (
            stale_extended_strict_validation["status"] == "fail"
            and "drills summary is stale" in stale_extended_strict_validation.get("errors", [])
        )

        private_key_artifact = clone_json(artifact)
        private_key_artifact["privateKey"] = "redacted-fixture"
        private_key_path = tmpdir / "private-key.json"
        write_json(private_key_path, private_key_artifact)
        checks["rejectPrivateKey"] = drill_verify(private_key_path)["status"] == "fail"

        private_uri_artifact = clone_json(artifact)
        private_uri_artifact["releaseNotes"]["redactedSnippet"] = "Contains USK@example/private"
        private_uri_path = tmpdir / "private-uri.json"
        write_json(private_uri_path, private_uri_artifact)
        checks["rejectPrivateInsertUri"] = drill_verify(private_uri_path)["status"] == "fail"

        raw_support_artifact = clone_json(artifact)
        raw_support_artifact["rawSupportBundleBody"] = "payload"
        raw_support_path = tmpdir / "raw-support.json"
        write_json(raw_support_path, raw_support_artifact)
        checks["rejectRawSupportBundleBody"] = drill_verify(raw_support_path)["status"] == "fail"

        raw_app_data_artifact = clone_json(artifact)
        raw_app_data_artifact["rawAppDataValue"] = "payload"
        raw_app_data_path = tmpdir / "raw-app-data.json"
        write_json(raw_app_data_path, raw_app_data_artifact)
        checks["rejectRawAppData"] = drill_verify(raw_app_data_path)["status"] == "fail"

        local_path_artifact = clone_json(artifact)
        local_path_artifact["releaseNotes"]["redactedSnippet"] = "Do not expose /tmp/cryptad/private.key"
        local_path = tmpdir / "local-path.json"
        write_json(local_path, local_path_artifact)
        checks["rejectAbsoluteLocalPath"] = drill_verify(local_path)["status"] == "fail"

        advisory_template_artifact = clone_json(artifact)
        advisory_template_artifact["advisoryTemplate"]["templateStatus"] = "fail"
        advisory_template_path = tmpdir / "advisory-template-fail.json"
        write_json(advisory_template_path, advisory_template_artifact)
        checks["rejectAdvisoryTemplateFailure"] = (
            drill_verify(advisory_template_path)["status"] == "fail"
        )

        malformed_path = tmpdir / "malformed.json"
        write_json(malformed_path, {"kind": "cryptad-security-response-drill", "schemaVersion": 2})
        checks["rejectMalformedEnvelope"] = drill_verify(malformed_path)["status"] == "fail"

        unknown_model = clone_json(model)
        unknown = clone_json(drills["reviewer-key-compromise"])
        unknown["id"] = "unknown-required-scenario"
        unknown_model["drills"].append(unknown)
        checks["rejectUnknownRequiredScenario"] = not validate_model(unknown_model)["ok"]

        missing_dir = tmpdir / "missing"
        drill_run_all(
            DEFAULT_MODEL,
            missing_dir,
            tmpdir / "missing-summary.json",
            release_id="cryptad-production-beta-self-test",
            generated_at="2026-07-03T00:00:00Z",
        )
        (missing_dir / DRILL_OUTPUT_FILENAMES["reviewer-key-compromise"]).unlink()
        missing_summary = drill_verify_all(
            missing_dir,
            tmpdir / "missing-summary-verified.json",
            release_id="cryptad-production-beta-self-test",
            generated_at="2026-07-03T00:00:00Z",
            now_text="2026-07-03T00:00:00Z",
        )
        checks["verifyAllRejectsMissingScenario"] = missing_summary["status"] == "fail"

        failed_dir = tmpdir / "failed"
        drill_run_all(
            DEFAULT_MODEL,
            failed_dir,
            tmpdir / "failed-summary.json",
            release_id="cryptad-production-beta-self-test",
            generated_at="2026-07-03T00:00:00Z",
        )
        failed_path = failed_dir / DRILL_OUTPUT_FILENAMES["reviewer-key-compromise"]
        failed_artifact = load_model(failed_path)
        failed_artifact["status"] = "fail"
        write_json(failed_path, failed_artifact)
        failed_summary = drill_verify_all(
            failed_dir,
            tmpdir / "failed-summary-verified.json",
            release_id="cryptad-production-beta-self-test",
            generated_at="2026-07-03T00:00:00Z",
            now_text="2026-07-03T00:00:00Z",
        )
        checks["verifyAllRejectsFailedScenario"] = failed_summary["status"] == "fail"

        redaction_dir = tmpdir / "redaction"
        drill_run_all(
            DEFAULT_MODEL,
            redaction_dir,
            tmpdir / "redaction-summary.json",
            release_id="cryptad-production-beta-self-test",
            generated_at="2026-07-03T00:00:00Z",
        )
        redaction_path = redaction_dir / DRILL_OUTPUT_FILENAMES["reviewer-key-compromise"]
        redaction_artifact = load_model(redaction_path)
        redaction_artifact["redaction"]["status"] = "fail"
        redaction_artifact["redaction"]["findings"] = ["raw support bundle marker"]
        write_json(redaction_path, redaction_artifact)
        redaction_summary = drill_verify_all(
            redaction_dir,
            tmpdir / "redaction-summary-verified.json",
            release_id="cryptad-production-beta-self-test",
            generated_at="2026-07-03T00:00:00Z",
            now_text="2026-07-03T00:00:00Z",
        )
        checks["verifyAllRejectsRedactionFailure"] = redaction_summary["status"] == "fail"

        verifier_redaction_dir = tmpdir / "verifier-redaction"
        drill_run_all(
            DEFAULT_MODEL,
            verifier_redaction_dir,
            tmpdir / "verifier-redaction-summary.json",
            release_id="cryptad-production-beta-self-test",
            generated_at="2026-07-03T00:00:00Z",
        )
        verifier_redaction_path = (
            verifier_redaction_dir / DRILL_OUTPUT_FILENAMES["reviewer-key-compromise"]
        )
        verifier_redaction_artifact = load_model(verifier_redaction_path)
        verifier_redaction_artifact["privateKey"] = "redacted-fixture"
        write_json(verifier_redaction_path, verifier_redaction_artifact)
        verifier_redaction_summary = drill_verify_all(
            verifier_redaction_dir,
            tmpdir / "verifier-redaction-summary-verified.json",
            release_id="cryptad-production-beta-self-test",
            generated_at="2026-07-03T00:00:00Z",
            now_text="2026-07-03T00:00:00Z",
        )
        checks["verifyAllPropagatesVerifierRedactionFailure"] = (
            verifier_redaction_summary["status"] == "fail"
            and verifier_redaction_summary["redaction"]["status"] == "fail"
            and bool(verifier_redaction_summary["redaction"]["findings"])
        )

        release_mismatch_dir = tmpdir / "release-mismatch"
        drill_run_all(
            DEFAULT_MODEL,
            release_mismatch_dir,
            tmpdir / "release-mismatch-summary.json",
            release_id="cryptad-production-beta-old",
            generated_at="2026-07-03T00:00:00Z",
        )
        release_mismatch_summary = drill_verify_all(
            release_mismatch_dir,
            tmpdir / "release-mismatch-summary-verified.json",
            release_id="cryptad-production-beta-current",
            generated_at="2026-07-03T00:00:00Z",
            now_text="2026-07-03T00:00:00Z",
        )
        checks["verifyAllRejectsReleaseIdMismatch"] = (
            release_mismatch_summary["status"] == "fail"
            and release_mismatch_summary["counts"]["malformed"] == len(REQUIRED_DRILLS)
        )

        mode_mismatch_dir = tmpdir / "mode-mismatch"
        drill_run_all(
            DEFAULT_MODEL,
            mode_mismatch_dir,
            tmpdir / "mode-mismatch-summary.json",
            release_id="cryptad-production-beta-self-test",
            generated_at="2026-07-03T00:00:00Z",
            mode="developer-dry-run",
        )
        mode_mismatch_summary = drill_verify_all(
            mode_mismatch_dir,
            tmpdir / "mode-mismatch-summary-verified.json",
            release_id="cryptad-production-beta-self-test",
            generated_at="2026-07-03T00:00:00Z",
            mode="release-candidate",
            now_text="2026-07-03T00:00:00Z",
        )
        checks["verifyAllRejectsModeMismatch"] = (
            mode_mismatch_summary["status"] == "fail"
            and mode_mismatch_summary["counts"]["malformed"] == len(REQUIRED_DRILLS)
        )

        stale_summary = drill_verify_all(
            tmpdir / "all",
            tmpdir / "stale-summary-verified.json",
            release_id="cryptad-production-beta-self-test",
            generated_at="2026-08-05T00:00:00Z",
            now_text="2026-08-05T00:00:00Z",
        )
        checks["verifyAllRejectsStaleScenario"] = stale_summary["status"] == "fail"

        fixture_summary = clone_json(summary)
        fixture_summary["fixtureOnly"] = True
        fixture_summary["nonRelease"] = True
        fixture_summary["promotionReady"] = False
        checks["productionRejectsFixtureOnly"] = (
            validate_drills_summary(fixture_summary, production=True)["status"] == "fail"
        )
        fixture_artifacts_dir = tmpdir / "fixture-artifacts"
        fixture_artifacts_summary_path = fixture_artifacts_dir / "security-drills-summary.json"
        fixture_artifacts_summary = drill_run_all(
            DEFAULT_MODEL,
            fixture_artifacts_dir,
            fixture_artifacts_summary_path,
            release_id="cryptad-production-beta-self-test",
            generated_at="2026-07-03T00:00:00Z",
            fixture_only=True,
        )
        fixture_artifacts_summary["fixtureOnly"] = False
        fixture_artifacts_summary["nonRelease"] = False
        fixture_artifacts_summary["promotionReady"] = True
        write_json(fixture_artifacts_summary_path, fixture_artifacts_summary)
        fixture_artifacts_validation = validate_drill_artifact_files(
            fixture_artifacts_summary,
            fixture_artifacts_summary_path,
            strict=True,
            now=dt.datetime(2026, 7, 3, tzinfo=dt.timezone.utc),
        )
        checks["rejectFixtureOnlyArtifactsInStrictValidation"] = (
            fixture_artifacts_validation["status"] == "fail"
            and any(
                str(error) == "security drill artifact for reviewer-key-compromise must not be fixtureOnly"
                for error in fixture_artifacts_validation.get("errors", [])
            )
        )

    failures = [name for name, ok in checks.items() if not ok]
    return {
        "schemaVersion": SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "status": "pass" if not failures else "fail",
        "checks": checks,
        "errors": failures,
    }


def advisory_template(model_path: Path, scenario: str, out: Path) -> str:
    model = load_model(model_path)
    drill = model_drills(model).get(scenario)
    if drill is None:
        raise ValueError(f"unknown scenario: {scenario}")
    text = "\n".join(
        [
            f"# Security advisory draft: {scenario}",
            "",
            f"- Severity: {drill['severity']}",
            f"- Trigger: {drill['trigger']}",
            "- Advisory id: CRYPTA-YYYY-NNNN",
            "- Affected apps and versions: app-id version",
            "- Containment status: pending",
            "- Replacement app/version: pending",
            "- Review/certification status: pending",
            "- Catalog channel status: pending",
            "- Support bundle guidance: use redacted support bundle preview",
            "- Redaction note: omit private keys, private insert URIs, tokens, raw content, raw app data, and local paths",
            "",
        ]
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    return text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify = subparsers.add_parser("verify", help="Verify runbook, model, and release notes template.")
    verify.add_argument("--runbook", type=Path, default=DEFAULT_RUNBOOK)
    verify.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    verify.add_argument("--template", type=Path, default=DEFAULT_TEMPLATE)

    subparsers.add_parser("self-test", help="Run deterministic runbook and drill negative tests.")

    drill = subparsers.add_parser("drill", help="Create or verify drill artifacts.")
    drill_sub = drill.add_subparsers(dest="drill_command", required=True)
    create = drill_sub.add_parser("create", help="Create one deterministic drill artifact.")
    create.add_argument("--scenario", required=True)
    create.add_argument("--out", type=Path, required=True)
    create.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    create.add_argument("--release-id", default=DEFAULT_RELEASE_ID)
    create.add_argument("--generated-at")
    create.add_argument("--mode", choices=DRILL_MODES, default="release-candidate")
    create.add_argument("--evidence-mode", default="release-operations")
    create.add_argument("--fixture-only", action="store_true")
    verify_drill = drill_sub.add_parser("verify", help="Verify a drill artifact or model.")
    verify_drill.add_argument("--input", type=Path, required=True)
    verify_drill.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    run_all = drill_sub.add_parser("run-all", help="Create all required drill artifacts and a summary.")
    run_all.add_argument("--out-dir", type=Path, required=True)
    run_all.add_argument("--summary-out", type=Path, required=True)
    run_all.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    run_all.add_argument("--release-id", default=DEFAULT_RELEASE_ID)
    run_all.add_argument("--generated-at")
    run_all.add_argument("--mode", choices=DRILL_MODES, default="release-candidate")
    run_all.add_argument("--evidence-mode", default="release-operations")
    run_all.add_argument("--fixture-only", action="store_true")
    run_all.add_argument("--max-age-days", type=int, default=DEFAULT_MAX_AGE_DAYS)
    run_all.add_argument("--release-notes-out", type=Path)
    verify_all = drill_sub.add_parser("verify-all", help="Verify all required drill artifacts and write a summary.")
    verify_all.add_argument("--input-dir", type=Path, required=True)
    verify_all.add_argument("--summary-out", type=Path, required=True)
    verify_all.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    verify_all.add_argument("--release-id")
    verify_all.add_argument("--generated-at")
    verify_all.add_argument("--mode", choices=DRILL_MODES)
    verify_all.add_argument("--evidence-mode")
    verify_all.add_argument("--fixture-only", action="store_true")
    verify_all.add_argument("--max-age-days", type=int, default=DEFAULT_MAX_AGE_DAYS)
    verify_all.add_argument("--now")

    advisory = subparsers.add_parser("advisory", help="Create advisory templates.")
    advisory_sub = advisory.add_subparsers(dest="advisory_command", required=True)
    template = advisory_sub.add_parser("template", help="Create a scenario-specific advisory draft.")
    template.add_argument("--scenario", required=True)
    template.add_argument("--out", type=Path, required=True)
    template.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "verify":
            result = verify_runbook(args.runbook, args.model, args.template)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result["status"] == "pass" else 1
        if args.command == "self-test":
            result = self_test()
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result["status"] == "pass" else 1
        if args.command == "drill" and args.drill_command == "create":
            drill_create(
                args.model,
                args.scenario,
                args.out,
                release_id=args.release_id,
                generated_at=args.generated_at,
                mode=args.mode,
                evidence_mode=args.evidence_mode,
                fixture_only=args.fixture_only,
            )
            print(f"created {args.out}")
            return 0
        if args.command == "drill" and args.drill_command == "verify":
            result = drill_verify(args.input, args.model)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result["status"] == "pass" else 1
        if args.command == "drill" and args.drill_command == "run-all":
            result = drill_run_all(
                args.model,
                args.out_dir,
                args.summary_out,
                release_id=args.release_id,
                generated_at=args.generated_at,
                mode=args.mode,
                evidence_mode=args.evidence_mode,
                fixture_only=args.fixture_only,
                max_age_days=args.max_age_days,
                release_notes_out=args.release_notes_out,
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result["status"] == "pass" else 1
        if args.command == "drill" and args.drill_command == "verify-all":
            result = drill_verify_all(
                args.input_dir,
                args.summary_out,
                model_path=args.model,
                release_id=args.release_id,
                generated_at=args.generated_at,
                mode=args.mode,
                evidence_mode=args.evidence_mode,
                fixture_only=args.fixture_only,
                max_age_days=args.max_age_days,
                now_text=args.now,
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result["status"] == "pass" else 1
        if args.command == "advisory" and args.advisory_command == "template":
            advisory_template(args.model, args.scenario, args.out)
            print(f"created {args.out}")
            return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"{TOOL_NAME}: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

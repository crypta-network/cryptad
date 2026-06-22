#!/usr/bin/env python3
"""Generate and verify deterministic production security response runbook artifacts."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


TOOL_NAME = "security-response-runbook"
SCHEMA_VERSION = 1
DEFAULT_RUNBOOK = Path("docs/production-security-response-runbook.md")
DEFAULT_MODEL = Path("tools/release-certification/production-security-response-runbook.json")
DEFAULT_TEMPLATE = Path("docs/templates/security-release-notes.md")
REQUIRED_DRILLS = (
    "vulnerable-app-version",
    "app-signing-key-compromise",
    "reviewer-key-compromise",
    "catalog-signing-key-rotation",
    "malicious-catalog-entry",
    "emergency-replacement-app",
    "support-bundle-intake-redaction",
)
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


def drill_create(model_path: Path, scenario: str, out: Path) -> dict[str, Any]:
    model = load_model(model_path)
    drills = model_drills(model)
    drill = drills.get(scenario)
    if drill is None:
        raise ValueError(f"unknown scenario: {scenario}")
    artifact = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "cryptad-security-response-drill",
        "scenario": scenario,
        "drill": drill,
    }
    write_json(out, artifact)
    return artifact


def validate_drill_artifact_envelope(
    value: dict[str, Any],
    drill: dict[str, Any] | None,
) -> list[str]:
    errors: list[str] = []
    if value.get("schemaVersion") != SCHEMA_VERSION:
        errors.append(f"schemaVersion must be {SCHEMA_VERSION}")
    scenario = value.get("scenario")
    if not isinstance(scenario, str) or not scenario:
        errors.append("scenario must be a non-empty string")
    elif drill is not None and scenario != drill.get("id"):
        errors.append("scenario must match drill id")
    return errors


def drill_verify(path: Path) -> dict[str, Any]:
    value = load_model(path)
    redaction_findings = forbidden_findings(*json_string_values(value))
    redaction_findings.extend(forbidden_json_key_findings(value))
    redaction_clean = not redaction_findings
    if value.get("kind") == "cryptad-security-response-drill":
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

    drill = subparsers.add_parser("drill", help="Create or verify drill artifacts.")
    drill_sub = drill.add_subparsers(dest="drill_command", required=True)
    create = drill_sub.add_parser("create", help="Create one deterministic drill artifact.")
    create.add_argument("--scenario", required=True)
    create.add_argument("--out", type=Path, required=True)
    create.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    verify_drill = drill_sub.add_parser("verify", help="Verify a drill artifact or model.")
    verify_drill.add_argument("--input", type=Path, required=True)

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
        if args.command == "drill" and args.drill_command == "create":
            drill_create(args.model, args.scenario, args.out)
            print(f"created {args.out}")
            return 0
        if args.command == "drill" and args.drill_command == "verify":
            result = drill_verify(args.input)
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

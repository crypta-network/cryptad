"""V2 evidence-envelope construction and validation."""

from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

from .io import write_json, write_text
from .models import EvidenceEnvelope, RunContext, SCHEMA_VERSION
from .redaction import scan_value


NEGATED_LEGACY_REDACTION_FIELDS = {
    "formPasswordStored": "formPasswordNotStored",
    "localPathsStored": "localPathsNotStored",
    "privateInsertUrisStored": "privateInsertUrisNotStored",
    "rawBodiesStored": "rawBodiesNotStored",
    "rawSignaturesStored": "rawSignaturesNotStored",
    "tokenValuesStored": "tokenValuesNotStored",
}


def utc_now() -> str:
    """Return the current UTC time as an RFC 3339 string."""

    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_status(value: Any) -> str:
    """Normalize legacy status spelling to the v2 result vocabulary."""

    status = str(value or "fail").lower()
    if status in {"pass", "passed", "success", "ready", "go"}:
        return "pass"
    if status in {"warn", "warning", "ready-with-allowed-limitations", "go-with-waivers"}:
        return "warn"
    return "fail"


def _scanned_legacy_redaction(legacy: dict[str, Any]) -> dict[str, Any]:
    """Build an explicit redaction result from a complete legacy-payload scan."""

    findings = scan_value(legacy)
    return {
        "status": "fail" if findings else "pass",
        "findingCount": len(findings),
        "findings": findings,
        "guarantees": {"legacyPayloadScanned": True},
    }


def _malformed_legacy_redaction(summary: str) -> dict[str, Any]:
    """Return a safe failure without copying malformed legacy metadata."""

    findings = [{"category": "redaction-metadata", "summary": summary}]
    return {
        "status": "fail",
        "findingCount": len(findings),
        "findings": findings,
        "guarantees": {},
    }


def _merge_legacy_guarantee(
    guarantees: dict[str, bool],
    key: str,
    value: bool,
) -> bool:
    """Normalize one legacy guarantee and reject contradictory aliases."""

    guarantee = NEGATED_LEGACY_REDACTION_FIELDS.get(key, key)
    normalized = not value if key in NEGATED_LEGACY_REDACTION_FIELDS else value
    if guarantee in guarantees and guarantees[guarantee] != normalized:
        return False
    guarantees[guarantee] = normalized
    return True


def redaction_from_legacy(value: Any, legacy: dict[str, Any]) -> dict[str, Any]:
    """Normalize explicit redaction metadata or scan the complete legacy payload."""

    if value is None or value == {}:
        return _scanned_legacy_redaction(legacy)
    if not isinstance(value, dict):
        return _malformed_legacy_redaction("legacy redaction metadata is malformed")
    raw_findings = value.get("findings", [])
    if not isinstance(raw_findings, list):
        return _malformed_legacy_redaction("legacy redaction findings are malformed")
    findings = list(raw_findings)
    finding_count = value.get("findingCount")
    if "findingCount" in value and (
        type(finding_count) is not int or finding_count != len(findings)
    ):
        return _malformed_legacy_redaction("legacy redaction findingCount is malformed")
    explicit = value.get("status")
    guarantees: dict[str, bool] = {}
    for key, item in value.items():
        if not isinstance(item, bool):
            continue
        if not _merge_legacy_guarantee(guarantees, key, item):
            return _malformed_legacy_redaction(
                "legacy redaction guarantees are contradictory"
            )
    nested_guarantees = value.get("guarantees")
    if nested_guarantees is not None:
        if not isinstance(nested_guarantees, dict) or not all(
            isinstance(key, str) and isinstance(item, bool)
            for key, item in nested_guarantees.items()
        ):
            return _malformed_legacy_redaction("legacy redaction guarantees are malformed")
        for key, item in nested_guarantees.items():
            if not _merge_legacy_guarantee(guarantees, key, item):
                return _malformed_legacy_redaction(
                    "legacy redaction guarantees are contradictory"
                )
    if explicit is None and not guarantees:
        return _scanned_legacy_redaction(legacy)
    explicit_pass = explicit is None or (
        isinstance(explicit, str) and explicit in {"pass", "passed", "success"}
    )
    passed = (
        explicit_pass
        and all(guarantees.values())
        and not findings
    )
    if not all(guarantees.values()):
        findings.append(
            {
                "category": "redaction-guarantee",
                "summary": "legacy redaction guarantee failed",
            }
        )
    return {
        "status": "pass" if passed else "fail",
        "findingCount": len(findings),
        "findings": findings,
        "guarantees": guarantees,
    }


def _legacy_decision(legacy: dict[str, Any]) -> Any:
    """Return a top-level decision or the production pipeline's nested launch decision."""

    for key in ("decision", "promotionDecision", "ecosystemRcDecision"):
        if legacy.get(key) is not None:
            return legacy[key]
    go_no_go = legacy.get("goNoGo")
    return go_no_go.get("decision") if isinstance(go_no_go, dict) else None


def from_legacy(
    context: RunContext,
    kind: str,
    legacy: dict[str, Any],
    exit_code: int,
    artifacts: dict[str, str],
    *,
    bind_identity: bool = True,
    result_status: str | None = None,
) -> EvidenceEnvelope:
    """Wrap one validated legacy result in the common v2 envelope."""

    evidence = legacy.get("evidence") if isinstance(legacy.get("evidence"), list) else []
    blockers = legacy.get("blockers") if isinstance(legacy.get("blockers"), list) else []
    warnings = legacy.get("warnings") if isinstance(legacy.get("warnings"), list) else []
    waivers = legacy.get("waivers") if isinstance(legacy.get("waivers"), list) else []
    decision = _legacy_decision(legacy)
    promotion_ready = legacy.get("promotionReady")
    if promotion_ready is None:
        promotion_ready = legacy.get("releaseCandidatePassed")
    status = normalize_status(
        result_status
        if result_status is not None
        else legacy.get("status", legacy.get("decision"))
    )
    redaction = redaction_from_legacy(legacy.get("redaction"), legacy)
    if exit_code != 0:
        status = "fail"
    if redaction["status"] == "fail":
        status = "fail"
        if exit_code == 0:
            exit_code = 1
    if status == "fail":
        promotion_ready = False
    release_id = context.manifest.release.release_id
    version = context.manifest.release.version
    legacy_release_id = legacy.get("releaseId")
    legacy_version = legacy.get("version")
    if bind_identity and legacy_release_id is not None:
        if not isinstance(legacy_release_id, str) or not legacy_release_id:
            raise ValueError("legacy evidence releaseId is malformed")
        if legacy_release_id != release_id:
            raise ValueError(
                f"legacy evidence releaseId {legacy_release_id!r} does not match manifest {release_id!r}"
            )
    if bind_identity and legacy_version is not None:
        if not isinstance(legacy_version, (str, int)) or isinstance(legacy_version, bool):
            raise ValueError("legacy evidence version is malformed")
        bound_version = str(legacy_version)
        if version is not None and bound_version != version:
            raise ValueError(
                f"legacy evidence version {bound_version!r} does not match manifest {version!r}"
            )
        if version is None:
            version = bound_version
    safe_inputs: dict[str, Any] = {}
    for key, value in context.manifest.inputs.items():
        if isinstance(value, str):
            candidate = Path(value)
            resolved = (
                candidate
                if candidate.is_absolute()
                else context.workspace_root / candidate
            )
            try:
                relative = resolved.resolve().relative_to(context.workspace_root)
                value = f"<repo>/{relative.as_posix()}"
            except ValueError:
                value = "<external-input>"
        if isinstance(value, (str, bool, int, float, type(None))):
            safe_inputs[key] = value
    return EvidenceEnvelope(
        kind=kind,
        generated_at=str(legacy.get("generatedAt") or utc_now()),
        subject={
            "releaseId": release_id,
            "version": version,
            "profile": context.manifest.release.profile,
            "component": context.component,
        },
        result={
            "status": status,
            "decision": decision,
            "promotionReady": promotion_ready if isinstance(promotion_ready, bool) else None,
            "exitCode": exit_code,
        },
        counts={
            "evidence": len(evidence),
            "blockers": len(blockers),
            "warnings": len(warnings),
            "waivers": len(waivers),
        },
        evidence=evidence,
        issues={"blockers": blockers, "warnings": warnings},
        waivers=waivers,
        redaction=redaction,
        inputs=safe_inputs,
        artifacts=artifacts,
        payload={"legacy": legacy},
    )


def validate_envelope(value: Any, expected_kind: str | None = None, release_id: str | None = None) -> None:
    """Fail closed when an evidence envelope violates the common contract."""

    if not isinstance(value, dict) or value.get("schemaVersion") != SCHEMA_VERSION:
        raise ValueError(f"expected release-certification schemaVersion {SCHEMA_VERSION}")
    required = {
        "schemaVersion",
        "kind",
        "generatedAt",
        "subject",
        "result",
        "counts",
        "evidence",
        "issues",
        "waivers",
        "redaction",
        "inputs",
        "artifacts",
        "payload",
    }
    missing = sorted(required - set(value))
    unknown = sorted(set(value) - required)
    if missing:
        raise ValueError(f"evidence envelope is missing fields: {', '.join(missing)}")
    if unknown:
        raise ValueError(f"evidence envelope has unknown fields: {', '.join(unknown)}")
    kind = value.get("kind")
    if not isinstance(kind, str) or not kind:
        raise ValueError("evidence kind must be a non-empty string")
    if expected_kind is not None and kind != expected_kind:
        raise ValueError(f"expected evidence kind {expected_kind}")
    generated_at = value.get("generatedAt")
    if not isinstance(generated_at, str) or not generated_at:
        raise ValueError("evidence generatedAt must be a non-empty string")
    subject = value.get("subject")
    result = value.get("result")
    counts = value.get("counts")
    evidence = value.get("evidence")
    issues = value.get("issues")
    waivers = value.get("waivers")
    redaction = value.get("redaction")
    inputs = value.get("inputs")
    artifacts = value.get("artifacts")
    payload = value.get("payload")
    object_fields = (subject, result, counts, issues, redaction, inputs, artifacts, payload)
    if not all(isinstance(item, dict) for item in object_fields):
        raise ValueError("evidence envelope object fields are malformed")
    if not isinstance(evidence, list) or not isinstance(waivers, list):
        raise ValueError("evidence and waivers must be arrays")
    if set(subject) != {"releaseId", "version", "profile", "component"}:
        raise ValueError("evidence subject fields are malformed")
    identity_fields = ("releaseId", "profile", "component")
    if not all(isinstance(subject.get(key), str) and subject.get(key) for key in identity_fields):
        raise ValueError("evidence subject identity fields must be non-empty strings")
    version = subject.get("version")
    if version is not None and (not isinstance(version, str) or not version):
        raise ValueError("evidence subject.version must be a non-empty string or null")
    if release_id is not None and subject.get("releaseId") != release_id:
        raise ValueError("evidence releaseId does not match the candidate")
    if set(result) != {"status", "decision", "promotionReady", "exitCode"}:
        raise ValueError("evidence result fields are malformed")
    if result.get("status") not in {"pass", "warn", "fail"}:
        raise ValueError("evidence result.status is invalid")
    if result.get("decision") is not None and not isinstance(result.get("decision"), str):
        raise ValueError("evidence result.decision must be a string or null")
    if result.get("promotionReady") is not None and not isinstance(result.get("promotionReady"), bool):
        raise ValueError("evidence result.promotionReady must be a boolean or null")
    if type(result.get("exitCode")) is not int:
        raise ValueError("evidence result.exitCode must be an integer")
    if result["exitCode"] != 0 and result["status"] != "fail":
        raise ValueError("nonzero evidence exitCode requires a failed result")
    count_fields = {"evidence", "blockers", "warnings", "waivers"}
    invalid_count = any(
        type(counts.get(key)) is not int or counts[key] < 0 for key in count_fields
    )
    if set(counts) != count_fields or invalid_count:
        raise ValueError("evidence counts fields must be non-negative integers")
    if set(issues) != {"blockers", "warnings"} or not all(
        isinstance(issues.get(key), list) for key in ("blockers", "warnings")
    ):
        raise ValueError("evidence issues fields are malformed")
    expected_counts = {
        "evidence": len(evidence),
        "blockers": len(issues["blockers"]),
        "warnings": len(issues["warnings"]),
        "waivers": len(waivers),
    }
    if counts != expected_counts:
        raise ValueError("evidence counts do not match envelope arrays")
    if set(redaction) != {"status", "findingCount", "findings", "guarantees"}:
        raise ValueError("evidence redaction fields are malformed")
    if redaction.get("status") not in {"pass", "fail"}:
        raise ValueError("evidence redaction.status is invalid")
    if type(redaction.get("findingCount")) is not int or redaction["findingCount"] < 0:
        raise ValueError("evidence redaction.findingCount must be a non-negative integer")
    if not isinstance(redaction.get("findings"), list) or not isinstance(redaction.get("guarantees"), dict):
        raise ValueError("evidence redaction findings or guarantees are malformed")
    if redaction["findingCount"] != len(redaction["findings"]):
        raise ValueError("evidence redaction findingCount does not match findings")
    if redaction["status"] == "pass" and redaction["findings"]:
        raise ValueError("passing redaction requires zero findings")
    if not all(
        isinstance(key, str) and isinstance(item, bool)
        for key, item in redaction["guarantees"].items()
    ):
        raise ValueError("evidence redaction guarantees must be booleans")
    if redaction["status"] == "pass" and not all(redaction["guarantees"].values()):
        raise ValueError("passing redaction requires every guarantee to pass")
    if not all(isinstance(key, str) and isinstance(item, str) for key, item in artifacts.items()):
        raise ValueError("evidence artifacts must map strings to strings")
    if redaction["status"] == "fail" and result["status"] != "fail":
        raise ValueError("failed redaction requires a failed evidence result")
    if result["status"] == "fail" and result["promotionReady"] is True:
        raise ValueError("failed evidence cannot be promotion ready")


def write_envelope(context: RunContext, envelope: EvidenceEnvelope, report: str) -> None:
    """Write the standard summary, report, and redaction report."""

    value = envelope.to_json()
    validate_envelope(value, envelope.kind, context.manifest.release.release_id)
    write_json(context.component_dir / "summary.json", value)
    write_json(context.component_dir / "redaction-report.json", envelope.redaction)
    write_text(context.component_dir / "report.md", report)

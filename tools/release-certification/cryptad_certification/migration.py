"""Explicit one-time migration of validated v1 historical summaries."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .envelope import from_legacy, normalize_status, write_envelope
from .io import read_json, write_json
from .models import RunContext
from .redaction import scan_value
from .workspace import relative_to_run

SOURCE_KEYS = {
    "previous-candidate": "previousCandidate",
    "release-history": "releaseHistory",
}
LEGACY_BOOLEAN_REDACTION_GUARANTEES = {
    "absolutePathsSanitized",
    "appProcessTokensRedacted",
    "browserSessionTokensRedacted",
    "formPasswordsRedacted",
    "privateInsertUrisExcluded",
    "rawFeedBodiesExcluded",
    "rawRequestBodiesExcluded",
    "rawUpdateRollbackOutputsExcluded",
    "secretMaterialRedacted",
    "signatureValuesRedacted",
}


def _source_path(context: RunContext, migration_kind: str) -> Path:
    key = SOURCE_KEYS[migration_kind]
    raw = context.manifest.inputs.get(key)
    if not isinstance(raw, str) or not raw:
        raise ValueError(f"manifest inputs.{key} is required")
    path = Path(raw)
    if not path.is_absolute():
        path = context.workspace_root / path
    return path.resolve()


def _require_passing_redaction(value: dict[str, Any]) -> None:
    """Require an explicit, internally consistent legacy redaction pass."""

    redaction = value.get("redaction")
    if not isinstance(redaction, dict) or not redaction:
        raise ValueError("legacy history redaction metadata must be a non-empty object")
    findings = redaction.get("findings")
    if "findings" in redaction and not isinstance(findings, list):
        raise ValueError("legacy history redaction findings must be an array")
    if findings:
        raise ValueError("legacy history contains redaction findings")
    finding_count = redaction.get("findingCount")
    if "findingCount" in redaction and (
        type(finding_count) is not int or finding_count != len(findings or [])
    ):
        raise ValueError("legacy history redaction findingCount is malformed")
    status = redaction.get("status")
    if status is not None:
        if not isinstance(status, str) or status not in {"pass", "passed", "success"}:
            raise ValueError("legacy history redaction status must explicitly pass")
        if "findings" not in redaction:
            raise ValueError("legacy history status-based redaction must include findings")
    guarantees = [item for item in redaction.values() if isinstance(item, bool)]
    if any(item is False for item in guarantees):
        raise ValueError("legacy history contains a failed redaction guarantee")
    recognized_guarantees = [
        redaction[key]
        for key in LEGACY_BOOLEAN_REDACTION_GUARANTEES
        if isinstance(redaction.get(key), bool)
    ]
    nested_guarantees = redaction.get("guarantees")
    if nested_guarantees is not None:
        if not isinstance(nested_guarantees, dict) or not all(
            isinstance(key, str) and isinstance(item, bool)
            for key, item in nested_guarantees.items()
        ):
            raise ValueError("legacy history redaction guarantees are malformed")
        if any(item is False for item in nested_guarantees.values()):
            raise ValueError("legacy history contains a failed redaction guarantee")
    if status is None and not recognized_guarantees and not nested_guarantees:
        raise ValueError("legacy history redaction metadata has no explicit passing signal")


def execute(context: RunContext, migration_kind: str) -> int:
    """Validate, bind, and convert one legacy historical summary."""

    source = _source_path(context, migration_kind)
    raw = source.read_bytes()
    value: Any = read_json(source)
    if not isinstance(value, dict):
        raise ValueError("migrate-v1 requires a legacy schemaVersion 1 JSON object")
    schema_version = value.get("schemaVersion")
    if "schemaVersion" in value and (type(schema_version) is not int or schema_version != 1):
        raise ValueError("migrate-v1 requires a legacy schemaVersion 1 JSON object")
    if normalize_status(value.get("status", value.get("decision"))) != "pass":
        raise ValueError("legacy history must have a passing status before migration")
    release_id = value.get("releaseId")
    expected_release_id = context.manifest.policies.get("expectedPreviousReleaseId")
    if expected_release_id is not None and release_id != expected_release_id:
        raise ValueError("legacy history releaseId does not match policies.expectedPreviousReleaseId")
    _require_passing_redaction(value)
    findings = scan_value(value)
    if findings:
        raise ValueError("legacy history failed the v2 private-material and absolute-path scan")
    migrated = context.component_dir / "artifacts" / "migrated-summary.json"
    write_json(migrated, value)
    digest = hashlib.sha256(raw).hexdigest()
    envelope = from_legacy(
        context,
        f"migrated-v1-{migration_kind}",
        value,
        0,
        {"migratedSummary": relative_to_run(migrated, context)},
        bind_identity=False,
    )
    envelope.payload = {
        "migration": {
            "sourceSchemaVersion": value.get("schemaVersion", 1),
            "sourceKind": value.get("kind") or value.get("tool") or migration_kind,
            "sourceSha256": digest,
        },
        "legacy": value,
    }
    write_envelope(
        context,
        envelope,
        f"# V1 {migration_kind} migration\n\nValidated and converted source SHA-256: `{digest}`.",
    )
    return int(envelope.result["exitCode"])

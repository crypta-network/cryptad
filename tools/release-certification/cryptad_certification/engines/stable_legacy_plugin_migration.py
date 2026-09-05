"""Validate sanitized local Sharesite observations without inventing runtime authority.

This command never reads conversion payloads or a legacy database. Local declarations are
retained as reports, not evidence of execution. No protected migration producer is configured
in v1, so runtime verification and release closeout fail closed regardless of caller claims.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import stat
from typing import Any

from ..io import read_json_bytes, write_json, write_text
from ..redaction import scan_value

SOURCE_REPOSITORY = "hyphanet/plugin-sharesite"
SOURCE_REVISION = "c99ad9c8e83004f904f8ee742ab2861f5751ee3b"
PROFILE = "sharesite-pastebin-v1"
MAX_OBSERVATION_BYTES = 16384
MODES = frozenset({"preflight", "verify-migration", "verify-runtime", "closeout"})
OUTCOMES = frozenset({"pass", "fail", "not-observed"})
CHECKS = frozenset({
    "literalFidelity", "sourcePreservation", "secretExclusionStatus", "importCommit",
    "restartPersistence", "editSave", "literalPreview", "replay", "stalePreview",
    "quotaFailure", "interruptionRecovery", "dataUndo", "privateRestore",
    "bundleRollback", "cleanup", "newChkPublication",
})
CATEGORIES = frozenset({
    "textile", "deleted", "css", "external-resource", "scheduling", "unknown-field",
    "prohibited-text", "invalid-public-reference", "unselected",
})
TOP_FIELDS = frozenset({
    "schemaVersion", "kind", "operationId", "classification", "source", "adapter",
    "target", "selectedCount", "excludedCounts", "outcomes",
})
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")


def _closed(value: Any, fields: set[str] | frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("migration-observation-fields-invalid")
    return value


def _matches(pattern: re.Pattern[str], value: Any) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def validate_observation(value: Any) -> dict[str, Any]:
    """Accept only bounded public metadata; errors never include supplied field names/values."""
    data = _closed(value, TOP_FIELDS)
    if type(data["schemaVersion"]) is not int or data["schemaVersion"] != 1:
        raise ValueError("migration-observation-version-unsupported")
    if data["kind"] != "sharesite-migration-local-observation":
        raise ValueError("migration-observation-kind-invalid")
    if not _matches(UUID, data["operationId"]):
        raise ValueError("migration-operation-id-invalid")
    if data["classification"] not in ("synthetic", "operator-local-unverified"):
        raise ValueError("migration-classification-not-authorized")
    source = _closed(data["source"], {"repository", "revision", "profile"})
    if source != {"repository": SOURCE_REPOSITORY, "revision": SOURCE_REVISION, "profile": PROFILE}:
        raise ValueError("migration-source-profile-mismatch")
    adapter = _closed(data["adapter"], {"sourceCommit", "artifactDigest"})
    if not _matches(COMMIT, adapter["sourceCommit"]) or not _matches(DIGEST, adapter["artifactDigest"]):
        raise ValueError("migration-adapter-identity-invalid")
    target = _closed(data["target"], {
        "appId", "version", "baseline", "bundleDigest", "manifestDigest", "catalogDigest",
        "signatureDigest", "publisherFingerprint",
    })
    if target["appId"] != "site-publisher" or target["baseline"] != "1.0":
        raise ValueError("migration-target-mismatch")
    if not isinstance(target["version"], str) or re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,3}", target["version"]) is None or len(target["version"]) > 32:
        raise ValueError("migration-target-version-invalid")
    if any(not _matches(DIGEST, target[field]) for field in target if field not in {"appId", "version", "baseline"}):
        raise ValueError("migration-target-identity-invalid")
    if type(data["selectedCount"]) is not int or not 1 <= data["selectedCount"] <= 16:
        raise ValueError("migration-selection-empty-or-oversized")
    excluded = data["excludedCounts"]
    if not isinstance(excluded, dict) or not set(excluded).issubset(CATEGORIES):
        raise ValueError("migration-exclusion-category-invalid")
    if any(type(count) is not int or not 0 <= count <= 100000 for count in excluded.values()):
        raise ValueError("migration-exclusion-count-invalid")
    outcomes = _closed(data["outcomes"], CHECKS)
    if any(not isinstance(result, str) or result not in OUTCOMES for result in outcomes.values()):
        raise ValueError("migration-outcome-invalid")
    if scan_value(data):
        raise ValueError("migration-observation-private-material")
    return data


def summarize(observation: Any, mode: str) -> dict[str, Any]:
    """Keep local reported results independent of unobserved operational/release status."""
    if mode not in MODES:
        raise ValueError("migration-mode-invalid")
    data = validate_observation(observation)
    failed = sorted(key for key, result in data["outcomes"].items() if result == "fail")
    blocked = mode in {"verify-runtime", "closeout"}
    return {
        "schemaVersion": 1,
        "kind": "stable-legacy-plugin-migration-summary",
        "operationId": data["operationId"],
        "mode": mode,
        "status": "blocked" if blocked else ("failed" if failed else "local-observation-validated"),
        "scope": "selected-workflow-only",
        "classification": data["classification"],
        "source": data["source"],
        "adapter": data["adapter"],
        "target": data["target"],
        "selectedCount": data["selectedCount"],
        "excludedCounts": data["excludedCounts"],
        "reportedLocalOutcomes": data["outcomes"],
        "failedLocalChecks": failed,
        "implementationStatus": "not-assessed",
        "formatVerification": "not-independently-observed",
        "runtimeObservation": "not-authenticated",
        "realDataMigration": "not-authenticated",
        "publication": "not-observed",
        "releaseEligibility": "blocked",
        "promotionReady": False,
        "operationallyComplete": False,
        "sameUskContinuity": "unsupported",
        "prerequisites": [
            "protected-migration-producer-not-configured",
            "pr296-protected-subject-projection-pending",
        ],
    }


def _confined(workspace: Path, requested: Path) -> Path:
    candidate = requested if requested.is_absolute() else workspace / requested
    try:
        relative = candidate.relative_to(workspace)
    except ValueError:
        raise ValueError("migration-path-outside-workspace") from None
    current = workspace
    for part in relative.parts:
        if part in {".", ".."}:
            raise ValueError("migration-path-invalid")
        current /= part
        if current.is_symlink():
            raise ValueError("migration-path-link-rejected")
    return candidate


def run(workspace: Path, observation: Path, mode: str, out_dir: Path) -> int:
    """Read one confined sanitized observation; write only fresh allowlisted summary files."""
    try:
        source = _confined(workspace, observation)
        info = source.stat(follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_OBSERVATION_BYTES:
            raise ValueError("migration-observation-file-invalid")
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError("migration-observation-file-changed")
            raw = handle.read(MAX_OBSERVATION_BYTES + 1)
        if len(raw) > MAX_OBSERVATION_BYTES:
            raise ValueError("migration-observation-file-oversized")
        try:
            value = read_json_bytes(raw, "migration observation")
        except (ValueError, RecursionError):
            raise ValueError("migration-observation-json-invalid") from None
        summary = summarize(value, mode)
        if scan_value(summary):
            raise ValueError("migration-output-private-material")
        output = _confined(workspace, out_dir)
        if output.exists():
            raise ValueError("migration-output-must-be-new")
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
        write_json(output / "summary.json", summary)
        write_json(output / "redaction-report.json", {"schemaVersion": 1, "status": "pass", "findings": []})
        write_text(output / "report.md", "# Selected Sharesite workflow observation\n\n"
                   f"State: {summary['status']}. Local declarations have not been authenticated.\n\n"
                   "Runtime, real-data migration, and publication are not certified. Release eligibility remains blocked by the protected migration producer and PR-296 subject-projection prerequisites.")
        return 0 if summary["status"] == "local-observation-validated" else 1
    except OSError:
        raise ValueError("migration-evidence-io-failed") from None

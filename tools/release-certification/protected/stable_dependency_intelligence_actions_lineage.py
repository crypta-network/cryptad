#!/usr/bin/env python3
"""Read and compare-and-swap durable dependency-intelligence source lineage."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptad_certification.schema_validation import validate_schema  # noqa: E402


_REPOSITORY = "crypta-network/cryptad"
_WORKFLOW = ".github/workflows/stable-1.0-dependency-intelligence-producer.yml"
_READ_TOKEN = "CRYPTAD_STABLE_DEPENDENCY_INTELLIGENCE_LINEAGE_READ_TOKEN"
_WRITE_TOKEN = "CRYPTAD_STABLE_DEPENDENCY_INTELLIGENCE_LINEAGE_WRITE_TOKEN"
_ROOT = Path(__file__).resolve().parents[1]
_POLICY = _ROOT / "stable-1.0-dependency-vulnerability-policy.json"
_SCHEMA = "stable-1.0-dependency-intelligence-source-lineage-anchor-v1.schema.json"
_SET_SCHEMA = "stable-1.0-dependency-intelligence-source-lineage-set-v1.schema.json"
_SET_GENESIS = _ROOT / "stable-1.0-dependency-intelligence-source-lineage-set-genesis.json"
_SET_VARIABLE = "STABLE_1_0_DEPENDENCY_INTELLIGENCE_SOURCE_LINEAGE_SET"
_SOURCE_SCHEMA = "stable-1.0-dependency-intelligence-source-v1.schema.json"
_PROVENANCE_SCHEMA = "stable-1.0-dependency-intelligence-provenance-v1.schema.json"
_PROMOTION_SCHEMA = "stable-1.0-dependency-vulnerability-promotion-summary-v1.schema.json"
_PUBLICATION_PLAN_SCHEMA = (
    "stable-1.0-dependency-vulnerability-publication-plan-v1.schema.json"
)
_PROPOSAL_FILE = "stable-1.0-dependency-intelligence-activation-proposal.json"
_PROPOSAL_KIND = "stable-1.0-dependency-intelligence-activation-proposal"
_PROPOSAL_FIELDS = {
    "schemaVersion",
    "kind",
    "repositoryIdentity",
    "sourceId",
    "expectedAnchorDigest",
    "producerWorkflow",
    "workflowCommit",
    "runId",
    "runAttempt",
    "sourceArtifactName",
    "sourceArtifactDigest",
    "proposalArtifactName",
    "sourceRecordByteDigest",
    "provenanceByteDigest",
    "manifestByteDigest",
    "proposalDigest",
}
_SOURCE_IDS = (
    "github-public-advisories",
    "osv-public",
    "reviewed-vendor-records",
)
_GENESIS = {
    source: _ROOT / f"stable-1.0-dependency-intelligence-{source}-lineage-genesis.json"
    for source in _SOURCE_IDS
}
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")


class LineageError(RuntimeError):
    """A fail-closed durable source-lineage error."""


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def _semantic(value: dict[str, Any], field: str) -> str:
    payload = dict(value)
    payload.pop(field, None)
    return "sha256:" + hashlib.sha256(_canonical(payload).rstrip(b"\n")).hexdigest()


def _load(path: Path, limit: int = 4 * 1024 * 1024) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        if not raw or len(raw) > limit:
            raise LineageError("dependency-intelligence-lineage-file-invalid")
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LineageError("dependency-intelligence-lineage-file-invalid") from exc
    if not isinstance(value, dict):
        raise LineageError("dependency-intelligence-lineage-file-invalid")
    return value


def _policy_digest() -> str:
    value = _load(_POLICY, 1024 * 1024).get("policyDigest")
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise LineageError("dependency-intelligence-lineage-policy-invalid")
    return value


def _gh(token_name: str, arguments: list[str]) -> bytes:
    executable = shutil.which("gh", path="/usr/bin:/bin")
    token = os.environ.get(token_name, "")
    if executable is None or not token or "\n" in token or len(token) > 4096:
        raise LineageError("dependency-intelligence-lineage-github-unavailable")
    try:
        completed = subprocess.run(
            [executable, *arguments],
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "GH_TOKEN": token},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=90,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LineageError("dependency-intelligence-lineage-github-failed") from exc
    if completed.returncode != 0 or len(completed.stdout) > 2 * 1024 * 1024:
        raise LineageError("dependency-intelligence-lineage-github-failed")
    return completed.stdout


def _validate_anchor(anchor: dict[str, Any], source_id: str) -> None:
    if source_id not in _SOURCE_IDS or validate_schema(anchor, _SCHEMA):
        raise LineageError("dependency-intelligence-lineage-anchor-schema-invalid")
    if (
        anchor.get("sourceId") != source_id
        or anchor.get("policyDigest") != _policy_digest()
        or anchor.get("anchorDigest") != _semantic(anchor, "anchorDigest")
    ):
        raise LineageError("dependency-intelligence-lineage-anchor-invalid")
    initialized = anchor.get("initialized")
    if initialized is False:
        if anchor != _load(_GENESIS[source_id]):
            raise LineageError("dependency-intelligence-lineage-genesis-mismatch")
        return
    if (
        initialized is not True
        or int(anchor.get("anchorSequence", 0)) < 1
        or anchor.get("contentStatus") not in {"changed", "unchanged-full-retrieval"}
        or anchor.get("retrievalValidation") != "complete-200-response"
        or anchor.get("producerWorkflow") != _WORKFLOW
    ):
        raise LineageError("dependency-intelligence-lineage-active-invalid")


def _validate_set(value: dict[str, Any]) -> None:
    lineages = value.get("lineages")
    if validate_schema(value, _SET_SCHEMA) or not isinstance(lineages, list):
        raise LineageError("dependency-intelligence-lineage-set-schema-invalid")
    if (
        value.get("policyDigest") != _policy_digest()
        or value.get("setDigest") != _semantic(value, "setDigest")
        or [row.get("sourceId") for row in lineages] != list(_SOURCE_IDS)
    ):
        raise LineageError("dependency-intelligence-lineage-set-invalid")
    for source_id, anchor in zip(_SOURCE_IDS, lineages, strict=True):
        _validate_anchor(anchor, source_id)
    if value.get("setEdition") == 0 and value != _load(_SET_GENESIS):
        raise LineageError("dependency-intelligence-lineage-set-genesis-mismatch")


def _read_set(repository: str, token_name: str) -> dict[str, Any]:
    if repository != _REPOSITORY:
        raise LineageError("dependency-intelligence-lineage-coordinate-invalid")
    raw = _gh(
        token_name,
        ["api", f"repos/{repository}/actions/variables/{_SET_VARIABLE}"],
    )
    try:
        response = json.loads(raw)
        encoded = response["value"]
        value = json.loads(encoded)
    except (KeyError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
        raise LineageError("dependency-intelligence-lineage-anchor-unavailable") from exc
    if (
        response.get("name") != _SET_VARIABLE
        or not isinstance(encoded, str)
        or encoded.encode("utf-8") != _canonical(value).rstrip(b"\n")
    ):
        raise LineageError("dependency-intelligence-lineage-anchor-unavailable")
    _validate_set(value)
    return value


def _read(repository: str, source_id: str, token_name: str) -> dict[str, Any]:
    if source_id not in _SOURCE_IDS:
        raise LineageError("dependency-intelligence-lineage-coordinate-invalid")
    value = _read_set(repository, token_name)
    return next(row for row in value["lineages"] if row["sourceId"] == source_id)


def _authenticate_artifact(arguments: argparse.Namespace) -> None:
    run_raw = _gh(
        _WRITE_TOKEN,
        ["api", f"repos/{arguments.repository}/actions/runs/{arguments.run_id}/attempts/{arguments.run_attempt}"],
    )
    artifacts_raw = _gh(
        _WRITE_TOKEN,
        ["api", "--paginate", "--slurp", f"repos/{arguments.repository}/actions/runs/{arguments.run_id}/artifacts?per_page=100"],
    )
    try:
        run = json.loads(run_raw)
        pages = json.loads(artifacts_raw)
        artifacts = [row for page in pages for row in page.get("artifacts", [])]
    except (TypeError, UnicodeError, json.JSONDecodeError) as exc:
        raise LineageError("dependency-intelligence-lineage-artifact-invalid") from exc
    if (
        run.get("id") != arguments.run_id
        or run.get("run_attempt") != arguments.run_attempt
        or run.get("path") != _WORKFLOW
        or run.get("head_sha") != arguments.workflow_commit
        or run.get("head_repository", {}).get("full_name") != _REPOSITORY
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or run.get("event") not in {"schedule", "workflow_dispatch"}
    ):
        raise LineageError("dependency-intelligence-lineage-run-invalid")
    matches = [row for row in artifacts if row.get("name") == arguments.artifact_name]
    if (
        len(matches) != 1
        or matches[0].get("expired") is not False
        or matches[0].get("digest") != arguments.artifact_digest
        or matches[0].get("workflow_run", {}).get("id") != arguments.run_id
    ):
        raise LineageError("dependency-intelligence-lineage-artifact-invalid")


def _byte_digest(path: Path, limit: int = 4 * 1024 * 1024) -> str:
    try:
        stat = path.stat(follow_symlinks=False)
        raw = path.read_bytes()
    except OSError as exc:
        raise LineageError("dependency-intelligence-lineage-file-invalid") from exc
    if (
        path.is_symlink()
        or not path.is_file()
        or stat.st_nlink != 1
        or not raw
        or len(raw) > limit
        or len(raw) != stat.st_size
    ):
        raise LineageError("dependency-intelligence-lineage-file-invalid")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _proposal_errors(proposal: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    source_id = proposal.get("sourceId")
    valid_source_id = isinstance(source_id, str) and source_id in _SOURCE_IDS
    expected_source_name = ""
    expected_proposal_name = ""
    if valid_source_id:
        expected_source_name = (
            f"stable-1-0-dependency-intelligence-{source_id}-"
            f"{proposal.get('runId')}-{proposal.get('runAttempt')}"
        )
        expected_proposal_name = (
            f"stable-1-0-dependency-intelligence-activation-proposal-{source_id}-"
            f"{proposal.get('runId')}-{proposal.get('runAttempt')}"
        )
    if set(proposal) != _PROPOSAL_FIELDS:
        errors.append("dependency-intelligence-lineage-proposal-fields-invalid")
    if (
        proposal.get("schemaVersion") != 1
        or proposal.get("kind") != _PROPOSAL_KIND
        or proposal.get("repositoryIdentity") != "github.com/crypta-network/cryptad"
        or not valid_source_id
        or proposal.get("producerWorkflow") != _WORKFLOW
        or _DIGEST.fullmatch(str(proposal.get("expectedAnchorDigest", ""))) is None
        or _COMMIT.fullmatch(str(proposal.get("workflowCommit", ""))) is None
        or type(proposal.get("runId")) is not int
        or int(proposal.get("runId", 0)) < 1
        or type(proposal.get("runAttempt")) is not int
        or int(proposal.get("runAttempt", 0)) < 1
        or proposal.get("sourceArtifactName") != expected_source_name
        or proposal.get("proposalArtifactName") != expected_proposal_name
        or any(
            _DIGEST.fullmatch(str(proposal.get(field, ""))) is None
            for field in (
                "sourceArtifactDigest",
                "sourceRecordByteDigest",
                "provenanceByteDigest",
                "manifestByteDigest",
            )
        )
    ):
        errors.append("dependency-intelligence-lineage-proposal-identity-invalid")
    if proposal.get("proposalDigest") != _semantic(proposal, "proposalDigest"):
        errors.append("dependency-intelligence-lineage-proposal-digest-invalid")
    return sorted(dict.fromkeys(errors))


def _bundle(arguments: argparse.Namespace, anchor: dict[str, Any]) -> dict[str, Any]:
    source = _load(arguments.source_record)
    provenance = _load(arguments.provenance)
    manifest = _load(arguments.manifest)
    files = manifest.get("files")
    file_rows = {
        row.get("file"): row
        for row in files
        if isinstance(row, dict) and isinstance(row.get("file"), str)
    } if isinstance(files, list) else {}
    for name, path in (
        ("stable-1.0-dependency-intelligence-source.json", arguments.source_record),
        ("stable-1.0-dependency-intelligence-provenance.json", arguments.provenance),
    ):
        raw = path.read_bytes()
        row = file_rows.get(name)
        if (
            not isinstance(row, dict)
            or row.get("size") != len(raw)
            or row.get("sha256") != "sha256:" + hashlib.sha256(raw).hexdigest()
        ):
            raise LineageError("dependency-intelligence-lineage-manifest-binding-invalid")
    if validate_schema(source, _SOURCE_SCHEMA) or validate_schema(provenance, _PROVENANCE_SCHEMA):
        raise LineageError("dependency-intelligence-lineage-bundle-schema-invalid")
    if (
        source.get("sourceId") != arguments.source_id
        or source.get("policyDigest") != _policy_digest()
        or source.get("sourceSnapshotDigest") != _semantic(source, "sourceSnapshotDigest")
        or source.get("responseStatus") != 200
        or provenance.get("sourceId") != arguments.source_id
        or provenance.get("provenanceDigest") != _semantic(provenance, "provenanceDigest")
        or provenance.get("provenanceDigest") != source.get("provenanceDigest")
        or provenance.get("workflowSha") != arguments.workflow_commit
        or provenance.get("runId") != arguments.run_id
        or provenance.get("runAttempt") != arguments.run_attempt
        or provenance.get("artifactName") != arguments.artifact_name
        or manifest.get("sourceId") != arguments.source_id
        or manifest.get("sourceCommit") != arguments.workflow_commit
        or manifest.get("runId") != arguments.run_id
        or manifest.get("runAttempt") != arguments.run_attempt
        or manifest.get("artifactName") != arguments.artifact_name
        or manifest.get("manifestDigest") != _semantic(manifest, "manifestDigest")
    ):
        raise LineageError("dependency-intelligence-lineage-bundle-invalid")
    expected_edition = int(anchor["anchorSequence"]) + 1
    previous_digest = anchor.get("sourceSnapshotDigest") if anchor.get("initialized") else None
    previous_edition = anchor.get("anchorSequence") if anchor.get("initialized") else None
    if (
        source.get("sourceEdition") != expected_edition
        or source.get("previousSourceSnapshotDigest") != previous_digest
        or source.get("previousSourceEdition") != previous_edition
    ):
        raise LineageError("dependency-intelligence-lineage-predecessor-invalid")
    return source


def _timestamp(value: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LineageError("dependency-intelligence-lineage-time-invalid") from exc
    if parsed.tzinfo is None:
        raise LineageError("dependency-intelligence-lineage-time-invalid")
    return parsed.astimezone(dt.timezone.utc)


def _content_status(anchor: dict[str, Any], source: dict[str, Any]) -> str:
    unchanged = bool(
        anchor.get("initialized")
        and source.get("rawContentDigest") == anchor.get("rawContentDigest")
        and source.get("canonicalRecordSetDigest") == anchor.get("canonicalRecordSetDigest")
        and source.get("componentInventoryDigest") == anchor.get("componentInventoryDigest")
    )
    return "unchanged-full-retrieval" if unchanged else "changed"


def _verify_current_bundle(arguments: argparse.Namespace) -> None:
    if (
        arguments.source_id not in {"github-public-advisories", "osv-public"}
        or arguments.run_id < 1
        or arguments.run_attempt < 1
        or _DIGEST.fullmatch(arguments.artifact_digest) is None
    ):
        raise LineageError("dependency-intelligence-lineage-current-coordinate-invalid")
    anchor = _read(arguments.repository, arguments.source_id, _READ_TOKEN)
    source = _load(arguments.source_record)
    provenance = _load(arguments.provenance)
    if (
        anchor.get("initialized") is not True
        or validate_schema(source, _SOURCE_SCHEMA)
        or validate_schema(provenance, _PROVENANCE_SCHEMA)
        or source.get("sourceSnapshotDigest") != _semantic(source, "sourceSnapshotDigest")
        or provenance.get("provenanceDigest") != _semantic(provenance, "provenanceDigest")
    ):
        raise LineageError("dependency-intelligence-lineage-current-bundle-invalid")
    source_bindings = {
        "sourceId": "sourceId",
        "sourceEdition": "anchorSequence",
        "sourceSnapshotDigest": "sourceSnapshotDigest",
        "rawContentDigest": "rawContentDigest",
        "canonicalRecordSetDigest": "canonicalRecordSetDigest",
        "componentInventoryDigest": "componentInventoryDigest",
        "retrievedAt": "retrievedAt",
        "policyDigest": "policyDigest",
    }
    if any(
        source.get(source_field) != anchor.get(anchor_field)
        for source_field, anchor_field in source_bindings.items()
    ):
        raise LineageError("dependency-intelligence-lineage-current-source-mismatch")
    if (
        provenance.get("sourceId") != arguments.source_id
        or provenance.get("policyDigest") != anchor.get("policyDigest")
        or provenance.get("provenanceDigest") != source.get("provenanceDigest")
        or provenance.get("componentInventoryDigest")
        != source.get("componentInventoryDigest")
        or provenance.get("workflowSha") != anchor.get("workflowCommit")
        or provenance.get("sourceCommit") != anchor.get("workflowCommit")
        or provenance.get("runId") != anchor.get("runId")
        or provenance.get("runAttempt") != anchor.get("runAttempt")
        or provenance.get("artifactName") != anchor.get("artifactName")
    ):
        raise LineageError("dependency-intelligence-lineage-current-provenance-mismatch")
    if (
        arguments.run_id != anchor.get("runId")
        or arguments.run_attempt != anchor.get("runAttempt")
        or arguments.artifact_name != anchor.get("artifactName")
        or arguments.artifact_digest != anchor.get("artifactDigest")
    ):
        raise LineageError("dependency-intelligence-lineage-current-artifact-mismatch")


def _verify_current_status(arguments: argparse.Namespace) -> None:
    """Bind a sealed publication plan to every current mandatory source anchor."""

    status = _load(arguments.source_status)
    plan = _load(arguments.publication_plan)
    promotion = _load(arguments.promotion_summary)
    policy = _load(_POLICY, 1024 * 1024)
    if validate_schema(plan, _PUBLICATION_PLAN_SCHEMA) or validate_schema(
        promotion, _PROMOTION_SCHEMA
    ):
        raise LineageError("dependency-intelligence-lineage-publication-schema-invalid")
    if (
        plan.get("publicationPlanDigest") != _semantic(plan, "publicationPlanDigest")
        or promotion.get("summaryDigest") != _semantic(promotion, "summaryDigest")
        or plan.get("promotionSummaryDigest") != promotion.get("summaryDigest")
        or plan.get("policyDigest") != _policy_digest()
        or promotion.get("policyDigest") != _policy_digest()
    ):
        raise LineageError("dependency-intelligence-lineage-publication-binding-invalid")

    rows, mandatory_sources = _source_status_rows(status, promotion, policy)

    status_bytes = arguments.source_status.read_bytes()
    status_digest = "sha256:" + hashlib.sha256(status_bytes).hexdigest()
    status_entries = [
        row
        for row in plan.get("entries", [])
        if isinstance(row, dict) and row.get("role") == "dependency-source-status"
    ]
    if (
        len(status_entries) != 1
        or status_entries[0].get("fileName")
        != "stable-1.0-dependency-vulnerability-source-status.json"
        or status_entries[0].get("digest") != status_digest
        or status_entries[0].get("sizeBytes") != len(status_bytes)
    ):
        raise LineageError("dependency-intelligence-lineage-source-status-unbound")
    _verify_status_anchors(arguments.repository, status, rows, mandatory_sources)


def _source_status_rows(
    status: dict[str, Any], promotion: dict[str, Any], policy: dict[str, Any]
) -> tuple[dict[str, dict[str, Any]], set[str]]:
    expected_status_keys = {
        "schemaVersion",
        "kind",
        "releaseId",
        "buildVersion",
        "policyDigest",
        "snapshotDigest",
        "sources",
    }
    sources = status.get("sources")
    if (
        set(status) != expected_status_keys
        or status.get("schemaVersion") != 1
        or status.get("kind")
        != "stable-1.0-dependency-vulnerability-source-status"
        or status.get("releaseId") != promotion.get("releaseId")
        or status.get("buildVersion") != promotion.get("buildVersion")
        or status.get("policyDigest") != promotion.get("policyDigest")
        or status.get("snapshotDigest") != promotion.get("intelligenceSnapshotDigest")
        or not isinstance(sources, list)
        or not 1 <= len(sources) <= 32
    ):
        raise LineageError("dependency-intelligence-lineage-source-status-invalid")

    expected_row_keys = {
        "sourceId",
        "status",
        "retrievedAt",
        "expiresAt",
        "snapshotDigest",
    }
    rows: dict[str, dict[str, Any]] = {}
    for row in sources:
        if (
            not isinstance(row, dict)
            or set(row) != expected_row_keys
            or not isinstance(row.get("sourceId"), str)
            or row["sourceId"] in rows
            or row.get("status") != "fresh"
            or _DIGEST.fullmatch(str(row.get("snapshotDigest"))) is None
            or not isinstance(row.get("retrievedAt"), str)
            or not isinstance(row.get("expiresAt"), str)
        ):
            raise LineageError("dependency-intelligence-lineage-source-status-invalid")
        _timestamp(row["retrievedAt"])
        _timestamp(row["expiresAt"])
        rows[row["sourceId"]] = row

    mandatory_sources = {
        row.get("sourceId")
        for row in policy.get("sources", [])
        if isinstance(row, dict) and row.get("mandatory") is True
    }
    if mandatory_sources != {"github-public-advisories", "osv-public"}:
        raise LineageError("dependency-intelligence-lineage-policy-invalid")
    return rows, mandatory_sources


def _verify_status_anchors(
    repository: str,
    status: dict[str, Any],
    rows: dict[str, dict[str, Any]],
    mandatory_sources: set[str],
) -> None:
    current_set = _read_set(repository, _READ_TOKEN)
    anchors = {row["sourceId"]: row for row in current_set["lineages"]}
    for source_id in sorted(mandatory_sources):
        row = rows.get(source_id)
        if row is None:
            raise LineageError("dependency-intelligence-lineage-mandatory-source-missing")
        anchor = anchors[source_id]
        if (
            anchor.get("initialized") is not True
            or anchor.get("policyDigest") != status.get("policyDigest")
            or anchor.get("sourceSnapshotDigest") != row.get("snapshotDigest")
            or anchor.get("retrievedAt") != row.get("retrievedAt")
        ):
            raise LineageError("dependency-intelligence-lineage-current-status-mismatch")


def _verify_current_summary(arguments: argparse.Namespace) -> None:
    """Bind a final HMAC handoff's exact source status to current source tips."""

    status = _load(arguments.source_status)
    promotion = _load(arguments.promotion_summary)
    handoff = _load(arguments.handoff, 64 * 1024)
    policy = _load(_POLICY, 1024 * 1024)
    if validate_schema(promotion, _PROMOTION_SCHEMA):
        raise LineageError("dependency-intelligence-lineage-publication-schema-invalid")
    promotion_bytes = arguments.promotion_summary.read_bytes()
    status_bytes = arguments.source_status.read_bytes()
    if (
        promotion.get("summaryDigest") != _semantic(promotion, "summaryDigest")
        or promotion.get("policyDigest") != _policy_digest()
        or handoff.get("summaryFileName") != arguments.promotion_summary.name
        or handoff.get("summaryByteDigest")
        != "sha256:" + hashlib.sha256(promotion_bytes).hexdigest()
        or handoff.get("sourceStatusFileName") != arguments.source_status.name
        or handoff.get("sourceStatusByteDigest")
        != "sha256:" + hashlib.sha256(status_bytes).hexdigest()
        or handoff.get("ledgerDigest") != promotion.get("ledgerDigest")
        or handoff.get("ledgerEdition") != promotion.get("ledgerEdition")
        or handoff.get("validUntil") != promotion.get("validUntil")
    ):
        raise LineageError("dependency-intelligence-lineage-final-handoff-unbound")
    rows, mandatory_sources = _source_status_rows(status, promotion, policy)
    _verify_status_anchors(arguments.repository, status, rows, mandatory_sources)


def _write_proposal(arguments: argparse.Namespace) -> None:
    anchor = _load(arguments.predecessor)
    _validate_anchor(anchor, arguments.source_id)
    if anchor.get("anchorDigest") != arguments.expected_anchor_digest:
        raise LineageError("dependency-intelligence-lineage-proposal-predecessor-invalid")
    if arguments.out.name != _PROPOSAL_FILE:
        raise LineageError("dependency-intelligence-lineage-proposal-output-invalid")
    _bundle(
        argparse.Namespace(
            source_id=arguments.source_id,
            source_record=arguments.source_record,
            provenance=arguments.provenance,
            manifest=arguments.manifest,
            workflow_commit=arguments.workflow_commit,
            run_id=arguments.run_id,
            run_attempt=arguments.run_attempt,
            artifact_name=arguments.source_artifact_name,
        ),
        anchor,
    )
    proposal = {
        "schemaVersion": 1,
        "kind": _PROPOSAL_KIND,
        "repositoryIdentity": "github.com/crypta-network/cryptad",
        "sourceId": arguments.source_id,
        "expectedAnchorDigest": arguments.expected_anchor_digest,
        "producerWorkflow": _WORKFLOW,
        "workflowCommit": arguments.workflow_commit,
        "runId": arguments.run_id,
        "runAttempt": arguments.run_attempt,
        "sourceArtifactName": arguments.source_artifact_name,
        "sourceArtifactDigest": arguments.source_artifact_digest,
        "proposalArtifactName": arguments.proposal_artifact_name,
        "sourceRecordByteDigest": _byte_digest(arguments.source_record),
        "provenanceByteDigest": _byte_digest(arguments.provenance),
        "manifestByteDigest": _byte_digest(arguments.manifest),
        "proposalDigest": "sha256:" + "0" * 64,
    }
    proposal["proposalDigest"] = _semantic(proposal, "proposalDigest")
    errors = _proposal_errors(proposal)
    if errors:
        raise LineageError(errors[0])
    try:
        arguments.out.parent.mkdir(parents=True, exist_ok=False)
        arguments.out.write_bytes(_canonical(proposal))
    except OSError as exc:
        raise LineageError("dependency-intelligence-lineage-proposal-output-invalid") from exc


def _finalization_arguments(
    arguments: argparse.Namespace,
    proposal: dict[str, Any],
    proposal_path: Path,
    source_root: Path,
    proposal_artifact_name: str,
    proposal_artifact_digest: str,
) -> argparse.Namespace:
    errors = _proposal_errors(proposal)
    if errors:
        raise LineageError(errors[0])
    if (
        proposal_path.name != _PROPOSAL_FILE
        or proposal.get("repositoryIdentity") != f"github.com/{arguments.repository}"
        or proposal.get("workflowCommit") != arguments.workflow_commit
        or proposal.get("runId") != arguments.run_id
        or proposal.get("runAttempt") != arguments.run_attempt
        or proposal.get("proposalArtifactName") != proposal_artifact_name
    ):
        raise LineageError("dependency-intelligence-lineage-finalizer-coordinate-invalid")
    source_record = source_root / "stable-1.0-dependency-intelligence-source.json"
    provenance = source_root / "stable-1.0-dependency-intelligence-provenance.json"
    manifest = source_root / "producer-manifest.json"
    for path, field in (
        (source_record, "sourceRecordByteDigest"),
        (provenance, "provenanceByteDigest"),
        (manifest, "manifestByteDigest"),
    ):
        if _byte_digest(path) != proposal.get(field):
            raise LineageError("dependency-intelligence-lineage-proposal-byte-mismatch")
    _authenticate_artifact(
        argparse.Namespace(
            repository=arguments.repository,
            workflow_commit=arguments.workflow_commit,
            run_id=arguments.run_id,
            run_attempt=arguments.run_attempt,
            artifact_name=proposal_artifact_name,
            artifact_digest=proposal_artifact_digest,
        )
    )
    return argparse.Namespace(
        repository=arguments.repository,
        source_id=proposal["sourceId"],
        expected_anchor_digest=proposal["expectedAnchorDigest"],
        source_record=source_record,
        provenance=provenance,
        manifest=manifest,
        workflow_commit=arguments.workflow_commit,
        run_id=arguments.run_id,
        run_attempt=arguments.run_attempt,
        artifact_name=proposal["sourceArtifactName"],
        artifact_digest=proposal["sourceArtifactDigest"],
        activated_at=arguments.activated_at,
    )


def _successor(arguments: argparse.Namespace, anchor: dict[str, Any]) -> dict[str, Any]:
    if (
        arguments.source_id not in _SOURCE_IDS
        or _COMMIT.fullmatch(arguments.workflow_commit) is None
        or _DIGEST.fullmatch(arguments.expected_anchor_digest) is None
        or _DIGEST.fullmatch(arguments.artifact_digest) is None
        or arguments.run_id < 1
        or arguments.run_attempt < 1
    ):
        raise LineageError("dependency-intelligence-lineage-activation-coordinate-invalid")
    if anchor.get("anchorDigest") != arguments.expected_anchor_digest:
        raise LineageError("dependency-intelligence-lineage-activation-conflict")
    _authenticate_artifact(arguments)
    source = _bundle(arguments, anchor)
    activated = _timestamp(arguments.activated_at)
    retrieved = _timestamp(str(source["retrievedAt"]))
    expires = _timestamp(str(source["expiresAt"]))
    now = dt.datetime.now(dt.timezone.utc)
    if (
        activated > now
        or now - activated > dt.timedelta(minutes=30)
        or retrieved > activated
        or activated >= expires
    ):
        raise LineageError("dependency-intelligence-lineage-time-invalid")
    successor = {
        "schemaVersion": 1,
        "kind": "stable-1.0-dependency-intelligence-source-lineage-anchor",
        "repositoryIdentity": "github.com/crypta-network/cryptad",
        "sourceId": arguments.source_id,
        "policyDigest": _policy_digest(),
        "initialized": True,
        "anchorSequence": source["sourceEdition"],
        "sourceSnapshotDigest": source["sourceSnapshotDigest"],
        "rawContentDigest": source["rawContentDigest"],
        "canonicalRecordSetDigest": source["canonicalRecordSetDigest"],
        "componentInventoryDigest": source["componentInventoryDigest"],
        "retrievedAt": source["retrievedAt"],
        "previousAnchorDigest": anchor["anchorDigest"],
        "producerWorkflow": _WORKFLOW,
        "workflowCommit": arguments.workflow_commit,
        "runId": arguments.run_id,
        "runAttempt": arguments.run_attempt,
        "artifactName": arguments.artifact_name,
        "artifactDigest": arguments.artifact_digest,
        "contentStatus": _content_status(anchor, source),
        "retrievalValidation": "complete-200-response",
        "activatedAt": arguments.activated_at,
    }
    successor["anchorDigest"] = _semantic(successor, "anchorDigest")
    _validate_anchor(successor, arguments.source_id)
    return successor


def _write_set(repository: str, successor: dict[str, Any]) -> None:
    value = _canonical(successor).decode("utf-8").rstrip("\n")
    _gh(
        _WRITE_TOKEN,
        [
            "api",
            "--method",
            "PATCH",
            f"repos/{repository}/actions/variables/{_SET_VARIABLE}",
            "-f",
            f"name={_SET_VARIABLE}",
            "-f",
            f"value={value}",
        ],
    )
    if _read_set(repository, _WRITE_TOKEN) != successor:
        raise LineageError("dependency-intelligence-lineage-activation-verification-failed")


def _updated_set(
    current: dict[str, Any], successors: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    if not successors or not set(successors).issubset(_SOURCE_IDS):
        raise LineageError("dependency-intelligence-lineage-activation-set-invalid")
    lineages = [successors.get(row["sourceId"], row) for row in current["lineages"]]
    value = {
        "schemaVersion": 1,
        "kind": "stable-1.0-dependency-intelligence-source-lineage-set",
        "repositoryIdentity": "github.com/crypta-network/cryptad",
        "policyDigest": _policy_digest(),
        "setEdition": int(current["setEdition"]) + 1,
        "lineages": lineages,
        "setDigest": "sha256:" + "0" * 64,
    }
    value["setDigest"] = _semantic(value, "setDigest")
    _validate_set(value)
    return value


def _activate(arguments: argparse.Namespace) -> None:
    current = _read_set(arguments.repository, _WRITE_TOKEN)
    anchor = next(
        row for row in current["lineages"] if row["sourceId"] == arguments.source_id
    )
    successor = _successor(arguments, anchor)
    _write_set(arguments.repository, _updated_set(current, {arguments.source_id: successor}))


def _finalize(arguments: argparse.Namespace) -> None:
    proposal = _load(arguments.proposal, 64 * 1024)
    activation = _finalization_arguments(
        arguments,
        proposal,
        arguments.proposal,
        arguments.root,
        arguments.proposal_artifact_name,
        arguments.proposal_artifact_digest,
    )
    _activate(activation)


def _finalize_batch(arguments: argparse.Namespace) -> None:
    artifact_map = _load(arguments.artifact_map, 64 * 1024)
    expected_sources = (
        {"github-public-advisories", "osv-public"}
        if arguments.event == "schedule"
        else set(artifact_map)
    )
    if (
        set(artifact_map) != expected_sources
        or (arguments.event == "workflow_dispatch" and len(expected_sources) != 1)
        or not expected_sources.issubset(_SOURCE_IDS)
    ):
        raise LineageError("dependency-intelligence-lineage-finalizer-set-invalid")
    current = _read_set(arguments.repository, _WRITE_TOKEN)
    current_by_source = {row["sourceId"]: row for row in current["lineages"]}
    successors: dict[str, dict[str, Any]] = {}
    already_current: set[str] = set()
    superseded_alternatives: set[str] = set()
    for source_id in sorted(expected_sources):
        coordinates = artifact_map[source_id]
        if not isinstance(coordinates, dict) or set(coordinates) != {
            "sourceName",
            "sourceDigest",
            "proposalName",
            "proposalDigest",
        }:
            raise LineageError("dependency-intelligence-lineage-finalizer-set-invalid")
        source_name = coordinates.get("sourceName")
        proposal_name = coordinates.get("proposalName")
        if not isinstance(source_name, str) or not isinstance(proposal_name, str):
            raise LineageError("dependency-intelligence-lineage-finalizer-set-invalid")
        source_root = arguments.root / source_name
        proposal_path = arguments.root / proposal_name / _PROPOSAL_FILE
        proposal = _load(proposal_path, 64 * 1024)
        if (
            proposal.get("sourceId") != source_id
            or proposal.get("sourceArtifactName") != source_name
            or proposal.get("sourceArtifactDigest") != coordinates.get("sourceDigest")
            or proposal.get("proposalArtifactName") != proposal_name
            or _DIGEST.fullmatch(str(coordinates.get("proposalDigest", ""))) is None
        ):
            raise LineageError("dependency-intelligence-lineage-finalizer-set-invalid")
        activation = _finalization_arguments(
            arguments,
            proposal,
            proposal_path,
            source_root,
            proposal_name,
            coordinates["proposalDigest"],
        )
        anchor = current_by_source[source_id]
        if all(
            anchor.get(field) == expected
            for field, expected in (
                ("producerWorkflow", _WORKFLOW),
                ("workflowCommit", activation.workflow_commit),
                ("runId", activation.run_id),
                ("runAttempt", activation.run_attempt),
                ("artifactName", activation.artifact_name),
                ("artifactDigest", activation.artifact_digest),
            )
        ):
            already_current.add(source_id)
            continue
        if anchor.get("anchorDigest") != activation.expected_anchor_digest:
            superseded_alternatives.add(source_id)
            continue
        successors[source_id] = _successor(activation, current_by_source[source_id])
    inactive = already_current | superseded_alternatives
    if inactive:
        # Scheduled source activation is atomic.  Once any member has already
        # become current or has been superseded, replaying the retained pair
        # must not commit only the other member.  Every member was fully
        # authenticated above, so the whole stale alternative is a safe no-op.
        return
    # Every proposal, source artifact, predecessor, and successor is authenticated
    # before this sole remote mutation. A failed scheduled pair leaves the set intact.
    _write_set(arguments.repository, _updated_set(current, successors))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    read = commands.add_parser("read")
    read.add_argument("--repository", required=True)
    read.add_argument("--source-id", required=True)
    read.add_argument("--out", required=True, type=Path)
    verify = commands.add_parser("verify-current-bundle")
    verify.add_argument("--repository", required=True)
    verify.add_argument(
        "--source-id", choices=("github-public-advisories", "osv-public"), required=True
    )
    verify.add_argument("--source-record", required=True, type=Path)
    verify.add_argument("--provenance", required=True, type=Path)
    verify.add_argument("--run-id", required=True, type=int)
    verify.add_argument("--run-attempt", required=True, type=int)
    verify.add_argument("--artifact-name", required=True)
    verify.add_argument("--artifact-digest", required=True)
    verify_status = commands.add_parser("verify-current-status")
    verify_status.add_argument("--repository", required=True)
    verify_status.add_argument("--source-status", required=True, type=Path)
    verify_status.add_argument("--publication-plan", required=True, type=Path)
    verify_status.add_argument("--promotion-summary", required=True, type=Path)
    verify_summary = commands.add_parser("verify-current-summary")
    verify_summary.add_argument("--repository", required=True)
    verify_summary.add_argument("--source-status", required=True, type=Path)
    verify_summary.add_argument("--promotion-summary", required=True, type=Path)
    verify_summary.add_argument("--handoff", required=True, type=Path)
    proposal = commands.add_parser("write-proposal")
    proposal.add_argument("--source-id", required=True)
    proposal.add_argument("--expected-anchor-digest", required=True)
    proposal.add_argument("--predecessor", required=True, type=Path)
    proposal.add_argument("--source-record", required=True, type=Path)
    proposal.add_argument("--provenance", required=True, type=Path)
    proposal.add_argument("--manifest", required=True, type=Path)
    proposal.add_argument("--workflow-commit", required=True)
    proposal.add_argument("--run-id", required=True, type=int)
    proposal.add_argument("--run-attempt", required=True, type=int)
    proposal.add_argument("--source-artifact-name", required=True)
    proposal.add_argument("--source-artifact-digest", required=True)
    proposal.add_argument("--proposal-artifact-name", required=True)
    proposal.add_argument("--out", required=True, type=Path)
    finalize = commands.add_parser("finalize")
    finalize.add_argument("--repository", required=True)
    finalize.add_argument("--proposal", required=True, type=Path)
    finalize.add_argument("--root", required=True, type=Path)
    finalize.add_argument("--workflow-commit", required=True)
    finalize.add_argument("--run-id", required=True, type=int)
    finalize.add_argument("--run-attempt", required=True, type=int)
    finalize.add_argument("--proposal-artifact-name", required=True)
    finalize.add_argument("--proposal-artifact-digest", required=True)
    finalize.add_argument("--activated-at", required=True)
    finalize_batch = commands.add_parser("finalize-batch")
    finalize_batch.add_argument("--repository", required=True)
    finalize_batch.add_argument("--artifact-map", required=True, type=Path)
    finalize_batch.add_argument("--root", required=True, type=Path)
    finalize_batch.add_argument("--workflow-commit", required=True)
    finalize_batch.add_argument("--run-id", required=True, type=int)
    finalize_batch.add_argument("--run-attempt", required=True, type=int)
    finalize_batch.add_argument(
        "--event", choices=("schedule", "workflow_dispatch"), required=True
    )
    finalize_batch.add_argument("--activated-at", required=True)
    activate = commands.add_parser("activate")
    activate.add_argument("--repository", required=True)
    activate.add_argument("--source-id", required=True)
    activate.add_argument("--expected-anchor-digest", required=True)
    activate.add_argument("--source-record", required=True, type=Path)
    activate.add_argument("--provenance", required=True, type=Path)
    activate.add_argument("--manifest", required=True, type=Path)
    activate.add_argument("--workflow-commit", required=True)
    activate.add_argument("--run-id", required=True, type=int)
    activate.add_argument("--run-attempt", required=True, type=int)
    activate.add_argument("--artifact-name", required=True)
    activate.add_argument("--artifact-digest", required=True)
    activate.add_argument("--activated-at", required=True)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        if arguments.command == "read":
            anchor = _read(arguments.repository, arguments.source_id, _READ_TOKEN)
            arguments.out.parent.mkdir(parents=True, exist_ok=True)
            arguments.out.write_bytes(_canonical(anchor))
        elif arguments.command == "verify-current-bundle":
            _verify_current_bundle(arguments)
        elif arguments.command == "verify-current-status":
            _verify_current_status(arguments)
        elif arguments.command == "verify-current-summary":
            _verify_current_summary(arguments)
        elif arguments.command == "write-proposal":
            _write_proposal(arguments)
        elif arguments.command == "finalize":
            _finalize(arguments)
        elif arguments.command == "finalize-batch":
            _finalize_batch(arguments)
        else:
            _activate(arguments)
    except LineageError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

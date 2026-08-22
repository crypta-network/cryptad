"""Canonical side-effect-free Stable 1.0 maintenance and hotfix certification."""

from __future__ import annotations

import copy
import datetime as dt
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote, urlsplit, urlunsplit

from cryptad_certification.io import read_json, write_json, write_text
from cryptad_certification.models import RunContext
from cryptad_certification.schema_validation import validate_schema
from cryptad_certification.stable_vulnerability_summary import (
    follow_up_closure_errors,
    promotion_errors,
)
from cryptad_certification.workspace import reset_confined_directory

from .stable_1_0_ga_core import (
    _has_unambiguous_publication_path,
    canonical_artifact_base_uri,
    canonical_public_https_uri,
    is_public_https_uri,
)
from .stable_1_0_maintenance_artifacts import (
    build_redaction_report,
    render_go_no_go,
    render_release_notes,
)
from .stable_1_0_maintenance_compatibility import (
    _known_limitations_digest,
    build_comparison,
    close_hotfix_follow_up,
    validate_production_evidence,
)
from .stable_1_0_maintenance_core import (
    AUDIT_CHECKSUMS_FILE,
    AUTHORIZATION_FILE,
    AUTHORIZATION_SCHEMA,
    AUTHORIZATION_SCOPE,
    CANDIDATE_FILE,
    CANDIDATE_FREEZE_FILE,
    CHECKSUMS_FILE,
    COMPARISON_FILE,
    CORE_INFO_FILE,
    CORE_PLAN_FILE,
    CORE_PLAN_SCHEMA,
    CORE_RECEIPT_FILE,
    CORE_RECEIPT_SCHEMA,
    FOLLOW_UP_CLOSURE_FILE,
    FOLLOW_UP_CLOSURE_SCHEMA,
    FOLLOW_UP_FILE,
    HISTORY_FILE,
    KNOWN_LIMITATIONS_FILE,
    LATEST_POINTER_FILE,
    LINEAGE_FILE,
    LINEAGE_SCHEMA,
    PROVENANCE_FILE,
    PUBLICATION_PLAN_FILE,
    PUBLICATION_PLAN_SCHEMA,
    PUBLICATION_RECEIPT_FILE,
    PUBLICATION_RECEIPT_SCHEMA,
    REDACTION_REPORT_FILE,
    RELEASE_NOTES_FILE,
    REPORT_FILE,
    SCHEMA_VERSION,
    STABLE_MILESTONE,
    SUCCESSOR_BASELINE_FILE,
    SUCCESSOR_SCHEMA,
    SUMMARY_FILE,
    TOOL_NAME,
    TOOL_VERSION,
    VALIDATION_FILE,
    VALIDATION_SCHEMA,
    Candidate,
    GaRoot,
    LoadedJson,
    Predecessor,
    _maintenance_public_redaction_findings,
    add_blockers,
    authenticate_candidate,
    authenticate_ga_root,
    authenticate_predecessor,
    build_core_info,
    canonical_policy,
    file_digest,
    load_json_input,
    parse_timestamp,
    receipt_identity,
    semantic_digest,
    successor_baseline_identity,
)
from .stable_1_0_rc_core import ValidationState
from .release_certification_core import (
    STABLE_SUPPLY_CHAIN_HANDOFF_AUTHENTICATION_ALGORITHM,
    stable_dependency_vulnerability_evaluation_handoff_errors,
    stable_supply_chain_handoff_authentication_errors,
)
from .stable_1_0_supply_chain import EVIDENCE_IDS as SUPPLY_CHAIN_EVIDENCE_IDS
from .stable_1_0_supply_chain_activation import supply_chain_governance_active
from .stable_1_0_supply_chain_core import (
    POLICY_FILE as SUPPLY_CHAIN_POLICY_FILE,
    PUBLICATION_ROLE_FILES,
    SUMMARY_SCHEMA as SUPPLY_CHAIN_SUMMARY_SCHEMA,
    canonical_json_bytes as supply_chain_canonical_json_bytes,
    semantic_digest as supply_chain_semantic_digest,
    sha256_digest as supply_chain_sha256_digest,
)
from .stable_1_0_dependency_vulnerability_core import (
    EVIDENCE_IDS as DEPENDENCY_VULNERABILITY_EVIDENCE_IDS,
    POLICY_FILE as DEPENDENCY_VULNERABILITY_POLICY_FILE,
    POLICY_SCHEMA as DEPENDENCY_VULNERABILITY_POLICY_SCHEMA,
    SUMMARY_SCHEMA as DEPENDENCY_VULNERABILITY_SUMMARY_SCHEMA,
    semantic_digest as dependency_vulnerability_semantic_digest,
)

_PASS_REDACTION = {"status": "pass", "findingCount": 0, "findings": []}
SUPPLY_CHAIN_PUBLICATION_EVIDENCE_ID = "stable-supply-chain.publication"
SUPPLY_CHAIN_PROMOTION_EVIDENCE_IDS = tuple(
    evidence_id
    for evidence_id in SUPPLY_CHAIN_EVIDENCE_IDS
    if evidence_id != SUPPLY_CHAIN_PUBLICATION_EVIDENCE_ID
)


def _dependency_vulnerability_activation(
    context: RunContext, candidate: Candidate
) -> tuple[bool | None, list[str]]:
    """Authenticate the prospective PR-290 policy and derive candidate activation."""

    policy_path = (
        context.workspace_root
        / "tools"
        / "release-certification"
        / DEPENDENCY_VULNERABILITY_POLICY_FILE
    )
    if policy_path.is_symlink() or not policy_path.is_file():
        return None, [
            "the checked-in dependency-vulnerability policy is missing or unsafe"
        ]
    policy = read_json(policy_path)
    errors = validate_schema(policy, DEPENDENCY_VULNERABILITY_POLICY_SCHEMA)
    if errors:
        return None, ["the checked-in dependency-vulnerability policy is invalid"]
    if policy.get("policyDigest") != dependency_vulnerability_semantic_digest(
        policy, "policyDigest"
    ):
        return None, [
            "the checked-in dependency-vulnerability policy digest is invalid"
        ]
    effective = parse_timestamp(policy.get("effectiveAt"))
    activation = policy.get("governanceActivation")
    governance_effective = parse_timestamp(
        activation.get("candidateFrozenAtNotBefore")
        if isinstance(activation, dict)
        else None
    )
    if effective is None or governance_effective is None:
        return None, [
            "the checked-in dependency-vulnerability activation timestamp is invalid"
        ]
    if effective != governance_effective:
        return None, [
            "the checked-in dependency-vulnerability policy activation timestamps differ"
        ]
    frozen = parse_timestamp(candidate.frozen_at)
    if frozen is None:
        return None, ["the maintenance candidate frozenAt timestamp is invalid"]
    return frozen >= governance_effective, []


def _dependency_vulnerability_promotion_errors(
    context: RunContext,
    candidate: Candidate,
    supply_chain_summary: LoadedJson,
    activation_result: tuple[bool | None, list[str]] | None = None,
) -> list[str]:
    """Apply PR-290 only to candidates frozen after its prospective activation."""

    active, activation_errors = (
        activation_result
        if activation_result is not None
        else _dependency_vulnerability_activation(context, candidate)
    )
    if activation_errors:
        return activation_errors
    if active is not True:
        return []
    policy_path = (
        context.workspace_root
        / "tools"
        / "release-certification"
        / DEPENDENCY_VULNERABILITY_POLICY_FILE
    )
    policy = read_json(policy_path)
    loaded = load_json_input(
        context, "dependencyVulnerabilityPromotionSummary", required=False
    )
    if loaded is None:
        return ["post-activation candidate lacks the PR-290 promotion companion"]
    value = loaded.value
    errors = validate_schema(value, DEPENDENCY_VULNERABILITY_SUMMARY_SCHEMA)
    if errors:
        return ["dependency-vulnerability promotion companion schema is invalid"]
    if value.get("summaryDigest") != dependency_vulnerability_semantic_digest(
        value, "summaryDigest"
    ):
        errors.append("dependency-vulnerability promotion companion digest is invalid")
    try:
        valid_until = parse_timestamp(value.get("validUntil"))
        if valid_until is None:
            raise ValueError("dependency-vulnerability promotion companion validUntil is invalid")
        if _now() >= valid_until:
            errors.append(
                "dependency-vulnerability promotion companion is stale at authorization preparation"
            )
    except (TypeError, ValueError):
        errors.append("dependency-vulnerability promotion companion validUntil is invalid")
    if not _canonical_json_input(loaded.path, value):
        errors.append("dependency-vulnerability promotion companion bytes are not canonical")
    handoff_errors, handoff = (
        stable_dependency_vulnerability_evaluation_handoff_errors(
            loaded.path,
            loaded.digest,
            context.manifest.release.release_id,
            context.manifest.release.version or "",
            str(candidate.source.get("commit", "")),
        )
    )
    errors.extend(handoff_errors)
    if handoff is not None:
        metadata = context.manifest.policies.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        metadata_bindings = {
            "stableDependencyVulnerabilityRunId": "runId",
            "stableDependencyVulnerabilityRunAttempt": "runAttempt",
            "stableDependencyVulnerabilityArtifactName": "artifactName",
            "stableDependencyVulnerabilityArtifactDigest": "producerArtifactDigest",
        }
        for metadata_field, handoff_field in metadata_bindings.items():
            if str(metadata.get(metadata_field, "")) != str(
                handoff.get(handoff_field, "")
            ):
                errors.append(
                    "dependency-vulnerability producer handoff differs from manifest "
                    f"{metadata_field}"
                )
    expected = {
        "releaseId": context.manifest.release.release_id,
        "buildVersion": int(context.manifest.release.version or "0"),
        "candidateSourceCommit": candidate.source.get("commit"),
        "policyDigest": policy.get("policyDigest"),
        "supplyChainPromotionSummaryDigest": supply_chain_summary.value.get("summaryDigest"),
    }
    for field, expected_value in expected.items():
        if value.get(field) != expected_value:
            errors.append(f"dependency-vulnerability promotion companion {field} differs")
    reverse_index_digest = supply_chain_summary.value.get(
        "vulnerabilityReverseIndexDigest"
    )
    if value.get("componentReverseIndexDigest") != reverse_index_digest:
        errors.append("dependency-vulnerability companion reverse-index digest differs")
    vulnerability = load_json_input(context, "stableVulnerabilitySummary", required=False)
    if vulnerability is None:
        errors.append("dependency-vulnerability companion lacks authenticated PR-288 input")
    elif value.get("vulnerabilityPromotionSummaryDigest") != vulnerability.value.get(
        "summaryDigest"
    ):
        errors.append("dependency-vulnerability companion PR-288 digest differs")
    evidence = value.get("evidence") if isinstance(value.get("evidence"), list) else []
    evidence_by_id = {
        row.get("evidenceId"): row for row in evidence if isinstance(row, dict)
    }
    prepublication_evidence_ids = tuple(
        evidence_id
        for evidence_id in DEPENDENCY_VULNERABILITY_EVIDENCE_IDS
        if evidence_id != "stable-dependency-vulnerability.publication"
    )
    if set(evidence_by_id) != set(prepublication_evidence_ids):
        errors.append(
            "dependency-vulnerability prepublication evidence ids are not the closed required set"
        )
    for evidence_id in prepublication_evidence_ids:
        row = evidence_by_id.get(evidence_id)
        if row is None or row.get("status") != "pass" or row.get("nonWaivable") is not True:
            errors.append(f"dependency-vulnerability companion evidence {evidence_id} is not passing")
    for field in (
        "publicationPlanDigest",
        "publicationReceiptDigest",
        "publicObservationDigest",
    ):
        if value.get(field) is not None:
            errors.append(
                f"dependency-vulnerability prepublication companion prematurely claims {field}"
            )
    if (
        value.get("mode") != "evaluate-promotion"
        or value.get("activationStatus") != "active-post-activation"
        or value.get("status") != "pass"
        or value.get("promotionReady") is not True
        or value.get("blockers") != []
        or value.get("waivers") != []
        or value.get("redaction", {}).get("status") != "pass"
    ):
        errors.append(
            "dependency-vulnerability companion does not authorize prepublication maintenance preparation"
        )
    return errors
SUPPLY_CHAIN_HANDOFF_FILE = "stable-1.0-supply-chain-summary-provenance.json"
SUPPLY_CHAIN_SUMMARY_FILE = "stable-1.0-supply-chain-summary.json"
SUPPLY_CHAIN_WORKFLOW = (
    "crypta-network/cryptad/.github/workflows/stable-1.0-supply-chain.yml"
)
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_RUN_ID_RE = re.compile(r"[1-9][0-9]*")
_SUPPLY_CHAIN_HANDOFF_FIELDS = frozenset(
    {
        "schemaVersion",
        "kind",
        "repository",
        "workflow",
        "workflowCommit",
        "runId",
        "runAttempt",
        "operation",
        "releaseId",
        "buildVersion",
        "sourceCommit",
        "artifactName",
        "producerArtifactDigest",
        "summaryFileName",
        "summaryByteDigest",
        "attestationSubjectDigest",
        "attestationVerified",
        "denySelfHostedRunners",
        "authenticationStatus",
        "authenticationAlgorithm",
        "authenticationTag",
    }
)
LIFECYCLE_PENDING_TRANSITION_FILE = (
    "stable-1.0-support-lifecycle-pending-maintenance-transition.json"
)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def _timestamp(value: Any) -> str:
    parsed = parse_timestamp(value)
    if parsed is None:
        raise ValueError("Stable maintenance generated timestamp is malformed")
    return parsed.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _https(value: Any) -> bool:
    canonical = canonical_public_https_uri(value)
    return (
        is_public_https_uri(canonical)
        and "replace" not in canonical.lower()
        and "example.invalid" not in canonical.lower()
        and "\\" not in canonical
    )


def _public_child(base: str, name: str) -> str:
    parsed = urlsplit(base)
    path = parsed.path.rstrip("/") + "/" + quote(name, safe="._-")
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _catalog_signature_uri(catalog_uri: str, signature_name: Any) -> str:
    """Place the detached catalog signature beside the authenticated catalog URI."""

    if not isinstance(signature_name, str) or Path(signature_name).name != signature_name:
        raise ValueError("stable catalog detached signature filename is unsafe")
    parsed = urlsplit(catalog_uri)
    parent = parsed.path.rpartition("/")[0]
    path = parent + "/" + quote(signature_name, safe="._-")
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _copy_exact(source: Path, destination: Path, digest: str) -> None:
    if destination.is_symlink() or destination.exists():
        raise ValueError("exact-byte candidate output already exists")
    shutil.copyfile(source, destination)
    os.chmod(destination, 0o644)
    if file_digest(destination) != digest:
        destination.unlink(missing_ok=True)
        raise ValueError("exact-byte candidate copy changed after freeze")


def _write_checksums(path: Path, members: Iterable[Path]) -> None:
    rows: dict[str, str] = {}
    for member in members:
        if member.name in rows:
            raise ValueError(f"checksum artifact basename is ambiguous: {member.name}")
        rows[member.name] = file_digest(member).removeprefix("sha256:")
    write_text(path, "\n".join(f"{rows[name]}  {name}" for name in sorted(rows)))


def _public_checksum_payload_paths(candidate: Candidate, out: Path) -> dict[str, Path]:
    """Return public payloads whose digests do not depend on the checksum manifest."""

    paths = dict(candidate.asset_paths)
    generated = {
        RELEASE_NOTES_FILE: out / RELEASE_NOTES_FILE,
        KNOWN_LIMITATIONS_FILE: out / KNOWN_LIMITATIONS_FILE,
        PROVENANCE_FILE: out / PROVENANCE_FILE,
        CORE_INFO_FILE: out / CORE_INFO_FILE,
    }
    pending_lifecycle = out / LIFECYCLE_PENDING_TRANSITION_FILE
    if pending_lifecycle.is_file():
        generated[LIFECYCLE_PENDING_TRANSITION_FILE] = pending_lifecycle
    duplicates = sorted(paths.keys() & generated.keys())
    if duplicates:
        raise ValueError(f"public payload basename is ambiguous: {duplicates[0]}")
    paths.update(generated)
    return paths


def _canonical_json_input(path: Path, value: dict[str, Any]) -> bool:
    expected = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
        + b"\n"
    )
    try:
        return path.read_bytes() == expected
    except OSError:
        return False


def _schema_gate(
    state: ValidationState,
    issue_id: str,
    value: dict[str, Any],
    schema: str,
    remediation: str,
) -> None:
    add_blockers(state, issue_id, validate_schema(value, schema), remediation)


def _supply_chain_governance_active(
    candidate: Candidate, supply_policy: dict[str, Any] | None
) -> bool:
    """Return whether PR-289 handoff authentication applies to this frozen candidate."""

    return supply_chain_governance_active(candidate.frozen_at, supply_policy)


def _supply_chain_handoff_errors(
    context: RunContext,
    summary: LoadedJson,
    candidate: Candidate,
    *,
    required: bool,
) -> list[str]:
    """Validate the exact protected producer identity that materialized the summary."""

    path = summary.path.with_name(SUPPLY_CHAIN_HANDOFF_FILE)
    if path.is_symlink() or not path.is_file():
        return (
            ["Stable supply-chain summary lacks its protected producer handoff"]
            if required
            else []
        )
    try:
        if path.stat(follow_symlinks=False).st_size > 64 * 1024:
            return ["Stable supply-chain producer handoff exceeds its size bound"]
        raw = path.read_bytes()
        value = read_json(path)
    except (OSError, UnicodeDecodeError, ValueError):
        return ["Stable supply-chain producer handoff is unreadable or malformed"]
    if not isinstance(value, dict):
        return ["Stable supply-chain producer handoff is not a JSON object"]
    errors: list[str] = []
    canonical = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
        + b"\n"
    )
    if raw != canonical:
        errors.append("Stable supply-chain producer handoff bytes are not canonical")
    if set(value) != _SUPPLY_CHAIN_HANDOFF_FIELDS:
        errors.append("Stable supply-chain producer handoff fields are not closed")

    release_id = context.manifest.release.release_id
    build_version = context.manifest.release.version or ""
    source_commit = str(candidate.source.get("commit", ""))
    expected_workflow = f"{SUPPLY_CHAIN_WORKFLOW}@{source_commit}"
    expected_artifact_name = f"stable-1.0-supply-chain-{release_id}-comparison"
    expected: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": "stable-1.0-supply-chain-promotion-handoff",
        "repository": "crypta-network/cryptad",
        "workflow": expected_workflow,
        "workflowCommit": source_commit,
        "operation": "compare-evaluate",
        "releaseId": release_id,
        "buildVersion": build_version,
        "sourceCommit": source_commit,
        "artifactName": expected_artifact_name,
        "summaryFileName": SUPPLY_CHAIN_SUMMARY_FILE,
        "summaryByteDigest": summary.digest,
        "attestationSubjectDigest": summary.digest,
        "attestationVerified": True,
        "denySelfHostedRunners": True,
        "authenticationStatus": "pass",
        "authenticationAlgorithm": STABLE_SUPPLY_CHAIN_HANDOFF_AUTHENTICATION_ALGORITHM,
    }
    for field, expected_value in expected.items():
        if value.get(field) != expected_value:
            errors.append(f"Stable supply-chain producer handoff {field} differs")
    if _RUN_ID_RE.fullmatch(str(value.get("runId", ""))) is None:
        errors.append("Stable supply-chain producer handoff runId is invalid")
    if _RUN_ID_RE.fullmatch(str(value.get("runAttempt", ""))) is None:
        errors.append("Stable supply-chain producer handoff runAttempt is invalid")
    if _DIGEST_RE.fullmatch(str(value.get("producerArtifactDigest", ""))) is None:
        errors.append("Stable supply-chain producer handoff artifact digest is invalid")
    errors.extend(
        stable_supply_chain_handoff_authentication_errors(
            value,
            label="Stable supply-chain producer handoff",
        )
    )

    metadata = context.manifest.policies.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    metadata_bindings = {
        "stableSupplyChainRunId": "runId",
        "stableSupplyChainRunAttempt": "runAttempt",
        "stableSupplyChainArtifactName": "artifactName",
        "stableSupplyChainArtifactDigest": "producerArtifactDigest",
    }
    for metadata_field, handoff_field in metadata_bindings.items():
        if str(metadata.get(metadata_field, "")) != str(value.get(handoff_field, "")):
            errors.append(
                f"Stable supply-chain producer handoff differs from manifest {metadata_field}"
            )
    return errors


def _supply_chain_promotion_errors(
    context: RunContext,
    summary: LoadedJson,
    candidate: Candidate,
    predecessor: Predecessor,
) -> list[str]:
    """Authenticate the non-waivable PR-289 summary for this exact successor."""

    value = summary.value
    errors = validate_schema(value, SUPPLY_CHAIN_SUMMARY_SCHEMA)
    if not _canonical_json_input(summary.path, value):
        errors.append("Stable supply-chain promotion summary bytes are not canonical")
    if value.get("summaryDigest") != supply_chain_semantic_digest(
        value, "summaryDigest"
    ):
        errors.append("Stable supply-chain promotion summary digest is invalid")

    policy_path = (
        context.workspace_root / "tools/release-certification" / SUPPLY_CHAIN_POLICY_FILE
    )
    try:
        supply_policy = read_json(policy_path)
    except (OSError, ValueError):
        supply_policy = None
    if not isinstance(supply_policy, dict):
        errors.append("checked-in Stable supply-chain policy is missing or malformed")
    elif value.get("policyDigest") != supply_policy.get("policyDigest"):
        errors.append("Stable supply-chain summary binds a different policy")
    errors.extend(
        _supply_chain_handoff_errors(
            context,
            summary,
            candidate,
            required=_supply_chain_governance_active(candidate, supply_policy),
        )
    )

    expected_candidate_digest = supply_chain_sha256_digest(
        supply_chain_canonical_json_bytes(candidate.input_value)
    )
    package_projection = {
        "packages": sorted(
            [
                {
                    "packageKey": row.get("packageKey"),
                    "digest": row.get("digest"),
                }
                for row in candidate.assets
            ],
            key=lambda row: str(row.get("packageKey")),
        )
    }
    expected_package_digest = supply_chain_sha256_digest(
        supply_chain_canonical_json_bytes(package_projection)
    )
    expected_bindings: dict[str, Any] = {
        "releaseId": context.manifest.release.release_id,
        "buildVersion": int(context.manifest.release.version or "0"),
        "tag": f"v{context.manifest.release.version}",
        "sourceCommit": candidate.source.get("commit"),
        "sourceRef": candidate.source.get("ref"),
        "candidateIdentityDigest": expected_candidate_digest,
        "candidateFreezeDigest": candidate.freeze_digest,
        "productDigest": candidate.product_digest,
        "predecessorReleaseId": predecessor.release_id,
        "predecessorBuildVersion": int(predecessor.build_version),
        "predecessorProductDigest": predecessor.product_digest,
        "packageMatrixDigest": expected_package_digest,
    }
    for field, expected in expected_bindings.items():
        if value.get(field) != expected:
            errors.append(f"Stable supply-chain summary {field} differs")

    vulnerability_loaded = load_json_input(
        context, "stableVulnerabilitySummary", required=False
    )
    if vulnerability_loaded is not None:
        vulnerability_digest = supply_chain_semantic_digest(
            vulnerability_loaded.value, "summaryDigest"
        )
        if (
            vulnerability_loaded.value.get("summaryDigest") != vulnerability_digest
            or value.get("vulnerabilitySummaryDigest") != vulnerability_digest
        ):
            errors.append(
                "Stable supply-chain summary binds a different vulnerability summary"
            )
    elif value.get("vulnerabilitySummaryDigest") is not None:
        errors.append(
            "Stable supply-chain summary names vulnerability state without its authenticated input"
        )

    if (
        value.get("mode") != "evaluate-promotion"
        or value.get("status") != "pass"
        or value.get("promotionReady") is not True
        or value.get("blockers") != []
        or value.get("waivers") != []
    ):
        errors.append("Stable supply-chain summary does not permit promotion")
    evidence = value.get("evidence")
    evidence = evidence if isinstance(evidence, list) else []
    evidence_by_id = {
        row.get("evidenceId"): row for row in evidence if isinstance(row, dict)
    }
    if len(evidence_by_id) != len(evidence):
        errors.append("Stable supply-chain summary contains duplicate evidence ids")
    if not set(SUPPLY_CHAIN_PROMOTION_EVIDENCE_IDS).issubset(evidence_by_id):
        errors.append("Stable supply-chain summary evidence coverage is incomplete")
    if set(evidence_by_id) - set(SUPPLY_CHAIN_EVIDENCE_IDS):
        errors.append("Stable supply-chain summary contains an unknown evidence id")
    publication_row = evidence_by_id.get(SUPPLY_CHAIN_PUBLICATION_EVIDENCE_ID)
    if isinstance(publication_row, dict) and publication_row.get("status") == "pass":
        errors.append(
            "Stable supply-chain promotion summary falsely claims publication passed"
        )
    for evidence_id in SUPPLY_CHAIN_PROMOTION_EVIDENCE_IDS:
        row = evidence_by_id.get(evidence_id)
        if (
            not isinstance(row, dict)
            or row.get("status") != "pass"
            or row.get("nonWaivable") is not True
        ):
            errors.append(f"Stable supply-chain evidence is not passing: {evidence_id}")
    for field in (
        "selectedSubjectInventoryDigest",
        "vulnerabilityReverseIndexDigest",
        "resolvedDependencySnapshotDigest",
        "componentInventoryDigest",
        "subjectInventoryDigest",
        "sbomDigest",
        "licenseInventoryDigest",
        "buildMaterialsDigest",
        "primaryBuilderReceiptDigest",
        "verifierBuilderReceiptDigest",
        "comparisonPlanDigest",
        "reproducibilityResultDigest",
    ):
        if not isinstance(value.get(field), str):
            errors.append(f"Stable supply-chain summary lacks {field}")
    redaction = value.get("redaction")
    if (
        not isinstance(redaction, dict)
        or redaction.get("status") != "pass"
        or redaction.get("sideEffectsPerformed") is not False
    ):
        errors.append("Stable supply-chain summary failed redaction or side-effect checks")
    publication_policy = supply_policy.get("publicationPolicy", {})
    required_roles = publication_policy.get("requiredRoles")
    if required_roles != list(PUBLICATION_ROLE_FILES):
        errors.append("Stable supply-chain publication role vocabulary differs")
    artifacts = value.get("artifacts")
    artifacts = artifacts if isinstance(artifacts, list) else []
    artifacts_by_name = {
        row.get("name"): row for row in artifacts if isinstance(row, dict)
    }
    if len(artifacts_by_name) != len(artifacts):
        errors.append("Stable supply-chain summary contains duplicate artifact names")
    expected_artifact_roles = set(PUBLICATION_ROLE_FILES) - {"supply-chain-summary"}
    if not expected_artifact_roles.issubset(artifacts_by_name):
        errors.append("Stable supply-chain summary omits a public companion artifact")
    return errors


def _supply_chain_companion_assets(
    context: RunContext, summary: Any | None
) -> list[dict[str, Any]]:
    """Bind the only supply-chain assets allowed beside maintenance-owned Release assets."""

    if summary is None:
        return []
    policy_path = (
        context.workspace_root
        / "tools/release-certification"
        / SUPPLY_CHAIN_POLICY_FILE
    )
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    publication = policy.get("publicationPolicy", {})
    roles = publication.get("requiredRoles")
    base = publication.get("immutableBaseUri")
    artifacts = summary.value.get("artifacts")
    artifacts = artifacts if isinstance(artifacts, list) else []
    artifacts_by_name = {
        row.get("name"): row for row in artifacts if isinstance(row, dict)
    }
    if (
        roles != list(PUBLICATION_ROLE_FILES)
        or not isinstance(base, str)
        or len(artifacts_by_name) != len(artifacts)
        or any(
            role != "supply-chain-summary" and role not in artifacts_by_name
            for role in PUBLICATION_ROLE_FILES
        )
    ):
        return []
    rows: list[dict[str, Any]] = []
    tag = f"v{context.manifest.release.version}"
    for role, file_name in PUBLICATION_ROLE_FILES.items():
        if role == "supply-chain-summary":
            digest = summary.digest
            size = summary.path.stat().st_size
        else:
            artifact = artifacts_by_name[role]
            digest = artifact.get("digest")
            size = artifact.get("size")
        rows.append(
            {
                "role": role,
                "fileName": file_name,
                "digest": digest,
                "sizeBytes": size,
                "publicUri": f"{base}/{tag}/{file_name}",
            }
        )
    return rows


def _targets(context: RunContext, state: ValidationState) -> tuple[dict[str, Any], str]:
    metadata = context.manifest.policies.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    artifact_base = context.manifest.policies.get("artifactBaseUri")
    mirrors = metadata.get("catalogMirrorUris")
    mirror_uris = (
        [
            canonical_public_https_uri(item.strip())
            for item in mirrors.split(",")
            if item.strip()
        ]
        if isinstance(mirrors, str)
        else []
    )
    targets = {
        "repository": "crypta-network/cryptad",
        "tag": f"v{context.manifest.release.version}",
        "githubReleasePageUri": canonical_public_https_uri(
            metadata.get("githubReleasePageUri")
        ),
        "deploymentServicePublicUri": canonical_public_https_uri(
            metadata.get("deploymentServicePublicUri")
        ),
        "latestPointerPublicUri": canonical_public_https_uri(
            metadata.get("latestPointerPublicUri")
        ),
        "artifactBaseUri": canonical_artifact_base_uri(
            canonical_public_https_uri(artifact_base)
        ),
        "catalogPrimaryUri": canonical_public_https_uri(
            metadata.get("catalogPrimaryUri")
        ),
        "catalogMirrorUris": sorted(mirror_uris),
        "catalogRollbackUri": canonical_public_https_uri(
            metadata.get("catalogRollbackUri")
        ),
        "coreUpdatePublicUri": canonical_public_https_uri(
            metadata.get("coreUpdatePublicUri")
        ),
        "coreUpdateEdition": int(str(context.manifest.release.version)),
    }
    expected_github_release_page = (
        "https://github.com/crypta-network/cryptad/releases/tag/"
        f"{targets['tag']}"
    )
    uris = [
        targets["githubReleasePageUri"],
        targets["deploymentServicePublicUri"],
        targets["latestPointerPublicUri"],
        targets["artifactBaseUri"],
        targets["catalogPrimaryUri"],
        *targets["catalogMirrorUris"],
        targets["catalogRollbackUri"],
        targets["coreUpdatePublicUri"],
    ]
    errors: list[str] = []
    if targets["githubReleasePageUri"] != expected_github_release_page:
        errors.append(
            "GitHub Release page URI must exactly match the fixed repository and build tag"
        )
    if not targets["catalogMirrorUris"]:
        errors.append("publication targets require at least one catalog mirror URI")
    # The exact GitHub URL above is a fixed public target. Avoid a DNS dependency for that
    # repository constant while retaining resolved-address validation for configurable targets.
    configurable_uris = uris[1:]
    if not all(
        _https(item) and _has_unambiguous_publication_path(item)
        for item in configurable_uris
    ):
        errors.append("publication targets must be distinct public credential-free HTTPS URIs")
    if len(uris) != len(set(uris)):
        errors.append("publication targets contain an ambiguous duplicate URI")
    add_blockers(
        state,
        "stable-maintenance.publication-conflict",
        errors,
        "Provide the exact conflict-free public publication target set.",
    )
    return targets, semantic_digest(targets)


def _concrete_publication_destination_errors(
    targets: dict[str, Any], candidate: Candidate
) -> list[str]:
    """Reject aliases among every concrete public object in the current plan schemas."""

    catalog = candidate.input_value.get("stableCatalog")
    catalog = catalog if isinstance(catalog, dict) else {}
    product = candidate.input_value.get("product")
    product = product if isinstance(product, dict) else {}
    artifact_names: list[tuple[str, Any]] = [
        ("artifact:product", product.get("fileName")),
        ("artifact:stable-catalog", catalog.get("fileName")),
        ("artifact:stable-catalog-signature", catalog.get("signatureFileName")),
        ("artifact:release-notes", RELEASE_NOTES_FILE),
        ("artifact:known-limitations", KNOWN_LIMITATIONS_FILE),
        ("artifact:checksums", CHECKSUMS_FILE),
        ("artifact:provenance", PROVENANCE_FILE),
        ("artifact:authorization", AUTHORIZATION_FILE),
        ("artifact:core-info", CORE_INFO_FILE),
    ]
    artifact_names.extend(
        (f"artifact:package:{row.get('packageKey')}", row.get("fileName"))
        for row in candidate.assets
        if isinstance(row, dict)
    )
    destinations: list[tuple[str, Any]] = []
    for role, name in artifact_names:
        if not isinstance(name, str) or Path(name).name != name:
            destinations.append((role, ""))
        else:
            destinations.append(
                (role, _public_child(str(targets.get("artifactBaseUri", "")), name))
            )
    destinations.extend(
        [
            ("github-release", targets.get("githubReleasePageUri")),
            ("deployment-service", targets.get("deploymentServicePublicUri")),
            ("latest-maintenance-pointer", targets.get("latestPointerPublicUri")),
            ("stable-catalog-primary", targets.get("catalogPrimaryUri")),
            (
                "stable-catalog-signature",
                _catalog_signature_uri(
                    str(targets.get("catalogPrimaryUri", "")),
                    catalog.get("signatureFileName"),
                ),
            ),
            ("stable-catalog-rollback", targets.get("catalogRollbackUri")),
            ("core-update-descriptor", targets.get("coreUpdatePublicUri")),
        ]
    )
    destinations.extend(
        (f"stable-catalog-mirror:{index}", uri)
        for index, uri in enumerate(targets.get("catalogMirrorUris", []))
    )

    errors: list[str] = []
    roles_by_uri: dict[str, list[str]] = {}
    fixed_github_release_uri = (
        "https://github.com/crypta-network/cryptad/releases/tag/"
        f"{targets.get('tag')}"
    )
    for role, raw_uri in destinations:
        canonical_uri = canonical_public_https_uri(raw_uri)
        is_public_destination = (
            canonical_uri == fixed_github_release_uri
            if role == "github-release"
            else _https(canonical_uri)
        )
        if (
            canonical_uri != raw_uri
            or not is_public_destination
            or not _has_unambiguous_publication_path(canonical_uri)
        ):
            errors.append(
                f"concrete publication destination for {role} is not canonical public HTTPS"
            )
            continue
        roles_by_uri.setdefault(canonical_uri, []).append(role)
    collisions = [
        sorted(roles)
        for roles in roles_by_uri.values()
        if len(roles) > 1
    ]
    for roles in sorted(collisions):
        errors.append(
            "concrete publication destinations collide across roles: "
            + ", ".join(roles)
        )
    return errors


def _lifecycle_input_presence_errors(
    lifecycle_inputs: tuple[
        Any | None,
        Any | None,
        Any | None,
        Any | None,
        Any | None,
    ],
    chain_depth: int,
    *,
    require_activation: bool = True,
) -> list[str]:
    """Require one exact authenticated lifecycle chain after genesis."""

    if not require_activation:
        return []
    present = [item is not None for item in lifecycle_inputs]
    if any(present) and not all(present):
        return [
            "lifecycle maintenance integration requires ledger, descriptor, approved "
            "authorization, authorized publication plan, and verified receipt together"
        ]
    if not any(present) and chain_depth > 0:
        return [
            "a post-GA maintenance chain requires the exact authenticated lifecycle ledger, "
            "descriptor, approved authorization, authorized publication plan, and verified "
            "publication receipt"
        ]
    return []


def _lifecycle_successor_capacity_errors(
    predecessor: Predecessor, lifecycle_policy: dict[str, Any]
) -> list[str]:
    """Block publication before the complete successor inventory exceeds runtime capacity."""

    descriptor_policy = lifecycle_policy.get("descriptor")
    descriptor_policy = (
        descriptor_policy if isinstance(descriptor_policy, dict) else {}
    )
    maximum_entries = descriptor_policy.get("maximumEntries")
    if type(maximum_entries) is not int or maximum_entries < 1:
        return ["lifecycle descriptor entry bound is missing or invalid"]
    successor_entries = predecessor.chain_depth + 2
    if successor_entries > maximum_entries:
        return [
            "candidate publication would exceed the authenticated lifecycle descriptor "
            f"entry bound of {maximum_entries}"
        ]
    return []


def _apply_lifecycle_promotion_gate(
    value: dict[str, Any], lifecycle_activation_verified: bool
) -> None:
    """Keep evaluation useful while lifecycle activation remains a protected pending step."""

    if not lifecycle_activation_verified:
        value["promotionReady"] = False
        value["decision"] = "no-go"


def _lifecycle_predecessor_errors(
    lifecycle_ledger: dict[str, Any],
    predecessor: Predecessor,
    release_class: Any,
) -> list[str]:
    """Reject a maintenance class that misrepresents lifecycle predecessor eligibility."""

    errors = validate_schema(
        lifecycle_ledger, "stable-1.0-support-lifecycle-ledger-v1.schema.json"
    )
    entry = _lifecycle_predecessor_entry(lifecycle_ledger, predecessor)
    if entry is None:
        errors.append("lifecycle ledger does not bind the exact authenticated predecessor")
        return errors
    status = entry.get("lifecycleStatus")
    if release_class == "maintenance" and status != "current-stable":
        errors.append("routine maintenance predecessor is not lifecycle current-stable")
    if release_class == "security-hotfix" and status not in {
        "current-stable",
        "supported-maintenance",
        "security-fixes-only",
        "deprecated",
        "revoked",
    }:
        errors.append("security hotfix predecessor is not eligible under lifecycle policy")
    if status == "end-of-support":
        errors.append("end-of-support predecessor cannot be treated as normally supported")
    return errors


def _lifecycle_predecessor_entry(
    lifecycle_ledger: dict[str, Any], predecessor: Predecessor
) -> dict[str, Any] | None:
    """Return the one ledger entry bound to the authenticated predecessor, if present."""

    rows = lifecycle_ledger.get("entries")
    rows = rows if isinstance(rows, list) else []
    matches = [
        row
        for row in rows
        if isinstance(row, dict)
        and row.get("releaseId") == predecessor.release_id
        and row.get("buildVersion") == predecessor.build_version
        and row.get("tag") == predecessor.tag
        and row.get("sourceCommit") == predecessor.source_commit
        and row.get("productDigest") == predecessor.product_digest
        and row.get("publicationReceiptDigest") == predecessor.receipt_digest
        and row.get("baselineDigest") == predecessor.baseline_digest
    ]
    return matches[0] if len(matches) == 1 else None


def _hotfix_lifecycle_authority_errors(
    lifecycle_ledger: dict[str, Any],
    lifecycle_descriptor: dict[str, Any],
    predecessor: Predecessor,
    release_class: Any,
    hotfix_scope: dict[str, Any] | None,
) -> list[str]:
    """Validate current selection and the protected exception for a security hotfix."""

    entry = _lifecycle_predecessor_entry(lifecycle_ledger, predecessor)
    if entry is None:
        return []
    current = [
        row
        for row in lifecycle_ledger.get("entries", [])
        if isinstance(row, dict) and row.get("lifecycleStatus") == "current-stable"
    ]
    ordered_entries = [
        row for row in lifecycle_ledger.get("entries", []) if isinstance(row, dict)
    ]
    status = entry.get("lifecycleStatus")
    if len(current) > 1:
        return ["lifecycle state selects more than one current-stable build"]
    if len(current) == 1 and (
        lifecycle_descriptor.get("currentStableBuild")
        != current[0].get("buildVersion")
    ):
        return ["lifecycle descriptor does not select the ledger current-stable build"]
    if release_class == "maintenance" or status == "current-stable":
        if (
            len(current) != 1
            or current[0].get("buildVersion") != predecessor.build_version
            or lifecycle_descriptor.get("currentStableBuild")
            != predecessor.build_version
        ):
            return [
                "lifecycle state does not select exactly the authenticated predecessor tip"
            ]
        return []
    if release_class != "security-hotfix":
        return ["lifecycle release class is not eligible for a non-current predecessor"]

    errors: list[str] = []
    scope = hotfix_scope if isinstance(hotfix_scope, dict) else {}
    incident_id = scope.get("incidentId")
    if not incident_id or not scope.get("hotfixPolicyAuthorizationDigest"):
        errors.append(
            "security hotfix lifecycle exception lacks exact incident and protected policy "
            "authorization scope"
        )
    if len(current) == 0 and (
        status != "revoked"
        or lifecycle_descriptor.get("currentStableBuild") is not None
        or not ordered_entries
        or ordered_entries[-1].get("buildVersion") != predecessor.build_version
    ):
        errors.append(
            "lifecycle state without a current-stable build is allowed only for a revoked "
            "predecessor tip"
        )
    if status == "revoked":
        matching_revocations = [
            transition
            for transition in lifecycle_ledger.get("transitions", [])
            if isinstance(transition, dict)
            and transition.get("targetBuild") == predecessor.build_version
            and transition.get("toStatus") == "revoked"
            and transition.get("advisoryId") == incident_id
            and predecessor.build_version in transition.get("affectedBuilds", [])
            and transition.get("securityEvidenceIds")
            and transition.get("publicationTargetDigest")
            and transition.get("authorizationRequestDigest")
        ]
        if (
            len(matching_revocations) != 1
            or incident_id not in entry.get("advisoryIds", [])
            or not entry.get("reasonCodes")
        ):
            errors.append(
                "revoked predecessor is not bound to the exact advisory, affected build, "
                "security evidence, publication target, and lifecycle authorization request"
            )
    return errors


def _authenticated_lifecycle_errors(
    ledger: dict[str, Any],
    descriptor: dict[str, Any],
    authorization: dict[str, Any],
    publication_plan: dict[str, Any],
    receipt: dict[str, Any],
    authorization_file_digest: str,
    descriptor_file_digest: str,
    expected_policy_digest: str | None,
    predecessor: Predecessor,
    release_class: Any,
    now: dt.datetime,
    hotfix_scope: dict[str, Any] | None = None,
) -> list[str]:
    """Bind the active lifecycle ledger, descriptor, and verified public receipt."""

    errors = _lifecycle_predecessor_errors(ledger, predecessor, release_class)
    errors.extend(
        validate_schema(
            descriptor, "stable-1.0-support-lifecycle-descriptor-v1.schema.json"
        )
    )
    errors.extend(
        validate_schema(
            authorization,
            "stable-1.0-support-lifecycle-authorization-v1.schema.json",
        )
    )
    errors.extend(
        validate_schema(
            publication_plan,
            "stable-1.0-support-lifecycle-publication-plan-v1.schema.json",
        )
    )
    errors.extend(
        validate_schema(
            receipt,
            "stable-1.0-support-lifecycle-publication-receipt-v1.schema.json",
        )
    )
    from .stable_1_0_lifecycle_core import (
        UPDATE_KEY_IDENTITY_DIGEST,
        canonical_file_digest,
        ledger_digest,
    )

    if ledger.get("ledgerDigest") != ledger_digest(ledger):
        errors.append("lifecycle ledger semantic digest is invalid")
    if ledger.get("policyDigest") != expected_policy_digest:
        errors.append(
            "lifecycle ledger policy digest does not match the exact checked-in support "
            "lifecycle policy"
        )
    descriptor_identity = semantic_digest(
        {key: item for key, item in descriptor.items() if key != "descriptorDigest"}
    )
    if descriptor.get("descriptorDigest") != descriptor_identity:
        errors.append("lifecycle descriptor semantic digest is invalid")
    authorization_digest = canonical_file_digest(authorization)
    if authorization_file_digest != authorization_digest:
        errors.append("lifecycle authorization bytes are not canonical")
    publication_plan_identity = semantic_digest(
        {
            key: item
            for key, item in publication_plan.items()
            if key != "publicationPlanDigest"
        }
    )
    if publication_plan.get("publicationPlanDigest") != publication_plan_identity:
        errors.append("lifecycle publication plan semantic digest is invalid")
    ledger_entries = {
        row.get("buildVersion"): row
        for row in ledger.get("entries", [])
        if isinstance(row, dict)
    }
    descriptor_entries = {
        row.get("buildVersion"): row
        for row in descriptor.get("entries", [])
        if isinstance(row, dict)
    }
    if (
        len(ledger_entries) != len(ledger.get("entries", []))
        or len(descriptor_entries) != len(descriptor.get("entries", []))
        or set(ledger_entries) != set(descriptor_entries)
    ):
        errors.append("lifecycle descriptor omits, duplicates, or invents a ledger build")
    descriptor_fields = (
        "releaseId",
        "buildVersion",
        "tag",
        "sourceCommit",
        "productDigest",
        "publicationReceiptDigest",
        "baselineDigest",
        "publishedAt",
        "lifecycleStatus",
        "statusEffectiveAt",
        "fullSupportUntil",
        "securityFixesUntil",
        "deprecationEffectiveAt",
        "endOfSupportAt",
        "securityRevocationEffectiveAt",
        "replacementBuild",
        "recoveryGuidance",
        "advisoryIds",
        "reasonCodes",
    )
    for build, entry in ledger_entries.items():
        projected = descriptor_entries.get(build, {})
        if any(projected.get(field) != entry.get(field) for field in descriptor_fields):
            errors.append(f"lifecycle descriptor rewrites ledger build {build}")
    authorization_request_digest = semantic_digest(
        {
            "operation": "publish-support-lifecycle",
            "ledgerDigest": ledger.get("ledgerDigest"),
            "descriptorDigest": descriptor.get("descriptorDigest"),
            "descriptorEdition": descriptor.get("descriptorEdition"),
            "publicRequestUri": publication_plan.get("publicRequestUri"),
            "latestMaintenancePointerPublicUri": publication_plan.get(
                "latestMaintenancePointerPublicUri"
            ),
            "latestMaintenancePointerDigest": publication_plan.get(
                "latestMaintenancePointerDigest"
            ),
            "transitionRequestDigest": authorization.get("transitionRequestDigest"),
            "previousLedgerDigest": ledger.get("previousLedgerDigest"),
            "previousDescriptorDigest": descriptor.get("previousDescriptorDigest"),
            "requiredRole": authorization.get("role"),
        }
    )
    expected_authorization = {
        "operation": "publish-support-lifecycle",
        "stableMilestone": STABLE_MILESTONE,
        "targetLedgerDigest": ledger.get("ledgerDigest"),
        "targetDescriptorDigest": descriptor.get("descriptorDigest"),
        "targetDescriptorEdition": descriptor.get("descriptorEdition"),
        "targetPublicRequestUri": publication_plan.get("publicRequestUri"),
        "targetLatestMaintenancePointerPublicUri": publication_plan.get(
            "latestMaintenancePointerPublicUri"
        ),
        "targetLatestMaintenancePointerDigest": publication_plan.get(
            "latestMaintenancePointerDigest"
        ),
        "previousLedgerDigest": ledger.get("previousLedgerDigest"),
        "previousDescriptorDigest": descriptor.get("previousDescriptorDigest"),
        "authorizationRequestDigest": authorization_request_digest,
        "decision": "approved",
    }
    if any(
        authorization.get(key) != value
        for key, value in expected_authorization.items()
    ):
        errors.append(
            "lifecycle authorization does not approve the exact descriptor, ledger, and target"
        )
    expected_plan = {
        "stableMilestone": STABLE_MILESTONE,
        "descriptorEdition": descriptor.get("descriptorEdition"),
        "descriptorDigest": descriptor.get("descriptorDigest"),
        "descriptorSizeBytes": len(
            (json.dumps(descriptor, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
                "utf-8"
            )
        ),
        "ledgerDigest": ledger.get("ledgerDigest"),
        "updateKeyIdentityDigest": descriptor.get("updateKeyIdentityDigest"),
        "updateKeyScope": descriptor.get("updateKeyScope"),
        "updateKeyDocName": descriptor.get("updateKeyDocName"),
        "previousDescriptorEdition": descriptor.get("previousDescriptorEdition"),
        "previousDescriptorDigest": descriptor.get("previousDescriptorDigest"),
        "authorizationDigest": authorization_digest,
        "publicationAuthorized": True,
    }
    if any(
        publication_plan.get(key) != value for key, value in expected_plan.items()
    ):
        errors.append(
            "lifecycle publication plan does not bind the exact approved descriptor and ledger"
        )
    authorization_generated = parse_timestamp(authorization.get("generatedAt"))
    authorization_expires = parse_timestamp(authorization.get("expiresAt"))
    receipt_generated = parse_timestamp(receipt.get("generatedAt"))
    if (
        authorization_generated is None
        or authorization_expires is None
        or receipt_generated is None
        or authorization_expires <= authorization_generated
        or receipt_generated < authorization_generated
        or receipt_generated >= authorization_expires
    ):
        errors.append(
            "lifecycle publication was not verified inside its authorization validity window"
        )
    if (
        descriptor.get("ledgerDigest") != ledger.get("ledgerDigest")
        or descriptor.get("inventoryDigest") != ledger.get("inventoryDigest")
        or receipt.get("ledgerDigest") != ledger.get("ledgerDigest")
        or receipt.get("descriptorDigest") != descriptor.get("descriptorDigest")
        or receipt.get("descriptorEdition") != descriptor.get("descriptorEdition")
        or receipt.get("descriptorBytesDigest") != descriptor_file_digest
        or receipt.get("updateKeyIdentityDigest")
        != descriptor.get("updateKeyIdentityDigest")
        or descriptor.get("updateKeyIdentityDigest") != UPDATE_KEY_IDENTITY_DIGEST
        or descriptor.get("updateKeyScope")
        != f"{UPDATE_KEY_IDENTITY_DIGEST}/support-lifecycle/0"
        or receipt.get("updateKeyScope") != descriptor.get("updateKeyScope")
        or receipt.get("updateKeyDocName") != "support-lifecycle"
        or receipt.get("publicRequestUri")
        != publication_plan.get("publicRequestUri")
        or receipt.get("previousDescriptorEdition")
        != publication_plan.get("previousDescriptorEdition")
        or receipt.get("previousDescriptorDigest")
        != publication_plan.get("previousDescriptorDigest")
        or receipt.get("publicationPlanDigest")
        != publication_plan.get("publicationPlanDigest")
        or receipt.get("authorizationDigest") != authorization_digest
        or receipt.get("operation") not in {"inserted", "verified-existing"}
        or receipt.get("publicationState") != "publication-complete"
        or receipt.get("verificationStatus") != "verified"
        or receipt.get("conflict") is not False
        or authorization.get("redaction", {}).get("status") != "pass"
        or publication_plan.get("redaction", {}).get("status") != "pass"
        or receipt.get("redaction", {}).get("status") != "pass"
    ):
        errors.append(
            "lifecycle public receipt does not verify the exact authorized publication plan, "
            "descriptor, and ledger"
        )
    stale_at = parse_timestamp(descriptor.get("staleAt"))
    if stale_at is None or stale_at <= now:
        errors.append("lifecycle descriptor is stale")
    errors.extend(
        _hotfix_lifecycle_authority_errors(
            ledger,
            descriptor,
            predecessor,
            release_class,
            hotfix_scope,
        )
    )
    return errors


def _public_lifecycle_observation_errors(
    observation: dict[str, Any],
    ledger: dict[str, Any],
    descriptor: dict[str, Any],
    authorization: dict[str, Any],
    publication_plan: dict[str, Any],
    publication_receipt: dict[str, Any],
    authorization_file_digest: str,
    descriptor_file_digest: str,
    now: dt.datetime,
    maximum_age_minutes: int,
) -> list[str]:
    """Bind one fresh read-only provider observation to the exact authority chain."""

    errors = validate_schema(
        observation,
        "stable-1.0-support-lifecycle-publication-receipt-v1.schema.json",
    )
    observed_at = parse_timestamp(observation.get("generatedAt"))
    published_at = parse_timestamp(publication_receipt.get("generatedAt"))
    if (
        observed_at is None
        or published_at is None
        or observed_at < published_at
        or observed_at > now
        or now - observed_at > dt.timedelta(minutes=maximum_age_minutes)
    ):
        errors.append(
            "lifecycle public observation is stale, future-dated, or predates publication"
        )
    expected = {
        "stableMilestone": STABLE_MILESTONE,
        "descriptorEdition": descriptor.get("descriptorEdition"),
        "descriptorDigest": descriptor.get("descriptorDigest"),
        "descriptorBytesDigest": descriptor_file_digest,
        "ledgerDigest": ledger.get("ledgerDigest"),
        "previousDescriptorEdition": descriptor.get("previousDescriptorEdition"),
        "previousDescriptorDigest": descriptor.get("previousDescriptorDigest"),
        "updateKeyIdentityDigest": descriptor.get("updateKeyIdentityDigest"),
        "updateKeyScope": descriptor.get("updateKeyScope"),
        "updateKeyDocName": descriptor.get("updateKeyDocName"),
        "publicRequestUri": publication_plan.get("publicRequestUri"),
        "publicationPlanDigest": publication_plan.get("publicationPlanDigest"),
        "authorizationDigest": authorization_file_digest,
        "operation": "verified-existing",
        "publicationState": "publication-complete",
        "verificationStatus": "verified",
        "conflict": False,
        "redaction": _PASS_REDACTION,
    }
    if any(observation.get(name) != value for name, value in expected.items()):
        errors.append(
            "lifecycle public observation does not re-fetch the exact authorized edition, "
            "descriptor bytes, ledger, plan, and update-key scope"
        )
    if authorization.get("decision") != "approved":
        errors.append("lifecycle public observation is not bound to approved authority")
    return errors


def _pending_lifecycle_transition(
    context: RunContext,
    predecessor: Predecessor,
    candidate: Candidate,
    predecessor_status: str,
    backport_release_train_digest: str,
) -> dict[str, Any]:
    """Describe publication-contingent lifecycle changes without activating them."""

    proposed_predecessor_status = (
        "supported-maintenance"
        if predecessor_status == "current-stable"
        else predecessor_status
    )
    value = {
        "schemaVersion": 1,
        "kind": "stable-1.0-support-lifecycle-pending-maintenance-transition",
        "generatedAt": candidate.input_value.get("generatedAt"),
        "stableMilestone": STABLE_MILESTONE,
        "status": "pending-publication-verification",
        "candidate": {
            "releaseId": context.manifest.release.release_id,
            "buildVersion": context.manifest.release.version,
            "tag": f"v{context.manifest.release.version}",
            "sourceCommit": candidate.source.get("commit"),
            "productDigest": candidate.product_digest,
            "candidateIdentityDigest": candidate.identity_digest,
            "proposedStatus": "current-stable",
        },
        "predecessor": {
            "releaseId": predecessor.release_id,
            "buildVersion": predecessor.build_version,
            "productDigest": predecessor.product_digest,
            "proposedStatus": proposed_predecessor_status,
        },
        "activationCondition": "maintenance-publication-receipt-verified-and-lifecycle-publication-authorized",
        "backportReleaseTrainDigest": backport_release_train_digest,
        "activeLedgerChanged": False,
        "redaction": dict(_PASS_REDACTION),
    }
    value["proposalDigest"] = semantic_digest(value)
    return value


def _release_train_evidence_freshness_errors(
    evidence_results: list[Any],
    *,
    now: dt.datetime,
    maximum_age: dt.timedelta,
) -> list[str]:
    errors: list[str] = []
    for evidence_result in evidence_results:
        evidence_generated_at = (
            parse_timestamp(evidence_result.get("generatedAt"))
            if isinstance(evidence_result, dict)
            else None
        )
        evidence_expires_at = (
            parse_timestamp(evidence_result.get("expiresAt"))
            if isinstance(evidence_result, dict)
            else None
        )
        evidence_deadline_at = (
            parse_timestamp(evidence_result.get("freshnessDeadlineAt"))
            if isinstance(evidence_result, dict)
            else None
        )
        if (
            evidence_generated_at is None
            or evidence_expires_at is None
            or evidence_deadline_at is None
            or evidence_generated_at > now
            or evidence_expires_at <= evidence_generated_at
            or evidence_deadline_at
            != min(evidence_expires_at, evidence_generated_at + maximum_age)
            or evidence_deadline_at < now
            or evidence_result.get("generatedAt")
            != _timestamp(evidence_generated_at.isoformat())
            or evidence_result.get("expiresAt")
            != _timestamp(evidence_expires_at.isoformat())
            or evidence_result.get("freshnessDeadlineAt")
            != _timestamp(evidence_deadline_at.isoformat())
        ):
            errors.append(
                "release-train candidate evidence is stale, expired, or "
                "has an inconsistent freshness deadline"
            )
            break
    return errors


def _authenticate_backport_release_train(
    context: RunContext,
    predecessor: Predecessor,
    candidate: Candidate,
    state: ValidationState,
) -> tuple[LoadedJson, bool]:
    """Authenticate the exact authorized train handoff for this maintenance candidate."""

    loaded = load_json_input(context, "stableBackportReleaseTrainValidation")
    authorization_loaded = load_json_input(
        context, "stableBackportReleaseTrainAuthorization"
    )
    assert loaded
    assert authorization_loaded
    value = loaded.value
    full_authorization = authorization_loaded.value
    errors = validate_schema(
        value, "stable-1.0-release-train-validation-v1.schema.json"
    )
    errors.extend(
        validate_schema(
            full_authorization,
            "stable-1.0-release-train-authorization-v1.schema.json",
        )
    )
    release = value.get("release")
    release = release if isinstance(release, dict) else {}
    expected_lane = (
        "routine-maintenance"
        if context.manifest.policies.get("releaseClass") == "maintenance"
        else "security-hotfix"
    )
    expected_validation_digest = semantic_digest(
        {key: item for key, item in value.items() if key != "validationDigest"}
    )
    train_authorization = value.get("authorization")
    train_authorization = (
        train_authorization if isinstance(train_authorization, dict) else {}
    )
    expected_role = (
        "stable-maintenance-train-manager"
        if expected_lane == "routine-maintenance"
        else "stable-security-train-manager"
    )
    required_fix_ids = value.get("requiredFixIds")
    included_fix_ids = value.get("includedFixIds")
    public_fixes = value.get("publicFixes")
    deferred_fix_ids = value.get("deferredFixIds")
    required_fix_ids = required_fix_ids if isinstance(required_fix_ids, list) else []
    included_fix_ids = included_fix_ids if isinstance(included_fix_ids, list) else []
    public_fixes = public_fixes if isinstance(public_fixes, list) else []
    deferred_fix_ids = (
        deferred_fix_ids if isinstance(deferred_fix_ids, list) else []
    )
    public_fix_ids = [
        row.get("fixId") for row in public_fixes if isinstance(row, dict)
    ]
    evidence_results = value.get("evidenceResults")
    evidence_results = (
        evidence_results if isinstance(evidence_results, list) else []
    )
    evidence_subjects = [
        (str(row.get("fixId")), str(row.get("evidenceId")))
        for row in evidence_results
        if isinstance(row, dict)
    ]
    if (
        value.get("kind") != "stable-1.0-release-train-validation"
        or value.get("mode") != "validate-authorization"
        or release.get("releaseId") != context.manifest.release.release_id
        or release.get("buildVersion") != context.manifest.release.version
        or release.get("releaseClass")
        != context.manifest.policies.get("releaseClass")
        or release.get("tag") != f"v{context.manifest.release.version}"
        or value.get("predecessorCommit") != predecessor.source_commit
        or value.get("candidateCommit") != candidate.source.get("commit")
        or value.get("hotfixFollowUpClosureDigest")
        != predecessor.follow_up_closure_digest
        or value.get("decision") != "go"
        or value.get("authorizationRequired") is not True
        or value.get("blockers") != []
        or value.get("omittedFixIds") != []
        or value.get("unaccountedCommitIds") != []
        or not required_fix_ids
        or required_fix_ids != sorted(required_fix_ids)
        or required_fix_ids != included_fix_ids
        or required_fix_ids != public_fix_ids
        or deferred_fix_ids != sorted(set(deferred_fix_ids))
        or len(public_fix_ids) != len(set(public_fix_ids))
        or not evidence_results
        or len(evidence_subjects) != len(evidence_results)
        or evidence_subjects != sorted(evidence_subjects)
        or len(evidence_subjects) != len(set(evidence_subjects))
        or {subject[0] for subject in evidence_subjects}
        != set(included_fix_ids)
        or any(
            not isinstance(row, dict)
            or row.get("status") != "pass"
            or row.get("candidateBound") is not True
            or row.get("predecessorBound") is not True
            or row.get("fresh") is not True
            for row in evidence_results
        )
        or value.get("validationDigest") != expected_validation_digest
        or train_authorization.get("status") != "valid"
        or train_authorization.get("role") != expected_role
        or not isinstance(train_authorization.get("authorizationDigest"), str)
        or value.get("redaction") != _PASS_REDACTION
    ):
        errors.append(
            "release-train validation does not authorize the exact predecessor, "
            "candidate, lane, and fully accounted fix set"
        )
    policy_path = (
        context.workspace_root
        / "tools/release-certification/stable-1.0-backport-release-train-policy.json"
    )
    authorization_policy: dict[str, Any] = {}
    try:
        if value.get("policyDigest") != file_digest(policy_path):
            errors.append(
                "release-train validation does not bind the exact checked-in train policy"
            )
        train_policy = read_json(policy_path)
        evidence_policy = (
            train_policy.get("evidencePolicy", {})
            if isinstance(train_policy, dict)
            else {}
        )
        classification_policy = (
            train_policy.get("classificationEligibility", {})
            if isinstance(train_policy, dict)
            else {}
        )
        authorization_policy = (
            train_policy.get("authorization", {})
            if isinstance(train_policy, dict)
            else {}
        )
        maximum_age_hours = (
            evidence_policy.get("routineMaximumAgeDays", 14) * 24
            if expected_lane == "routine-maintenance"
            else evidence_policy.get("securityHotfixMaximumAgeHours", 24)
        )
        for public_fix in public_fixes:
            if not isinstance(public_fix, dict):
                errors.append("release-train public fix projection is malformed")
                continue
            expected_fix_projection = semantic_digest(
                {
                    "fixId": public_fix.get("fixId"),
                    "classification": public_fix.get("classification"),
                    "publicSummary": public_fix.get("publicSummary"),
                }
            )
            if public_fix.get("publicProjectionDigest") != expected_fix_projection:
                errors.append(
                    "release-train public fix projection digest is inconsistent"
                )
            classification = public_fix.get("classification")
            eligibility = (
                classification_policy.get(classification, {})
                if isinstance(classification_policy, dict)
                else {}
            )
            if expected_lane not in eligibility.get("allowedLanes", []):
                errors.append(
                    "release-train public fix classification is ineligible for its lane"
                )
            security_fields = (
                public_fix.get("incidentOpaqueId"),
                public_fix.get("advisoryOpaqueId"),
                public_fix.get("publicSecuritySummary"),
                public_fix.get("securityPublicProjectionDigest"),
                public_fix.get("disclosureState"),
            )
            if classification == "security-fix":
                expected_security_projection = semantic_digest(
                    {
                        "fixId": public_fix.get("fixId"),
                        "incidentOpaqueId": public_fix.get("incidentOpaqueId"),
                        "advisoryOpaqueId": public_fix.get("advisoryOpaqueId"),
                        "severity": public_fix.get("severity"),
                        "disclosureState": public_fix.get("disclosureState"),
                        "publicSafeSummary": public_fix.get(
                            "publicSecuritySummary"
                        ),
                    }
                )
                if (
                    not public_fix.get("incidentOpaqueId")
                    or public_fix.get("securityPublicProjectionDigest")
                    != expected_security_projection
                ):
                    errors.append(
                        "release-train public security projection is incomplete or inconsistent"
                    )
                if (
                    public_fix.get("severity") == "critical"
                    and expected_lane != "security-hotfix"
                ):
                    errors.append(
                        "critical release-train security fix is assigned to the wrong lane"
                    )
                if (
                    expected_lane == "security-hotfix"
                    and public_fix.get("severity") != "critical"
                ):
                    errors.append(
                        "noncritical release-train security fix uses the security-hotfix lane"
                    )
            elif any(field is not None for field in security_fields):
                errors.append(
                    "non-security release-train fix carries a security projection"
                )
        if expected_lane == "security-hotfix" and not any(
            isinstance(row, dict)
            and row.get("classification") == "security-fix"
            and row.get("severity") == "critical"
            for row in public_fixes
        ):
            errors.append(
                "security-hotfix train lacks a critical incident-bound security fix"
            )
    except (OSError, ValueError):
        errors.append("checked-in release-train policy is missing or malformed")
        maximum_age_hours = 0
    generated_at = parse_timestamp(value.get("generatedAt"))
    authorization_expires = parse_timestamp(train_authorization.get("expiresAt"))
    now = _now()
    errors.extend(
        _release_train_evidence_freshness_errors(
            evidence_results,
            now=now,
            maximum_age=dt.timedelta(hours=maximum_age_hours),
        )
    )
    if (
        generated_at is None
        or generated_at > now
        or generated_at < now - dt.timedelta(hours=maximum_age_hours)
    ):
        errors.append("release-train validation is stale or future-dated")
    if authorization_expires is None or authorization_expires <= now:
        errors.append("release-train authorization is expired or malformed")
    if not _canonical_json_input(loaded.path, value):
        errors.append("release-train validation JSON is not canonical deterministic JSON")
    if not _canonical_json_input(authorization_loaded.path, full_authorization):
        errors.append(
            "release-train authorization JSON is not canonical deterministic JSON"
        )
    prepare_validation = copy.deepcopy(value)
    prepare_validation["mode"] = "prepare-candidate"
    prepare_validation["authorization"] = None
    prepare_validation.pop("validationDigest", None)
    prepare_validation_digest = semantic_digest(prepare_validation)
    expected_scopes = authorization_policy.get("candidateHandoffScopes")
    maximum_validity_hours = authorization_policy.get("maximumValidityHours")
    expected_security_ids = sorted(
        {
            str(row["incidentOpaqueId"])
            for row in public_fixes
            if isinstance(row, dict)
            and isinstance(row.get("incidentOpaqueId"), str)
        }
    )
    expected_candidate_security_ids = sorted(
        {
            str(row.get("advisoryOpaqueId") or row["incidentOpaqueId"])
            for row in public_fixes
            if isinstance(row, dict)
            and isinstance(row.get("incidentOpaqueId"), str)
        }
    )
    if expected_lane == "security-hotfix":
        candidate_scope = candidate.input_value.get("changeScope")
        candidate_scope = (
            candidate_scope if isinstance(candidate_scope, dict) else {}
        )
        security_fix_ids = sorted(
            str(row["fixId"])
            for row in public_fixes
            if isinstance(row, dict)
            and row.get("classification") == "security-fix"
            and isinstance(row.get("fixId"), str)
        )
        incident_scope_rows = [
            row
            for row in evidence_results
            if isinstance(row, dict)
            and row.get("evidenceId")
            == "stable-backport.security-incident-scope"
        ]
        if (
            expected_candidate_security_ids
            != [candidate_scope.get("incidentId")]
            or candidate_scope.get("severity") != "critical"
            or sorted(
                str(row.get("fixId")) for row in incident_scope_rows
            )
            != security_fix_ids
            or any(
                row.get("evidenceDigest")
                != candidate_scope.get("hotfixPolicyAuthorizationDigest")
                for row in incident_scope_rows
            )
        ):
            errors.append(
                "security-hotfix train incident and policy authorization do not "
                "match the maintenance candidate change scope"
            )
    issued_at = parse_timestamp(full_authorization.get("issuedAt"))
    expires_at = parse_timestamp(full_authorization.get("expiresAt"))
    expected_authorization = {
        "stableMilestone": STABLE_MILESTONE,
        "trainId": value.get("trainId"),
        "release": value.get("release"),
        "repositoryIdentity": "github.com/crypta-network/cryptad",
        "workflowIdentity": (
            "github.com/crypta-network/cryptad/.github/workflows/"
            "stable-1.0-backport-release-train.yml@"
            f"{candidate.source.get('commit')}"
        ),
        "policyDigest": value.get("policyDigest"),
        "queueDigest": value.get("queueDigest"),
        "planDigest": value.get("planDigest"),
        "validationDigest": prepare_validation_digest,
        "predecessorCommit": value.get("predecessorCommit"),
        "candidateCommit": value.get("candidateCommit"),
        "acceptedFixes": public_fixes,
        "securityOpaqueIds": expected_security_ids,
        "allowedOperation": "candidate-handoff",
        "role": expected_role,
        "scope": expected_scopes,
        "decision": "go",
        "redaction": _PASS_REDACTION,
    }
    if (
        not isinstance(expected_scopes, list)
        or type(maximum_validity_hours) is not int
        or maximum_validity_hours < 1
        or any(
            full_authorization.get(field) != expected
            for field, expected in expected_authorization.items()
        )
        or full_authorization.get("authorizationDigest")
        != semantic_digest(
            {
                key: item
                for key, item in full_authorization.items()
                if key != "authorizationDigest"
            }
        )
        or train_authorization
        != {
            "authorizationDigest": full_authorization.get(
                "authorizationDigest"
            ),
            "status": "valid",
            "expiresAt": full_authorization.get("expiresAt"),
            "role": full_authorization.get("role"),
        }
        or issued_at is None
        or expires_at is None
        or issued_at > now
        or expires_at <= now
        or expires_at <= issued_at
        or expires_at - issued_at
        > dt.timedelta(hours=maximum_validity_hours)
    ):
        errors.append(
            "full release-train authorization does not bind the exact protected "
            "candidate handoff"
        )
    if _maintenance_public_redaction_findings(value):
        errors.append("release-train validation contains unsafe public material")
    if _maintenance_public_redaction_findings(full_authorization):
        errors.append("release-train authorization contains unsafe public material")
    add_blockers(
        state,
        "stable-maintenance.backport-release-train",
        errors,
        "Regenerate and authorize the exact candidate-bound Stable backport release train.",
    )
    return loaded, not errors


def _lineage(
    context: RunContext,
    ga: GaRoot,
    predecessor: Predecessor,
    candidate: Candidate,
    state: ValidationState,
) -> dict[str, Any]:
    ga_predecessor = predecessor.baseline.get("schemaVersion") == 1
    latest_pointer_digest = (
        ga.root_identity_digest
        if ga_predecessor
        else predecessor.latest_pointer_digest
    )
    release_class = (
        "stable-ga"
        if ga_predecessor
        else predecessor.baseline.get("release", {}).get("releaseClass")
    )
    value = {
        "schemaVersion": 1,
        "kind": "stable-1.0-maintenance-lineage",
        "generatedAt": candidate.input_value.get("generatedAt"),
        "stableMilestone": STABLE_MILESTONE,
        "gaRoot": {
            "releaseId": ga.release_id,
            "buildVersion": ga.build_version,
            "tag": ga.tag,
            "sourceCommit": ga.source_commit,
            "productDigest": ga.product_digest,
            "maintenanceBaselineDigest": ga.baseline_digest,
            "publicationReceiptDigest": ga.receipt_digest,
            "publicationState": "publication-complete",
        },
        "predecessor": {
            "releaseId": predecessor.release_id,
            "buildVersion": predecessor.build_version,
            "tag": predecessor.tag,
            "sourceCommit": predecessor.source_commit,
            "productDigest": predecessor.product_digest,
            "releaseClass": release_class,
            "publicationReceiptDigest": predecessor.receipt_digest,
            "successorBaselineDigest": (
                None
                if predecessor.baseline.get("schemaVersion") == 1
                else predecessor.baseline_digest
            ),
            "hotfixFollowUpClosureDigest": predecessor.follow_up_closure_digest,
            "publicationState": "publication-complete",
        },
        "candidate": {
            "releaseId": context.manifest.release.release_id,
            "buildVersion": context.manifest.release.version,
            "tag": f"v{context.manifest.release.version}",
            "sourceBranch": candidate.source.get("branch"),
            "sourceRef": candidate.source.get("ref"),
            "sourceCommit": candidate.source.get("commit"),
            "releaseClass": context.manifest.policies.get("releaseClass"),
        },
        "chainDepth": predecessor.chain_depth + 1,
        "previousLineageDigest": predecessor.previous_lineage_digest,
        "latestPublishedPointerDigest": latest_pointer_digest,
        "noGap": True,
        "noFork": ga_predecessor or predecessor.latest_pointer_digest is not None,
        "status": "pass",
        "redaction": dict(_PASS_REDACTION),
    }
    _schema_gate(
        state,
        "stable-maintenance.predecessor-lineage",
        value,
        LINEAGE_SCHEMA,
        "Regenerate lineage from the authenticated GA root and latest predecessor.",
    )
    return value


def _known_limitations(context: RunContext, candidate: Candidate) -> dict[str, Any]:
    value = candidate.input_value.get("limitations")
    value = value if isinstance(value, dict) else {}
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-maintenance-known-limitations-delta",
        "generatedAt": candidate.input_value.get("generatedAt"),
        "releaseId": context.manifest.release.release_id,
        "buildVersion": context.manifest.release.version,
        "releaseClass": context.manifest.policies.get("releaseClass"),
        "knownLimitationsDigest": value.get("knownLimitationsDigest"),
        "deltaDigest": value.get("deltaDigest"),
        "added": sorted(value.get("addedIds", [])),
        "resolved": sorted(value.get("resolvedIds", [])),
        "unchanged": sorted(value.get("unchangedIds", [])),
        "status": "reviewed",
        "redaction": dict(_PASS_REDACTION),
    }


def _provenance(
    context: RunContext,
    policy_digest: str,
    ga: GaRoot,
    predecessor: Predecessor,
    candidate: Candidate,
    lineage_digest: str,
    comparison_digest: str,
    evidence_digest: str,
    core_info_digest: str,
    pending_lifecycle_transition_digest: str,
    backport_release_train_digest: str,
) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-maintenance-provenance",
        "generatedAt": candidate.input_value.get("generatedAt"),
        "releaseId": context.manifest.release.release_id,
        "buildVersion": context.manifest.release.version,
        "releaseClass": context.manifest.policies.get("releaseClass"),
        "source": candidate.source,
        "policyDigest": policy_digest,
        "gaRootIdentityDigest": ga.root_identity_digest,
        "gaBaselineDigest": ga.baseline_digest,
        "gaPublicationReceiptDigest": ga.receipt_digest,
        "predecessorBaselineDigest": predecessor.baseline_digest,
        "predecessorPublicationReceiptDigest": predecessor.receipt_digest,
        "predecessorProductDigest": predecessor.product_digest,
        "candidateInputDigest": candidate.input_digest,
        "candidateFreezeDigest": candidate.freeze_digest,
        "candidateIdentityDigest": candidate.identity_digest,
        "candidateProductDigest": candidate.product_digest,
        "candidateChecksumsDigest": candidate.checksums_digest,
        "candidateProvenanceDigest": candidate.provenance_digest,
        "lineageDigest": lineage_digest,
        "comparisonDigest": comparison_digest,
        "evidenceDigest": evidence_digest,
        "coreInfoDigest": core_info_digest,
        "pendingLifecycleTransitionDigest": pending_lifecycle_transition_digest,
        "backportReleaseTrainDigest": backport_release_train_digest,
        "assets": [
            {
                "name": name,
                "sizeBytes": path.stat().st_size,
                "digest": file_digest(path),
            }
            for name, path in sorted(candidate.asset_paths.items())
        ],
        "builtOnce": True,
        "rebuildPerformedAfterFreeze": False,
        "redaction": dict(_PASS_REDACTION),
    }


def _authorization_expected(
    context: RunContext,
    ga: GaRoot,
    predecessor: Predecessor,
    candidate: Candidate,
    comparison_digest: str,
    evidence_digest: str,
    core_info_digest: str,
    checksums_digest: str,
    provenance_digest: str,
    release_notes_digest: str,
    targets_digest: str,
    follow_up_digest: str | None,
    backport_release_train_digest: str,
    dependency_vulnerability_governance_active: bool = False,
) -> dict[str, Any]:
    scope = candidate.input_value.get("changeScope")
    scope = scope if isinstance(scope, dict) else {}
    expected = {
        "releaseId": context.manifest.release.release_id,
        "buildVersion": context.manifest.release.version,
        "releaseClass": context.manifest.policies.get("releaseClass"),
        "candidateIdentityDigest": candidate.identity_digest,
        "gaBaselineDigest": ga.baseline_digest,
        "predecessorIdentityDigest": semantic_digest(
            {
                "releaseId": predecessor.release_id,
                "buildVersion": predecessor.build_version,
                "sourceCommit": predecessor.source_commit,
                "productDigest": predecessor.product_digest,
                "baselineDigest": predecessor.baseline_digest,
            }
        ),
        "predecessorProductDigest": predecessor.product_digest,
        "predecessorPublicationReceiptDigest": predecessor.receipt_digest,
        "candidateFreezeDigest": candidate.freeze_digest,
        "productDigest": candidate.product_digest,
        "checksumsDigest": checksums_digest,
        "provenanceDigest": provenance_digest,
        "comparisonDigest": comparison_digest,
        "evidenceDigest": evidence_digest,
        "coreInfoDigest": core_info_digest,
        "stableCatalogDigest": candidate.input_value.get("stableCatalog", {}).get("digest"),
        "knownLimitationsDeltaDigest": candidate.input_value.get("limitations", {}).get("deltaDigest"),
        "releaseNotesDigest": release_notes_digest,
        "publicationTargetsDigest": targets_digest,
        "dependencyVulnerabilityGovernanceActive": (
            dependency_vulnerability_governance_active
        ),
        "backportReleaseTrainDigest": backport_release_train_digest,
        "allowedPublicationScopes": list(AUTHORIZATION_SCOPE),
        "acceptedWarningIds": sorted(
            row.get("warningId")
            for row in candidate.input_value.get("operationalWarnings", [])
            if isinstance(row, dict)
        ),
        "role": (
            "stable-security-release-manager"
            if context.manifest.policies.get("releaseClass") == "security-hotfix"
            else "stable-maintenance-release-manager"
        ),
        "hotfixIncidentId": scope.get("incidentId"),
        "hotfixPolicyAuthorizationDigest": scope.get(
            "hotfixPolicyAuthorizationDigest"
        ),
        "hotfixShortenedEvidenceIds": sorted(
            scope.get("shortenedEvidenceIds", [])
        ),
        "hotfixFollowUpObligationDigest": follow_up_digest,
    }
    catalog_authority = candidate.input_value.get("catalogAuthority")
    if isinstance(catalog_authority, dict):
        expected.update(
            {
                "catalogAuthoritySummaryDigest": catalog_authority.get(
                    "summaryDigest"
                ),
                "catalogAuthorityEvidenceDigest": catalog_authority.get(
                    "protectedEvidenceDigest"
                ),
                "catalogAuthorityBindingDigest": semantic_digest(
                    catalog_authority
                ),
            }
        )
    return expected


def _required_authorization_decision(expected: dict[str, Any]) -> str:
    return "go-with-waivers" if expected.get("acceptedWarningIds") else "go"


def _authorization(
    context: RunContext,
    expected: dict[str, Any],
    policy: dict[str, Any],
    state: ValidationState,
    prepare: bool,
) -> tuple[dict[str, Any], str, bool]:
    request_identity = {
        "schemaVersion": 1,
        "kind": "stable-1.0-maintenance-authorization-request",
        **expected,
        "decisionRequired": _required_authorization_decision(expected),
        "redaction": dict(_PASS_REDACTION),
    }
    if prepare:
        summary = {
            **request_identity,
            "status": "missing",
            "authorizationRequestDigest": semantic_digest(request_identity),
        }
        return summary, semantic_digest(summary), False
    loaded = load_json_input(
        context, "stableMaintenanceAuthorization", public_authorization=True
    )
    assert loaded
    value = loaded.value
    errors = validate_schema(value, AUTHORIZATION_SCHEMA)
    if state.blockers:
        errors.append("authorization cannot approve a candidate with an open blocker")
    for key, expected_value in expected.items():
        if value.get(key) != expected_value:
            errors.append(f"authorization field {key} does not bind the prepared candidate")
    scopes = value.get("allowedPublicationScopes")
    if scopes != list(AUTHORIZATION_SCOPE) or "*" in (scopes or []):
        errors.append("authorization scopes are incomplete, reordered, or wildcarded")
    now = _now()
    authorized = parse_timestamp(value.get("authorizedAt"))
    expires = parse_timestamp(value.get("expiresAt"))
    if authorized is None or expires is None or authorized > now or expires <= now:
        errors.append("authorization time window is not currently valid")
    allowed_decisions = policy.get("authorization", {}).get("allowedDecisions", [])
    expected_decision = _required_authorization_decision(expected)
    if (
        value.get("decision") not in allowed_decisions
        or value.get("decision") != expected_decision
    ):
        errors.append("authorization decision does not allow publication")
    if not _canonical_json_input(loaded.path, value):
        errors.append("authorization JSON bytes are not canonical deterministic JSON")
    add_blockers(
        state,
        "stable-maintenance.authorization",
        errors,
        "Obtain a current closed-scope authorization for the exact prepared identity.",
    )
    return value, loaded.digest, not errors


def _close_authorization_errors(
    authorization: Any,
    obligation: Any,
    published_follow_up: dict[str, Any],
) -> list[str]:
    """Authenticate the exact authorization for the originally obligated hotfix."""

    errors = validate_schema(authorization.value, AUTHORIZATION_SCHEMA)
    if (
        authorization.value.get("releaseId")
        != obligation.value.get("releaseId")
        or authorization.value.get("buildVersion")
        != obligation.value.get("buildVersion")
        or authorization.value.get("releaseClass") != "security-hotfix"
        or authorization.value.get("candidateIdentityDigest")
        != obligation.value.get("candidateIdentityDigest")
        or authorization.value.get("candidateFreezeDigest")
        != obligation.value.get("candidateFreezeDigest")
        or authorization.value.get("productDigest")
        != obligation.value.get("productDigest")
        or authorization.value.get("role") != "stable-security-release-manager"
        or authorization.value.get("status") != "approved"
        or authorization.value.get("decision") not in {"go", "go-with-waivers"}
        or authorization.digest != published_follow_up.get("authorizationDigest")
    ):
        errors.append(
            "hotfix follow-up authorization does not bind the original published authorization"
        )
    return errors


def _concurrent_follow_up_errors(
    predecessor: Predecessor, follow_up: dict[str, Any] | None
) -> list[str]:
    """Reject a second open obligation that the v2 baseline cannot represent safely."""

    outstanding = predecessor.outstanding_follow_up
    if (
        isinstance(outstanding, dict)
        and outstanding.get("status") in {"open", "overdue"}
        and follow_up is not None
    ):
        return [
            "a superseding expedited hotfix cannot create a second concurrent follow-up obligation"
        ]
    return []


def _core_plan(
    context: RunContext,
    candidate: Candidate,
    descriptor: dict[str, Any],
    core_info_path: Path,
    targets: dict[str, Any],
    targets_digest: str,
    authorization_digest: str,
    state: ValidationState,
) -> dict[str, Any]:
    value = {
        "schemaVersion": 1,
        "kind": "cryptad-core-update-publication-plan",
        "generatedAt": candidate.input_value.get("generatedAt"),
        "releaseId": context.manifest.release.release_id,
        "buildVersion": context.manifest.release.version,
        "releaseClass": context.manifest.policies.get("releaseClass"),
        "candidateIdentityDigest": candidate.identity_digest,
        "descriptorDigest": file_digest(core_info_path),
        "descriptorSizeBytes": core_info_path.stat().st_size,
        "packageMapDigest": semantic_digest(descriptor.get("packages")),
        "edition": targets["coreUpdateEdition"],
        "publicFetchUri": targets["coreUpdatePublicUri"],
        "protectedInsertInputName": "CRYPTAD_CORE_UPDATE_PUBLICATION_INPUT",
        "authorizationDigest": authorization_digest,
        "publicationTargetDigest": targets_digest,
        "preInsertionConflictStatus": "clear",
        "sideEffectsPerformed": False,
        "redaction": dict(_PASS_REDACTION),
    }
    _schema_gate(
        state,
        "stable-maintenance.core-update-descriptor",
        value,
        CORE_PLAN_SCHEMA,
        "Regenerate the protected CoreUpdater insertion plan.",
    )
    return value


def _public_assets(
    candidate: Candidate,
    out: Path,
    artifact_base: str,
    authorization_path: Path,
) -> list[dict[str, Any]]:
    roles: dict[str, str] = {
        candidate.product_path.name: "product",
        candidate.input_value.get("stableCatalog", {}).get("fileName"): "stable-catalog",
        candidate.input_value.get("stableCatalog", {}).get("signatureFileName"): "stable-catalog-signature",
        RELEASE_NOTES_FILE: "release-notes",
        KNOWN_LIMITATIONS_FILE: "known-limitations",
        CHECKSUMS_FILE: "checksums",
        PROVENANCE_FILE: "provenance",
        AUTHORIZATION_FILE: "authorization",
        CORE_INFO_FILE: "core-info",
        LIFECYCLE_PENDING_TRANSITION_FILE: "pending-lifecycle-transition",
    }
    for package in candidate.assets:
        roles[str(package.get("fileName"))] = "package"
    paths = _public_checksum_payload_paths(candidate, out)
    manifest_paths = {
        CHECKSUMS_FILE: out / CHECKSUMS_FILE,
        AUTHORIZATION_FILE: authorization_path,
    }
    duplicates = sorted(paths.keys() & manifest_paths.keys())
    if duplicates:
        raise ValueError(f"public asset basename is ambiguous: {duplicates[0]}")
    paths.update(manifest_paths)
    return [
        {
            "role": roles[name],
            "fileName": name,
            "digest": file_digest(path),
            "sizeBytes": path.stat().st_size,
            "publicUri": _public_child(artifact_base, name),
        }
        for name, path in sorted(paths.items())
    ]


def _publication_plan(
    context: RunContext,
    candidate: Candidate,
    out: Path,
    targets: dict[str, Any],
    targets_digest: str,
    authorization_path: Path,
    authorization_digest: str,
    backport_release_train_digest: str,
    authorized: bool,
    state: ValidationState,
    supply_chain_summary: Any | None,
    dependency_vulnerability_governance_active: bool,
) -> dict[str, Any]:
    catalog = candidate.input_value.get("stableCatalog", {})
    value = {
        "schemaVersion": 1,
        "kind": "stable-1.0-maintenance-publication-plan",
        "generatedAt": candidate.input_value.get("generatedAt"),
        "releaseId": context.manifest.release.release_id,
        "buildVersion": context.manifest.release.version,
        "releaseClass": context.manifest.policies.get("releaseClass"),
        "sourceBranch": candidate.source.get("branch"),
        "sourceCommit": candidate.source.get("commit"),
        "expectedTag": f"v{context.manifest.release.version}",
        "githubReleasePageUri": targets["githubReleasePageUri"],
        "artifactBaseUri": targets["artifactBaseUri"],
        "deploymentServicePublicUri": targets["deploymentServicePublicUri"],
        "latestPointerPublicUri": targets["latestPointerPublicUri"],
        "candidateIdentityDigest": candidate.identity_digest,
        "productDigest": candidate.product_digest,
        "checksumsDigest": file_digest(out / CHECKSUMS_FILE),
        "provenanceDigest": file_digest(out / PROVENANCE_FILE),
        "authorizationDigest": authorization_digest,
        "backportReleaseTrainDigest": backport_release_train_digest,
        "releaseNotesDigest": file_digest(out / RELEASE_NOTES_FILE),
        "coreInfoDigest": file_digest(out / CORE_INFO_FILE),
        "stableCatalogDigest": catalog.get("digest"),
        "knownLimitationsDeltaDigest": candidate.input_value.get("limitations", {}).get("deltaDigest"),
        "publicationTargetsDigest": targets_digest,
        "dependencyVulnerabilityGovernanceActive": (
            dependency_vulnerability_governance_active
        ),
        "assets": _public_assets(
            candidate, out, targets["artifactBaseUri"], authorization_path
        ),
        "stableCatalogTarget": {
            "catalogId": catalog.get("catalogId"),
            "channel": catalog.get("channel"),
            "revision": catalog.get("revision"),
            "edition": catalog.get("edition"),
            "digest": catalog.get("digest"),
            "signatureDigest": catalog.get("signatureDigest"),
            "publicUri": targets["catalogPrimaryUri"],
            "signaturePublicUri": _catalog_signature_uri(
                targets["catalogPrimaryUri"], catalog.get("signatureFileName")
            ),
            "mirrorUris": targets["catalogMirrorUris"],
            "rollbackUri": targets["catalogRollbackUri"],
            "mirrorSetDigest": semantic_digest(targets["catalogMirrorUris"]),
            "rollbackStateDigest": semantic_digest(targets["catalogRollbackUri"]),
        },
        "coreUpdateTarget": {
            "edition": targets["coreUpdateEdition"],
            "descriptorDigest": file_digest(out / CORE_INFO_FILE),
            "publicUri": targets["coreUpdatePublicUri"],
            "protectedInsertInputName": "CRYPTAD_CORE_UPDATE_PUBLICATION_INPUT",
        },
        "sideEffectsPerformed": False,
        "publicationState": "publication-authorized" if authorized and not state.blockers else "validated",
        "redaction": dict(_PASS_REDACTION),
    }
    companion_assets = _supply_chain_companion_assets(context, supply_chain_summary)
    if companion_assets:
        value["supplyChainCompanionAssets"] = companion_assets
    _schema_gate(
        state,
        "stable-maintenance.publication-conflict",
        value,
        PUBLICATION_PLAN_SCHEMA,
        "Regenerate the exact-byte publication plan from authenticated outputs.",
    )
    return value


def _core_receipt_errors(
    context: RunContext,
    loaded: Any,
    candidate: Candidate,
    core_plan_path: Path,
    core_plan: dict[str, Any],
    core_info_path: Path,
    descriptor: dict[str, Any],
) -> list[str]:
    value = loaded.value
    errors = validate_schema(value, CORE_RECEIPT_SCHEMA)
    expected_packages = {
        row.get("packageKey"): (
            row.get("digest"),
            row.get("sizeBytes"),
            row.get("publicChk") or row.get("storeUrl"),
        )
        for row in candidate.assets
    }
    observed = {
        row.get("packageKey"): (
            row.get("candidateAssetDigest"),
            row.get("candidateAssetSizeBytes"),
            row.get("publicReference"),
        )
        for row in value.get("referencedPackages", [])
        if isinstance(row, dict)
    }
    package_rows = value.get("referencedPackages", [])
    package_rows = package_rows if isinstance(package_rows, list) else []
    if (
        len(expected_packages) != len(candidate.assets)
        or len(observed) != len(package_rows)
        or len(package_rows) != len(candidate.assets)
        or any(
            not isinstance(row, dict) or row.get("verificationStatus") != "pass"
            for row in package_rows
        )
        or
        value.get("releaseId") != context.manifest.release.release_id
        or value.get("buildVersion") != context.manifest.release.version
        or value.get("releaseClass") != context.manifest.policies.get("releaseClass")
        or value.get("candidateIdentityDigest") != candidate.identity_digest
        or value.get("publicationPlanDigest") != file_digest(core_plan_path)
        or value.get("descriptorDigest") != file_digest(core_info_path)
        or value.get("descriptorDigest") != core_plan.get("descriptorDigest")
        or value.get("fetchedDescriptorDigest") != file_digest(core_info_path)
        or value.get("descriptorSizeBytes") != core_info_path.stat().st_size
        or value.get("descriptorSizeBytes") != core_plan.get("descriptorSizeBytes")
        or value.get("packageMapDigest") != semantic_digest(descriptor.get("packages"))
        or value.get("packageMapDigest") != core_plan.get("packageMapDigest")
        or value.get("edition") != core_plan.get("edition")
        or value.get("publicFetchUri") != core_plan.get("publicFetchUri")
        or value.get("operation") not in {"created", "verified-existing"}
        or value.get("conflictStatus") != "clear"
        or value.get("verificationStatus") != "pass"
        or value.get("publicationState") != "publication-complete"
        or observed != expected_packages
    ):
        errors.append(
            "CoreUpdater receipt does not prove the exact authorized descriptor, edition, "
            "public target, and package map"
        )
    if not _canonical_json_input(loaded.path, value):
        errors.append("CoreUpdater receipt JSON is not canonical deterministic JSON")
    return errors


def _receipt_errors(
    context: RunContext,
    loaded: Any,
    candidate: Candidate,
    plan_path: Path,
    plan: dict[str, Any],
    core_receipt: dict[str, Any],
    core_receipt_digest: str,
    successor_digest: str,
    history_digest: str,
) -> list[str]:
    value = loaded.value
    errors = validate_schema(value, PUBLICATION_RECEIPT_SCHEMA)
    metadata = context.manifest.policies.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    expected_release_page_uri = canonical_public_https_uri(
        metadata.get("githubReleasePageUri")
    )
    planned_assets = {
        row.get("fileName"): (
            row.get("role"), row.get("digest"), row.get("sizeBytes"), row.get("publicUri")
        )
        for row in plan.get("assets", [])
        if isinstance(row, dict)
    }
    observed_assets = {
        row.get("fileName"): (
            row.get("role"), row.get("digest"), row.get("sizeBytes"), row.get("publicUri")
        )
        for row in value.get("assets", [])
        if isinstance(row, dict)
    }
    planned_rows = plan.get("assets", [])
    planned_rows = planned_rows if isinstance(planned_rows, list) else []
    receipt_rows = value.get("assets", [])
    receipt_rows = receipt_rows if isinstance(receipt_rows, list) else []
    observations = value.get("publicObservations")
    observations = observations if isinstance(observations, dict) else {}
    catalog_target = plan.get("stableCatalogTarget")
    catalog_target = catalog_target if isinstance(catalog_target, dict) else {}
    catalog_identity = candidate.input_value.get("stableCatalog")
    catalog_identity = catalog_identity if isinstance(catalog_identity, dict) else {}
    catalog_receipt = value.get("stableCatalog")
    catalog_receipt = catalog_receipt if isinstance(catalog_receipt, dict) else {}
    core_target = plan.get("coreUpdateTarget")
    core_target = core_target if isinstance(core_target, dict) else {}
    core_summary = value.get("coreUpdate")
    core_summary = core_summary if isinstance(core_summary, dict) else {}
    catalog_target_fields = (
        "catalogId",
        "revision",
        "edition",
        "digest",
        "signatureDigest",
        "publicUri",
        "signaturePublicUri",
        "mirrorSetDigest",
        "rollbackStateDigest",
    )
    catalog_identity_fields = (
        "catalogId",
        "revision",
        "edition",
        "digest",
        "signatureDigest",
    )
    core_target_fields = ("edition", "descriptorDigest", "publicUri")
    if (
        len(planned_assets) != len(planned_rows)
        or len(observed_assets) != len(receipt_rows)
        or len(receipt_rows) != len(planned_rows)
        or any(
            not isinstance(row, dict)
            or row.get("operation") not in {"created", "verified-existing"}
            or row.get("verificationStatus") != "verified"
            for row in receipt_rows
        )
        or
        value.get("releaseId") != context.manifest.release.release_id
        or value.get("buildVersion") != context.manifest.release.version
        or value.get("releaseClass") != context.manifest.policies.get("releaseClass")
        or value.get("sourceCommit") != candidate.source.get("commit")
        or value.get("githubReleasePageUri") != plan.get("githubReleasePageUri")
        or value.get("deploymentServicePublicUri")
        != plan.get("deploymentServicePublicUri")
        or value.get("latestPointerPublicUri") != plan.get("latestPointerPublicUri")
        or value.get("candidateIdentityDigest") != candidate.identity_digest
        or value.get("productDigest") != candidate.product_digest
        or value.get("checksumsDigest") != plan.get("checksumsDigest")
        or value.get("provenanceDigest") != plan.get("provenanceDigest")
        or value.get("authorizationDigest") != plan.get("authorizationDigest")
        or value.get("backportReleaseTrainDigest")
        != plan.get("backportReleaseTrainDigest")
        or value.get("coreUpdateReceiptDigest") != core_receipt_digest
        or value.get("publicationPlanDigest") != file_digest(plan_path)
        or value.get("releaseNotesDigest") != plan.get("releaseNotesDigest")
        or value.get("coreInfoDigest") != plan.get("coreInfoDigest")
        or value.get("successorBaselineDigest") != successor_digest
        or value.get("releaseHistoryDigest") != history_digest
        or planned_assets != observed_assets
        or value.get("tag", {}).get("name") != f"v{context.manifest.release.version}"
        or value.get("tag", {}).get("objectType") != "annotated"
        or value.get("tag", {}).get("targetCommit") != candidate.source.get("commit")
        or value.get("tag", {}).get("operation") not in {"created", "verified-existing"}
        or value.get("tag", {}).get("verificationStatus") != "verified"
        or value.get("githubRelease", {}).get("operation")
        not in {"created", "verified-existing"}
        or value.get("githubRelease", {}).get("verificationStatus") != "verified"
        or value.get("githubRelease", {}).get("releaseId")
        != context.manifest.release.release_id
        or value.get("githubRelease", {}).get("tag")
        != f"v{context.manifest.release.version}"
        or value.get("githubRelease", {}).get("pageUri")
        != expected_release_page_uri
        or value.get("githubRelease", {}).get("notesDigest") != plan.get("releaseNotesDigest")
        or any(catalog_receipt.get(key) != catalog_target.get(key) for key in catalog_target_fields)
        or any(
            catalog_target.get(key) != catalog_identity.get(key)
            for key in catalog_identity_fields
        )
        or catalog_target.get("digest") != plan.get("stableCatalogDigest")
        or catalog_receipt.get("signatureDigest") != catalog_identity.get("signatureDigest")
        or catalog_receipt.get("operation")
        not in {"created", "verified-existing"}
        or catalog_receipt.get("verificationStatus") != "verified"
        or any(core_summary.get(key) != core_target.get(key) for key in core_target_fields)
        or core_summary.get("descriptorDigest") != core_receipt.get("descriptorDigest")
        or core_summary.get("packageMapDigest") != core_receipt.get("packageMapDigest")
        or core_receipt.get("edition") != core_target.get("edition")
        or core_receipt.get("publicFetchUri") != core_target.get("publicUri")
        or core_summary.get("operation")
        not in {"created", "verified-existing"}
        or core_summary.get("verificationStatus") != "verified"
        or set(observations.values()) != {"verified"}
        or value.get("publicationState") != "publication-complete"
        or value.get("finalVerificationStatus") != "pass"
        or value.get("failureCategory") is not None
    ):
        errors.append("publication receipt does not prove exact complete idempotent public state")
    if not _canonical_json_input(loaded.path, value):
        errors.append("publication receipt JSON is not canonical deterministic JSON")
    return errors


def _history_entry(
    context: RunContext,
    candidate: Candidate,
    ga: GaRoot,
    predecessor: Predecessor,
    receipt_identity_digest: str,
    core_info_digest: str,
    evidence_digest: str,
    backport_release_train_digest: str,
) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-maintenance-history-entry",
        "generatedAt": candidate.input_value.get("generatedAt"),
        "stableMilestone": STABLE_MILESTONE,
        "releaseId": context.manifest.release.release_id,
        "buildVersion": context.manifest.release.version,
        "tag": f"v{context.manifest.release.version}",
        "sourceCommit": candidate.source.get("commit"),
        "releaseClass": context.manifest.policies.get("releaseClass"),
        "chainDepth": predecessor.chain_depth + 1,
        "gaBaselineDigest": ga.baseline_digest,
        "previousBaselineDigest": predecessor.baseline_digest,
        "previousLineageDigest": predecessor.previous_lineage_digest,
        "candidateIdentityDigest": candidate.identity_digest,
        "productDigest": candidate.product_digest,
        "publicationReceiptIdentityDigest": receipt_identity_digest,
        "coreInfoDigest": core_info_digest,
        "evidenceDigest": evidence_digest,
        "backportReleaseTrainDigest": backport_release_train_digest,
        "status": "published-and-verified",
        "redaction": dict(_PASS_REDACTION),
    }


def _successor(
    context: RunContext,
    ga: GaRoot,
    predecessor: Predecessor,
    candidate: Candidate,
    policy_digest: str,
    evidence: dict[str, Any],
    evidence_digest: str,
    receipt: dict[str, Any],
    history_digest: str,
    backport_release_train_digest: str,
    follow_up: dict[str, Any] | None,
    follow_up_digest: str | None,
) -> dict[str, Any]:
    receipt_id = receipt_identity(receipt)
    limitations = candidate.input_value.get("limitations", {})
    current_limitation_ids = sorted(
        {
            item
            for field in ("addedIds", "unchangedIds")
            for item in (
                limitations.get(field) if isinstance(limitations.get(field), list) else []
            )
            if isinstance(item, str)
        }
    )
    security = candidate.input_value.get("security", {})
    support = candidate.input_value.get("support", {})
    inherited_follow_up = predecessor.outstanding_follow_up
    inherited_follow_up = (
        inherited_follow_up
        if isinstance(inherited_follow_up, dict)
        and inherited_follow_up.get("status") in {"open", "overdue"}
        else None
    )
    effective_follow_up = inherited_follow_up or follow_up
    effective_follow_up_digest = (
        inherited_follow_up.get("obligationDigest")
        if inherited_follow_up is not None
        else follow_up_digest
    )
    hotfix_follow_up = {
        "status": (
            effective_follow_up.get("status", "open")
            if effective_follow_up
            else "not-required"
        ),
        "generatedAt": (
            effective_follow_up.get("generatedAt")
            if effective_follow_up
            else candidate.input_value.get("generatedAt")
        ),
        "obligationDigest": effective_follow_up_digest,
        "deadline": (
            effective_follow_up.get("deadline") if effective_follow_up else None
        ),
        "closureEvidenceDigest": (
            effective_follow_up.get("closureEvidenceDigest")
            if effective_follow_up
            else None
        ),
        "blocksRoutineMaintenance": bool(effective_follow_up),
    }
    if effective_follow_up:
        hotfix_follow_up.update(
            {
                "obligatedReleaseId": effective_follow_up.get(
                    "obligatedReleaseId", effective_follow_up.get("releaseId")
                ),
                "obligatedBuildVersion": effective_follow_up.get(
                    "obligatedBuildVersion", effective_follow_up.get("buildVersion")
                ),
                "obligatedProductDigest": effective_follow_up.get(
                    "obligatedProductDigest", effective_follow_up.get("productDigest")
                ),
                "obligatedCandidateIdentityDigest": effective_follow_up.get(
                    "obligatedCandidateIdentityDigest",
                    effective_follow_up.get("candidateIdentityDigest"),
                ),
                "obligatedCandidateFreezeDigest": effective_follow_up.get(
                    "obligatedCandidateFreezeDigest",
                    effective_follow_up.get("candidateFreezeDigest"),
                ),
                "obligatedCandidateFrozenAt": effective_follow_up.get(
                    "obligatedCandidateFrozenAt",
                    effective_follow_up.get("candidateFrozenAt"),
                ),
                "obligatedPredecessorBuild": effective_follow_up.get(
                    "obligatedPredecessorBuild",
                    effective_follow_up.get("predecessorBuild"),
                ),
                "obligatedPredecessorProductDigest": effective_follow_up.get(
                    "obligatedPredecessorProductDigest",
                    effective_follow_up.get("predecessorProductDigest"),
                ),
                "authorizationDigest": (
                    effective_follow_up.get("authorizationDigest")
                    if inherited_follow_up is not None
                    else receipt.get("authorizationDigest")
                ),
            }
        )
    baseline = {
        "schemaVersion": 2,
        "kind": "stable-1.0-maintenance-successor-baseline",
        "generatedAt": candidate.input_value.get("generatedAt"),
        "stableMilestone": STABLE_MILESTONE,
        "status": "published",
        "gaRoot": {
            "releaseId": ga.release_id,
            "buildVersion": ga.build_version,
            "tag": ga.tag,
            "sourceCommit": ga.source_commit,
            "productDigest": ga.product_digest,
            "maintenanceBaselineDigest": ga.baseline_digest,
            "publicationReceiptDigest": ga.receipt_digest,
        },
        "previousBaselineDigest": predecessor.baseline_digest,
        "chainDepth": predecessor.chain_depth + 1,
        "previousLineageDigest": predecessor.previous_lineage_digest,
        "publication": {
            "receiptIdentityDigest": receipt_id,
            "publicationState": "publication-complete",
            "verificationStatus": "pass",
        },
        "release": {
            "releaseId": context.manifest.release.release_id,
            "buildVersion": context.manifest.release.version,
            "tag": f"v{context.manifest.release.version}",
            "sourceCommit": candidate.source.get("commit"),
            "releaseClass": context.manifest.policies.get("releaseClass"),
            "productDigest": candidate.product_digest,
            "publicationReceiptIdentityDigest": receipt_id,
            "checksumsDigest": receipt.get("checksumsDigest"),
            "provenanceDigest": receipt.get("provenanceDigest"),
            "coreInfoDigest": receipt.get("coreInfoDigest"),
        },
        "platformApi": {
            key: candidate.input_value.get("platformApi", {}).get(key)
            for key in (
                "baselineName",
                "baselineDigest",
                "baselineContractVersion",
                "currentContractVersion",
                "currentContractDigest",
                "stableSurfaceDigest",
                "compatibilityWindowPolicyDigest",
                "deprecationHistoryDigest",
                "deprecationHistory",
            )
        },
        "stableCatalog": {
            key: candidate.input_value.get("stableCatalog", {}).get(key)
            for key in (
                "catalogId",
                "channel",
                "revision",
                "edition",
                "digest",
                "signatureFileName",
                "signatureSizeBytes",
                "signatureDigest",
                "signingKeyId",
            )
        },
        "firstPartyApps": [
            {
                key: row.get(key)
                for key in (
                    "appId",
                    "version",
                    "channel",
                    "supportLevel",
                    "bundleDigest",
                    "reviewReceiptDigest",
                    "appSigningKeyId",
                    "reviewerKeyId",
                    "manifestDigest",
                    "permissionSetDigest",
                    "appDataSchemaVersion",
                    "supportMetadataDigest",
                )
            }
            for row in candidate.input_value.get("firstPartyApps", [])
        ],
        "contentFormatProfiles": [
            {
                key: row.get(key)
                for key in (
                    "profileId",
                    "version",
                    "status",
                    "descriptorDigest",
                    "canonicalizationRulesDigest",
                    "maximumSizePolicyDigest",
                    "signaturePayloadRulesDigest",
                )
            }
            for row in candidate.input_value.get("contentFormatProfiles", [])
        ],
        "limitations": {
            "currentDigest": _known_limitations_digest(set(current_limitation_ids)),
            "currentIds": current_limitation_ids,
            "gaBaselineDigest": semantic_digest(ga.baseline.get("limitations")),
            "predecessorDigest": semantic_digest(predecessor.baseline.get("limitations")),
        },
        "security": {
            "currentDigest": semantic_digest(security),
            "gaBaselineDigest": semantic_digest(ga.baseline.get("securityBaseline")),
            "predecessorDigest": semantic_digest(
                predecessor.baseline.get("security", predecessor.baseline.get("securityBaseline"))
            ),
        },
        "support": {
            "currentDigest": semantic_digest(support),
            "gaBaselineDigest": semantic_digest(ga.baseline.get("supportBaseline")),
            "predecessorDigest": semantic_digest(
                predecessor.baseline.get("support", predecessor.baseline.get("supportBaseline"))
            ),
        },
        "legacyBoundaries": candidate.input_value.get("legacyBoundaries"),
        "evidenceWindowPolicy": {
            "windowClass": evidence.get("windowClass"),
            "policyDigest": policy_digest,
            "requiredEvidenceDigest": semantic_digest(
                sorted(row.get("evidenceId") for row in evidence.get("evidenceRows", []))
            ),
            "completedEvidenceDigest": evidence_digest,
        },
        "hotfixFollowUp": hotfix_follow_up,
        "releaseTrain": {
            "validationDigest": backport_release_train_digest,
            "requiredEvidenceId": "stable-maintenance.backport-release-train",
            "candidateCommit": candidate.source.get("commit"),
            "predecessorCommit": predecessor.source_commit,
            "unresolvedObligationsCarried": bool(effective_follow_up),
        },
        "releaseHistoryDigest": history_digest,
        "redaction": dict(_PASS_REDACTION),
    }
    identity = successor_baseline_identity(baseline)
    history = list(predecessor.lineage_history)
    history.append(
        {
            "chainDepth": predecessor.chain_depth + 1,
            "releaseId": context.manifest.release.release_id,
            "buildVersion": context.manifest.release.version,
            "tag": f"v{context.manifest.release.version}",
            "sourceCommit": candidate.source.get("commit"),
            "releaseClass": context.manifest.policies.get("releaseClass"),
            "productDigest": candidate.product_digest,
            "baselineIdentityDigest": identity,
            "publicationReceiptIdentityDigest": receipt_id,
            "previousLineageDigest": predecessor.previous_lineage_digest,
        }
    )
    baseline["lineage"] = {
        "gaBaselineDigest": ga.baseline_digest,
        "gaPublicationReceiptDigest": ga.receipt_digest,
        "chainDepth": predecessor.chain_depth + 1,
        "lineageDigest": semantic_digest(history),
        "history": history,
    }
    return baseline


def _verify_receipts(
    context: RunContext,
    out: Path,
    ga: GaRoot,
    predecessor: Predecessor,
    candidate: Candidate,
    policy_digest: str,
    evidence: dict[str, Any],
    evidence_digest: str,
    descriptor: dict[str, Any],
    core_plan: dict[str, Any],
    plan: dict[str, Any],
    backport_release_train_digest: str,
    follow_up: dict[str, Any] | None,
    follow_up_digest: str | None,
    state: ValidationState,
) -> tuple[str, dict[str, Any] | None]:
    receipt_loaded = load_json_input(
        context, "stableMaintenancePublicationReceipt", required=False
    )
    core_loaded = load_json_input(context, "coreUpdatePublicationReceipt", required=False)
    if receipt_loaded is None and core_loaded is None:
        return "publication-authorized", None
    if receipt_loaded is None or core_loaded is None or state.blockers:
        add_blockers(
            state,
            "stable-maintenance.publication-verification",
            ["publication receipts are incomplete or prepublication validation failed"],
            "Recover protected publication state without changing authorized bytes.",
        )
        return "publication-verification-failed", None
    core_errors = _core_receipt_errors(
        context,
        core_loaded,
        candidate,
        out / CORE_PLAN_FILE,
        core_plan,
        out / CORE_INFO_FILE,
        descriptor,
    )
    add_blockers(
        state,
        "stable-maintenance.core-update-descriptor",
        core_errors,
        "Verify the exact fetched descriptor and every candidate package reference.",
    )
    receipt_id = receipt_identity(receipt_loaded.value)
    history = _history_entry(
        context,
        candidate,
        ga,
        predecessor,
        receipt_id,
        file_digest(out / CORE_INFO_FILE),
        evidence_digest,
        backport_release_train_digest,
    )
    write_json(out / HISTORY_FILE, history)
    history_digest = file_digest(out / HISTORY_FILE)
    successor = _successor(
        context,
        ga,
        predecessor,
        candidate,
        policy_digest,
        evidence,
        evidence_digest,
        receipt_loaded.value,
        history_digest,
        backport_release_train_digest,
        follow_up,
        follow_up_digest,
    )
    _schema_gate(
        state,
        "stable-maintenance.successor-baseline",
        successor,
        SUCCESSOR_SCHEMA,
        "Regenerate the v2 successor from exact verified publication state.",
    )
    write_json(out / SUCCESSOR_BASELINE_FILE, successor)
    receipt_errors = _receipt_errors(
        context,
        receipt_loaded,
        candidate,
        out / PUBLICATION_PLAN_FILE,
        plan,
        core_loaded.value,
        core_loaded.digest,
        file_digest(out / SUCCESSOR_BASELINE_FILE),
        history_digest,
    )
    add_blockers(
        state,
        "stable-maintenance.publication-verification",
        receipt_errors,
        "Record partial/conflicting state truthfully and recover without overwrite or deletion.",
    )
    if state.blockers:
        (out / SUCCESSOR_BASELINE_FILE).unlink(missing_ok=True)
        (out / HISTORY_FILE).unlink(missing_ok=True)
        return "publication-verification-failed", None
    _copy_exact(receipt_loaded.path, out / PUBLICATION_RECEIPT_FILE, receipt_loaded.digest)
    _copy_exact(core_loaded.path, out / CORE_RECEIPT_FILE, core_loaded.digest)
    pointer = {
        "schemaVersion": 1,
        "kind": "stable-1.0-maintenance-latest-published",
        "generatedAt": candidate.input_value.get("generatedAt"),
        "releaseId": context.manifest.release.release_id,
        "buildVersion": context.manifest.release.version,
        "releaseClass": context.manifest.policies.get("releaseClass"),
        "baselineDigest": file_digest(out / SUCCESSOR_BASELINE_FILE),
        "baselineIdentityDigest": successor_baseline_identity(successor),
        "publicationReceiptDigest": receipt_loaded.digest,
        "publicationReceiptIdentityDigest": receipt_id,
        "lineageDigest": successor["lineage"]["lineageDigest"],
        "historyDigest": history_digest,
        "backportReleaseTrainDigest": backport_release_train_digest,
        "compareAndSwapPredecessorBaselineDigest": predecessor.baseline_digest,
        "status": "active",
        "redaction": dict(_PASS_REDACTION),
    }
    write_json(out / LATEST_POINTER_FILE, pointer)
    return "publication-complete", successor


def _validation(
    context: RunContext,
    state: ValidationState,
    mode: str,
    candidate: Candidate,
    lineage_digest: str,
    comparison_digest: str,
    evidence: dict[str, Any],
    evidence_digest: str,
    core_info_digest: str,
    checksums_digest: str,
    provenance_digest: str,
    pending_lifecycle_transition_digest: str,
    backport_release_train_digest: str,
    backport_release_train_authenticated: bool,
    authorization_digest: str,
    authorization_valid: bool,
    publication_state: str,
) -> dict[str, Any]:
    evidence_results = [
        {
            "evidenceId": row.get("evidenceId"),
            "status": row.get("status"),
            "evidenceDigest": row.get("evidenceDigest"),
            "candidateBound": True,
            "predecessorBound": True,
            "fresh": row.get("fresh"),
            "production": row.get("production"),
        }
        for row in evidence.get("evidenceRows", [])
        if isinstance(row, dict)
    ]
    if backport_release_train_authenticated:
        evidence_results.append(
            {
                "evidenceId": "stable-maintenance.backport-release-train",
                "status": "pass",
                "evidenceDigest": backport_release_train_digest,
                "candidateBound": True,
                "predecessorBound": True,
                "fresh": True,
                "production": True,
            }
        )
    decision = (
        "no-go"
        if state.blockers
        else ("go-with-waivers" if state.warnings else "go")
    )
    value = {
        "schemaVersion": 1,
        "kind": "stable-1.0-maintenance-validation",
        "generatedAt": candidate.input_value.get("generatedAt"),
        "releaseId": context.manifest.release.release_id,
        "buildVersion": context.manifest.release.version,
        "releaseClass": context.manifest.policies.get("releaseClass"),
        "mode": mode,
        "lineageDigest": lineage_digest,
        "candidateIdentityDigest": candidate.identity_digest,
        "comparisonDigest": comparison_digest,
        "evidenceDigest": evidence_digest,
        "coreInfoDigest": core_info_digest,
        "checksumsDigest": checksums_digest,
        "provenanceDigest": provenance_digest,
        "pendingLifecycleTransitionDigest": pending_lifecycle_transition_digest,
        "backportReleaseTrainDigest": backport_release_train_digest,
        "evidenceResults": evidence_results,
        "blockers": [
            {
                "id": row.get("id"),
                "category": row.get("evidenceId", row.get("id")),
                "message": row.get("summary"),
                "waivable": False,
            }
            for row in state.blockers
        ],
        "warnings": [
            {
                "id": row.get("id"),
                "category": row.get("evidenceId", row.get("id")),
                "message": row.get("summary"),
                "waivable": True,
            }
            for row in state.warnings
        ],
        "waivers": (
            [
                {
                    "warningId": row.get("id"),
                    "allowlisted": True,
                    "authorizationDigest": authorization_digest,
                }
                for row in state.warnings
            ]
            if authorization_valid
            else []
        ),
        "decision": decision,
        "status": "fail" if state.blockers else "pass",
        "publicationState": publication_state,
        "promotionReady": bool(
            not state.blockers
            and authorization_valid
            and publication_state in {"publication-authorized", "publication-complete"}
        ),
        "redaction": dict(_PASS_REDACTION),
    }
    _schema_gate(
        state,
        "stable-maintenance.validation-schema",
        value,
        VALIDATION_SCHEMA,
        "Regenerate the complete maintenance validation artifact.",
    )
    return value


def _summary(
    context: RunContext,
    state: ValidationState,
    candidate: Candidate | None,
    publication_state: str,
    authorization_valid: bool,
    backport_release_train_digest: str | None,
    artifacts: dict[str, str],
    redaction: dict[str, Any],
) -> dict[str, Any]:
    promotion_ready = bool(
        candidate
        and not state.blockers
        and authorization_valid
        and publication_state in {"publication-authorized", "publication-complete"}
    )
    return {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "stable-1.0-maintenance-promotion",
        "tool": TOOL_NAME,
        "toolVersion": TOOL_VERSION,
        "generatedAt": (
            candidate.input_value.get("generatedAt") if candidate else _now().isoformat().replace("+00:00", "Z")
        ),
        "releaseId": context.manifest.release.release_id,
        "version": context.manifest.release.version,
        "buildVersion": context.manifest.release.version,
        "releaseClass": context.manifest.policies.get("releaseClass"),
        "stableMilestone": STABLE_MILESTONE,
        "status": "fail" if state.blockers else "pass",
        "promotionReady": promotion_ready,
        "nonRelease": publication_state != "publication-complete",
        "decision": (
            "no-go"
            if state.blockers
            else ("go-with-waivers" if state.warnings else "go")
        ),
        "publicationState": publication_state,
        "backportReleaseTrainDigest": backport_release_train_digest,
        "blockers": state.blockers,
        "warnings": state.warnings,
        "waivers": [],
        "redaction": redaction,
        "artifacts": artifacts,
    }


def run(context: RunContext) -> tuple[int, Path, Path]:
    """Run the native maintenance engine and fail closed without public side effects."""

    out = reset_confined_directory(
        context.component_dir / "artifacts" / "legacy",
        context.run_root,
        "Stable maintenance native output",
    )
    summary_path = out / SUMMARY_FILE
    report_path = out / REPORT_FILE
    state = ValidationState()
    try:
        code = _run(context, out, state)
    except Exception:  # noqa: BLE001 - protected release inputs must fail closed
        state.block(
            "stable-maintenance.execution-input",
            "stable-maintenance.execution-input",
            "Stable maintenance rejected a malformed, unsafe, or unauthenticated protected input.",
            "Correct the protected candidate-bound input and restart certification.",
        )
        out = reset_confined_directory(
            context.component_dir / "artifacts" / "legacy",
            context.run_root,
            "Stable maintenance failed native output",
        )
        _write_fail_closed(context, out, state)
        code = 1
    return code, summary_path, report_path


def _vulnerability_promotion_scope(
    backport_release_train: dict[str, Any] | None,
    hotfix_follow_up_obligation: dict[str, Any] | None,
) -> tuple[set[str], list[dict[str, Any]]]:
    """Return exact PR-288 incident scope for release or follow-up evaluation."""

    public_fixes = (
        backport_release_train.get("publicFixes", [])
        if isinstance(backport_release_train, dict)
        else []
    )
    public_fixes = public_fixes if isinstance(public_fixes, list) else []
    incident_ids = {
        str(row["incidentOpaqueId"])
        for row in public_fixes
        if isinstance(row, dict)
        and isinstance(row.get("incidentOpaqueId"), str)
    }
    security_bindings = [
        row
        for row in public_fixes
        if isinstance(row, dict) and row.get("classification") == "security-fix"
    ]
    if isinstance(hotfix_follow_up_obligation, dict):
        incident_id = hotfix_follow_up_obligation.get("incidentId")
        if isinstance(incident_id, str):
            incident_ids.add(incident_id)
    return incident_ids, security_bindings


def _run(context: RunContext, out: Path, state: ValidationState) -> int:
    mode = context.manifest.commands.get("stable-maintenance", {}).get(
        "mode", "validate-only"
    )
    prepare = mode == "prepare-authorization"
    closing_follow_up = mode == "close-hotfix-follow-up"
    policy_loaded = load_json_input(context, "maintenancePolicy")
    assert policy_loaded
    add_blockers(
        state,
        "stable-maintenance.policy",
        canonical_policy(context, policy_loaded),
        "Use the exact checked-in Stable 1.0 maintenance policy.",
    )
    policy = policy_loaded.value
    lifecycle_policy_path = (
        context.workspace_root
        / "tools/release-certification/stable-1.0-support-lifecycle-policy.json"
    )
    lifecycle_policy_digest: str | None = None
    try:
        lifecycle_policy = json.loads(lifecycle_policy_path.read_text(encoding="utf-8"))
        lifecycle_policy_digest = file_digest(lifecycle_policy_path)
    except (OSError, json.JSONDecodeError):
        lifecycle_policy = {}
    from .stable_1_0_lifecycle_core import policy_errors as lifecycle_policy_errors

    lifecycle_policy_failures = validate_schema(
        lifecycle_policy,
        "stable-1.0-support-lifecycle-policy-v1.schema.json",
    ) + lifecycle_policy_errors(lifecycle_policy)
    add_blockers(
        state,
        "stable-lifecycle.policy",
        lifecycle_policy_failures,
        "Use the exact reviewed Stable 1.0 support lifecycle policy.",
    )
    lifecycle_observation_maximum_age_minutes = (
        lifecycle_policy.get("supportWindows", {}).get(
            "maximumPublicObservationAgeMinutes", 0
        )
        if not lifecycle_policy_failures
        else 0
    )
    ga = authenticate_ga_root(context, state)
    obligation = (
        load_json_input(context, "hotfixFollowUpObligation")
        if closing_follow_up
        else None
    )
    freeze_predecessor_observation: dict[str, Any] | None = None
    if closing_follow_up:
        assert obligation
        freeze_input = load_json_input(context, "maintenanceCandidateFreeze")
        assert freeze_input
        observation = freeze_input.value.get("predecessorObservation")
        freeze_predecessor_observation = (
            dict(observation) if isinstance(observation, dict) else {}
        )
        original_predecessor_errors: list[str] = []
        if (
            freeze_predecessor_observation.get("buildVersion")
            != obligation.value.get("predecessorBuild")
            or freeze_predecessor_observation.get("productDigest")
            != obligation.value.get("predecessorProductDigest")
            or freeze_predecessor_observation.get("status") != "latest-published"
        ):
            original_predecessor_errors.append(
                "hotfix follow-up candidate freeze is not bound to its original predecessor"
            )
        add_blockers(
            state,
            "stable-maintenance.hotfix-follow-up",
            original_predecessor_errors,
            "Use the exact originally authorized hotfix freeze and predecessor observation.",
        )
    predecessor = authenticate_predecessor(
        context, ga, state, allow_non_successor_build=closing_follow_up
    )
    add_blockers(
        state,
        "stable-lifecycle.release-inventory",
        (
            []
            if closing_follow_up
            else _lifecycle_successor_capacity_errors(predecessor, lifecycle_policy)
        ),
        "Do not publish another Stable 1.0 build until a separately versioned, runtime-compatible "
        "lifecycle rollover policy is reviewed and implemented.",
    )
    lifecycle_ledger = load_json_input(
        context, "previousStableLifecycleLedger", required=False
    )
    lifecycle_descriptor = load_json_input(
        context, "previousStableLifecycleDescriptor", required=False
    )
    lifecycle_authorization = load_json_input(
        context, "stableLifecycleAuthorization", required=False
    )
    lifecycle_publication_plan = load_json_input(
        context, "stableLifecyclePublicationPlan", required=False
    )
    lifecycle_receipt = load_json_input(
        context, "stableLifecyclePublicationReceipt", required=False
    )
    lifecycle_public_observation = load_json_input(
        context, "stableLifecyclePublicObservationReceipt", required=False
    )
    lifecycle_inputs = (
        lifecycle_ledger,
        lifecycle_descriptor,
        lifecycle_authorization,
        lifecycle_publication_plan,
        lifecycle_receipt,
    )
    lifecycle_activation_verified = False
    predecessor_lifecycle_status = "current-stable"
    lifecycle_presence_errors = _lifecycle_input_presence_errors(
        lifecycle_inputs,
        predecessor.chain_depth,
        require_activation=not closing_follow_up,
    )
    candidate = authenticate_candidate(
        context,
        predecessor,
        policy,
        state,
        allow_published_product=closing_follow_up,
        freeze_predecessor_observation=freeze_predecessor_observation,
    )
    if closing_follow_up:
        backport_release_train = None
        backport_release_train_authenticated = False
    else:
        (
            backport_release_train,
            backport_release_train_authenticated,
        ) = _authenticate_backport_release_train(
            context, predecessor, candidate, state
        )
    backport_release_train_digest = (
        backport_release_train.digest
        if backport_release_train is not None
        else None
    )
    (
        vulnerability_incident_ids,
        vulnerability_security_bindings,
    ) = _vulnerability_promotion_scope(
        backport_release_train.value
        if backport_release_train is not None
        else None,
        obligation.value if closing_follow_up and obligation is not None else None,
    )
    if closing_follow_up:
        vulnerability_errors = follow_up_closure_errors(
            context,
            incident_id=next(iter(vulnerability_incident_ids), None),
            evaluation_clock=_now(),
        )
    else:
        vulnerability_errors = promotion_errors(
            context,
            release_class=str(context.manifest.policies.get("releaseClass")),
            incident_ids=vulnerability_incident_ids,
            security_bindings=vulnerability_security_bindings,
            evaluation_clock=_now(),
        )
    add_blockers(
        state,
        "stable-maintenance.stable-vulnerability",
        vulnerability_errors,
        "Provide the exact authenticated case summary and operation-bound incident scope.",
    )
    supply_chain_summary = None
    dependency_vulnerability_governance_active = False
    if not closing_follow_up:
        supply_chain_summary = load_json_input(
            context, "supplyChainPromotionSummary"
        )
        assert supply_chain_summary
        add_blockers(
            state,
            "stable-maintenance.supply-chain",
            _supply_chain_promotion_errors(
                context, supply_chain_summary, candidate, predecessor
            ),
            "Provide the exact authenticated PR-289 promotion summary for this candidate, predecessor, package matrix, and vulnerability inventory.",
        )
        dependency_vulnerability_activation = _dependency_vulnerability_activation(
            context, candidate
        )
        dependency_vulnerability_governance_active = (
            dependency_vulnerability_activation[0] is True
        )
        add_blockers(
            state,
            "stable-maintenance.dependency-vulnerability",
            _dependency_vulnerability_promotion_errors(
                context,
                candidate,
                supply_chain_summary,
                dependency_vulnerability_activation,
            ),
            "Provide the exact post-activation PR-290 companion bound to PR-289, PR-288, and this candidate.",
        )
    if lifecycle_presence_errors:
        add_blockers(
            state,
            "stable-lifecycle.state-consistency",
            lifecycle_presence_errors,
            "Provide the exact verified five-artifact lifecycle authority chain or use the "
            "policy-defined non-promoting GA bootstrap.",
        )
    elif not closing_follow_up and all(item is not None for item in lifecycle_inputs):
        assert (
            lifecycle_ledger
            and lifecycle_descriptor
            and lifecycle_authorization
            and lifecycle_publication_plan
            and lifecycle_receipt
        )
        lifecycle_errors = _authenticated_lifecycle_errors(
            lifecycle_ledger.value,
            lifecycle_descriptor.value,
            lifecycle_authorization.value,
            lifecycle_publication_plan.value,
            lifecycle_receipt.value,
            lifecycle_authorization.digest,
            lifecycle_descriptor.digest,
            lifecycle_policy_digest,
            predecessor,
            context.manifest.policies.get("releaseClass"),
            _now(),
            candidate.input_value.get("changeScope"),
        )
        if lifecycle_public_observation is None:
            lifecycle_errors.append(
                "a fresh protected read-only observation of the exact public lifecycle edition "
                "is required"
            )
        else:
            lifecycle_errors.extend(
                _public_lifecycle_observation_errors(
                    lifecycle_public_observation.value,
                    lifecycle_ledger.value,
                    lifecycle_descriptor.value,
                    lifecycle_authorization.value,
                    lifecycle_publication_plan.value,
                    lifecycle_receipt.value,
                    lifecycle_authorization.digest,
                    lifecycle_descriptor.digest,
                    _now(),
                    lifecycle_observation_maximum_age_minutes,
                )
            )
        add_blockers(
            state,
            "stable-lifecycle.state-consistency",
            lifecycle_errors,
            "Use the exact latest verified lifecycle state and a policy-eligible predecessor.",
        )
        predecessor_entry = _lifecycle_predecessor_entry(
            lifecycle_ledger.value, predecessor
        )
        if predecessor_entry is not None and predecessor_entry.get(
            "lifecycleStatus"
        ) in {
            "current-stable",
            "supported-maintenance",
            "security-fixes-only",
            "deprecated",
            "end-of-support",
            "revoked",
        }:
            predecessor_lifecycle_status = str(
                predecessor_entry.get("lifecycleStatus")
            )
        lifecycle_activation_verified = not lifecycle_errors
    if mode == "close-hotfix-follow-up":
        assert obligation
        published_follow_up = predecessor.baseline.get("hotfixFollowUp")
        published_follow_up = (
            published_follow_up if isinstance(published_follow_up, dict) else {}
        )
        close_authorization = load_json_input(
            context, "stableMaintenanceAuthorization", public_authorization=True
        )
        assert close_authorization
        close_errors = _close_authorization_errors(
            close_authorization, obligation, published_follow_up
        )
        add_blockers(
            state,
            "stable-maintenance.authorization",
            close_errors,
            "Use the original exact-hotfix security release authorization.",
        )
        publication_binding_errors: list[str] = []
        if (
            candidate.input_value.get("releaseId") != obligation.value.get("releaseId")
            or candidate.input_value.get("buildVersion")
            != obligation.value.get("buildVersion")
            or candidate.product_digest != obligation.value.get("productDigest")
            or candidate.identity_digest
            != obligation.value.get("candidateIdentityDigest")
            or candidate.freeze_digest != obligation.value.get("candidateFreezeDigest")
            or candidate.frozen_at != obligation.value.get("candidateFrozenAt")
            or predecessor.latest_pointer_digest is None
            or published_follow_up.get("status") not in {"open", "overdue"}
            or published_follow_up.get("obligationDigest") != obligation.digest
            or published_follow_up.get("obligatedReleaseId")
            != obligation.value.get("releaseId")
            or published_follow_up.get("obligatedBuildVersion")
            != obligation.value.get("buildVersion")
            or published_follow_up.get("obligatedProductDigest")
            != obligation.value.get("productDigest")
            or published_follow_up.get("obligatedCandidateIdentityDigest")
            != obligation.value.get("candidateIdentityDigest")
            or published_follow_up.get("obligatedCandidateFreezeDigest")
            != obligation.value.get("candidateFreezeDigest")
            or published_follow_up.get("obligatedCandidateFrozenAt")
            != obligation.value.get("candidateFrozenAt")
            or published_follow_up.get("obligatedPredecessorBuild")
            != obligation.value.get("predecessorBuild")
            or published_follow_up.get("obligatedPredecessorProductDigest")
            != obligation.value.get("predecessorProductDigest")
        ):
            publication_binding_errors.append(
                "hotfix follow-up closure is not bound to the original obligated "
                "hotfix and current activated carrier"
            )
        add_blockers(
            state,
            "stable-maintenance.hotfix-follow-up",
            publication_binding_errors,
            "Select the exact activated hotfix baseline, receipt, pointer, and obligation.",
        )
        closure = close_hotfix_follow_up(context, ga, candidate, state)
        closure.update(
            {
                "closedAt": closure.get("generatedAt"),
                "releaseClass": "security-hotfix",
                "successorBaselineDigest": predecessor.baseline_digest,
                "publicationReceiptDigest": predecessor.receipt_digest,
                "publicationReceiptIdentityDigest": receipt_identity(
                    predecessor.receipt
                ),
                "authorizationDigest": published_follow_up.get("authorizationDigest"),
                "latestPublishedPointerDigest": predecessor.latest_pointer_digest,
                "owner": obligation.value.get("owner"),
                "approver": obligation.value.get("approver"),
            }
        )
        add_blockers(
            state,
            "stable-maintenance.hotfix-follow-up",
            validate_schema(closure, FOLLOW_UP_CLOSURE_SCHEMA),
            "Regenerate the versioned closure overlay from exact published inputs.",
        )
        write_json(out / FOLLOW_UP_CLOSURE_FILE, closure)
        redaction = build_redaction_report(((FOLLOW_UP_CLOSURE_FILE, closure),))
        artifacts = {"hotfixFollowUpClosure": FOLLOW_UP_CLOSURE_FILE}
        summary = _summary(
            context,
            state,
            candidate,
            "publication-complete",
            False,
            None,
            artifacts,
            redaction,
        )
        summary["nonRelease"] = True
        write_json(out / REDACTION_REPORT_FILE, redaction)
        write_json(out / SUMMARY_FILE, summary)
        write_text(out / REPORT_FILE, render_go_no_go(summary))
        return 0 if not state.blockers else 1

    lifecycle_proposal = _pending_lifecycle_transition(
        context,
        predecessor,
        candidate,
        predecessor_lifecycle_status,
        str(backport_release_train_digest),
    )
    add_blockers(
        state,
        "stable-lifecycle.transition-policy",
        validate_schema(
            lifecycle_proposal,
            "stable-1.0-support-lifecycle-pending-maintenance-transition-v1.schema.json",
        ),
        "Correct the publication-contingent lifecycle proposal.",
    )
    write_json(out / LIFECYCLE_PENDING_TRANSITION_FILE, lifecycle_proposal)

    targets, targets_digest = _targets(context, state)
    add_blockers(
        state,
        "stable-maintenance.publication-conflict",
        _concrete_publication_destination_errors(targets, candidate),
        "Use distinct canonical public HTTPS destinations for every concrete publication object.",
    )
    candidate_freeze_input = load_json_input(context, "maintenanceCandidateFreeze")
    assert candidate_freeze_input
    _copy_exact(
        candidate_freeze_input.path,
        out / CANDIDATE_FREEZE_FILE,
        candidate_freeze_input.digest,
    )
    lineage = _lineage(context, ga, predecessor, candidate, state)
    write_json(out / LINEAGE_FILE, lineage)
    write_json(out / CANDIDATE_FILE, candidate.identity)
    comparison = build_comparison(context, ga, predecessor, candidate, policy, state)
    write_json(out / COMPARISON_FILE, comparison)
    evidence, evidence_digest, follow_up = validate_production_evidence(
        context, ga, predecessor, candidate, policy, state
    )
    add_blockers(
        state,
        "stable-maintenance.hotfix-follow-up",
        _concurrent_follow_up_errors(predecessor, follow_up),
        "Use the full evidence window for the superseding hotfix or close the predecessor obligation first.",
    )
    follow_up_digest: str | None = None
    if follow_up is not None:
        write_json(out / FOLLOW_UP_FILE, follow_up)
        follow_up_digest = file_digest(out / FOLLOW_UP_FILE)
    descriptor, _core_identity = build_core_info(context, candidate, state)
    write_json(out / CORE_INFO_FILE, descriptor)
    known = _known_limitations(context, candidate)
    write_json(out / KNOWN_LIMITATIONS_FILE, known)
    notes = render_release_notes(
        context.manifest.release.release_id,
        str(context.manifest.release.version),
        str(context.manifest.policies.get("releaseClass")),
        predecessor.build_version,
        candidate.input_value,
        "validated",
        list(backport_release_train.value.get("publicFixes", [])),
        list(backport_release_train.value.get("deferredFixIds", [])),
        str(backport_release_train_digest),
    )
    write_text(out / RELEASE_NOTES_FILE, notes)
    provenance = _provenance(
        context,
        policy_loaded.digest,
        ga,
        predecessor,
        candidate,
        file_digest(out / LINEAGE_FILE),
        file_digest(out / COMPARISON_FILE),
        evidence_digest,
        file_digest(out / CORE_INFO_FILE),
        lifecycle_proposal["proposalDigest"],
        str(backport_release_train_digest),
    )
    write_json(out / PROVENANCE_FILE, provenance)
    _write_checksums(
        out / CHECKSUMS_FILE,
        _public_checksum_payload_paths(candidate, out).values(),
    )
    expected = _authorization_expected(
        context,
        ga,
        predecessor,
        candidate,
        file_digest(out / COMPARISON_FILE),
        evidence_digest,
        file_digest(out / CORE_INFO_FILE),
        file_digest(out / CHECKSUMS_FILE),
        file_digest(out / PROVENANCE_FILE),
        file_digest(out / RELEASE_NOTES_FILE),
        targets_digest,
        follow_up_digest,
        str(backport_release_train_digest),
        dependency_vulnerability_governance_active,
    )
    authorization, authorization_digest, authorization_valid = _authorization(
        context, expected, policy, state, prepare
    )
    authorization_input = load_json_input(
        context,
        "stableMaintenanceAuthorization",
        required=False,
        public_authorization=True,
    )
    if authorization_input is not None and authorization_valid:
        _copy_exact(authorization_input.path, out / AUTHORIZATION_FILE, authorization_input.digest)
        authorization_path = out / AUTHORIZATION_FILE
    else:
        write_json(out / AUTHORIZATION_FILE, authorization)
        authorization_path = out / AUTHORIZATION_FILE
        authorization_digest = file_digest(authorization_path)
    core_plan = _core_plan(
        context,
        candidate,
        descriptor,
        out / CORE_INFO_FILE,
        targets,
        targets_digest,
        authorization_digest,
        state,
    )
    write_json(out / CORE_PLAN_FILE, core_plan)
    plan = _publication_plan(
        context,
        candidate,
        out,
        targets,
        targets_digest,
        authorization_path,
        authorization_digest,
        str(backport_release_train_digest),
        authorization_valid,
        state,
        supply_chain_summary,
        dependency_vulnerability_governance_active,
    )
    write_json(out / PUBLICATION_PLAN_FILE, plan)
    publication_state = "validated" if not authorization_valid else "publication-authorized"
    successor: dict[str, Any] | None = None
    if authorization_valid:
        publication_state, successor = _verify_receipts(
            context,
            out,
            ga,
            predecessor,
            candidate,
            policy_loaded.digest,
            evidence,
            evidence_digest,
            descriptor,
            core_plan,
            plan,
            str(backport_release_train_digest),
            follow_up,
            follow_up_digest,
            state,
        )
    validation = _validation(
        context,
        state,
        mode,
        candidate,
        file_digest(out / LINEAGE_FILE),
        file_digest(out / COMPARISON_FILE),
        evidence,
        evidence_digest,
        file_digest(out / CORE_INFO_FILE),
        file_digest(out / CHECKSUMS_FILE),
        file_digest(out / PROVENANCE_FILE),
        lifecycle_proposal["proposalDigest"],
        str(backport_release_train_digest),
        backport_release_train_authenticated,
        authorization_digest,
        authorization_valid,
        publication_state,
    )
    _apply_lifecycle_promotion_gate(validation, lifecycle_activation_verified)
    write_json(out / VALIDATION_FILE, validation)
    artifacts = {
        "lineage": LINEAGE_FILE,
        "candidate": CANDIDATE_FILE,
        "candidateFreeze": CANDIDATE_FREEZE_FILE,
        "comparison": COMPARISON_FILE,
        "validation": VALIDATION_FILE,
        "authorization": AUTHORIZATION_FILE,
        "knownLimitations": KNOWN_LIMITATIONS_FILE,
        "releaseNotes": RELEASE_NOTES_FILE,
        "publicationPlan": PUBLICATION_PLAN_FILE,
        "checksums": CHECKSUMS_FILE,
        "auditChecksums": AUDIT_CHECKSUMS_FILE,
        "provenance": PROVENANCE_FILE,
        "coreInfo": CORE_INFO_FILE,
        "coreUpdatePublicationPlan": CORE_PLAN_FILE,
        "redactionReport": REDACTION_REPORT_FILE,
        "goNoGo": REPORT_FILE,
    }
    artifacts["pendingLifecycleTransition"] = LIFECYCLE_PENDING_TRANSITION_FILE
    if follow_up is not None:
        artifacts["hotfixFollowUp"] = FOLLOW_UP_FILE
    if successor is not None:
        artifacts.update(
            {
                "publicationReceipt": PUBLICATION_RECEIPT_FILE,
                "coreUpdatePublicationReceipt": CORE_RECEIPT_FILE,
                "successorBaseline": SUCCESSOR_BASELINE_FILE,
                "releaseHistory": HISTORY_FILE,
                "latestPublishedPointer": LATEST_POINTER_FILE,
            }
        )
    redaction_items: list[tuple[str, Any]] = [
        (LINEAGE_FILE, lineage),
        (CANDIDATE_FILE, candidate.identity),
        (CANDIDATE_FREEZE_FILE, candidate_freeze_input.value),
        (COMPARISON_FILE, comparison),
        (VALIDATION_FILE, validation),
        (AUTHORIZATION_FILE, authorization),
        (KNOWN_LIMITATIONS_FILE, known),
        (RELEASE_NOTES_FILE, notes),
        (PROVENANCE_FILE, provenance),
        (CHECKSUMS_FILE, (out / CHECKSUMS_FILE).read_text(encoding="utf-8")),
        (CORE_INFO_FILE, descriptor),
        (CORE_PLAN_FILE, core_plan),
        (PUBLICATION_PLAN_FILE, plan),
    ]
    redaction_items.append((LIFECYCLE_PENDING_TRANSITION_FILE, lifecycle_proposal))
    if follow_up is not None:
        redaction_items.append((FOLLOW_UP_FILE, follow_up))
    if successor is not None:
        redaction_items.extend(
            [
                (PUBLICATION_RECEIPT_FILE, load_json_input(context, "stableMaintenancePublicationReceipt").value),
                (CORE_RECEIPT_FILE, load_json_input(context, "coreUpdatePublicationReceipt").value),
                (SUCCESSOR_BASELINE_FILE, successor),
            ]
        )
    redaction = build_redaction_report(redaction_items)
    if redaction.get("status") != "pass":
        add_blockers(
            state,
            "stable-maintenance.support-redaction",
            ["generated public maintenance artifact set failed redaction"],
            "Remove unsafe input metadata and restart candidate certification.",
        )
        publication_state = "publication-verification-failed" if successor else "validated"
    write_json(out / REDACTION_REPORT_FILE, redaction)
    if not state.blockers:
        for name, source in sorted(candidate.asset_paths.items()):
            _copy_exact(source, out / name, file_digest(source))
    summary = _summary(
        context,
        state,
        candidate,
        publication_state,
        authorization_valid,
        backport_release_train_digest,
        artifacts,
        redaction,
    )
    _apply_lifecycle_promotion_gate(summary, lifecycle_activation_verified)
    write_json(out / SUMMARY_FILE, summary)
    write_text(out / REPORT_FILE, render_go_no_go(summary))
    audit_members = [path for path in out.iterdir() if path.is_file() and path.name != AUDIT_CHECKSUMS_FILE]
    _write_checksums(out / AUDIT_CHECKSUMS_FILE, audit_members)
    if prepare and not state.blockers:
        return 0
    return 0 if summary.get("promotionReady") is True else 1


def _write_fail_closed(context: RunContext, out: Path, state: ValidationState) -> None:
    redaction = {
        "schemaVersion": 1,
        "status": "fail",
        "findingCount": 1,
        "findings": [
            {
                "category": "protected-input",
                "summary": "Unsafe or malformed maintenance input was rejected.",
            }
        ],
        "guarantees": {"unsafeInputExcluded": True},
    }
    summary = _summary(context, state, None, "validated", False, None, {}, redaction)
    write_json(out / SUMMARY_FILE, summary)
    write_text(out / REPORT_FILE, render_go_no_go(summary))
    write_json(out / REDACTION_REPORT_FILE, redaction)

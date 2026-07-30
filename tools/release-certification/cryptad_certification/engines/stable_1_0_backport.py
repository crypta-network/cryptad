"""Canonical side-effect-free Stable 1.0 backport and release-train certification."""

from __future__ import annotations

import copy
import datetime as dt
import json
import re
import shutil
from pathlib import Path
from typing import Any, Iterable

from cryptad_certification.io import read_json, write_json, write_text
from cryptad_certification.models import RunContext
from cryptad_certification.redaction import scan_value
from cryptad_certification.schema_validation import validate_schema
from cryptad_certification.stable_backport_git import (
    GitInspectionError,
    GitInspector,
    MergeEvidence,
    NonAutomaticMergeResolutionError,
    PatchProvenance,
)
from cryptad_certification.workspace import reset_confined_directory

from .stable_1_0_backport_core import (
    AUTHORIZATION_FILE,
    AUTHORIZATION_SCHEMA,
    BACKPORT_LINEAGE_FILE,
    BACKPORT_LINEAGE_SCHEMA,
    BACKPORT_PLAN_FILE,
    BACKPORT_PLAN_SCHEMA,
    CANDIDATE_FILE,
    CANDIDATE_SCHEMA,
    CHECKSUMS_FILE,
    COMMAND_MODES,
    COMPLETION_FILE,
    COMPLETION_HANDOFF_FILE,
    COMPLETION_HANDOFF_SCHEMA,
    COMPLETION_SCHEMA,
    FIX_INTAKE_FILE,
    PROVENANCE_FILE,
    PROVENANCE_SCHEMA,
    PUBLIC_QUEUE_FILE,
    PUBLIC_QUEUE_SCHEMA,
    PUBLIC_VALIDATION_FILE,
    PUBLIC_VALIDATION_SCHEMA,
    QUEUE_FILE,
    QUEUE_SCHEMA,
    REDACTION_FILE,
    REDACTION_SCHEMA,
    REVIEW_AUTHORIZATIONS_SCHEMA,
    REPORT_FILE,
    SCHEMA_VERSION,
    STABLE_MILESTONE,
    SUMMARY_FILE,
    SUMMARY_SCHEMA,
    VALIDATION_FILE,
    VALIDATION_SCHEMA,
    _PASS_REDACTION,
    build_queue,
    canonical_identity_digest,
    checked_in_policy_errors,
    clean_cherry_pick_review_errors,
    file_digest,
    intake_errors,
    load_object,
    manual_conflict_review_errors,
    parse_timestamp,
    phase_intake_composition_digest,
    permitted_carried_obligation_ids,
    queue_evidence_binding_errors,
    queue_identity_digest,
    semantic_digest,
)
from .stable_1_0_maintenance_core import (
    authenticate_ga_root as authenticate_stable_ga_root,
)
from .stable_1_0_maintenance_core import (
    authenticate_predecessor as authenticate_stable_predecessor,
)
from .stable_1_0_maintenance import (
    _authenticated_lifecycle_errors as authenticated_lifecycle_errors,
)
from .stable_1_0_maintenance import (
    _public_lifecycle_observation_errors as public_lifecycle_observation_errors,
)
from .stable_1_0_rc_core import ValidationState

REPOSITORY_IDENTITY = "github.com/crypta-network/cryptad"
EVIDENCE_ID = "stable-maintenance.backport-release-train"
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ACTIVE_STATES = {"accepted", "scheduled", "landed", "verified"}
_PASS_REDACTION_GUARANTEES = {
    "embargoedDetailsExcluded": True,
    "privateIssueAndForkNamesExcluded": True,
    "credentialsAndPrivateInsertUrisExcluded": True,
    "rawPatchesAndUserDataExcluded": True,
    "absolutePathsExcluded": True,
    "unsafeMarkdownAndHtmlExcluded": True,
    "sideEffectsNotPerformed": True,
}


def _canonical_json_input(path: Path, value: dict[str, Any]) -> bool:
    expected = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
        + b"\n"
    )
    try:
        return path.read_bytes() == expected
    except OSError:
        return False


def _release(context: RunContext) -> dict[str, Any]:
    version = context.manifest.release.version
    assert version is not None
    release_class = context.manifest.policies.get("releaseClass")
    assert release_class in {"maintenance", "security-hotfix"}
    return {
        "releaseId": context.manifest.release.release_id,
        "releaseClass": release_class,
        "buildVersion": version,
        "tag": f"v{version}",
    }


def _lane(context: RunContext) -> str:
    lane = context.manifest.policies.get("backportReleaseLane")
    if lane not in {"routine-maintenance", "security-hotfix"}:
        raise ValueError("release-train lane is invalid")
    return lane


def _timestamp(value: Any) -> str:
    parsed = parse_timestamp(value)
    if parsed is None:
        raise ValueError("release-train timestamp is malformed")
    return parsed.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def _schema_or_raise(value: dict[str, Any], schema: str, label: str) -> None:
    errors = validate_schema(value, schema)
    if errors:
        raise ValueError(f"generated {label} is inconsistent with its strict schema")


def _write_canonical(path: Path, value: dict[str, Any], schema: str) -> None:
    _schema_or_raise(value, schema, path.name)
    write_json(path, value)


def _copy_canonical_input(source: Path, destination: Path, value: dict[str, Any]) -> None:
    if not _canonical_json_input(source, value):
        raise ValueError("release-train public JSON input is not canonical")
    if destination.exists() or destination.is_symlink():
        raise ValueError("release-train output path already exists")
    shutil.copyfile(source, destination)
    if file_digest(source) != file_digest(destination):
        destination.unlink(missing_ok=True)
        raise ValueError("release-train exact input copy changed")


def _load_inputs(
    context: RunContext,
) -> dict[str, tuple[Path, dict[str, Any], str] | None]:
    keys = (
        "stableBackportPolicy",
        "stableFixIntake",
        "stableBackportReviewAuthorizations",
        "previousStableBackportQueue",
        "previousStableBackportValidation",
        "previousStableBackportCompletion",
        "previousStableBackportCompletionHandoff",
        "predecessorPublicationReceipt",
        "predecessorBaseline",
        "hotfixFollowUpClosure",
        "latestPublishedMaintenancePointer",
        "stableLifecyclePolicy",
        "previousStableLifecycleLedger",
        "previousStableLifecycleDescriptor",
        "previousStableLifecycleAuthorization",
        "previousStableLifecyclePublicationPlan",
        "previousStableLifecyclePublicationReceipt",
        "stableLifecyclePublicObservationReceipt",
        "stableBackportAuthorization",
        "stableBackportFrozenValidation",
        "stableBackportCompletionEvidence",
        "stableMaintenancePublicationReceipt",
        "stableLifecyclePublicationReceipt",
        "completedStableLifecycleLedger",
        "completedStableLifecycleDescriptor",
    )
    optional = {
        "stableBackportReviewAuthorizations",
        "previousStableBackportQueue",
        "previousStableBackportValidation",
        "previousStableBackportCompletion",
        "previousStableBackportCompletionHandoff",
        "hotfixFollowUpClosure",
        "latestPublishedMaintenancePointer",
        "stableBackportAuthorization",
        "stableBackportFrozenValidation",
        "stableBackportCompletionEvidence",
        "stableMaintenancePublicationReceipt",
        "stableLifecyclePublicationReceipt",
        "completedStableLifecycleLedger",
        "completedStableLifecycleDescriptor",
    }
    return {
        key: load_object(context, key, required=key not in optional)
        for key in keys
    }


def _authenticate_previous_queue(
    inputs: dict[str, tuple[Path, dict[str, Any], str] | None],
    *,
    predecessor_commit: str,
    predecessor_build: str,
) -> dict[str, Any] | None:
    """Require the queue authenticated by the published predecessor, except at GA."""

    baseline_loaded = inputs["predecessorBaseline"]
    previous_queue_loaded = inputs["previousStableBackportQueue"]
    previous_validation_loaded = inputs["previousStableBackportValidation"]
    assert baseline_loaded is not None
    baseline = baseline_loaded[1]
    if baseline.get("kind") == "stable-1.0-maintenance-baseline":
        if previous_queue_loaded is not None or previous_validation_loaded is not None:
            raise ValueError("GA-root release-train queue must begin at authenticated genesis")
        return None
    if previous_queue_loaded is None or previous_validation_loaded is None:
        raise ValueError(
            "maintenance successor requires its authenticated previous queue and validation"
        )
    queue_path, queue, _queue_file_digest = previous_queue_loaded
    validation_path, validation, validation_file_digest = previous_validation_loaded
    for path, value, schema, label in (
        (queue_path, queue, QUEUE_SCHEMA, "previous release-train queue"),
        (
            validation_path,
            validation,
            VALIDATION_SCHEMA,
            "previous release-train validation",
        ),
    ):
        if not _canonical_json_input(path, value) or _scan_public_artifact(
            label, value
        ):
            raise ValueError(f"{label} is not canonical and public-safe")
        _schema_or_raise(value, schema, label)
    release_train = baseline.get("releaseTrain")
    release_train = release_train if isinstance(release_train, dict) else {}
    queue_binding_errors = queue_evidence_binding_errors(queue)
    if (
        queue_binding_errors
        or release_train.get("validationDigest") != validation_file_digest
        or release_train.get("candidateCommit") != predecessor_commit
        or validation.get("mode") != "validate-authorization"
        or validation.get("decision") != "go"
        or validation.get("candidateCommit") != predecessor_commit
        or validation.get("release", {}).get("buildVersion") != predecessor_build
        or validation.get("queueDigest") != queue.get("queueDigest")
        or queue.get("candidateCommit") != predecessor_commit
        or queue.get("queueDigest") != queue_identity_digest(queue)
    ):
        raise ValueError(
            "previous release-train queue is not authenticated by the published predecessor"
        )
    return queue


def _closure_adjusted_predecessor_baseline(
    baseline: dict[str, Any],
    canonical_predecessor: Any,
    closure_loaded: tuple[Path, dict[str, Any], str] | None,
) -> tuple[dict[str, Any], str | None]:
    """Apply only the closure overlay authenticated by the maintenance authority."""

    if canonical_predecessor is None:
        if closure_loaded is not None:
            raise ValueError(
                "hotfix follow-up closure requires the authenticated predecessor authority"
            )
        return baseline, None
    closure_digest = canonical_predecessor.follow_up_closure_digest
    if (
        (closure_loaded is None) != (closure_digest is None)
        or (
            closure_loaded is not None
            and closure_loaded[2] != closure_digest
        )
    ):
        raise ValueError(
            "hotfix follow-up closure differs from the authenticated predecessor authority"
        )
    effective_baseline = copy.deepcopy(baseline)
    effective_follow_up = canonical_predecessor.outstanding_follow_up
    if effective_follow_up is None:
        effective_baseline.pop("hotfixFollowUp", None)
    else:
        effective_baseline["hotfixFollowUp"] = copy.deepcopy(
            effective_follow_up
        )
    return effective_baseline, closure_digest


def _authenticate_predecessor(
    context: RunContext,
    inputs: dict[str, tuple[Path, dict[str, Any], str] | None],
    inspector: GitInspector,
    *,
    authenticate_chain: bool = True,
) -> tuple[str, str, str, str, dict[str, Any], str | None]:
    canonical_predecessor = None
    if authenticate_chain:
        authority_state = ValidationState()
        ga_root = authenticate_stable_ga_root(context, authority_state)
        canonical_predecessor = authenticate_stable_predecessor(
            context, ga_root, authority_state
        )
        if authority_state.blockers:
            raise ValueError(
                "predecessor is not authenticated by the Stable GA root and successor chain"
            )
    baseline_loaded = inputs["predecessorBaseline"]
    receipt_loaded = inputs["predecessorPublicationReceipt"]
    pointer_loaded = inputs["latestPublishedMaintenancePointer"]
    closure_loaded = inputs.get("hotfixFollowUpClosure")
    assert baseline_loaded and receipt_loaded
    baseline_path, baseline, baseline_digest = baseline_loaded
    receipt_path, receipt, receipt_digest = receipt_loaded
    authenticated_inputs = [(baseline_path, baseline), (receipt_path, receipt)]
    if pointer_loaded is not None:
        authenticated_inputs.append((pointer_loaded[0], pointer_loaded[1]))
    if closure_loaded is not None:
        authenticated_inputs.append((closure_loaded[0], closure_loaded[1]))
    for path, value in authenticated_inputs:
        if not _canonical_json_input(path, value):
            raise ValueError("authenticated predecessor input is not canonical JSON")
        if scan_value(value):
            raise ValueError("authenticated predecessor input failed redaction")
    baseline_kind = baseline.get("kind")
    if baseline_kind == "stable-1.0-maintenance-successor-baseline":
        _schema_or_raise(
            baseline,
            "stable-1.0-maintenance-successor-baseline-v2.schema.json",
            "predecessor baseline",
        )
    elif baseline_kind == "stable-1.0-maintenance-baseline":
        _schema_or_raise(
            baseline,
            "stable-1.0-maintenance-baseline-v1.schema.json",
            "predecessor baseline",
        )
    else:
        raise ValueError("predecessor baseline kind is unsupported")
    receipt_kind = receipt.get("kind")
    if receipt_kind == "stable-1.0-maintenance-publication-receipt":
        _schema_or_raise(
            receipt,
            "stable-1.0-maintenance-publication-receipt-v1.schema.json",
            "predecessor publication receipt",
        )
        if (
            receipt.get("publicationState") != "publication-complete"
            or receipt.get("finalVerificationStatus") != "pass"
        ):
            raise ValueError("predecessor maintenance publication is not verified")
    elif receipt_kind == "stable-1.0-ga-publication-receipt":
        _schema_or_raise(
            receipt,
            "stable-1.0-ga-publication-receipt-v1.schema.json",
            "predecessor publication receipt",
        )
        if receipt.get("publicationState") != "publication-complete":
            raise ValueError("predecessor GA publication is not complete")
    else:
        raise ValueError("predecessor publication receipt kind is unsupported")
    if (
        baseline_kind == "stable-1.0-maintenance-successor-baseline"
        and receipt_kind != "stable-1.0-maintenance-publication-receipt"
    ) or (
        baseline_kind == "stable-1.0-maintenance-baseline"
        and receipt_kind != "stable-1.0-ga-publication-receipt"
    ):
        raise ValueError("predecessor baseline and publication receipt classes disagree")
    release = baseline.get("release")
    release = release if isinstance(release, dict) else {}
    predecessor_build = str(release.get("buildVersion", ""))
    predecessor_commit = str(release.get("sourceCommit", ""))
    expected_build = str(context.manifest.policies.get("expectedPredecessorBuild", ""))
    if (
        predecessor_build != expected_build
        or receipt.get("buildVersion") != predecessor_build
        or receipt.get("sourceCommit") != predecessor_commit
        or receipt.get("tag", {}).get("name") != f"v{predecessor_build}"
        or receipt.get("tag", {}).get("targetCommit") != predecessor_commit
    ):
        raise ValueError("predecessor baseline and publication receipt identities disagree")
    inspector.validate_commit_oid(predecessor_commit)
    if baseline_kind == "stable-1.0-maintenance-baseline":
        if pointer_loaded is not None:
            raise ValueError(
                "authenticated GA-root predecessor requires maintenance pointer absence"
            )
        if closure_loaded is not None:
            raise ValueError(
                "authenticated GA-root predecessor cannot consume a hotfix follow-up closure"
            )
        ga_root_digest = semantic_digest(
            {
                "baselineDigest": baseline_digest,
                "publicationReceiptDigest": receipt_digest,
            }
        )
        result = (
            predecessor_commit,
            predecessor_build,
            ga_root_digest,
            receipt_digest,
            baseline,
            None,
        )
        if canonical_predecessor is not None and (
            canonical_predecessor.baseline_digest != baseline_digest
            or canonical_predecessor.receipt_digest != receipt_digest
            or canonical_predecessor.source_commit != predecessor_commit
            or canonical_predecessor.build_version != predecessor_build
            or canonical_predecessor.latest_pointer_digest is not None
        ):
            raise ValueError(
                "GA-root predecessor differs from the authenticated Stable authority chain"
            )
        return result
    if pointer_loaded is None:
        raise ValueError("maintenance predecessor requires the exact latest pointer")
    _pointer_path, pointer, pointer_digest = pointer_loaded
    required_pointer = {
        "kind": "stable-1.0-maintenance-latest-published",
        "releaseId": release.get("releaseId"),
        "buildVersion": predecessor_build,
        "baselineDigest": baseline_digest,
        "publicationReceiptDigest": receipt_digest,
        "status": "active",
    }
    if any(pointer.get(key) != value for key, value in required_pointer.items()):
        raise ValueError("latest pointer does not select the exact supplied predecessor")
    pointer_train_digest = pointer.get("backportReleaseTrainDigest")
    baseline_train = baseline.get("releaseTrain")
    if isinstance(baseline_train, dict):
        if pointer_train_digest != baseline_train.get("validationDigest"):
            raise ValueError("latest pointer release-train identity was substituted")
    elif pointer_train_digest is not None:
        raise ValueError("GA-root predecessor unexpectedly names a maintenance train")
    if canonical_predecessor is not None and (
        canonical_predecessor.baseline_digest != baseline_digest
        or canonical_predecessor.receipt_digest != receipt_digest
        or canonical_predecessor.source_commit != predecessor_commit
        or canonical_predecessor.build_version != predecessor_build
        or canonical_predecessor.latest_pointer_digest != pointer_digest
    ):
        raise ValueError(
            "maintenance predecessor differs from the authenticated Stable authority chain"
        )
    effective_baseline, follow_up_closure_digest = (
        _closure_adjusted_predecessor_baseline(
            baseline,
            canonical_predecessor,
            closure_loaded,
        )
    )
    return (
        predecessor_commit,
        predecessor_build,
        pointer_digest,
        receipt_digest,
        effective_baseline,
        follow_up_closure_digest,
    )


def _authenticate_lifecycle(
    inputs: dict[str, tuple[Path, dict[str, Any], str] | None],
    predecessor_build: str,
    release_class: str,
) -> tuple[str, dict[str, str]]:
    ledger_loaded = inputs["previousStableLifecycleLedger"]
    descriptor_loaded = inputs["previousStableLifecycleDescriptor"]
    assert ledger_loaded and descriptor_loaded
    ledger_path, ledger, ledger_file_digest = ledger_loaded
    descriptor_path, descriptor, _descriptor_file_digest = descriptor_loaded
    _schema_or_raise(
        ledger,
        "stable-1.0-support-lifecycle-ledger-v1.schema.json",
        "lifecycle ledger",
    )
    _schema_or_raise(
        descriptor,
        "stable-1.0-support-lifecycle-descriptor-v1.schema.json",
        "lifecycle descriptor",
    )
    if (
        not _canonical_json_input(ledger_path, ledger)
        or not _canonical_json_input(descriptor_path, descriptor)
        or scan_value(ledger)
        or scan_value(descriptor)
    ):
        raise ValueError("lifecycle state is not canonical or public-safe")
    if ledger.get("ledgerDigest") != canonical_identity_digest(ledger, "ledgerDigest"):
        raise ValueError("lifecycle ledger semantic digest is inconsistent")
    if descriptor.get("descriptorDigest") != canonical_identity_digest(
        descriptor, "descriptorDigest"
    ):
        raise ValueError("lifecycle descriptor semantic digest is inconsistent")
    if descriptor.get("ledgerDigest") != ledger.get("ledgerDigest"):
        raise ValueError("lifecycle descriptor does not select the immediate predecessor")
    statuses: dict[str, str] = {}
    for entry in descriptor.get("entries", []):
        if isinstance(entry, dict):
            build = entry.get("buildVersion")
            status = entry.get("lifecycleStatus")
            if isinstance(build, str) and isinstance(status, str):
                statuses[build] = status
    predecessor_status = statuses.get(predecessor_build)
    if release_class == "maintenance" and predecessor_status != "current-stable":
        raise ValueError("routine predecessor is not current-stable in lifecycle state")
    if release_class == "security-hotfix" and predecessor_status not in {
        "current-stable",
        "supported-maintenance",
        "security-fixes-only",
        "deprecated",
        "revoked",
    }:
        raise ValueError("security-hotfix predecessor is not lifecycle eligible")
    return ledger_file_digest, statuses


def _authenticate_lifecycle_authority(
    context: RunContext,
    inputs: dict[str, tuple[Path, dict[str, Any], str] | None],
    *,
    release_class: str,
    now: dt.datetime,
    hotfix_scope: dict[str, Any] | None,
) -> dt.datetime:
    policy_loaded = inputs["stableLifecyclePolicy"]
    ledger_loaded = inputs["previousStableLifecycleLedger"]
    descriptor_loaded = inputs["previousStableLifecycleDescriptor"]
    authorization_loaded = inputs["previousStableLifecycleAuthorization"]
    plan_loaded = inputs["previousStableLifecyclePublicationPlan"]
    receipt_loaded = inputs["previousStableLifecyclePublicationReceipt"]
    observation_loaded = inputs["stableLifecyclePublicObservationReceipt"]
    assert (
        policy_loaded
        and ledger_loaded
        and descriptor_loaded
        and authorization_loaded
        and plan_loaded
        and receipt_loaded
        and observation_loaded
    )
    policy_path, policy, policy_digest = policy_loaded
    expected_policy_path = (
        context.workspace_root
        / "tools/release-certification/stable-1.0-support-lifecycle-policy.json"
    ).resolve(strict=True)
    if policy_path != expected_policy_path:
        raise ValueError("lifecycle authority uses a noncanonical policy path")
    _schema_or_raise(
        policy,
        "stable-1.0-support-lifecycle-policy-v1.schema.json",
        "Stable lifecycle policy",
    )
    authority_inputs = (
        policy_loaded,
        ledger_loaded,
        descriptor_loaded,
        authorization_loaded,
        plan_loaded,
        receipt_loaded,
        observation_loaded,
    )
    if any(
        not _canonical_json_input(path, value)
        for path, value, _digest in authority_inputs
        if path != policy_path
    ) or any(
        scan_value(value)
        for path, value, _digest in authority_inputs
        if path != policy_path
    ):
        raise ValueError("lifecycle authority chain is not canonical and public-safe")
    authority_state = ValidationState()
    ga_root = authenticate_stable_ga_root(context, authority_state)
    predecessor = authenticate_stable_predecessor(
        context, ga_root, authority_state
    )
    if authority_state.blockers:
        raise ValueError(
            "lifecycle authority predecessor is not rooted in the Stable publication chain"
        )
    errors = authenticated_lifecycle_errors(
        ledger_loaded[1],
        descriptor_loaded[1],
        authorization_loaded[1],
        plan_loaded[1],
        receipt_loaded[1],
        authorization_loaded[2],
        descriptor_loaded[2],
        policy_digest,
        predecessor,
        release_class,
        now,
        hotfix_scope,
    )
    support_windows = policy.get("supportWindows")
    support_windows = (
        support_windows if isinstance(support_windows, dict) else {}
    )
    maximum_observation_age = support_windows.get(
        "maximumPublicObservationAgeMinutes"
    )
    if type(maximum_observation_age) is not int or maximum_observation_age < 1:
        errors.append(
            "lifecycle policy public-observation freshness window is invalid"
        )
        maximum_observation_age = 0
    errors.extend(
        public_lifecycle_observation_errors(
            observation_loaded[1],
            ledger_loaded[1],
            descriptor_loaded[1],
            authorization_loaded[1],
            plan_loaded[1],
            receipt_loaded[1],
            authorization_loaded[2],
            descriptor_loaded[2],
            now,
            maximum_observation_age,
        )
    )
    _raise_errors(errors, "Stable lifecycle authority chain")
    observed_at = parse_timestamp(observation_loaded[1].get("generatedAt"))
    if observed_at is None:
        raise ValueError("Stable lifecycle public observation time is malformed")
    return observed_at


def _provenance_dict(value: PatchProvenance, branch_role: str) -> dict[str, Any]:
    return {
        "mode": value.mode,
        "candidateCommit": value.candidate_commit,
        "candidateBranchRole": branch_role,
        "stablePatchId": value.stable_patch_id,
        "sourceTreeOid": value.source_tree_oid,
        "sourceTreeDigest": value.source_tree_digest,
        "sourceDiffDigest": value.source_diff_digest,
        "candidateTreeOid": value.candidate_tree_oid,
        "candidateTreeDigest": value.candidate_tree_digest,
        "candidateDiffDigest": value.candidate_diff_digest,
        "touchedPaths": list(value.touched_paths),
        "mergeBaseCommit": value.merge_base_commit,
        "sourceBaseCommit": value.source_base_commit,
        "targetBaseCommit": value.target_base_commit,
        "conflictPaths": list(value.conflict_paths),
        "normalizedDiffEvidenceDigest": value.normalized_diff_evidence_digest,
        "reviewerAuthorizationDigest": value.reviewer_authorization_digest,
        "focusedTestEvidenceIds": list(value.focused_test_evidence_ids),
        "noUnrelatedFeatureChange": value.no_unrelated_feature_change,
    }


def _authenticate_review_authorizations(
    loaded: tuple[Path, dict[str, Any], str] | None,
    *,
    intake: dict[str, Any],
    policy: dict[str, Any],
    policy_digest: str,
    now: dt.datetime,
) -> dict[str, dict[str, Any]]:
    """Authenticate the exact protected-workflow approval for each reviewed patch."""

    reviewed_fixes = {
        str(row.get("fixId")): row
        for row in intake.get("fixes", [])
        if isinstance(row, dict)
        and isinstance(row.get("provenance"), dict)
        and row["provenance"].get("mode")
        in {"clean-cherry-pick", "manual-conflict-resolution"}
        and row.get("state") not in {"released", "rejected", "superseded"}
    }
    if not reviewed_fixes:
        if loaded is not None:
            raise ValueError(
                "protected provenance-review authorizations appeared without "
                "a reviewed backport"
            )
        return {}
    if loaded is None:
        raise ValueError(
            "reviewed backport lacks protected provenance-review authorization artifacts"
        )
    path, value, _file_digest = loaded
    if not _canonical_json_input(path, value):
        raise ValueError(
            "protected provenance-review authorization set is not canonical JSON"
        )
    _schema_or_raise(
        value,
        REVIEW_AUTHORIZATIONS_SCHEMA,
        "protected provenance-review authorization set",
    )
    generated_at = parse_timestamp(value.get("generatedAt"))
    if (
        generated_at is None
        or generated_at > now
        or value.get("repositoryIdentity") != REPOSITORY_IDENTITY
        or value.get("policyDigest") != policy_digest
        or value.get("authorizationSetDigest")
        != canonical_identity_digest(value, "authorizationSetDigest")
    ):
        raise ValueError(
            "protected provenance-review authorization set has an invalid identity"
        )
    rows = value.get("authorizations")
    rows = rows if isinstance(rows, list) else []
    fix_ids = [row.get("fixId") for row in rows if isinstance(row, dict)]
    artifact_rows = value.get("authenticatedArtifacts")
    artifact_rows = artifact_rows if isinstance(artifact_rows, list) else []
    artifact_fix_ids = [
        row.get("fixId") for row in artifact_rows if isinstance(row, dict)
    ]
    if (
        len(fix_ids) != len(rows)
        or fix_ids != sorted(fix_ids)
        or len(fix_ids) != len(set(fix_ids))
        or set(fix_ids) != set(reviewed_fixes)
        or len(artifact_fix_ids) != len(artifact_rows)
        or artifact_fix_ids != sorted(artifact_fix_ids)
        or len(artifact_fix_ids) != len(set(artifact_fix_ids))
        or artifact_fix_ids != fix_ids
    ):
        raise ValueError(
            "protected provenance-review authorization set does not exactly "
            "cover the reviewed fixes"
        )
    authorization_policy = policy.get("authorization")
    authorization_policy = (
        authorization_policy if isinstance(authorization_policy, dict) else {}
    )
    maximum_validity = dt.timedelta(
        hours=int(
            authorization_policy.get(
                "provenanceReviewMaximumValidityHours", 0
            )
        )
    )
    workflow_path = authorization_policy.get("provenanceReviewWorkflow")
    environment = authorization_policy.get("provenanceReviewEnvironment")
    if (
        maximum_validity <= dt.timedelta(0)
        or not isinstance(workflow_path, str)
        or not isinstance(environment, str)
    ):
        raise ValueError("provenance-review authorization policy is invalid")
    provenance_policy = policy.get("provenancePolicy")
    provenance_policy = (
        provenance_policy if isinstance(provenance_policy, dict) else {}
    )
    authenticated: dict[str, dict[str, Any]] = {}
    artifacts_by_fix = {
        str(row["fixId"]): row for row in artifact_rows if isinstance(row, dict)
    }
    for row in rows:
        assert isinstance(row, dict)
        fix_id = str(row.get("fixId"))
        fix = reviewed_fixes[fix_id]
        provenance = fix["provenance"]
        source = fix.get("source")
        source = source if isinstance(source, dict) else {}
        producer = row.get("producer")
        producer = producer if isinstance(producer, dict) else {}
        artifact = artifacts_by_fix[fix_id]
        workflow_commit = producer.get("workflowCommit")
        expected_workflow = (
            f"crypta-network/cryptad/{workflow_path}@{workflow_commit}"
        )
        issued_at = parse_timestamp(row.get("issuedAt"))
        expires_at = parse_timestamp(row.get("expiresAt"))
        mode = provenance.get("mode")
        role_field = (
            "cleanCherryPickReviewerRole"
            if mode == "clean-cherry-pick"
            else "manualConflictReviewerRole"
        )
        mode_policy = provenance_policy.get(mode)
        mode_policy = mode_policy if isinstance(mode_policy, dict) else {}
        evidence_id = mode_policy.get("reviewEvidenceId")
        review_rows = [
            evidence
            for evidence in fix.get("evidence", [])
            if isinstance(evidence, dict)
            and evidence.get("evidenceId") == evidence_id
        ]
        evidence_generated = (
            parse_timestamp(review_rows[0].get("generatedAt"))
            if len(review_rows) == 1
            else None
        )
        if (
            row.get("authorizationDigest")
            != canonical_identity_digest(row, "authorizationDigest")
            or row.get("repositoryIdentity") != REPOSITORY_IDENTITY
            or row.get("policyDigest") != policy_digest
            or row.get("provenanceMode") != mode
            or row.get("reviewerRole")
            != authorization_policy.get(role_field)
            or row.get("sourceCommit") != source.get("sourceCommit")
            or row.get("candidateCommit") != provenance.get("candidateCommit")
            or row.get("normalizedDiffEvidenceDigest")
            != provenance.get("normalizedDiffEvidenceDigest")
            or row.get("pathInventoryDigest")
            != semantic_digest(
                {
                    "conflictPaths": sorted(
                        provenance.get("conflictPaths", [])
                    ),
                    "touchedPaths": sorted(
                        provenance.get("touchedPaths", [])
                    ),
                }
            )
            or row.get("focusedTestEvidenceIds")
            != provenance.get("focusedTestEvidenceIds")
            or row.get("reviewEvidenceId") != evidence_id
            or row.get("producerAuthenticated") is not True
            or producer.get("workflowIdentity") != expected_workflow
            or artifact.get("workflowRef") != expected_workflow
            or artifact.get("sourceCommit") != workflow_commit
            or artifact.get("runId") != producer.get("runId")
            or artifact.get("artifactName") != producer.get("artifactName")
            or producer.get("environment") != environment
            or producer.get("operation") != "authorize-provenance-review"
            or issued_at is None
            or expires_at is None
            or evidence_generated is None
            or issued_at < evidence_generated
            or issued_at > now
            or expires_at <= issued_at
            or expires_at - issued_at > maximum_validity
            or expires_at <= now
        ):
            raise ValueError(
                f"fix {fix_id} provenance review is not bound to an exact "
                "protected reviewer authorization"
            )
        authenticated[fix_id] = row
    return authenticated


def _verify_fix_provenance(
    inspector: GitInspector,
    fix: dict[str, Any],
    candidate_tip: str,
    branch_role: str,
    policy: dict[str, Any],
    review_authorization: dict[str, Any] | None,
) -> PatchProvenance:
    source = fix.get("source")
    source = source if isinstance(source, dict) else {}
    declared = fix.get("provenance")
    declared = declared if isinstance(declared, dict) else {}
    ownership = fix.get("ownership")
    ownership = ownership if isinstance(ownership, dict) else {}
    _verify_fix_source_identity(inspector, fix)
    source_commit = str(source.get("sourceCommit", ""))
    authorization_digest = declared.get("reviewerAuthorizationDigest")
    if not isinstance(authorization_digest, str):
        authorization_digest = ownership.get("authorizationDigest")
    mode = declared.get("mode")
    if mode == "inherited":
        actual = inspector.verify_inherited(
            source_commit, candidate_tip, str(authorization_digest)
        )
    elif mode == "clean-cherry-pick":
        review_errors = clean_cherry_pick_review_errors(
            fix, policy, review_authorization
        )
        if review_errors:
            raise GitInspectionError(review_errors[0])
        actual = inspector.verify_clean_cherry_pick(
            source_commit,
            str(declared.get("candidateCommit", "")),
            candidate_tip,
            str(authorization_digest),
            declared.get("touchedPaths", []),
        )
    elif mode == "manual-conflict-resolution":
        review_errors = manual_conflict_review_errors(
            fix, policy, review_authorization
        )
        if review_errors:
            raise GitInspectionError(review_errors[0])
        actual = inspector.verify_manual_conflict_resolution(
            source_commit=source_commit,
            candidate_commit=str(declared.get("candidateCommit", "")),
            candidate_tip=candidate_tip,
            source_base_commit=str(declared.get("sourceBaseCommit", "")),
            target_base_commit=str(declared.get("targetBaseCommit", "")),
            expected_merge_base_commit=str(declared.get("mergeBaseCommit", "")),
            conflict_paths=declared.get("conflictPaths", []),
            allowed_paths=declared.get("touchedPaths", []),
            reviewer_authorization_digest=str(authorization_digest),
            focused_test_evidence_ids=declared.get("focusedTestEvidenceIds", []),
            normalized_diff_evidence_digest=str(
                declared.get("normalizedDiffEvidenceDigest", "")
            ),
            no_unrelated_feature_change=bool(
                declared.get("noUnrelatedFeatureChange")
            ),
        )
    else:
        raise GitInspectionError("fix provenance mode is unsupported")
    actual_dict = _provenance_dict(actual, branch_role)
    if actual_dict != declared:
        raise GitInspectionError("declared source-to-candidate provenance was substituted")
    return actual


def _verify_fix_source_identity(
    inspector: GitInspector,
    fix: dict[str, Any],
) -> None:
    source = fix.get("source")
    source = source if isinstance(source, dict) else {}
    if source.get("repositoryIdentity") != REPOSITORY_IDENTITY:
        raise GitInspectionError("fix source is bound to a different repository")
    if source.get("objectFormat") != inspector.object_format:
        raise GitInspectionError("fix source object format does not match the repository")
    inspector.inspect_commit(str(source.get("sourceCommit", "")))


def _coverage_category(fix: dict[str, Any]) -> str:
    classification = fix.get("classification")
    if classification == "release-tooling-fix":
        scope = fix.get("affectedScope")
        components = (
            scope.get("components", []) if isinstance(scope, dict) else []
        )
        if "release-metadata" in components:
            return "approved-release-metadata"
        return "approved-release-tooling"
    if classification == "documentation-support-fix":
        return "approved-docs-support"
    return "accepted-fix"


def _candidate_coverage(
    inspector: GitInspector,
    predecessor_commit: str,
    candidate_commit: str,
    fixes: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    candidate_commits = inspector.candidate_commits(
        predecessor_commit, candidate_commit
    )
    candidate_commit_set = set(candidate_commits)
    commit_to_fix: dict[str, dict[str, Any]] = {}
    for fix in fixes:
        provenance = fix.get("provenance")
        provenance = provenance if isinstance(provenance, dict) else {}
        mapped = provenance.get("candidateCommit")
        if isinstance(mapped, str):
            if mapped not in candidate_commit_set:
                raise GitInspectionError(
                    "accepted fix commit is outside the predecessor-to-candidate change set"
                )
            existing = commit_to_fix.get(mapped)
            if existing is not None and existing.get("fixId") != fix.get("fixId"):
                raise GitInspectionError(
                    "candidate commit is assigned to more than one accepted fix"
                )
            commit_to_fix[mapped] = fix
    coverage: list[dict[str, Any]] = []
    unaccounted: list[str] = []
    for commit in candidate_commits:
        inspected = inspector.inspect_commit(commit)
        fix = commit_to_fix.get(commit)
        merge_resolution_paths = (
            inspector.merge_resolution_paths(commit) if inspected.is_merge else ()
        )
        if fix is not None:
            category = _coverage_category(fix)
            fix_id: str | None = str(fix.get("fixId"))
        elif inspected.is_merge and not merge_resolution_paths:
            category = "merge-context"
            fix_id = None
        else:
            category = "unaccounted"
            fix_id = None
            unaccounted.append(commit)
        entry = {
            "commit": commit,
            "category": category,
            "fixId": fix_id,
            "evidenceDigest": semantic_digest(
                {
                    "commit": commit,
                    "category": category,
                    "fixId": fix_id,
                    "parents": list(inspected.parents),
                    "paths": list(inspected.touched_paths),
                    "mergeResolutionPaths": list(merge_resolution_paths),
                    "diffDigest": inspected.diff_digest,
                }
            ),
            "parentCommits": list(inspected.parents),
            "touchedPaths": list(inspected.touched_paths),
            "mergeResolutionPaths": list(merge_resolution_paths),
            "diffDigest": inspected.diff_digest,
        }
        coverage.append(entry)
    return coverage, sorted(unaccounted)


def _public_fix(fix: dict[str, Any]) -> dict[str, Any]:
    scope = fix.get("affectedScope")
    components = (
        scope.get("components", []) if isinstance(scope, dict) else []
    )
    provenance = fix.get("provenance")
    provenance = provenance if isinstance(provenance, dict) else {}
    security = fix.get("security")
    security = security if isinstance(security, dict) else {}
    return {
        "fixId": fix.get("fixId"),
        "classification": fix.get("classification"),
        "severity": fix.get("severity"),
        "publicSummary": fix.get("publicSummary"),
        "affectedComponentSummary": ", ".join(sorted(str(row) for row in components)),
        "provenanceMode": provenance.get("mode"),
        "lineageDigest": semantic_digest(
            {
                "fixId": fix.get("fixId"),
                "sourceCommit": fix.get("source", {}).get("sourceCommit"),
                "candidateCommit": provenance.get("candidateCommit"),
                "provenanceMode": provenance.get("mode"),
                "sourceDiffDigest": provenance.get("sourceDiffDigest"),
                "candidateDiffDigest": provenance.get("candidateDiffDigest"),
            }
        ),
        "publicProjectionDigest": fix.get("publicProjectionDigest"),
        "incidentOpaqueId": security.get("incidentOpaqueId") if security else None,
        "advisoryOpaqueId": security.get("advisoryOpaqueId") if security else None,
        "publicSecuritySummary": (
            security.get("publicSafeSummary") if security else None
        ),
        "securityPublicProjectionDigest": (
            security.get("publicProjectionDigest") if security else None
        ),
        "disclosureState": security.get("disclosureState") if security else None,
    }


def _public_queue(queue: dict[str, Any]) -> dict[str, Any]:
    """Build the bounded queue projection that may cross a public artifact boundary."""

    public_fixes = sorted(
        (_public_fix(row) for row in queue.get("fixes", []) if isinstance(row, dict)),
        key=lambda row: str(row.get("fixId")),
    )
    public_obligations = sorted(
        (
            {
                "obligationId": row.get("obligationId"),
                "obligationType": row.get("obligationType"),
                "status": row.get("status"),
            }
            for row in queue.get("obligations", [])
            if isinstance(row, dict)
        ),
        key=lambda row: str(row.get("obligationId")),
    )
    fix_evolution = sorted(
        (
            {
                "fixId": row.get("fixId"),
                "transitionDigests": [
                    semantic_digest(transition)
                    for transition in row.get("stateTransitions", [])
                    if isinstance(transition, dict)
                ],
            }
            for row in queue.get("fixes", [])
            if isinstance(row, dict)
        ),
        key=lambda row: str(row.get("fixId")),
    )
    value = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "stable-1.0-release-train-queue-public",
        "generatedAt": queue.get("generatedAt"),
        "stableMilestone": STABLE_MILESTONE,
        "policyDigest": queue.get("policyDigest"),
        "repositoryIdentity": queue.get("repositoryIdentity"),
        "queueId": queue.get("queueId"),
        "previousQueueDigest": queue.get("previousQueueDigest"),
        "candidateCommit": queue.get("candidateCommit"),
        "queueDigest": queue.get("queueDigest"),
        "status": queue.get("status"),
        "intakeCompositionDigest": phase_intake_composition_digest(queue),
        "publicFixes": public_fixes,
        "fixEvolution": fix_evolution,
        "obligations": public_obligations,
        "unresolvedFixIds": list(queue.get("unresolvedFixIds", [])),
        "criticalFixIds": list(queue.get("criticalFixIds", [])),
        "deferredFixIds": list(queue.get("deferredFixIds", [])),
        "rejectedFixIds": list(queue.get("rejectedFixIds", [])),
        "supersededFixIds": list(queue.get("supersededFixIds", [])),
        "carriedObligationIds": list(queue.get("carriedObligationIds", [])),
        "redaction": dict(_PASS_REDACTION),
    }
    value["projectionDigest"] = canonical_identity_digest(
        value, "projectionDigest"
    )
    return value


def _fix_sets(
    fixes: list[dict[str, Any]], lane: str
) -> tuple[list[dict[str, Any]], list[str], list[str], list[str]]:
    accepted = sorted(
        (
            fix
            for fix in fixes
            if fix.get("releaseLane") == lane and fix.get("state") in _ACTIVE_STATES
        ),
        key=lambda row: str(row.get("fixId")),
    )
    deferred = sorted(
        str(fix.get("fixId"))
        for fix in fixes
        if fix.get("state") == "deferred"
    )
    rejected = sorted(
        str(fix.get("fixId"))
        for fix in fixes
        if fix.get("state") == "rejected"
    )
    superseded = sorted(
        str(fix.get("fixId"))
        for fix in fixes
        if fix.get("state") == "superseded"
    )
    return accepted, deferred, rejected, superseded


def _authenticate_released_transitions(
    intake: dict[str, Any],
    previous_queue: dict[str, Any] | None,
    completion_loaded: tuple[Path, dict[str, Any], str] | None,
    completion_handoff_loaded: tuple[Path, dict[str, Any], str] | None,
    previous_validation_loaded: tuple[Path, dict[str, Any], str] | None,
    predecessor_receipt_loaded: tuple[Path, dict[str, Any], str] | None,
    policy: dict[str, Any],
    inspector: GitInspector,
    now: dt.datetime,
) -> None:
    current_fixes = {
        row.get("fixId"): row
        for row in intake.get("fixes", [])
        if isinstance(row, dict) and isinstance(row.get("fixId"), str)
    }
    prior_fixes = {
        row.get("fixId"): row
        for row in (
            previous_queue.get("fixes", [])
            if isinstance(previous_queue, dict)
            else []
        )
        if isinstance(row, dict) and isinstance(row.get("fixId"), str)
    }
    prior_included_fix_ids: list[str] = []
    if previous_validation_loaded is not None:
        included = previous_validation_loaded[1].get("includedFixIds")
        if not isinstance(included, list) or any(
            not isinstance(row, str) for row in included
        ):
            raise ValueError(
                "prior authorized validation has malformed included fix identities"
            )
        prior_included_fix_ids = included
        for fix_id in prior_included_fix_ids:
            prior = prior_fixes.get(fix_id)
            current = current_fixes.get(fix_id)
            if (
                not isinstance(prior, dict)
                or prior.get("state") != "verified"
                or not isinstance(current, dict)
                or current.get("state") != "released"
            ):
                raise ValueError(
                    "every fix included by the prior authorized validation must "
                    "transition from verified to released through exact completion"
                )
    transitioned = [
        row
        for fix_id, row in current_fixes.items()
        if row.get("state") == "released"
        and prior_fixes.get(fix_id, {}).get("state") != "released"
    ]
    if not transitioned:
        return
    if previous_queue is None:
        raise ValueError(
            "released fix state cannot appear before an authenticated prior queue"
        )
    for fix in transitioned:
        prior = prior_fixes.get(fix.get("fixId"))
        if not isinstance(prior, dict) or prior.get("state") != "verified":
            raise ValueError(
                "released fix did not exist in verified state in the prior queue"
            )
    if completion_loaded is None:
        raise ValueError(
            "released fix transition lacks exact verified completion evidence"
        )
    if completion_handoff_loaded is None:
        raise ValueError(
            "released fix transition lacks an authenticated protected-workflow "
            "completion handoff"
        )
    if previous_validation_loaded is None or predecessor_receipt_loaded is None:
        raise ValueError(
            "released fix transition lacks its authenticated validation or "
            "publication receipt"
        )
    completion_path, completion, completion_file_digest = completion_loaded
    validation_path, previous_validation, validation_file_digest = (
        previous_validation_loaded
    )
    receipt_path, predecessor_receipt, predecessor_receipt_digest = (
        predecessor_receipt_loaded
    )
    handoff_path, completion_handoff, _handoff_file_digest = (
        completion_handoff_loaded
    )
    _schema_or_raise(
        completion, COMPLETION_SCHEMA, "prior release-train completion"
    )
    _schema_or_raise(
        previous_validation,
        VALIDATION_SCHEMA,
        "prior release-train validation",
    )
    _schema_or_raise(
        predecessor_receipt,
        "stable-1.0-maintenance-publication-receipt-v1.schema.json",
        "prior Stable maintenance publication receipt",
    )
    _schema_or_raise(
        completion_handoff,
        COMPLETION_HANDOFF_SCHEMA,
        "prior completion protected-workflow handoff",
    )
    authorization = previous_validation.get("authorization")
    authorization = authorization if isinstance(authorization, dict) else {}
    release = previous_validation.get("release")
    release = release if isinstance(release, dict) else {}
    release_class = release.get("releaseClass")
    lane = (
        "routine-maintenance"
        if release_class == "maintenance"
        else "security-hotfix"
        if release_class == "security-hotfix"
        else ""
    )
    if (
        not _canonical_json_input(completion_path, completion)
        or not _canonical_json_input(handoff_path, completion_handoff)
        or not _canonical_json_input(validation_path, previous_validation)
        or not _canonical_json_input(receipt_path, predecessor_receipt)
        or scan_value(completion)
        or scan_value(completion_handoff)
        or _scan_public_artifact(
            "prior release-train validation", previous_validation
        )
        or scan_value(predecessor_receipt)
        or completion.get("completionDigest")
        != canonical_identity_digest(completion, "completionDigest")
        or completion.get("queueDigest") != previous_queue.get("queueDigest")
        or completion.get("status") != "complete"
        or previous_validation.get("mode") != "validate-authorization"
        or previous_validation.get("decision") != "go"
        or previous_validation.get("validationDigest")
        != canonical_identity_digest(
            previous_validation, "validationDigest"
        )
        or previous_validation.get("queueDigest")
        != previous_queue.get("queueDigest")
        or authorization.get("status") != "valid"
        or not isinstance(authorization.get("authorizationDigest"), str)
        or not lane
        or completion.get("lifecycleState") not in {
            "activated",
            "pending-activation",
        }
    ):
        raise ValueError(
            "released fix transition does not bind an authenticated prior completion"
        )
    handoff_generated_at = parse_timestamp(completion_handoff.get("generatedAt"))
    receipt_generated_at = parse_timestamp(
        predecessor_receipt.get("generatedAt")
    )
    completion_generated_at = parse_timestamp(completion.get("generatedAt"))
    producer = completion_handoff.get("producer")
    producer = producer if isinstance(producer, dict) else {}
    observed_refs = completion_handoff.get("observedProtectedRefs")
    observed_refs = observed_refs if isinstance(observed_refs, dict) else {}
    release_id = release.get("releaseId")
    build_version = release.get("buildVersion")
    expected_artifact_name = (
        f"stable-1.0-backport-verify-release-completion-"
        f"{release_id}-{build_version}"
    )
    workflow_commit = producer.get("workflowCommit")
    expected_workflow_identity = (
        "crypta-network/cryptad/.github/workflows/"
        f"stable-1.0-backport-release-train.yml@{workflow_commit}"
    )
    producer_operation = producer.get("operation")
    evidence_source = producer.get("evidenceSource")
    evidence_digest = producer.get("evidenceDigest")
    producer_source_valid = (
        producer_operation == "verify-release-completion"
        and evidence_source == "actions-artifact"
        and producer.get("artifactName") == expected_artifact_name
    ) or (
        producer_operation == "reauthenticate-predecessor-completion"
        and evidence_source == "protected-input-bundle"
        and "artifactName" not in producer
    )
    if (
        handoff_generated_at is None
        or handoff_generated_at > now
        or completion_handoff.get("handoffDigest")
        != canonical_identity_digest(completion_handoff, "handoffDigest")
        or completion_handoff.get("repositoryIdentity") != REPOSITORY_IDENTITY
        or completion_handoff.get("trainId") != completion.get("trainId")
        or completion_handoff.get("candidateCommit")
        != completion.get("publicationCommit")
        or completion_handoff.get("completionFileDigest")
        != completion_file_digest
        or completion_handoff.get("completionDigest")
        != completion.get("completionDigest")
        or completion_handoff.get("validationFileDigest")
        != validation_file_digest
        or completion_handoff.get("validationDigest")
        != previous_validation.get("validationDigest")
        or completion_handoff.get("queueDigest")
        != previous_queue.get("queueDigest")
        or completion_handoff.get("producerAuthenticated") is not True
        or producer.get("workflowIdentity") != expected_workflow_identity
        or not isinstance(evidence_digest, str)
        or _DIGEST_RE.fullmatch(evidence_digest) is None
        or not producer_source_valid
        or receipt_generated_at is None
        or completion_generated_at is None
        or completion_generated_at < receipt_generated_at
        or handoff_generated_at < completion_generated_at
    ):
        raise ValueError(
            "prior completion handoff is not bound to an authenticated protected "
            "workflow evidence source"
        )
    release_transition_not_before = max(
        receipt_generated_at,
        completion_generated_at,
        handoff_generated_at,
    )
    intake_generated_at = parse_timestamp(intake.get("generatedAt"))
    if (
        intake_generated_at is None
        or intake_generated_at < release_transition_not_before
    ):
        raise ValueError(
            "released fix transition predates authenticated publication completion"
        )
    for role, expected_ref in (
        ("main", "refs/heads/main"),
        ("develop", "refs/heads/develop"),
    ):
        observed = observed_refs.get(role)
        observed = observed if isinstance(observed, dict) else {}
        merge = completion.get(f"{role}Merge")
        merge = merge if isinstance(merge, dict) else {}
        tip = observed.get("tip")
        merge_commit = merge.get("mergeCommit")
        try:
            if (
                observed.get("ref") != expected_ref
                or not isinstance(tip, str)
                or not isinstance(merge_commit, str)
            ):
                raise GitInspectionError(
                    "completion handoff protected ref is malformed"
                )
            inspector.validate_commit_oid(tip)
            inspector.validate_commit_oid(merge_commit)
            if not inspector.is_first_parent_ancestor(merge_commit, tip):
                raise GitInspectionError(
                    "completion merge is absent from the observed protected "
                    "branch first-parent chain"
                )
        except GitInspectionError as exc:
            raise ValueError(
                "prior completion handoff does not authenticate protected "
                "branch reconciliation"
            ) from exc
    included_fix_ids = previous_validation.get("includedFixIds")
    if not isinstance(included_fix_ids, list) or any(
        fix.get("fixId") not in included_fix_ids for fix in transitioned
    ) or sorted(included_fix_ids) != sorted(prior_included_fix_ids):
        raise ValueError(
            "released fix was not included in the prior authorized validation"
        )
    prior_completion_obligation_ids, obligation_errors = (
        permitted_carried_obligation_ids(
            previous_queue,
            previous_queue,
            lane=lane,
            policy=policy,
        )
    )
    _raise_errors(
        obligation_errors,
        "prior completion carried obligations",
    )
    verified_completion = _verify_completion_release_and_reconciliation(
        completion,
        predecessor_receipt,
        predecessor_receipt_digest,
        inspector=inspector,
        release=release,
        train_id=str(previous_validation.get("trainId", "")),
        lane=lane,
        policy_digest=str(previous_validation.get("policyDigest", "")),
        queue_digest=str(previous_queue.get("queueDigest", "")),
        validation_file_digest=validation_file_digest,
        authorization_digest=str(authorization["authorizationDigest"]),
        candidate_commit=str(previous_validation.get("candidateCommit", "")),
        expected_carried_obligation_ids=prior_completion_obligation_ids,
        source_fix_ids=sorted(included_fix_ids),
        reconciliation_policy=(
            policy.get("postReleaseReconciliation")
            if isinstance(policy.get("postReleaseReconciliation"), dict)
            else {}
        ),
    )
    if verified_completion != completion:
        raise ValueError(
            "prior completion artifact omits its derived reconciliation obligations"
        )
    current_obligations = {
        row.get("obligationId"): row
        for row in intake.get("obligations", [])
        if isinstance(row, dict)
        and isinstance(row.get("obligationId"), str)
    }
    completion_obligations = completion.get("reconciliationObligations")
    completion_obligations = (
        completion_obligations
        if isinstance(completion_obligations, list)
        else []
    )
    if any(
        not isinstance(row, dict)
        or current_obligations.get(row.get("obligationId")) != row
        for row in completion_obligations
    ):
        raise ValueError(
            "released fix transition omits an exact completion-created "
            "reconciliation obligation"
        )
    evidence_policy = policy.get("evidencePolicy")
    evidence_policy = (
        evidence_policy if isinstance(evidence_policy, dict) else {}
    )
    required_evidence_id = evidence_policy.get(
        "releasedStateCompletionEvidenceId"
    )
    prior_predecessor_commit = previous_validation.get("predecessorCommit")
    for fix in transitioned:
        matching_evidence = [
            row
            for row in fix.get("evidence", [])
            if isinstance(row, dict)
            and row.get("evidenceId") == required_evidence_id
            and row.get("digest") == completion_file_digest
            and row.get("predecessorCommit") == prior_predecessor_commit
            and row.get("candidateCommit") == completion.get("publicationCommit")
        ]
        history = fix.get("stateTransitions")
        last_transition = history[-1] if isinstance(history, list) and history else {}
        provenance = fix.get("provenance")
        provenance = provenance if isinstance(provenance, dict) else {}
        provenance_commit = str(provenance.get("candidateCommit", ""))
        schedule = fix.get("schedule")
        schedule = schedule if isinstance(schedule, dict) else {}
        publication_commit = str(completion.get("publicationCommit", ""))
        if len(matching_evidence) != 1:
            raise ValueError(
                "released fix transition is not bound to its exact completion "
                "artifact"
            )
        evidence_generated_at = (
            parse_timestamp(matching_evidence[0].get("generatedAt"))
        )
        transition_occurred_at = parse_timestamp(
            last_transition.get("occurredAt")
        )
        if (
            evidence_generated_at is None
            or transition_occurred_at is None
            or evidence_generated_at < release_transition_not_before
            or transition_occurred_at < release_transition_not_before
            or transition_occurred_at < evidence_generated_at
            or intake_generated_at < evidence_generated_at
            or intake_generated_at < transition_occurred_at
        ):
            raise ValueError(
                "released fix transition predates authenticated publication "
                "completion"
            )
        try:
            inspector.validate_commit_oid(provenance_commit)
            provenance_released = inspector.is_ancestor(
                provenance_commit, publication_commit
            )
        except GitInspectionError:
            provenance_released = False
        if (
            last_transition.get("to") != "released"
            or last_transition.get("evidenceDigest") != completion_file_digest
            or not provenance_released
            or schedule.get("targetTrainId") != completion.get("trainId")
        ):
            raise ValueError(
                "released fix transition is not bound to its exact completion artifact"
            )


def _required_evidence(
    fixes: list[dict[str, Any]],
    predecessor_commit: str,
    candidate_commit: str,
    now: dt.datetime,
    maximum_age: dt.timedelta,
    *,
    policy_digest: str,
    queue_digest: str,
    evidence_policy: dict[str, Any],
    provenance_policy: dict[str, Any],
) -> list[dict[str, Any]]:
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for fix in fixes:
        fix_id = fix.get("fixId")
        if not isinstance(fix_id, str):
            raise ValueError("fix evidence subject identity is malformed")
        provenance = fix.get("provenance")
        provenance = provenance if isinstance(provenance, dict) else {}
        provenance_mode = provenance.get("mode")
        mode_policy = provenance_policy.get(provenance_mode)
        mode_policy = mode_policy if isinstance(mode_policy, dict) else {}
        patch_bound_evidence_ids = {
            value
            for value in (mode_policy.get("reviewEvidenceId"),)
            if isinstance(value, str)
        }
        if mode_policy.get("candidateBoundFocusedTestsRequired") is True:
            patch_bound_evidence_ids.update(
                value
                for value in provenance.get("focusedTestEvidenceIds", [])
                if isinstance(value, str)
            )
        patch_commit = provenance.get("candidateCommit")
        for evidence in fix.get("evidence", []):
            if not isinstance(evidence, dict):
                continue
            evidence_id = evidence.get("evidenceId")
            if not isinstance(evidence_id, str):
                raise ValueError("fix evidence identity is malformed")
            evidence_subject = (fix_id, evidence_id)
            prior = rows.get(evidence_subject)
            if prior is not None and prior != evidence:
                raise ValueError(
                    "duplicate fix evidence identity has contradictory content"
                )
            expected_commit = (
                patch_commit
                if evidence_id in patch_bound_evidence_ids
                else candidate_commit
            )
            if evidence.get("candidateCommit") != expected_commit:
                subject = (
                    "reviewed patch"
                    if evidence_id in patch_bound_evidence_ids
                    else "candidate"
                )
                raise ValueError(
                    f"fix evidence is not bound to the exact {subject}"
                )
            if evidence.get("predecessorCommit") != predecessor_commit:
                raise ValueError("fix evidence is not bound to the exact predecessor")
            if (
                evidence_policy.get("policyDigestBindingRequired") is True
                and evidence.get("policyDigest") != policy_digest
            ):
                raise ValueError(
                    "fix evidence is not bound to the exact reviewed policy"
                )
            if (
                evidence_policy.get("queueDigestBindingRequired") is True
                and evidence.get("queueDigest") != queue_digest
            ):
                raise ValueError(
                    "fix evidence is not bound to the exact release-train queue"
                )
            expires = parse_timestamp(evidence.get("expiresAt"))
            generated = parse_timestamp(evidence.get("generatedAt"))
            if (
                generated is None
                or generated > now
                or now - generated > maximum_age
                or expires is None
                or expires <= generated
                or expires < now
            ):
                raise ValueError("fix evidence is stale or has a future generation time")
            rows[evidence_subject] = evidence
    if not rows:
        raise ValueError("accepted release-train fixes require candidate-bound evidence")
    results: list[dict[str, Any]] = []
    for (fix_id, evidence_id), evidence in sorted(rows.items()):
        generated = parse_timestamp(evidence.get("generatedAt"))
        expires = parse_timestamp(evidence.get("expiresAt"))
        assert generated is not None
        assert expires is not None
        results.append(
            {
                "fixId": fix_id,
                "evidenceId": evidence_id,
                "status": "pass",
                "evidenceDigest": evidence["digest"],
                "generatedAt": _timestamp(generated.isoformat()),
                "expiresAt": _timestamp(expires.isoformat()),
                "freshnessDeadlineAt": _timestamp(
                    min(expires, generated + maximum_age).isoformat()
                ),
                "candidateBound": True,
                "predecessorBound": True,
                "fresh": True,
            }
        )
    return results


def _build_plan(
    *,
    generated_at: str,
    train_id: str,
    release: dict[str, Any],
    policy_digest: str,
    intake_digest: str,
    queue: dict[str, Any],
    lane: str,
    candidate_commit: str,
    accepted: list[dict[str, Any]],
    deferred: list[str],
    rejected: list[str],
    evidence_results: list[dict[str, Any]],
) -> dict[str, Any]:
    plan = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "stable-1.0-backport-plan",
        "generatedAt": generated_at,
        "stableMilestone": STABLE_MILESTONE,
        "trainId": train_id,
        "release": release,
        "repositoryIdentity": REPOSITORY_IDENTITY,
        "policyDigest": policy_digest,
        "intakeDigest": intake_digest,
        "previousQueueDigest": queue.get("previousQueueDigest"),
        "proposedQueueDigest": queue.get("queueDigest"),
        "targetLane": lane,
        "candidateBuild": release["buildVersion"],
        "intendedCandidateCommit": candidate_commit,
        "acceptedFixIds": sorted(str(row["fixId"]) for row in accepted),
        "deferredFixIds": deferred,
        "rejectedFixIds": rejected,
        "provenanceModes": sorted(
            {
                str(row.get("provenance", {}).get("mode"))
                for row in accepted
                if isinstance(row.get("provenance"), dict)
            }
        ),
        "requiredEvidenceIds": sorted(
            {str(row["evidenceId"]) for row in evidence_results}
        ),
        "carriedObligationIds": list(queue.get("carriedObligationIds", [])),
        "noFork": True,
        "status": "ready",
        "redaction": dict(_PASS_REDACTION),
    }
    plan["planDigest"] = canonical_identity_digest(plan, "planDigest")
    _schema_or_raise(plan, BACKPORT_PLAN_SCHEMA, "backport plan")
    return plan


def _build_lineage(
    *,
    generated_at: str,
    train_id: str,
    release: dict[str, Any],
    policy_digest: str,
    queue_digest: str,
    candidate_commit: str,
    hotfix_follow_up_closure_digest: str | None,
    accepted: list[dict[str, Any]],
) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for fix in accepted:
        provenance = fix.get("provenance")
        ownership = fix.get("ownership")
        provenance = provenance if isinstance(provenance, dict) else {}
        ownership = ownership if isinstance(ownership, dict) else {}
        authorization_digest = provenance.get("reviewerAuthorizationDigest")
        if not isinstance(authorization_digest, str):
            authorization_digest = ownership.get("authorizationDigest")
        entry = {
            "fixId": fix.get("fixId"),
            "source": fix.get("source"),
            "provenance": provenance,
            "authorizationDigest": authorization_digest,
        }
        entry["lineageEntryDigest"] = canonical_identity_digest(
            entry, "lineageEntryDigest"
        )
        entries.append(entry)
    lineage = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "stable-1.0-backport-lineage",
        "generatedAt": generated_at,
        "stableMilestone": STABLE_MILESTONE,
        "policyDigest": policy_digest,
        "repositoryIdentity": REPOSITORY_IDENTITY,
        "trainId": train_id,
        "release": release,
        "candidateCommit": candidate_commit,
        "queueDigest": queue_digest,
        "hotfixFollowUpClosureDigest": hotfix_follow_up_closure_digest,
        "fixes": sorted(entries, key=lambda row: str(row["fixId"])),
        "redaction": dict(_PASS_REDACTION),
    }
    lineage["lineageDigest"] = canonical_identity_digest(lineage, "lineageDigest")
    _schema_or_raise(lineage, BACKPORT_LINEAGE_SCHEMA, "backport lineage")
    return lineage


def _git_identity(inspector: GitInspector, commit: str) -> dict[str, Any]:
    return {
        "repositoryIdentity": REPOSITORY_IDENTITY,
        "objectFormat": inspector.object_format,
        "commit": commit,
    }


def _build_candidate(
    *,
    generated_at: str,
    train_id: str,
    release: dict[str, Any],
    policy_digest: str,
    queue: dict[str, Any],
    plan: dict[str, Any],
    inspector: GitInspector,
    predecessor_commit: str,
    candidate_commit: str,
    branch_base: str,
    development_lineage_commit: str | None,
    main_lineage_commit: str | None,
    lifecycle_ledger_digest: str,
    latest_pointer_digest: str,
    hotfix_follow_up_closure_digest: str | None,
    accepted: list[dict[str, Any]],
    coverage: list[dict[str, Any]],
    unaccounted: list[str],
) -> dict[str, Any]:
    landed = sorted(
        str(row["fixId"])
        for row in accepted
        if row.get("state") in {"landed", "verified"}
    )
    verified = sorted(
        str(row["fixId"]) for row in accepted if row.get("state") == "verified"
    )
    candidate = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "stable-1.0-release-train-candidate",
        "generatedAt": generated_at,
        "stableMilestone": STABLE_MILESTONE,
        "trainId": train_id,
        "release": release,
        "repositoryIdentity": REPOSITORY_IDENTITY,
        "policyDigest": policy_digest,
        "queueDigest": queue["queueDigest"],
        "planDigest": plan["planDigest"],
        "predecessor": _git_identity(inspector, predecessor_commit),
        "candidate": _git_identity(inspector, candidate_commit),
        "branchBase": _git_identity(inspector, branch_base),
        "developmentLineageCommit": development_lineage_commit,
        "mainLineageCommit": main_lineage_commit,
        "lifecycleLedgerDigest": lifecycle_ledger_digest,
        "latestMaintenancePointerDigest": latest_pointer_digest,
        "hotfixFollowUpClosureDigest": hotfix_follow_up_closure_digest,
        "acceptedFixIds": sorted(str(row["fixId"]) for row in accepted),
        "landedFixIds": landed,
        "verifiedFixIds": verified,
        "coverage": coverage,
        "unaccountedCommitIds": unaccounted,
        "carriedObligationIds": list(queue.get("carriedObligationIds", [])),
        "noFork": True,
        "status": "ready" if not unaccounted else "blocked",
        "redaction": dict(_PASS_REDACTION),
    }
    _schema_or_raise(candidate, CANDIDATE_SCHEMA, "release-train candidate")
    return candidate


def _validation_blockers(state: ValidationState) -> list[dict[str, Any]]:
    return [
        {
            "blockerId": str(row.get("id")),
            "message": str(row.get("summary")),
            "waivable": False,
        }
        for row in state.blockers
    ]


def _build_validation(
    *,
    generated_at: str,
    mode: str,
    train_id: str,
    release: dict[str, Any],
    policy_digest: str,
    queue_digest: str,
    plan_digest: str,
    candidate_digest: str,
    predecessor_commit: str,
    candidate_commit: str,
    accepted: list[dict[str, Any]],
    deferred: list[str],
    evidence_results: list[dict[str, Any]],
    unaccounted: list[str],
    state: ValidationState,
    authorization: dict[str, Any] | None,
    hotfix_follow_up_closure_digest: str | None = None,
) -> dict[str, Any]:
    required = sorted(str(row["fixId"]) for row in accepted)
    included = sorted(
        str(row["fixId"])
        for row in accepted
        if row.get("state") == "verified"
    )
    omitted = sorted(set(required) - set(included))
    public_fixes = [_public_fix(row) for row in accepted if str(row["fixId"]) in included]
    validation = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "stable-1.0-release-train-validation",
        "generatedAt": generated_at,
        "stableMilestone": STABLE_MILESTONE,
        "mode": mode,
        "trainId": train_id,
        "release": release,
        "policyDigest": policy_digest,
        "queueDigest": queue_digest,
        "planDigest": plan_digest,
        "candidateDigest": candidate_digest,
        "predecessorCommit": predecessor_commit,
        "candidateCommit": candidate_commit,
        "hotfixFollowUpClosureDigest": hotfix_follow_up_closure_digest,
        "requiredFixIds": required,
        "includedFixIds": included,
        "omittedFixIds": omitted,
        "deferredFixIds": deferred,
        "unaccountedCommitIds": unaccounted,
        "publicFixes": public_fixes,
        "evidenceResults": evidence_results,
        "blockers": _validation_blockers(state),
        "authorizationRequired": True,
        "authorization": authorization,
        "decision": (
            "go"
            if (
                not state.blockers
                and not unaccounted
                and (mode == "evaluate" or not omitted)
            )
            else "no-go"
        ),
        "redaction": dict(_PASS_REDACTION),
    }
    validation["validationDigest"] = canonical_identity_digest(
        validation, "validationDigest"
    )
    _schema_or_raise(validation, VALIDATION_SCHEMA, "release-train validation")
    return validation


def _public_validation(
    validation: dict[str, Any],
    accepted: list[dict[str, Any]],
    authoritative_file_digest: str,
) -> dict[str, Any]:
    """Project a validation without protected evidence inventory or digests."""

    public_evidence = {
        (str(fix.get("fixId")), str(evidence.get("evidenceId")))
        for fix in accepted
        for evidence in fix.get("evidence", [])
        if isinstance(evidence, dict) and evidence.get("visibility") == "public"
    }
    value = {
        key: json.loads(json.dumps(item))
        for key, item in validation.items()
        if key not in {"hotfixFollowUpClosureDigest", "validationDigest"}
    }
    value["kind"] = "stable-1.0-release-train-validation-public"
    value["evidenceResults"] = [
        row
        for row in value.get("evidenceResults", [])
        if (str(row.get("fixId")), str(row.get("evidenceId")))
        in public_evidence
    ]
    value["authoritativeValidationDigest"] = validation["validationDigest"]
    value["authoritativeValidationFileDigest"] = authoritative_file_digest
    value["publicValidationDigest"] = canonical_identity_digest(
        value, "publicValidationDigest"
    )
    _schema_or_raise(
        value,
        PUBLIC_VALIDATION_SCHEMA,
        "public release-train validation",
    )
    return value


def _authenticate_authorization(
    loaded: tuple[Path, dict[str, Any], str] | None,
    *,
    now: dt.datetime,
    release: dict[str, Any],
    train_id: str,
    lane: str,
    policy_digest: str,
    queue_digest: str,
    plan_digest: str,
    prepare_validation_digest: str,
    predecessor_commit: str,
    candidate_commit: str,
    public_fixes: list[dict[str, Any]],
    authorization_policy: dict[str, Any],
    require_current: bool,
    not_before: dt.datetime,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    if loaded is None:
        raise ValueError("release-train authorization is required")
    path, authorization, exact_digest = loaded
    _schema_or_raise(
        authorization, AUTHORIZATION_SCHEMA, "release-train authorization"
    )
    if not _canonical_json_input(path, authorization) or scan_value(authorization):
        raise ValueError("release-train authorization is not canonical and public-safe")
    if authorization.get("authorizationDigest") != canonical_identity_digest(
        authorization, "authorizationDigest"
    ):
        raise ValueError("release-train authorization digest is inconsistent")
    expected_role = (
        authorization_policy.get("routineRole")
        if lane == "routine-maintenance"
        else authorization_policy.get("securityHotfixRole")
    )
    maximum_validity_hours = authorization_policy.get("maximumValidityHours")
    expected_scopes = authorization_policy.get("candidateHandoffScopes")
    if (
        not isinstance(expected_role, str)
        or type(maximum_validity_hours) is not int
        or maximum_validity_hours < 1
        or not isinstance(expected_scopes, list)
        or "candidate-handoff"
        not in authorization_policy.get("allowedOperations", [])
    ):
        raise ValueError("release-train authorization policy is malformed")
    expected = {
        "stableMilestone": STABLE_MILESTONE,
        "trainId": train_id,
        "release": release,
        "repositoryIdentity": REPOSITORY_IDENTITY,
        "workflowIdentity": (
            "github.com/crypta-network/cryptad/.github/workflows/"
            f"stable-1.0-backport-release-train.yml@{candidate_commit}"
        ),
        "policyDigest": policy_digest,
        "queueDigest": queue_digest,
        "planDigest": plan_digest,
        "validationDigest": prepare_validation_digest,
        "predecessorCommit": predecessor_commit,
        "candidateCommit": candidate_commit,
        "acceptedFixes": public_fixes,
        "allowedOperation": "candidate-handoff",
        "role": expected_role,
        "scope": expected_scopes,
        "decision": "go",
        "redaction": _PASS_REDACTION,
    }
    for field, value in expected.items():
        if authorization.get(field) != value:
            raise ValueError(
                "release-train authorization does not bind the exact candidate handoff"
            )
    issued = parse_timestamp(authorization.get("issuedAt"))
    expires = parse_timestamp(authorization.get("expiresAt"))
    if issued is not None and issued < not_before:
        raise ValueError(
            "release-train authorization predates evidence or state it approves"
        )
    if (
        issued is None
        or expires is None
        or issued > now
        or (require_current and expires <= now)
        or expires <= issued
        or expires - issued > dt.timedelta(hours=maximum_validity_hours)
    ):
        raise ValueError("release-train authorization is expired or outside its validity window")
    summary = {
        "authorizationDigest": authorization["authorizationDigest"],
        "status": "valid",
        "expiresAt": authorization["expiresAt"],
        "role": expected_role,
    }
    return authorization, summary, exact_digest


def _latest_authorized_input_time(
    intake: dict[str, Any],
    lifecycle_observed_at: dt.datetime,
    *,
    hotfix_follow_up_closure: dict[str, Any] | None = None,
    review_authorization_set: dict[str, Any] | None = None,
    review_authorizations: dict[str, dict[str, Any]] | None = None,
) -> dt.datetime:
    """Return the latest completed event incorporated into train authorization."""

    timestamps = [lifecycle_observed_at]
    generated_at = parse_timestamp(intake.get("generatedAt"))
    if generated_at is not None:
        timestamps.append(generated_at)
    for fix in intake.get("fixes", []):
        if not isinstance(fix, dict):
            continue
        for transition in fix.get("stateTransitions", []):
            if not isinstance(transition, dict):
                continue
            occurred_at = parse_timestamp(transition.get("occurredAt"))
            if occurred_at is not None:
                timestamps.append(occurred_at)
        schedule = fix.get("schedule")
        schedule = schedule if isinstance(schedule, dict) else {}
        for field in ("submittedAt", "decisionAt"):
            parsed = parse_timestamp(schedule.get(field))
            if parsed is not None:
                timestamps.append(parsed)
        for evidence in fix.get("evidence", []):
            if not isinstance(evidence, dict):
                continue
            evidence_generated_at = parse_timestamp(evidence.get("generatedAt"))
            if evidence_generated_at is not None:
                timestamps.append(evidence_generated_at)
    for obligation in intake.get("obligations", []):
        if not isinstance(obligation, dict):
            continue
        for field in ("generatedAt", "resolvedAt"):
            parsed = parse_timestamp(obligation.get(field))
            if parsed is not None:
                timestamps.append(parsed)
    if hotfix_follow_up_closure is not None:
        for field in ("generatedAt", "closedAt"):
            parsed = parse_timestamp(hotfix_follow_up_closure.get(field))
            if parsed is not None:
                timestamps.append(parsed)
    if review_authorization_set is not None:
        generated_at = parse_timestamp(review_authorization_set.get("generatedAt"))
        if generated_at is not None:
            timestamps.append(generated_at)
    for authorization in (review_authorizations or {}).values():
        issued_at = parse_timestamp(authorization.get("issuedAt"))
        if issued_at is not None:
            timestamps.append(issued_at)
    return max(timestamps)


def _validate_security_authorization_ids(
    authorization: dict[str, Any], accepted: list[dict[str, Any]]
) -> None:
    expected = sorted(
        {
            str(security["incidentOpaqueId"])
            for fix in accepted
            for security in [fix.get("security")]
            if isinstance(security, dict)
        }
    )
    if authorization.get("securityOpaqueIds") != expected:
        raise ValueError("release-train authorization security scope was substituted")


def _validate_security_hotfix_fix_set(fixes: list[dict[str, Any]]) -> None:
    def security_value(row: dict[str, Any]) -> dict[str, Any]:
        value = row.get("security")
        return value if isinstance(value, dict) else {}

    security_scopes = {
        (
            security_value(row).get("incidentOpaqueId"),
            security_value(row).get("advisoryOpaqueId"),
        )
        for row in fixes
    }
    if (
        not fixes
        or any(
            row.get("classification") != "security-fix"
            or security_value(row).get("severity") != "critical"
            for row in fixes
        )
        or len(security_scopes) != 1
    ):
        raise ValueError(
            "security-hotfix train requires one critical incident and advisory scope"
        )


def _merge_evidence_dict(value: MergeEvidence) -> dict[str, Any]:
    return {
        "mergeCommit": value.merge_commit,
        "firstParent": value.first_parent,
        "mergedTip": value.merged_tip,
        "protectedRef": value.protected_ref,
        "protectedTip": value.protected_tip,
        "parentCount": value.parent_count,
        "graphVerified": value.graph_verified,
        "workflowAttestationDigest": value.workflow_attestation_digest,
    }


def _reconciliation_obligation(
    *,
    completion: dict[str, Any],
    evidence: MergeEvidence,
    resolution_paths: tuple[str, ...],
    role: str,
    lane: str,
    source_fix_ids: list[str],
    reconciliation_policy: dict[str, Any],
) -> dict[str, Any]:
    """Derive one path-safe blocker from authenticated non-automatic merge content."""

    obligation_types = reconciliation_policy.get(
        "manualResolutionObligationTypes"
    )
    obligation_types = (
        obligation_types if isinstance(obligation_types, dict) else {}
    )
    policy_key = (
        "main"
        if role == "main"
        else "hotfixDevelop"
        if lane == "security-hotfix"
        else "routineDevelop"
    )
    obligation_type = obligation_types.get(policy_key)
    prefix = reconciliation_policy.get("manualResolutionObligationIdPrefix")
    release = completion.get("release")
    release = release if isinstance(release, dict) else {}
    build_version = release.get("buildVersion")
    if (
        reconciliation_policy.get("manualResolutionCreatesCarriedObligation")
        is not True
        or obligation_type
        not in {
            "post-release-main-merge",
            "post-release-develop-merge",
            "hotfix-develop-merge-back",
        }
        or not isinstance(prefix, str)
        or not isinstance(build_version, str)
        or role not in {"main", "develop"}
        or not resolution_paths
        or not source_fix_ids
        or source_fix_ids != sorted(set(source_fix_ids))
    ):
        raise ValueError("post-release reconciliation obligation policy is malformed")
    obligation_id = f"{prefix}-{build_version}-{role}"
    evidence_digest = semantic_digest(
        {
            "kind": "stable-1.0-reconciliation-content-review-required",
            "trainId": completion.get("trainId"),
            "obligationId": obligation_id,
            "obligationType": obligation_type,
            "publicationCommit": completion.get("publicationCommit"),
            "mergeEvidence": _merge_evidence_dict(evidence),
            "resolutionPathDigest": semantic_digest(list(resolution_paths)),
        }
    )
    return {
        "obligationId": obligation_id,
        "obligationType": obligation_type,
        "sourceTrainId": completion.get("trainId"),
        "sourceFixIds": source_fix_ids,
        "status": "open",
        "generatedAt": completion.get("generatedAt"),
        "resolvedAt": None,
        "evidenceDigest": evidence_digest,
    }


def _verify_completion_release_and_reconciliation(
    completion: dict[str, Any],
    receipt: dict[str, Any],
    receipt_digest: str,
    *,
    inspector: GitInspector,
    release: dict[str, Any],
    train_id: str,
    lane: str,
    policy_digest: str,
    queue_digest: str,
    validation_file_digest: str,
    authorization_digest: str,
    candidate_commit: str,
    expected_carried_obligation_ids: list[str],
    source_fix_ids: list[str],
    reconciliation_policy: dict[str, Any],
) -> dict[str, Any]:
    """Authenticate the immutable publication and both protected merge graphs."""

    expected = {
        "stableMilestone": STABLE_MILESTONE,
        "trainId": train_id,
        "release": release,
        "policyDigest": policy_digest,
        "queueDigest": queue_digest,
        "validationDigest": validation_file_digest,
        "authorizationDigest": authorization_digest,
        "publicationReceiptDigest": receipt_digest,
        "publicationCommit": candidate_commit,
        "tag": release["tag"],
        "status": "complete",
        "redaction": _PASS_REDACTION,
    }
    if any(completion.get(field) != value for field, value in expected.items()):
        raise ValueError("completion evidence does not bind the exact released train")
    if completion.get("completionDigest") != canonical_identity_digest(
        completion, "completionDigest"
    ):
        raise ValueError("completion evidence semantic digest is inconsistent")
    if (
        receipt.get("releaseId") != release["releaseId"]
        or receipt.get("buildVersion") != release["buildVersion"]
        or receipt.get("releaseClass") != release["releaseClass"]
        or receipt.get("sourceCommit") != candidate_commit
        or receipt.get("tag", {}).get("name") != release["tag"]
        or receipt.get("tag", {}).get("targetCommit") != candidate_commit
        or receipt.get("publicationState") != "publication-complete"
        or receipt.get("finalVerificationStatus") != "pass"
        or receipt.get("backportReleaseTrainDigest")
        != validation_file_digest
    ):
        raise ValueError(
            "maintenance publication receipt does not authenticate this train"
        )
    main = completion.get("mainMerge")
    develop = completion.get("developMerge")
    if not isinstance(main, dict) or not isinstance(develop, dict):
        raise ValueError("completion merge evidence is missing")
    reconciliation_obligations: list[dict[str, Any]] = []

    def verify_merge(
        value: dict[str, Any],
        *,
        role: str,
        expected_ref: str,
    ) -> MergeEvidence:
        try:
            return inspector.verify_no_ff_merge(
                merge_commit=str(value.get("mergeCommit", "")),
                first_parent=str(value.get("firstParent", "")),
                merged_tip=str(value.get("mergedTip", "")),
                protected_ref=str(value.get("protectedRef", "")),
                protected_tip=str(value.get("protectedTip", "")),
                expected_protected_ref=expected_ref,
                workflow_attestation_digest=str(
                    value.get("workflowAttestationDigest", "")
                ),
            )
        except NonAutomaticMergeResolutionError as exc:
            reconciliation_obligations.append(
                _reconciliation_obligation(
                    completion=completion,
                    evidence=exc.evidence,
                    resolution_paths=exc.resolution_paths,
                    role=role,
                    lane=lane,
                    source_fix_ids=source_fix_ids,
                    reconciliation_policy=reconciliation_policy,
                )
            )
            return exc.evidence

    verified_main = verify_merge(
        main,
        role="main",
        expected_ref="refs/heads/main",
    )
    verified_develop = verify_merge(
        develop,
        role="develop",
        expected_ref="refs/heads/develop",
    )
    if (
        _merge_evidence_dict(verified_main) != main
        or _merge_evidence_dict(verified_develop) != develop
        or verified_main.merged_tip != candidate_commit
        or verified_develop.merged_tip != candidate_commit
        or verified_main.merge_commit == verified_develop.merge_commit
    ):
        raise ValueError(
            "post-release merge reconciliation identities do not match"
        )
    hotfix_present = inspector.is_ancestor(
        candidate_commit, verified_develop.protected_tip
    )
    if completion.get("hotfixPresentInDevelop") != hotfix_present:
        raise ValueError(
            "completion hotfix merge-back claim does not match Git history"
        )
    if lane == "security-hotfix" and not hotfix_present:
        raise ValueError(
            "security hotfix is absent from reconciled develop history"
        )
    reconciliation_obligations.sort(key=lambda row: row["obligationId"])
    derived_ids = [
        str(row["obligationId"]) for row in reconciliation_obligations
    ]
    if set(derived_ids).intersection(expected_carried_obligation_ids):
        raise ValueError("completion reconciliation obligation identity collides")
    expected_ids = sorted(expected_carried_obligation_ids + derived_ids)
    supplied_obligations = completion.get("reconciliationObligations")
    supplied_ids = completion.get("carriedObligationIds")
    unaugmented = (
        supplied_obligations == []
        and supplied_ids == expected_carried_obligation_ids
        and completion.get("reconciliationStatus") == "verified"
    )
    already_augmented = (
        supplied_obligations == reconciliation_obligations
        and supplied_ids == expected_ids
        and completion.get("reconciliationStatus")
        == (
            "content-review-required"
            if reconciliation_obligations
            else "verified"
        )
    )
    if not unaugmented and not already_augmented:
        raise ValueError(
            "completion does not retain the exact permitted carried obligations"
        )
    normalized = copy.deepcopy(completion)
    normalized["reconciliationStatus"] = (
        "content-review-required"
        if reconciliation_obligations
        else "verified"
    )
    normalized["reconciliationObligations"] = reconciliation_obligations
    normalized["carriedObligationIds"] = expected_ids
    normalized["completionDigest"] = canonical_identity_digest(
        normalized, "completionDigest"
    )
    return normalized


def _verify_completion(
    completion_loaded: tuple[Path, dict[str, Any], str] | None,
    maintenance_receipt_loaded: tuple[Path, dict[str, Any], str] | None,
    lifecycle_receipt_loaded: tuple[Path, dict[str, Any], str] | None,
    lifecycle_ledger_loaded: tuple[Path, dict[str, Any], str] | None,
    lifecycle_descriptor_loaded: tuple[Path, dict[str, Any], str] | None,
    *,
    inspector: GitInspector,
    release: dict[str, Any],
    train_id: str,
    lane: str,
    policy_digest: str,
    queue_digest: str,
    validation_file_digest: str,
    authorization_digest: str,
    candidate_commit: str,
    expected_carried_obligation_ids: list[str],
    source_fix_ids: list[str],
    reconciliation_policy: dict[str, Any],
) -> dict[str, Any]:
    if completion_loaded is None or maintenance_receipt_loaded is None:
        raise ValueError("completion verification requires exact protected receipts")
    completion_path, completion, _completion_file_digest = completion_loaded
    receipt_path, receipt, receipt_digest = maintenance_receipt_loaded
    _schema_or_raise(
        completion, COMPLETION_SCHEMA, "release-train completion evidence"
    )
    _schema_or_raise(
        receipt,
        "stable-1.0-maintenance-publication-receipt-v1.schema.json",
        "Stable maintenance publication receipt",
    )
    if (
        not _canonical_json_input(completion_path, completion)
        or not _canonical_json_input(receipt_path, receipt)
        or scan_value(completion)
        or scan_value(receipt)
    ):
        raise ValueError("completion input is not canonical and public-safe")
    completion = _verify_completion_release_and_reconciliation(
        completion,
        receipt,
        receipt_digest,
        inspector=inspector,
        release=release,
        train_id=train_id,
        lane=lane,
        policy_digest=policy_digest,
        queue_digest=queue_digest,
        validation_file_digest=validation_file_digest,
        authorization_digest=authorization_digest,
        candidate_commit=candidate_commit,
        expected_carried_obligation_ids=expected_carried_obligation_ids,
        source_fix_ids=source_fix_ids,
        reconciliation_policy=reconciliation_policy,
    )
    lifecycle_state = completion.get("lifecycleState")
    lifecycle_receipt_digest = completion.get("lifecycleReceiptDigest")
    lifecycle_ledger_digest = completion.get("lifecycleLedgerDigest")
    lifecycle_descriptor_digest = completion.get("lifecycleDescriptorDigest")
    if lifecycle_state == "activated" and not isinstance(
        lifecycle_receipt_digest, str
    ):
        raise ValueError("activated completion lacks its lifecycle receipt digest")
    if lifecycle_state == "activated":
        if (
            lifecycle_receipt_loaded is None
            or lifecycle_ledger_loaded is None
            or lifecycle_descriptor_loaded is None
            or not isinstance(lifecycle_ledger_digest, str)
            or not isinstance(lifecycle_descriptor_digest, str)
        ):
            raise ValueError(
                "activated completion lacks the exact lifecycle receipt, ledger, or descriptor"
            )
        lifecycle_path, lifecycle_receipt, lifecycle_file_digest = (
            lifecycle_receipt_loaded
        )
        lifecycle_ledger_path, lifecycle_ledger, lifecycle_ledger_file_digest = (
            lifecycle_ledger_loaded
        )
        (
            lifecycle_descriptor_path,
            lifecycle_descriptor,
            lifecycle_descriptor_file_digest,
        ) = lifecycle_descriptor_loaded
        _schema_or_raise(
            lifecycle_receipt,
            "stable-1.0-support-lifecycle-publication-receipt-v1.schema.json",
            "Stable lifecycle publication receipt",
        )
        _schema_or_raise(
            lifecycle_ledger,
            "stable-1.0-support-lifecycle-ledger-v1.schema.json",
            "activated Stable lifecycle ledger",
        )
        _schema_or_raise(
            lifecycle_descriptor,
            "stable-1.0-support-lifecycle-descriptor-v1.schema.json",
            "activated Stable lifecycle descriptor",
        )
        matching_entries = [
            row
            for row in lifecycle_ledger.get("entries", [])
            if isinstance(row, dict)
            and row.get("releaseId") == release["releaseId"]
            and row.get("buildVersion") == release["buildVersion"]
            and row.get("tag") == release["tag"]
            and row.get("sourceCommit") == candidate_commit
            and row.get("publicationReceiptDigest") == receipt_digest
            and row.get("lifecycleStatus") == "current-stable"
        ]
        if (
            not _canonical_json_input(lifecycle_path, lifecycle_receipt)
            or not _canonical_json_input(lifecycle_ledger_path, lifecycle_ledger)
            or not _canonical_json_input(
                lifecycle_descriptor_path, lifecycle_descriptor
            )
            or scan_value(lifecycle_receipt)
            or scan_value(lifecycle_ledger)
            or scan_value(lifecycle_descriptor)
            or lifecycle_file_digest != lifecycle_receipt_digest
            or lifecycle_ledger_file_digest != lifecycle_ledger_digest
            or lifecycle_descriptor_file_digest != lifecycle_descriptor_digest
            or lifecycle_ledger.get("ledgerDigest")
            != canonical_identity_digest(lifecycle_ledger, "ledgerDigest")
            or lifecycle_descriptor.get("descriptorDigest")
            != canonical_identity_digest(
                lifecycle_descriptor, "descriptorDigest"
            )
            or lifecycle_descriptor.get("ledgerDigest")
            != lifecycle_ledger.get("ledgerDigest")
            or lifecycle_descriptor.get("currentStableBuild")
            != release["buildVersion"]
            or len(matching_entries) != 1
            or lifecycle_receipt.get("ledgerDigest")
            != lifecycle_ledger.get("ledgerDigest")
            or lifecycle_receipt.get("descriptorDigest")
            != lifecycle_descriptor.get("descriptorDigest")
            or lifecycle_receipt.get("descriptorBytesDigest")
            != lifecycle_descriptor_file_digest
            or lifecycle_receipt.get("publicationState") != "publication-complete"
            or lifecycle_receipt.get("verificationStatus") != "verified"
            or lifecycle_receipt.get("conflict") is not False
        ):
            raise ValueError(
                "lifecycle publication receipt does not authenticate activation"
            )
    elif (
        lifecycle_receipt_digest is not None
        or lifecycle_ledger_digest is not None
        or lifecycle_descriptor_digest is not None
        or lifecycle_receipt_loaded is not None
        or lifecycle_ledger_loaded is not None
        or lifecycle_descriptor_loaded is not None
    ):
        raise ValueError(
            "pending lifecycle activation must not claim activated lifecycle evidence"
        )
    return completion


def _report(
    *,
    mode: str,
    train_id: str,
    release: dict[str, Any],
    lane: str,
    queue: dict[str, Any],
    validation: dict[str, Any],
    completion: dict[str, Any] | None,
) -> str:
    rows = [
        "# Stable 1.0 backport and release-train report",
        "",
        f"- Train: `{train_id}`",
        f"- Mode: `{mode}`",
        f"- Release: `{release['releaseId']}`; tag `{release['tag']}`",
        f"- Lane: `{lane}`",
        f"- Decision: **{validation['decision']}**",
        f"- Queue digest: `{queue['queueDigest']}`",
        f"- Validation digest: `{validation['validationDigest']}`",
        "- Historical Stable build bytes modified: **no**",
        "- Git or publication side effects performed: **no**",
        "",
        "## Included public-safe fixes",
        "",
    ]
    public_fixes = validation.get("publicFixes", [])
    if public_fixes:
        for fix in public_fixes:
            rows.append(
                "- `{fixId}` — `{classification}` — {components} — "
                "`{provenanceMode}`".format(
                    fixId=fix["fixId"],
                    classification=fix["classification"],
                    components=fix["affectedComponentSummary"],
                    provenanceMode=fix["provenanceMode"],
                )
            )
    else:
        rows.append("- None.")
    deferred = queue.get("deferredFixIds", [])
    rows.extend(["", "## Carried queue state", ""])
    rows.append(
        "- Deferred fixes: "
        + (", ".join(f"`{row}`" for row in deferred) if deferred else "none")
    )
    obligations = (
        completion.get("carriedObligationIds", [])
        if completion is not None
        else queue.get("carriedObligationIds", [])
    )
    rows.append(
        "- Unresolved obligations: "
        + (", ".join(f"`{row}`" for row in obligations) if obligations else "none")
    )
    rows.append(
        "- Lifecycle activation: "
        + (
            f"`{completion['lifecycleState']}`"
            if completion is not None
            else "not evaluated in this mode"
        )
    )
    rows.append(
        "- Reconciliation status: "
        + (
            f"`{completion['reconciliationStatus']}`"
            if completion is not None
            else "not evaluated in this mode"
        )
    )
    rows.extend(
        [
            "",
            "The JSON artifacts are authoritative. This report contains only the "
            "bounded public projection.",
        ]
    )
    return "\n".join(rows)


def _scan_public_artifact(name: str, value: Any) -> list[dict[str, str]]:
    # These keys contain only schema-constrained digest/status metadata, but the shared scanner
    # intentionally treats any generic "authorization" container as sensitive. Remove only the
    # already schema-validated proof wrapper before applying all remaining shared checks.
    normalized = json.loads(json.dumps(value))
    if isinstance(normalized, dict):
        normalized.pop("authorization", None)
        principal = normalized.get("principalArtifacts")
        if isinstance(principal, dict):
            principal.pop("authorizationSummary", None)
    return [
        {"artifact": name, **finding}
        for finding in scan_value(normalized)
    ]


def _redaction_report(
    *,
    generated_at: str,
    train_id: str,
    policy_digest: str,
    artifacts: dict[str, Any],
) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    for name, value in sorted(artifacts.items()):
        findings.extend(_scan_public_artifact(name, value))
    report = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "stable-1.0-release-train-redaction",
        "generatedAt": generated_at,
        "trainId": train_id,
        "policyDigest": policy_digest,
        "scannedArtifacts": sorted(artifacts),
        "status": "fail" if findings else "pass",
        "findingCount": len(findings),
        "findings": findings,
        "guarantees": {
            key: not findings if key != "sideEffectsNotPerformed" else True
            for key in _PASS_REDACTION_GUARANTEES
        },
    }
    _schema_or_raise(report, REDACTION_SCHEMA, "release-train redaction report")
    return report


def _fix_counts(fixes: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "total": len(fixes),
        "submitted": sum(row.get("state") == "submitted" for row in fixes),
        "triaged": sum(row.get("state") == "triaged" for row in fixes),
        "accepted": sum(row.get("state") == "accepted" for row in fixes),
        "scheduled": sum(row.get("state") == "scheduled" for row in fixes),
        "landed": sum(row.get("state") == "landed" for row in fixes),
        "verified": sum(row.get("state") == "verified" for row in fixes),
        "deferred": sum(row.get("state") == "deferred" for row in fixes),
        "rejected": sum(row.get("state") == "rejected" for row in fixes),
        "superseded": sum(row.get("state") == "superseded" for row in fixes),
        "released": sum(row.get("state") == "released" for row in fixes),
    }


def _summary(
    *,
    generated_at: str,
    mode: str,
    train_id: str,
    release: dict[str, Any],
    policy_digest: str,
    queue_digest: str,
    candidate_commit: str,
    validation_digest: str,
    completion_digest: str | None,
    fixes: list[dict[str, Any]],
    authorization_present: bool,
) -> dict[str, Any]:
    promotion_ready = mode in {
        "validate-authorization",
        "verify-release-completion",
    }
    value = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "stable-1.0-release-train-summary",
        "generatedAt": generated_at,
        "stableMilestone": STABLE_MILESTONE,
        "mode": mode,
        "trainId": train_id,
        "release": release,
        "policyDigest": policy_digest,
        "queueDigest": queue_digest,
        "candidateCommit": candidate_commit,
        "validationDigest": validation_digest,
        "completionDigest": completion_digest,
        "fixCounts": _fix_counts(fixes),
        "decision": "go",
        "promotionReady": promotion_ready,
        "sideEffectsPerformed": False,
        "principalArtifacts": {
            "fixIntake": FIX_INTAKE_FILE,
            "backportPlan": BACKPORT_PLAN_FILE,
            "backportLineage": BACKPORT_LINEAGE_FILE,
            "queue": QUEUE_FILE,
            "publicQueue": PUBLIC_QUEUE_FILE,
            "candidate": CANDIDATE_FILE,
            "validation": VALIDATION_FILE,
            "publicValidation": PUBLIC_VALIDATION_FILE,
            "authorizationSummary": (
                AUTHORIZATION_FILE if authorization_present else None
            ),
            "completion": (
                COMPLETION_FILE if completion_digest is not None else None
            ),
            "report": REPORT_FILE,
            "checksums": CHECKSUMS_FILE,
            "provenance": PROVENANCE_FILE,
            "redactionReport": REDACTION_FILE,
        },
        "redaction": dict(_PASS_REDACTION),
    }
    _schema_or_raise(value, SUMMARY_SCHEMA, "release-train summary")
    return value


def _provenance(
    *,
    generated_at: str,
    train_id: str,
    release: dict[str, Any],
    inspector: GitInspector,
    policy_digest: str,
    queue_digest: str,
    candidate_commit: str,
    predecessor_commit: str,
    source_inputs: dict[str, tuple[Path, dict[str, Any], str] | None],
    output_paths: Iterable[Path],
) -> dict[str, Any]:
    source_rows = [
        {"artifact": key, "digest": loaded[2]}
        for key, loaded in sorted(source_inputs.items())
        if loaded is not None
    ]
    output_rows = [
        {"artifact": path.name, "digest": file_digest(path)}
        for path in sorted(output_paths, key=lambda row: row.name)
        if path.is_file()
    ]
    value = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "stable-1.0-release-train-provenance",
        "generatedAt": generated_at,
        "stableMilestone": STABLE_MILESTONE,
        "trainId": train_id,
        "release": release,
        "repositoryIdentity": REPOSITORY_IDENTITY,
        "objectFormat": inspector.object_format,
        "policyDigest": policy_digest,
        "queueDigest": queue_digest,
        "candidateCommit": candidate_commit,
        "predecessorCommit": predecessor_commit,
        "mergeBaseCommit": inspector.merge_base(
            predecessor_commit, candidate_commit
        ),
        "sourceInputs": source_rows,
        "outputDigests": output_rows,
        "gitCommandsWereReadOnly": True,
        "networkAccessPerformed": False,
        "sideEffectsPerformed": False,
        "redaction": dict(_PASS_REDACTION),
    }
    value["provenanceDigest"] = canonical_identity_digest(
        value, "provenanceDigest"
    )
    _schema_or_raise(value, PROVENANCE_SCHEMA, "release-train provenance")
    return value


def _write_checksums(path: Path, members: Iterable[Path]) -> None:
    rows = {
        member.name: file_digest(member).removeprefix("sha256:")
        for member in members
        if member.is_file() and member != path
    }
    write_text(path, "\n".join(f"{rows[name]}  {name}" for name in sorted(rows)))


def _raise_errors(errors: Iterable[str], label: str) -> None:
    failures = [str(row) for row in errors]
    if failures:
        raise ValueError(f"{label} failed closed: {failures[0]}")


def _run(context: RunContext, out: Path, state: ValidationState) -> int:
    mode = context.manifest.commands.get("stable-backport", {}).get(
        "mode", "evaluate"
    )
    if mode not in COMMAND_MODES:
        raise ValueError("Stable backport command mode is unsupported")
    now = _now()
    inputs = _load_inputs(context)
    completion_handoff_loaded = inputs[
        "previousStableBackportCompletionHandoff"
    ]
    if completion_handoff_loaded is not None:
        handoff_path, handoff_value, _handoff_digest = completion_handoff_loaded
        if inputs["previousStableBackportCompletion"] is None:
            raise ValueError(
                "predecessor completion handoff appeared without its completion"
            )
        if (
            not _canonical_json_input(handoff_path, handoff_value)
            or scan_value(handoff_value)
        ):
            raise ValueError(
                "predecessor completion handoff is not canonical public-safe JSON"
            )
        _schema_or_raise(
            handoff_value,
            COMPLETION_HANDOFF_SCHEMA,
            "predecessor completion handoff",
        )
    policy_loaded = inputs["stableBackportPolicy"]
    intake_loaded = inputs["stableFixIntake"]
    assert policy_loaded and intake_loaded
    policy_path, policy, policy_digest = policy_loaded
    intake_path, intake, intake_file_digest = intake_loaded
    validation_now = now
    frozen_validation_loaded = inputs["stableBackportFrozenValidation"]
    if mode == "verify-release-completion":
        authorization_loaded = inputs["stableBackportAuthorization"]
        if frozen_validation_loaded is None or authorization_loaded is None:
            raise ValueError(
                "completion requires the frozen authorized validation and authorization"
            )
        frozen_path, frozen_validation, _frozen_digest = frozen_validation_loaded
        authorization_path, authorization_value, _authorization_digest = (
            authorization_loaded
        )
        for path, value, schema, label in (
            (
                frozen_path,
                frozen_validation,
                VALIDATION_SCHEMA,
                "frozen release-train validation",
            ),
            (
                authorization_path,
                authorization_value,
                AUTHORIZATION_SCHEMA,
                "release-train authorization",
            ),
        ):
            if not _canonical_json_input(path, value):
                raise ValueError(f"{label} is not canonical JSON")
            if _scan_public_artifact(label, value):
                raise ValueError(f"{label} is not public-safe")
            _schema_or_raise(value, schema, label)
        issued_at = parse_timestamp(authorization_value.get("issuedAt"))
        if issued_at is None or issued_at > now:
            raise ValueError("completion authorization issue time is invalid")
        # Publication freezes the authorized validation. Replaying its time-bound
        # gates at authorization issuance authenticates the original handoff
        # without incorrectly aging evidence against the later completion run.
        validation_now = issued_at
    elif frozen_validation_loaded is not None:
        raise ValueError("frozen release-train validation is completion-only")
    _raise_errors(
        checked_in_policy_errors(context, policy_path, policy),
        "release-train policy authentication",
    )
    review_authorizations = _authenticate_review_authorizations(
        inputs["stableBackportReviewAuthorizations"],
        intake=intake,
        policy=policy,
        policy_digest=policy_digest,
        now=validation_now,
    )
    repository_policy = policy.get("repository")
    repository_policy = (
        repository_policy if isinstance(repository_policy, dict) else {}
    )
    inspector = GitInspector(
        context.workspace_root,
        expected_repository_identity=REPOSITORY_IDENTITY,
        max_output_bytes=int(
            repository_policy.get("maximumGitOutputBytes", 8 * 1024 * 1024)
        ),
        timeout_seconds=int(repository_policy.get("gitCommandTimeoutSeconds", 30)),
    )
    _raise_errors(
        intake_errors(
            intake,
            policy,
            policy_digest=policy_digest,
            repository_identity=REPOSITORY_IDENTITY,
            now=validation_now,
            review_authorizations=review_authorizations,
        ),
        "fix intake",
    )
    if not _canonical_json_input(intake_path, intake):
        raise ValueError("fix intake is not canonical JSON")
    release = _release(context)
    train_id = f"stable-train-{release['buildVersion']}"
    lane = _lane(context)
    candidate_commit = str(
        context.manifest.policies.get("candidateSourceCommit", "")
    )
    branch_base = str(context.manifest.policies.get("candidateBaseCommit", ""))
    development_lineage_value = context.manifest.policies.get(
        "developmentLineageCommit"
    )
    main_lineage_value = context.manifest.policies.get("mainLineageCommit")
    inspector.validate_commit_oid(candidate_commit)
    inspector.validate_commit_oid(branch_base)
    if lane == "routine-maintenance":
        if not isinstance(development_lineage_value, str):
            raise ValueError(
                "routine train lacks an independently authenticated development lineage"
            )
        development_lineage_commit = inspector.validate_commit_oid(
            development_lineage_value
        )
        if main_lineage_value is not None:
            raise ValueError(
                "routine train must not claim a security-hotfix main lineage"
            )
        main_lineage_commit = None
        authorized_lineage_commit = development_lineage_commit
    else:
        if development_lineage_value is not None:
            raise ValueError(
                "security hotfix must not claim a routine development lineage"
            )
        development_lineage_commit = None
        if not isinstance(main_lineage_value, str):
            raise ValueError(
                "security hotfix lacks an independently authenticated protected main lineage"
            )
        main_lineage_commit = inspector.validate_commit_oid(main_lineage_value)
        authorized_lineage_commit = main_lineage_commit
    inspector.verify_project_build_version(
        candidate_commit, release["buildVersion"]
    )
    authenticated_predecessor = _authenticate_predecessor(
        context, inputs, inspector
    )
    (
        predecessor_commit,
        predecessor_build,
        latest_pointer_digest,
        _receipt_digest,
    ) = authenticated_predecessor[:4]
    effective_predecessor_baseline = (
        authenticated_predecessor[4]
        if len(authenticated_predecessor) > 4
        else inputs["predecessorBaseline"][1]  # type: ignore[index]
    )
    hotfix_follow_up_closure_digest = (
        authenticated_predecessor[5]
        if len(authenticated_predecessor) > 5
        else None
    )
    lifecycle_ledger_digest, lifecycle_statuses = _authenticate_lifecycle(
        inputs, predecessor_build, release["releaseClass"]
    )
    branch_role = inspector.verify_branch_role(
        lane=lane,
        candidate_build=release["buildVersion"],
        candidate_commit=candidate_commit,
        branch_base=branch_base,
        authorized_lineage_commit=authorized_lineage_commit,
        authenticated_predecessor_commit=predecessor_commit,
    )
    inspector.verify_no_fork(
        predecessor_commit, predecessor_commit, candidate_commit
    )
    previous_queue = _authenticate_previous_queue(
        inputs,
        predecessor_commit=predecessor_commit,
        predecessor_build=predecessor_build,
    )
    _authenticate_released_transitions(
        intake,
        previous_queue,
        inputs["previousStableBackportCompletion"],
        inputs["previousStableBackportCompletionHandoff"],
        inputs["previousStableBackportValidation"],
        inputs["predecessorPublicationReceipt"],
        policy,
        inspector,
        validation_now,
    )
    queue, queue_errors = build_queue(
        intake,
        previous_queue,
        policy_digest=policy_digest,
        latest_maintenance_pointer_digest=latest_pointer_digest,
        lifecycle_ledger_digest=lifecycle_ledger_digest,
        repository_identity=REPOSITORY_IDENTITY,
        candidate_commit=candidate_commit,
        hotfix_follow_up_closure_digest=hotfix_follow_up_closure_digest,
    )
    _raise_errors(queue_errors, "append-only release-train queue")
    fixes = [
        row for row in queue.get("fixes", []) if isinstance(row, dict)
    ]
    for fix in fixes:
        _verify_fix_source_identity(inspector, fix)
    accepted, deferred, rejected, _superseded = _fix_sets(fixes, lane)
    if mode != "evaluate" and not accepted:
        raise ValueError("release train contains no accepted fix for its selected lane")
    if mode != "evaluate" and any(
        fix.get("state") != "verified" for fix in accepted
    ):
        raise ValueError(
            "accepted release-train fix is not explicitly verified"
        )
    if mode != "evaluate" and any(
        not isinstance(fix.get("schedule"), dict)
        or fix["schedule"].get("targetTrainId") != train_id
        for fix in accepted
    ):
        raise ValueError(
            "accepted release-train fix targets a different release train"
        )
    permitted_obligation_ids: list[str] = []
    if mode != "evaluate":
        permitted_obligation_ids, obligation_errors = (
            permitted_carried_obligation_ids(
                queue,
                previous_queue,
                lane=lane,
                policy=policy,
                predecessor_baseline=effective_predecessor_baseline,
            )
        )
        _raise_errors(obligation_errors, "release-train carried obligations")
    if (
        mode != "evaluate"
        and lane == "routine-maintenance"
        and queue.get("criticalFixIds")
    ):
        raise ValueError("routine train omits or misroutes a critical security obligation")
    accepted_fix_ids = {str(row.get("fixId")) for row in accepted}
    if mode != "evaluate" and any(
        str(fix_id) not in accepted_fix_ids
        for fix_id in queue.get("criticalFixIds", [])
    ):
        raise ValueError("release train omits an unresolved critical security obligation")
    if mode != "evaluate" and lane == "security-hotfix":
        _validate_security_hotfix_fix_set(accepted)
    hotfix_scope: dict[str, Any] | None = None
    if lane == "security-hotfix" and any(
        row.get("classification") == "security-fix" for row in accepted
    ):
        primary_security_fix = next(
            row for row in accepted if row.get("classification") == "security-fix"
        )
        security = primary_security_fix.get("security")
        security = security if isinstance(security, dict) else {}
        incident_scope_evidence = next(
            (
                row
                for row in primary_security_fix.get("evidence", [])
                if isinstance(row, dict)
                and row.get("evidenceId")
                == "stable-backport.security-incident-scope"
            ),
            {},
        )
        hotfix_scope = {
            "incidentId": (
                security.get("advisoryOpaqueId")
                or security.get("incidentOpaqueId")
            ),
            "hotfixPolicyAuthorizationDigest": incident_scope_evidence.get("digest"),
        }
    lifecycle_observed_at = _authenticate_lifecycle_authority(
        context,
        inputs,
        release_class=release["releaseClass"],
        now=validation_now,
        hotfix_scope=hotfix_scope,
    )
    for fix in accepted if mode != "evaluate" else []:
        scope = fix.get("affectedScope")
        scope = scope if isinstance(scope, dict) else {}
        evidence_ids = {
            str(row.get("evidenceId"))
            for row in fix.get("evidence", [])
            if isinstance(row, dict)
        }
        evidence_policy = policy.get("evidencePolicy")
        evidence_policy = (
            evidence_policy if isinstance(evidence_policy, dict) else {}
        )
        for build in scope.get("affectedBuilds", []):
            status = lifecycle_statuses.get(str(build))
            if status is None:
                raise ValueError("fix affected-build scope is absent from lifecycle state")
            if (
                status in {"supported-maintenance", "security-fixes-only", "deprecated"}
                and evidence_policy.get("supportedBuildUpgradeEvidenceId")
                not in evidence_ids
            ):
                raise ValueError(
                    "historical supported-build coverage lacks exact upgrade evidence"
                )
            if (
                status == "deprecated"
                and evidence_policy.get("deprecatedBuildGuidanceEvidenceId")
                not in evidence_ids
            ):
                raise ValueError(
                    "deprecated-build coverage lacks public upgrade guidance"
                )
            if (
                status in {"end-of-support", "revoked"}
                and evidence_policy.get("recoverySourceEvidenceId")
                not in evidence_ids
            ):
                raise ValueError(
                    "end-of-support or revoked coverage requires explicit recovery evidence"
                )
        if (
            fix.get("classification") == "security-fix"
            and fix.get("severity") == "critical"
            and evidence_policy.get("criticalOperationalCoverageEvidenceId")
            not in evidence_ids
        ):
            raise ValueError(
                "critical security fix lacks supported-build upgrade or recovery coverage"
            )
        _verify_fix_provenance(
            inspector,
            fix,
            candidate_commit,
            branch_role.branch_role,
            policy,
            review_authorizations.get(str(fix.get("fixId"))),
        )
    evidence_results: list[dict[str, Any]] = []
    coverage: list[dict[str, Any]] = []
    unaccounted: list[str] = []
    if mode != "evaluate":
        evidence_policy = policy.get("evidencePolicy")
        evidence_policy = evidence_policy if isinstance(evidence_policy, dict) else {}
        maximum_age = (
            dt.timedelta(days=int(evidence_policy.get("routineMaximumAgeDays", 0)))
            if lane == "routine-maintenance"
            else dt.timedelta(
                hours=int(evidence_policy.get("securityHotfixMaximumAgeHours", 0))
            )
        )
        if maximum_age <= dt.timedelta(0):
            raise ValueError("release-train policy evidence freshness window is invalid")
        evidence_results = _required_evidence(
            accepted,
            predecessor_commit,
            candidate_commit,
            validation_now,
            maximum_age,
            policy_digest=policy_digest,
            queue_digest=str(queue["queueDigest"]),
            evidence_policy=evidence_policy,
            provenance_policy=(
                policy.get("provenancePolicy")
                if isinstance(policy.get("provenancePolicy"), dict)
                else {}
            ),
        )
        coverage, unaccounted = _candidate_coverage(
            inspector, predecessor_commit, candidate_commit, accepted
        )
        if unaccounted:
            raise ValueError("candidate Git range contains an unaccounted commit")
    generated_at = _timestamp(intake.get("generatedAt"))
    plan = _build_plan(
        generated_at=generated_at,
        train_id=train_id,
        release=release,
        policy_digest=policy_digest,
        intake_digest=intake_file_digest,
        queue=queue,
        lane=lane,
        candidate_commit=candidate_commit,
        accepted=accepted,
        deferred=deferred,
        rejected=rejected,
        evidence_results=evidence_results,
    )
    lineage = _build_lineage(
        generated_at=generated_at,
        train_id=train_id,
        release=release,
        policy_digest=policy_digest,
        queue_digest=str(queue["queueDigest"]),
        candidate_commit=candidate_commit,
        hotfix_follow_up_closure_digest=hotfix_follow_up_closure_digest,
        accepted=accepted,
    )
    candidate = _build_candidate(
        generated_at=generated_at,
        train_id=train_id,
        release=release,
        policy_digest=policy_digest,
        queue=queue,
        plan=plan,
        inspector=inspector,
        predecessor_commit=predecessor_commit,
        candidate_commit=candidate_commit,
        branch_base=branch_base,
        development_lineage_commit=development_lineage_commit,
        main_lineage_commit=main_lineage_commit,
        lifecycle_ledger_digest=lifecycle_ledger_digest,
        latest_pointer_digest=latest_pointer_digest,
        hotfix_follow_up_closure_digest=hotfix_follow_up_closure_digest,
        accepted=accepted,
        coverage=coverage,
        unaccounted=unaccounted,
    )
    # These six artifacts are independent of train authorization and form the exact
    # candidate-composition subject that the protected authorization must bind.
    _copy_canonical_input(intake_path, out / FIX_INTAKE_FILE, intake)
    _write_canonical(out / QUEUE_FILE, queue, QUEUE_SCHEMA)
    public_queue = _public_queue(queue)
    _write_canonical(out / PUBLIC_QUEUE_FILE, public_queue, PUBLIC_QUEUE_SCHEMA)
    if inputs["previousStableBackportCompletionHandoff"] is not None:
        handoff_path, handoff_value, _handoff_digest = inputs[
            "previousStableBackportCompletionHandoff"
        ]
        _copy_canonical_input(
            handoff_path,
            out / COMPLETION_HANDOFF_FILE,
            handoff_value,
        )
    _write_canonical(out / BACKPORT_PLAN_FILE, plan, BACKPORT_PLAN_SCHEMA)
    _write_canonical(
        out / BACKPORT_LINEAGE_FILE, lineage, BACKPORT_LINEAGE_SCHEMA
    )
    _write_canonical(out / CANDIDATE_FILE, candidate, CANDIDATE_SCHEMA)
    candidate_file_digest = file_digest(out / CANDIDATE_FILE)
    prepare_validation = _build_validation(
        generated_at=generated_at,
        mode="prepare-candidate" if mode != "evaluate" else "evaluate",
        train_id=train_id,
        release=release,
        policy_digest=policy_digest,
        queue_digest=str(queue["queueDigest"]),
        plan_digest=str(plan["planDigest"]),
        candidate_digest=candidate_file_digest,
        predecessor_commit=predecessor_commit,
        candidate_commit=candidate_commit,
        hotfix_follow_up_closure_digest=hotfix_follow_up_closure_digest,
        accepted=accepted,
        deferred=deferred,
        evidence_results=evidence_results,
        unaccounted=unaccounted,
        state=state,
        authorization=None,
    )
    authorization: dict[str, Any] | None = None
    authorization_summary: dict[str, Any] | None = None
    authorization_exact_digest: str | None = None
    validation = prepare_validation
    if mode in {"validate-authorization", "verify-release-completion"}:
        authorization, authorization_summary, authorization_exact_digest = (
            _authenticate_authorization(
                inputs["stableBackportAuthorization"],
                now=now,
                release=release,
                train_id=train_id,
                lane=lane,
                policy_digest=policy_digest,
                queue_digest=str(queue["queueDigest"]),
                plan_digest=str(plan["planDigest"]),
                prepare_validation_digest=str(
                    prepare_validation["validationDigest"]
                ),
                predecessor_commit=predecessor_commit,
                candidate_commit=candidate_commit,
                public_fixes=list(prepare_validation["publicFixes"]),
                authorization_policy=(
                    policy.get("authorization")
                    if isinstance(policy.get("authorization"), dict)
                    else {}
                ),
                require_current=mode != "verify-release-completion",
                not_before=_latest_authorized_input_time(
                    intake,
                    lifecycle_observed_at,
                    hotfix_follow_up_closure=(
                        inputs["hotfixFollowUpClosure"][1]
                        if inputs["hotfixFollowUpClosure"] is not None
                        else None
                    ),
                    review_authorization_set=(
                        inputs["stableBackportReviewAuthorizations"][1]
                        if inputs["stableBackportReviewAuthorizations"]
                        is not None
                        else None
                    ),
                    review_authorizations=review_authorizations,
                ),
            )
        )
        _validate_security_authorization_ids(authorization, accepted)
        validation = _build_validation(
            generated_at=generated_at,
            mode="validate-authorization",
            train_id=train_id,
            release=release,
            policy_digest=policy_digest,
            queue_digest=str(queue["queueDigest"]),
            plan_digest=str(plan["planDigest"]),
            candidate_digest=candidate_file_digest,
            predecessor_commit=predecessor_commit,
            candidate_commit=candidate_commit,
            hotfix_follow_up_closure_digest=hotfix_follow_up_closure_digest,
            accepted=accepted,
            deferred=deferred,
            evidence_results=evidence_results,
            unaccounted=unaccounted,
            state=state,
            authorization=authorization_summary,
        )
        assert authorization_exact_digest is not None
        _copy_canonical_input(
            inputs["stableBackportAuthorization"][0],  # type: ignore[index]
            out / AUTHORIZATION_FILE,
            authorization,
        )
    if mode == "verify-release-completion":
        assert frozen_validation_loaded is not None
        frozen_path, frozen_validation, _frozen_digest = frozen_validation_loaded
        if validation != frozen_validation:
            raise ValueError(
                "completion inputs do not reconstruct the frozen authorized validation"
            )
        _copy_canonical_input(
            frozen_path,
            out / VALIDATION_FILE,
            frozen_validation,
        )
    else:
        _write_canonical(out / VALIDATION_FILE, validation, VALIDATION_SCHEMA)
    validation_file_digest = file_digest(out / VALIDATION_FILE)
    public_validation = _public_validation(
        validation,
        accepted,
        validation_file_digest,
    )
    _write_canonical(
        out / PUBLIC_VALIDATION_FILE,
        public_validation,
        PUBLIC_VALIDATION_SCHEMA,
    )
    if validation.get("decision") != "go":
        raise ValueError("release-train validation decision is no-go")
    completion: dict[str, Any] | None = None
    if mode == "verify-release-completion":
        assert authorization is not None
        completion = _verify_completion(
            inputs["stableBackportCompletionEvidence"],
            inputs["stableMaintenancePublicationReceipt"],
            inputs["stableLifecyclePublicationReceipt"],
            inputs["completedStableLifecycleLedger"],
            inputs["completedStableLifecycleDescriptor"],
            inspector=inspector,
            release=release,
            train_id=train_id,
            lane=lane,
            policy_digest=policy_digest,
            queue_digest=str(queue["queueDigest"]),
            validation_file_digest=validation_file_digest,
            authorization_digest=str(authorization["authorizationDigest"]),
            candidate_commit=candidate_commit,
            expected_carried_obligation_ids=permitted_obligation_ids,
            source_fix_ids=sorted(
                str(row["fixId"])
                for row in accepted
                if isinstance(row.get("fixId"), str)
            ),
            reconciliation_policy=(
                policy.get("postReleaseReconciliation")
                if isinstance(policy.get("postReleaseReconciliation"), dict)
                else {}
            ),
        )
        _write_canonical(out / COMPLETION_FILE, completion, COMPLETION_SCHEMA)
    report_text = _report(
        mode=mode,
        train_id=train_id,
        release=release,
        lane=lane,
        queue=queue,
        validation=validation,
        completion=completion,
    )
    write_text(out / REPORT_FILE, report_text)
    summary = _summary(
        generated_at=generated_at,
        mode=mode,
        train_id=train_id,
        release=release,
        policy_digest=policy_digest,
        queue_digest=str(queue["queueDigest"]),
        candidate_commit=candidate_commit,
        validation_digest=str(validation["validationDigest"]),
        completion_digest=(
            str(completion["completionDigest"]) if completion is not None else None
        ),
        fixes=fixes,
        authorization_present=authorization is not None,
    )
    _write_canonical(out / SUMMARY_FILE, summary, SUMMARY_SCHEMA)
    redaction_subjects: dict[str, Any] = {
        FIX_INTAKE_FILE: intake,
        QUEUE_FILE: queue,
        PUBLIC_QUEUE_FILE: public_queue,
        BACKPORT_PLAN_FILE: plan,
        BACKPORT_LINEAGE_FILE: lineage,
        CANDIDATE_FILE: candidate,
        VALIDATION_FILE: validation,
        PUBLIC_VALIDATION_FILE: public_validation,
        SUMMARY_FILE: summary,
        REPORT_FILE: report_text,
    }
    if inputs["previousStableBackportCompletionHandoff"] is not None:
        redaction_subjects[COMPLETION_HANDOFF_FILE] = inputs[
            "previousStableBackportCompletionHandoff"
        ][1]
    if authorization is not None:
        redaction_subjects[AUTHORIZATION_FILE] = authorization
    if completion is not None:
        redaction_subjects[COMPLETION_FILE] = completion
    redaction = _redaction_report(
        generated_at=generated_at,
        train_id=train_id,
        policy_digest=policy_digest,
        artifacts=redaction_subjects,
    )
    if redaction["status"] != "pass":
        raise ValueError("release-train public artifacts failed redaction")
    _write_canonical(out / REDACTION_FILE, redaction, REDACTION_SCHEMA)
    initial_outputs = [
        path
        for path in out.iterdir()
        if path.name not in {PROVENANCE_FILE, CHECKSUMS_FILE}
    ]
    provenance = _provenance(
        generated_at=generated_at,
        train_id=train_id,
        release=release,
        inspector=inspector,
        policy_digest=policy_digest,
        queue_digest=str(queue["queueDigest"]),
        candidate_commit=candidate_commit,
        predecessor_commit=predecessor_commit,
        source_inputs=inputs,
        output_paths=initial_outputs,
    )
    if _scan_public_artifact(PROVENANCE_FILE, provenance):
        raise ValueError("release-train provenance failed redaction")
    _write_canonical(out / PROVENANCE_FILE, provenance, PROVENANCE_SCHEMA)
    _write_checksums(out / CHECKSUMS_FILE, out.iterdir())
    return 0


def _fail_closed(context: RunContext, out: Path, state: ValidationState) -> None:
    generated_at = _timestamp(_now().isoformat())
    version = context.manifest.release.version
    train_id = (
        f"stable-train-{version}"
        if isinstance(version, str) and version.isdigit() and int(version) > 0
        else "stable-train-rejected"
    )
    policy_digest = "sha256:" + "0" * 64
    try:
        loaded = load_object(context, "stableBackportPolicy", required=False)
        if loaded is not None and _DIGEST_RE.fullmatch(loaded[2]):
            policy_digest = loaded[2]
    except (OSError, ValueError):
        pass
    findings = _redaction_report(
        generated_at=generated_at,
        train_id=train_id,
        policy_digest=policy_digest,
        artifacts={},
    )
    failure = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "stable-1.0-release-train-failure",
        "generatedAt": generated_at,
        "stableMilestone": STABLE_MILESTONE,
        "mode": context.manifest.commands.get("stable-backport", {}).get(
            "mode", "evaluate"
        ),
        "decision": "no-go",
        "promotionReady": False,
        "sideEffectsPerformed": False,
        "blockers": state.blockers,
        "artifacts": {
            "redactionReport": REDACTION_FILE,
            "report": REPORT_FILE,
        },
        "redaction": dict(_PASS_REDACTION),
    }
    write_json(out / REDACTION_FILE, findings)
    write_json(out / SUMMARY_FILE, failure)
    write_text(
        out / REPORT_FILE,
        "# Stable 1.0 backport and release-train report\n\n"
        "Decision: **no-go**\n\n"
        "The protected input was rejected. No candidate, authorization, completion, "
        "Git mutation, or publication artifact was produced.",
    )


def run(context: RunContext) -> tuple[int, Path, Path]:
    """Run the native release-train engine without Git mutation or network access."""

    out = reset_confined_directory(
        context.component_dir / "artifacts" / "legacy",
        context.run_root,
        "Stable backport native output",
    )
    state = ValidationState()
    try:
        code = _run(context, out, state)
    except Exception:  # noqa: BLE001 - protected failures are deliberately sanitized
        state.block(
            "stable-backport.execution-input",
            EVIDENCE_ID,
            "Stable backport rejected malformed, unsafe, incomplete, or unauthenticated input.",
            "Correct the exact policy, queue, Git, lifecycle, evidence, or authorization input and rerun.",
        )
        out = reset_confined_directory(
            context.component_dir / "artifacts" / "legacy",
            context.run_root,
            "Stable backport failed native output",
        )
        _fail_closed(context, out, state)
        code = 1
    return code, out / SUMMARY_FILE, out / REPORT_FILE

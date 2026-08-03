"""Policy, queue, and identity helpers for Stable 1.0 release-train governance."""

from __future__ import annotations

import copy
import datetime as dt
import json
import re
from pathlib import Path
from typing import Any, Iterable

from cryptad_certification.io import read_json
from cryptad_certification.models import RunContext
from cryptad_certification.redaction import scan_value
from cryptad_certification.schema_validation import validate_schema

from .stable_1_0_rc_core import ValidationState, file_digest, parse_timestamp, semantic_digest

SCHEMA_VERSION = 1
TOOL_NAME = "stable-1.0-backport-release-train"
TOOL_VERSION = 1
STABLE_MILESTONE = "1.0"
COMPONENT = "stable-backport"

COMMAND_MODES = (
    "evaluate",
    "prepare-candidate",
    "validate-authorization",
    "verify-release-completion",
)
CLASSIFICATIONS = (
    "compatible-bug-fix",
    "security-fix",
    "platform-api-compatible-addition",
    "platform-api-deprecation",
    "stable-catalog-app-patch",
    "packaging-installer-fix",
    "release-tooling-fix",
    "documentation-support-fix",
    "unsupported-feature-change",
    "breaking-change",
)
DISPOSITIONS = (
    "routine-maintenance",
    "security-hotfix",
    "future-milestone",
    "deferred",
    "rejected",
)
RELEASE_LANES = ("routine-maintenance", "security-hotfix")
FIX_STATES = (
    "submitted",
    "triaged",
    "accepted",
    "scheduled",
    "landed",
    "verified",
    "released",
    "deferred",
    "rejected",
    "superseded",
)
PROVENANCE_MODES = (
    "inherited",
    "clean-cherry-pick",
    "manual-conflict-resolution",
)
COVERAGE_CATEGORIES = (
    "accepted-fix",
    "approved-release-metadata",
    "approved-release-tooling",
    "approved-docs-support",
    "merge-context",
    "unaccounted",
)
LIFECYCLE_STATUSES = (
    "current-stable",
    "supported-maintenance",
    "security-fixes-only",
    "deprecated",
    "end-of-support",
    "revoked",
)

FIX_INTAKE_FILE = "stable-1.0-fix-intake.json"
BACKPORT_PLAN_FILE = "stable-1.0-backport-plan.json"
BACKPORT_LINEAGE_FILE = "stable-1.0-backport-lineage.json"
QUEUE_FILE = "stable-1.0-release-train-queue.json"
PUBLIC_QUEUE_FILE = "stable-1.0-release-train-queue-public.json"
CANDIDATE_FILE = "stable-1.0-release-train-candidate.json"
VALIDATION_FILE = "stable-1.0-release-train-validation.json"
PUBLIC_VALIDATION_FILE = "stable-1.0-release-train-validation-public.json"
AUTHORIZATION_FILE = "stable-1.0-release-train-authorization-summary.json"
COMPLETION_FILE = "stable-1.0-release-train-completion.json"
COMPLETION_HANDOFF_FILE = (
    "stable-1.0-release-train-predecessor-completion-handoff.json"
)
SUMMARY_FILE = "stable-1.0-release-train-summary.json"
REPORT_FILE = "stable-1.0-release-train-report.md"
CHECKSUMS_FILE = "stable-1.0-release-train-checksums.txt"
PROVENANCE_FILE = "stable-1.0-release-train-provenance.json"
REDACTION_FILE = "redaction-report.json"

POLICY_SCHEMA = "stable-1.0-backport-release-train-policy-v1.schema.json"
FIX_INTAKE_SCHEMA = "stable-1.0-fix-intake-v1.schema.json"
FIX_RECORD_SCHEMA = "stable-1.0-fix-record-v1.schema.json"
BACKPORT_PLAN_SCHEMA = "stable-1.0-backport-plan-v1.schema.json"
BACKPORT_LINEAGE_SCHEMA = "stable-1.0-backport-lineage-v1.schema.json"
QUEUE_SCHEMA = "stable-1.0-release-train-queue-v1.schema.json"
PUBLIC_QUEUE_SCHEMA = "stable-1.0-release-train-queue-public-v1.schema.json"
CANDIDATE_SCHEMA = "stable-1.0-release-train-candidate-v1.schema.json"
VALIDATION_SCHEMA = "stable-1.0-release-train-validation-v1.schema.json"
PUBLIC_VALIDATION_SCHEMA = (
    "stable-1.0-release-train-validation-public-v1.schema.json"
)
AUTHORIZATION_SCHEMA = "stable-1.0-release-train-authorization-v1.schema.json"
REVIEW_AUTHORIZATIONS_SCHEMA = (
    "stable-1.0-backport-review-authorizations-v1.schema.json"
)
COMPLETION_SCHEMA = "stable-1.0-release-train-completion-v1.schema.json"
COMPLETION_HANDOFF_SCHEMA = (
    "stable-1.0-release-train-completion-handoff-v1.schema.json"
)
SUMMARY_SCHEMA = "stable-1.0-release-train-summary-v1.schema.json"
PROVENANCE_SCHEMA = "stable-1.0-release-train-provenance-v1.schema.json"
REDACTION_SCHEMA = "stable-1.0-release-train-redaction-v1.schema.json"

DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
FIX_ID_RE = re.compile(r"stable-fix-[a-z0-9]{16,64}\Z")
SAFE_REASON_RE = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
HTML_RE = re.compile(r"(?is)<\s*/?\s*(?:script|style|iframe|object|embed|svg|math|img|a)\b")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

_PASS_REDACTION = {"status": "pass", "findingCount": 0, "findings": []}
_QUEUE_BINDING_PLACEHOLDER = "sha256:" + "0" * 64


def canonical_identity_digest(value: Any, identity_field: str) -> str:
    """Return the semantic digest of an object without its self-identifying digest field."""

    if not isinstance(value, dict):
        raise ValueError("release-train identity subject must be an object")
    subject = {key: item for key, item in value.items() if key != identity_field}
    return semantic_digest(subject)


def queue_identity_digest(value: Any) -> str:
    """Return the queue digest with embedded self-bindings normalized."""

    if not isinstance(value, dict):
        raise ValueError("release-train queue identity subject must be an object")
    subject = copy.deepcopy(value)
    subject.pop("queueDigest", None)
    fixes = subject.get("fixes")
    fixes = fixes if isinstance(fixes, list) else []
    for fix in fixes:
        if not isinstance(fix, dict):
            continue
        evidence_rows = fix.get("evidence")
        evidence_rows = evidence_rows if isinstance(evidence_rows, list) else []
        for evidence in evidence_rows:
            if isinstance(evidence, dict) and "queueDigest" in evidence:
                evidence["queueDigest"] = _QUEUE_BINDING_PLACEHOLDER
    return semantic_digest(subject)


def queue_evidence_binding_errors(value: Any) -> list[str]:
    """Require every evidence row to name the queue identity that contains it."""

    if not isinstance(value, dict):
        return ["release-train queue evidence binding subject is not an object"]
    expected = value.get("queueDigest")
    fixes = value.get("fixes")
    fixes = fixes if isinstance(fixes, list) else []
    errors: list[str] = []
    for fix in fixes:
        if not isinstance(fix, dict):
            continue
        evidence_rows = fix.get("evidence")
        evidence_rows = evidence_rows if isinstance(evidence_rows, list) else []
        if any(
            isinstance(evidence, dict)
            and evidence.get("queueDigest") != expected
            for evidence in evidence_rows
        ):
            errors.append(
                f"fix {fix.get('fixId')} evidence does not bind the declared queue digest"
            )
    return errors


def phase_intake_composition_digest(value: Any) -> str:
    """Commit protected queue fields that must remain fixed between train phases."""

    if not isinstance(value, dict):
        raise ValueError("release-train phase composition subject must be an object")
    fixes = value.get("fixes")
    fixes = fixes if isinstance(fixes, list) else []
    obligations = value.get("obligations")
    obligations = obligations if isinstance(obligations, list) else []
    fix_composition = []
    for fix in fixes:
        if not isinstance(fix, dict):
            continue
        security = fix.get("security")
        security = security if isinstance(security, dict) else None
        security_composition = None
        if security is not None:
            security_composition = {
                "incidentOpaqueId": security.get("incidentOpaqueId"),
                "advisoryOpaqueId": security.get("advisoryOpaqueId"),
                "severity": security.get("severity"),
                "disclosureState": security.get("disclosureState"),
                "publicSafeSummary": security.get("publicSafeSummary"),
                "privateRecordDigest": security.get("privateRecordDigest"),
                "publicProjectionDigest": security.get(
                    "publicProjectionDigest"
                ),
            }
            vulnerability_projection_digest = security.get(
                "vulnerabilityPublicProjectionDigest"
            )
            if vulnerability_projection_digest is not None:
                security_composition[
                    "vulnerabilityPublicProjectionDigest"
                ] = vulnerability_projection_digest
        schedule = fix.get("schedule")
        schedule = schedule if isinstance(schedule, dict) else {}
        fix_composition.append(
            {
                "fixId": fix.get("fixId"),
                "publicTitle": fix.get("publicTitle"),
                "publicSummary": fix.get("publicSummary"),
                "classification": fix.get("classification"),
                "disposition": fix.get("disposition"),
                "releaseLane": fix.get("releaseLane"),
                "severity": fix.get("severity"),
                "risk": fix.get("risk"),
                "affectedScope": fix.get("affectedScope"),
                "source": fix.get("source"),
                "security": security_composition,
                "targetTrainId": schedule.get("targetTrainId"),
                "supersedingFixId": fix.get("supersedingFixId"),
                "privateRecordDigest": fix.get("privateRecordDigest"),
                "publicProjectionDigest": fix.get("publicProjectionDigest"),
            }
        )
    obligation_composition = [
        {
            "obligationId": obligation.get("obligationId"),
            "obligationType": obligation.get("obligationType"),
            "sourceTrainId": obligation.get("sourceTrainId"),
            "sourceFixIds": obligation.get("sourceFixIds"),
            "generatedAt": obligation.get("generatedAt"),
        }
        for obligation in obligations
        if isinstance(obligation, dict)
    ]
    return semantic_digest(
        {
            "policyDigest": value.get("policyDigest"),
            "repositoryIdentity": value.get("repositoryIdentity"),
            "queueId": value.get("queueId"),
            "previousQueueDigest": value.get("previousQueueDigest"),
            "latestMaintenancePointerDigest": value.get(
                "latestMaintenancePointerDigest"
            ),
            "hotfixFollowUpClosureDigest": value.get(
                "hotfixFollowUpClosureDigest"
            ),
            "lifecycleLedgerDigest": value.get("lifecycleLedgerDigest"),
            "fixes": sorted(
                fix_composition, key=lambda row: str(row.get("fixId"))
            ),
            "obligations": sorted(
                obligation_composition,
                key=lambda row: str(row.get("obligationId")),
            ),
        }
    )


def public_phase_evolution_errors(previous: Any, current: Any) -> list[str]:
    """Validate the public commitment for evaluate-to-prepare queue evolution."""

    errors = [
        f"evaluated queue: {error}"
        for error in validate_schema(previous, PUBLIC_QUEUE_SCHEMA)
    ]
    errors.extend(
        f"prepared queue: {error}"
        for error in validate_schema(current, PUBLIC_QUEUE_SCHEMA)
    )
    if errors or not isinstance(previous, dict) or not isinstance(current, dict):
        return errors or ["release-train phase queue is not an object"]
    for field in (
        "stableMilestone",
        "policyDigest",
        "repositoryIdentity",
        "queueId",
        "previousQueueDigest",
        "intakeCompositionDigest",
    ):
        if current.get(field) != previous.get(field):
            errors.append(f"prepared queue changed evaluated {field}")
    previous_fix_ids = sorted(
        row.get("fixId")
        for row in previous.get("publicFixes", [])
        if isinstance(row, dict)
    )
    current_fix_ids = sorted(
        row.get("fixId")
        for row in current.get("publicFixes", [])
        if isinstance(row, dict)
    )
    if previous_fix_ids != current_fix_ids:
        errors.append("prepared queue changed the evaluated fix identity set")
    previous_evolution = {
        row.get("fixId"): row
        for row in previous.get("fixEvolution", [])
        if isinstance(row, dict)
    }
    current_evolution = {
        row.get("fixId"): row
        for row in current.get("fixEvolution", [])
        if isinstance(row, dict)
    }
    if sorted(previous_evolution) != sorted(current_evolution):
        errors.append("prepared queue changed the evaluated evolution identity set")
    for fix_id, prior in previous_evolution.items():
        successor = current_evolution.get(fix_id)
        if not isinstance(successor, dict):
            continue
        prior_transitions = prior.get("transitionDigests")
        current_transitions = successor.get("transitionDigests")
        if not isinstance(prior_transitions, list) or not isinstance(
            current_transitions, list
        ):
            continue
        if current_transitions[: len(prior_transitions)] != prior_transitions:
            errors.append(
                f"prepared fix {fix_id} rewrote evaluated transition history"
            )
    previous_obligations = {
        row.get("obligationId"): row
        for row in previous.get("obligations", [])
        if isinstance(row, dict)
    }
    current_obligations = {
        row.get("obligationId"): row
        for row in current.get("obligations", [])
        if isinstance(row, dict)
    }
    if sorted(previous_obligations) != sorted(current_obligations):
        errors.append("prepared queue changed the evaluated obligation identity set")
    for obligation_id, prior in previous_obligations.items():
        successor = current_obligations.get(obligation_id)
        if not isinstance(successor, dict):
            continue
        if successor.get("obligationType") != prior.get("obligationType"):
            errors.append(
                f"prepared obligation {obligation_id} changed its evaluated type"
            )
        if (
            prior.get("status") == "resolved"
            and successor.get("status") != "resolved"
        ):
            errors.append(
                f"prepared obligation {obligation_id} reopened after evaluation"
            )
    return errors


def safe_public_text_error(value: Any, maximum: int) -> str | None:
    """Return a bounded failure for text that is unsafe in public JSON or Markdown."""

    if not isinstance(value, str) or not value.strip():
        return "is not nonblank public text"
    if len(value) > maximum:
        return f"exceeds the {maximum}-character public text bound"
    if CONTROL_RE.search(value):
        return "contains a forbidden control character"
    if HTML_RE.search(value):
        return "contains active Markdown or HTML markup"
    if scan_value(value):
        return "contains private, credential, URI, or local-path material"
    return None


def add_errors(
    state: ValidationState,
    evidence_id: str,
    errors: Iterable[str],
    remediation: str,
) -> None:
    """Append unique, non-waivable redaction-safe blockers."""

    existing = {
        (row.get("id"), row.get("summary"))
        for row in state.blockers
        if isinstance(row, dict)
    }
    for error in errors:
        summary = str(error).rstrip(".") + "."
        identity = (evidence_id, summary)
        if identity in existing:
            continue
        state.block(evidence_id, evidence_id, summary, remediation)
        existing.add(identity)


def configured_path(
    context: RunContext,
    key: str,
    *,
    required: bool = True,
) -> Path | None:
    """Resolve one manifest input without following a symlink or escaping the workspace."""

    configured = context.manifest.inputs.get(key)
    if configured is None:
        if required:
            raise ValueError(f"missing required input {key}")
        return None
    if not isinstance(configured, str) or not configured:
        raise ValueError(f"input {key} must be a non-empty path")
    path = Path(configured)
    if ".." in path.parts:
        raise ValueError(f"input {key} contains a parent traversal")
    path = path if path.is_absolute() else context.workspace_root / path
    workspace = context.workspace_root.resolve(strict=True)
    try:
        lexical_relative = path.relative_to(workspace)
    except ValueError as exc:
        raise ValueError(f"input {key} escapes the exact repository root") from exc
    lexical_current = workspace
    for part in lexical_relative.parts:
        lexical_current /= part
        if lexical_current.is_symlink():
            raise ValueError(f"input {key} traverses a symbolic link")
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"input {key} is missing or is not a regular file")
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(workspace)
    except ValueError as exc:
        raise ValueError(f"input {key} escapes the exact repository root") from exc
    return resolved


def load_object(
    context: RunContext,
    key: str,
    *,
    required: bool = True,
) -> tuple[Path, dict[str, Any], str] | None:
    """Load one duplicate-key-safe JSON object and its exact file digest."""

    path = configured_path(context, key, required=required)
    if path is None:
        return None
    value = read_json(path)
    if not isinstance(value, dict):
        raise ValueError(f"input {key} must be a JSON object")
    return path, value, file_digest(path)


def checked_in_policy_errors(
    context: RunContext,
    supplied_path: Path,
    supplied: dict[str, Any],
) -> list[str]:
    """Authenticate the supplied policy against the exact reviewed repository policy."""

    expected_path = (
        context.workspace_root
        / "tools/release-certification/stable-1.0-backport-release-train-policy.json"
    )
    errors = validate_schema(supplied, POLICY_SCHEMA)
    try:
        expected = read_json(expected_path)
        if not isinstance(expected, dict):
            raise ValueError("checked-in policy is not an object")
        if read_json(supplied_path) != expected or file_digest(supplied_path) != file_digest(
            expected_path
        ):
            errors.append("supplied release-train policy is not the exact checked-in policy")
    except (OSError, ValueError):
        errors.append("checked-in release-train policy is unavailable or malformed")
        return errors
    errors.extend(policy_errors(supplied))
    return errors


def policy_errors(policy: dict[str, Any]) -> list[str]:
    """Validate security-critical closed vocabularies and policy relationships."""

    errors: list[str] = []
    if (
        policy.get("schemaVersion") != SCHEMA_VERSION
        or policy.get("policyVersion") != 1
    ):
        errors.append("release-train policy version is unsupported")
    expected_lists = {
        "classifications": list(CLASSIFICATIONS),
        "dispositions": list(DISPOSITIONS),
        "releaseLanes": list(RELEASE_LANES),
        "fixStates": list(FIX_STATES),
        "provenanceModes": list(PROVENANCE_MODES),
        "candidateCoverageCategories": list(COVERAGE_CATEGORIES),
    }
    for field, expected in expected_lists.items():
        if policy.get(field) != expected:
            errors.append(f"release-train policy {field} does not match the closed vocabulary")
    no_fork = policy.get("noFork")
    if not isinstance(no_fork, dict) or not all(
        no_fork.get(field) is True
        for field in (
            "singleAuthenticatedPublicationChain",
            "latestPointerImmediatePredecessorRequired",
            "historicalBuildBytesImmutable",
            "parallelStableBranchesAllowed",
        )
        if field != "parallelStableBranchesAllowed"
    ):
        errors.append("release-train policy does not preserve the single-chain invariant")
    if isinstance(no_fork, dict) and no_fork.get("parallelStableBranchesAllowed") is not False:
        errors.append("release-train policy permits a parallel Stable publication branch")
    repository = policy.get("repository")
    if (
        not isinstance(repository, dict)
        or repository.get("identity") != "github.com/crypta-network/cryptad"
        or repository.get("fullObjectIdsRequired") is not True
        or repository.get("commitObjectsRequired") is not True
        or repository.get("symbolicRevisionsAllowed") is not False
        or repository.get("abbreviatedObjectIdsAllowed") is not False
        or repository.get("remoteFetchDuringEvaluationAllowed") is not False
    ):
        errors.append("release-train policy weakens exact local Git object authentication")
    lane_policy = policy.get("releaseLanePolicy")
    routine_policy = (
        lane_policy.get("routine-maintenance")
        if isinstance(lane_policy, dict)
        else None
    )
    hotfix_policy = (
        lane_policy.get("security-hotfix")
        if isinstance(lane_policy, dict)
        else None
    )
    if (
        not isinstance(routine_policy, dict)
        or routine_policy.get("protectedDevelopmentLineageRequired") is not True
        or routine_policy.get("exactDevelopmentMergeBaseRequired") is not True
        or routine_policy.get("developmentFirstParentBaseRequired") is not True
        or not isinstance(hotfix_policy, dict)
        or hotfix_policy.get("protectedDevelopmentLineageRequired") is not False
        or hotfix_policy.get("exactDevelopmentMergeBaseRequired") is not False
        or hotfix_policy.get("developmentFirstParentBaseRequired") is not False
    ):
        errors.append(
            "release-train policy does not authenticate the routine development base"
        )
    maintenance = policy.get("maintenanceIntegration")
    if (
        not isinstance(maintenance, dict)
        or maintenance.get("requiredEvidenceId")
        != "stable-maintenance.backport-release-train"
        or maintenance.get("policyGatedInputRequired") is not True
    ):
        errors.append("release-train policy omits the maintenance handoff blocker")
    authorization = policy.get("authorization")
    provenance_policy = policy.get("provenancePolicy")
    clean_policy = (
        provenance_policy.get("clean-cherry-pick")
        if isinstance(provenance_policy, dict)
        else None
    )
    if (
        not isinstance(authorization, dict)
        or authorization.get("cleanCherryPickReviewerRole")
        != "stable-backport-cherry-pick-reviewer"
        or not isinstance(clean_policy, dict)
        or clean_policy.get("reviewEvidenceId")
        != "stable-backport.clean-cherry-pick-review"
    ):
        errors.append(
            "release-train policy omits clean cherry-pick review authentication"
        )
    queue_policy = policy.get("queuePolicy")
    if (
        not isinstance(queue_policy, dict)
        or queue_policy.get("securityHotfixAllowedCarriedObligationTypes")
        != ["hotfix-follow-up"]
        or queue_policy.get("securityHotfixMaximumCarriedFollowUps") != 1
        or queue_policy.get("publicationCreatedFollowUpBaselineBindingRequired")
        is not True
    ):
        errors.append(
            "release-train policy does not narrowly bound hotfix follow-up carry-forward"
        )
    classification_eligibility = policy.get("classificationEligibility")
    classification_eligibility = (
        classification_eligibility
        if isinstance(classification_eligibility, dict)
        else {}
    )
    for classification, eligibility in classification_eligibility.items():
        if classification == "security-fix" or not isinstance(eligibility, dict):
            continue
        if (
            "security-hotfix" in eligibility.get("allowedLanes", [])
            or "security-hotfix" in eligibility.get("allowedDispositions", [])
        ):
            errors.append(
                "release-train policy permits a non-security classification "
                "in the security-hotfix lane"
            )
    return errors


def _transition_pairs(policy: dict[str, Any]) -> set[tuple[str, str]]:
    transitions = policy.get("stateTransitions")
    if not isinstance(transitions, dict):
        return set()
    return {
        (source, target)
        for source, targets in transitions.items()
        if isinstance(source, str) and isinstance(targets, list)
        for target in targets
        if isinstance(target, str)
    }


def _critical_transition_window_errors(
    fix_id: Any,
    history: list[Any],
    policy: dict[str, Any],
    *,
    now: dt.datetime,
) -> list[str]:
    """Enforce every reviewed incident-response residency interval."""

    critical_policy = policy.get("criticalFixPolicy")
    critical_policy = (
        critical_policy if isinstance(critical_policy, dict) else {}
    )
    windows = (
        ("submitted", "intakeToTriageDeadlineHours", "intake-to-triage"),
        ("triaged", "triageToDecisionDeadlineHours", "triage-to-decision"),
        ("accepted", "acceptedToScheduledDeadlineHours", "accepted-to-scheduled"),
    )
    window_policy = {
        state: (policy_key, label) for state, policy_key, label in windows
    }
    entered: dict[str, dt.datetime] = {}
    errors: list[str] = []

    def check_interval(
        state: str, entered_at: dt.datetime, ended_at: dt.datetime
    ) -> None:
        policy_key, label = window_policy[state]
        try:
            maximum = dt.timedelta(
                hours=int(critical_policy.get(policy_key, 0))
            )
        except (TypeError, ValueError, OverflowError):
            maximum = dt.timedelta(0)
        if (
            maximum <= dt.timedelta(0)
            or ended_at < entered_at
            or ended_at - entered_at > maximum
        ):
            errors.append(
                f"critical security fix {fix_id} exceeded its {label} policy window"
            )

    for row in history:
        if not isinstance(row, dict):
            continue
        occurred_at = parse_timestamp(row.get("occurredAt"))
        target = row.get("to")
        source = row.get("from")
        if occurred_at is None:
            continue
        if isinstance(source, str) and source in window_policy:
            entered_at = entered.pop(source, None)
            if entered_at is not None:
                check_interval(source, entered_at, occurred_at)
        if isinstance(target, str) and target in window_policy:
            entered[target] = occurred_at
    for state, entered_at in entered.items():
        check_interval(state, entered_at, now)
    return errors


def _critical_deferral_errors(
    fix_id: Any,
    history: list[Any],
    policy: dict[str, Any],
    evidence: list[Any],
    schedule: dict[str, Any],
    *,
    now: dt.datetime,
) -> list[str]:
    """Authenticate and bound every completed or open critical deferral."""

    critical_policy = policy.get("criticalFixPolicy")
    critical_policy = (
        critical_policy if isinstance(critical_policy, dict) else {}
    )
    try:
        maximum = dt.timedelta(
            hours=int(critical_policy.get("maximumDeferralHours", 0))
        )
    except (TypeError, ValueError, OverflowError):
        maximum = dt.timedelta(0)
    required_evidence_id = critical_policy.get(
        "deferralSecurityDecisionEvidenceId"
    )
    decision_evidence_digests = {
        row.get("digest")
        for row in evidence
        if isinstance(row, dict)
        and row.get("evidenceId") == required_evidence_id
        and isinstance(row.get("digest"), str)
    }
    errors: list[str] = []
    active_deferral: tuple[dt.datetime, Any] | None = None
    for row in history:
        if not isinstance(row, dict):
            continue
        occurred_at = parse_timestamp(row.get("occurredAt"))
        if row.get("to") == "deferred":
            active_deferral = (occurred_at, row.get("evidenceDigest")) if (
                occurred_at is not None
            ) else None
            if (
                critical_policy.get(
                    "explicitSecurityDecisionRequiredForDeferral"
                )
                is not True
                or active_deferral is None
                or row.get("evidenceDigest") not in decision_evidence_digests
            ):
                errors.append(
                    f"critical deferred fix {fix_id} lacks a bounded security decision"
                )
        if row.get("from") != "deferred" or active_deferral is None:
            continue
        entered_at, _decision_digest = active_deferral
        if (
            occurred_at is None
            or maximum <= dt.timedelta(0)
            or occurred_at < entered_at
            or occurred_at - entered_at > maximum
        ):
            errors.append(
                f"critical security fix {fix_id} exceeded its "
                "critical-deferral policy window"
            )
        active_deferral = None
    if active_deferral is not None:
        entered_at, _decision_digest = active_deferral
        decision_at = parse_timestamp(schedule.get("decisionAt"))
        review_at = parse_timestamp(schedule.get("reviewAt"))
        if (
            decision_at != entered_at
            or review_at is None
            or maximum <= dt.timedelta(0)
            or review_at <= entered_at
            or review_at - entered_at > maximum
            or (
                critical_policy.get("overdueDeferralRemainsBlocker") is True
                and review_at <= now
            )
        ):
            errors.append(
                f"critical deferred fix {fix_id} lacks a bounded security decision"
            )
    return errors


def _provenance_review_errors(
    record: dict[str, Any],
    policy: dict[str, Any],
    *,
    mode: str,
    reviewer_role_field: str,
    label: str,
    authenticated_authorization: dict[str, Any] | None,
) -> list[str]:
    """Authenticate one policy-bound protected provenance-review record."""

    provenance = record.get("provenance")
    provenance = provenance if isinstance(provenance, dict) else {}
    if provenance.get("mode") != mode:
        return []
    fix_id = record.get("fixId")
    errors: list[str] = []
    ownership = record.get("ownership")
    ownership = ownership if isinstance(ownership, dict) else {}
    authorization_policy = policy.get("authorization")
    authorization_policy = (
        authorization_policy if isinstance(authorization_policy, dict) else {}
    )
    provenance_policy = policy.get("provenancePolicy")
    provenance_policy = (
        provenance_policy if isinstance(provenance_policy, dict) else {}
    )
    mode_policy = provenance_policy.get(mode)
    mode_policy = mode_policy if isinstance(mode_policy, dict) else {}
    required_role = authorization_policy.get(reviewer_role_field)
    review_evidence_id = mode_policy.get("reviewEvidenceId")
    reviewer_digest = provenance.get("reviewerAuthorizationDigest")
    candidate_commit = provenance.get("candidateCommit")
    evidence_rows = [
        row for row in record.get("evidence", []) if isinstance(row, dict)
    ]
    if (
        not isinstance(required_role, str)
        or ownership.get("reviewerRole") != required_role
    ):
        errors.append(
            f"{label} fix {fix_id} lacks the configured reviewer role"
        )
    if (
        not isinstance(reviewer_digest, str)
        or ownership.get("authorizationDigest") != reviewer_digest
    ):
        errors.append(
            f"{label} fix {fix_id} review authorization digest is not "
            "ownership-bound"
        )
    review_rows = [
        row
        for row in evidence_rows
        if isinstance(review_evidence_id, str)
        and row.get("evidenceId") == review_evidence_id
    ]
    authorization = (
        authenticated_authorization
        if isinstance(authenticated_authorization, dict)
        else {}
    )
    authorization_required = record.get("state") not in {
        "released",
        "rejected",
        "superseded",
    }
    source = record.get("source")
    source = source if isinstance(source, dict) else {}
    expected_path_inventory_digest = semantic_digest(
        {
            "conflictPaths": sorted(provenance.get("conflictPaths", [])),
            "touchedPaths": sorted(provenance.get("touchedPaths", [])),
        }
    )
    if authorization_required and (
        not authorization
        or authorization.get("fixId") != fix_id
        or authorization.get("provenanceMode") != mode
        or authorization.get("reviewerRole") != required_role
        or authorization.get("sourceCommit") != source.get("sourceCommit")
        or authorization.get("candidateCommit") != candidate_commit
        or authorization.get("normalizedDiffEvidenceDigest")
        != provenance.get("normalizedDiffEvidenceDigest")
        or authorization.get("pathInventoryDigest")
        != expected_path_inventory_digest
        or authorization.get("focusedTestEvidenceIds")
        != provenance.get("focusedTestEvidenceIds")
        or authorization.get("reviewEvidenceId") != review_evidence_id
        or authorization.get("authorizationDigest") != reviewer_digest
        or authorization.get("producerAuthenticated") is not True
    ):
        errors.append(
            f"{label} fix {fix_id} lacks an exact authenticated protected "
            "review authorization"
        )
    if (
        authorization_required
        and review_rows
        and authorization.get("predecessorCommit")
        != review_rows[0].get("predecessorCommit")
    ):
        errors.append(
            f"{label} fix {fix_id} review authorization predecessor is inconsistent"
        )
    if (
        len(review_rows) != 1
        or review_rows[0].get("digest") != reviewer_digest
        or review_rows[0].get("visibility") != "protected"
        or review_rows[0].get("candidateCommit") != candidate_commit
        or not isinstance(review_rows[0].get("predecessorCommit"), str)
    ):
        errors.append(
            f"{label} fix {fix_id} lacks exact protected review evidence"
        )
    return errors


def clean_cherry_pick_review_errors(
    record: dict[str, Any],
    policy: dict[str, Any],
    authenticated_authorization: dict[str, Any] | None = None,
) -> list[str]:
    """Authenticate independent review of a clean cherry-pick."""

    return _provenance_review_errors(
        record,
        policy,
        mode="clean-cherry-pick",
        reviewer_role_field="cleanCherryPickReviewerRole",
        label="clean cherry-pick",
        authenticated_authorization=authenticated_authorization,
    )


def manual_conflict_review_errors(
    record: dict[str, Any],
    policy: dict[str, Any],
    authenticated_authorization: dict[str, Any] | None = None,
) -> list[str]:
    """Authenticate the reviewer and focused evidence for a conflict fix."""

    errors = _provenance_review_errors(
        record,
        policy,
        mode="manual-conflict-resolution",
        reviewer_role_field="manualConflictReviewerRole",
        label="manual conflict",
        authenticated_authorization=authenticated_authorization,
    )
    provenance = record.get("provenance")
    provenance = provenance if isinstance(provenance, dict) else {}
    if provenance.get("mode") != "manual-conflict-resolution":
        return errors
    fix_id = record.get("fixId")
    provenance_policy = policy.get("provenancePolicy")
    provenance_policy = (
        provenance_policy if isinstance(provenance_policy, dict) else {}
    )
    manual_policy = provenance_policy.get("manual-conflict-resolution")
    manual_policy = manual_policy if isinstance(manual_policy, dict) else {}
    review_evidence_id = manual_policy.get("reviewEvidenceId")
    candidate_commit = provenance.get("candidateCommit")
    evidence_rows = [
        row for row in record.get("evidence", []) if isinstance(row, dict)
    ]
    focused_ids = provenance.get("focusedTestEvidenceIds")
    focused_ids = focused_ids if isinstance(focused_ids, list) else []
    if review_evidence_id in focused_ids:
        errors.append(
            f"manual conflict fix {fix_id} reuses review evidence as focused test evidence"
        )
    for evidence_id in focused_ids:
        matching = [
            row for row in evidence_rows if row.get("evidenceId") == evidence_id
        ]
        if (
            len(matching) != 1
            or matching[0].get("candidateCommit") != candidate_commit
            or not isinstance(matching[0].get("predecessorCommit"), str)
        ):
            errors.append(
                f"manual conflict fix {fix_id} focused test evidence is not "
                "candidate-bound"
            )
    return errors


def fix_record_errors(
    record: dict[str, Any],
    policy: dict[str, Any],
    *,
    now: dt.datetime,
    review_authorizations: dict[str, dict[str, Any]] | None = None,
) -> list[str]:
    """Validate one public-safe fix record against the reviewed policy."""

    errors = validate_schema(record, FIX_RECORD_SCHEMA)
    fix_id = record.get("fixId")
    if not isinstance(fix_id, str) or FIX_ID_RE.fullmatch(fix_id) is None:
        errors.append("fix record has an invalid opaque fixId")
    for field, maximum in (("publicTitle", 160), ("publicSummary", 512)):
        error = safe_public_text_error(record.get(field), maximum)
        if error:
            errors.append(f"fix {fix_id or '<unknown>'} {field} {error}")
    classification = record.get("classification")
    disposition = record.get("disposition")
    lane = record.get("releaseLane")
    state = record.get("state")
    if classification not in CLASSIFICATIONS:
        errors.append(f"fix {fix_id} uses an unknown classification")
    if disposition not in DISPOSITIONS:
        errors.append(f"fix {fix_id} uses an unknown disposition")
    if lane is not None and lane not in RELEASE_LANES:
        errors.append(f"fix {fix_id} uses an unknown release lane")
    expected_lane = disposition if disposition in RELEASE_LANES else None
    if lane != expected_lane:
        errors.append(f"fix {fix_id} release lane contradicts its disposition")
    if state not in FIX_STATES:
        errors.append(f"fix {fix_id} uses an unknown state")
    expected_public_projection_digest = semantic_digest(
        {
            "fixId": fix_id,
            "classification": classification,
            "publicSummary": record.get("publicSummary"),
        }
    )
    if record.get("publicProjectionDigest") != expected_public_projection_digest:
        errors.append(f"fix {fix_id} public projection digest is inconsistent")
    history = record.get("stateTransitions")
    history = history if isinstance(history, list) else []
    if not history or history[-1].get("to") != state:
        errors.append(f"fix {fix_id} state history does not terminate at its current state")
    transition_pairs = _transition_pairs(policy)
    prior_time: dt.datetime | None = None
    prior_state: str | None = None
    for sequence, row in enumerate(history):
        if not isinstance(row, dict):
            errors.append(f"fix {fix_id} has a malformed state transition")
            continue
        source = row.get("from")
        target = row.get("to")
        if row.get("sequence") != sequence:
            errors.append(f"fix {fix_id} state transition sequence is not contiguous")
        occurred_at = parse_timestamp(row.get("occurredAt"))
        if occurred_at is None or (prior_time is not None and occurred_at < prior_time):
            errors.append(f"fix {fix_id} state transition timestamps are malformed or reordered")
        elif occurred_at > now:
            errors.append(f"fix {fix_id} state transition is future-dated")
        if source != prior_state:
            errors.append(f"fix {fix_id} state transition history is not contiguous")
        if source is not None and (source, target) not in transition_pairs:
            errors.append(f"fix {fix_id} uses a forbidden {source}-to-{target} transition")
        if source is None and target != "submitted":
            errors.append(f"fix {fix_id} must begin in submitted state")
        prior_state = target if isinstance(target, str) else prior_state
        prior_time = occurred_at or prior_time
    if classification == "breaking-change" and disposition in RELEASE_LANES:
        errors.append(f"breaking fix {fix_id} is never eligible for Stable 1.0")
    if classification == "unsupported-feature-change" and disposition in RELEASE_LANES:
        errors.append(f"unsupported feature fix {fix_id} is not eligible for Stable 1.0")
    if classification == "security-fix":
        security = record.get("security")
        security = security if isinstance(security, dict) else {}
        if not all(
            security.get(field)
            for field in (
                "incidentOpaqueId",
                "severity",
                "disclosureState",
                "publicProjectionDigest",
                "privateRecordDigest",
            )
        ):
            errors.append(f"security fix {fix_id} lacks its opaque incident projection")
        if security.get("severity") == "critical" and disposition not in {
            "security-hotfix",
            "deferred",
        }:
            errors.append(f"critical security fix {fix_id} is assigned to the wrong lane")
        if (
            disposition == "security-hotfix"
            and security.get("severity") != "critical"
        ):
            errors.append(
                f"noncritical security fix {fix_id} cannot use the security-hotfix lane"
            )
        if security.get("publicProjectionDigest") == security.get("privateRecordDigest"):
            errors.append(f"security fix {fix_id} does not separate public and protected views")
        if security.get("severity") != record.get("severity"):
            errors.append(f"security fix {fix_id} severity scope is inconsistent")
        expected_security_projection_digest = semantic_digest(
            {
                "fixId": fix_id,
                "incidentOpaqueId": security.get("incidentOpaqueId"),
                "advisoryOpaqueId": security.get("advisoryOpaqueId"),
                "severity": security.get("severity"),
                "disclosureState": security.get("disclosureState"),
                "publicSafeSummary": security.get("publicSafeSummary"),
            }
        )
        incident_id = security.get("incidentOpaqueId")
        pr_288_bound = isinstance(incident_id, str) and incident_id.startswith("sv-")
        if security.get("publicProjectionDigest") != expected_security_projection_digest:
            errors.append(f"security fix {fix_id} public security projection is inconsistent")
        if pr_288_bound and DIGEST_RE.fullmatch(
            str(security.get("vulnerabilityPublicProjectionDigest", ""))
        ) is None:
            errors.append(
                f"security fix {fix_id} lacks its PR-288 vulnerability projection binding"
            )
        if record.get("privateRecordDigest") != security.get("privateRecordDigest"):
            errors.append(f"security fix {fix_id} protected-record digest was substituted")
        if security.get("severity") == "critical":
            errors.extend(
                _critical_transition_window_errors(
                    fix_id, history, policy, now=now
                )
            )
            schedule = record.get("schedule")
            schedule = schedule if isinstance(schedule, dict) else {}
            evidence = record.get("evidence")
            evidence = evidence if isinstance(evidence, list) else []
            errors.extend(
                _critical_deferral_errors(
                    fix_id,
                    history,
                    policy,
                    evidence,
                    schedule,
                    now=now,
                )
            )
    elif record.get("security") is not None:
        errors.append(f"non-security fix {fix_id} carries a security record")
    elif record.get("privateRecordDigest") is not None:
        errors.append(f"non-security fix {fix_id} carries a protected-record digest")
    if disposition == "security-hotfix" and classification != "security-fix":
        errors.append(f"fix {fix_id} cannot use the security-hotfix lane")
    if (state == "deferred") != (disposition == "deferred"):
        errors.append(f"fix {fix_id} deferred state contradicts its disposition")
    eligibility = policy.get("classificationEligibility", {}).get(classification)
    if isinstance(eligibility, dict):
        if disposition not in eligibility.get("allowedDispositions", []):
            errors.append(
                f"fix {fix_id} disposition is forbidden for its classification"
            )
        if lane is not None and lane not in eligibility.get("allowedLanes", []):
            errors.append(f"fix {fix_id} lane is forbidden for its classification")
        present_evidence_ids = {
            row.get("evidenceId")
            for row in record.get("evidence", [])
            if isinstance(row, dict)
        }
        missing_evidence = sorted(
            set(eligibility.get("requiredEvidenceIds", []))
            - present_evidence_ids
        )
        if missing_evidence:
            errors.append(
                f"fix {fix_id} lacks required classification evidence"
            )
    evidence_policy = policy.get("evidencePolicy")
    evidence_policy = (
        evidence_policy if isinstance(evidence_policy, dict) else {}
    )
    protected_evidence_ids = set(
        str(row)
        for row in evidence_policy.get("protectedEvidenceIds", [])
        if isinstance(row, str)
    )
    for evidence in record.get("evidence", []):
        if not isinstance(evidence, dict):
            continue
        if (
            evidence.get("evidenceId") in protected_evidence_ids
            and evidence.get("visibility") != "protected"
        ):
            errors.append(
                f"fix {fix_id} exposes policy-protected evidence as public"
            )
    if state == "deferred":
        ownership = record.get("ownership")
        ownership = ownership if isinstance(ownership, dict) else {}
        schedule = record.get("schedule")
        schedule = schedule if isinstance(schedule, dict) else {}
        if not ownership.get("ownerRole") or not schedule.get("rationale") or not schedule.get(
            "reviewAt"
        ):
            errors.append(f"deferred fix {fix_id} lacks owner, rationale, or review time")
    if disposition == "rejected" and state != "rejected":
        errors.append(
            f"fix {fix_id} uses rejected routing without entering rejected state"
        )
    if disposition == "rejected":
        reason = history[-1].get("reasonCode") if history else None
        if not isinstance(reason, str) or SAFE_REASON_RE.fullmatch(reason) is None:
            errors.append(f"rejected fix {fix_id} lacks a safe reason code")
    if state == "superseded":
        replacement = record.get("supersedingFixId")
        if not isinstance(replacement, str) or FIX_ID_RE.fullmatch(replacement) is None:
            errors.append(f"superseded fix {fix_id} lacks a replacement fix id")
    elif record.get("supersedingFixId") is not None:
        errors.append(f"non-superseded fix {fix_id} carries a replacement identity")
    schedule = record.get("schedule")
    schedule = schedule if isinstance(schedule, dict) else {}
    if disposition in RELEASE_LANES and not schedule.get("targetTrainId"):
        errors.append(f"accepted fix {fix_id} lacks its intended train identity")
    deadline = parse_timestamp(schedule.get("deadlineAt"))
    if (
        classification == "security-fix"
        and isinstance(record.get("security"), dict)
        and record.get("security", {}).get("severity") == "critical"
        and deadline is not None
        and deadline < now
        and state not in {"released", "superseded"}
    ):
        errors.append(f"critical security fix {fix_id} is overdue")
    affected_scope = record.get("affectedScope")
    affected_scope = affected_scope if isinstance(affected_scope, dict) else {}
    if classification == "packaging-installer-fix" and not affected_scope.get(
        "packageKeys"
    ):
        errors.append(f"packaging fix {fix_id} lacks affected package keys")
    if classification in {
        "platform-api-compatible-addition",
        "platform-api-deprecation",
    } and not affected_scope.get("platformApiIds"):
        errors.append(f"Platform API fix {fix_id} lacks exact API scope")
    if classification == "stable-catalog-app-patch" and not affected_scope.get(
        "appIds"
    ):
        errors.append(f"stable app fix {fix_id} lacks exact app-id scope")
    provenance = record.get("provenance")
    provenance = provenance if isinstance(provenance, dict) else {}
    provenance_mode = provenance.get("mode")
    if provenance_mode not in PROVENANCE_MODES:
        errors.append(f"fix {fix_id} uses an unknown provenance mode")
    if provenance_mode == "clean-cherry-pick" and not all(
        provenance.get(field)
        for field in (
            "candidateCommit",
            "candidateBranchRole",
            "stablePatchId",
            "candidateTreeOid",
            "candidateTreeDigest",
            "candidateDiffDigest",
            "normalizedDiffEvidenceDigest",
            "reviewerAuthorizationDigest",
        )
    ):
        errors.append(f"clean cherry-pick fix {fix_id} lacks exact patch or review provenance")
    review_authorization = (
        review_authorizations.get(str(fix_id))
        if isinstance(review_authorizations, dict)
        else None
    )
    errors.extend(
        clean_cherry_pick_review_errors(
            record, policy, review_authorization
        )
    )
    if provenance_mode == "manual-conflict-resolution" and (
        not all(
            provenance.get(field)
            for field in (
                "candidateCommit",
                "candidateBranchRole",
                "mergeBaseCommit",
                "sourceBaseCommit",
                "targetBaseCommit",
                "normalizedDiffEvidenceDigest",
                "reviewerAuthorizationDigest",
            )
        )
        or not provenance.get("conflictPaths")
        or not provenance.get("focusedTestEvidenceIds")
        or provenance.get("noUnrelatedFeatureChange") is not True
    ):
        errors.append(f"manual conflict fix {fix_id} lacks its non-waivable review evidence")
    errors.extend(
        manual_conflict_review_errors(record, policy, review_authorization)
    )
    if disposition in RELEASE_LANES and state in {
        "accepted",
        "scheduled",
        "landed",
        "verified",
    }:
        for evidence in record.get("evidence", []):
            if isinstance(evidence, dict):
                expires_at = parse_timestamp(evidence.get("expiresAt"))
                if expires_at is not None and expires_at < now:
                    errors.append(f"fix {fix_id} carries stale candidate evidence")
    if scan_value(record):
        errors.append(f"fix {fix_id} public record failed redaction")
    return errors


def intake_errors(
    intake: dict[str, Any],
    policy: dict[str, Any],
    *,
    policy_digest: str,
    repository_identity: str,
    now: dt.datetime,
    review_authorizations: dict[str, dict[str, Any]] | None = None,
) -> list[str]:
    """Validate one deterministic fix-intake snapshot and its candidate binding."""

    errors = validate_schema(intake, FIX_INTAKE_SCHEMA)
    if intake.get("policyDigest") != policy_digest:
        errors.append("fix intake policy digest does not match the reviewed policy")
    if intake.get("repositoryIdentity") != repository_identity:
        errors.append("fix intake is bound to a different repository")
    fixes = intake.get("fixes")
    fixes = fixes if isinstance(fixes, list) else []
    ids = [row.get("fixId") for row in fixes if isinstance(row, dict)]
    if len(ids) != len(fixes) or len(ids) != len(set(ids)):
        errors.append("fix intake contains a duplicate or malformed fix id")
    if ids != sorted(ids):
        errors.append("fix intake records are not in deterministic fix-id order")
    for row in fixes:
        if isinstance(row, dict):
            errors.extend(
                fix_record_errors(
                    row,
                    policy,
                    now=now,
                    review_authorizations=review_authorizations,
                )
            )
            for evidence in row.get("evidence", []):
                if (
                    isinstance(evidence, dict)
                    and evidence.get("policyDigest") != policy_digest
                ):
                    errors.append(
                        f"fix {row.get('fixId')} evidence is not bound to the reviewed policy"
                    )
    by_id = {
        row.get("fixId"): row
        for row in fixes
        if isinstance(row, dict) and isinstance(row.get("fixId"), str)
    }
    for row in fixes:
        if not isinstance(row, dict) or row.get("state") != "superseded":
            continue
        replacement = by_id.get(row.get("supersedingFixId"))
        if (
            replacement is None
            or replacement is row
            or replacement.get("affectedScope") != row.get("affectedScope")
        ):
            errors.append(
                f"superseded fix {row.get('fixId')} lacks a compatible in-scope replacement"
            )
            continue
        security = row.get("security")
        replacement_security = replacement.get("security")
        if (
            row.get("classification") == "security-fix"
            and isinstance(security, dict)
            and security.get("severity") == "critical"
            and (
                replacement.get("classification") != "security-fix"
                or not isinstance(replacement_security, dict)
                or replacement_security.get("severity") != "critical"
                or replacement_security.get("incidentOpaqueId")
                != security.get("incidentOpaqueId")
                or replacement_security.get("advisoryOpaqueId")
                != security.get("advisoryOpaqueId")
            )
        ):
            errors.append(
                f"superseded critical fix {row.get('fixId')} lacks an "
                "incident- and severity-equivalent replacement"
            )
    cycle_signatures: set[tuple[str, ...]] = set()
    for start_id in sorted(by_id):
        path: list[str] = []
        path_offsets: dict[str, int] = {}
        current_id = start_id
        while True:
            current = by_id.get(current_id)
            if not isinstance(current, dict) or current.get("state") != "superseded":
                break
            if current_id in path_offsets:
                cycle = path[path_offsets[current_id] :]
                signature = tuple(sorted(cycle))
                if signature not in cycle_signatures:
                    errors.append(
                        "supersession chain is cyclic: " + ", ".join(signature)
                    )
                    cycle_signatures.add(signature)
                break
            path_offsets[current_id] = len(path)
            path.append(current_id)
            replacement_id = current.get("supersedingFixId")
            replacement = by_id.get(replacement_id)
            if (
                not isinstance(replacement_id, str)
                or not isinstance(replacement, dict)
                or replacement is current
                or replacement.get("affectedScope") != current.get("affectedScope")
            ):
                break
            current_security = current.get("security")
            replacement_security = replacement.get("security")
            if (
                current.get("classification") == "security-fix"
                and isinstance(current_security, dict)
                and current_security.get("severity") == "critical"
                and (
                    replacement.get("classification") != "security-fix"
                    or not isinstance(replacement_security, dict)
                    or replacement_security.get("severity") != "critical"
                    or replacement_security.get("incidentOpaqueId")
                    != current_security.get("incidentOpaqueId")
                    or replacement_security.get("advisoryOpaqueId")
                    != current_security.get("advisoryOpaqueId")
                )
            ):
                break
            current_id = replacement_id
    candidate_commits = [
        row.get("provenance", {}).get("candidateCommit")
        for row in fixes
        if isinstance(row, dict)
        and isinstance(row.get("provenance"), dict)
        and row.get("provenance", {}).get("candidateCommit") is not None
    ]
    if len(candidate_commits) != len(set(candidate_commits)):
        errors.append("fix intake assigns one candidate commit to multiple fix identities")
    obligations = intake.get("obligations")
    obligations = obligations if isinstance(obligations, list) else []
    obligation_ids = [
        row.get("obligationId") for row in obligations if isinstance(row, dict)
    ]
    if (
        len(obligation_ids) != len(obligations)
        or len(obligation_ids) != len(set(obligation_ids))
        or obligation_ids != sorted(obligation_ids)
    ):
        errors.append("fix intake obligations are duplicated, malformed, or reordered")
    for obligation in obligations:
        if not isinstance(obligation, dict):
            continue
        status = obligation.get("status")
        generated_at = parse_timestamp(obligation.get("generatedAt"))
        resolved_at = parse_timestamp(obligation.get("resolvedAt"))
        if not obligation.get("sourceFixIds"):
            errors.append(
                f"obligation {obligation.get('obligationId')} lacks source fix identities"
            )
        if status == "open" and obligation.get("resolvedAt") is not None:
            errors.append(
                f"open obligation {obligation.get('obligationId')} claims resolution"
            )
        if generated_at is not None and generated_at > now:
            errors.append(
                f"obligation {obligation.get('obligationId')} generation time is future-dated"
            )
        if resolved_at is not None and resolved_at > now:
            errors.append(
                f"obligation {obligation.get('obligationId')} resolution time is future-dated"
            )
        if status == "resolved" and (
            resolved_at is None
            or generated_at is None
            or resolved_at < generated_at
        ):
            errors.append(
                f"resolved obligation {obligation.get('obligationId')} lacks resolution time"
            )
    expected_intake_projection = semantic_digest(
        {
            "fixIds": sorted(str(fix_id) for fix_id in ids),
            "obligations": [
                {
                    "obligationId": row.get("obligationId"),
                    "status": row.get("status"),
                }
                for row in obligations
                if isinstance(row, dict)
            ],
        }
    )
    if intake.get("publicProjectionDigest") != expected_intake_projection:
        errors.append("fix intake public projection digest is inconsistent")
    incident_rows: dict[str, list[dict[str, Any]]] = {}
    for row in fixes:
        if not isinstance(row, dict) or not isinstance(row.get("security"), dict):
            continue
        incident_id = row["security"].get("incidentOpaqueId")
        if not isinstance(incident_id, str):
            continue
        prior_rows = incident_rows.setdefault(incident_id, [])
        for prior in prior_rows:
            prior_components = set(
                prior.get("affectedScope", {}).get("components", [])
            )
            current_components = set(
                row.get("affectedScope", {}).get("components", [])
            )
            if (
                prior_components & current_components
                and (
                    prior.get("disposition") != row.get("disposition")
                    or prior.get("releaseLane") != row.get("releaseLane")
                )
            ):
                errors.append(
                    f"security incident {incident_id} has overlapping contradictory scope"
                )
        prior_rows.append(row)
    declared_digest = intake.get("intakeDigest")
    if declared_digest != canonical_identity_digest(intake, "intakeDigest"):
        errors.append("fix intake identity digest is missing or inconsistent")
    return errors


def _queue_entry(record: dict[str, Any]) -> dict[str, Any]:
    """Return the bounded queue projection of one complete fix record."""

    return {
        key: record.get(key)
        for key in (
            "schemaVersion",
            "kind",
            "stableMilestone",
            "fixId",
            "publicTitle",
            "publicSummary",
            "classification",
            "disposition",
            "releaseLane",
            "severity",
            "risk",
            "affectedScope",
            "source",
            "candidate",
            "provenance",
            "evidence",
            "security",
            "ownership",
            "schedule",
            "state",
            "stateTransitions",
            "supersedingFixId",
            "privateRecordDigest",
            "publicProjectionDigest",
        )
        if key in record
    }


def build_queue(
    intake: dict[str, Any],
    previous: dict[str, Any] | None,
    *,
    policy_digest: str,
    latest_maintenance_pointer_digest: str,
    lifecycle_ledger_digest: str,
    repository_identity: str,
    candidate_commit: str | None,
    hotfix_follow_up_closure_digest: str | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Merge a prior append-only queue and the current intake without omission."""

    errors: list[str] = []
    previous_entries = (
        previous.get("fixes", [])
        if isinstance(previous, dict) and isinstance(previous.get("fixes"), list)
        else []
    )
    current_fixes = intake.get("fixes")
    current_fixes = current_fixes if isinstance(current_fixes, list) else []
    prior_by_id = {
        row.get("fixId"): row
        for row in previous_entries
        if isinstance(row, dict) and isinstance(row.get("fixId"), str)
    }
    current_by_id = {
        row.get("fixId"): row
        for row in current_fixes
        if isinstance(row, dict) and isinstance(row.get("fixId"), str)
    }
    automatically_carried_terminal_fix_ids: set[str] = set()
    previous_obligations = (
        previous.get("obligations", [])
        if isinstance(previous, dict)
        and isinstance(previous.get("obligations"), list)
        else []
    )
    current_obligations = (
        intake.get("obligations", [])
        if isinstance(intake.get("obligations"), list)
        else []
    )
    prior_obligation_by_id = {
        row.get("obligationId"): row
        for row in previous_obligations
        if isinstance(row, dict) and isinstance(row.get("obligationId"), str)
    }
    current_obligation_by_id = {
        row.get("obligationId"): row
        for row in current_obligations
        if isinstance(row, dict) and isinstance(row.get("obligationId"), str)
    }
    for obligation_id, prior in prior_obligation_by_id.items():
        current = current_obligation_by_id.get(obligation_id)
        if current is None:
            if prior.get("status") == "open":
                errors.append(
                    f"prior open obligation {obligation_id} was omitted from the queue"
                )
            else:
                current_obligation_by_id[obligation_id] = prior
            continue
        for immutable in (
            "obligationId",
            "obligationType",
            "sourceTrainId",
            "sourceFixIds",
            "generatedAt",
        ):
            if current.get(immutable) != prior.get(immutable):
                errors.append(
                    f"obligation {obligation_id} rewrites immutable {immutable}"
                )
        if prior.get("status") == "resolved" and current.get("status") != "resolved":
            errors.append(f"resolved obligation {obligation_id} was reopened")
        if prior.get("status") == "resolved" and (
            current.get("evidenceDigest") != prior.get("evidenceDigest")
            or current.get("resolvedAt") != prior.get("resolvedAt")
        ):
            errors.append(
                f"resolved obligation {obligation_id} rewrites its resolution evidence"
            )
        if (
            prior.get("status") == "open"
            and current.get("status") == "resolved"
            and (
                not current.get("evidenceDigest")
                or current.get("evidenceDigest") == prior.get("evidenceDigest")
                or parse_timestamp(current.get("resolvedAt")) is None
            )
        ):
            errors.append(
                f"obligation {obligation_id} resolution lacks new exact evidence"
            )
    for obligation_id, current in current_obligation_by_id.items():
        if (
            obligation_id not in prior_obligation_by_id
            and current.get("status") == "resolved"
        ):
            errors.append(
                f"new obligation {obligation_id} cannot begin resolved"
            )
    unresolved_states = {
        "submitted",
        "triaged",
        "accepted",
        "scheduled",
        "landed",
        "verified",
        "deferred",
    }

    def explicit_routing_transition(
        prior: dict[str, Any],
        current: dict[str, Any],
    ) -> bool:
        """Allow routing changes only when append-only state history explains them."""

        prior_history = prior.get("stateTransitions")
        current_history = current.get("stateTransitions")
        if not isinstance(prior_history, list) or not isinstance(current_history, list):
            return False
        appended = current_history[len(prior_history) :]
        if not appended or any(not isinstance(row, dict) for row in appended):
            return False
        current_disposition = current.get("disposition")
        if (
            current_disposition in {"deferred", "rejected"}
            and current.get("state") == current_disposition
            and appended[-1].get("to") == current_disposition
        ):
            return True
        prior_disposition = prior.get("disposition")
        routable_dispositions = set(RELEASE_LANES) | {"future-milestone"}
        return (
            prior_disposition in {"deferred", "rejected"}
            and prior.get("state") == prior_disposition
            and appended[0].get("from") == prior_disposition
            and appended[0].get("to") == "triaged"
            and current_disposition in routable_dispositions
            and current.get("releaseLane")
            == (
                current_disposition
                if current_disposition in RELEASE_LANES
                else None
            )
        )

    def explicit_rescheduling_transition(
        prior: dict[str, Any],
        current: dict[str, Any],
    ) -> bool:
        """Require a scheduled fix to leave its train through deferred state."""

        prior_history = prior.get("stateTransitions")
        current_history = current.get("stateTransitions")
        if not isinstance(prior_history, list) or not isinstance(
            current_history, list
        ):
            return False
        appended = current_history[len(prior_history) :]
        return (
            prior.get("state") == "scheduled"
            and bool(appended)
            and isinstance(appended[0], dict)
            and appended[0].get("from") == "scheduled"
            and appended[0].get("to") == "deferred"
        )

    for fix_id, row in prior_by_id.items():
        if row.get("state") in unresolved_states and fix_id not in current_by_id:
            errors.append(f"prior unresolved fix {fix_id} was omitted from the queue")
        current = current_by_id.get(fix_id)
        if isinstance(current, dict):
            prior_history = row.get("stateTransitions")
            current_history = current.get("stateTransitions")
            if (
                not isinstance(prior_history, list)
                or not isinstance(current_history, list)
                or current_history[: len(prior_history)] != prior_history
            ):
                errors.append(f"fix {fix_id} rewrites its append-only transition history")
            for immutable in (
                "fixId",
                "classification",
                "affectedScope",
                "source",
                "privateRecordDigest",
                "publicProjectionDigest",
            ):
                if current.get(immutable) != row.get(immutable):
                    errors.append(f"fix {fix_id} rewrites immutable {immutable} provenance")
            if (
                row.get("state") == "superseded"
                and current.get("supersedingFixId")
                != row.get("supersedingFixId")
            ):
                errors.append(
                    f"fix {fix_id} rewrites immutable supersedingFixId provenance"
                )
            if current.get("severity") != row.get("severity"):
                errors.append(f"fix {fix_id} rewrites immutable severity")
            prior_security = row.get("security")
            current_security = current.get("security")
            if isinstance(prior_security, dict) or isinstance(current_security, dict):
                prior_security = (
                    prior_security if isinstance(prior_security, dict) else {}
                )
                current_security = (
                    current_security if isinstance(current_security, dict) else {}
                )
                for immutable in (
                    "incidentOpaqueId",
                    "advisoryOpaqueId",
                    "severity",
                    "privateRecordDigest",
                    "vulnerabilityPublicProjectionDigest",
                ):
                    if current_security.get(immutable) != prior_security.get(immutable):
                        errors.append(
                            f"fix {fix_id} rewrites immutable security {immutable}"
                        )
            if (
                current.get("disposition") != row.get("disposition")
                or current.get("releaseLane") != row.get("releaseLane")
            ) and not explicit_routing_transition(row, current):
                errors.append(
                    f"fix {fix_id} rewrites release routing without an explicit "
                    "state transition"
                )
            if (
                row.get("state")
                in {"scheduled", "landed", "verified", "released"}
                and current.get("schedule") != row.get("schedule")
                and not explicit_rescheduling_transition(row, current)
            ):
                errors.append(
                    f"fix {fix_id} rewrites immutable scheduled train assignment"
                )
            if row.get("state") in {"landed", "verified", "released"} and (
                current.get("provenance") != row.get("provenance")
            ):
                errors.append(
                    f"fix {fix_id} rewrites immutable landed provenance"
                )
    for fix_id, row in prior_by_id.items():
        if fix_id not in current_by_id and row.get("state") in {
            "rejected",
            "released",
            "superseded",
        }:
            current_by_id[fix_id] = copy.deepcopy(row)
            automatically_carried_terminal_fix_ids.add(fix_id)
    state_priority = {
        state: index
        for index, state in enumerate(
            (
                "verified",
                "landed",
                "scheduled",
                "accepted",
                "triaged",
                "submitted",
                "deferred",
                "rejected",
                "superseded",
                "released",
            )
        )
    }

    def ordering_key(row: dict[str, Any]) -> tuple[int, str, str]:
        schedule = row.get("schedule")
        deadline = (
            schedule.get("deadlineAt")
            if isinstance(schedule, dict) and isinstance(schedule.get("deadlineAt"), str)
            else "9999-12-31T23:59:59Z"
        )
        return (
            state_priority.get(str(row.get("state")), len(state_priority)),
            deadline,
            str(row.get("fixId")),
        )

    entries = sorted(
        (_queue_entry(row) for row in current_by_id.values()),
        key=ordering_key,
    )
    obligation_entries = sorted(
        current_obligation_by_id.values(),
        key=lambda row: str(row.get("obligationId")),
    )
    previous_digest = previous.get("queueDigest") if isinstance(previous, dict) else None
    candidate_commits = [
        row.get("provenance", {}).get("candidateCommit")
        for row in entries
        if isinstance(row.get("provenance"), dict)
        and row.get("provenance", {}).get("candidateCommit") is not None
    ]
    if len(candidate_commits) != len(set(candidate_commits)):
        errors.append("queue assigns one candidate commit to multiple fix identities")
    if previous is not None:
        errors.extend(validate_schema(previous, QUEUE_SCHEMA))
        if previous_digest != queue_identity_digest(previous):
            errors.append("prior queue digest is inconsistent")
        errors.extend(queue_evidence_binding_errors(previous))
        if previous.get("policyDigest") != policy_digest:
            errors.append("prior queue uses a different release-train policy")
        if previous.get("repositoryIdentity") != repository_identity:
            errors.append("prior queue is bound to a different repository")
        if intake.get("previousQueueDigest") != previous_digest:
            errors.append("fix intake does not authenticate the immediately prior queue")
    elif intake.get("previousQueueDigest") is not None:
        errors.append("genesis queue intake names an unavailable prior queue")
    intake_id = str(intake.get("intakeId", ""))
    queue_id = intake_id.replace("stable-intake-", "stable-queue-", 1)
    unresolved_fix_ids = sorted(
        str(row["fixId"])
        for row in entries
        if row.get("state")
        in {"submitted", "triaged", "accepted", "scheduled", "landed", "verified", "deferred"}
    )
    critical_fix_ids = sorted(
        str(row["fixId"])
        for row in entries
        if row.get("severity") == "critical"
        and row.get("state") not in {"released", "superseded"}
    )
    deferred_fix_ids = sorted(
        str(row["fixId"]) for row in entries if row.get("state") == "deferred"
    )
    rejected_fix_ids = sorted(
        str(row["fixId"]) for row in entries if row.get("state") == "rejected"
    )
    superseded_fix_ids = sorted(
        str(row["fixId"]) for row in entries if row.get("state") == "superseded"
    )
    carried_obligation_ids = sorted(
        str(row["obligationId"])
        for row in obligation_entries
        if row.get("status") == "open"
    )
    transition_subject = [
        {"fixId": row.get("fixId"), "stateTransitions": row.get("stateTransitions")}
        for row in entries
    ]
    transition_subject.extend(
        {
            "obligationId": row.get("obligationId"),
            "status": row.get("status"),
            "evidenceDigest": row.get("evidenceDigest"),
        }
        for row in obligation_entries
    )
    queue = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "stable-1.0-release-train-queue",
        "generatedAt": intake.get("generatedAt"),
        "stableMilestone": STABLE_MILESTONE,
        "policyDigest": policy_digest,
        "repositoryIdentity": repository_identity,
        "queueId": queue_id,
        "previousQueueDigest": previous_digest,
        "latestMaintenancePointerDigest": latest_maintenance_pointer_digest,
        "hotfixFollowUpClosureDigest": hotfix_follow_up_closure_digest,
        "lifecycleLedgerDigest": lifecycle_ledger_digest,
        "candidateCommit": candidate_commit,
        "fixes": entries,
        "obligations": obligation_entries,
        "unresolvedFixIds": unresolved_fix_ids,
        "criticalFixIds": critical_fix_ids,
        "deferredFixIds": deferred_fix_ids,
        "rejectedFixIds": rejected_fix_ids,
        "supersededFixIds": superseded_fix_ids,
        "carriedObligationIds": carried_obligation_ids,
        "ordering": "state-priority,deadline,fix-id",
        "transitionDigest": semantic_digest(transition_subject),
        "status": "blocked" if errors or carried_obligation_ids else "ready",
        "redaction": dict(_PASS_REDACTION),
    }
    queue["queueDigest"] = queue_identity_digest(queue)
    for fix in entries:
        if not isinstance(fix, dict):
            continue
        if fix.get("fixId") in automatically_carried_terminal_fix_ids:
            for evidence in fix.get("evidence", []):
                if isinstance(evidence, dict):
                    evidence["queueDigest"] = queue["queueDigest"]
        for evidence in fix.get("evidence", []):
            if not isinstance(evidence, dict):
                continue
            if evidence.get("policyDigest") != policy_digest:
                errors.append(
                    f"fix {fix.get('fixId')} evidence policy binding is inconsistent"
                )
            if evidence.get("queueDigest") != queue["queueDigest"]:
                errors.append(
                    f"fix {fix.get('fixId')} evidence queue binding is inconsistent"
                )
    errors.extend(validate_schema(queue, QUEUE_SCHEMA))
    return queue, errors


def permitted_carried_obligation_ids(
    queue: dict[str, Any],
    previous: dict[str, Any] | None,
    *,
    lane: str,
    policy: dict[str, Any],
    predecessor_baseline: dict[str, Any] | None = None,
) -> tuple[list[str], list[str]]:
    """Return the exact inherited obligations compatible with this release lane."""

    errors: list[str] = []
    obligations = queue.get("obligations")
    obligations = obligations if isinstance(obligations, list) else []
    open_rows = [
        row
        for row in obligations
        if isinstance(row, dict) and row.get("status") == "open"
    ]
    open_ids = sorted(str(row.get("obligationId")) for row in open_rows)
    if queue.get("carriedObligationIds") != open_ids:
        errors.append("release-train queue carried-obligation index is inconsistent")
    published_follow_up = (
        predecessor_baseline.get("hotfixFollowUp")
        if isinstance(predecessor_baseline, dict)
        else None
    )
    published_follow_up = (
        published_follow_up if isinstance(published_follow_up, dict) else {}
    )
    if not open_rows:
        if published_follow_up.get("status") in {"open", "overdue"}:
            errors.append(
                "published predecessor hotfix follow-up is absent from "
                "the release-train queue"
            )
        return [], errors
    if lane != "security-hotfix":
        errors.append(
            "prior post-release or hotfix obligations are incompatible with this lane"
        )
        return [], errors
    queue_policy = policy.get("queuePolicy")
    queue_policy = queue_policy if isinstance(queue_policy, dict) else {}
    allowed_types = queue_policy.get(
        "securityHotfixAllowedCarriedObligationTypes"
    )
    maximum = queue_policy.get("securityHotfixMaximumCarriedFollowUps")
    if (
        allowed_types != ["hotfix-follow-up"]
        or type(maximum) is not int
        or maximum != 1
        or queue_policy.get("publicationCreatedFollowUpBaselineBindingRequired")
        is not True
    ):
        errors.append("security-hotfix carry-forward policy is malformed")
        return [], errors
    previous_obligations = (
        previous.get("obligations", [])
        if isinstance(previous, dict)
        and isinstance(previous.get("obligations"), list)
        else []
    )
    prior_open_by_id = {
        row.get("obligationId"): row
        for row in previous_obligations
        if isinstance(row, dict)
        and isinstance(row.get("obligationId"), str)
        and row.get("status") == "open"
    }

    def is_publication_created_follow_up(row: dict[str, Any]) -> bool:
        """Bind a first queue projection to the authenticated predecessor baseline."""

        if published_follow_up.get("status") not in {"open", "overdue"}:
            return False
        if published_follow_up.get("blocksRoutineMaintenance") is not True:
            return False
        obligated_build = published_follow_up.get("obligatedBuildVersion")
        obligation_digest = published_follow_up.get("obligationDigest")
        if not isinstance(obligated_build, str) or not isinstance(
            obligation_digest, str
        ):
            return False
        source_train_id = f"stable-train-{obligated_build}"
        source_fix_ids = sorted(
            str(fix.get("fixId"))
            for fix in (
                previous.get("fixes", [])
                if isinstance(previous, dict)
                and isinstance(previous.get("fixes"), list)
                else []
            )
            if isinstance(fix, dict)
            and fix.get("classification") == "security-fix"
            and fix.get("severity") == "critical"
            and isinstance(fix.get("schedule"), dict)
            and fix["schedule"].get("targetTrainId") == source_train_id
            and isinstance(fix.get("fixId"), str)
        )
        return bool(source_fix_ids) and all(
            (
                row.get("obligationId")
                == f"hotfix-follow-up-{obligated_build}",
                row.get("sourceTrainId") == source_train_id,
                row.get("sourceFixIds") == source_fix_ids,
                row.get("generatedAt") == published_follow_up.get("generatedAt"),
                row.get("status") == "open",
                row.get("resolvedAt") is None,
                row.get("evidenceDigest") == obligation_digest,
            )
        )

    permitted: list[str] = []
    publication_follow_up_present = False
    for row in open_rows:
        obligation_id = str(row.get("obligationId"))
        if row.get("obligationType") not in allowed_types:
            errors.append(
                f"open obligation {obligation_id} is incompatible with a security hotfix"
            )
            continue
        if (
            prior_open_by_id.get(obligation_id) != row
            and not is_publication_created_follow_up(row)
        ):
            errors.append(
                f"hotfix follow-up {obligation_id} is neither an exact inherited "
                "obligation nor authenticated by the predecessor baseline"
            )
            continue
        publication_follow_up_present = (
            publication_follow_up_present
            or is_publication_created_follow_up(row)
        )
        permitted.append(obligation_id)
    if (
        published_follow_up.get("status") in {"open", "overdue"}
        and not publication_follow_up_present
    ):
        errors.append(
            "published predecessor hotfix follow-up is absent from "
            "the release-train queue"
        )
    if len(permitted) > maximum:
        errors.append(
            "security hotfix cannot carry multiple concurrent follow-up obligations"
        )
    return sorted(permitted), errors


def candidate_fix_ids(queue: dict[str, Any], lane: str) -> list[str]:
    """Return accepted fixes that must be represented in the selected candidate."""

    return sorted(
        row.get("fixId")
        for row in queue.get("fixes", [])
        if isinstance(row, dict)
        and row.get("releaseLane") == lane
        and row.get("state") in {"scheduled", "landed", "verified"}
        and isinstance(row.get("fixId"), str)
    )


def release_class_for_lane(lane: str) -> str:
    """Map the release-train lane to the existing Stable maintenance release class."""

    if lane == "routine-maintenance":
        return "maintenance"
    if lane == "security-hotfix":
        return "security-hotfix"
    raise ValueError("unknown Stable release-train lane")


def canonical_json_bytes(value: Any) -> bytes:
    """Return compact canonical bytes used for internal semantic evidence digests."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

"""Pure policy, lineage, ledger, and descriptor helpers for Stable 1.0 lifecycle state."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from .stable_1_0_maintenance_core import (
    GaRoot,
    Predecessor,
    receipt_identity,
    successor_baseline_identity,
)
from .stable_1_0_rc_core import parse_timestamp, semantic_digest
from ..safe_text import recovery_guidance_error

STABLE_MILESTONE = "1.0"
STATUSES = (
    "current-stable",
    "supported-maintenance",
    "security-fixes-only",
    "deprecated",
    "end-of-support",
    "revoked",
)
NORMAL_ORDER = STATUSES[:-1]
NORMAL_TRANSITIONS = tuple(zip(NORMAL_ORDER, NORMAL_ORDER[1:]))
SECURITY_TRANSITION_TARGET = "revoked"
SECURITY_SUPPORTED_STATUSES = {
    "current-stable",
    "supported-maintenance",
    "security-fixes-only",
}
UPDATE_KEY_DOC_NAME = "support-lifecycle"
UPDATE_KEY_IDENTITY_DIGEST = (
    "sha256:b6386982e7eed893448339eed564fcdc140547266b0dc70978ddfa345f6136d7"
)
EVIDENCE_IDS = (
    "stable-lifecycle.ga-root-authentication",
    "stable-lifecycle.maintenance-chain-authentication",
    "stable-lifecycle.policy",
    "stable-lifecycle.release-inventory",
    "stable-lifecycle.state-consistency",
    "stable-lifecycle.transition-policy",
    "stable-lifecycle.transition-authorization",
    "stable-lifecycle.descriptor-integrity",
    "stable-lifecycle.updater-integration",
    "stable-lifecycle.platform-api-deprecation",
    "stable-lifecycle.catalog-app-profile-governance",
    "stable-lifecycle.security-linkage",
    "stable-lifecycle.operator-support",
    "stable-lifecycle.publication-conflict",
    "stable-lifecycle.publication-verification",
    "stable-lifecycle.redaction",
)
GOVERNANCE_REFERENCES = (
    "docs/platform-api-compatibility-support-window.md",
    "platform-api/src/main/java/network/crypta/platform/api/contentformats/ContentFormatProfile.java",
    "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog/AppCatalogProductionMetadata.java",
    "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog/AppCatalogSecurityAdvisoryRecord.java",
    "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog/AppReviewReceiptRevocation.java",
    "tools/release-certification/first-party-app-maintenance-policy.json",
    "tools/release-certification/schemas/stable-1.0-maintenance-successor-baseline-v2.schema.json",
    "docs/platform-api/contracts/platform-api-1.0-baseline.json",
)
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
PUBLIC_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
SECURITY_SEVERITIES = {"critical", "high"}


@dataclass(frozen=True)
class InventoryResult:
    """Authenticated public release inventory and exact input-chain errors."""

    value: dict[str, Any]
    errors: list[str]


def canonical_file_digest(value: Any) -> str:
    """Return the digest of the repository's canonical pretty-printed JSON bytes."""

    encoded = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def canonical_timestamp(value: Any) -> str | None:
    """Return one second-precision canonical UTC timestamp, or ``None``."""

    parsed = parse_timestamp(value)
    if parsed is None:
        return None
    return parsed.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def add_days(value: str, days: int) -> str:
    """Add a policy day count using deterministic UTC calendar arithmetic."""

    parsed = parse_timestamp(value)
    if parsed is None:
        raise ValueError("lifecycle timestamp is malformed")
    return (parsed + dt.timedelta(days=days)).isoformat().replace("+00:00", "Z")


def policy_errors(policy: dict[str, Any]) -> list[str]:
    """Validate cross-field policy semantics not expressible in the offline schema."""

    errors: list[str] = []
    if policy.get("lifecycleVocabulary") != list(STATUSES):
        errors.append("policy lifecycle vocabulary is not the canonical closed order")
    transitions = policy.get("normalTransitions")
    expected = [{"from": before, "to": after} for before, after in NORMAL_TRANSITIONS]
    if transitions != expected:
        errors.append("policy normal transition matrix is not the canonical monotonic matrix")
    revocation = policy.get("revocation")
    if not isinstance(revocation, dict) or revocation.get("fromStatuses") != list(NORMAL_ORDER):
        errors.append("policy revocation path does not cover exactly every non-revoked state")
    if not isinstance(revocation, dict) or revocation.get("terminal") is not True:
        errors.append("policy must make build revocation terminal")
    if (
        not isinstance(revocation, dict)
        or revocation.get("allowEmergencyNoCurrentStableWhenTipRevoked") is not True
    ):
        errors.append(
            "policy must allow the current-stable invariant to suspend only for emergency tip revocation"
        )
    if policy.get("durationUnit") != "days":
        errors.append("policy durationUnit must be days")
    windows = policy.get("supportWindows")
    required_windows = (
        "minimumFullMaintenanceDuration",
        "minimumSecurityFixesOnlyDuration",
        "minimumDeprecationNoticeDuration",
        "maximumDescriptorAgeDays",
        "maximumEvidenceAgeDays",
    )
    if not isinstance(windows, dict) or any(
        type(windows.get(name)) is not int or windows.get(name) < 1
        for name in required_windows
    ):
        errors.append("policy support windows must be positive integer day counts")
    if (
        not isinstance(windows, dict)
        or type(windows.get("maximumGenesisProofAgeMinutes")) is not int
        or not 1 <= windows.get("maximumGenesisProofAgeMinutes") <= 60
    ):
        errors.append("policy genesis absence proof window must be 1 through 60 minutes")
    if (
        not isinstance(windows, dict)
        or type(windows.get("maximumPublicObservationAgeMinutes")) is not int
        or not 1 <= windows.get("maximumPublicObservationAgeMinutes") <= 60
    ):
        errors.append("policy public observation window must be 1 through 60 minutes")
    cardinality = policy.get("cardinality")
    if not isinstance(cardinality, dict) or cardinality.get("currentStable") != 1:
        errors.append("policy current-stable cardinality must be exactly one")
    if (
        not isinstance(cardinality, dict)
        or type(cardinality.get("minimumSimultaneouslySupportedBuilds")) is not int
        or cardinality.get("minimumSimultaneouslySupportedBuilds") < 1
    ):
        errors.append("policy minimum simultaneously supported build count is invalid")
    descriptor = policy.get("descriptor")
    if not isinstance(descriptor, dict) or descriptor.get("updateKeyDocName") != UPDATE_KEY_DOC_NAME:
        errors.append("policy descriptor docname must be support-lifecycle")
    if (
        not isinstance(descriptor, dict)
        or descriptor.get("updateKeyIdentityDigest") != UPDATE_KEY_IDENTITY_DIGEST
    ):
        errors.append("policy descriptor update-key identity is not the pinned Stable 1.0 key")
    if (
        not isinstance(descriptor, dict)
        or type(descriptor.get("maximumEntries")) is not int
        or descriptor.get("maximumEntries") < 1
    ):
        errors.append("policy descriptor entry bound must be a positive integer")
    if policy.get("governanceReferences") != list(GOVERNANCE_REFERENCES):
        errors.append("policy governance references are not the exact canonical trust sources")
    required_revocation = {
        "advisoryId",
        "severity",
        "reasonCode",
        "affectedBuilds",
        "effectiveAt",
        "replacementOrRecoveryGuidance",
        "securityDrillOrReferenceEvidence",
        "protectedAuthorization",
        "publicationTargetAndDigest",
    }
    if not isinstance(revocation, dict) or set(revocation.get("requiredAdvisoryFields", [])) != required_revocation:
        errors.append("policy revocation requirements omit mandatory protected security evidence")
    return errors


def _inventory_entry(
    *,
    release_id: str,
    build: str,
    tag: str,
    source_commit: str,
    release_class: str,
    product_digest: str,
    receipt_digest: str,
    baseline_digest: str,
    published_at: Any,
    chain_depth: int,
    unresolved_follow_up: bool,
) -> dict[str, Any]:
    timestamp = canonical_timestamp(published_at)
    return {
        "releaseId": release_id,
        "buildVersion": build,
        "tag": tag,
        "sourceCommit": source_commit,
        "releaseClass": release_class,
        "productDigest": product_digest,
        "publicationReceiptDigest": receipt_digest,
        "baselineDigest": baseline_digest,
        "publishedAt": timestamp or "",
        "chainDepth": chain_depth,
        "unresolvedHotfixFollowUp": unresolved_follow_up,
    }


def authenticate_inventory(
    ga: GaRoot,
    predecessor: Predecessor,
    ga_receipt: dict[str, Any],
    history: dict[str, Any],
    predecessor_baseline: dict[str, Any],
    predecessor_receipt: dict[str, Any],
    latest_pointer: dict[str, Any] | None,
    generated_at: str,
    maximum_entries: int,
) -> InventoryResult:
    """Reconstruct every real release from exact canonical PR-285 history objects."""

    errors: list[str] = []
    links = history.get("links")
    if (
        history.get("kind") != "stable-1.0-maintenance-authenticated-history"
        or history.get("stableMilestone") != STABLE_MILESTONE
        or not isinstance(links, list)
    ):
        links = []
        errors.append("maintenance history is malformed")
    entries = [
        _inventory_entry(
            release_id=ga.release_id,
            build=ga.build_version,
            tag=ga.tag,
            source_commit=ga.source_commit,
            release_class="stable-ga",
            product_digest=ga.product_digest,
            receipt_digest=ga.receipt_digest,
            baseline_digest=ga.baseline_digest,
            published_at=ga_receipt.get("generatedAt"),
            chain_depth=0,
            unresolved_follow_up=False,
        )
    ]
    previous_baseline_digest = ga.baseline_digest
    previous_build = int(ga.build_version)
    for index, link in enumerate(links, start=1):
        if not isinstance(link, dict):
            errors.append("maintenance history contains a malformed link")
            continue
        baseline = link.get("successorBaseline")
        receipt = link.get("publicationReceipt")
        if not isinstance(baseline, dict) or not isinstance(receipt, dict):
            errors.append("maintenance history link omits exact baseline or receipt objects")
            continue
        baseline_digest = canonical_file_digest(baseline)
        receipt_digest = canonical_file_digest(receipt)
        release = baseline.get("release")
        lineage = baseline.get("lineage")
        publication = baseline.get("publication")
        release = release if isinstance(release, dict) else {}
        lineage = lineage if isinstance(lineage, dict) else {}
        publication = publication if isinstance(publication, dict) else {}
        build = str(release.get("buildVersion", ""))
        if (
            link.get("baselineDigest") != baseline_digest
            or link.get("publicationReceiptDigest") != receipt_digest
        ):
            errors.append("maintenance history exact canonical object digest does not match")
        if (
            baseline.get("previousBaselineDigest") != previous_baseline_digest
            or lineage.get("chainDepth") != index
            or receipt.get("successorBaselineDigest") != baseline_digest
            or receipt.get("publicationState") != "publication-complete"
            or receipt.get("finalVerificationStatus") != "pass"
            or publication.get("receiptIdentityDigest") != receipt_identity(receipt)
            or receipt.get("releaseId") != release.get("releaseId")
            or receipt.get("buildVersion") != build
            or receipt.get("sourceCommit") != release.get("sourceCommit")
            or receipt.get("productDigest") != release.get("productDigest")
            or receipt.get("tag", {}).get("name") != release.get("tag")
            or not build.isdigit()
            or int(build) <= previous_build
        ):
            errors.append("maintenance history contains a gap, fork, or substituted release")
        lineage_history = lineage.get("history")
        if (
            not isinstance(lineage_history, list)
            or len(lineage_history) != index + 1
            or not lineage_history
            or lineage_history[-1].get("baselineIdentityDigest")
            != successor_baseline_identity(baseline)
        ):
            errors.append("maintenance history successor lineage is incomplete or mismatched")
        follow_up = baseline.get("hotfixFollowUp")
        unresolved = isinstance(follow_up, dict) and follow_up.get("status") in {"open", "overdue"}
        entries.append(
            _inventory_entry(
                release_id=str(release.get("releaseId", "")),
                build=build,
                tag=str(release.get("tag", "")),
                source_commit=str(release.get("sourceCommit", "")),
                release_class=str(release.get("releaseClass", "")),
                product_digest=str(release.get("productDigest", "")),
                receipt_digest=receipt_digest,
                baseline_digest=baseline_digest,
                published_at=receipt.get("generatedAt"),
                chain_depth=index,
                unresolved_follow_up=unresolved,
            )
        )
        previous_baseline_digest = baseline_digest
        previous_build = int(build) if build.isdigit() else previous_build
    if len(links) != predecessor.chain_depth:
        errors.append("maintenance history does not contain every published successor")
    if predecessor.chain_depth == 0:
        if links:
            errors.append("GA-only lifecycle requires an empty maintenance history")
        if predecessor.baseline_digest != ga.baseline_digest or predecessor.receipt_digest != ga.receipt_digest:
            errors.append("GA-only predecessor is not the authenticated GA root")
    else:
        if not links:
            errors.append("post-GA lifecycle requires exact maintenance history links")
        elif (
            links[-1].get("successorBaseline") != predecessor_baseline
            or links[-1].get("publicationReceipt") != predecessor_receipt
            or canonical_file_digest(predecessor_baseline) != predecessor.baseline_digest
            or canonical_file_digest(predecessor_receipt) != predecessor.receipt_digest
        ):
            errors.append("maintenance history tip does not equal the authenticated predecessor")
        if latest_pointer is None:
            errors.append("post-GA lifecycle requires the exact latest published pointer")
        elif (
            latest_pointer.get("releaseId") != predecessor.release_id
            or latest_pointer.get("buildVersion") != predecessor.build_version
            or latest_pointer.get("baselineDigest") != predecessor.baseline_digest
            or latest_pointer.get("publicationReceiptDigest") != predecessor.receipt_digest
            or latest_pointer.get("lineageDigest") != predecessor.previous_lineage_digest
            or latest_pointer.get("status") != "active"
        ):
            errors.append("latest published pointer is stale or does not select the history tip")
    for entry in entries:
        if (
            canonical_timestamp(entry.get("publishedAt")) != entry.get("publishedAt")
            or entry.get("tag") != f"v{entry.get('buildVersion')}"
            or not DIGEST_RE.fullmatch(str(entry.get("productDigest", "")))
            or not DIGEST_RE.fullmatch(str(entry.get("publicationReceiptDigest", "")))
            or not DIGEST_RE.fullmatch(str(entry.get("baselineDigest", "")))
        ):
            errors.append("published inventory contains a malformed release identity")
    if entries[-1]["buildVersion"] != predecessor.build_version:
        errors.append("published inventory tip does not equal the authenticated predecessor")
    if type(maximum_entries) is not int or maximum_entries < 1:
        errors.append("lifecycle inventory entry bound is invalid")
    elif len(entries) > maximum_entries:
        errors.append("published inventory exceeds the lifecycle descriptor entry bound")
    inventory = {
        "schemaVersion": 1,
        "kind": "stable-1.0-support-lifecycle-inventory",
        "generatedAt": generated_at,
        "stableMilestone": STABLE_MILESTONE,
        "gaRootDigest": ga.root_identity_digest,
        "latestPointerDigest": predecessor.latest_pointer_digest,
        "chainDepth": predecessor.chain_depth,
        "entries": entries,
        "status": "pass" if not errors else "fail",
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }
    inventory["inventoryDigest"] = semantic_digest(inventory)
    return InventoryResult(inventory, errors)


def deadlines(entry: dict[str, Any], policy: dict[str, Any]) -> dict[str, str]:
    """Derive the four distinct lifecycle deadlines for a published build."""

    windows = policy["supportWindows"]
    published = entry["publishedAt"]
    full = add_days(published, windows["minimumFullMaintenanceDuration"])
    security = add_days(full, windows["minimumSecurityFixesOnlyDuration"])
    deprecated = security
    end = add_days(deprecated, windows["minimumDeprecationNoticeDuration"])
    return {
        "fullSupportUntil": full,
        "securityFixesUntil": security,
        "deprecationEffectiveAt": deprecated,
        "endOfSupportAt": end,
    }


def due_status(entry: dict[str, Any], policy: dict[str, Any], now: dt.datetime, tip: str) -> str:
    """Return the policy-derived non-revocation state at one evaluation time."""

    if entry["buildVersion"] == tip:
        return "current-stable"
    dates = deadlines(entry, policy)
    if now < parse_timestamp(dates["fullSupportUntil"]):
        return "supported-maintenance"
    if now < parse_timestamp(dates["securityFixesUntil"]):
        return "security-fixes-only"
    if now < parse_timestamp(dates["endOfSupportAt"]):
        return "deprecated"
    return "end-of-support"


def _normal_replacement_build(
    status: str,
    build: str,
    tip: str,
    requested: str | None = None,
) -> str | None:
    """Return required normal-transition guidance, excluding optional upgrades."""

    if build == tip or status in {"current-stable", "supported-maintenance"}:
        return None
    return requested or tip


def _initial_status_effective_at(
    entry: dict[str, Any],
    status: str,
    dates: dict[str, str],
    successor_published_at: str | None,
) -> str:
    """Derive a genesis entry's status clock from authenticated release and policy facts."""

    effective = {
        "current-stable": entry["publishedAt"],
        "supported-maintenance": successor_published_at or entry["publishedAt"],
        "security-fixes-only": dates["fullSupportUntil"],
        "deprecated": dates["deprecationEffectiveAt"],
        "end-of-support": dates["endOfSupportAt"],
    }.get(status, entry["publishedAt"])
    if status == "current-stable" or successor_published_at is None:
        return effective
    parsed_effective = parse_timestamp(effective)
    parsed_successor = parse_timestamp(successor_published_at)
    if parsed_effective is None or parsed_successor is None:
        return effective
    return max(parsed_effective, parsed_successor).isoformat().replace("+00:00", "Z")


def ledger_digest(value: dict[str, Any]) -> str:
    """Return the non-circular semantic digest of a lifecycle ledger."""

    return semantic_digest({key: item for key, item in value.items() if key != "ledgerDigest"})


def entry_digest(value: dict[str, Any]) -> str:
    """Return the non-circular semantic digest of one projected build entry."""

    return semantic_digest({key: item for key, item in value.items() if key != "entryDigest"})


def transition_digest(value: dict[str, Any]) -> str:
    """Digest transition policy facts without the later protected approval binding."""

    return semantic_digest(
        {
            key: item
            for key, item in value.items()
            if key not in {"transitionDigest", "resultingLedgerDigest"}
        }
    )


def _reconcile_replacement_guidance(
    entries: list[dict[str, Any]], errors: list[str]
) -> None:
    """Prevent the current projection from recommending an unsafe build.

    Historical transition rows retain the exact guidance authorized at the time. The mutable
    per-build projection instead follows the currently authenticated safe build, or carries the
    revoked tip's recovery-only guidance when no security-supported replacement exists.
    """

    entries_by_build = {row["buildVersion"]: row for row in entries}
    revoked_builds = {
        row["buildVersion"]
        for row in entries
        if row["lifecycleStatus"] == "revoked"
    }
    current = next(
        (row for row in entries if row["lifecycleStatus"] == "current-stable"),
        None,
    )
    tip_entry = entries[-1]
    safe_replacement = current["buildVersion"] if current is not None else None
    recovery_guidance: str | None = None
    if current is None and tip_entry["lifecycleStatus"] == "revoked":
        candidate = tip_entry.get("replacementBuild")
        candidate_entry = next(
            (row for row in entries if row["buildVersion"] == candidate), None
        )
        if (
            candidate_entry is not None
            and candidate_entry["lifecycleStatus"] in SECURITY_SUPPORTED_STATUSES
        ):
            safe_replacement = candidate
        recovery_guidance = tip_entry.get("recoveryGuidance")
    for row in entries:
        replacement = entries_by_build.get(row.get("replacementBuild"))
        points_to_unsupported = (
            replacement is not None
            and replacement["lifecycleStatus"] not in SECURITY_SUPPORTED_STATUSES
        )
        recovery_only = (
            row.get("replacementBuild") is None
            and row.get("recoveryGuidance") is not None
        )
        if not points_to_unsupported and not (
            safe_replacement is not None and recovery_only
        ):
            continue
        if safe_replacement is not None:
            row["replacementBuild"] = (
                safe_replacement
                if safe_replacement != row["buildVersion"]
                else None
            )
            row["recoveryGuidance"] = None
        else:
            row["replacementBuild"] = None
            row["recoveryGuidance"] = row.get("recoveryGuidance") or recovery_guidance
            if row["recoveryGuidance"] is None:
                errors.append(
                    f"build {row['buildVersion']} has no safe replacement or recovery guidance"
                )
        row["entryDigest"] = entry_digest(row)
    if any(row.get("replacementBuild") in revoked_builds for row in entries):
        errors.append("lifecycle ledger recommends a revoked replacement build")


def build_ledger(
    inventory: dict[str, Any],
    policy: dict[str, Any],
    policy_digest: str,
    generated_at: str,
    previous: dict[str, Any] | None,
    request: dict[str, Any] | None,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    """Build a monotonic projection plus retained append-only transition history."""

    errors: list[str] = []
    now = parse_timestamp(generated_at)
    if now is None:
        raise ValueError("lifecycle generation time is malformed")
    inventory_entries = inventory["entries"]
    maximum_entries = policy.get("descriptor", {}).get("maximumEntries")
    if type(maximum_entries) is not int or maximum_entries < 1:
        errors.append("lifecycle descriptor entry bound is invalid")
    elif len(inventory_entries) > maximum_entries:
        errors.append("published inventory exceeds the lifecycle descriptor entry bound")
    tip = inventory_entries[-1]["buildVersion"]
    prior_by_build: dict[str, dict[str, Any]] = {}
    transitions: list[dict[str, Any]] = []
    previous_ledger_digest: str | None = None
    sequence = 0
    if previous is not None:
        if previous.get("ledgerDigest") != ledger_digest(previous):
            errors.append("previous lifecycle ledger digest is invalid")
        previous_ledger_digest = str(previous.get("ledgerDigest", ""))
        if previous.get("policyDigest") != policy_digest:
            errors.append("previous lifecycle ledger uses a different support policy")
        prior_entries = previous.get("entries")
        if not isinstance(prior_entries, list):
            errors.append("previous lifecycle ledger entries are malformed")
            prior_entries = []
        duplicate_prior_builds: set[str] = set()
        for row in prior_entries:
            if isinstance(row, dict):
                build = str(row.get("buildVersion", ""))
                if build in prior_by_build:
                    duplicate_prior_builds.add(build)
                else:
                    prior_by_build[build] = row
                if row.get("entryDigest") != entry_digest(row):
                    errors.append("previous lifecycle ledger contains an invalid entry digest")
        if duplicate_prior_builds:
            errors.append("previous lifecycle ledger names a published build more than once")
        raw_transitions = previous.get("transitions")
        if isinstance(raw_transitions, list):
            transitions = list(raw_transitions)
            expected_sequence = 1
            seen_sequences: set[int] = set()
            for row in transitions:
                if not isinstance(row, dict):
                    errors.append("previous lifecycle ledger contains a malformed transition")
                    continue
                row_sequence = row.get("transitionSequence")
                if type(row_sequence) is not int or row_sequence < 1:
                    errors.append("previous lifecycle transition has an unknown sequence value")
                elif row_sequence in seen_sequences:
                    errors.append("previous lifecycle transition sequence is duplicated")
                else:
                    seen_sequences.add(row_sequence)
                if row.get("targetBuild") not in prior_by_build:
                    errors.append("previous lifecycle transition targets a build outside the prior inventory")
                if row_sequence != expected_sequence or row.get("transitionDigest") != transition_digest(row):
                    errors.append("previous lifecycle transition digest chain is invalid")
                expected_sequence += 1
        else:
            errors.append("previous lifecycle transition history is malformed")
        sequence = max(
            [item.get("transitionSequence", 0) for item in transitions if isinstance(item, dict)],
            default=0,
        )
    requested: dict[str, dict[str, Any]] = {}
    if request is not None:
        rows = request.get("transitions")
        if not isinstance(rows, list):
            errors.append("lifecycle transition request is malformed")
        else:
            for row in rows:
                if not isinstance(row, dict):
                    errors.append("lifecycle transition request contains a malformed row")
                    continue
                build = str(row.get("targetBuild", ""))
                if build in requested:
                    errors.append("lifecycle transition request names a build more than once")
                requested[build] = row
    entries: list[dict[str, Any]] = []
    proposed: list[dict[str, Any]] = []
    inventory_builds = [row["buildVersion"] for row in inventory_entries]
    prior_builds = list(prior_by_build)
    if previous is not None and (
        len(prior_builds) > len(inventory_builds)
        or set(prior_builds) != set(inventory_builds[: len(prior_builds)])
    ):
        errors.append("previous lifecycle ledger omits or invents published release identities")
    for release_index, release in enumerate(inventory_entries):
        build = release["buildVersion"]
        dates = deadlines(release, policy)
        successor_published_at = (
            inventory_entries[release_index + 1]["publishedAt"]
            if release_index + 1 < len(inventory_entries)
            else None
        )
        prior = prior_by_build.get(build)
        if prior is not None:
            immutable_fields = (
                "releaseId",
                "buildVersion",
                "tag",
                "sourceCommit",
                "releaseClass",
                "productDigest",
                "publicationReceiptDigest",
                "baselineDigest",
                "publishedAt",
                "chainDepth",
            )
            if any(prior.get(field) != release.get(field) for field in immutable_fields):
                errors.append(f"build {build} prior lifecycle release identity was rewritten")
            expected_dates = deadlines(release, policy)
            if any(prior.get(field) != value for field, value in expected_dates.items()):
                errors.append(f"build {build} prior lifecycle support deadline was reset")
        default_target = due_status(release, policy, now, tip)
        requested_row = requested.get(build)
        if requested_row is not None and requested_row.get("recoveryGuidance") is not None:
            if recovery_guidance_error(requested_row.get("recoveryGuidance")) is not None:
                errors.append(
                    f"build {build} recovery guidance violates the public safe-text contract"
                )
                requested_row = None
        target = str(requested_row.get("toStatus")) if requested_row else default_target
        previous_status = str(prior.get("lifecycleStatus")) if prior else None
        request_time_invalid = False
        requested_effective: dt.datetime | None = None
        if requested_row is not None:
            requested_effective = parse_timestamp(requested_row.get("effectiveAt"))
            published_at = parse_timestamp(release.get("publishedAt"))
            if (
                requested_effective is None
                or canonical_timestamp(requested_row.get("effectiveAt"))
                != requested_row.get("effectiveAt")
                or published_at is None
                or requested_effective < published_at
                or requested_effective > now
            ):
                errors.append(
                    f"build {build} transition effective time is non-canonical, before publication, or future"
                )
                request_time_invalid = True
            else:
                prior_effective = (
                    parse_timestamp(prior.get("statusEffectiveAt")) if prior else None
                )
                if prior is not None and prior_effective is None:
                    errors.append(f"build {build} prior status effective time is malformed")
                    request_time_invalid = True
                elif prior_effective is not None and requested_effective < prior_effective:
                    errors.append(
                        f"build {build} transition effective time predates its prior status"
                    )
                    request_time_invalid = True
        if target not in STATUSES:
            errors.append(f"build {build} requests an unknown lifecycle state")
            target = default_target
        if (
            requested_row is not None
            and previous_status is None
            and target != "revoked"
            and target != default_target
        ):
            errors.append(
                f"build {build} newly inventoried state may only use its policy status or explicit revocation"
            )
            target = default_target
        if previous_status == "revoked" and requested_row is None:
            target = "revoked"
        elif previous_status == "revoked" and target != "revoked":
            errors.append(f"build {build} attempts to reverse terminal revocation")
            target = "revoked"
        if (
            requested_row is not None
            and requested_effective is not None
            and previous_status is not None
            and target in NORMAL_ORDER
            and target != previous_status
        ):
            earliest_effective = {
                "supported-maintenance": successor_published_at,
                "security-fixes-only": dates["fullSupportUntil"],
                "deprecated": dates["deprecationEffectiveAt"],
                "end-of-support": dates["endOfSupportAt"],
            }.get(target)
            parsed_earliest = parse_timestamp(earliest_effective)
            if parsed_earliest is not None and requested_effective < parsed_earliest:
                errors.append(
                    f"build {build} transition effective time precedes its policy deadline"
                )
                request_time_invalid = True
        if target == "revoked":
            if requested_row is None or previous_status == "revoked":
                if previous_status != "revoked":
                    errors.append(f"build {build} revocation lacks an explicit security transition")
            else:
                advisory_id = requested_row.get("advisoryId")
                reason_code = requested_row.get("reasonCode")
                affected_builds = requested_row.get("affectedBuilds")
                evidence_ids = requested_row.get("securityEvidenceIds")
                replacement_build = requested_row.get("replacementBuild")
                replacement_prior = prior_by_build.get(str(replacement_build), {})
                replacement_request = requested.get(str(replacement_build), {})
                replacement_release = next(
                    (
                        candidate
                        for candidate in inventory_entries
                        if candidate["buildVersion"] == replacement_build
                    ),
                    None,
                )
                replacement_status = replacement_request.get(
                    "toStatus"
                ) or replacement_prior.get("lifecycleStatus")
                if replacement_status is None and replacement_release is not None:
                    replacement_status = due_status(
                        replacement_release, policy, now, tip
                    )
                replacement_is_safe = (
                    isinstance(replacement_build, str)
                    and replacement_build in inventory_builds
                    and replacement_build != build
                    and isinstance(affected_builds, list)
                    and replacement_build not in affected_builds
                    and replacement_prior.get("lifecycleStatus") != "revoked"
                    and replacement_request.get("toStatus") != "revoked"
                    and replacement_status in SECURITY_SUPPORTED_STATUSES
                )
                if not (
                    isinstance(advisory_id, str)
                    and PUBLIC_ID_RE.fullmatch(advisory_id)
                    and isinstance(reason_code, str)
                    and PUBLIC_ID_RE.fullmatch(reason_code)
                    and requested_row.get("severity") in SECURITY_SEVERITIES
                    and isinstance(affected_builds, list)
                    and build in affected_builds
                    and len(set(affected_builds)) == len(affected_builds)
                    and all(affected in inventory_builds for affected in affected_builds)
                    and isinstance(evidence_ids, list)
                    and evidence_ids
                    and len(set(evidence_ids)) == len(evidence_ids)
                    and all(
                        isinstance(evidence_id, str) and PUBLIC_ID_RE.fullmatch(evidence_id)
                        for evidence_id in evidence_ids
                    )
                    and DIGEST_RE.fullmatch(str(requested_row.get("publicationTargetDigest", "")))
                    and (
                        replacement_is_safe
                        and requested_row.get("recoveryGuidance") is None
                        or replacement_build is None
                        and requested_row.get("recoveryGuidance")
                    )
                ):
                    errors.append(
                        f"build {build} revocation lacks advisory, severity, affected-build, "
                        "security-evidence, publication-target, or safe recovery fields"
                    )
        elif requested_row is not None and any(
            (
                requested_row.get("advisoryId"),
                requested_row.get("severity"),
                requested_row.get("affectedBuilds"),
                requested_row.get("securityEvidenceIds"),
                requested_row.get("publicationTargetDigest"),
                requested_row.get("recoveryGuidance"),
            )
        ):
            errors.append(
                f"build {build} normal transition carries build-revocation-only security fields"
            )
        elif previous_status is not None and previous_status != "current-stable":
            if NORMAL_ORDER.index(target) < NORMAL_ORDER.index(previous_status):
                errors.append(f"build {build} attempts a backward normal lifecycle transition")
                target = previous_status
        if (
            requested_row is not None
            and target != "revoked"
            and previous_status is not None
            and target != previous_status
            and NORMAL_ORDER.index(target) != NORMAL_ORDER.index(previous_status) + 1
        ):
            errors.append(f"build {build} explicit normal transition is not adjacent")
            target = previous_status
        if request_time_invalid and previous_status is not None:
            target = previous_status
        emergency_tip_revocation = (
            build == tip
            and target == "revoked"
            and policy["revocation"].get(
                "allowEmergencyNoCurrentStableWhenTipRevoked"
            )
            is True
        )
        if build == tip and target != "current-stable" and not emergency_tip_revocation:
            errors.append("authenticated chain tip must remain current-stable")
            target = "current-stable"
        if build != tip and target == "current-stable":
            errors.append("only the authenticated chain tip may be current-stable")
            target = default_target
        entering_revocation = target == "revoked" and previous_status != "revoked"
        change_path: list[str] = []
        if target == "revoked" and previous_status != "revoked":
            if requested_row is not None:
                change_path = ["revoked"]
        elif previous_status is not None and previous_status != target:
            if target != "revoked":
                start = NORMAL_ORDER.index(previous_status)
                finish = NORMAL_ORDER.index(target)
                if finish > start:
                    change_path = list(NORMAL_ORDER[start + 1 : finish + 1])
        active_status = previous_status or default_target
        last_effective = parse_timestamp(prior.get("statusEffectiveAt")) if prior else None
        for next_status in change_path:
            sequence += 1
            effective = generated_at
            if requested_row is None:
                effective = {
                    "supported-maintenance": successor_published_at,
                    "security-fixes-only": dates["fullSupportUntil"],
                    "deprecated": dates["deprecationEffectiveAt"],
                    "end-of-support": dates["endOfSupportAt"],
                }.get(next_status) or generated_at
                parsed_effective = parse_timestamp(effective)
                if last_effective is not None and parsed_effective is not None and parsed_effective < last_effective:
                    effective = last_effective.isoformat().replace("+00:00", "Z")
            row = {
                "transitionSequence": sequence,
                "targetBuild": build,
                "fromStatus": active_status,
                "toStatus": next_status,
                "effectiveAt": canonical_timestamp(
                    requested_row.get("effectiveAt") if requested_row else effective
                ) or effective,
                "policyRule": "explicit-security-revocation" if next_status == "revoked" else "support-window-or-successor",
                "reasonCode": (requested_row or {}).get("reasonCode") or "policy-window-transition",
                "advisoryId": (requested_row or {}).get("advisoryId"),
                "severity": (requested_row or {}).get("severity"),
                "affectedBuilds": list((requested_row or {}).get("affectedBuilds") or []),
                "securityEvidenceIds": list(
                    (requested_row or {}).get("securityEvidenceIds") or []
                ),
                "publicationTargetDigest": (requested_row or {}).get(
                    "publicationTargetDigest"
                ),
                "replacementBuild": (
                    (requested_row or {}).get("replacementBuild")
                    if next_status == "revoked"
                    else _normal_replacement_build(
                        next_status,
                        build,
                        tip,
                        (requested_row or {}).get("replacementBuild"),
                    )
                ),
                "recoveryGuidance": (requested_row or {}).get("recoveryGuidance"),
                "previousLedgerDigest": previous_ledger_digest,
            }
            row["authorizationRequestDigest"] = semantic_digest(row)
            row["transitionDigest"] = transition_digest(row)
            transitions.append(row)
            proposed.append(row)
            active_status = next_status
            last_effective = parse_timestamp(row["effectiveAt"])
        last_sequence = max(
            [
                row.get("transitionSequence", 0)
                for row in transitions
                if isinstance(row, dict) and row.get("targetBuild") == build
            ],
            default=0,
        )
        previous_entry_digest = prior.get("entryDigest") if prior else None
        projected = {
            **release,
            "lifecycleStatus": target,
            "statusEffectiveAt": (
                proposed[-1]["effectiveAt"]
                if change_path
                else (
                    prior.get("statusEffectiveAt")
                    if prior
                    else _initial_status_effective_at(
                        release, target, dates, successor_published_at
                    )
                )
            ),
            **dates,
            "securityRevocationEffectiveAt": (
                canonical_timestamp((requested_row or {}).get("effectiveAt"))
                if entering_revocation
                else prior.get("securityRevocationEffectiveAt")
                if target == "revoked" and prior
                else None
            ),
            "replacementBuild": (
                (requested_row or {}).get("replacementBuild")
                if entering_revocation
                else prior.get("replacementBuild")
                if target == "revoked" and prior
                else _normal_replacement_build(target, build, tip)
            ),
            "recoveryGuidance": (
                (requested_row or {}).get("recoveryGuidance")
                if entering_revocation
                else prior.get("recoveryGuidance")
                if target == "revoked" and prior
                else None
            ),
            "advisoryIds": (
                sorted({str((requested_row or {}).get("advisoryId"))})
                if entering_revocation and (requested_row or {}).get("advisoryId")
                else list(prior.get("advisoryIds", [])) if prior else []
            ),
            "reasonCodes": (
                sorted({str((requested_row or {}).get("reasonCode"))})
                if entering_revocation and (requested_row or {}).get("reasonCode")
                else list(prior.get("reasonCodes", [])) if prior else []
            ),
            "transitionSequence": last_sequence,
            "previousEntryDigest": previous_entry_digest,
        }
        projected["entryDigest"] = entry_digest(projected)
        entries.append(projected)
    unknown_requested = sorted(set(requested).difference(row["buildVersion"] for row in inventory_entries))
    if unknown_requested:
        errors.append("lifecycle transition request names an unpublished build")
    _reconcile_replacement_guidance(entries, errors)
    if any(
        row.get("replacementBuild") is not None
        and row.get("recoveryGuidance") is not None
        for row in entries
    ):
        errors.append("lifecycle ledger mixes replacement and recovery-only guidance")
    current = [row for row in entries if row["lifecycleStatus"] == "current-stable"]
    tip_entry = entries[-1]
    tip_revocation = next(
        (
            row
            for row in reversed(transitions)
            if row.get("targetBuild") == tip and row.get("toStatus") == "revoked"
        ),
        None,
    )
    emergency_tip_revoked = (
        tip_entry["lifecycleStatus"] == "revoked"
        and not current
        and policy["revocation"].get("allowEmergencyNoCurrentStableWhenTipRevoked")
        is True
        and isinstance(tip_revocation, dict)
        and bool(
            tip_revocation.get("replacementBuild")
            or tip_revocation.get("recoveryGuidance")
        )
    )
    if not emergency_tip_revoked and (
        len(current) != 1 or current[0]["buildVersion"] != tip
    ):
        errors.append("lifecycle ledger does not select exactly one authenticated current-stable tip")
    supported_count = sum(
        row["lifecycleStatus"]
        in {"current-stable", "supported-maintenance", "security-fixes-only"}
        for row in entries
    )
    if (
        not emergency_tip_revoked
        and supported_count
        < policy["cardinality"]["minimumSimultaneouslySupportedBuilds"]
    ):
        errors.append("lifecycle ledger violates the minimum simultaneously supported build count")
    ledger = {
        "schemaVersion": 1,
        "kind": "stable-1.0-support-lifecycle-ledger",
        "generatedAt": generated_at,
        "stableMilestone": STABLE_MILESTONE,
        "policyDigest": policy_digest,
        "inventoryDigest": inventory["inventoryDigest"],
        "previousLedgerDigest": previous_ledger_digest,
        "entries": entries,
        "transitions": transitions,
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }
    ledger["ledgerDigest"] = ledger_digest(ledger)
    return ledger, proposed, errors


def build_descriptor(
    ledger: dict[str, Any],
    policy: dict[str, Any],
    generated_at: str,
    previous: dict[str, Any] | None,
    update_key_identity_digest: str,
) -> tuple[dict[str, Any], list[str]]:
    """Build the bounded authenticated runtime projection with rollback bindings."""

    errors: list[str] = []
    if update_key_identity_digest != UPDATE_KEY_IDENTITY_DIGEST:
        errors.append("lifecycle descriptor update-key identity is not the pinned Stable 1.0 key")
    previous_edition = previous.get("descriptorEdition") if previous else None
    previous_digest = previous.get("descriptorDigest") if previous else None
    generated_time = parse_timestamp(generated_at)
    if generated_time is None or canonical_timestamp(generated_at) != generated_at:
        errors.append("lifecycle descriptor generation time is not canonical UTC")
    if previous is not None:
        if previous_digest != semantic_digest(
            {key: item for key, item in previous.items() if key != "descriptorDigest"}
        ):
            errors.append("previous lifecycle descriptor digest is invalid")
        if type(previous_edition) is not int or previous_edition < 1:
            errors.append("previous lifecycle descriptor edition is invalid")
        previous_generated = parse_timestamp(previous.get("generatedAt"))
        previous_effective = parse_timestamp(previous.get("effectiveAt"))
        previous_stale = parse_timestamp(previous.get("staleAt"))
        if (
            previous_generated is None
            or previous_effective is None
            or previous_stale is None
            or previous_generated > previous_effective
            or previous_effective > previous_stale
        ):
            errors.append("previous lifecycle descriptor timestamps are unordered")
        if (
            generated_time is not None
            and previous_generated is not None
            and generated_time <= previous_generated
        ):
            errors.append(
                "lifecycle descriptor generation time did not advance beyond its predecessor"
            )
        if previous.get("updateKeyIdentityDigest") != update_key_identity_digest:
            errors.append("previous lifecycle descriptor uses a different update-key identity")
        if previous.get("updateKeyDocName") != UPDATE_KEY_DOC_NAME:
            errors.append("previous lifecycle descriptor uses a different update-key docname")
        if previous.get("updateKeyScope") != (
            f"{update_key_identity_digest}/{UPDATE_KEY_DOC_NAME}/0"
        ):
            errors.append("previous lifecycle descriptor uses a different update-key scope")
    edition = (previous_edition or 0) + 1
    entries = ledger["entries"]
    maximum_entries = policy.get("descriptor", {}).get("maximumEntries")
    if type(maximum_entries) is not int or maximum_entries < 1:
        errors.append("lifecycle descriptor entry bound is invalid")
    elif len(entries) > maximum_entries:
        errors.append("lifecycle descriptor exceeds its policy entry bound")
    revoked_builds = {
        row["buildVersion"]
        for row in entries
        if row["lifecycleStatus"] == "revoked"
    }
    if any(row.get("replacementBuild") in revoked_builds for row in entries):
        errors.append("lifecycle descriptor would recommend a revoked replacement build")
    entries_by_build = {row["buildVersion"]: row for row in entries}
    if any(
        replacement is not None
        and (
            replacement == row["buildVersion"]
            or replacement not in entries_by_build
            or entries_by_build[replacement]["lifecycleStatus"]
            not in SECURITY_SUPPORTED_STATUSES
        )
        for row in entries
        for replacement in (row.get("replacementBuild"),)
    ):
        errors.append(
            "lifecycle descriptor recommends a missing, self-referential, or "
            "non-security-supported replacement build"
        )
    if any(
        row.get("replacementBuild") is not None
        and row.get("recoveryGuidance") is not None
        for row in entries
    ):
        errors.append("lifecycle descriptor mixes replacement and recovery-only guidance")
    current_entries = [
        row for row in entries if row["lifecycleStatus"] == "current-stable"
    ]
    if current_entries and any(
        row.get("replacementBuild") is None
        and row.get("recoveryGuidance") is not None
        for row in entries
    ):
        errors.append(
            "lifecycle descriptor carries recovery-only guidance while current-stable exists"
        )
    current = current_entries[0] if len(current_entries) == 1 else None
    tip_entry = entries[-1]
    emergency_tip_revoked = (
        current is None
        and tip_entry["lifecycleStatus"] == "revoked"
        and policy["revocation"].get("allowEmergencyNoCurrentStableWhenTipRevoked")
        is True
    )
    if current is None and not emergency_tip_revoked:
        errors.append(
            "lifecycle descriptor lacks current-stable outside an authenticated tip revocation"
        )
    if len(current_entries) > 1:
        errors.append("lifecycle descriptor projects more than one current-stable build")
    replacement = tip_entry.get("replacementBuild") if emergency_tip_revoked else None
    replacement_entry = next(
        (row for row in entries if row["buildVersion"] == replacement), None
    )
    recommended = (
        current["buildVersion"]
        if current is not None
        else replacement
        if replacement_entry is not None
        and replacement_entry["lifecycleStatus"] in SECURITY_SUPPORTED_STATUSES
        else None
    )
    ordinarily_supported = [
        int(row["buildVersion"])
        for row in entries
        if row["lifecycleStatus"] in {"current-stable", "supported-maintenance"}
    ]
    security_supported = [
        int(row["buildVersion"])
        for row in entries
        if row["lifecycleStatus"]
        in {"current-stable", "supported-maintenance", "security-fixes-only"}
    ]
    descriptor_entries = [
        {
            key: row.get(key)
            for key in (
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
        }
        for row in entries
    ]
    scope = f"{update_key_identity_digest}/{UPDATE_KEY_DOC_NAME}/0"
    descriptor = {
        "schemaVersion": 1,
        "kind": "stable-1.0-support-lifecycle-descriptor",
        "stableMilestone": STABLE_MILESTONE,
        "descriptorEdition": edition,
        "updateKeyIdentityDigest": update_key_identity_digest,
        "updateKeyScope": scope,
        "updateKeyDocName": UPDATE_KEY_DOC_NAME,
        "generatedAt": generated_at,
        "effectiveAt": generated_at,
        "staleAt": add_days(
            generated_at, policy["supportWindows"]["maximumDescriptorAgeDays"]
        ),
        "ledgerDigest": ledger["ledgerDigest"],
        "inventoryDigest": ledger["inventoryDigest"],
        "currentStableBuild": current["buildVersion"] if current is not None else None,
        "minimumSupportedBuild": str(min(ordinarily_supported)) if ordinarily_supported else None,
        "minimumSecuritySupportedBuild": str(min(security_supported)) if security_supported else None,
        "recommendedBuild": recommended,
        "entries": descriptor_entries,
        "previousDescriptorEdition": previous_edition,
        "previousDescriptorDigest": previous_digest,
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }
    descriptor["descriptorDigest"] = semantic_digest(descriptor)
    descriptor_generated = parse_timestamp(descriptor["generatedAt"])
    descriptor_effective = parse_timestamp(descriptor["effectiveAt"])
    descriptor_stale = parse_timestamp(descriptor["staleAt"])
    if (
        descriptor_generated is None
        or descriptor_effective is None
        or descriptor_stale is None
        or descriptor_generated > descriptor_effective
        or descriptor_effective > descriptor_stale
    ):
        errors.append("lifecycle descriptor timestamps are unordered")
    elif any(
        (status_effective := parse_timestamp(row.get("statusEffectiveAt"))) is None
        or status_effective > descriptor_effective
        for row in descriptor_entries
    ):
        errors.append(
            "lifecycle descriptor entry status is future-effective at descriptor activation"
        )
    if previous is not None and edition <= previous_edition:
        errors.append("lifecycle descriptor edition did not advance")
    return descriptor, errors


def governance_projection(
    predecessor_baseline: dict[str, Any],
    inventory: dict[str, Any],
    generated_at: str,
    ga_baseline: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Project existing Platform API and catalog/app/profile truth without replacing it."""

    platform = predecessor_baseline.get("platformApi")
    platform = platform if isinstance(platform, dict) else {}
    deprecations = platform.get("deprecationHistory")
    deprecations = list(deprecations) if isinstance(deprecations, list) else []
    api = {
        "schemaVersion": 1,
        "kind": "stable-1.0-platform-api-deprecation-governance",
        "generatedAt": generated_at,
        "stableMilestone": STABLE_MILESTONE,
        "baselineName": platform.get("baselineName"),
        "baselineContractVersion": platform.get("baselineContractVersion"),
        "currentContractVersion": platform.get("currentContractVersion"),
        "compatibilityWindowPolicyDigest": platform.get("compatibilityWindowPolicyDigest"),
        "deprecationHistoryDigest": platform.get("deprecationHistoryDigest")
        or semantic_digest(deprecations),
        "deprecationHistory": deprecations,
        "originalClocksPreserved": True,
        "supportedBuildsConsidered": [
            row["buildVersion"] for row in inventory["entries"]
        ],
        "stableRemovalPermitted": False,
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }
    catalog = predecessor_baseline.get("stableCatalog")
    apps = predecessor_baseline.get("firstPartyApps")
    profiles = predecessor_baseline.get("contentFormatProfiles")
    security = predecessor_baseline.get("security")
    ga_security = ga_baseline.get("securityBaseline")
    ga_security = ga_security if isinstance(ga_security, dict) else {}
    security_section = security if isinstance(security, dict) else {}
    composite_security_digest = (
        security_section.get("currentDigest")
        if security_section
        else semantic_digest(ga_security)
    )
    follow_up = predecessor_baseline.get("hotfixFollowUp")
    governance = {
        "schemaVersion": 1,
        "kind": "stable-1.0-catalog-app-profile-lifecycle-governance",
        "generatedAt": generated_at,
        "stableMilestone": STABLE_MILESTONE,
        "stableCatalog": {
            "catalogId": catalog.get("catalogId"),
            "channel": catalog.get("channel"),
            "revision": catalog.get("revision"),
            "edition": catalog.get("edition"),
            "digest": catalog.get("digest") or catalog.get("catalogDigest"),
            "signingKeyId": catalog.get("signingKeyId"),
        } if isinstance(catalog, dict) else {},
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
            for row in apps
            if isinstance(row, dict)
        ] if isinstance(apps, list) else [],
        "contentFormatProfiles": [
            {key: row.get(key) for key in ("profileId", "version", "status", "descriptorDigest")}
            for row in profiles
            if isinstance(row, dict)
        ] if isinstance(profiles, list) else [],
        "securityStateDigest": semantic_digest(
            security if isinstance(security, dict) else predecessor_baseline.get("securityBaseline", {})
        ),
        "securityState": {
            "gaBaselineDigest": semantic_digest(ga_security),
            "compositeCurrentStateDigest": composite_security_digest,
            "predecessorStateDigest": (
                security_section.get("predecessorDigest") if security_section else None
            ),
            "baselineAdvisoryCount": ga_security.get("advisoryCount", 0),
            "baselineExactVersionDenylistCount": ga_security.get("denylistCount", 0),
            "trackedDimensions": [
                "active-security-advisories",
                "exact-version-denylist",
                "reviewer-key-revocations",
                "app-signing-key-revocations",
            ],
            "continuityStatus": "pass",
            "authority": "authenticated-maintenance-security-digest-chain",
        },
        "hotfixFollowUp": (
            {key: follow_up.get(key) for key in ("status", "obligationDigest", "deadline", "blocksRoutineMaintenance")}
            if isinstance(follow_up, dict)
            else None
        ),
        "trustModel": "projection-only-existing-signed-metadata-remains-authoritative",
        "legacyBoundariesDigest": semantic_digest(predecessor_baseline.get("legacyBoundaries", {})),
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }
    return api, governance

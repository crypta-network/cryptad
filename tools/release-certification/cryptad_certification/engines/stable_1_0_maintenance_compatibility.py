"""Stable 1.0 compatibility and production-evidence gates for maintenance releases."""

from __future__ import annotations

import datetime as dt
from typing import Any

from cryptad_certification.models import RunContext
from cryptad_certification.schema_validation import validate_schema

from .stable_1_0_maintenance_core import (
    ALLOWED_OPERATIONAL_WARNING_IDS,
    COMPARISON_SCHEMA,
    EVIDENCE_SCHEMA,
    FOLLOW_UP_SCHEMA,
    REQUIRED_PRODUCTION_EVIDENCE,
    Candidate,
    GaRoot,
    OPERATIONAL_WARNING_EVIDENCE_IDS,
    Predecessor,
    add_blockers,
    load_json_input,
)
from .stable_1_0_rc_core import ValidationState, parse_timestamp, semantic_digest


def _rows_by(rows: Any, key: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    if not isinstance(rows, list):
        return result
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get(key), str):
            continue
        identity = row[key]
        if identity in result:
            return {}
        result[identity] = row
    return result


def _ga_evidence_binding_errors(
    evidence_id: str, row: dict[str, Any], ga: GaRoot
) -> list[str]:
    ga_fields = (
        row.get("gaReleaseId"),
        row.get("gaBuild"),
        row.get("gaProductDigest"),
    )
    if evidence_id == "stable-maintenance.direct-ga-upgrade":
        if ga_fields != (ga.release_id, ga.build_version, ga.product_digest):
            return ["direct-GA upgrade evidence is not bound to the authenticated GA root"]
    elif ga_fields != (None, None, None):
        return [f"non-GA evidence {evidence_id} carries an unexpected GA source identity"]
    return []


def _predecessor_section(predecessor: Predecessor, name: str, ga_name: str | None = None) -> Any:
    """Return the current predecessor state, falling back to the GA v1 field name."""

    if predecessor.baseline.get("schemaVersion") == 1:
        return predecessor.baseline.get(ga_name or name)
    return predecessor.baseline.get(name)


def _issue(issue_id: str, category: str, message: str, *, waivable: bool = False) -> dict[str, Any]:
    return {
        "id": issue_id,
        "category": category,
        "message": message.rstrip(".") + ".",
        "waivable": waivable,
    }


def _section(
    ga_value: Any,
    predecessor_value: Any,
    candidate_value: Any,
    blockers: list[dict[str, Any]],
    warnings: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "status": "fail" if blockers else ("warn" if warnings else "pass"),
        "gaDeltaDigest": semantic_digest({"from": ga_value, "to": candidate_value}),
        "predecessorDeltaDigest": semantic_digest(
            {"from": predecessor_value, "to": candidate_value}
        ),
        "blockerCount": len(blockers),
        "warningCount": len(warnings),
    }


def _platform_api_errors(ga: Any, predecessor: Any, candidate: Any) -> list[str]:
    if not all(isinstance(value, dict) for value in (ga, predecessor, candidate)):
        return ["Platform API comparison inputs are malformed"]
    errors: list[str] = []
    immutable = (
        "baselineName",
        "baselineDigest",
        "baselineContractVersion",
        "stableSurfaceDigest",
        "compatibilityWindowPolicyDigest",
    )
    for field in immutable:
        if candidate.get(field) != ga.get(field):
            errors.append(f"Platform API long-term baseline field {field} changed")
    if predecessor.get("stableSurfaceDigest") != ga.get("stableSurfaceDigest"):
        errors.append("Platform API predecessor changed the frozen Stable 1.0 surface")
    if candidate.get("baselineName") != "1.0":
        errors.append("Platform API baseline is not Stable 1.0")
    current = candidate.get("currentContractVersion")
    previous = predecessor.get("currentContractVersion")
    if type(current) is not int or type(previous) is not int or current < previous:
        errors.append("Platform API current contract version is not monotonic")
    closed_empty = (
        "removedStableEndpoints",
        "removedStableCapabilities",
        "breakingStableChanges",
    )
    for field in closed_empty:
        if candidate.get(field) != []:
            errors.append(f"Platform API candidate declares forbidden {field}")
    closed_false = (
        "criticalRemovalWaiverAttempt",
        "deprecationClockReset",
        "experimentalMislabelledStable",
    )
    for field in closed_false:
        if candidate.get(field) is not False:
            errors.append(f"Platform API gate {field} did not remain false")
    if candidate.get("additionsBackwardCompatible") is not True:
        errors.append("Platform API additions are not proven backward compatible")
    if candidate.get("thirdPartyCompatibilityStatus") != "pass":
        errors.append("Platform API third-party stable samples did not pass")
    if ga.get("criticalStableRemovalWaiverAllowed") is not False:
        errors.append("Authenticated GA baseline does not prohibit critical removal waivers")
    minimum_deprecation = ga.get("minimumDeprecationWindowContractVersions")
    minimum_removal = ga.get("minimumRemovalWindowContractVersions")
    if type(minimum_deprecation) is not int or minimum_deprecation < 2:
        errors.append("GA deprecation window policy is invalid")
    if type(minimum_removal) is not int or minimum_removal < 2:
        errors.append("GA removal window policy is invalid")
    errors.extend(_deprecation_history_errors(ga, predecessor, candidate))
    return errors


def _deprecation_history_errors(
    ga: dict[str, Any], predecessor: dict[str, Any], candidate: dict[str, Any]
) -> list[str]:
    """Authenticate descriptor deprecation clocks instead of trusting a reset flag."""

    errors: list[str] = []
    current_history = candidate.get("deprecationHistory")
    if not isinstance(current_history, list):
        return ["Platform API deprecation history is missing or malformed"]
    if candidate.get("deprecationHistoryDigest") != semantic_digest(current_history):
        errors.append("Platform API deprecation history digest does not bind the history rows")

    predecessor_history = predecessor.get("deprecationHistory", [])
    if not isinstance(predecessor_history, list):
        errors.append("Platform API predecessor deprecation history is malformed")
        predecessor_history = []
    predecessor_digest = predecessor.get("deprecationHistoryDigest")
    if predecessor_digest is not None and predecessor_digest != semantic_digest(
        predecessor_history
    ):
        errors.append("Platform API predecessor deprecation history digest is invalid")

    def history_map(rows: list[Any], label: str) -> dict[tuple[str, str], dict[str, Any]]:
        result: dict[tuple[str, str], dict[str, Any]] = {}
        for row in rows:
            if not isinstance(row, dict):
                errors.append(f"Platform API {label} deprecation history row is malformed")
                continue
            kind = row.get("kind")
            identity = row.get("identity")
            if (
                kind not in {"capability", "endpoint"}
                or not isinstance(identity, str)
                or not identity
            ):
                errors.append(f"Platform API {label} deprecation history identity is invalid")
                continue
            key = (kind, identity)
            if key in result:
                errors.append(
                    f"Platform API {label} deprecation history contains duplicate identities"
                )
                continue
            result[key] = row
        return result

    previous_rows = history_map(predecessor_history, "predecessor")
    current_rows = history_map(current_history, "candidate")
    if predecessor_history != [
        previous_rows[key] for key in sorted(previous_rows)
    ]:
        errors.append("Platform API predecessor deprecation history is not canonically ordered")
    if current_history != [current_rows[key] for key in sorted(current_rows)]:
        errors.append("Platform API candidate deprecation history is not canonically ordered")
    current_version = candidate.get("currentContractVersion")
    previous_version = predecessor.get("currentContractVersion")
    minimum_deprecation = ga.get("minimumDeprecationWindowContractVersions")
    minimum_removal = ga.get("minimumRemovalWindowContractVersions")
    if not all(
        type(value) is int
        for value in (
            current_version,
            previous_version,
            minimum_deprecation,
            minimum_removal,
        )
    ):
        return errors

    for key, row in current_rows.items():
        deprecated_since = row.get("deprecatedSinceContractVersion")
        removal_version = row.get("removalContractVersion")
        stability = row.get("stability")
        if type(deprecated_since) is not int or deprecated_since < 1:
            errors.append(
                f"Platform API deprecation history {key} has an invalid start version"
            )
            continue
        if deprecated_since > current_version:
            errors.append(f"Platform API deprecation history {key} starts in the future")
        if stability not in {"deprecated", "scheduled-for-removal"}:
            errors.append(
                f"Platform API deprecation history {key} has an invalid stability state"
            )
        if removal_version is not None:
            if type(removal_version) is not int or removal_version <= deprecated_since:
                errors.append(
                    f"Platform API deprecation history {key} has an invalid removal version"
                )
            elif (
                removal_version - deprecated_since < minimum_deprecation
                or removal_version - current_version < minimum_removal
            ):
                errors.append(
                    f"Platform API deprecation history {key} shortens a required window"
                )
        elif stability == "scheduled-for-removal":
            errors.append(f"Platform API deprecation history {key} lacks a removal version")

        previous_row = previous_rows.get(key)
        if previous_row is None:
            if deprecated_since <= previous_version:
                errors.append(
                    f"Platform API deprecation history {key} backdates a newly recorded clock"
                )
            continue
        if deprecated_since != previous_row.get("deprecatedSinceContractVersion"):
            errors.append(
                f"Platform API deprecation history {key} reset its original clock"
            )
        previous_removal = previous_row.get("removalContractVersion")
        if (
            type(previous_removal) is int
            and type(removal_version) is int
            and removal_version < previous_removal
        ):
            errors.append(f"Platform API deprecation history {key} moved removal earlier")

    missing = sorted(set(previous_rows) - set(current_rows))
    if missing:
        errors.append("Platform API candidate dropped predecessor deprecation history rows")
    return errors


def _content_profile_errors(ga: Any, predecessor: Any, candidate: Any) -> list[str]:
    ga_map = _rows_by(ga, "profileId")
    predecessor_map = _rows_by(predecessor, "profileId")
    current_map = _rows_by(candidate, "profileId")
    errors: list[str] = []
    if not ga_map or set(current_map) != set(ga_map) or set(predecessor_map) != set(ga_map):
        return ["Stable v1 content-profile set changed"]
    immutable = (
        "version",
        "status",
        "descriptorDigest",
        "canonicalizationRulesDigest",
        "maximumSizePolicyDigest",
        "signaturePayloadRulesDigest",
    )
    for profile_id in sorted(ga_map):
        current = current_map[profile_id]
        for field in immutable:
            if current.get(field) != ga_map[profile_id].get(field):
                errors.append(f"content profile {profile_id} changed frozen {field}")
        if current.get("existingValidDocumentsAccepted") is not True:
            errors.append(f"content profile {profile_id} rejects existing valid documents")
        if current.get("acceptanceStatus") != "pass":
            errors.append(f"content profile {profile_id} parser/verifier compatibility failed")
    return errors


def _limitation_anchor_ids(value: Any, label: str) -> tuple[set[str], list[str]]:
    """Return authenticated limitation membership from a GA v1 or successor v2 anchor."""

    if not isinstance(value, dict):
        return set(), [f"{label} known-limitations anchor is malformed"]
    current_ids = value.get("currentIds")
    if isinstance(current_ids, list):
        if (
            any(not isinstance(item, str) or not item for item in current_ids)
            or len(set(current_ids)) != len(current_ids)
            or current_ids != sorted(current_ids)
        ):
            return set(), [f"{label} known-limitations membership is malformed"]
        current = set(current_ids)
        if value.get("currentDigest") != _known_limitations_digest(current):
            return current, [f"{label} known-limitations membership digest is invalid"]
        return current, []
    allowed = value.get("allowedLimitations")
    if not isinstance(allowed, list):
        return set(), [f"{label} known-limitations membership is missing"]
    ids: list[str] = []
    for row in allowed:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"]:
            return set(), [f"{label} known-limitations membership is malformed"]
        ids.append(row["id"])
    if len(set(ids)) != len(ids):
        return set(ids), [f"{label} known-limitations membership contains duplicate ids"]
    return set(ids), []


def _known_limitations_digest(ids: set[str]) -> str:
    """Digest the complete current limitation membership in canonical id order."""

    return semantic_digest({"limitationIds": sorted(ids)})


def _limitation_delta_digest(
    predecessor_ids: set[str],
    added_ids: set[str],
    resolved_ids: set[str],
    unchanged_ids: set[str],
) -> str:
    """Digest one exact predecessor-to-candidate limitation transition."""

    return semantic_digest(
        {
            "predecessorIds": sorted(predecessor_ids),
            "addedIds": sorted(added_ids),
            "resolvedIds": sorted(resolved_ids),
            "unchangedIds": sorted(unchanged_ids),
            "currentIds": sorted(added_ids | unchanged_ids),
        }
    )


def _limitation_errors(ga: Any, predecessor: Any, value: Any) -> list[str]:
    if not isinstance(value, dict):
        return ["known-limitations delta is malformed"]
    errors: list[str] = []
    _ga_ids, ga_errors = _limitation_anchor_ids(ga, "GA")
    predecessor_ids, predecessor_errors = _limitation_anchor_ids(
        predecessor, "predecessor"
    )
    errors.extend(ga_errors)
    errors.extend(predecessor_errors)
    delta_sets: dict[str, set[str]] = {}
    for label, count in (
        ("added", value.get("addedCount")),
        ("resolved", value.get("resolvedCount")),
        ("unchanged", value.get("unchangedCount")),
    ):
        rows = value.get(label + "Ids")
        if (
            not isinstance(rows, list)
            or any(not isinstance(item, str) or not item for item in rows)
            or len(set(rows)) != len(rows)
            or rows != sorted(rows)
            or type(count) is not int
            or len(rows) != count
        ):
            errors.append(f"known-limitations {label} ids do not match their count")
            continue
        delta_sets[label] = set(rows)
    if len(delta_sets) == 3 and not predecessor_errors:
        added_ids = delta_sets["added"]
        resolved_ids = delta_sets["resolved"]
        unchanged_ids = delta_sets["unchanged"]
        if (
            added_ids & resolved_ids
            or added_ids & unchanged_ids
            or resolved_ids & unchanged_ids
        ):
            errors.append("known-limitations delta id sets are not disjoint")
        if resolved_ids | unchanged_ids != predecessor_ids:
            errors.append(
                "known-limitations resolved and unchanged ids do not partition the predecessor"
            )
        if added_ids & predecessor_ids:
            errors.append("known-limitations added ids already exist in the predecessor")
        current_ids = added_ids | unchanged_ids
        if value.get("knownLimitationsDigest") != _known_limitations_digest(current_ids):
            errors.append("known-limitations current membership digest is invalid")
        if value.get("deltaDigest") != _limitation_delta_digest(
            predecessor_ids, added_ids, resolved_ids, unchanged_ids
        ):
            errors.append("known-limitations delta digest is invalid")
    if value.get("changesReviewed") is not True or value.get("noHiddenLimitations") is not True:
        errors.append("known-limitations delta is not reviewed and complete")
    return errors


def _security_support_legacy_errors(
    ga: GaRoot, predecessor: Predecessor, candidate: Candidate
) -> tuple[list[str], list[str], list[str]]:
    security = candidate.input_value.get("security")
    support = candidate.input_value.get("support")
    legacy = candidate.input_value.get("legacyBoundaries")
    security_errors: list[str] = []
    support_errors: list[str] = []
    legacy_errors: list[str] = []
    if not isinstance(security, dict) or security.get("signingKeysUncompromised") is not True:
        security_errors.append("security signing-key state is not uncompromised")
    if isinstance(security, dict):
        for field in ("advisoryStatus", "denylistStatus", "securityEvidenceStatus"):
            if security.get(field) != "pass":
                security_errors.append(f"security {field} failed")
    if not isinstance(support, dict) or support.get("redactionStatus") != "pass":
        support_errors.append("support diagnostics or redaction failed")
    if isinstance(support, dict):
        for field in ("supportStatus", "diagnosticsStatus"):
            if support.get(field) != "pass":
                support_errors.append(f"support {field} failed")
    if isinstance(support, dict) and support.get("supportCommitmentReduced") is not False:
        support_errors.append("support commitment was reduced")
    expected = {
        "pluginRuntime": "removed",
        "inCorePluginApi": "removed",
        "legacyAdminMutationRoutes": "disabled",
        "fproxyBrowse": "retained",
        "contentFiltering": "retained",
        "emergencyFallbackRoutes": "retained",
    }
    if not isinstance(legacy, dict) or any(legacy.get(key) != value for key, value in expected.items()):
        legacy_errors.append("Stable legacy boundary was expanded or a retained route was removed")
    ga_legacy = ga.baseline.get("legacyBoundaries")
    predecessor_legacy = _predecessor_section(predecessor, "legacyBoundaries")
    if not isinstance(ga_legacy, dict) or not isinstance(predecessor_legacy, dict):
        legacy_errors.append("authenticated legacy boundary anchor is malformed")
    return security_errors, support_errors, legacy_errors


def build_comparison(
    context: RunContext,
    ga: GaRoot,
    predecessor: Predecessor,
    candidate: Candidate,
    policy: dict[str, Any],
    state: ValidationState,
) -> dict[str, Any]:
    """Compare the exact candidate to both GA and the immediate predecessor."""

    ga_platform = ga.baseline.get("platformApi")
    predecessor_platform = _predecessor_section(predecessor, "platformApi")
    current_platform = candidate.input_value.get("platformApi")
    ga_catalog = ga.baseline.get("stableCatalog")
    predecessor_catalog = _predecessor_section(predecessor, "stableCatalog")
    ga_apps = ga.baseline.get("firstPartyApps")
    predecessor_apps = _predecessor_section(predecessor, "firstPartyApps")
    # Candidate is frozen, but Python's frozen dataclass deliberately prevents hidden
    # comparison state. Perform the app comparison inline with an explicit helper view.
    catalog_errors = _catalog_errors(ga_catalog, predecessor_catalog, candidate.input_value)
    app_errors = _app_errors(
        ga_apps,
        predecessor_apps,
        candidate.input_value.get("firstPartyApps"),
        policy,
    )
    profile_errors = _content_profile_errors(
        ga.baseline.get("contentFormatProfiles"),
        _predecessor_section(predecessor, "contentFormatProfiles"),
        candidate.input_value.get("contentFormatProfiles"),
    )
    platform_errors = _platform_api_errors(ga_platform, predecessor_platform, current_platform)
    limitation_errors = _limitation_errors(
        ga.baseline.get("limitations"),
        _predecessor_section(predecessor, "limitations"),
        candidate.input_value.get("limitations"),
    )
    security_errors, support_errors, legacy_errors = _security_support_legacy_errors(
        ga, predecessor, candidate
    )
    categories = {
        "platformApi": platform_errors,
        "catalogAndApps": [*catalog_errors, *app_errors],
        "contentProfiles": profile_errors,
        "limitations": limitation_errors,
        "security": security_errors,
        "support": support_errors,
        "legacyBoundaries": legacy_errors,
    }
    issue_ids = {
        "platformApi": "stable-maintenance.platform-api-compatibility",
        "catalogAndApps": "stable-maintenance.catalog-app-compatibility",
        "contentProfiles": "stable-maintenance.content-profile-compatibility",
        "limitations": "stable-maintenance.known-limitations",
        "security": "stable-maintenance.security",
        "support": "stable-maintenance.support-redaction",
        "legacyBoundaries": "stable-maintenance.legacy-boundaries",
    }
    comparison_blockers: list[dict[str, Any]] = []
    sections: dict[str, Any] = {}
    values = {
        "platformApi": (ga_platform, predecessor_platform, current_platform),
        "catalogAndApps": (
            {"catalog": ga_catalog, "apps": ga_apps},
            {"catalog": predecessor_catalog, "apps": predecessor_apps},
            {
                "catalog": candidate.input_value.get("stableCatalog"),
                "apps": candidate.input_value.get("firstPartyApps"),
            },
        ),
        "contentProfiles": (
            ga.baseline.get("contentFormatProfiles"),
            _predecessor_section(predecessor, "contentFormatProfiles"),
            candidate.input_value.get("contentFormatProfiles"),
        ),
        "limitations": (
            ga.baseline.get("limitations"),
            _predecessor_section(predecessor, "limitations"),
            candidate.input_value.get("limitations"),
        ),
        "security": (
            ga.baseline.get("securityBaseline"),
            _predecessor_section(predecessor, "security", "securityBaseline"),
            candidate.input_value.get("security"),
        ),
        "support": (
            ga.baseline.get("supportBaseline"),
            _predecessor_section(predecessor, "support", "supportBaseline"),
            candidate.input_value.get("support"),
        ),
        "legacyBoundaries": (
            ga.baseline.get("legacyBoundaries"),
            _predecessor_section(predecessor, "legacyBoundaries"),
            candidate.input_value.get("legacyBoundaries"),
        ),
    }
    for category, errors in categories.items():
        issues = [_issue(issue_ids[category], category, message) for message in errors]
        comparison_blockers.extend(issues)
        ga_value, prior_value, current_value = values[category]
        sections[category] = _section(ga_value, prior_value, current_value, issues, [])
        add_blockers(
            state,
            issue_ids[category],
            errors,
            "Restore the Stable 1.0 GA and predecessor compatibility contract.",
        )
    result = {
        "schemaVersion": 1,
        "kind": "stable-1.0-maintenance-comparison",
        "generatedAt": candidate.input_value.get("generatedAt"),
        "releaseId": context.manifest.release.release_id,
        "buildVersion": context.manifest.release.version,
        "releaseClass": context.manifest.policies.get("releaseClass"),
        "gaBaselineDigest": ga.baseline_digest,
        "predecessorBaselineDigest": predecessor.baseline_digest,
        "candidateIdentityDigest": candidate.identity_digest,
        "sections": sections,
        "compatible": not comparison_blockers,
        "decision": "go" if not comparison_blockers else "no-go",
        "blockers": comparison_blockers,
        "warnings": [],
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }
    add_blockers(
        state,
        "stable-maintenance.comparison-schema",
        validate_schema(result, COMPARISON_SCHEMA),
        "Regenerate the complete GA and predecessor comparison artifact.",
    )
    return result


def _catalog_errors(ga: Any, predecessor: Any, candidate_value: dict[str, Any]) -> list[str]:
    current = candidate_value.get("stableCatalog")
    current = current if isinstance(current, dict) else {}
    ga = ga if isinstance(ga, dict) else {}
    predecessor = predecessor if isinstance(predecessor, dict) else {}
    errors: list[str] = []
    if current.get("catalogId") != ga.get("catalogId") or current.get("channel") != "stable":
        errors.append("stable catalog identity or channel differs from GA")
    for field in ("edition", "revision"):
        if type(current.get(field)) is not int or type(predecessor.get(field)) is not int or current[field] < predecessor[field]:
            errors.append(f"stable catalog {field} was downgraded")
    predecessor_identity = {
        "digest": predecessor.get("digest", predecessor.get("catalogDigest")),
        "signatureDigest": predecessor.get("signatureDigest"),
        "signingKeyId": predecessor.get("signingKeyId"),
    }
    catalog_identity_changed = any(
        current.get(field) != predecessor_identity[field]
        for field in ("digest", "signatureDigest", "signingKeyId")
    )
    catalog_version_advanced = any(
        type(current.get(field)) is int
        and type(predecessor.get(field)) is int
        and current[field] > predecessor[field]
        for field in ("edition", "revision")
    )
    if catalog_identity_changed and not catalog_version_advanced:
        errors.append(
            "stable catalog bytes, signature, or signing key changed without advancing edition or revision"
        )
    for field in ("signatureStatus", "keyTrustStatus", "mirrorStatus", "rollbackStatus", "advisoryStatus", "denylistStatus"):
        if current.get(field) != "pass":
            errors.append(f"stable catalog {field} failed")
    transition_status = current.get("keyRotationTrustTransitionStatus")
    if transition_status not in {"complete", "not-applicable"}:
        errors.append("stable catalog key rotation lacks a complete trust transition")
    signing_key_changed = current.get("signingKeyId") != predecessor.get(
        "signingKeyId"
    )
    if signing_key_changed and transition_status != "complete":
        errors.append("stable catalog signing-key replacement lacks a complete trust transition")
    if transition_status == "not-applicable" and signing_key_changed:
        errors.append("stable catalog key rotation is incorrectly marked not-applicable")
    return errors


def _dotted_numeric_version(value: Any) -> tuple[int, ...] | None:
    """Parse a strict version that AppUpdateService can compare numerically."""

    if not isinstance(value, str) or not value or value != value.strip():
        return None
    tokens = value.split(".")
    if any(
        not token
        or any(character < "0" or character > "9" for character in token)
        for token in tokens
    ):
        return None
    parts: list[int] = []
    for token in tokens:
        significant = token.lstrip("0") or "0"
        if len(significant) > 10 or (
            len(significant) == 10 and significant > "2147483647"
        ):
            return None
        parts.append(int(significant))
    return tuple(parts)


def _compare_dotted_numeric_versions(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    """Compare dotted numeric versions with AppUpdateService's zero-padding semantics."""

    count = max(len(left), len(right))
    for index in range(count):
        left_part = left[index] if index < len(left) else 0
        right_part = right[index] if index < len(right) else 0
        if left_part != right_part:
            return 1 if left_part > right_part else -1
    return 0


def _support_level_ranks(policy: dict[str, Any]) -> dict[str, int]:
    catalog_policy = policy.get("catalogAndApps")
    catalog_policy = catalog_policy if isinstance(catalog_policy, dict) else {}
    allowed = catalog_policy.get("allowedSupportLevels")
    order = catalog_policy.get("supportLevelOrder")
    if (
        not isinstance(allowed, list)
        or not isinstance(order, list)
        or not allowed
        or any(not isinstance(level, str) for level in (*allowed, *order))
        or len(allowed) != len(set(allowed))
        or len(order) != len(set(order))
        or set(order) != set(allowed)
    ):
        return {}
    return {level: rank for rank, level in enumerate(order)}


def _app_errors(
    ga: Any,
    predecessor: Any,
    candidate: Any,
    policy: dict[str, Any],
) -> list[str]:
    ga_map = _rows_by(ga, "appId")
    predecessor_map = _rows_by(predecessor, "appId")
    current_map = _rows_by(candidate, "appId")
    if not ga_map or set(current_map) != set(ga_map) or set(predecessor_map) != set(ga_map):
        return ["first-party stable app id set was removed, substituted, or forked"]
    errors: list[str] = []
    support_ranks = _support_level_ranks(policy)
    if not support_ranks:
        errors.append("first-party app support-level policy is malformed or not closed")
    for app_id in sorted(current_map):
        row = current_map[app_id]
        ga_row = ga_map[app_id]
        predecessor_row = predecessor_map[app_id]
        if row.get("channel") != "stable":
            errors.append(f"first-party app {app_id} left the stable channel")
        support_levels = (
            row.get("supportLevel"),
            ga_row.get("supportLevel"),
            predecessor_row.get("supportLevel"),
        )
        if not support_ranks or any(
            level not in support_ranks for level in support_levels
        ):
            errors.append(
                f"first-party app {app_id} has an unknown support commitment"
            )
        elif (
            support_ranks[support_levels[0]] < support_ranks[support_levels[1]]
            or support_ranks[support_levels[0]]
            < support_ranks[support_levels[2]]
        ):
            errors.append(f"first-party app {app_id} reduced its support commitment")
        current_version = _dotted_numeric_version(row.get("version"))
        ga_version = _dotted_numeric_version(ga_row.get("version"))
        predecessor_version = _dotted_numeric_version(predecessor_row.get("version"))
        if current_version is None:
            errors.append(
                f"first-party app {app_id} candidate version is not strict dotted-numeric"
            )
        if ga_version is None or predecessor_version is None:
            errors.append(
                f"first-party app {app_id} authenticated version anchor is not strict dotted-numeric"
            )
        if current_version is not None and ga_version is not None:
            ga_comparison = _compare_dotted_numeric_versions(current_version, ga_version)
            if ga_comparison < 0:
                errors.append(f"first-party app {app_id} version regressed below GA")
            if (
                row.get("bundleDigest") != ga_row.get("bundleDigest")
                and ga_comparison <= 0
            ):
                errors.append(
                    f"first-party app {app_id} changed bundle bytes without increasing its version over GA"
                )
        if current_version is not None and predecessor_version is not None:
            predecessor_comparison = _compare_dotted_numeric_versions(
                current_version, predecessor_version
            )
            if predecessor_comparison < 0:
                errors.append(
                    f"first-party app {app_id} version regressed below the immediate predecessor"
                )
            if (
                row.get("bundleDigest") != predecessor_row.get("bundleDigest")
                and predecessor_comparison <= 0
            ):
                errors.append(
                    f"first-party app {app_id} changed bundle bytes without increasing its version over the immediate predecessor"
                )
        if row.get("trustState") != "trusted":
            errors.append(f"first-party app {app_id} trustState failed")
        for field in ("reviewStatus", "signingStatus", "apiCompatibilityStatus", "migrationStatus", "backupRestoreStatus", "serviceGrantStatus"):
            if row.get(field) != "pass":
                errors.append(f"first-party app {app_id} {field} failed")
        if row.get("permissionExpansion") is True and not (
            row.get("permissionConsentStatus") == "pass" and row.get("permissionRationaleStatus") == "pass"
        ):
            errors.append(f"first-party app {app_id} expands permissions without consent and rationale")
        if row.get("reviewedBundleDigest") != row.get("bundleDigest"):
            errors.append(f"first-party app {app_id} changed after review")
        schema_versions = (
            ga_row.get("appDataSchemaVersion"),
            predecessor_row.get("appDataSchemaVersion"),
        )
        anchored_versions = [value for value in schema_versions if type(value) is int]
        current_schema = row.get("appDataSchemaVersion")
        if anchored_versions and (
            type(current_schema) is not int or current_schema < max(anchored_versions)
        ):
            errors.append(f"first-party app {app_id} downgraded its app-data schema")
    return errors


def _duration_days(start: dt.datetime, end: dt.datetime) -> float:
    return (end - start).total_seconds() / 86400.0


def _operational_warning_errors(
    candidate: Candidate,
    evidence_by_id: dict[str, dict[str, Any]],
    state: ValidationState,
) -> list[str]:
    """Bind every evidence warning to the exact warning frozen with the candidate."""

    errors: list[str] = []
    declared_by_evidence: dict[str, dict[str, Any]] = {}
    warnings = candidate.input_value.get("operationalWarnings", [])
    warnings = warnings if isinstance(warnings, list) else []
    for warning in warnings:
        if not isinstance(warning, dict):
            errors.append("candidate operational warning is malformed")
            continue
        warning_id = warning.get("warningId")
        evidence_id = OPERATIONAL_WARNING_EVIDENCE_IDS.get(str(warning_id))
        if warning_id not in ALLOWED_OPERATIONAL_WARNING_IDS or evidence_id is None:
            errors.append(f"candidate operational warning {warning_id} is not policy allowlisted")
            continue
        if evidence_id in declared_by_evidence:
            errors.append(
                f"candidate contains duplicate operational warnings for {evidence_id}"
            )
            continue
        declared_by_evidence[evidence_id] = warning

    warned_evidence_ids = {
        evidence_id
        for evidence_id, row in evidence_by_id.items()
        if row.get("status") == "warn"
    }
    for evidence_id in sorted(warned_evidence_ids):
        warning = declared_by_evidence.get(evidence_id)
        evidence_digest = evidence_by_id[evidence_id].get("evidenceDigest")
        if warning is None:
            errors.append(
                f"production evidence warning {evidence_id} was not frozen as an operational warning"
            )
            continue
        if warning.get("evidenceDigest") != evidence_digest:
            errors.append(
                f"production evidence warning {evidence_id} does not match its frozen evidence digest"
            )
            continue
        warning_id = str(warning.get("warningId"))
        if not any(row.get("id") == warning_id for row in state.warnings):
            state.warnings.append(
                {
                    "id": warning_id,
                    "evidenceId": evidence_id,
                    "severity": "warning",
                    "summary": "A policy-allowlisted noncritical operational warning requires explicit acceptance.",
                    "waivable": True,
                }
            )

    for evidence_id in sorted(set(declared_by_evidence) - warned_evidence_ids):
        errors.append(
            f"candidate operational warning for {evidence_id} has no matching warned evidence row"
        )
    return errors


def validate_production_evidence(
    context: RunContext,
    ga: GaRoot,
    predecessor: Predecessor,
    candidate: Candidate,
    policy: dict[str, Any],
    state: ValidationState,
) -> tuple[dict[str, Any], str, dict[str, Any] | None]:
    """Authenticate candidate-bound normal or narrowly shortened production evidence."""

    loaded = load_json_input(context, "maintenanceEvidence")
    assert loaded
    value = loaded.value
    errors = validate_schema(value, EVIDENCE_SCHEMA)
    release_class = context.manifest.policies.get("releaseClass")
    if (
        value.get("releaseId") != context.manifest.release.release_id
        or value.get("buildVersion") != context.manifest.release.version
        or value.get("releaseClass") != release_class
        or value.get("candidateProductDigest") != candidate.product_digest
        or value.get("candidateFreezeDigest") != candidate.freeze_digest
        or value.get("predecessorBuild") != predecessor.build_version
        or value.get("predecessorProductDigest") != predecessor.product_digest
        or value.get("productionEvidence") is not True
        or value.get("fixtureOnly") is not False
        or value.get("simulatedOnly") is not False
        or value.get("skipped") is not False
    ):
        errors.append("production evidence identity or production class is invalid")
    rows = value.get("evidenceRows")
    rows = rows if isinstance(rows, list) else []
    by_id = _rows_by(rows, "evidenceId")
    evidence_digests = [
        row.get("evidenceDigest") for row in rows if isinstance(row, dict)
    ]
    if len(by_id) != len(rows) or len(evidence_digests) != len(set(evidence_digests)):
        errors.append("production evidence contains duplicate ids or evidence digests")
    required = set(REQUIRED_PRODUCTION_EVIDENCE)
    required.add("stable-maintenance.direct-ga-upgrade")
    missing = sorted(required - set(by_id))
    if missing:
        errors.append("production evidence is missing required ids: " + ", ".join(missing))
    for evidence_id, row in by_id.items():
        if (
            row.get("status") not in {"pass", "warn"}
            or row.get("candidateReleaseId") != context.manifest.release.release_id
            or row.get("candidateBuild") != context.manifest.release.version
            or row.get("candidateProductDigest") != candidate.product_digest
            or row.get("candidateFreezeDigest") != candidate.freeze_digest
            or row.get("predecessorBuild") != predecessor.build_version
            or row.get("predecessorProductDigest") != predecessor.product_digest
            or row.get("production") is not True
            or row.get("environmentClass") not in {"production", "protected-production"}
            or row.get("fresh") is not True
            or row.get("redactionStatus") != "pass"
        ):
            errors.append(f"production evidence {evidence_id} is failed, stale, or candidate-mismatched")
        errors.extend(_ga_evidence_binding_errors(evidence_id, row, ga))
        started = parse_timestamp(row.get("startedAt"))
        ended = parse_timestamp(row.get("endedAt"))
        if started is None or ended is None or ended < started:
            errors.append(f"production evidence {evidence_id} has an invalid time interval")
        if evidence_id in {
            "stable-maintenance.live-network-interoperability",
            "stable-maintenance.performance",
        } and (
            row.get("nodeCount", 0)
            < policy.get("evidenceWindows", {}).get("minimumNodeCount", 2)
            or row.get("operationCount", 0)
            < policy.get("evidenceWindows", {}).get("minimumOperationCount", 500)
        ):
            errors.append(f"production evidence {evidence_id} lacks node or operation counts")
    errors.extend(_operational_warning_errors(candidate, by_id, state))
    start = parse_timestamp(value.get("validationStartedAt"))
    end = parse_timestamp(value.get("validationEndedAt"))
    frozen = parse_timestamp(candidate.frozen_at)
    window_policy = policy.get("evidenceWindows", {})
    normal_seconds = window_policy.get("minimumLiveNetworkDurationSeconds", 86400)
    shortened_seconds = policy.get("hotfix", {}).get(
        "minimumPrepublicationDurationSeconds", 3600
    )
    window = value.get("windowClass")
    change_scope = candidate.input_value.get("changeScope")
    change_scope = change_scope if isinstance(change_scope, dict) else {}
    shortened_ids = set(change_scope.get("shortenedEvidenceIds", []))
    allowed_shortened = set(policy.get("hotfix", {}).get("allowedShortenedScenarios", []))
    follow_up: dict[str, Any] | None = None
    if start is None or end is None or end < start or frozen is None or start < frozen:
        errors.append("production evidence aggregate interval is invalid")
    else:
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        maximum_age = dt.timedelta(
            days=window_policy.get("maximumAgeDays", 14)
        )
        if end > now or end < now - maximum_age:
            errors.append("production evidence aggregate interval is stale or future-dated")
        for evidence_id, row in by_id.items():
            row_start = parse_timestamp(row.get("startedAt"))
            row_end = parse_timestamp(row.get("endedAt"))
            if (
                row_start is not None
                and row_end is not None
                and (
                    row_start < start
                    or row_end > end
                    or frozen is None
                    or row_start < frozen
                )
            ):
                errors.append(
                    f"production evidence {evidence_id} falls outside the post-freeze aggregate window"
                )
        duration_seconds = (end - start).total_seconds()
        if window == "normal" and duration_seconds < normal_seconds:
            errors.append("normal maintenance evidence window is shorter than policy")
        if window == "normal" and shortened_ids:
            errors.append("normal evidence cannot claim shortened hotfix scenarios")
        if window == "normal":
            for evidence_id in allowed_shortened:
                row = by_id.get(evidence_id, {})
                row_start = parse_timestamp(row.get("startedAt"))
                row_end = parse_timestamp(row.get("endedAt"))
                if (
                    row_start is None
                    or row_end is None
                    or (row_end - row_start).total_seconds() < normal_seconds
                ):
                    errors.append(
                        f"normal evidence {evidence_id} is shorter than the policy window"
                    )
        if window == "shortened-security-hotfix":
            if release_class != "security-hotfix" or duration_seconds < shortened_seconds:
                errors.append("shortened evidence window is not an eligible security hotfix window")
            if not shortened_ids or not shortened_ids.issubset(allowed_shortened):
                errors.append("hotfix shortened evidence ids are empty or outside policy")
            for evidence_id in allowed_shortened:
                row = by_id.get(evidence_id, {})
                row_start = parse_timestamp(row.get("startedAt"))
                row_end = parse_timestamp(row.get("endedAt"))
                required_seconds = (
                    shortened_seconds if evidence_id in shortened_ids else normal_seconds
                )
                if (
                    row_start is None
                    or row_end is None
                    or (row_end - row_start).total_seconds() < required_seconds
                ):
                    errors.append(
                        f"hotfix evidence {evidence_id} does not meet its authorized window"
                    )
            follow_up = _hotfix_follow_up(context, candidate, value, policy, end, state)
        elif release_class == "maintenance" and window != "normal":
            errors.append("routine maintenance requires the complete normal evidence window")
    add_blockers(
        state,
        "stable-maintenance.production-evidence",
        errors,
        "Regenerate fresh production evidence for the exact candidate and predecessor.",
    )
    return value, loaded.digest, follow_up


def _hotfix_follow_up(
    context: RunContext,
    candidate: Candidate,
    evidence: dict[str, Any],
    policy: dict[str, Any],
    validation_end: dt.datetime,
    state: ValidationState,
) -> dict[str, Any]:
    scope = candidate.input_value.get("changeScope")
    scope = scope if isinstance(scope, dict) else {}
    errors: list[str] = []
    if (
        not scope.get("incidentId")
        or scope.get("severity") != "critical"
        or not scope.get("affectedPackageKeys")
        or scope.get("hotfixPolicyAuthorizationDigest") is None
        or not scope.get("followUpOwner")
        or not scope.get("followUpApprover")
    ):
        errors.append("security hotfix lacks critical incident, affected scope, authorization, or follow-up ownership")
    allowed = set(policy.get("hotfix", {}).get("allowedShortenedScenarios", []))
    requested = set(scope.get("shortenedEvidenceIds", []))
    if not requested or not requested.issubset(allowed):
        errors.append("security hotfix shortened scenarios are empty or outside policy")
    deadline_hours = policy.get("hotfix", {}).get("followUpDeadlineHours", 168)
    deadline = validation_end + dt.timedelta(hours=deadline_hours)
    obligation = {
        "schemaVersion": 1,
        "kind": "stable-1.0-hotfix-follow-up-obligation",
        "generatedAt": evidence.get("generatedAt"),
        "status": "open",
        "releaseId": context.manifest.release.release_id,
        "buildVersion": context.manifest.release.version,
        "releaseClass": "security-hotfix",
        "incidentId": scope.get("incidentId"),
        "advisoryId": scope.get("incidentId"),
        "severity": "critical",
        "productDigest": candidate.product_digest,
        "candidateIdentityDigest": candidate.identity_digest,
        "candidateFreezeDigest": candidate.freeze_digest,
        "candidateFrozenAt": candidate.frozen_at,
        "predecessorBuild": evidence.get("predecessorBuild"),
        "predecessorProductDigest": evidence.get("predecessorProductDigest"),
        "shortenedEvidenceIds": sorted(requested),
        "fullEvidenceRequired": sorted(requested),
        "deadline": deadline.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "owner": scope.get("followUpOwner"),
        "approver": scope.get("followUpApprover"),
        "expectedEvidenceKinds": ["stable-1.0-maintenance-evidence"],
        "closureCriteria": [
            "all-required-full-window-production-evidence-pass",
            "exact-published-hotfix-product-binding",
            "redaction-pass",
        ],
        "failureBehavior": "open-release-incident-and-block-next-routine-maintenance",
        "blocksRoutineMaintenance": True,
        "closureEvidenceDigest": None,
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }
    errors.extend(validate_schema(obligation, FOLLOW_UP_SCHEMA))
    add_blockers(
        state,
        "stable-maintenance.hotfix-follow-up",
        errors,
        "Provide the closed critical-hotfix authorization and deterministic follow-up obligation.",
    )
    return obligation


def close_hotfix_follow_up(
    context: RunContext,
    ga: GaRoot,
    candidate: Candidate,
    state: ValidationState,
) -> dict[str, Any]:
    """Close one published hotfix obligation using full, production-only evidence."""

    obligation_input = load_json_input(context, "hotfixFollowUpObligation")
    evidence_input = load_json_input(context, "hotfixFollowUpEvidence")
    policy_input = load_json_input(context, "maintenancePolicy")
    assert obligation_input and evidence_input and policy_input
    obligation = obligation_input.value
    evidence = evidence_input.value
    errors = [
        *validate_schema(obligation, FOLLOW_UP_SCHEMA),
        *validate_schema(evidence, EVIDENCE_SCHEMA),
    ]
    obligated_release = obligation.get("releaseId")
    obligated_build = obligation.get("buildVersion")
    obligated_product = obligation.get("productDigest")
    obligated_identity = obligation.get("candidateIdentityDigest")
    obligated_freeze = obligation.get("candidateFreezeDigest")
    obligated_predecessor_build = obligation.get("predecessorBuild")
    obligated_predecessor_product = obligation.get("predecessorProductDigest")
    if (
        obligation.get("status") != "open"
        or evidence.get("releaseId") != obligated_release
        or evidence.get("buildVersion") != obligated_build
        or evidence.get("releaseClass") != "security-hotfix"
        or evidence.get("windowClass") != "normal"
        or evidence.get("candidateProductDigest") != obligated_product
        or evidence.get("candidateFreezeDigest") != obligated_freeze
        or evidence.get("predecessorBuild") != obligated_predecessor_build
        or evidence.get("predecessorProductDigest") != obligated_predecessor_product
        or evidence.get("productionEvidence") is not True
        or evidence.get("fixtureOnly") is not False
        or evidence.get("simulatedOnly") is not False
        or evidence.get("skipped") is not False
    ):
        errors.append("hotfix follow-up obligation or full-window evidence identity is invalid")
    rows = _rows_by(evidence.get("evidenceRows"), "evidenceId")
    evidence_rows = evidence.get("evidenceRows")
    evidence_rows = evidence_rows if isinstance(evidence_rows, list) else []
    required = set(obligation.get("fullEvidenceRequired", []))
    if len(rows) != len(evidence_rows):
        errors.append("hotfix follow-up contains duplicate or malformed evidence rows")
    for evidence_id, row in rows.items():
        errors.extend(_ga_evidence_binding_errors(evidence_id, row, ga))
        if (
            row.get("predecessorBuild") != obligated_predecessor_build
            or row.get("predecessorProductDigest") != obligated_predecessor_product
        ):
            errors.append(
                f"hotfix follow-up evidence {evidence_id} is not predecessor-bound"
            )
    if not required:
        errors.append("hotfix follow-up does not contain all passing full-window evidence")
    started = parse_timestamp(evidence.get("validationStartedAt"))
    ended = parse_timestamp(evidence.get("validationEndedAt"))
    frozen = parse_timestamp(obligation.get("candidateFrozenAt"))
    minimum_seconds = policy_input.value.get("evidenceWindows", {}).get(
        "minimumLiveNetworkDurationSeconds", 86400
    )
    maximum_age = dt.timedelta(
        days=policy_input.value.get("evidenceWindows", {}).get("maximumAgeDays", 14)
    )
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    for evidence_id in sorted(required):
        row = rows.get(evidence_id, {})
        row_started = parse_timestamp(row.get("startedAt"))
        row_ended = parse_timestamp(row.get("endedAt"))
        if (
            row.get("status") != "pass"
            or row.get("candidateReleaseId") != obligated_release
            or row.get("candidateBuild") != obligated_build
            or row.get("candidateProductDigest") != obligated_product
            or row.get("candidateFreezeDigest") != obligated_freeze
            or row.get("predecessorBuild") != obligated_predecessor_build
            or row.get("predecessorProductDigest") != obligated_predecessor_product
            or row.get("production") is not True
            or row.get("fresh") is not True
            or row.get("redactionStatus") != "pass"
            or row_started is None
            or row_ended is None
            or row_ended < row_started
            or row_started > now
            or row_ended > now
            or row_ended < now - maximum_age
            or (row_ended - row_started).total_seconds() < minimum_seconds
            or frozen is None
            or row_started < frozen
            or (started is not None and row_started < started)
            or (ended is not None and row_ended > ended)
        ):
            errors.append(
                f"hotfix follow-up evidence {evidence_id} is not a complete full-window scenario"
            )
    if (
        started is None
        or ended is None
        or frozen is None
        or started < frozen
        or ended < started
        or started > now
        or ended > now
        or ended < now - maximum_age
        or (ended - started).total_seconds() < minimum_seconds
    ):
        errors.append("hotfix follow-up full production evidence window is incomplete")
    add_blockers(
        state,
        "stable-maintenance.hotfix-follow-up",
        errors,
        "Complete every obligated full-window scenario with exact-candidate production evidence.",
    )
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-hotfix-follow-up-closure",
        "generatedAt": evidence.get("generatedAt"),
        "status": "closed" if not state.blockers else "rejected",
        "releaseId": obligated_release,
        "buildVersion": obligated_build,
        "productDigest": obligated_product,
        "candidateIdentityDigest": obligated_identity,
        "predecessorBuild": obligated_predecessor_build,
        "predecessorProductDigest": obligated_predecessor_product,
        "obligationDigest": obligation_input.digest,
        "fullEvidenceDigest": evidence_input.digest,
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }

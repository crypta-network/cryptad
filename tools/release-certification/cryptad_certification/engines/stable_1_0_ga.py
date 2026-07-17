"""Canonical, side-effect-free Stable 1.0 GA validation and promotion preparation."""

from __future__ import annotations

import datetime as dt
import os
import shutil
from pathlib import Path
from typing import Any

from cryptad_certification.io import read_json, write_json, write_text
from cryptad_certification.models import RunContext
from cryptad_certification.schema_validation import validate_schema
from cryptad_certification.workspace import reset_confined_directory

from .stable_1_0_ga_artifacts import (
    build_redaction_report,
    render_go_no_go,
    render_release_notes,
)
from .stable_1_0_ga_core import (
    AUTHORIZATION_FILE,
    AUTHORIZATION_SCOPE,
    CHECKSUMS_FILE,
    GA_VALIDATION_SCHEMA,
    KNOWN_LIMITATIONS_FILE,
    MAINTENANCE_BASELINE_FILE,
    MAINTENANCE_BASELINE_SCHEMA,
    PROVENANCE_FILE,
    PUBLICATION_PLAN_FILE,
    PUBLICATION_RECEIPT_FILE,
    REDACTION_REPORT_FILE,
    RELEASE_NOTES_FILE,
    REPORT_FILE,
    SCHEMA_VERSION,
    STABLE_MILESTONE,
    SUMMARY_FILE,
    TOOL_NAME,
    TOOL_VERSION,
    VALIDATION_FILE,
    VALIDATION_IDENTITY_FILE,
    ValidationState,
    authenticate_selected_rc,
    authenticate_upgrade_predecessor,
    build_ga_validation_record,
    canonical_artifact_base_uri,
    canonical_publication_targets,
    file_digest,
    ga_validation_authorization_identity,
    is_public_https_uri,
    is_supported_catalog_publication_uri,
    load_json_input,
    parse_timestamp,
    publication_receipt_errors,
    semantic_digest,
    validate_authorization,
    validate_carried_waivers,
    validate_lineage,
    validate_post_freeze,
)

PUBLICATION_PLAN_SCHEMA = "stable-1.0-ga-publication-plan-v1.schema.json"
MAINTENANCE_CATEGORIES = [
    "compatible-bug-fixes",
    "security-fixes-and-hotfixes",
    "platform-api-compatible-additions-and-deprecations",
    "stable-catalog-and-app-patch-updates",
    "emergency-advisory-and-denylist-updates",
    "maintenance-release-upgrade-and-rollback-verification",
]
PUBLIC_ASSET_ROLES = (
    "rc-archive",
    "rc-product",
    "release-notes",
    "known-limitations",
    "provenance",
    "maintenance-baseline",
    "checksums",
)


def _timestamp(value: Any) -> str:
    parsed = parse_timestamp(value)
    if parsed is None:
        raise ValueError("Stable GA timestamp is malformed")
    return parsed.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _utc_now() -> dt.datetime:
    """Return the production validation clock normalized to whole UTC seconds."""

    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def _canonical_policy(context: RunContext, supplied: dict[str, Any], path: Path) -> list[str]:
    canonical_path = (
        context.workspace_root
        / "tools"
        / "release-certification"
        / "stable-1.0-ga-policy.json"
    )
    errors: list[str] = []
    if read_json(canonical_path) != supplied or file_digest(canonical_path) != file_digest(path):
        errors.append("Stable GA policy is not the exact checked-in authoritative policy")
    expected_keys = {
        "schemaVersion",
        "kind",
        "stableMilestone",
        "component",
        "profile",
        "owner",
        "postFreezeValidation",
        "authorization",
        "allowedRcWaiverIds",
        "publication",
        "nonWaivableBlockers",
        "maintenanceEvidenceWindows",
        "maintenanceBaseline",
    }
    if set(supplied) != expected_keys:
        errors.append("Stable GA policy top-level fields are not closed")
    if (
        supplied.get("schemaVersion") != 1
        or supplied.get("kind") != "stable-1.0-ga-policy"
        or supplied.get("stableMilestone") != STABLE_MILESTONE
        or supplied.get("component") != "stable-ga"
        or supplied.get("profile") != "stable-review"
    ):
        errors.append("Stable GA policy identity is invalid")
    maintenance_baseline = supplied.get("maintenanceBaseline")
    if (
        not isinstance(maintenance_baseline, dict)
        or set(maintenance_baseline)
        != {
            "minimumDeprecationWindowContractVersions",
            "minimumRemovalWindowContractVersions",
            "criticalStableRemovalWaiverAllowed",
        }
        or type(
            maintenance_baseline.get("minimumDeprecationWindowContractVersions")
        )
        is not int
        or maintenance_baseline.get("minimumDeprecationWindowContractVersions", 0) < 2
        or type(maintenance_baseline.get("minimumRemovalWindowContractVersions"))
        is not int
        or maintenance_baseline.get("minimumRemovalWindowContractVersions", 0) < 2
        or maintenance_baseline.get("criticalStableRemovalWaiverAllowed") is not False
    ):
        errors.append("Stable GA maintenance baseline policy is malformed")
    return errors


def _block_errors(
    state: ValidationState,
    issue_id: str,
    errors: list[str],
    remediation: str,
) -> None:
    existing = {
        (
            row.get("id"),
            row.get("evidenceId"),
            row.get("summary"),
            row.get("remediation"),
            row.get("waivable"),
        )
        for row in state.blockers
        if isinstance(row, dict)
    }
    for error in errors:
        summary = error.rstrip(".") + "."
        identity = (issue_id, issue_id, summary, remediation, False)
        if identity in existing:
            continue
        state.block(issue_id, issue_id, summary, remediation)
        existing.add(identity)


def _safe_https(value: Any) -> bool:
    return is_public_https_uri(value)


def _catalog_targets(context: RunContext) -> tuple[dict[str, Any], list[str]]:
    publication_targets = canonical_publication_targets(context)
    catalog_targets = publication_targets["catalog"]
    primary_uri = catalog_targets["primaryUri"]
    mirrors = catalog_targets["mirrorUris"]
    rollback_uri = catalog_targets["rollbackUri"]
    errors: list[str] = []
    if not is_supported_catalog_publication_uri(primary_uri):
        errors.append("catalog primary publication target is not a public HTTPS URI")
    if not mirrors or any(
        not is_supported_catalog_publication_uri(item) for item in mirrors
    ):
        errors.append("catalog mirror publication targets must be nonempty public HTTPS URIs")
    if len(mirrors) != len(set(mirrors)) or primary_uri in mirrors:
        errors.append("catalog publication targets contain ambiguous duplicate locations")
    if (
        not is_supported_catalog_publication_uri(rollback_uri)
        or rollback_uri == primary_uri
        or rollback_uri in mirrors
    ):
        errors.append("catalog rollback target must be a distinct public HTTPS catalog URI")
    targets = {
        "primary": {
            "locationId": "primary",
            "publicUri": primary_uri,
        },
        "mirrors": [
            {"locationId": f"mirror-{index}", "publicUri": uri}
            for index, uri in enumerate(mirrors, start=1)
        ],
        "rollback": {"locationId": "rollback", "publicUri": rollback_uri},
    }
    return targets, errors


def _copy_exact(source: Path, destination: Path, expected_digest: str) -> None:
    if destination.is_symlink() or destination.exists():
        raise ValueError("Stable GA exact-byte output path already exists")
    shutil.copyfile(source, destination)
    os.chmod(destination, 0o644)
    if file_digest(destination) != expected_digest:
        destination.unlink(missing_ok=True)
        raise ValueError("Stable GA exact-byte copy differs from the selected RC")


def _normalized_apps(freeze: dict[str, Any]) -> list[dict[str, Any]]:
    apps = freeze.get("firstPartyApps")
    if not isinstance(apps, list):
        raise ValueError("Stable RC first-party app freeze is malformed")
    return [
        {
            "appId": row.get("appId"),
            "version": row.get("version"),
            "bundleDigest": row.get("bundleDigest"),
            "reviewReceiptDigest": row.get("reviewReceiptDigest"),
            "appSigningKeyId": row.get("appSigningKeyId"),
            "reviewerKeyId": row.get("reviewerKeyId"),
        }
        for row in apps
        if isinstance(row, dict)
    ]


def _promotion_identity(
    context: RunContext,
    selected: Any,
    lineage_digest: str,
    validation_identity_digest: str,
) -> dict[str, Any]:
    catalog = selected.freeze.get("stableCatalog", {})
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-ga-promotion-identity",
        "stableMilestone": STABLE_MILESTONE,
        "releaseId": context.manifest.release.release_id,
        "buildVersion": context.manifest.release.version,
        "expectedTag": f"v{context.manifest.release.version}",
        "expectedReleaseBranch": f"release/{context.manifest.release.version}",
        "sourceCommit": selected.freeze.get("candidate", {}).get("sourceCommit"),
        "sourceRef": selected.freeze.get("candidate", {}).get("sourceRef"),
        "freezeDigest": selected.freeze.get("contentDigest"),
        "freezeFileDigest": selected.freeze_file_digest,
        "archiveDigest": selected.archive_digest,
        "productDistributionDigest": selected.product_digest,
        "lineageDigest": lineage_digest,
        "validationAuthorizationIdentityDigest": validation_identity_digest,
        "catalogDigest": catalog.get("catalogDigest"),
        "catalogRevision": catalog.get("revision"),
        "platformApiDigest": semantic_digest(selected.freeze.get("platformApi")),
        "firstPartyAppsDigest": semantic_digest(selected.freeze.get("firstPartyApps")),
        "contentProfilesDigest": semantic_digest(
            selected.freeze.get("contentFormatProfiles")
        ),
        "limitationsDigest": semantic_digest(
            selected.freeze.get("limitationsAndPolicy")
        ),
    }


def _maintenance_baseline(
    context: RunContext,
    selected: Any,
    validation: dict[str, Any],
    policy: dict[str, Any],
    promotion_identity_digest: str,
    generated_at: str,
) -> dict[str, Any]:
    freeze = selected.freeze
    candidate = freeze.get("candidate", {})
    platform = freeze.get("platformApi", {})
    catalog = freeze.get("stableCatalog", {})
    limitations = freeze.get("limitationsAndPolicy", {})
    scenarios = validation.get("scenarios", {})
    security = scenarios.get("securityResponse", {})
    support = scenarios.get("supportDiagnostics", {})
    catalog_operations = scenarios.get("catalogOperations", {})
    apps = freeze.get("firstPartyApps", [])
    profiles = freeze.get("contentFormatProfiles", [])
    reviewer_keys = sorted(
        {str(row.get("reviewerKeyId")) for row in apps if isinstance(row, dict)}
    )
    app_keys = sorted(
        {str(row.get("appSigningKeyId")) for row in apps if isinstance(row, dict)}
    )
    normalized_apps = [
        {
            "appId": row.get("appId"),
            "version": row.get("version"),
            "channel": row.get("channel"),
            "supportLevel": row.get("supportLevel"),
            "bundleDigest": row.get("bundleDigest"),
            "appSigningKeyId": row.get("appSigningKeyId"),
            "reviewReceiptDigest": row.get("reviewReceiptDigest"),
            "reviewerKeyId": row.get("reviewerKeyId"),
            "manifestDigest": row.get("manifestDigest"),
            "permissionSetDigest": row.get("declaredPermissionSetDigest"),
            "targetApiStability": row.get("targetApiStability"),
            "apiCompatibilityEvidenceDigest": row.get(
                "apiCompatibilityEvidenceDigest"
            ),
            "appDataSchemaVersion": row.get("appDataSchemaVersion"),
            "migrationReadiness": row.get("migrationReadiness"),
            "backupRestoreSupport": row.get("backupRestore"),
            "supportMetadataDigest": row.get("supportMetadataDigest"),
            "redactedDiagnosticsReadiness": row.get(
                "redactedDiagnosticsReadiness"
            ),
        }
        for row in apps
        if isinstance(row, dict)
    ]
    normalized_profiles = [
        {
            "profileId": row.get("profileId"),
            "version": row.get("version"),
            "status": row.get("status"),
            "descriptorDigest": row.get("descriptorDigest"),
            "canonicalizationRulesDigest": row.get(
                "canonicalizationRulesDigest"
            ),
            "maximumSizePolicyDigest": semantic_digest(
                row.get("maximumSizePolicy")
            ),
            "signaturePayloadRulesDigest": semantic_digest(
                row.get("signaturePayloadRules")
            ),
            "parserValidatorCompatibilityEvidenceDigest": row.get(
                "parserValidatorCompatibilityEvidenceDigest"
            ),
        }
        for row in profiles
        if isinstance(row, dict)
    ]
    allowed = limitations.get("allowedLimitations", [])
    maintenance_policy = policy.get("maintenanceBaseline")
    if not isinstance(maintenance_policy, dict):
        raise ValueError("Stable GA maintenance baseline policy is malformed")
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-maintenance-baseline",
        "generatedAt": generated_at,
        "stableMilestone": STABLE_MILESTONE,
        "status": "prepared",
        "release": {
            "releaseId": context.manifest.release.release_id,
            "buildVersion": context.manifest.release.version,
            "tag": f"v{context.manifest.release.version}",
            "sourceCommit": candidate.get("sourceCommit"),
            "sourceRef": candidate.get("sourceRef"),
            "rcFreezeDigest": freeze.get("contentDigest"),
            "rcProductDigest": selected.product_digest,
            "gaPromotionDigest": promotion_identity_digest,
        },
        "platformApi": {
            "baselineName": platform.get("baselineName"),
            "baselineContractVersion": platform.get("baselineContractVersion"),
            "baselineDigest": platform.get("baselineDigest"),
            "currentContractVersion": platform.get("currentContractVersion"),
            "currentContractDigest": platform.get("currentContractDigest"),
            "stableSurfaceDigest": semantic_digest(
                {
                    "baselineDigest": platform.get("baselineDigest"),
                    "currentContractDigest": platform.get("currentContractDigest"),
                    "stableCapabilityCount": platform.get("stableCapabilityCount"),
                    "stableEndpointCount": platform.get("stableEndpointCount"),
                }
            ),
            "compatibilityWindowPolicyDigest": platform.get(
                "compatibilityWindowPolicyDigest"
            ),
            "minimumDeprecationWindowContractVersions": maintenance_policy.get(
                "minimumDeprecationWindowContractVersions"
            ),
            "minimumRemovalWindowContractVersions": maintenance_policy.get(
                "minimumRemovalWindowContractVersions"
            ),
            "criticalStableRemovalWaiverAllowed": maintenance_policy.get(
                "criticalStableRemovalWaiverAllowed"
            ),
        },
        "stableCatalog": {
            "catalogId": catalog.get("catalogId"),
            "channel": catalog.get("channel"),
            "catalogVersion": catalog.get("catalogVersion"),
            "edition": catalog.get("edition"),
            "revision": catalog.get("revision"),
            "catalogDigest": catalog.get("catalogDigest"),
            "signatureDigest": catalog.get("signatureDigest"),
            "signingKeyId": catalog.get("catalogSigningKeyId"),
            "artifactTimestamp": catalog.get("artifactTimestamp"),
            "keyRotationStatus": catalog.get("keyRotationStatus", {}).get("status"),
            "advisoryCount": catalog.get("securityAdvisoryCount"),
            "denylistCount": catalog.get("denylistCount"),
        },
        "firstPartyApps": normalized_apps,
        "contentFormatProfiles": normalized_profiles,
        "limitations": {
            "stablePolicyDigest": limitations.get("stableReadinessPolicyDigest"),
            "stableKnownLimitationsDigest": limitations.get(
                "stableKnownLimitationsDigest"
            ),
            "publicKnownIssuesDigest": limitations.get(
                "publicBetaKnownIssuesDigest"
            ),
            "allowedLimitationsDigest": limitations.get(
                "allowedLimitationsDigest"
            ),
            "allowedLimitations": allowed,
            "disallowedLimitationCount": limitations.get(
                "disallowedLimitationCount"
            ),
            "betaOnlyLimitationCount": limitations.get("betaOnlyLimitationCount"),
        },
        "securityBaseline": {
            "catalogSigningKey": {
                "keyId": catalog.get("catalogSigningKeyId"),
                "state": "uncompromised",
            },
            "reviewerKeys": [
                {"keyId": key, "state": "uncompromised"} for key in reviewer_keys
            ],
            "appSigningKeys": [
                {"keyId": key, "state": "uncompromised"} for key in app_keys
            ],
            "keyRotationStatus": catalog.get("keyRotationStatus", {}).get("status"),
            "advisoryCount": catalog.get("securityAdvisoryCount"),
            "denylistCount": catalog.get("denylistCount"),
            "securityDrillDigest": candidate.get("securityDrillDigest"),
            "failClosedUpdateEvidenceDigest": security.get("evidenceDigest"),
        },
        "supportBaseline": {
            "supportBundleKind": "cryptad-operator-support-bundle",
            "supportBundleSchemaVersion": 2,
            "diagnosticsEvidenceDigest": support.get("evidenceDigest"),
            "supportFeedbackEvidenceDigest": limitations.get(
                "supportFeedbackReadinessEvidenceDigest"
            ),
            "securityReportingEvidenceDigest": security.get("evidenceDigest"),
            "redactionStatus": "pass",
        },
        "legacyBoundaries": {
            "evidenceDigest": limitations.get(
                "legacyPluginAdminFreezeEvidenceDigest"
            ),
            "legacyAdminState": "maintenance-only",
            "mutatingLegacyPathsAllowed": False,
            "newInCorePluginApiAllowed": False,
            "legacyPluginRuntimeRestored": False,
            "fproxyBrowseRetained": True,
            "contentFilterRetained": True,
            "emergencyFallbackRetained": True,
        },
        "requiredEvidenceWindows": policy.get("maintenanceEvidenceWindows"),
        "maintenanceCategories": MAINTENANCE_CATEGORIES,
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }


def _known_limitations(context: RunContext, selected: Any) -> dict[str, Any]:
    limitations = selected.freeze.get("limitationsAndPolicy", {})
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-ga-known-limitations",
        "stableMilestone": STABLE_MILESTONE,
        "releaseId": context.manifest.release.release_id,
        "buildVersion": context.manifest.release.version,
        "freezeDigest": selected.freeze.get("contentDigest"),
        "productDistributionDigest": selected.product_digest,
        "allowedLimitations": limitations.get("allowedLimitations", []),
        "allowedLimitationsDigest": limitations.get("allowedLimitationsDigest"),
        "disallowedLimitationCount": limitations.get("disallowedLimitationCount"),
        "betaOnlyLimitationCount": limitations.get("betaOnlyLimitationCount"),
    }


def _write_checksums(path: Path, files: list[Path]) -> None:
    rows = [
        f"{file_digest(item).removeprefix('sha256:')}  {item.name}"
        for item in sorted(files, key=lambda item: item.name)
    ]
    write_text(path, "\n".join(rows))


def _publication_plan(
    context: RunContext,
    selected: Any,
    targets: dict[str, Any],
    promotion_identity_digest: str,
    release_notes_digest: str,
    generated_at: str,
    assets: list[dict[str, Any]],
    publication_state: str,
) -> dict[str, Any]:
    catalog = selected.freeze.get("stableCatalog", {})
    base = canonical_artifact_base_uri(
        context.manifest.policies.get("artifactBaseUri")
    )
    publication_targets_digest = semantic_digest(
        canonical_publication_targets(context)
    )
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-ga-publication-plan",
        "generatedAt": generated_at,
        "releaseId": context.manifest.release.release_id,
        "buildVersion": context.manifest.release.version,
        "sourceCommit": selected.freeze.get("candidate", {}).get("sourceCommit"),
        "expectedTag": f"v{context.manifest.release.version}",
        "expectedReleaseBranch": f"release/{context.manifest.release.version}",
        "artifactBaseUri": base,
        "publicationTargetsDigest": publication_targets_digest,
        "publicationState": publication_state,
        "promotionIdentityDigest": promotion_identity_digest,
        "releaseNotesDigest": release_notes_digest,
        "catalog": {
            "catalogId": catalog.get("catalogId"),
            "channel": "stable",
            "revision": catalog.get("revision"),
            "catalogDigest": catalog.get("catalogDigest"),
            "signatureDigest": catalog.get("signatureDigest"),
            "signingKeyId": catalog.get("catalogSigningKeyId"),
            "artifactTimestamp": catalog.get("artifactTimestamp"),
            "primary": targets["primary"],
            "mirrors": targets["mirrors"],
            "rollbackUri": targets["rollback"]["publicUri"],
            "rollbackRevision": catalog.get("verifiedRollback", {}).get("revision"),
            "rollbackDigest": catalog.get("verifiedRollback", {}).get("digest"),
            "keyRotationState": catalog.get("keyRotationStatus", {}).get("status"),
            "advisoryCount": catalog.get("securityAdvisoryCount"),
            "denylistCount": catalog.get("denylistCount"),
            "publicationOperation": "verify-exact-frozen-bytes",
        },
        "assets": assets,
        "sideEffectsPerformed": False,
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }


def _promotion_record(
    context: RunContext,
    selected: Any,
    lineage_digest: str,
    ga_validation_digest: str,
    authorization_digest: str,
    carried_waivers: list[dict[str, Any]],
    known: dict[str, Any],
    release_notes_digest: str,
    baseline_digest: str,
    assets: list[dict[str, Any]],
    publication_state: str,
    authorization_valid: bool,
    state: ValidationState,
    generated_at: str,
) -> dict[str, Any]:
    validation_passed = not state.blockers
    promotion_ready = validation_passed and authorization_valid
    candidate = selected.freeze.get("candidate", {})
    platform = selected.freeze.get("platformApi", {})
    catalog = selected.freeze.get("stableCatalog", {})
    decision = (
        "go-with-waivers"
        if promotion_ready and carried_waivers
        else "go"
        if promotion_ready
        else "no-go"
    )
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-ga-promotion",
        "generatedAt": generated_at,
        "validationState": "publication-authorized" if promotion_ready else "validated",
        "publicationState": publication_state,
        "stableMilestone": STABLE_MILESTONE,
        "releaseId": context.manifest.release.release_id,
        "buildVersion": context.manifest.release.version,
        "expectedTag": f"v{context.manifest.release.version}",
        "expectedReleaseBranch": f"release/{context.manifest.release.version}",
        "sourceCommit": candidate.get("sourceCommit"),
        "sourceRef": candidate.get("sourceRef"),
        "status": "pass" if validation_passed else "fail",
        "promotionReady": promotion_ready,
        "nonRelease": False,
        "decision": decision,
        "selectedRc": {
            "freezeDigest": selected.freeze.get("contentDigest"),
            "freezeFileDigest": selected.freeze_file_digest,
            "archiveDigest": selected.archive_digest,
            "productDistributionDigest": selected.product_digest,
            "lineageDigest": lineage_digest,
        },
        "payloadIdentity": {
            "rcProductDigest": selected.product_digest,
            "gaProductDigest": selected.product_digest,
            "bitIdentical": True,
            "rebuildPerformed": False,
        },
        "platformApi": {
            key: platform.get(key)
            for key in (
                "baselineName",
                "baselineContractVersion",
                "baselineDigest",
                "currentContractVersion",
                "currentContractDigest",
                "compatibilityWindowPolicyDigest",
                "stableBreakingChangeVerification",
            )
        },
        "stableCatalog": {
            "catalogId": catalog.get("catalogId"),
            "channel": catalog.get("channel"),
            "revision": catalog.get("revision"),
            "catalogDigest": catalog.get("catalogDigest"),
            "signatureDigest": catalog.get("signatureDigest"),
            "signingKeyId": catalog.get("catalogSigningKeyId"),
            "artifactTimestamp": catalog.get("artifactTimestamp"),
        },
        "firstPartyApps": _normalized_apps(selected.freeze),
        "contentProfilesDigest": semantic_digest(
            selected.freeze.get("contentFormatProfiles")
        ),
        "gaValidationDigest": ga_validation_digest,
        "gaAuthorizationDigest": authorization_digest,
        "publicationTargetsDigest": semantic_digest(
            canonical_publication_targets(context)
        ),
        "acceptedRcWaivers": [
            {key: row[key] for key in ("id", "source", "scope", "expiresAt", "stableGaAllowed")}
            for row in carried_waivers
        ],
        "allowedLimitations": known["allowedLimitations"],
        "publicationReadiness": {
            "status": "pass" if promotion_ready else "fail",
            "authorizationStatus": "pass" if authorization_valid else "fail",
            "targetConflictStatus": (
                "pass"
                if publication_state == "publication-complete"
                else "fail"
                if publication_state == "publication-verification-failed"
                else "not-checked"
            ),
            "catalogConfirmationStatus": (
                "pass"
                if publication_state == "publication-complete"
                else "fail"
                if publication_state == "publication-verification-failed"
                else "planned"
            ),
            "sideEffectsPerformed": False,
        },
        "plannedPublicArtifacts": [
            {
                "name": row["name"],
                "sizeBytes": row["sizeBytes"],
                "digest": row["digest"],
                "sourceKind": row["sourceKind"],
            }
            for row in assets
        ],
        "releaseNotesDigest": release_notes_digest,
        "maintenanceBaselineDigest": baseline_digest,
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
        "blockers": state.blockers,
    }


def _provenance(
    context: RunContext,
    selected: Any,
    lineage_digest: str,
    rc_validation_digest: str,
    validation_identity_digest: str,
    ga_validation_digest: str,
    authorization_digest: str,
    promotion_identity_digest: str,
    generated_at: str,
) -> dict[str, Any]:
    catalog = selected.freeze.get("stableCatalog", {})
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-ga-provenance",
        "generatedAt": generated_at,
        "stableMilestone": STABLE_MILESTONE,
        "releaseId": context.manifest.release.release_id,
        "buildVersion": context.manifest.release.version,
        "source": {
            "commit": selected.freeze.get("candidate", {}).get("sourceCommit"),
            "ref": selected.freeze.get("candidate", {}).get("sourceRef"),
        },
        "selectedRc": {
            "freezeDigest": selected.freeze.get("contentDigest"),
            "freezeFileDigest": selected.freeze_file_digest,
            "archiveDigest": selected.archive_digest,
            "productDistributionDigest": selected.product_digest,
            "checksumsDigest": selected.checksums_digest,
            "provenanceDigest": selected.provenance_digest,
            "lineageDigest": lineage_digest,
        },
        "ga": {
            "postFreezeValidationDigest": rc_validation_digest,
            "validationAuthorizationIdentityDigest": validation_identity_digest,
            "validationFileDigest": ga_validation_digest,
            "authorizationDigest": authorization_digest,
            "promotionIdentityDigest": promotion_identity_digest,
        },
        "payloadIdentity": {
            "rcProductDigest": selected.product_digest,
            "gaProductDigest": selected.product_digest,
            "bitIdentical": True,
            "rebuildPerformed": False,
        },
        "catalogIdentity": {
            "catalogId": catalog.get("catalogId"),
            "revision": catalog.get("revision"),
            "catalogDigest": catalog.get("catalogDigest"),
            "signatureDigest": catalog.get("signatureDigest"),
        },
        "publicationSemantics": {
            "validationSideEffectFree": True,
            "tagOrReleaseCreated": False,
            "catalogOrNetworkInsertPerformed": False,
            "authorizationDigestTarget": "validationAuthorizationIdentityDigest",
            "publicationTargetsDigest": semantic_digest(
                canonical_publication_targets(context)
            ),
            "publicationReceiptDigestTarget": "promotionIdentityDigest",
        },
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }


def run(context: RunContext) -> tuple[int, Path, Path]:
    """Validate and prepare exact Stable GA promotion material without side effects."""

    out = reset_confined_directory(
        context.component_dir / "artifacts" / "legacy",
        context.run_root,
        "Stable GA native output",
    )
    summary_path = out / SUMMARY_FILE
    report_path = out / REPORT_FILE
    state = ValidationState()
    try:
        code = _run(context, out, state)
    except Exception:  # noqa: BLE001 - release validation must fail closed
        state.block(
            "stable-1.0-ga.execution-input",
            "stable-1.0-ga.execution-input",
            "Stable GA could not authenticate a required protected input or artifact.",
            "Correct the protected candidate-bound input and rerun Stable GA from the beginning.",
        )
        out = reset_confined_directory(
            context.component_dir / "artifacts" / "legacy",
            context.run_root,
            "Stable GA failed native output",
        )
        _write_fail_closed(context, out, state)
        code = 1
    return code, summary_path, report_path


def _run(context: RunContext, out: Path, state: ValidationState) -> int:
    now = _utc_now()
    command_mode = context.manifest.commands.get("stable-ga", {}).get(
        "mode", "validate-only"
    )
    prepare_authorization = command_mode == "prepare-authorization"
    selected = authenticate_selected_rc(context, state)
    lineage_path, lineage = load_json_input(context, "selectedStableRcLineage") or (None, {})
    validation_path, rc_validation = load_json_input(context, "stableRcValidation") or (None, {})
    policy_path, policy = load_json_input(context, "stableGaPolicy") or (None, {})
    authorization_input = load_json_input(
        context,
        "stableGaAuthorization",
        required=not prepare_authorization,
    )
    authorization_path, authorization = (
        authorization_input if authorization_input is not None else (None, None)
    )
    if any(path is None for path in (lineage_path, validation_path, policy_path)):
        raise ValueError("Stable GA protected JSON input set is incomplete")
    assert lineage_path and validation_path and policy_path
    _block_errors(
        state,
        "stable-1.0-ga.policy",
        _canonical_policy(context, policy, policy_path),
        "Use the exact checked-in Stable GA policy for this candidate.",
    )
    targets, target_errors = _catalog_targets(context)
    if not _safe_https(context.manifest.policies.get("artifactBaseUri")):
        target_errors.append("public release artifact base is not a public HTTPS URI")
    _block_errors(
        state,
        "stable-1.0-ga.publication-targets",
        target_errors,
        "Provide public, credential-free HTTPS release and catalog verification targets.",
    )
    validate_lineage(context, selected, lineage, state)
    upgrade_predecessor = authenticate_upgrade_predecessor(context, selected, state)
    carried_waivers = validate_carried_waivers(selected, policy, now, state)
    validate_post_freeze(
        context,
        selected,
        lineage,
        rc_validation,
        upgrade_predecessor,
        policy,
        file_digest(policy_path),
        now,
        state,
    )
    lineage_digest = file_digest(lineage_path)
    rc_validation_digest = file_digest(validation_path)
    validation_identity = ga_validation_authorization_identity(
        context,
        selected,
        lineage_digest,
        rc_validation,
        rc_validation_digest,
        upgrade_predecessor,
        carried_waivers,
    )
    validation_identity_digest = semantic_digest(validation_identity)
    write_json(out / VALIDATION_IDENTITY_FILE, validation_identity)
    authorization_valid = False
    if authorization is not None:
        before_authorization = len(state.blockers)
        validate_authorization(
            context,
            selected,
            validation_identity,
            authorization,
            policy,
            now,
            state,
        )
        authorization_valid = len(state.blockers) == before_authorization
        assert authorization_path is not None
        authorization_summary = authorization if authorization_valid else {
            "schemaVersion": 1,
            "kind": "stable-1.0-ga-authorization-summary",
            "generatedAt": rc_validation.get("generatedAt"),
            "releaseId": context.manifest.release.release_id,
            "buildVersion": context.manifest.release.version,
            "status": "invalid",
            "validationAuthorizationIdentityDigest": validation_identity_digest,
            "allowedPublicationScope": [],
            "redaction": {"status": "pass", "findingCount": 0, "findings": []},
        }
    else:
        authorization_summary = {
            "schemaVersion": 1,
            "kind": "stable-1.0-ga-authorization-summary",
            "generatedAt": rc_validation.get("generatedAt"),
            "releaseId": context.manifest.release.release_id,
            "buildVersion": context.manifest.release.version,
            "status": "missing",
            "validationAuthorizationIdentityDigest": validation_identity_digest,
            "allowedPublicationScope": [],
            "redaction": {"status": "pass", "findingCount": 0, "findings": []},
        }
    write_json(out / AUTHORIZATION_FILE, authorization_summary)
    authorization_digest = (
        file_digest(authorization_path)
        if authorization_path is not None
        else file_digest(out / AUTHORIZATION_FILE)
    )
    ga_validation = build_ga_validation_record(
        context,
        selected,
        lineage_digest,
        rc_validation,
        rc_validation_digest,
        upgrade_predecessor,
        authorization,
        authorization_digest,
        authorization_valid,
        carried_waivers,
        state,
    )
    schema_errors = validate_schema(ga_validation, GA_VALIDATION_SCHEMA)
    _block_errors(
        state,
        "stable-1.0-ga.validation-schema",
        schema_errors,
        "Regenerate the complete Stable GA validation record.",
    )
    if schema_errors:
        ga_validation = build_ga_validation_record(
            context,
            selected,
            lineage_digest,
            rc_validation,
            rc_validation_digest,
            upgrade_predecessor,
            authorization,
            authorization_digest,
            authorization_valid,
            carried_waivers,
            state,
        )
    write_json(out / VALIDATION_FILE, ga_validation)
    ga_validation_digest = file_digest(out / VALIDATION_FILE)

    copied_archive = out / selected.archive_path.name
    copied_product = out / selected.product_path.name

    generated_at = _timestamp(rc_validation.get("generatedAt"))
    known = _known_limitations(context, selected)
    write_json(out / KNOWN_LIMITATIONS_FILE, known)
    promotion_identity = _promotion_identity(
        context,
        selected,
        lineage_digest,
        validation_identity_digest,
    )
    promotion_identity_digest = semantic_digest(promotion_identity)
    baseline = _maintenance_baseline(
        context,
        selected,
        rc_validation,
        policy,
        promotion_identity_digest,
        generated_at,
    )
    baseline_errors = validate_schema(baseline, MAINTENANCE_BASELINE_SCHEMA)
    _block_errors(
        state,
        "stable-1.0-ga.maintenance-baseline",
        baseline_errors,
        "Regenerate the maintenance baseline from the exact authenticated freeze.",
    )
    write_json(out / MAINTENANCE_BASELINE_FILE, baseline)

    # Baseline construction is itself a release gate. Re-emit validation after every
    # pre-publication semantic gate so its status and blocker set cannot lag the final decision.
    ga_validation = build_ga_validation_record(
        context,
        selected,
        lineage_digest,
        rc_validation,
        rc_validation_digest,
        upgrade_predecessor,
        authorization,
        authorization_digest,
        authorization_valid,
        carried_waivers,
        state,
    )
    write_json(out / VALIDATION_FILE, ga_validation)
    ga_validation_digest = file_digest(out / VALIDATION_FILE)

    preview = {
        "publicationState": (
            "publication-authorized"
            if not state.blockers and authorization_valid
            else "validated"
        )
    }
    release_notes = render_release_notes(selected.freeze, rc_validation, preview)
    write_text(out / RELEASE_NOTES_FILE, release_notes)
    release_notes_digest = file_digest(out / RELEASE_NOTES_FILE)
    provenance = _provenance(
        context,
        selected,
        lineage_digest,
        rc_validation_digest,
        validation_identity_digest,
        ga_validation_digest,
        authorization_digest,
        promotion_identity_digest,
        generated_at,
    )
    write_json(out / PROVENANCE_FILE, provenance)

    redaction = build_redaction_report(
        (
            (VALIDATION_FILE, ga_validation),
            (VALIDATION_IDENTITY_FILE, validation_identity),
            (AUTHORIZATION_FILE, authorization_summary),
            (KNOWN_LIMITATIONS_FILE, known),
            (MAINTENANCE_BASELINE_FILE, baseline),
            (RELEASE_NOTES_FILE, release_notes),
            (PROVENANCE_FILE, provenance),
        )
    )
    if redaction.get("status") != "pass":
        state.block(
            "stable-1.0-ga.redaction",
            "stable-1.0-ga.redaction",
            "Generated Stable GA material failed redaction validation.",
            "Remove unsafe source metadata and restart exact-RC validation.",
        )
    write_json(out / REDACTION_REPORT_FILE, redaction)

    public_checksum_members = [
        selected.archive_path,
        selected.product_path,
        out / RELEASE_NOTES_FILE,
        out / KNOWN_LIMITATIONS_FILE,
        out / PROVENANCE_FILE,
        out / MAINTENANCE_BASELINE_FILE,
    ]
    _write_checksums(out / CHECKSUMS_FILE, public_checksum_members)
    asset_paths = [*public_checksum_members, out / CHECKSUMS_FILE]
    assets = [
        {
            "name": path.name,
            "sizeBytes": path.stat().st_size,
            "digest": file_digest(path),
            "role": role,
            "sourceKind": "immutable-rc" if role.startswith("rc-") else "ga-metadata",
        }
        for role, path in zip(PUBLIC_ASSET_ROLES, asset_paths, strict=True)
    ]
    plan = _publication_plan(
        context,
        selected,
        targets,
        promotion_identity_digest,
        release_notes_digest,
        generated_at,
        assets,
        (
            "publication-authorized"
            if not state.blockers and authorization_valid
            else "validated"
        ),
    )
    plan_errors = validate_schema(plan, PUBLICATION_PLAN_SCHEMA)
    _block_errors(
        state,
        "stable-1.0-ga.publication-plan",
        plan_errors,
        "Regenerate the closed publication plan from the authenticated candidate.",
    )
    write_json(out / PUBLICATION_PLAN_FILE, plan)

    receipt: dict[str, Any] | None = None
    receipt_input = load_json_input(
        context, "stableGaPublicationReceipt", required=False
    )
    publication_state = (
        "publication-authorized"
        if not state.blockers and authorization_valid
        else "validated"
    )
    if receipt_input is not None:
        _receipt_path, receipt = receipt_input
        receipt_errors = (
            publication_receipt_errors(
                receipt,
                context,
                selected,
                lineage,
                promotion_identity_digest,
                release_notes_digest,
                assets,
            )
            if authorization_valid and not state.blockers
            else [
                "publication receipt cannot complete an unauthorized or failed GA validation"
            ]
        )
        if receipt_errors:
            publication_state = "publication-verification-failed"
            _block_errors(
                state,
                "stable-1.0-ga.publication-receipt",
                receipt_errors,
                "Recover or correct public state without changing the authorized bytes.",
            )
            # Keep schema-invalid, conflicting, or partial external state out of the
            # canonical public receipt slot. The fail-closed promotion record retains
            # safe blocker categories without re-publishing an untrusted receipt.
            receipt = None
        else:
            publication_state = "publication-complete"
            write_json(out / PUBLICATION_RECEIPT_FILE, receipt)

    promotion = _promotion_record(
        context,
        selected,
        lineage_digest,
        ga_validation_digest,
        authorization_digest,
        carried_waivers,
        known,
        release_notes_digest,
        file_digest(out / MAINTENANCE_BASELINE_FILE),
        assets,
        publication_state,
        authorization_valid,
        state,
        generated_at,
    )
    promotion_errors = validate_schema(promotion, "stable-1.0-ga-promotion-v1.schema.json")
    _block_errors(
        state,
        "stable-1.0-ga.promotion-schema",
        promotion_errors,
        "Regenerate the complete Stable GA promotion record.",
    )
    if promotion_errors:
        promotion = _promotion_record(
            context,
            selected,
            lineage_digest,
            ga_validation_digest,
            authorization_digest,
            carried_waivers,
            known,
            release_notes_digest,
            file_digest(out / MAINTENANCE_BASELINE_FILE),
            assets,
            publication_state,
            authorization_valid,
            state,
            generated_at,
        )
    report = render_go_no_go(promotion)
    final_redaction_items: list[tuple[str, Any]] = [
        (VALIDATION_FILE, ga_validation),
        (VALIDATION_IDENTITY_FILE, validation_identity),
        (AUTHORIZATION_FILE, authorization_summary),
        (KNOWN_LIMITATIONS_FILE, known),
        (MAINTENANCE_BASELINE_FILE, baseline),
        (RELEASE_NOTES_FILE, release_notes),
        (PROVENANCE_FILE, provenance),
        (PUBLICATION_PLAN_FILE, plan),
        (SUMMARY_FILE, promotion),
        (REPORT_FILE, report),
        (CHECKSUMS_FILE, (out / CHECKSUMS_FILE).read_text(encoding="utf-8")),
    ]
    if receipt is not None:
        final_redaction_items.append((PUBLICATION_RECEIPT_FILE, receipt))
    final_redaction = build_redaction_report(tuple(final_redaction_items))
    if final_redaction.get("status") != "pass":
        categories = sorted(
            {
                f"{row.get('artifact', 'unknown')}:{row.get('category', 'redaction')}"
                for row in final_redaction.get("findings", [])
                if isinstance(row, dict)
            }
        )
        raise ValueError(
            "final Stable GA public bundle failed redaction validation: "
            + ", ".join(categories)
        )
    # A passing report is content-independent by design. Rewriting it here proves
    # that the checksum-bound report also represents the complete, late-generated
    # public bundle without introducing a checksum/publication-plan cycle.
    if not state.blockers:
        _copy_exact(selected.archive_path, copied_archive, selected.archive_digest)
        _copy_exact(selected.product_path, copied_product, selected.product_digest)
    write_json(out / REDACTION_REPORT_FILE, final_redaction)
    write_json(out / SUMMARY_FILE, promotion)
    write_text(out / REPORT_FILE, report)
    if prepare_authorization and promotion.get("status") == "pass":
        return 0
    return 0 if promotion.get("promotionReady") is True else 1


def _write_fail_closed(
    context: RunContext,
    out: Path,
    state: ValidationState,
) -> None:
    generated_at = _utc_now().isoformat().replace("+00:00", "Z")
    redaction = {
        "schemaVersion": 1,
        "status": "fail",
        "findingCount": 1,
        "findings": [
            {
                "category": "protected-input",
                "summary": "Unsafe or malformed protected input was rejected.",
            }
        ],
        "guarantees": {"unsafeInputExcluded": True},
    }
    summary = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "stable-1.0-ga-promotion",
        "tool": TOOL_NAME,
        "toolVersion": TOOL_VERSION,
        "generatedAt": generated_at,
        "releaseId": context.manifest.release.release_id,
        "buildVersion": context.manifest.release.version,
        "stableMilestone": STABLE_MILESTONE,
        "status": "fail",
        "promotionReady": False,
        "nonRelease": True,
        "decision": "no-go",
        "publicationState": "validated",
        "blockers": state.blockers,
        "warnings": [],
        "acceptedRcWaivers": [],
        "redaction": redaction,
        "artifacts": {
            "goNoGo": REPORT_FILE,
            "redactionReport": REDACTION_REPORT_FILE,
        },
    }
    write_json(out / SUMMARY_FILE, summary)
    write_text(out / REPORT_FILE, render_go_no_go(summary))
    write_json(out / REDACTION_REPORT_FILE, redaction)

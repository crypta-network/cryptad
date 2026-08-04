"""Canonical side-effect-free Stable 1.0 support lifecycle certification."""

from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

from cryptad_certification.io import read_json, write_text
from cryptad_certification.models import RunContext
from cryptad_certification.redaction import scan_value
from cryptad_certification.schema_validation import validate_schema
from cryptad_certification.stable_vulnerability_summary import load_summary
from cryptad_certification.workspace import reset_confined_directory

from .stable_1_0_lifecycle_core import (
    DIGEST_RE,
    EVIDENCE_IDS,
    STABLE_MILESTONE,
    authenticate_inventory,
    build_descriptor,
    build_ledger,
    canonical_file_digest,
    canonical_timestamp,
    governance_projection,
    policy_errors,
)
from .stable_1_0_maintenance_core import (
    ValidationState,
    authenticate_ga_root,
    authenticate_predecessor,
    file_digest,
    load_json_input,
)
from .stable_1_0_rc_core import parse_timestamp, semantic_digest
from .stable_1_0_ga_core import (
    _has_unambiguous_publication_path,
    canonical_public_https_uri,
    is_public_https_uri,
)

TOOL_NAME = "stable-1.0-support-lifecycle"
POLICY_FILE = "stable-1.0-support-lifecycle-policy.json"
GENESIS_PROOF_FILE = "stable-1.0-support-lifecycle-genesis-proof.json"
INVENTORY_FILE = "stable-1.0-support-lifecycle-inventory.json"
LEDGER_FILE = "stable-1.0-support-lifecycle-ledger.json"
TRANSITION_FILE = "stable-1.0-support-lifecycle-transition-set.json"
DESCRIPTOR_FILE = "stable-1.0-support-lifecycle-descriptor.json"
AUTHORIZATION_FILE = "stable-1.0-support-lifecycle-authorization-summary.json"
PLAN_FILE = "stable-1.0-support-lifecycle-publication-plan.json"
RECEIPT_FILE = "stable-1.0-support-lifecycle-publication-receipt.json"
LATEST_FILE = "stable-1.0-support-lifecycle-latest.json"
SUMMARY_FILE = "stable-1.0-support-lifecycle-summary.json"
REPORT_FILE = "stable-1.0-support-lifecycle-report.md"
CHECKSUMS_FILE = "stable-1.0-support-lifecycle-checksums.txt"
PROVENANCE_FILE = "stable-1.0-support-lifecycle-provenance.json"
API_GOVERNANCE_FILE = "stable-1.0-platform-api-deprecation-governance.json"
ECOSYSTEM_GOVERNANCE_FILE = "stable-1.0-catalog-app-profile-lifecycle-governance.json"
REDACTION_FILE = "redaction-report.json"

SCHEMAS = {
    POLICY_FILE: "stable-1.0-support-lifecycle-policy-v1.schema.json",
    GENESIS_PROOF_FILE: "stable-1.0-support-lifecycle-genesis-proof-v1.schema.json",
    INVENTORY_FILE: "stable-1.0-support-lifecycle-inventory-v1.schema.json",
    LEDGER_FILE: "stable-1.0-support-lifecycle-ledger-v1.schema.json",
    TRANSITION_FILE: "stable-1.0-support-lifecycle-transition-set-v1.schema.json",
    DESCRIPTOR_FILE: "stable-1.0-support-lifecycle-descriptor-v1.schema.json",
    AUTHORIZATION_FILE: "stable-1.0-support-lifecycle-authorization-v1.schema.json",
    PLAN_FILE: "stable-1.0-support-lifecycle-publication-plan-v1.schema.json",
    RECEIPT_FILE: "stable-1.0-support-lifecycle-publication-receipt-v1.schema.json",
    LATEST_FILE: "stable-1.0-support-lifecycle-latest-v1.schema.json",
    SUMMARY_FILE: "stable-1.0-support-lifecycle-summary-v1.schema.json",
    API_GOVERNANCE_FILE: "stable-1.0-platform-api-deprecation-governance-v1.schema.json",
    ECOSYSTEM_GOVERNANCE_FILE: "stable-1.0-catalog-app-profile-lifecycle-governance-v1.schema.json",
    PROVENANCE_FILE: "stable-1.0-support-lifecycle-provenance-v1.schema.json",
    REDACTION_FILE: "stable-1.0-support-lifecycle-redaction-v1.schema.json",
}


def _block(state: ValidationState, evidence_id: str, summary: str, remediation: str) -> None:
    state.block(evidence_id, evidence_id, summary.rstrip(".") + ".", remediation)


def _schema_block(
    state: ValidationState, evidence_id: str, value: dict[str, Any], schema: str
) -> None:
    for error in validate_schema(value, schema):
        _block(state, evidence_id, error, "Correct the closed lifecycle artifact and retry.")


def _configured_json(context: RunContext, key: str, required: bool = False) -> dict[str, Any] | None:
    loaded = load_json_input(context, key, required=required, public_authorization=True)
    return loaded.value if loaded is not None else None


def _generated_at(request: dict[str, Any] | None, metadata: dict[str, Any]) -> str:
    if request is not None:
        value = canonical_timestamp(request.get("generatedAt"))
        if value is not None:
            return value
    value = canonical_timestamp(metadata.get("lifecycleEvaluationAt"))
    if value is None:
        raise ValueError("stable lifecycle requires canonical policies.metadata.lifecycleEvaluationAt")
    return value


def _history_governance_errors(history: dict[str, Any], ga_baseline: dict[str, Any]) -> list[str]:
    """Detect deprecation clock reset across every authenticated successor snapshot."""

    errors: list[str] = []
    previous_platform = ga_baseline.get("platformApi")
    previous_platform = previous_platform if isinstance(previous_platform, dict) else {}
    previous_rows = previous_platform.get("deprecationHistory")
    previous_rows = previous_rows if isinstance(previous_rows, list) else []
    previous = {
        (row.get("kind"), row.get("identity")): row
        for row in previous_rows
        if isinstance(row, dict)
    }
    previous_apps = ga_baseline.get("firstPartyApps")
    previous_apps = previous_apps if isinstance(previous_apps, list) else []
    previous_profiles = ga_baseline.get("contentFormatProfiles")
    previous_profiles = previous_profiles if isinstance(previous_profiles, list) else []
    previous_catalog = ga_baseline.get("stableCatalog")
    previous_catalog = previous_catalog if isinstance(previous_catalog, dict) else {}
    ga_security = ga_baseline.get("securityBaseline")
    ga_security = ga_security if isinstance(ga_security, dict) else {}
    ga_security_digest = semantic_digest(ga_security)
    previous_security: dict[str, Any] = ga_security
    initial_follow_up = ga_baseline.get("hotfixFollowUp")
    previous_follow_up = initial_follow_up if isinstance(initial_follow_up, dict) else None
    support_order = {"local-rc": 0, "maintained": 1, "core": 2}
    for link in history.get("links", []):
        if not isinstance(link, dict):
            continue
        baseline = link.get("successorBaseline")
        baseline = baseline if isinstance(baseline, dict) else {}
        platform = baseline.get("platformApi")
        platform = platform if isinstance(platform, dict) else {}
        rows = platform.get("deprecationHistory")
        rows = rows if isinstance(rows, list) else []
        current = {
            (row.get("kind"), row.get("identity")): row
            for row in rows
            if isinstance(row, dict)
        }
        for field in (
            "baselineName",
            "baselineDigest",
            "baselineContractVersion",
            "stableSurfaceDigest",
            "compatibilityWindowPolicyDigest",
        ):
            if platform.get(field) != previous_platform.get(field):
                errors.append(f"Platform API stable {field} changed across maintenance history")
        for identity, old in previous.items():
            new = current.get(identity)
            if new is None:
                errors.append("published Platform API deprecation history entry was removed")
                continue
            if new.get("deprecatedSinceContractVersion") != old.get(
                "deprecatedSinceContractVersion"
            ):
                errors.append("Platform API original deprecation clock was changed")
            if new.get("removalContractVersion") != old.get("removalContractVersion"):
                errors.append("Platform API scheduled-removal clock was changed")
        previous = current
        current_apps = baseline.get("firstPartyApps")
        current_apps = current_apps if isinstance(current_apps, list) else []
        old_apps = {row.get("appId"): row for row in previous_apps if isinstance(row, dict)}
        new_apps = {row.get("appId"): row for row in current_apps if isinstance(row, dict)}
        if len(new_apps) != len(current_apps):
            errors.append("stable first-party app metadata contains a duplicate identity")
        if not set(old_apps).issubset(new_apps):
            errors.append("stable first-party app identity was removed or renamed")
        for app_id, old in old_apps.items():
            new = new_apps.get(app_id, {})
            if support_order.get(str(new.get("supportLevel")), -1) < support_order.get(
                str(old.get("supportLevel")), -1
            ):
                errors.append("stable first-party app support level regressed")
            if new.get("channel") != "stable":
                errors.append("stable first-party app left the stable catalog channel")
        current_profiles = baseline.get("contentFormatProfiles")
        current_profiles = current_profiles if isinstance(current_profiles, list) else []
        old_profiles = {
            row.get("profileId"): row for row in previous_profiles if isinstance(row, dict)
        }
        new_profiles = {
            row.get("profileId"): row for row in current_profiles if isinstance(row, dict)
        }
        if len(new_profiles) != len(current_profiles):
            errors.append("stable content-profile metadata contains a duplicate identity")
        if not set(old_profiles).issubset(new_profiles):
            errors.append("a stable content-profile identity was removed or renamed")
        for profile_id, old in old_profiles.items():
            new = new_profiles.get(profile_id, {})
            for field in (
                "version",
                "canonicalizationRulesDigest",
                "maximumSizePolicyDigest",
                "signaturePayloadRulesDigest",
            ):
                if new.get(field) != old.get(field):
                    errors.append(f"stable content profile {profile_id} changed {field} in place")
        catalog = baseline.get("stableCatalog")
        catalog = catalog if isinstance(catalog, dict) else {}
        if (
            catalog.get("catalogId") != previous_catalog.get("catalogId")
            or catalog.get("channel") != "stable"
        ):
            errors.append("stable catalog identity or channel regressed")
        security = baseline.get("security")
        security = security if isinstance(security, dict) else {}
        if (
            security.get("gaBaselineDigest") != ga_security_digest
            or security.get("predecessorDigest") != semantic_digest(previous_security)
            or not DIGEST_RE.fullmatch(str(security.get("currentDigest", "")))
        ):
            errors.append(
                "catalog advisory, exact-version denylist, or signing/reviewer revocation "
                "security-state digest continuity was broken"
            )
        follow_up = baseline.get("hotfixFollowUp")
        follow_up = follow_up if isinstance(follow_up, dict) else None
        if previous_follow_up and previous_follow_up.get("status") in {"open", "overdue"}:
            if follow_up is None or follow_up.get("status") not in {"open", "overdue", "closed"}:
                errors.append("unresolved hotfix follow-up obligation disappeared")
            elif follow_up.get("obligationDigest") != previous_follow_up.get("obligationDigest"):
                errors.append("hotfix follow-up obligation identity was replaced")
            elif (
                follow_up.get("status") == "closed"
                and not follow_up.get("closureEvidenceDigest")
            ):
                errors.append("hotfix follow-up obligation was cleared without closure evidence")
        previous_platform = platform
        previous_apps = current_apps
        previous_profiles = current_profiles
        previous_catalog = catalog
        previous_security = security
        previous_follow_up = follow_up
    return sorted(set(errors))


def _descriptor_freshness_errors(
    descriptor: dict[str, Any], now: dt.datetime
) -> list[str]:
    """Reject a descriptor that is future-dated or stale when it is certified."""

    generated = parse_timestamp(descriptor.get("generatedAt"))
    effective = parse_timestamp(descriptor.get("effectiveAt"))
    stale = parse_timestamp(descriptor.get("staleAt"))
    if generated is None or effective is None or stale is None:
        return ["lifecycle descriptor freshness timestamps are malformed"]
    if generated > now or effective > now:
        return ["lifecycle descriptor is future-dated at certification time"]
    if stale <= now:
        return ["lifecycle descriptor is already stale at certification time"]
    return []


def _validate_authorization(
    authorization: dict[str, Any] | None,
    policy: dict[str, Any],
    descriptor: dict[str, Any],
    ledger: dict[str, Any],
    transition_set: dict[str, Any],
    public_uri: str,
    latest_pointer_public_uri: str | None,
    latest_pointer_digest: str | None,
    now: dt.datetime,
    *,
    valid_at: dt.datetime | None = None,
) -> tuple[dict[str, Any], bool, list[str]]:
    expected_role = (
        "stable-lifecycle-security-manager"
        if any(row.get("toStatus") == "revoked" for row in transition_set["transitions"])
        else "stable-lifecycle-release-manager"
    )
    transition_request_digest = transition_set["transitionRequestDigest"]
    request_digest = semantic_digest(
        {
            "operation": "publish-support-lifecycle",
            "ledgerDigest": ledger["ledgerDigest"],
            "descriptorDigest": descriptor["descriptorDigest"],
            "descriptorEdition": descriptor["descriptorEdition"],
            "publicRequestUri": public_uri,
            "latestMaintenancePointerPublicUri": latest_pointer_public_uri,
            "latestMaintenancePointerDigest": latest_pointer_digest,
            "transitionRequestDigest": transition_request_digest,
            "previousLedgerDigest": ledger["previousLedgerDigest"],
            "previousDescriptorDigest": descriptor["previousDescriptorDigest"],
            "requiredRole": expected_role,
        }
    )
    prepared = {
        "schemaVersion": 1,
        "kind": "stable-1.0-support-lifecycle-authorization",
        "authorizationId": "pending-protected-approval",
        "generatedAt": descriptor["generatedAt"],
        "expiresAt": descriptor["generatedAt"],
        "role": expected_role,
        "operation": "publish-support-lifecycle",
        "stableMilestone": STABLE_MILESTONE,
        "targetLedgerDigest": ledger["ledgerDigest"],
        "targetDescriptorDigest": descriptor["descriptorDigest"],
        "targetDescriptorEdition": descriptor["descriptorEdition"],
        "targetPublicRequestUri": public_uri,
        "targetLatestMaintenancePointerPublicUri": latest_pointer_public_uri,
        "targetLatestMaintenancePointerDigest": latest_pointer_digest,
        "transitionRequestDigest": transition_request_digest,
        "previousLedgerDigest": ledger["previousLedgerDigest"],
        "previousDescriptorDigest": descriptor["previousDescriptorDigest"],
        "authorizationRequestDigest": request_digest,
        "decision": "pending",
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }
    if authorization is None:
        return prepared, False, []
    errors = validate_schema(
        authorization, "stable-1.0-support-lifecycle-authorization-v1.schema.json"
    )
    fields = {
        "role": expected_role,
        "operation": "publish-support-lifecycle",
        "stableMilestone": STABLE_MILESTONE,
        "targetLedgerDigest": ledger["ledgerDigest"],
        "targetDescriptorDigest": descriptor["descriptorDigest"],
        "targetDescriptorEdition": descriptor["descriptorEdition"],
        "targetPublicRequestUri": public_uri,
        "targetLatestMaintenancePointerPublicUri": latest_pointer_public_uri,
        "targetLatestMaintenancePointerDigest": latest_pointer_digest,
        "transitionRequestDigest": transition_request_digest,
        "previousLedgerDigest": ledger["previousLedgerDigest"],
        "previousDescriptorDigest": descriptor["previousDescriptorDigest"],
        "authorizationRequestDigest": request_digest,
        "decision": "approved",
    }
    if any(authorization.get(key) != value for key, value in fields.items()):
        errors.append("lifecycle authorization target, role, transition, or digest is mismatched")
    generated = parse_timestamp(authorization.get("generatedAt"))
    expires = parse_timestamp(authorization.get("expiresAt"))
    max_hours = policy["authorization"]["maximumValidityHours"]
    authorization_time = valid_at if valid_at is not None else now
    if (
        generated is None
        or expires is None
        or authorization_time > now
        or generated > authorization_time
        or expires <= authorization_time
        or expires <= generated
        or expires - generated > dt.timedelta(hours=max_hours)
    ):
        errors.append("lifecycle authorization is future-dated, expired, or overlong")
    return authorization, not errors, errors


def _publication_plan(
    descriptor: dict[str, Any],
    ledger: dict[str, Any],
    authorization: dict[str, Any],
    authorization_valid: bool,
    public_uri: str,
    latest_pointer_public_uri: str | None,
    latest_pointer_digest: str | None,
    transition_set_digest: str,
) -> dict[str, Any]:
    approval_digest = canonical_file_digest(authorization) if authorization_valid else None
    value = {
        "schemaVersion": 1,
        "kind": "stable-1.0-support-lifecycle-publication-plan",
        "generatedAt": descriptor["generatedAt"],
        "stableMilestone": STABLE_MILESTONE,
        "operation": "insert-or-verify-support-lifecycle",
        "descriptorEdition": descriptor["descriptorEdition"],
        "descriptorDigest": descriptor["descriptorDigest"],
        "descriptorSizeBytes": len(
            (json_dumps(descriptor) + "\n").encode("utf-8")
        ),
        "ledgerDigest": ledger["ledgerDigest"],
        "transitionSetDigest": transition_set_digest,
        "updateKeyIdentityDigest": descriptor["updateKeyIdentityDigest"],
        "updateKeyScope": descriptor["updateKeyScope"],
        "updateKeyDocName": descriptor["updateKeyDocName"],
        "publicRequestUri": public_uri,
        "latestMaintenancePointerPublicUri": latest_pointer_public_uri,
        "latestMaintenancePointerDigest": latest_pointer_digest,
        "previousDescriptorEdition": descriptor["previousDescriptorEdition"],
        "previousDescriptorDigest": descriptor["previousDescriptorDigest"],
        "authorizationDigest": approval_digest,
        "publicationAuthorized": authorization_valid,
        "conflictPolicy": "verify-identical-or-fail-never-overwrite",
        "sideEffectsPerformed": False,
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }
    value["publicationPlanDigest"] = semantic_digest(value)
    return value


def json_dumps(value: Any) -> str:
    """Serialize exactly as lifecycle JSON artifacts are written, without the final newline."""

    import json

    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)


def _write_canonical_json(path: Path, value: Any) -> None:
    """Write the exact UTF-8 JSON representation used for lifecycle byte identities."""

    write_text(path, json_dumps(value))


def _verify_receipt(
    receipt: dict[str, Any] | None,
    descriptor: dict[str, Any],
    plan: dict[str, Any],
    authorization: dict[str, Any],
    verification_time: dt.datetime,
) -> tuple[bool, list[str]]:
    if receipt is None:
        return False, []
    errors = validate_schema(
        receipt, "stable-1.0-support-lifecycle-publication-receipt-v1.schema.json"
    )
    descriptor_bytes_digest = canonical_file_digest(descriptor)
    approval_digest = canonical_file_digest(authorization)
    expected = {
        "stableMilestone": STABLE_MILESTONE,
        "descriptorEdition": descriptor["descriptorEdition"],
        "descriptorDigest": descriptor["descriptorDigest"],
        "descriptorBytesDigest": descriptor_bytes_digest,
        "ledgerDigest": descriptor["ledgerDigest"],
        "updateKeyIdentityDigest": descriptor["updateKeyIdentityDigest"],
        "updateKeyScope": descriptor["updateKeyScope"],
        "updateKeyDocName": descriptor["updateKeyDocName"],
        "publicRequestUri": plan["publicRequestUri"],
        "previousDescriptorEdition": descriptor["previousDescriptorEdition"],
        "previousDescriptorDigest": descriptor["previousDescriptorDigest"],
        "publicationPlanDigest": plan["publicationPlanDigest"],
        "authorizationDigest": approval_digest,
        "publicationState": "publication-complete",
        "verificationStatus": "verified",
    }
    if any(receipt.get(key) != value for key, value in expected.items()):
        errors.append("public lifecycle receipt does not bind the exact authorized descriptor bytes")
    if receipt.get("operation") not in {"inserted", "verified-existing"}:
        errors.append("lifecycle publication is neither an exact insert nor idempotent verification")
    if receipt.get("conflict") is not False:
        errors.append("lifecycle publication receipt reports a public-state conflict")
    receipt_generated = parse_timestamp(receipt.get("generatedAt"))
    authorization_generated = parse_timestamp(authorization.get("generatedAt"))
    authorization_expires = parse_timestamp(authorization.get("expiresAt"))
    if (
        receipt_generated is None
        or authorization_generated is None
        or authorization_expires is None
        or receipt_generated > verification_time
        or receipt_generated < authorization_generated
        or receipt_generated >= authorization_expires
    ):
        errors.append(
            "lifecycle publication receipt timestamp is outside the authorization interval"
        )
    return not errors, errors


def _lifecycle_history_input_errors(
    previous_ledger: dict[str, Any] | None,
    previous_descriptor: dict[str, Any] | None,
    genesis_proof: dict[str, Any] | None,
) -> list[str]:
    """Require either an observed first-publication proof or the exact prior pair."""

    if (previous_ledger is None) != (previous_descriptor is None):
        return ["previous ledger and descriptor must be supplied together"]
    if previous_ledger is None and genesis_proof is None:
        return ["lifecycle descriptor genesis requires a fresh protected absence proof"]
    if previous_ledger is not None and genesis_proof is not None:
        return ["lifecycle descriptor successors must not reuse a genesis absence proof"]
    return []


def _genesis_proof_errors(
    proof: dict[str, Any],
    inventory: dict[str, Any],
    policy: dict[str, Any],
    public_uri: str | None,
    actual_now: dt.datetime,
) -> list[str]:
    """Bind a short-lived protected 404 observation to the exact release inventory."""

    errors = validate_schema(
        proof, "stable-1.0-support-lifecycle-genesis-proof-v1.schema.json"
    )
    expected_digest = semantic_digest(
        {key: value for key, value in proof.items() if key != "proofDigest"}
    )
    if proof.get("proofDigest") != expected_digest:
        errors.append("lifecycle genesis proof digest is invalid")
    entries = inventory.get("entries")
    tip = entries[-1] if isinstance(entries, list) and entries else {}
    update_key_digest = policy["descriptor"]["updateKeyIdentityDigest"]
    bindings = {
        "generatedAt": inventory.get("generatedAt"),
        "stableMilestone": STABLE_MILESTONE,
        "observationStatus": "absent",
        "transportStatus": 404,
        "publicRequestUri": public_uri,
        "updateKeyIdentityDigest": update_key_digest,
        "updateKeyScope": f"{update_key_digest}/support-lifecycle/0",
        "updateKeyDocName": "support-lifecycle",
        "inventoryDigest": inventory.get("inventoryDigest"),
        "gaRootDigest": inventory.get("gaRootDigest"),
        "latestPointerDigest": inventory.get("latestPointerDigest"),
        "chainDepth": inventory.get("chainDepth"),
        "releaseId": tip.get("releaseId"),
        "buildVersion": tip.get("buildVersion"),
        "baselineDigest": tip.get("baselineDigest"),
        "publicationReceiptDigest": tip.get("publicationReceiptDigest"),
    }
    if any(proof.get(name) != expected for name, expected in bindings.items()):
        errors.append(
            "lifecycle genesis proof does not bind the exact inventory, target, and update-key scope"
        )
    generated = parse_timestamp(proof.get("generatedAt"))
    observed = parse_timestamp(proof.get("observedAt"))
    maximum_age = dt.timedelta(
        minutes=policy["supportWindows"]["maximumGenesisProofAgeMinutes"]
    )
    if (
        generated is None
        or observed is None
        or generated > observed
        or observed > actual_now
        or actual_now - observed > maximum_age
        or observed - generated > maximum_age
    ):
        errors.append("lifecycle genesis proof is future-dated, stale, or overlong")
    return errors


def _redaction_view(value: Any) -> Any:
    if isinstance(value, dict):
        aliases = {
            "authorization": "publicApproval",
            "authorizationDigest": "publicApprovalDigest",
            "authorizationId": "publicApprovalId",
            "authorizationRequestDigest": "publicApprovalRequestDigest",
        }
        return {aliases.get(str(key), str(key)): _redaction_view(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redaction_view(item) for item in value]
    return value


def _transition_set_digest(value: dict[str, Any]) -> str:
    return semantic_digest(
        {key: item for key, item in value.items() if key != "transitionSetDigest"}
    )


def _checksums(out: Path, names: list[str]) -> None:
    rows = [f"{file_digest(out / name).removeprefix('sha256:')}  {name}" for name in sorted(names)]
    write_text(out / CHECKSUMS_FILE, "\n".join(rows))


def _report(summary: dict[str, Any]) -> str:
    return "\n".join(
        (
            "# Stable 1.0 support lifecycle",
            "",
            f"- Decision: `{summary['decision']}`",
            f"- Mode: `{summary['commandMode']}`",
            (
                f"- Current Stable build: `v{summary['currentStableBuild']}`"
                if summary.get("currentStableBuild") is not None
                else "- Current Stable build: `none (authenticated tip revoked)`"
            ),
            f"- Descriptor edition: `{summary.get('descriptorEdition')}`",
            f"- Publication state: `{summary['publicationState']}`",
            "",
            "This command evaluated authenticated public release history only. It did not insert an update-key edition or mutate release state.",
        )
    )


def _run(context: RunContext, out: Path, state: ValidationState) -> int:
    mode = context.manifest.commands.get("stable-lifecycle", {}).get("mode", "evaluate")
    policy_loaded = load_json_input(context, "stableLifecyclePolicy", required=True)
    assert policy_loaded is not None
    policy = policy_loaded.value
    canonical = context.workspace_root / "tools/release-certification" / POLICY_FILE
    policy_failures = validate_schema(policy, SCHEMAS[POLICY_FILE]) + policy_errors(policy)
    if read_json(canonical) != policy or file_digest(canonical) != policy_loaded.digest:
        policy_failures.append("lifecycle policy is not the exact checked-in policy")
    for error in policy_failures:
        _block(state, EVIDENCE_IDS[2], error, "Use the exact reviewed lifecycle policy.")
    ga = authenticate_ga_root(context, state)
    predecessor = authenticate_predecessor(
        context, ga, state, allow_non_successor_build=True
    )
    history = _configured_json(context, "stableMaintenanceHistory", True)
    assert history is not None
    for error in validate_schema(
        history, "stable-1.0-maintenance-authenticated-history-v1.schema.json"
    ):
        _block(state, EVIDENCE_IDS[1], error, "Provide the complete exact public maintenance chain.")
    request = _configured_json(context, "stableLifecycleTransitionRequest")
    if request is not None:
        for error in validate_schema(
            request, "stable-1.0-support-lifecycle-transition-request-v1.schema.json"
        ):
            _block(state, EVIDENCE_IDS[5], error, "Correct the closed transition request.")
    metadata = context.manifest.policies.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    generated_at = _generated_at(request, metadata)
    actual_now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    evaluation_time = parse_timestamp(generated_at)
    assert evaluation_time is not None
    _vulnerability_summary, vulnerability_errors = load_summary(
        context, evaluation_clock=evaluation_time
    )
    for error in vulnerability_errors:
        _block(
            state,
            EVIDENCE_IDS[3],
            error,
            "Provide the exact canonical, redaction-safe vulnerability governance summary.",
        )
    if (
        evaluation_time > actual_now
        or actual_now - evaluation_time
        > dt.timedelta(days=policy["supportWindows"]["maximumEvidenceAgeDays"])
    ):
        _block(state, EVIDENCE_IDS[2], "lifecycle evaluation timestamp is future-dated or stale", "Use a fresh deterministic protected evaluation timestamp.")
    public_uri = canonical_public_https_uri(
        context.manifest.policies.get("lifecycleDescriptorPublicUri")
    )
    if (
        public_uri != context.manifest.policies.get("lifecycleDescriptorPublicUri")
        or not is_public_https_uri(public_uri)
        or not _has_unambiguous_publication_path(public_uri)
    ):
        _block(state, EVIDENCE_IDS[13], "lifecycle descriptor public URI is not canonical public HTTPS", "Use the exact public observation target without credentials, query, fragment, aliases, or private addresses.")
    ga_receipt = _configured_json(context, "stableGaPublicationReceipt", True)
    predecessor_baseline = _configured_json(context, "predecessorBaseline", True)
    predecessor_receipt = _configured_json(context, "predecessorPublicationReceipt", True)
    latest_pointer = _configured_json(context, "latestPublishedMaintenancePointer")
    assert ga_receipt and predecessor_baseline and predecessor_receipt
    inventory_result = authenticate_inventory(
        ga,
        predecessor,
        ga_receipt,
        history,
        predecessor_baseline,
        predecessor_receipt,
        latest_pointer,
        generated_at,
        policy["descriptor"]["maximumEntries"],
    )
    inventory = inventory_result.value
    for error in inventory_result.errors:
        _block(state, EVIDENCE_IDS[3], error, "Restore the complete authenticated no-fork publication history.")
    inventory_entries = inventory.get("entries")
    inventory_tip = (
        inventory_entries[-1]
        if isinstance(inventory_entries, list)
        and inventory_entries
        and isinstance(inventory_entries[-1], dict)
        else {}
    )
    if context.manifest.release.version != inventory_tip.get("buildVersion"):
        _block(
            state,
            EVIDENCE_IDS[3],
            "manifest build version does not equal the authenticated release inventory tip",
            "Use the exact authenticated maintenance-chain tip as release.version.",
        )
    _schema_block(state, EVIDENCE_IDS[3], inventory, SCHEMAS[INVENTORY_FILE])
    previous_ledger = _configured_json(context, "previousStableLifecycleLedger")
    previous_descriptor = _configured_json(context, "previousStableLifecycleDescriptor")
    genesis_proof = _configured_json(context, "stableLifecycleGenesisProof")
    if previous_ledger is not None:
        _schema_block(state, EVIDENCE_IDS[4], previous_ledger, SCHEMAS[LEDGER_FILE])
    if previous_descriptor is not None:
        _schema_block(state, EVIDENCE_IDS[7], previous_descriptor, SCHEMAS[DESCRIPTOR_FILE])
    for history_error in _lifecycle_history_input_errors(
        previous_ledger, previous_descriptor, genesis_proof
    ):
        _block(
            state,
            EVIDENCE_IDS[7],
            history_error,
            "Provide a fresh protected genesis proof or the exact previously published pair.",
        )
    if genesis_proof is not None:
        for proof_error in _genesis_proof_errors(
            genesis_proof, inventory, policy, public_uri, actual_now
        ):
            _block(
                state,
                EVIDENCE_IDS[7],
                proof_error,
                "Obtain a fresh protected 404 observation for the exact lifecycle target and inventory.",
            )
    ledger, proposed, ledger_errors = build_ledger(
        inventory, policy, policy_loaded.digest, generated_at, previous_ledger, request
    )
    for error in ledger_errors:
        _block(state, EVIDENCE_IDS[5], error, "Use a monotonic transition over published builds only.")
    _schema_block(state, EVIDENCE_IDS[4], ledger, SCHEMAS[LEDGER_FILE])
    transition_set = {
        "schemaVersion": 1,
        "kind": "stable-1.0-support-lifecycle-transition-set",
        "generatedAt": generated_at,
        "stableMilestone": STABLE_MILESTONE,
        "previousLedgerDigest": ledger["previousLedgerDigest"],
        "resultingLedgerDigest": ledger["ledgerDigest"],
        "transitionRequestDigest": semantic_digest(
            [row["authorizationRequestDigest"] for row in proposed]
        ),
        "transitions": [
            {
                **row,
                "authorizationDigest": None,
                "resultingLedgerDigest": ledger["ledgerDigest"],
            }
            for row in proposed
        ],
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }
    transition_set["transitionSetDigest"] = _transition_set_digest(transition_set)
    _schema_block(state, EVIDENCE_IDS[5], transition_set, SCHEMAS[TRANSITION_FILE])
    if previous_ledger is not None and previous_descriptor is not None:
        if (
            previous_descriptor.get("ledgerDigest") != previous_ledger.get("ledgerDigest")
            or previous_descriptor.get("inventoryDigest")
            != previous_ledger.get("inventoryDigest")
        ):
            _block(state, EVIDENCE_IDS[7], "previous descriptor does not bind the previous ledger and inventory", "Provide the exact last-known-good pair.")
        prior_entries = {
            row.get("buildVersion"): row
            for row in previous_ledger.get("entries", [])
            if isinstance(row, dict)
        }
        descriptor_entries = {
            row.get("buildVersion"): row
            for row in previous_descriptor.get("entries", [])
            if isinstance(row, dict)
        }
        if set(prior_entries) != set(descriptor_entries):
            _block(state, EVIDENCE_IDS[7], "previous descriptor omits or invents a ledger build", "Provide the exact last-known-good pair.")
        for build, prior in prior_entries.items():
            projected = descriptor_entries.get(build, {})
            for field in (
                "releaseId", "buildVersion", "tag", "sourceCommit", "productDigest",
                "publicationReceiptDigest", "baselineDigest", "publishedAt", "lifecycleStatus",
                "statusEffectiveAt", "fullSupportUntil", "securityFixesUntil",
                "deprecationEffectiveAt", "endOfSupportAt", "securityRevocationEffectiveAt",
                "replacementBuild", "recoveryGuidance", "advisoryIds", "reasonCodes",
            ):
                if projected.get(field) != prior.get(field):
                    _block(state, EVIDENCE_IDS[7], f"previous descriptor rewrites build {build} field {field}", "Provide the exact last-known-good pair.")
                    break
    update_key_digest = str(policy["descriptor"].get("updateKeyIdentityDigest", ""))
    descriptor, descriptor_errors = build_descriptor(
        ledger, policy, generated_at, previous_descriptor, update_key_digest
    )
    for error in descriptor_errors:
        _block(state, EVIDENCE_IDS[7], error, "Use the last-known-good descriptor and advance exactly one edition.")
    for error in _descriptor_freshness_errors(descriptor, actual_now):
        _block(
            state,
            EVIDENCE_IDS[7],
            error,
            "Use a fresh canonical lifecycle evaluation timestamp and retry.",
        )
    _schema_block(state, EVIDENCE_IDS[7], descriptor, SCHEMAS[DESCRIPTOR_FILE])
    api_governance, ecosystem_governance = governance_projection(
        predecessor_baseline, inventory, generated_at, ga.baseline
    )
    for error in _history_governance_errors(history, ga.baseline):
        _block(state, EVIDENCE_IDS[9], error, "Preserve original Platform API deprecation and removal clocks.")
        api_governance["originalClocksPreserved"] = False
    _schema_block(state, EVIDENCE_IDS[9], api_governance, SCHEMAS[API_GOVERNANCE_FILE])
    _schema_block(state, EVIDENCE_IDS[10], ecosystem_governance, SCHEMAS[ECOSYSTEM_GOVERNANCE_FILE])
    configured_pointer_public_uri = context.manifest.policies.get(
        "latestMaintenancePointerPublicUri"
    )
    latest_pointer_public_uri = canonical_public_https_uri(
        configured_pointer_public_uri
    )
    latest_pointer_digest = inventory.get("latestPointerDigest")
    authenticated_pointer_public_uri = (
        predecessor_receipt.get("latestPointerPublicUri")
        if inventory.get("chainDepth", 0) > 0
        else configured_pointer_public_uri
    )
    if (
        latest_pointer_public_uri != configured_pointer_public_uri
        or latest_pointer_public_uri != authenticated_pointer_public_uri
        or not is_public_https_uri(latest_pointer_public_uri)
        or not _has_unambiguous_publication_path(latest_pointer_public_uri)
        or latest_pointer_public_uri == public_uri
    ):
        _block(state, EVIDENCE_IDS[1], "authorization-bound latest-maintenance pointer URI is unsafe, mismatched, or aliases the lifecycle descriptor", "Use the exact producer-attested public pointer URI; after the first maintenance publication it must equal the authenticated receipt target.")
    approval_input = _configured_json(context, "stableLifecycleAuthorization")
    receipt_input = _configured_json(context, "stableLifecyclePublicationReceipt")
    authorization_valid_at = (
        parse_timestamp(receipt_input.get("generatedAt"))
        if mode == "verify-publication" and receipt_input is not None
        else None
    )
    authorization, authorization_valid, approval_errors = _validate_authorization(
        approval_input,
        policy,
        descriptor,
        ledger,
        transition_set,
        public_uri,
        latest_pointer_public_uri,
        latest_pointer_digest,
        actual_now,
        valid_at=authorization_valid_at,
    )
    for error in approval_errors:
        _block(state, EVIDENCE_IDS[6], error, "Obtain exact unexpired protected lifecycle approval.")
    if mode in {"validate-authorization", "verify-publication"} and not authorization_valid:
        _block(state, EVIDENCE_IDS[6], "protected lifecycle authorization is not valid", "Provide exact approval.")
    _schema_block(state, EVIDENCE_IDS[6], authorization, SCHEMAS[AUTHORIZATION_FILE])
    if authorization_valid:
        approval_digest = canonical_file_digest(authorization)
        for row in transition_set["transitions"]:
            row["authorizationDigest"] = approval_digest
        transition_set["transitionSetDigest"] = _transition_set_digest(transition_set)
        _schema_block(state, EVIDENCE_IDS[5], transition_set, SCHEMAS[TRANSITION_FILE])
    plan = _publication_plan(
        descriptor,
        ledger,
        authorization,
        authorization_valid,
        public_uri,
        latest_pointer_public_uri,
        latest_pointer_digest,
        transition_set["transitionSetDigest"],
    )
    _schema_block(state, EVIDENCE_IDS[13], plan, SCHEMAS[PLAN_FILE])
    receipt_verified, receipt_errors = _verify_receipt(
        receipt_input, descriptor, plan, authorization, actual_now
    )
    for error in receipt_errors:
        evidence = EVIDENCE_IDS[13] if "conflict" in error else EVIDENCE_IDS[14]
        _block(state, evidence, error, "Verify identical public descriptor bytes; never overwrite conflicts.")
    if mode == "verify-publication" and not receipt_verified:
        _block(state, EVIDENCE_IDS[14], "lifecycle publication is not independently verified", "Provide the exact public receipt.")
    receipt = receipt_input or {
        "schemaVersion": 1,
        "kind": "stable-1.0-support-lifecycle-publication-receipt",
        "generatedAt": generated_at,
        "stableMilestone": STABLE_MILESTONE,
        "descriptorEdition": descriptor["descriptorEdition"],
        "descriptorDigest": descriptor["descriptorDigest"],
        "descriptorBytesDigest": canonical_file_digest(descriptor),
        "ledgerDigest": ledger["ledgerDigest"],
        "updateKeyIdentityDigest": descriptor["updateKeyIdentityDigest"],
        "updateKeyScope": descriptor["updateKeyScope"],
        "updateKeyDocName": descriptor["updateKeyDocName"],
        "publicRequestUri": plan["publicRequestUri"],
        "previousDescriptorEdition": descriptor["previousDescriptorEdition"],
        "previousDescriptorDigest": descriptor["previousDescriptorDigest"],
        "publicationPlanDigest": plan["publicationPlanDigest"],
        "authorizationDigest": None,
        "operation": "not-performed",
        "publicationState": "not-published",
        "verificationStatus": "not-verified",
        "conflict": False,
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }
    latest = {
        "schemaVersion": 1,
        "kind": "stable-1.0-support-lifecycle-latest",
        "generatedAt": generated_at,
        "stableMilestone": STABLE_MILESTONE,
        "descriptorEdition": descriptor["descriptorEdition"],
        "descriptorDigest": descriptor["descriptorDigest"],
        "ledgerDigest": ledger["ledgerDigest"],
        "previousDescriptorEdition": descriptor["previousDescriptorEdition"],
        "previousDescriptorDigest": descriptor["previousDescriptorDigest"],
        "publicationVerified": receipt_verified,
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }
    provenance = {
        "schemaVersion": 1,
        "kind": "stable-1.0-support-lifecycle-provenance",
        "generatedAt": generated_at,
        "stableMilestone": STABLE_MILESTONE,
        "gaRootDigest": ga.root_identity_digest,
        "maintenanceTipBaselineDigest": predecessor.baseline_digest,
        "maintenanceTipReceiptDigest": predecessor.receipt_digest,
        "latestMaintenancePointerPublicUri": latest_pointer_public_uri,
        "inventoryDigest": inventory["inventoryDigest"],
        "ledgerDigest": ledger["ledgerDigest"],
        "descriptorDigest": descriptor["descriptorDigest"],
        "policyDigest": policy_loaded.digest,
        "genesisProofDigest": (
            genesis_proof.get("proofDigest") if genesis_proof is not None else None
        ),
        "sideEffectsPerformed": False,
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }
    _schema_block(state, EVIDENCE_IDS[3], provenance, SCHEMAS[PROVENANCE_FILE])
    _schema_block(state, EVIDENCE_IDS[14], receipt, SCHEMAS[RECEIPT_FILE])
    _schema_block(state, EVIDENCE_IDS[7], latest, SCHEMAS[LATEST_FILE])
    artifacts = {
        "inventory": INVENTORY_FILE,
        "ledger": LEDGER_FILE,
        "transitionSet": TRANSITION_FILE,
        "descriptor": DESCRIPTOR_FILE,
        "authorization": AUTHORIZATION_FILE,
        "publicationPlan": PLAN_FILE,
        "publicationReceipt": RECEIPT_FILE,
        "latest": LATEST_FILE,
        "platformApiDeprecationGovernance": API_GOVERNANCE_FILE,
        "catalogAppProfileGovernance": ECOSYSTEM_GOVERNANCE_FILE,
        "provenance": PROVENANCE_FILE,
        "checksums": CHECKSUMS_FILE,
        "redactionReport": REDACTION_FILE,
    }
    if genesis_proof is not None:
        artifacts["genesisProof"] = GENESIS_PROOF_FILE
    values = {
        INVENTORY_FILE: inventory,
        LEDGER_FILE: ledger,
        TRANSITION_FILE: transition_set,
        DESCRIPTOR_FILE: descriptor,
        AUTHORIZATION_FILE: authorization,
        PLAN_FILE: plan,
        RECEIPT_FILE: receipt,
        LATEST_FILE: latest,
        API_GOVERNANCE_FILE: api_governance,
        ECOSYSTEM_GOVERNANCE_FILE: ecosystem_governance,
        PROVENANCE_FILE: provenance,
    }
    if genesis_proof is not None:
        values[GENESIS_PROOF_FILE] = genesis_proof
    findings: list[dict[str, str]] = []
    for name, value in values.items():
        for finding in scan_value(_redaction_view(value)):
            findings.append({"artifact": name, **finding})
    redaction = {
        "schemaVersion": 1,
        "status": "fail" if findings else "pass",
        "findingCount": len(findings),
        "findings": findings,
        "guarantees": {
            "privateInsertUrisExcluded": not findings,
            "rawBodiesExcluded": not findings,
            "absolutePathsExcluded": not findings,
            "sideEffectsNotPerformed": True,
        },
    }
    if findings:
        _block(state, EVIDENCE_IDS[15], "lifecycle public artifacts failed redaction", "Remove unsafe fields and retry.")
    _schema_block(state, EVIDENCE_IDS[15], redaction, SCHEMAS[REDACTION_FILE])
    publication_state = "publication-verified" if receipt_verified else "not-published"
    promotion_ready = (
        not state.blockers
        and mode == "verify-publication"
        and authorization_valid
        and receipt_verified
    )
    summary = {
        "schemaVersion": 1,
        "kind": "stable-1.0-support-lifecycle-summary",
        "tool": TOOL_NAME,
        "generatedAt": generated_at,
        "releaseId": context.manifest.release.release_id,
        "buildVersion": context.manifest.release.version,
        "stableMilestone": STABLE_MILESTONE,
        "commandMode": mode,
        "status": "fail" if state.blockers else "pass",
        "decision": "no-go" if state.blockers else ("go" if promotion_ready else "evaluation-complete"),
        "promotionReady": promotion_ready,
        "authorizationReady": authorization_valid,
        "publicationReady": receipt_verified,
        "nonRelease": not receipt_verified,
        "publicationState": publication_state,
        "currentStableBuild": descriptor["currentStableBuild"],
        "descriptorEdition": descriptor["descriptorEdition"],
        "descriptorDigest": descriptor["descriptorDigest"],
        "ledgerDigest": ledger["ledgerDigest"],
        "evidence": [
            {"id": evidence, "status": "fail" if any(row.get("evidenceId") == evidence for row in state.blockers) else "pass"}
            for evidence in EVIDENCE_IDS
        ],
        "blockers": state.blockers,
        "warnings": state.warnings,
        "waivers": [],
        "artifacts": artifacts,
        "redaction": redaction,
    }
    _schema_block(state, EVIDENCE_IDS[4], summary, SCHEMAS[SUMMARY_FILE])
    for name, value in values.items():
        _write_canonical_json(out / name, value)
    _write_canonical_json(out / REDACTION_FILE, redaction)
    _write_canonical_json(out / SUMMARY_FILE, summary)
    write_text(out / REPORT_FILE, _report(summary))
    _checksums(out, [*values, REDACTION_FILE, SUMMARY_FILE, REPORT_FILE])
    mode_success = (
        not state.blockers
        and (
            mode in {"evaluate", "prepare-transition"}
            or (mode == "validate-authorization" and authorization_valid)
            or (mode == "verify-publication" and receipt_verified)
        )
    )
    return 0 if mode_success else 1


def _fail_closed(context: RunContext, out: Path, state: ValidationState) -> None:
    generated = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    redaction = {
        "schemaVersion": 1,
        "status": "pass",
        "findingCount": 0,
        "findings": [],
        "guarantees": {
            "privateInsertUrisExcluded": True,
            "rawBodiesExcluded": True,
            "absolutePathsExcluded": True,
            "sideEffectsNotPerformed": True,
        },
    }
    summary = {
        "schemaVersion": 1,
        "kind": "stable-1.0-support-lifecycle-summary",
        "tool": TOOL_NAME,
        "generatedAt": generated,
        "releaseId": context.manifest.release.release_id,
        "buildVersion": context.manifest.release.version,
        "stableMilestone": STABLE_MILESTONE,
        "commandMode": context.manifest.commands.get("stable-lifecycle", {}).get("mode", "evaluate"),
        "status": "fail",
        "decision": "no-go",
        "promotionReady": False,
        "authorizationReady": False,
        "publicationReady": False,
        "nonRelease": True,
        "publicationState": "not-published",
        "currentStableBuild": None,
        "descriptorEdition": None,
        "descriptorDigest": None,
        "ledgerDigest": None,
        "evidence": [{"id": item, "status": "fail"} for item in EVIDENCE_IDS],
        "blockers": state.blockers,
        "warnings": [],
        "waivers": [],
        "artifacts": {"redactionReport": REDACTION_FILE},
        "redaction": redaction,
    }
    _write_canonical_json(out / REDACTION_FILE, redaction)
    _write_canonical_json(out / SUMMARY_FILE, summary)
    write_text(out / REPORT_FILE, _report(summary))


def run(context: RunContext) -> tuple[int, Path, Path]:
    """Run lifecycle certification without any network or publication side effect."""

    out = reset_confined_directory(
        context.component_dir / "artifacts" / "legacy",
        context.run_root,
        "Stable lifecycle native output",
    )
    state = ValidationState()
    try:
        code = _run(context, out, state)
    except Exception:  # noqa: BLE001 - protected input failures are deliberately sanitized
        _block(
            state,
            "stable-lifecycle.execution-input",
            "Stable lifecycle rejected malformed, unsafe, or unauthenticated input",
            "Correct the exact protected input and rerun certification.",
        )
        out = reset_confined_directory(
            context.component_dir / "artifacts" / "legacy",
            context.run_root,
            "Stable lifecycle failed native output",
        )
        _fail_closed(context, out, state)
        code = 1
    return code, out / SUMMARY_FILE, out / REPORT_FILE

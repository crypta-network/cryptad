"""Canonical side-effect-free Stable 1.0 maintenance and hotfix certification."""

from __future__ import annotations

import datetime as dt
import json
import os
import shutil
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote, urlsplit, urlunsplit

from cryptad_certification.io import write_json, write_text
from cryptad_certification.models import RunContext
from cryptad_certification.schema_validation import validate_schema
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
    Predecessor,
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

_PASS_REDACTION = {"status": "pass", "findingCount": 0, "findings": []}


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
    for role, raw_uri in destinations:
        canonical_uri = canonical_public_https_uri(raw_uri)
        if (
            canonical_uri != raw_uri
            or not _https(canonical_uri)
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
) -> dict[str, Any]:
    scope = candidate.input_value.get("changeScope")
    scope = scope if isinstance(scope, dict) else {}
    return {
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
    authorized: bool,
    state: ValidationState,
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
        "releaseNotesDigest": file_digest(out / RELEASE_NOTES_FILE),
        "coreInfoDigest": file_digest(out / CORE_INFO_FILE),
        "stableCatalogDigest": catalog.get("digest"),
        "knownLimitationsDeltaDigest": candidate.input_value.get("limitations", {}).get("deltaDigest"),
        "publicationTargetsDigest": targets_digest,
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
    candidate = authenticate_candidate(
        context,
        predecessor,
        policy,
        state,
        allow_published_product=closing_follow_up,
        freeze_predecessor_observation=freeze_predecessor_observation,
    )

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
            artifacts,
            redaction,
        )
        summary["nonRelease"] = True
        write_json(out / REDACTION_REPORT_FILE, redaction)
        write_json(out / SUMMARY_FILE, summary)
        write_text(out / REPORT_FILE, render_go_no_go(summary))
        return 0 if not state.blockers else 1

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
        authorization_valid,
        state,
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
        authorization_digest,
        authorization_valid,
        publication_state,
    )
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
        artifacts,
        redaction,
    )
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
    summary = _summary(context, state, None, "validated", False, {}, redaction)
    write_json(out / SUMMARY_FILE, summary)
    write_text(out / REPORT_FILE, render_go_no_go(summary))
    write_json(out / REDACTION_REPORT_FILE, redaction)

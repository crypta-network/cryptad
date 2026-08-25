"""Fail-closed certification for the Stable 1.0 external app pilot.

The engine never publishes, installs, or mutates a remote node.  Operational
closeout performs read-only GitHub Actions metadata authentication for its
protected PR-291, PR-292, and PR-293 roots; all earlier modes remain offline.
"""

from __future__ import annotations

import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any
from urllib.parse import urlsplit
import zipfile

from ..io import read_json, read_json_bytes, write_json, write_text
from ..redaction import scan_manifest_scalar, scan_value
from ..schema_validation import validate_schema
from . import stable_1_0_catalog_authority as catalog_authority
from . import stable_1_0_catalog_authority_closeout as catalog_authority_closeout
from . import stable_1_0_rc_freeze as rc_freeze
from . import stable_1_0_supply_chain_archive as supply_chain_archive
from . import stable_1_0_supply_chain_core as supply_chain_core
from .stable_1_0_independent_reproducibility import independent_summary_errors
from .stable_1_0_protected_release import _github_actions_coordinate_errors


EXECUTION_SCHEMA = "stable-1.0-third-party-app-pilot-execution-v1.schema.json"
HANDOFF_SCHEMA = "stable-1.0-external-developer-handoff-v1.schema.json"
REVIEW_SCHEMA = "stable-1.0-third-party-review-cohort-v1.schema.json"
APPROVAL_SCHEMA = "stable-1.0-pilot-publisher-key-approval-v1.schema.json"
PUBLICATION_SCHEMA = "stable-1.0-third-party-beta-catalog-publication-v1.schema.json"
RUNTIME_SCHEMA = "stable-1.0-third-party-runtime-drill-v1.schema.json"
COLLECTOR_SCHEMA = "stable-1.0-live-network-beta-smoke-summary-v1.schema.json"
RC_FREEZE_SCHEMA = "stable-1.0-rc-freeze-v1.schema.json"
SUMMARY_SCHEMA = "stable-1.0-third-party-app-pilot-summary-v1.schema.json"
POLICY_FILE = "stable-1.0-third-party-app-pilot-policy.json"
RUNTIME_PRODUCER_WORKFLOW = (
    ".github/workflows/stable-1.0-third-party-app-pilot-runtime.yml"
)
RUNTIME_PRODUCER_ENVIRONMENT = "stable-1-0-third-party-pilot-node"
RUNTIME_PRODUCER_JOB = "Produce protected isolated-node runtime receipt"
RUNTIME_PRODUCER_STEPS = (
    "Run isolated AppHost install update caution rollback and cleanup",
    "Sign exact runtime receipt with the pilot node attestation key",
)
SELECTED_RC_WORKFLOW = ".github/workflows/stable-1.0-rc-release.yml"
SELECTED_RC_ENVIRONMENT = "stable-1-0-rc"
COLLECTOR_LOOPBACK_BASE_URL_SHAPES = frozenset(
    {
        "http://127.0.0.1:<port>",
        "http://localhost:<port>",
        "http://[::1]:<port>",
    }
)

SUMMARY_FILE = "stable-1.0-third-party-app-pilot-summary.json"
REPORT_FILE = "stable-1.0-third-party-app-pilot-report.md"
REDACTION_FILE = "stable-1.0-third-party-app-pilot-redaction-report.json"
MODE_FILES = {
    "preflight": "stable-1.0-third-party-app-pilot-preflight.json",
    "verify-external-handoff": "stable-1.0-external-developer-handoff-summary.json",
    "verify-review-cohort": "stable-1.0-third-party-review-cohort.json",
    "verify-catalog-publication": "stable-1.0-third-party-catalog-publication-summary.json",
    "verify-runtime-drill": "stable-1.0-third-party-runtime-drill.json",
    "closeout": SUMMARY_FILE,
}
MODES = tuple(MODE_FILES)
ZERO_DIGEST = "sha256:" + "0" * 64
COHORT_IDS = (
    "version-1-reviewed",
    "version-2-rejected",
    "version-2-corrected",
    "version-3-caution",
)
EXPECTED_DECISIONS = {
    "version-1-reviewed": "reviewed",
    "version-2-rejected": frozenset({"rejected", "resubmission_requested"}),
    "version-2-corrected": "reviewed",
    "version-3-caution": "caution",
}
EVIDENCE_IDS = (
    "third-party-pilot.external-developer",
    "third-party-pilot.bundle-signature",
    "third-party-pilot.reviewed-install",
    "third-party-pilot.rejected-resubmission",
    "third-party-pilot.caution-consent",
    "third-party-pilot.catalog-publication",
    "third-party-pilot.update-rollback",
    "third-party-pilot.transparency",
    "third-party-pilot.redaction",
)
ROLE_NAMES = frozenset(
    {"catalog-signing", "first-party-app-signing", "app-reviewer", "offline-recovery"}
)
RECEIPT_DOMAINS = {
    "stable-1.0-third-party-review-cohort":
        "cryptad.stable-1.0.external-third-party-app-pilot.review-cohort.v1",
    "stable-1.0-pilot-publisher-key-approval":
        "cryptad.stable-1.0.external-third-party-app-pilot.publisher-approval.v1",
    "stable-1.0-third-party-beta-catalog-publication":
        "cryptad.stable-1.0.external-third-party-app-pilot.beta-publication.v1",
    "stable-1.0-third-party-runtime-drill":
        "cryptad.stable-1.0.external-third-party-app-pilot.runtime-drill.v1",
}
TRANSPARENCY_FIELDS = (
    "schemaVersion",
    "sequence",
    "recordId",
    "createdAt",
    "kind",
    "subjectType",
    "appId",
    "appVersion",
    "catalogId",
    "artifactSha256",
    "artifactSizeBytes",
    "reviewerKeyId",
    "reviewerKeyStatus",
    "policyId",
    "policyVersion",
    "receiptStatus",
    "trustStatus",
    "trusted",
    "positive",
    "requiresAcknowledgement",
    "blocksInstall",
    "blocksUpdate",
    "blocksPolicyApply",
    "evidenceSha256",
    "evidenceUri",
    "previousRecordHash",
    "recordHash",
    "warnings",
)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _semantic_digest(value: dict[str, Any], field: str) -> str:
    normalized = copy.deepcopy(value)
    normalized[field] = ZERO_DIGEST
    normalized.pop("signatureBase64", None)
    return _digest_bytes(_canonical_bytes(normalized))


def _redaction_view(value: Any) -> Any:
    """Hide schema-validated public keys and proofs from path heuristics only."""

    public_cryptographic_fields = {
        "approvalSignatureBase64",
        "attestationSignatureBase64",
        "nodeAttestationPublicKeySpkiBase64",
        "publicKeySpkiBase64",
        "publisherPublicKeySpkiBase64",
        "signatureBase64",
        "workloadPublicKeySpkiBase64",
    }
    if isinstance(value, dict):
        return {
            key: "<public-cryptographic-value>"
            if key in public_cryptographic_fields
            else _redaction_view(child)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_redaction_view(child) for child in value]
    return value


def _signature_subject(value: dict[str, Any]) -> bytes:
    normalized = copy.deepcopy(value)
    normalized.pop("signatureBase64", None)
    domain = RECEIPT_DOMAINS.get(str(normalized.get("kind")))
    if domain is None:
        raise ValueError("signed pilot receipt has an unknown domain")
    return domain.encode("ascii") + b"\x00" + _canonical_bytes(normalized)


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} is missing or malformed")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"{label} has no timezone offset")
    return parsed.astimezone(timezone.utc)


def _freshness_errors(
    observed: datetime,
    evaluation: datetime,
    maximum_age_seconds: int,
    label: str,
) -> list[str]:
    if observed > evaluation + timedelta(seconds=300):
        return [f"{label} is in the future"]
    if evaluation - observed > timedelta(seconds=maximum_age_seconds):
        return [f"{label} is stale"]
    return []


def _verification_time(
    contract: dict[str, Any],
    policy: dict[str, Any],
    observed: datetime | None = None,
) -> datetime:
    """Use retained fixture time or the current runner time for operational checks."""

    contract_time = _timestamp(contract["evaluationTime"], "evaluation time")
    if contract["fixtureOnly"] or contract["selfTest"]:
        return contract_time
    current = observed or datetime.now(timezone.utc).replace(microsecond=0)
    if current.tzinfo is None:
        raise ValueError("operational verification time has no timezone offset")
    current = current.astimezone(timezone.utc)
    maximum_skew = timedelta(
        seconds=policy["freshness"]["maximumClockSkewSeconds"]
    )
    if contract_time > current + maximum_skew:
        raise ValueError("operational pilot evaluation time is in the future")
    return current


def _policy(workspace: Path) -> tuple[dict[str, Any], str]:
    policy = read_json(workspace / "tools" / "release-certification" / POLICY_FILE)
    if not isinstance(policy, dict):
        raise ValueError("third-party pilot policy is malformed")
    expected = _semantic_digest(policy, "policyDigest")
    if policy.get("policyDigest") != expected:
        raise ValueError("third-party pilot policy digest is invalid")
    return policy, expected


def _spki(value: str, label: str) -> bytes:
    try:
        encoded = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} is not canonical base64") from exc
    if not encoded.startswith(catalog_authority.SPKI_PREFIX) or len(encoded) != 44:
        raise ValueError(f"{label} is not canonical Ed25519 SubjectPublicKeyInfo")
    return encoded


def _signature(value: Any, label: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} is malformed") from exc
    if len(decoded) != 64:
        raise ValueError(f"{label} is not one Ed25519 signature")
    return decoded


def _verify(key_spki: str, subject: bytes, signature: Any, label: str) -> list[str]:
    try:
        public = _spki(key_spki, f"{label} public key")[len(catalog_authority.SPKI_PREFIX) :]
        proof = _signature(signature, f"{label} signature")
        if not catalog_authority._verify_ed25519(public, subject, proof):
            return [f"{label} signature does not verify"]
    except ValueError as exc:
        return [str(exc)]
    return []


def _key_errors(contract: dict[str, Any], evaluation: datetime) -> tuple[list[str], dict[str, dict[str, Any]]]:
    errors: list[str] = []
    by_role: dict[str, dict[str, Any]] = {}
    keys = contract["authorities"]["keys"]
    ids: set[str] = set()
    fingerprints: set[str] = set()
    for key in keys:
        role = key["role"]
        if role in by_role:
            errors.append(f"authority role {role} is not unique")
        by_role[role] = key
        if key["keyId"] in ids or key["fingerprint"] in fingerprints:
            errors.append("PR-293 key ids and fingerprints must be unique")
        ids.add(key["keyId"])
        fingerprints.add(key["fingerprint"])
        try:
            spki = _spki(key["publicKeySpkiBase64"], f"{role} key")
            if _digest_bytes(spki) != key["fingerprint"]:
                errors.append(f"{role} key fingerprint is invalid")
            if key["lifecycle"] != "active":
                errors.append(f"{role} key is not active")
            if not (_timestamp(key["validFrom"], f"{role} validFrom") <= evaluation < _timestamp(key["validUntil"], f"{role} validUntil")):
                errors.append(f"{role} key is outside its validity interval")
        except ValueError as exc:
            errors.append(str(exc))
    missing = ROLE_NAMES.difference(by_role)
    if missing:
        errors.append("PR-293 keyset omits required roles: " + ", ".join(sorted(missing)))
    publisher = contract["externalApp"]
    try:
        publisher_spki = _spki(publisher["publisherPublicKeySpkiBase64"], "external publisher key")
        if _digest_bytes(publisher_spki) != publisher["publisherFingerprint"]:
            errors.append("external publisher key fingerprint is invalid")
    except ValueError as exc:
        errors.append(str(exc))
    keyset_ids = {
        key["keyId"] for key in contract["authorities"]["keysetSubject"]["keys"]
    }
    keyset_fingerprints = {
        key["publicKeyFingerprintSha256"]
        for key in contract["authorities"]["keysetSubject"]["keys"]
    }
    if (
        publisher["publisherKeyId"] in keyset_ids
        or publisher["publisherFingerprint"] in keyset_fingerprints
    ):
        errors.append("external publisher key is reused for a PR-293 authority role")
    errors.extend(_keyset_binding_errors(contract))
    return sorted(set(errors)), by_role


def _keyset_binding_errors(contract: dict[str, Any]) -> list[str]:
    """Bind selected pilot authority keys to PR-293's canonical keyset commitment."""

    errors: list[str] = []
    authorities = contract["authorities"]
    subject = authorities["keysetSubject"]
    if _digest_bytes(_canonical_bytes(subject)) != authorities["keysetDigest"]:
        errors.append("PR-293 keyset digest does not match the canonical keyset subject")
    release = subject["release"]
    contract_release = contract["release"]
    repository = contract["repository"]
    if (
        release["releaseId"] != contract_release["releaseId"]
        or release["buildVersion"] != contract_release["buildVersion"]
        or release["sourceCommit"] != repository["sourceCommit"]
    ):
        errors.append("PR-293 keyset subject belongs to a different release")
    bindings = subject["bindings"]
    if (
        bindings["protectedReleaseContractDigest"]
        != authorities["protectedReleaseRootDigest"]
        or bindings["protectedReleaseLifecycleState"] != "publicly-observed"
    ):
        errors.append("PR-293 keyset subject differs from the protected release root")
    if (
        bindings["independentReproducibilitySummaryDigest"]
        != authorities["independentReproducibilityDigest"]
        or bindings["independentReproducibilityOperational"] is not True
        or bindings["providerIndependent"] is not True
    ):
        errors.append("PR-293 keyset subject differs from independent reproducibility")

    subject_keys = subject["keys"]
    key_ids = [key["keyId"] for key in subject_keys]
    key_fingerprints = [key["publicKeyFingerprintSha256"] for key in subject_keys]
    if key_ids != sorted(key_ids):
        errors.append("PR-293 keyset subject keys are not canonically ordered")
    if len(key_ids) != len(set(key_ids)) or len(key_fingerprints) != len(
        set(key_fingerprints)
    ):
        errors.append("PR-293 keyset subject repeats a key identity or fingerprint")
    by_id = {key["keyId"]: key for key in subject_keys}
    for subject_key in subject_keys:
        try:
            spki = _spki(
                subject_key["publicKeySpkiBase64"],
                f"PR-293 keyset key {subject_key['keyId']}",
            )
            if _digest_bytes(spki) != subject_key["publicKeyFingerprintSha256"]:
                errors.append(
                    f"PR-293 keyset key {subject_key['keyId']} fingerprint is invalid"
                )
        except ValueError as exc:
            errors.append(str(exc))
    for selected in authorities["keys"]:
        subject_key = by_id.get(selected["keyId"])
        if subject_key is None:
            errors.append(
                f"selected {selected['role']} key is absent from the PR-293 keyset subject"
            )
            continue
        expected = {
            "keyId": subject_key["keyId"],
            "role": subject_key["role"],
            "publicKeySpkiBase64": subject_key["publicKeySpkiBase64"],
            "fingerprint": subject_key["publicKeyFingerprintSha256"],
            "lifecycle": subject_key["lifecycle"],
            "validFrom": subject_key["validFrom"],
            "validUntil": subject_key["validUntil"],
        }
        if selected != expected or subject_key["compromiseState"] != "uncompromised":
            errors.append(
                f"selected {selected['role']} key differs from the PR-293 keyset subject"
            )
    return sorted(set(errors))


def _node_attestation_role_errors(
    contract: dict[str, Any], fingerprint: str
) -> list[str]:
    reserved = {
        key["publicKeyFingerprintSha256"]
        for key in contract["authorities"]["keysetSubject"]["keys"]
    }
    reserved.update(
        {
            contract["externalApp"]["publisherFingerprint"],
            contract["externalApp"]["workloadProfile"]["workloadFingerprint"],
        }
    )
    if fingerprint in reserved:
        return ["pilot node attestation key is not role-distinct"]
    return []


def _profile_subject(contract: dict[str, Any]) -> bytes:
    profile = copy.deepcopy(contract["externalApp"]["workloadProfile"])
    profile.pop("approvalSignatureBase64", None)
    value = {
        "domain": "cryptad.stable-1.0.external-third-party-app-pilot.workload-profile-approval.v1",
        "pilotId": contract["pilotId"],
        "appId": contract["externalApp"]["appId"],
        "source": contract["externalApp"]["source"],
        "profile": profile,
    }
    return value["domain"].encode("ascii") + b"\x00" + _canonical_bytes(value)


def _externality_errors(
    contract: dict[str, Any], policy: dict[str, Any], by_role: dict[str, dict[str, Any]], evaluation: datetime
) -> list[str]:
    errors: list[str] = []
    app = contract["externalApp"]
    source = app["source"]
    profile = app["workloadProfile"]
    repo = source["repositoryIdentity"].casefold()
    owner = source["owner"].casefold()
    if repo in {item.casefold() for item in policy["prohibitedSourceRepositories"]}:
        errors.append("external source repository is controlled by Crypta")
    if owner in {item.casefold() for item in policy["prohibitedSourceOwners"]}:
        errors.append("external source owner is controlled by Crypta")
    if app["appId"].casefold() in {item.casefold() for item in policy["prohibitedAppIds"]}:
        errors.append("checked-in sample app cannot satisfy operational externality")
    expected_repo = f"{source['host']}/{source['owner']}/{source['name']}".casefold()
    if repo != expected_repo:
        errors.append("source repository identity does not match host, owner, and name")
    markers = tuple(item.casefold() for item in policy["prohibitedIdentityMarkers"])
    operational_identity_fields = (
        contract["pilotId"], app["publisherKeyId"], profile["profileId"], profile["organizationId"],
        profile["accountId"], profile["subject"], profile["pipelineDefinition"],
    )
    if not contract["fixtureOnly"] and any(marker in str(value).casefold() for value in operational_identity_fields for marker in markers):
        errors.append("fixture, sample, template, or test identity cannot be operational")
    if not contract["fixtureOnly"] and (profile["profileType"] != "operational" or profile["operationalAllowed"] is not True):
        errors.append("workload profile is not approved for operational evidence")
    if profile["organizationId"].casefold() in {item.casefold() for item in policy["prohibitedSourceOwners"]}:
        errors.append("external workload organization is controlled by Crypta")
    if profile["pipelineRevision"] != source["revision"]:
        errors.append("workload pipeline revision does not bind the immutable source revision")
    try:
        workload_spki = _spki(profile["workloadPublicKeySpkiBase64"], "workload key")
        if _digest_bytes(workload_spki) != profile["workloadFingerprint"]:
            errors.append("workload public-key fingerprint is invalid")
        keyset_fingerprints = {
            key["publicKeyFingerprintSha256"]
            for key in contract["authorities"]["keysetSubject"]["keys"]
        }
        if profile["workloadFingerprint"] in keyset_fingerprints | {
            app["publisherFingerprint"]
        }:
            errors.append("workload key is not role-distinct")
        if not (_timestamp(profile["approvedAt"], "workload profile approval") <= evaluation < _timestamp(profile["expiresAt"], "workload profile expiry")):
            errors.append("workload profile approval is stale or expired")
    except ValueError as exc:
        errors.append(str(exc))
    reviewer = by_role.get("app-reviewer")
    if reviewer is not None:
        if profile["approvalReviewerKeyId"] != reviewer["keyId"]:
            errors.append("workload profile approval does not use the active PR-293 reviewer")
        errors.extend(_verify(reviewer["publicKeySpkiBase64"], _profile_subject(contract), profile["approvalSignatureBase64"], "workload profile approval"))
    return sorted(set(errors))


def _cohort_contract_errors(contract: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    rows = contract["cohort"]
    if tuple(row["cohortId"] for row in rows) != COHORT_IDS:
        errors.append("pilot cohort order or membership is invalid")
        return errors
    by_id = {row["cohortId"]: row for row in rows}
    for cohort_id, row in by_id.items():
        expected = EXPECTED_DECISIONS[cohort_id]
        if isinstance(expected, frozenset):
            if row["expectedDecision"] not in expected:
                errors.append("initial version 2 must be rejected or request resubmission")
        elif row["expectedDecision"] != expected:
            errors.append(f"{cohort_id} has the wrong expected decision")
    rejected = by_id["version-2-rejected"]
    corrected = by_id["version-2-corrected"]
    if corrected["submissionType"] != "resubmission" or corrected["resubmissionOf"] != rejected["submissionId"]:
        errors.append("corrected version 2 does not exactly link to the rejected submission")
    if rejected["submissionId"] == corrected["submissionId"]:
        errors.append("corrected resubmission reuses the rejected submission id")
    for field in ("submissionDigest", "bundleDigest", "bundleSignatureDigest", "preReviewDigest"):
        if rejected[field] == corrected[field]:
            errors.append(f"corrected resubmission reuses stale {field}")
    if rejected["appVersion"] != corrected["appVersion"]:
        errors.append("initial and corrected version 2 app versions differ")
    version_rows = (
        by_id["version-1-reviewed"],
        corrected,
        by_id["version-3-caution"],
    )
    parsed_versions = [
        _dotted_numeric_version(row["appVersion"]) for row in version_rows
    ]
    if any(version is None for version in parsed_versions):
        errors.append("pilot cohort app versions are not AppUpdateService-compatible")
    else:
        version_1, version_2, version_3 = parsed_versions
        if _compare_dotted_numeric_versions(version_2, version_1) <= 0:
            errors.append("corrected version 2 does not strictly advance the app version")
        if _compare_dotted_numeric_versions(version_3, version_2) <= 0:
            errors.append("caution version 3 does not strictly advance the app version")
    return sorted(set(errors))


def _pilot_node_contract_errors(contract: dict[str, Any]) -> list[str]:
    """Bind all runtime registries and require their trust roots to differ."""

    node = contract["protectedPilotNode"]
    errors: list[str] = []
    expected_catalog_digest = _catalog_registry_digest(
        contract["authorities"]["keysetSubject"]
    )
    if node["catalogRegistryDigest"] != expected_catalog_digest:
        errors.append(
            "pilot catalog registry digest is not the canonical authenticated PR-293 projection"
        )
    registry_digests = {
        node["normalStableRegistryDigest"],
        node["catalogRegistryDigest"],
        node["pilotRegistryDigest"],
    }
    if len(registry_digests) != 3:
        errors.append("normal Stable, catalog, and pilot registry digests are not distinct")
    return errors


def _catalog_registry_digest(keyset_subject: dict[str, Any]) -> str:
    """Digest the exact PR-293 catalog registry projection written by catalog authority."""

    catalog_keys = (
        key
        for key in keyset_subject["keys"]
        if key["role"] == "catalog-signing" and key["lifecycle"] != "staged"
    )
    registry_text = catalog_authority._registry_text(catalog_keys).rstrip() + "\n"
    return _digest_bytes(registry_text.encode("utf-8"))


def _dotted_numeric_version(value: str) -> tuple[int, ...] | None:
    """Parse a version using AppUpdateService's dotted-numeric constraints."""

    parts: list[int] = []
    for token in value.split("."):
        if not token or not token.isascii() or not token.isdecimal():
            return None
        number = int(token)
        if number > 2_147_483_647:
            return None
        parts.append(number)
    return tuple(parts) if parts else None


def _compare_dotted_numeric_versions(
    left: tuple[int, ...], right: tuple[int, ...]
) -> int:
    """Compare dotted-numeric versions with AppUpdateService's zero padding."""

    count = max(len(left), len(right))
    for index in range(count):
        left_part = left[index] if index < len(left) else 0
        right_part = right[index] if index < len(right) else 0
        if left_part != right_part:
            return 1 if left_part > right_part else -1
    return 0


def _confined_directory(workspace: Path, requested: Path, label: str) -> Path:
    if ".." in requested.parts:
        raise ValueError(f"{label} contains traversal")
    target = requested if requested.is_absolute() else workspace / requested
    resolved_workspace = workspace.resolve()
    try:
        relative = target.relative_to(resolved_workspace)
    except ValueError as exc:
        raise ValueError(f"{label} escapes the repository workspace") from exc
    current = resolved_workspace
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"{label} contains a symbolic-link component")
        if current.exists() and not current.is_dir():
            raise ValueError(f"{label} contains a non-directory component")
    target.mkdir(parents=True, exist_ok=True)
    resolved = target.resolve()
    resolved.relative_to(resolved_workspace)
    return resolved


def _confined_existing_path(
    workspace: Path,
    requested: Path,
    label: str,
    *,
    directory: bool,
) -> Path:
    """Confine an existing input without erasing lexical symlinks first."""

    if ".." in requested.parts:
        raise ValueError(f"{label} contains traversal")
    resolved_workspace = workspace.resolve()
    lexical = requested if requested.is_absolute() else resolved_workspace / requested
    try:
        relative = lexical.relative_to(resolved_workspace)
    except ValueError as exc:
        raise ValueError(f"{label} escapes the repository workspace") from exc
    current = resolved_workspace
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"{label} contains a symbolic-link component")
    try:
        resolved = lexical.resolve(strict=True)
        resolved.relative_to(resolved_workspace)
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        raise ValueError(f"{label} is missing or unsafe") from exc
    expected_kind = resolved.is_dir() if directory else resolved.is_file()
    if not expected_kind:
        raise ValueError(f"{label} is missing or unsafe")
    return resolved


def _der_tlv(value: bytes, offset: int) -> tuple[int, bytes, int] | None:
    """Read one canonical bounded DER TLV without accepting indefinite lengths."""

    if offset + 2 > len(value):
        return None
    tag = value[offset]
    first_length = value[offset + 1]
    cursor = offset + 2
    if first_length < 0x80:
        length = first_length
    else:
        width = first_length & 0x7F
        if width == 0 or width > 4 or cursor + width > len(value):
            return None
        encoded_length = value[cursor : cursor + width]
        if encoded_length[0] == 0:
            return None
        length = int.from_bytes(encoded_length, "big")
        if length < 0x80:
            return None
        cursor += width
    end = cursor + length
    if end > len(value):
        return None
    return tag, value[cursor:end], end


def _der_children(value: bytes) -> list[tuple[int, bytes]] | None:
    children: list[tuple[int, bytes]] = []
    cursor = 0
    while cursor < len(value):
        parsed = _der_tlv(value, cursor)
        if parsed is None:
            return None
        tag, content, cursor = parsed
        children.append((tag, content))
    return children


def _looks_like_private_key_der(value: bytes) -> bool:
    outer = _der_tlv(value, 0)
    if outer is None or outer[0] != 0x30 or outer[2] != len(value):
        return False
    children = _der_children(outer[1])
    if not children:
        return False
    tags = [tag for tag, _content in children]
    # EncryptedPrivateKeyInfo contains an encryption AlgorithmIdentifier and
    # the encrypted PKCS#8 bytes, without the version INTEGER used below.
    if len(tags) == 2 and tags == [0x30, 0x04]:
        return True
    if children[0][0] != 0x02:
        return False
    version = int.from_bytes(children[0][1], "big") if children[0][1] else -1
    # PKCS#8 PrivateKeyInfo / OneAsymmetricKey.
    if version in {0, 1} and len(tags) >= 3 and tags[1:3] == [0x30, 0x04]:
        return True
    # PKCS#1 RSA private keys contain version plus eight or more INTEGERs.
    if version in {0, 1} and len(tags) >= 9 and all(tag == 0x02 for tag in tags[:9]):
        return True
    # SEC1 ECPrivateKey contains version 1 followed by the private OCTET STRING.
    if version == 1 and len(tags) >= 2 and tags[1] == 0x04:
        return True
    # PKCS#12 PFX starts with version 3 and an AuthenticatedSafe ContentInfo.
    return version == 3 and len(tags) >= 2 and tags[1] == 0x30


def _binary_secret_reason(path: str, value: bytes) -> str | None:
    """Recognize private-key and credential containers before text decoding."""

    lowered = PurePosixPath(path).name.casefold()
    if lowered.endswith((".p8", ".pk8", ".p12", ".pfx", ".jks", ".jceks", ".keystore")):
        return "credential-container filename"
    if lowered.endswith(".key") and not lowered.endswith(".pub.key"):
        return "private-key filename"
    if value.startswith(b"openssh-key-v1\x00"):
        return "OpenSSH private-key encoding"
    if value[:4] in {bytes.fromhex("feedfeed"), bytes.fromhex("cececece")}:
        return "Java credential-store encoding"
    if _looks_like_private_key_der(value):
        return "DER private-key or credential-container encoding"
    return None


def _archive_container_kind(value: bytes) -> str | None:
    """Identify prohibited archive or compression bytes without trusting a suffix."""

    signatures = (
        (b"\x1f\x8b\x08", "gzip"),
        (b"BZh", "bzip2"),
        (b"\xfd7zXZ\x00", "xz"),
        (b"7z\xbc\xaf'\x1c", "7z"),
    )
    for signature, kind in signatures:
        if value.startswith(signature):
            return kind
    return supply_chain_archive._archive_stream_kind(BytesIO(value))


def _evidence_file(evidence_dir: Path, binding: dict[str, Any], label: str) -> tuple[Path, bytes]:
    name = binding["fileName"]
    relative = Path(name)
    if relative.is_absolute() or len(relative.parts) != 1 or ".." in relative.parts:
        raise ValueError(f"{label} file name is unsafe")
    path = evidence_dir / relative
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} is missing or is not a regular file")
    metadata = path.stat(follow_symlinks=False)
    if metadata.st_nlink != 1:
        raise ValueError(f"{label} has ambiguous hard-link identity")
    value = path.read_bytes()
    if len(value) != binding["size"] or _digest_bytes(value) != binding["digest"]:
        raise ValueError(f"{label} bytes differ from the execution contract")
    return path, value


def _bound_json(
    contract: dict[str, Any], evidence_dir: Path | None, field: str, expected_schema: str
) -> tuple[dict[str, Any] | None, list[str]]:
    binding = contract["evidence"].get(field)
    if binding is None:
        return None, [f"{field} evidence is not bound"]
    if evidence_dir is None:
        return None, ["an evidence directory is required"]
    errors: list[str] = []
    if binding.get("schema") != expected_schema:
        errors.append(f"{field} schema identity differs")
    try:
        _path, raw = _evidence_file(evidence_dir, binding, field)
        value = read_json_bytes(raw, field)
    except (OSError, ValueError) as exc:
        return None, [*errors, str(exc)]
    if not isinstance(value, dict):
        return None, [*errors, f"{field} evidence is not a JSON object"]
    errors.extend(validate_schema(value, expected_schema))
    if "provenance" in value and binding.get("provenance") != value.get("provenance"):
        errors.append(f"{field} protected artifact provenance differs from the execution contract")
    findings = scan_value(_redaction_view(value))
    if expected_schema == HANDOFF_SCHEMA:
        # Immutable repository and workflow identities are slash-delimited public
        # identifiers. Their exact values are bound to the more restrictive
        # execution-contract schema by _handoff_errors below.
        findings = [item for item in findings if item["category"] != "absolute-path"]
    if findings:
        errors.append(f"{field} evidence contains prohibited or unredacted material")
    return value, sorted(set(errors))


def _bound_file(
    contract: dict[str, Any],
    evidence_dir: Path | None,
    field: str,
    expected_schema: str | None,
) -> tuple[Path | None, bytes | None, list[str]]:
    """Load exact contract-bound bytes without assuming that they are JSON."""

    binding = contract["evidence"].get(field)
    if binding is None:
        return None, None, [f"{field} evidence is not bound"]
    if evidence_dir is None:
        return None, None, ["an evidence directory is required"]
    errors: list[str] = []
    if binding.get("schema") != expected_schema:
        errors.append(f"{field} schema identity differs")
    try:
        path, raw = _evidence_file(evidence_dir, binding, field)
    except (OSError, ValueError) as exc:
        return None, None, [*errors, str(exc)]
    return path, raw, sorted(set(errors))


def _bound_artifact_json(
    contract: dict[str, Any],
    evidence_dir: Path | None,
    field: str,
    member_name: str,
    expected_schema: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Authenticate JSON as an exact member of its retained Actions ZIP."""

    path, _raw, errors = _bound_file(contract, evidence_dir, field, None)
    binding = contract["evidence"].get(field)
    if path is None or binding is None:
        return None, errors
    if binding["digest"] != binding["provenance"]["artifactDigest"]:
        errors.append(f"{field} retained artifact digest differs from protected provenance")
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if (
                len(members) > 20_000
                or sum(row.file_size for row in members) > 5_000_000_000
                or any(not _safe_zip_member(row) for row in members)
            ):
                raise ValueError("unsafe member table")
            matches = [row for row in members if row.filename == member_name]
            if len(matches) != 1 or matches[0].is_dir() or matches[0].file_size > 10_000_000:
                raise ValueError("missing exact summary member")
            value = read_json_bytes(archive.read(matches[0]), field)
    except (OSError, ValueError, zipfile.BadZipFile):
        return None, [*errors, f"{field} retained Actions artifact is unsafe or malformed"]
    if not isinstance(value, dict):
        return None, [*errors, f"{field} retained summary is not a JSON object"]
    errors.extend(validate_schema(value, expected_schema))
    if scan_value(_redaction_view(value)):
        errors.append(f"{field} retained summary contains prohibited material")
    return value, sorted(set(errors))


def _catalog_authority_summary(archive_path: Path) -> dict[str, Any]:
    """Read the PR-293 summary only after canonical archive safety inspection."""

    catalog_authority_closeout.inspect_artifact_safety(archive_path)
    with zipfile.ZipFile(archive_path) as archive:
        members = [row for row in archive.infolist() if not row.is_dir()]
        expected_names = {
            catalog_authority_closeout.SUMMARY_MEMBER,
            catalog_authority_closeout.REPORT_MEMBER,
            catalog_authority_closeout.REDACTION_MEMBER,
        }
        if {row.filename for row in members} != expected_names or len(members) != 3:
            raise ValueError(
                "catalog authority artifact does not contain the exact closeout member set"
            )
        by_name = {row.filename: row for row in members}
        candidate = read_json_bytes(
            archive.read(by_name[catalog_authority_closeout.SUMMARY_MEMBER]),
            "catalog authority summary",
        )
    if not isinstance(candidate, dict):
        raise ValueError("catalog authority summary is not a JSON object")
    return candidate


def _safe_zip_member(info: zipfile.ZipInfo) -> bool:
    path = PurePosixPath(info.filename)
    mode = info.external_attr >> 16
    file_type = stat.S_IFMT(mode)
    return (
        not info.is_dir()
        and not info.flag_bits & 1
        and info.create_system in {0, 3}
        and not path.is_absolute()
        and bool(path.parts)
        and all(part not in {"", ".", "..", "__MACOSX", ".DS_Store"} for part in path.parts)
        and not any(part.startswith("._") for part in path.parts)
        and "\\" not in info.filename
        and "\x00" not in info.filename
        and not stat.S_ISLNK(mode)
        and file_type in {0, stat.S_IFREG}
        and info.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
    )


def _members(
    archive: zipfile.ZipFile,
    label: str,
    policy: dict[str, Any],
    *,
    stored: bool = False,
) -> dict[str, zipfile.ZipInfo]:
    infos = archive.infolist()
    names = [info.filename for info in infos]
    bounds = policy["archiveBounds"]
    if archive.comment or not infos or len(infos) > bounds["maximumMembers"]:
        raise ValueError(f"{label} has an invalid member table")
    if names != sorted(names) or len(names) != len(set(names)) or len(names) != len({name.casefold() for name in names}):
        raise ValueError(f"{label} has duplicate, colliding, or non-canonical members")
    if any(not _safe_zip_member(info) for info in infos):
        raise ValueError(f"{label} contains an unsafe archive member")
    if stored and any(info.compress_type != zipfile.ZIP_STORED for info in infos):
        raise ValueError(f"{label} is not a deterministic stored-entry archive")
    if sum(info.file_size for info in infos) > bounds["maximumExpandedBytes"]:
        raise ValueError(f"{label} exceeds its expanded byte bound")
    return {info.filename: info for info in infos}


def _strict_properties(value: bytes, label: str) -> dict[str, str]:
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not UTF-8") from exc
    properties: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        if "=" not in line or line[:1].isspace() or line.endswith("\\"):
            raise ValueError(f"{label} contains a non-canonical property")
        name, item = line.split("=", 1)
        if not name or name in properties:
            raise ValueError(f"{label} contains an empty or duplicate property")
        properties[name] = item
    return properties


_JAVA_TRIM_CHARACTERS = "".join(chr(codepoint) for codepoint in range(0x21))
_PROPERTIES_CONTROL_ESCAPES = {
    "t": "\t",
    "n": "\n",
    "r": "\r",
    "f": "\f",
}


def _java_trim(value: str) -> str:
    return value.strip(_JAVA_TRIM_CHARACTERS)


def _manifest_separator(line: str) -> int:
    equals = line.find("=")
    colon = line.find(":")
    if equals < 0:
        return colon
    if colon < 0:
        return equals
    return min(equals, colon)


def _manifest_unicode_escape(value: str, offset: int, label: str) -> str:
    digits = value[offset + 2 : offset + 6]
    if len(digits) != 4 or re.fullmatch(r"[0-9A-Fa-f]{4}", digits) is None:
        raise ValueError(f"{label} contains an invalid unicode escape")
    return chr(int(digits, 16))


def _decode_manifest_component(
    value: str,
    label: str,
    *,
    decode_control_escapes: bool,
    decode_unicode_escapes: bool,
) -> str:
    decoded: list[str] = []
    offset = 0
    while offset < len(value):
        character = value[offset]
        if character != "\\" or offset + 1 >= len(value):
            decoded.append(character)
            offset += 1
            continue
        escaped = value[offset + 1]
        if escaped in _PROPERTIES_CONTROL_ESCAPES:
            decoded.append(
                _PROPERTIES_CONTROL_ESCAPES[escaped]
                if decode_control_escapes
                else "\\" + escaped
            )
            offset += 2
        elif escaped == "\\":
            decoded.append("\\")
            offset += 2
        elif escaped in " :=#!":
            decoded.append(escaped)
            offset += 2
        elif escaped == "u" and decode_unicode_escapes:
            decoded.append(_manifest_unicode_escape(value, offset, label))
            offset += 6
        else:
            decoded.append("\\" + escaped)
            offset += 2
    return "".join(decoded)


def _contains_manifest_unicode_escape(value: str) -> bool:
    for offset in range(max(0, len(value) - 5)):
        if (
            value[offset] == "\\"
            and value[offset + 1] in {"u", "U"}
            and re.fullmatch(r"[0-9A-Fa-f]{4}", value[offset + 2 : offset + 6])
        ):
            return True
    return False


def _contains_plain_manifest_backslash(value: str) -> bool:
    return any(
        value[offset] == "\\" and value[offset + 1] not in {"u", "U"}
        for offset in range(max(0, len(value) - 1))
    )


def _decode_manifest_unicode_value(key: str, raw_value: str) -> bool:
    if key != "app.exec":
        return True
    return (
        "/" in raw_value
        or "\\\\" in raw_value
        or raw_value.startswith(("\\u", "\\U"))
        or (
            _contains_manifest_unicode_escape(raw_value)
            and not _contains_plain_manifest_backslash(raw_value)
        )
    )


def _manifest_properties(value: bytes, label: str) -> dict[str, str]:
    """Parse the signed manifest with AppBundleManifestParser semantics."""
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not UTF-8") from exc
    if text.startswith("\ufeff"):
        text = text[1:]
    properties: dict[str, str] = {}
    for line in re.split(r"\r\n|\n|\r", text):
        trimmed = _java_trim(line)
        if not trimmed or trimmed.startswith(("#", "!")):
            continue
        separator = _manifest_separator(line)
        if separator < 0:
            raise ValueError(f"{label} contains an invalid property")
        key = _decode_manifest_component(
            _java_trim(line[:separator]),
            label,
            decode_control_escapes=True,
            decode_unicode_escapes=True,
        )
        if not key:
            raise ValueError(f"{label} contains an empty property")
        raw_item = _java_trim(line[separator + 1 :])
        item = _decode_manifest_component(
            raw_item,
            label,
            decode_control_escapes=False,
            decode_unicode_escapes=_decode_manifest_unicode_value(key, raw_item),
        )
        if key in properties:
            raise ValueError(f"{label} contains a duplicate decoded property")
        properties[key] = item
    return properties


_DISTRIBUTION_SIDECARS = frozenset(
    {
        "cryptad-app.digests",
        "cryptad-app.signature",
        "cryptad-app.catalog",
        "cryptad-app.catalog.signature",
    }
)


def _normalized_exec_path(value: str) -> str:
    normalized = value.strip().replace("\\", "/")
    if (
        not normalized
        or normalized.startswith("/")
        or re.match(r"^[A-Za-z]:", normalized)
    ):
        raise ValueError("bundle manifest app.exec must be a relative path")
    segments = normalized.split("/")
    if any(not segment.strip() or segment in {".", ".."} for segment in segments):
        raise ValueError("bundle manifest app.exec must be normalized under the app root")
    if normalized.casefold() in _DISTRIBUTION_SIDECARS:
        raise ValueError("bundle manifest app.exec must not name a distribution sidecar")
    return normalized


def _bundle_launch_metadata(
    info: zipfile.ZipInfo,
    value: bytes,
) -> tuple[bool, str | None]:
    lowered = info.filename.casefold()
    if lowered.endswith((".bat", ".cmd", ".com", ".sh")):
        return True, None
    if value.startswith(b"#!"):
        return True, None
    if len(value) >= 64 and value.startswith(b"MZ"):
        pe_offset = int.from_bytes(value[0x3C:0x40], "little")
        if pe_offset >= 64 and len(value) >= pe_offset + 24 and value[pe_offset : pe_offset + 4] == b"PE\x00\x00":
            characteristics = int.from_bytes(value[pe_offset + 22 : pe_offset + 24], "little")
            if characteristics & 0x0002 and not characteristics & 0x2000:
                return True, None
    unix_mode = info.external_attr >> 16
    if unix_mode & 0o111:
        return True, "true"
    return False, None


def _validate_bundle_manifest(
    manifest: dict[str, str],
    bundle: zipfile.ZipFile,
    members: dict[str, zipfile.ZipInfo],
    app_id: str,
    app_version: str,
) -> tuple[str, str | None]:
    required = ("manifest.version", "app.id", "app.name", "app.version", "app.exec")
    if any(not manifest.get(name, "").strip() for name in required):
        raise ValueError("bundle manifest omits a required AppHost field")
    if manifest["manifest.version"] != "1":
        raise ValueError("bundle manifest version is unsupported")
    if re.fullmatch(r"[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?", manifest["app.id"].strip()) is None:
        raise ValueError("bundle manifest app.id is invalid")
    if manifest["app.id"].strip() != app_id or manifest["app.version"].strip() != app_version:
        raise ValueError("bundle manifest app identity or version differs from the cohort")
    exec_path = _normalized_exec_path(manifest["app.exec"])
    exec_info = members.get(exec_path)
    launchable, executable = (
        _bundle_launch_metadata(exec_info, bundle.read(exec_info))
        if exec_info is not None
        else (False, None)
    )
    if not launchable:
        raise ValueError("bundle manifest app.exec is missing or not launchable")

    ui_mode = manifest.get("app.ui.mode")
    ui_entry = manifest.get("app.ui.entry")
    if ui_mode == "static" or (ui_mode is None and ui_entry and not ui_entry.startswith("/")):
        if not ui_entry:
            raise ValueError("bundle manifest static UI omits app.ui.entry")
        ui_path = _normalized_exec_path(ui_entry)
        if ui_path not in members:
            raise ValueError("bundle manifest app.ui.entry is missing from the bundle")

    for name, command in manifest.items():
        if name.startswith("app.data.migration.") and name.endswith(".command"):
            command_path = _normalized_exec_path(command)
            if command_path not in members:
                raise ValueError("bundle manifest migration command is missing from the bundle")
    return exec_path, executable


def _bundle_errors(raw: bytes, row: dict[str, Any], contract: dict[str, Any], policy: dict[str, Any]) -> tuple[list[str], str | None]:
    errors: list[str] = []
    manifest_digest: str | None = None
    if len(raw) > policy["archiveBounds"]["maximumBundleBytes"]:
        return ["app bundle exceeds the configured byte bound"], None
    try:
        with zipfile.ZipFile(BytesIO(raw)) as bundle:
            members = _members(bundle, "external app bundle", policy)
            required = {"cryptad-app.properties", "cryptad-app.digests", "cryptad-app.signature"}
            if not required.issubset(members):
                raise ValueError("external app bundle omits required signed sidecars")
            manifest_bytes = bundle.read(members["cryptad-app.properties"])
            digest_bytes = bundle.read(members["cryptad-app.digests"])
            signature_bytes = bundle.read(members["cryptad-app.signature"])
            manifest_digest = _digest_bytes(manifest_bytes)
            signature_properties = _strict_properties(signature_bytes, "bundle signature sidecar")
            expected_signature_fields = {
                "signature.version", "signature.algorithm", "signature.key.id",
                "signature.payload", "signature.value.base64",
            }
            if set(signature_properties) != expected_signature_fields:
                raise ValueError("bundle signature sidecar has missing or unknown fields")
            app = contract["externalApp"]
            if (
                signature_properties["signature.version"] != "1"
                or signature_properties["signature.algorithm"] != "Ed25519"
                or signature_properties["signature.key.id"] != app["publisherKeyId"]
                or signature_properties["signature.payload"] != "cryptad-app.digests"
            ):
                raise ValueError("bundle signature sidecar does not bind the approved publisher")
            if _digest_bytes(signature_bytes) != row["bundleSignatureDigest"]:
                errors.append("bundle signature sidecar digest differs from the cohort")
            errors.extend(_verify(app["publisherPublicKeySpkiBase64"], digest_bytes, signature_properties["signature.value.base64"], "external app bundle"))
            manifest = _manifest_properties(manifest_bytes, "bundle manifest")
            exec_path, expected_exec_flag = _validate_bundle_manifest(
                manifest,
                bundle,
                members,
                app["appId"],
                row["appVersion"],
            )
            digest_properties = _strict_properties(digest_bytes, "bundle digest sidecar")
            if digest_properties.pop("digest.version", None) != "1" or digest_properties.pop("digest.algorithm", None) != "SHA-256":
                raise ValueError("bundle digest sidecar header is invalid")
            entries: list[tuple[str, str, str | None]] = []
            index = 0
            while f"file.{index}.path" in digest_properties:
                path = digest_properties.pop(f"file.{index}.path")
                sha = digest_properties.pop(f"file.{index}.sha256", None)
                executable = digest_properties.pop(f"file.{index}.executable", None)
                if executable not in {None, "true", "false"} or sha is None or re.fullmatch(r"[0-9a-f]{64}", sha) is None:
                    raise ValueError("bundle digest sidecar contains an invalid file row")
                entries.append((path, sha, executable))
                index += 1
            if not entries or digest_properties:
                raise ValueError("bundle digest sidecar has unknown or non-contiguous fields")
            paths = [path for path, _sha, _executable in entries]
            if paths != sorted(paths) or len(paths) != len(set(paths)) or "cryptad-app.properties" not in paths:
                raise ValueError("bundle digest sidecar file inventory is non-canonical")
            payload_members = set(members).difference({"cryptad-app.digests", "cryptad-app.signature"})
            if set(paths) != payload_members:
                raise ValueError("bundle digest sidecar does not cover the exact payload")
            for path, expected_sha, executable in entries:
                expected_executable = expected_exec_flag if path == exec_path else None
                if executable != expected_executable:
                    errors.append(f"bundle executable metadata mismatch for {path}")
                value = bundle.read(members[path])
                if hashlib.sha256(value).hexdigest() != expected_sha:
                    errors.append(f"bundle payload digest mismatch for {path}")
                if _archive_container_kind(value) is not None:
                    errors.append(
                        f"bundle member is an unexpected nested archive: {path}"
                    )
                binary_reason = _binary_secret_reason(path, value)
                if binary_reason is not None:
                    errors.append(
                        f"bundle member contains prohibited binary material: {path}"
                    )
                text = value.decode("utf-8", errors="ignore")
                if len(value) > policy["archiveBounds"]["maximumTextBytes"] and text:
                    errors.append(f"bundle text member exceeds its byte bound: {path}")
                elif scan_manifest_scalar(text):
                    errors.append(f"bundle member contains prohibited material: {path}")
    except (KeyError, OSError, ValueError, zipfile.BadZipFile) as exc:
        errors.append(str(exc))
    return sorted(set(errors)), manifest_digest


_SUBMISSION_METADATA_FIELDS = frozenset(
    {
        "schemaVersion",
        "submissionId",
        "submissionCreatedAt",
        "submissionType",
        "resubmissionOf",
        "appId",
        "appVersion",
        "bundleDigest",
        "bundleSignatureKeyId",
        "catalogEntryDigest",
        "apiTargetStability",
        "experimentalCapabilitiesAccepted",
        "requestedPermissions",
        "permissionRationaleDigest",
        "sandboxRequirement",
        "appDataSchemaDeclared",
        "appDataMigrationDeclared",
        "backupRestoreDeclared",
        "maintainer",
        "sourceReference",
        "redactionScanDigest",
        "nonProduction",
    }
)


def _manifest_boolean(manifest: dict[str, str], name: str, default: bool = False) -> bool:
    value = manifest.get(name)
    if value is None:
        return default
    normalized = value.strip().casefold()
    if normalized not in {"true", "false"}:
        raise ValueError(f"bundle manifest {name} is not a Boolean")
    return normalized == "true"


def _manifest_permissions(manifest: dict[str, str]) -> list[str]:
    value = manifest.get("app.permissions")
    if value is None:
        return []
    permissions = [item.strip().casefold() for item in value.split(",")]
    if any(not item for item in permissions):
        raise ValueError("bundle manifest app.permissions contains a blank entry")
    return list(dict.fromkeys(permissions))


def _submission_redaction_digest(member_names: set[str]) -> str:
    subject = "".join(
        f"{name}\n"
        for name in sorted(member_names.difference({"crypta-app-submission.json"}))
    ) + "redaction-scan-v1\n"
    return hashlib.sha256(subject.encode("utf-8")).hexdigest()


def _source_repository_identity(source_reference: dict[str, Any]) -> str:
    if set(source_reference).difference({"url", "revision"}):
        raise ValueError("submission source reference has unknown fields")
    raw_url = source_reference.get("url")
    if not isinstance(raw_url, str):
        raise ValueError("submission source reference URL is invalid")
    parsed = urlsplit(raw_url)
    if (
        parsed.scheme.casefold() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("submission source reference URL is invalid")
    host = parsed.hostname.casefold()
    if parsed.port is not None:
        host += f":{parsed.port}"
    path = parsed.path.strip("/")
    return host + (f"/{path}" if path else "")


def _required_review_evidence_errors(
    package: zipfile.ZipFile,
    members: dict[str, zipfile.ZipInfo],
    manifest: dict[str, str],
    metadata: dict[str, Any],
    permissions: list[str],
) -> list[str]:
    errors: list[str] = []
    sandbox_mode = manifest.get("sandbox.mode", "none").strip().casefold()
    sandbox_required = _manifest_boolean(manifest, "sandbox.required")
    schema_declared = bool(
        manifest.get("app.data.schema.current", "").strip()
        or manifest.get("app.data.schema.namespaces", "").strip()
    )
    migration_declared = bool(manifest.get("app.data.migrations", "").strip())
    owns_durable_data = schema_declared or any(
        permission.startswith("app.data.") for permission in permissions
    )
    required = {
        "review/permission-rationale.md": bool(permissions),
        "review/sandbox-rationale.md": sandbox_mode != "none" or sandbox_required,
        "review/data-schema.md": schema_declared,
        "review/backup-restore.md": owns_durable_data,
    }
    for name, is_required in required.items():
        if not is_required:
            continue
        info = members.get(name)
        if info is None:
            errors.append(f"submission package omits required review evidence: {name}")
            continue
        try:
            if not package.read(info).decode("utf-8").strip("\ufeff").strip():
                errors.append(f"submission required review evidence is empty: {name}")
        except UnicodeDecodeError:
            errors.append(f"submission required review evidence is not UTF-8: {name}")
    expected = {
        "apiTargetStability": manifest.get("api.targetStability", "experimental").strip().casefold(),
        "experimentalCapabilitiesAccepted": _manifest_boolean(
            manifest, "api.experimentalCapabilitiesAccepted"
        ),
        "requestedPermissions": permissions,
        "sandboxRequirement": sandbox_mode + (":required" if sandbox_required else ""),
        "appDataSchemaDeclared": schema_declared,
        "appDataMigrationDeclared": migration_declared,
        "backupRestoreDeclared": "review/backup-restore.md" in members,
    }
    for name, value in expected.items():
        if metadata.get(name) != value:
            errors.append(f"submission metadata {name} differs from the reviewed bundle")
    return errors


def _submission_errors(
    raw: bytes,
    row: dict[str, Any],
    bundle_raw: bytes,
    policy: dict[str, Any],
    *,
    allow_non_production: bool = False,
) -> list[str]:
    errors: list[str] = []
    if len(raw) > policy["archiveBounds"]["maximumSubmissionBytes"]:
        return ["submission package exceeds the configured byte bound"]
    try:
        with zipfile.ZipFile(BytesIO(raw)) as package:
            members = _members(package, "external submission package", policy, stored=True)
            metadata_info = members.get("crypta-app-submission.json")
            artifact_info = members.get("artifacts/app-bundle.zip")
            if metadata_info is None or artifact_info is None:
                raise ValueError("submission package omits metadata or bundle artifact")
            embedded = package.read(artifact_info)
            if embedded != bundle_raw:
                errors.append("submission package embeds different bundle bytes")
            metadata = read_json_bytes(package.read(metadata_info), "submission metadata")
            if not isinstance(metadata, dict):
                raise ValueError("submission metadata is not an object")
            if set(metadata).difference(_SUBMISSION_METADATA_FIELDS):
                raise ValueError("submission metadata has unknown fields")
            required_metadata = _SUBMISSION_METADATA_FIELDS.difference(
                {
                    "resubmissionOf",
                    "catalogEntryDigest",
                    "permissionRationaleDigest",
                }
            )
            if not required_metadata.issubset(metadata):
                raise ValueError("submission metadata omits required fields")
            if metadata.get("schemaVersion") != 1:
                errors.append("submission metadata schema version is unsupported")
            _timestamp(metadata.get("submissionCreatedAt"), "submission creation time")
            expected = {
                "submissionId": row["submissionId"],
                "submissionType": row["submissionType"],
                "appId": row.get("appId"),
                "appVersion": row["appVersion"],
                "bundleDigest": row["bundleDigest"].removeprefix("sha256:"),
                "bundleSignatureKeyId": row.get("publisherKeyId"),
            }
            # appId and publisherKeyId are filled by the caller's contract rather than the row.
            for name, value in expected.items():
                if value is not None and metadata.get(name) != value:
                    errors.append(f"submission metadata {name} differs from the authenticated cohort")
            actual_link = metadata.get("resubmissionOf")
            if actual_link != row["resubmissionOf"]:
                errors.append("submission metadata resubmission link differs from the cohort")
            if metadata.get("nonProduction") is not False and not (
                allow_non_production and metadata.get("nonProduction") is True
            ):
                errors.append("non-production submission cannot satisfy operational handoff")
            maintainer_metadata = metadata.get("maintainer")
            if not isinstance(maintainer_metadata, dict) or set(maintainer_metadata) != {
                "name",
                "contact",
            }:
                errors.append("submission maintainer metadata shape is invalid")
            source_reference = metadata.get("sourceReference")
            if not isinstance(source_reference, dict):
                errors.append("submission source reference metadata shape is invalid")
            else:
                source_identity = _source_repository_identity(source_reference)
                expected_source_identity = row.get("sourceRepositoryIdentity")
                if (
                    expected_source_identity is not None
                    and source_identity.casefold() != expected_source_identity.casefold()
                ):
                    errors.append("submission source repository differs from the authenticated source")
                expected_source_revision = row.get("sourceRevision")
                if (
                    expected_source_revision is not None
                    and source_reference.get("revision") != expected_source_revision
                ):
                    errors.append("submission source revision differs from the authenticated source")

            with zipfile.ZipFile(BytesIO(bundle_raw)) as bundle:
                bundle_members = _members(bundle, "submission app bundle", policy)
                reviewed_bundle = {
                    name.removeprefix("bundle/"): info
                    for name, info in members.items()
                    if name.startswith("bundle/")
                }
                if set(reviewed_bundle) != set(bundle_members):
                    errors.append(
                        "submission reviewed bundle tree differs from the packaged app bundle"
                    )
                else:
                    for name, info in reviewed_bundle.items():
                        if package.read(info) != bundle.read(bundle_members[name]):
                            errors.append(
                                f"submission reviewed bundle bytes differ for {name}"
                            )
                            break
                manifest_info = reviewed_bundle.get("cryptad-app.properties")
                signature_info = reviewed_bundle.get("cryptad-app.signature")
                if manifest_info is None or signature_info is None:
                    errors.append("submission reviewed bundle omits required sidecars")
                else:
                    manifest = _manifest_properties(
                        package.read(manifest_info), "submission reviewed bundle manifest"
                    )
                    permissions = _manifest_permissions(manifest)
                    errors.extend(
                        _required_review_evidence_errors(
                            package, members, manifest, metadata, permissions
                        )
                    )
                    signature_properties = _strict_properties(
                        package.read(signature_info), "submission reviewed bundle signature"
                    )
                    if (
                        signature_properties.get("signature.key.id")
                        != metadata.get("bundleSignatureKeyId")
                    ):
                        errors.append(
                            "submission metadata bundle signature key differs from the reviewed bundle"
                        )

            maintainer_info = members.get("metadata/maintainer.json")
            source_info = members.get("metadata/source.json")
            if maintainer_info is None or source_info is None:
                errors.append("submission package omits canonical maintainer or source metadata")
            else:
                maintainer = read_json_bytes(
                    package.read(maintainer_info), "submission maintainer metadata"
                )
                source = read_json_bytes(package.read(source_info), "submission source metadata")
                if maintainer != metadata.get("maintainer"):
                    errors.append("submission maintainer sidecar differs from metadata")
                if source != metadata.get("sourceReference"):
                    errors.append("submission source sidecar differs from metadata")
            permission_info = members.get("review/permission-rationale.md")
            actual_permission_digest = (
                hashlib.sha256(package.read(permission_info)).hexdigest()
                if permission_info is not None
                else None
            )
            if metadata.get("permissionRationaleDigest") != actual_permission_digest:
                errors.append("submission permission rationale digest differs")
            catalog_info = members.get("artifacts/catalog-entry.properties")
            actual_catalog_digest = (
                hashlib.sha256(package.read(catalog_info)).hexdigest()
                if catalog_info is not None
                else None
            )
            if metadata.get("catalogEntryDigest") != actual_catalog_digest:
                errors.append("submission catalog entry digest differs")
            if metadata.get("redactionScanDigest") != _submission_redaction_digest(set(members)):
                errors.append("submission redaction scan digest differs")
            text_suffixes = (".json", ".md", ".properties", ".txt", ".yaml", ".yml", ".xml")
            archive_suffixes = (".zip", ".jar", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z")
            for name, info in members.items():
                if name == "artifacts/app-bundle.zip":
                    continue
                lowered = name.casefold()
                value = package.read(info)
                if (
                    lowered.endswith(archive_suffixes)
                    or _archive_container_kind(value) is not None
                ):
                    errors.append(f"submission package contains an unexpected nested archive: {name}")
                    continue
                binary_reason = _binary_secret_reason(name, value)
                if binary_reason is not None:
                    errors.append(
                        f"submission member contains prohibited binary material: {name}"
                    )
                if lowered.endswith(text_suffixes):
                    if len(value) > policy["archiveBounds"]["maximumTextBytes"]:
                        errors.append(f"submission text member exceeds its byte bound: {name}")
                        continue
                    try:
                        text = value.decode("utf-8")
                    except UnicodeDecodeError:
                        errors.append(f"submission text member is not UTF-8: {name}")
                        continue
                else:
                    text = value.decode("utf-8", errors="ignore")
                findings = (
                    scan_manifest_scalar(text)
                    if name.startswith("bundle/")
                    else scan_value(text)
                )
                if findings:
                    errors.append(f"submission member contains prohibited material: {name}")
    except (KeyError, OSError, TypeError, ValueError, zipfile.BadZipFile) as exc:
        errors.append(str(exc))
    return sorted(set(errors))


def _workload_subject(contract: dict[str, Any], handoff: dict[str, Any]) -> bytes:
    workload = copy.deepcopy(handoff["workload"])
    workload["attestationDigest"] = ZERO_DIGEST
    workload.pop("signatureBase64", None)
    value = {
        "domain": "cryptad.stable-1.0.external-third-party-app-pilot.workload-attestation.v1",
        "pilotId": handoff["pilotId"],
        "appId": handoff["appId"],
        "source": handoff["source"],
        "provenance": handoff["provenance"],
        "publisherKeyId": handoff["publisherKeyId"],
        "publisherFingerprint": handoff["publisherFingerprint"],
        "cohort": [
            {name: row[name] for name in ("cohortId", "submissionDigest", "bundleDigest", "bundleSignatureDigest")}
            for row in handoff["cohort"]
        ],
        "workload": workload,
    }
    return value["domain"].encode("ascii") + b"\x00" + _canonical_bytes(value)


def _handoff_errors(contract: dict[str, Any], handoff: dict[str, Any], evidence_dir: Path, policy: dict[str, Any], evaluation: datetime) -> list[str]:
    errors: list[str] = []
    app = contract["externalApp"]
    profile = app["workloadProfile"]
    if handoff["pilotId"] != contract["pilotId"] or handoff["appId"] != app["appId"]:
        errors.append("external handoff pilot or app identity differs")
    provenance = handoff["provenance"]
    if (
        provenance["repositoryIdentity"].casefold()
        != app["source"]["repositoryIdentity"].casefold()
        or provenance["workflowPath"] != app["workloadProfile"]["pipelineDefinition"]
        or str(provenance["runId"]) != handoff["workload"]["runId"]
    ):
        errors.append("external handoff provenance differs from the authenticated workload")
    if provenance["workflowCommit"] != profile["pipelineRevision"]:
        errors.append(
            "external handoff workflow commit differs from the approved pipeline revision"
        )
    if handoff["source"] != {name: app["source"][name] for name in ("repositoryIdentity", "revision", "archiveDigest", "treeDigest")}:
        errors.append("external handoff source provenance differs from the contract")
    if handoff["publisherKeyId"] != app["publisherKeyId"] or handoff["publisherFingerprint"] != app["publisherFingerprint"]:
        errors.append("external handoff publisher identity differs")
    expected_classification = "fixture" if contract["fixtureOnly"] or contract["selfTest"] else "authenticated-external-developer"
    if handoff["evidenceClassification"] != expected_classification:
        errors.append("external handoff evidence classification differs")
    if handoff["handoffDigest"] != _semantic_digest(handoff, "handoffDigest"):
        errors.append("external handoff semantic digest is invalid")
    for field in ("profileId", "providerId", "organizationId", "accountId", "issuer", "audience", "subject", "pipelineDefinition", "pipelineRevision"):
        if handoff["workload"].get(field) != profile.get(field):
            errors.append(f"workload attestation {field} differs from the approved profile")
    expected_workload_digest = _digest_bytes(_workload_subject(contract, handoff))
    if handoff["workload"]["attestationDigest"] != expected_workload_digest:
        errors.append("workload attestation digest is invalid")
    errors.extend(_verify(profile["workloadPublicKeySpkiBase64"], _workload_subject(contract, handoff), handoff["workload"]["signatureBase64"], "external workload attestation"))
    errors.extend(
        _freshness_errors(
            _timestamp(handoff["workload"]["verifiedAt"], "workload verification time"),
            evaluation,
            policy["freshness"]["maximumHandoffAgeSeconds"],
            "workload verification",
        )
    )
    if tuple(row["cohortId"] for row in handoff["cohort"]) != COHORT_IDS:
        errors.append("external handoff cohort is incomplete or reordered")
        return sorted(set(errors))
    contract_rows = {row["cohortId"]: row for row in contract["cohort"]}
    for handoff_row in handoff["cohort"]:
        row = contract_rows[handoff_row["cohortId"]]
        for field in ("submissionDigest", "bundleDigest", "bundleSignatureDigest"):
            if handoff_row[field] != row[field]:
                errors.append(f"{handoff_row['cohortId']} {field} differs from the contract")
        try:
            submission_path, submission_raw = _artifact_file(evidence_dir, handoff_row["submissionFile"], handoff_row["submissionDigest"], handoff_row["submissionSize"], "submission artifact")
            bundle_path, bundle_raw = _artifact_file(evidence_dir, handoff_row["bundleFile"], handoff_row["bundleDigest"], handoff_row["bundleSize"], "app bundle")
            del submission_path, bundle_path
            bundle_errors, manifest_digest = _bundle_errors(bundle_raw, row, contract, policy)
            errors.extend(bundle_errors)
            enriched = dict(row)
            enriched["appId"] = app["appId"]
            enriched["publisherKeyId"] = app["publisherKeyId"]
            enriched["sourceRepositoryIdentity"] = app["source"]["repositoryIdentity"]
            enriched["sourceRevision"] = app["source"]["revision"]
            errors.extend(
                _submission_errors(
                    submission_raw,
                    enriched,
                    bundle_raw,
                    policy,
                    allow_non_production=contract["fixtureOnly"] or contract["selfTest"],
                )
            )
            attestation = handoff_row["attestation"]
            expected_attestation = {
                "pilotId": contract["pilotId"], "appId": app["appId"], "appVersion": row["appVersion"],
                "submissionId": row["submissionId"], "submissionType": row["submissionType"], "resubmissionOf": row["resubmissionOf"],
                "sourceRepositoryIdentity": app["source"]["repositoryIdentity"], "sourceRevision": app["source"]["revision"],
                "sourceArchiveDigest": app["source"]["archiveDigest"], "sourceTreeDigest": app["source"]["treeDigest"],
                "buildProviderId": profile["providerId"], "buildWorkflow": profile["pipelineDefinition"],
                "buildRunId": handoff["workload"]["runId"], "bundleDigest": row["bundleDigest"],
                "bundleSignatureDigest": row["bundleSignatureDigest"], "publisherKeyId": app["publisherKeyId"],
                "publisherFingerprint": app["publisherFingerprint"], "submissionDigest": row["submissionDigest"],
                "manifestDigest": manifest_digest,
            }
            for field, expected in expected_attestation.items():
                if attestation.get(field) != expected:
                    errors.append(f"developer attestation {field} differs for {row['cohortId']}")
            created = _timestamp(attestation["createdAt"], "developer attestation creation")
            effective = _timestamp(attestation["effectiveAt"], "developer attestation effective time")
            expires = _timestamp(attestation["expiresAt"], "developer attestation expiry")
            if not (created <= effective <= evaluation < expires):
                errors.append(f"developer attestation is stale or expired for {row['cohortId']}")
            errors.extend(
                _freshness_errors(
                    created,
                    evaluation,
                    policy["freshness"]["maximumHandoffAgeSeconds"],
                    f"developer attestation {row['cohortId']}",
                )
            )
            subject = attestation["domain"].encode("ascii") + b"\x00" + _canonical_bytes(attestation)
            errors.extend(_verify(app["publisherPublicKeySpkiBase64"], subject, handoff_row["attestationSignatureBase64"], f"developer attestation {row['cohortId']}"))
        except (KeyError, OSError, ValueError) as exc:
            errors.append(str(exc))
    return sorted(set(errors))


def _artifact_file(evidence_dir: Path, name: str, digest: str, size: int, label: str) -> tuple[Path, bytes]:
    relative = Path(name)
    if relative.is_absolute() or len(relative.parts) != 1 or ".." in relative.parts:
        raise ValueError(f"{label} file name is unsafe")
    path = evidence_dir / relative
    if path.is_symlink() or not path.is_file() or path.stat(follow_symlinks=False).st_nlink != 1:
        raise ValueError(f"{label} is missing or has ambiguous file identity")
    raw = path.read_bytes()
    if len(raw) != size or _digest_bytes(raw) != digest:
        raise ValueError(f"{label} bytes differ from the authenticated handoff")
    return path, raw


def _signed_receipt_errors(value: dict[str, Any], digest_field: str, key: dict[str, Any], label: str) -> list[str]:
    errors: list[str] = []
    if value.get(digest_field) != _semantic_digest(value, digest_field):
        errors.append(f"{label} semantic digest is invalid")
    errors.extend(_verify(key["publicKeySpkiBase64"], _signature_subject(value), value.get("signatureBase64"), label))
    return errors


def _without_digest_prefix(value: str) -> str:
    return value.removeprefix("sha256:")


def _standard_review_receipt_payload(receipt: dict[str, Any]) -> bytes:
    fields = (
        ("review.receipt.version", receipt["version"]),
        ("review.receipt.app.id", receipt["appId"]),
        ("review.receipt.app.version", receipt["appVersion"]),
        ("review.receipt.artifact.sha256", receipt["artifactSha256"]),
        ("review.receipt.artifact.size", receipt["artifactSizeBytes"]),
        ("review.receipt.bundle.key.id", receipt["bundleKeyId"]),
        ("review.receipt.policy.id", receipt["policyId"]),
        ("review.receipt.policy.version", receipt["policyVersion"]),
        ("review.receipt.status", receipt["status"]),
        ("review.receipt.reviewer.key.id", receipt["reviewerKeyId"]),
        ("review.receipt.reviewed.at", receipt["reviewedAt"]),
        ("review.receipt.expires.at", receipt["expiresAt"]),
        ("review.receipt.evidence.sha256", receipt["evidenceSha256"]),
        ("review.receipt.decision.reason.sha256", receipt["decisionReasonSha256"]),
        ("review.receipt.evidence.uri", receipt["evidenceUri"]),
        ("review.receipt.note", receipt["note"]),
    )
    return "".join(
        f"{name}={value}\n" for name, value in fields if value is not None
    ).encode("utf-8")


def _standard_review_receipt_bytes(receipt: dict[str, Any]) -> bytes:
    return _standard_review_receipt_payload(receipt) + (
        "review.receipt.signature.algorithm="
        + receipt["signatureAlgorithm"]
        + "\nreview.receipt.signature.value.base64="
        + receipt["signatureBase64"]
        + "\n"
    ).encode("utf-8")


def _standard_review_receipt_errors(
    receipt: dict[str, Any],
    receipt_digest: str,
    row: dict[str, Any],
    handoff_row: dict[str, Any],
    review: dict[str, Any],
    contract: dict[str, Any],
    reviewer: dict[str, Any],
    workload_verified_at: datetime,
    evaluation: datetime,
    maximum_age_seconds: int,
) -> list[str]:
    errors: list[str] = []
    expected = {
        "appId": contract["externalApp"]["appId"],
        "appVersion": row["appVersion"],
        "artifactSha256": _without_digest_prefix(row["bundleDigest"]),
        "artifactSizeBytes": handoff_row["bundleSize"],
        "bundleKeyId": contract["externalApp"]["publisherKeyId"],
        "policyId": review["policyId"],
        "policyVersion": review["policyVersion"],
        "status": row["expectedDecision"],
        "reviewerKeyId": reviewer["keyId"],
        "evidenceSha256": _without_digest_prefix(row["preReviewDigest"]),
        "decisionReasonSha256": _without_digest_prefix(
            next(
                item["decisionRecordDigest"]
                for item in review["rows"]
                if item["cohortId"] == row["cohortId"]
            )
        ),
        "signatureAlgorithm": "Ed25519",
    }
    for field, expected_value in expected.items():
        if receipt.get(field) != expected_value:
            errors.append(
                f"standard review receipt {field} differs for {row['cohortId']}"
            )
    if receipt.get("evidenceUri") is not None:
        errors.append(
            f"standard review receipt exposes an evidence URI for {row['cohortId']}"
        )
    try:
        reviewed_at = _timestamp(receipt["reviewedAt"], "standard review time")
        cohort_reviewed_at = _timestamp(review["reviewedAt"], "review cohort time")
        attestation = handoff_row["attestation"]
        attestation_ready_at = max(
            _timestamp(attestation["createdAt"], "developer attestation creation"),
            _timestamp(attestation["effectiveAt"], "developer attestation effective time"),
        )
        if reviewed_at > evaluation:
            errors.append(
                f"standard review receipt is from the future for {row['cohortId']}"
            )
        if reviewed_at > cohort_reviewed_at:
            errors.append(
                f"standard review receipt follows cohort completion for {row['cohortId']}"
            )
        if reviewed_at < max(workload_verified_at, attestation_ready_at):
            errors.append(
                f"standard review receipt predates authenticated handoff for {row['cohortId']}"
            )
        reviewer_valid_from = _timestamp(
            reviewer["validFrom"], "reviewer validity start"
        )
        reviewer_valid_until = _timestamp(
            reviewer["validUntil"], "reviewer validity end"
        )
        if not (reviewer_valid_from <= reviewed_at < reviewer_valid_until):
            errors.append(
                f"standard review receipt is outside reviewer validity for {row['cohortId']}"
            )
        expires_value = receipt["expiresAt"]
        if expires_value is not None:
            expires_at = _timestamp(expires_value, "standard review expiry")
            if not (reviewed_at < expires_at and evaluation < expires_at):
                errors.append(
                    f"standard review receipt is expired for {row['cohortId']}"
                )
        errors.extend(
            _freshness_errors(
                reviewed_at,
                evaluation,
                maximum_age_seconds,
                f"standard review receipt for {row['cohortId']}",
            )
        )
    except (KeyError, ValueError) as exc:
        errors.append(str(exc))
    serialized = _standard_review_receipt_bytes(receipt)
    if _digest_bytes(serialized) != receipt_digest:
        errors.append(
            f"standard review receipt digest is invalid for {row['cohortId']}"
        )
    errors.extend(
        _verify(
            reviewer["publicKeySpkiBase64"],
            _standard_review_receipt_payload(receipt),
            receipt.get("signatureBase64"),
            f"standard-review-receipt-{row['cohortId']}",
        )
    )
    return errors


def _transparency_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)


def _transparency_warnings(warnings: list[str]) -> str:
    return str(len(warnings)) + ":" + "".join(
        f"{len(warning.encode('utf-8'))}:{warning}" for warning in warnings
    )


def _transparency_canonical(record: dict[str, Any]) -> bytes:
    values = dict(record)
    values["warnings"] = _transparency_warnings(record["warnings"])
    return "".join(
        f"{field}={_transparency_value(values[field])}\n"
        for field in TRANSPARENCY_FIELDS
        if field != "recordHash"
    ).encode("utf-8")


def _transparency_jsonl(records: list[dict[str, Any]]) -> bytes:
    return b"".join(
        json.dumps(
            {field: record[field] for field in TRANSPARENCY_FIELDS},
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
        for record in records
    )


def _transparency_errors(
    contract: dict[str, Any], review: dict[str, Any], reviewer: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    records = review["transparencyRecords"]
    previous = ""
    for expected_sequence, record in enumerate(records, start=1):
        if record["sequence"] != expected_sequence:
            errors.append(
                f"review transparency sequence gap at {expected_sequence}"
            )
        if record["previousRecordHash"] != previous:
            errors.append(
                f"review transparency predecessor differs at {expected_sequence}"
            )
        recomputed = hashlib.sha256(_transparency_canonical(record)).hexdigest()
        if record["recordHash"] != recomputed:
            errors.append(
                f"review transparency record hash differs at {expected_sequence}"
            )
        previous = record["recordHash"]
    if review["transparencyRecordCount"] != len(records):
        errors.append("review transparency record count differs")
    if review["transparencyHead"] != "sha256:" + previous:
        errors.append("review transparency head differs")
    if review["transparencyHead"] == ZERO_DIGEST:
        errors.append("review transparency lineage is incomplete")
    if review["transparencyLogDigest"] != _digest_bytes(
        _transparency_jsonl(records)
    ):
        errors.append("review transparency JSONL digest differs")
    rows = {row["cohortId"]: row for row in contract["cohort"]}
    review_rows = {row["cohortId"]: row for row in review["rows"]}
    assignment_digest = _without_digest_prefix(review["assignmentDigest"])
    if review["assignmentDigest"] == ZERO_DIGEST:
        errors.append("review assignment digest is a placeholder")
    for cohort_id, row in rows.items():
        matching = [
            record
            for record in records
            if record["recordId"]
            == f"{row['submissionId']}:{record['kind']}"
            and record["subjectType"] == "submission"
            and record["catalogId"] == row["submissionId"]
            and record["appId"] == contract["externalApp"]["appId"]
            and record["appVersion"] == row["appVersion"]
            and record["artifactSha256"]
            == _without_digest_prefix(row["bundleDigest"])
        ]
        if not matching:
            errors.append(
                f"review transparency omits exact subject for {cohort_id}"
            )
            continue
        assignment_records = [
            record
            for record in matching
            if record["kind"] == "reviewer_assigned"
        ]
        pre_review_records = [
            record
            for record in matching
            if record["kind"] == "pre_review_completed"
        ]
        decision_records = [
            record
            for record in matching
            if record["kind"] == "review_decision_recorded"
        ]
        if len(assignment_records) != 1:
            errors.append(
                f"review transparency requires one reviewer assignment for {cohort_id}"
            )
        else:
            assignment = assignment_records[0]
            if (
                assignment["reviewerKeyId"] != reviewer["keyId"]
                or assignment["evidenceSha256"] != assignment_digest
                or assignment["warnings"]
                != ["assignmentReasonSha256=" + assignment_digest]
            ):
                errors.append(
                    f"review transparency assignment binding differs for {cohort_id}"
                )
        if len(pre_review_records) != 1:
            errors.append(
                f"review transparency requires one completed pre-review for {cohort_id}"
            )
        else:
            pre_review = pre_review_records[0]
            pre_review_statuses = {
                "preReviewStatus=pass",
                "preReviewStatus=warn",
            }
            if row["expectedDecision"] in {
                "rejected",
                "resubmission_requested",
            }:
                pre_review_statuses.add("preReviewStatus=fail")
            if (
                pre_review["evidenceSha256"]
                != _without_digest_prefix(row["preReviewDigest"])
                or len(pre_review["warnings"]) != 1
                or pre_review["warnings"][0] not in pre_review_statuses
            ):
                errors.append(
                    f"review transparency pre-review binding differs for {cohort_id}"
                )
        if len(decision_records) != 1:
            errors.append(
                f"review transparency requires one recorded decision for {cohort_id}"
            )
        if (
            len(assignment_records) == 1
            and len(pre_review_records) == 1
            and len(decision_records) == 1
            and not (
                assignment_records[0]["sequence"]
                < pre_review_records[0]["sequence"]
                < decision_records[0]["sequence"]
            )
        ):
            errors.append(
                f"review transparency prerequisites are out of order for {cohort_id}"
            )
        for record in assignment_records + pre_review_records + decision_records:
            try:
                if _timestamp(
                    record["createdAt"], "review transparency event time"
                ) > _timestamp(review["reviewedAt"], "review cohort completion"):
                    errors.append(
                        f"review transparency event follows cohort completion for {cohort_id}"
                    )
            except ValueError as exc:
                errors.append(str(exc))
        for record in decision_records:
            expected_status = (
                None
                if row["expectedDecision"] == "resubmission_requested"
                else row["expectedDecision"]
            )
            if (
                record["reviewerKeyId"] != reviewer["keyId"]
                or record["policyId"] != review["policyId"]
                or record["policyVersion"] != review["policyVersion"]
                or record["receiptStatus"] != expected_status
                or record["evidenceSha256"]
                != _without_digest_prefix(
                    review_rows[cohort_id]["decisionRecordDigest"]
                )
                or set(record["warnings"])
                != {
                    "decision=" + row["expectedDecision"],
                    "preReviewSha256="
                    + _without_digest_prefix(row["preReviewDigest"]),
                }
            ):
                errors.append(
                    f"review transparency authority differs for {cohort_id}"
                )
    return errors


def _review_errors(
    contract: dict[str, Any],
    handoff: dict[str, Any],
    review: dict[str, Any],
    reviewer: dict[str, Any],
    evaluation: datetime,
    maximum_age_seconds: int,
) -> list[str]:
    errors = _signed_receipt_errors(review, "receiptDigest", reviewer, "protected review cohort")
    app = contract["externalApp"]
    reviewed_at = _timestamp(review["reviewedAt"], "review time")
    workload_verified_at = _timestamp(
        handoff["workload"]["verifiedAt"], "workload verification time"
    )
    if review["pilotId"] != contract["pilotId"] or review["appId"] != app["appId"]:
        errors.append("review cohort pilot or app differs")
    if review["reviewerKeyId"] != reviewer["keyId"] or review["reviewerFingerprint"] != reviewer["fingerprint"]:
        errors.append("review cohort does not use the active PR-293 reviewer")
    if (
        review["provenance"]["repositoryIdentity"]
        != contract["repository"]["identity"]
        or review["provenance"] == handoff["provenance"]
    ):
        errors.append("review cohort provenance is not distinct protected Cryptad authority")
    if not (reviewed_at <= evaluation < _timestamp(review["expiresAt"], "review expiry")):
        errors.append("review cohort receipt is stale or expired")
    if reviewed_at < workload_verified_at:
        errors.append("review cohort predates authenticated workload handoff")
    for handoff_row in handoff["cohort"]:
        attestation = handoff_row["attestation"]
        attestation_ready_at = max(
            _timestamp(attestation["createdAt"], "developer attestation creation"),
            _timestamp(attestation["effectiveAt"], "developer attestation effective time"),
        )
        if reviewed_at < attestation_ready_at:
            errors.append(
                "review cohort predates developer attestation for "
                + handoff_row["cohortId"]
            )
    errors.extend(
        _freshness_errors(
            reviewed_at,
            evaluation,
            maximum_age_seconds,
            "review cohort receipt",
        )
    )
    if tuple(row["cohortId"] for row in review["rows"]) != COHORT_IDS:
        errors.append("review cohort is incomplete or reordered")
        return sorted(set(errors))
    contract_rows = {row["cohortId"]: row for row in contract["cohort"]}
    handoff_rows = {row["cohortId"]: row for row in handoff["cohort"]}
    for item in review["rows"]:
        row = contract_rows[item["cohortId"]]
        for field in ("submissionId", "submissionDigest", "bundleDigest", "bundleSignatureDigest", "preReviewDigest", "resubmissionOf"):
            if item[field] != row[field]:
                errors.append(f"review {field} differs for {row['cohortId']}")
        if item["decision"] != row["expectedDecision"]:
            errors.append(f"review decision differs for {row['cohortId']}")
        eligible = item["decision"] in {"reviewed", "caution"}
        if item["candidateEligible"] != eligible:
            errors.append(f"candidate eligibility is invalid for {row['cohortId']}")
        if item["decision"] == "caution":
            if not item["cautionWarnings"] or item["cautionAllowance"] is not True:
                errors.append("caution decision omits warnings or explicit candidate allowance")
        elif item["cautionWarnings"] or item["cautionAllowance"]:
            errors.append(f"non-caution row carries caution authority for {row['cohortId']}")
        standard_receipt = item["standardReviewReceipt"]
        standard_digest = item["standardReviewReceiptDigest"]
        if item["decision"] in {"rejected", "resubmission_requested"}:
            if standard_receipt is not None or standard_digest is not None:
                errors.append(
                    f"negative review row must not carry a standard receipt for {row['cohortId']}"
                )
        elif standard_receipt is None or standard_digest is None:
            errors.append(
                f"review row omits its signed standard receipt for {row['cohortId']}"
            )
        else:
            errors.extend(
                _standard_review_receipt_errors(
                    standard_receipt,
                    standard_digest,
                    row,
                    handoff_rows[row["cohortId"]],
                    review,
                    contract,
                    reviewer,
                    workload_verified_at,
                    evaluation,
                    maximum_age_seconds,
                )
            )
    errors.extend(_transparency_errors(contract, review, reviewer))
    return sorted(set(errors))


def _approval_errors(
    contract: dict[str, Any],
    handoff: dict[str, Any],
    approval: dict[str, Any],
    reviewer: dict[str, Any],
    evaluation: datetime,
    maximum_age_seconds: int,
) -> list[str]:
    errors = _signed_receipt_errors(approval, "receiptDigest", reviewer, "pilot publisher approval")
    app = contract["externalApp"]
    node = contract["protectedPilotNode"]
    errors.extend(
        _node_attestation_role_errors(
            contract, approval["nodeAttestationFingerprint"]
        )
    )
    expected = {
        "pilotId": contract["pilotId"], "appId": app["appId"], "publisherKeyId": app["publisherKeyId"],
        "publisherFingerprint": app["publisherFingerprint"], "sourceRepositoryIdentity": app["source"]["repositoryIdentity"],
        "handoffDigest": handoff["handoffDigest"], "pilotNodeId": node["nodeId"],
        "normalStableRegistryDigest": node["normalStableRegistryDigest"],
        "catalogRegistryDigest": node["catalogRegistryDigest"],
        "pilotRegistryDigest": node["pilotRegistryDigest"],
        "approvalAuthorityKeyId": reviewer["keyId"],
    }
    for field, value in expected.items():
        if approval.get(field) != value:
            errors.append(f"pilot publisher approval {field} differs")
    if len(
        {
            approval["normalStableRegistryDigest"],
            approval["catalogRegistryDigest"],
            approval["pilotRegistryDigest"],
        }
    ) != 3:
        errors.append(
            "pilot publisher approval does not isolate all three registry trust roots"
        )
    approval_start = _timestamp(approval["validFrom"], "approval start")
    if approval["revoked"] or not (
        approval_start
        <= evaluation
        < _timestamp(approval["validUntil"], "approval expiry")
    ):
        errors.append("pilot publisher approval is revoked or outside its validity window")
    errors.extend(
        _freshness_errors(
            approval_start,
            evaluation,
            maximum_age_seconds,
            "pilot publisher approval",
        )
    )
    if approval["provenance"]["repositoryIdentity"] != contract["repository"]["identity"]:
        errors.append("pilot publisher approval provenance is not protected Cryptad authority")
    expected_ops = {"install", "update", "caution-update", "rollback", "cleanup"}
    if set(approval["allowedOperations"]) != expected_ops:
        errors.append("pilot publisher approval operation set is not closed")
    rows = {row["cohortId"]: row for row in contract["cohort"]}
    expected_subjects = [
        {"version": rows[item]["appVersion"], "bundleDigest": rows[item]["bundleDigest"], "bundleSignatureDigest": rows[item]["bundleSignatureDigest"]}
        for item in ("version-1-reviewed", "version-2-corrected", "version-3-caution")
    ]
    if approval["permittedSubjects"] != expected_subjects:
        errors.append("pilot publisher approval does not bind the exact eligible subjects")
    return sorted(set(errors))


def _publication_errors(
    contract: dict[str, Any],
    review: dict[str, Any],
    publication: dict[str, Any],
    catalog_key: dict[str, Any],
    evaluation: datetime,
    maximum_age_seconds: int,
) -> list[str]:
    errors = _signed_receipt_errors(publication, "receiptDigest", catalog_key, "beta catalog publication")
    app = contract["externalApp"]
    if publication["pilotId"] != contract["pilotId"] or publication["appId"] != app["appId"] or publication["channel"] != "beta":
        errors.append("catalog publication is not the exact pilot beta subject")
    expected = contract["authorities"]
    if (
        publication["catalogSigningKeyId"] != catalog_key["keyId"]
        or publication["catalogSigningKeyFingerprint"] != catalog_key["fingerprint"]
        or publication["keysetDigest"] != expected["keysetDigest"]
        or publication["catalogAuthorityDigest"] != expected["catalogAuthorityDigest"]
    ):
        errors.append("catalog publication does not bind PR-293 authority")
    if (
        publication["provenance"]["repositoryIdentity"]
        != contract["repository"]["identity"]
        or publication["provenance"]["workflowPath"]
        != ".github/workflows/stable-1.0-catalog-authority.yml"
    ):
        errors.append("catalog publication provenance is not the PR-293 authority workflow")
    review_rows = {row["cohortId"]: row for row in review["rows"]}
    contract_rows = {row["cohortId"]: row for row in contract["cohort"]}
    included = ("version-1-reviewed", "version-2-corrected", "version-3-caution")
    if len(publication["editions"]) == 3:
        last_revision = 0
        last_edition = 0
        for cohort_id, edition in zip(included, publication["editions"], strict=True):
            row = contract_rows[cohort_id]
            review_row = review_rows[cohort_id]
            expected_fields = {
                "version": row["appVersion"], "bundleDigest": row["bundleDigest"],
                "bundleSignatureDigest": row["bundleSignatureDigest"], "publisherKeyId": app["publisherKeyId"],
                "publisherFingerprint": app["publisherFingerprint"], "submissionDigest": row["submissionDigest"],
                "reviewReceiptDigest": review_row["standardReviewReceiptDigest"], "decision": review_row["decision"],
                "cautionWarnings": review_row["cautionWarnings"], "acknowledgementRequired": cohort_id == "version-3-caution",
            }
            for field, value in expected_fields.items():
                if edition.get(field) != value:
                    errors.append(f"catalog edition {field} differs for {cohort_id}")
            subject = {
                name: edition[name]
                for name in edition
                if name
                not in {
                    "entryDigest",
                    "subjectDigest",
                    "signatureSiblingDigest",
                }
            }
            if edition["entryDigest"] != _digest_bytes(_canonical_bytes(subject)):
                errors.append(f"catalog entry digest is invalid for {cohort_id}")
            if edition["catalogRevision"] <= last_revision or edition["catalogEdition"] <= last_edition:
                errors.append("catalog revision and edition must advance for every subject change")
            last_revision, last_edition = edition["catalogRevision"], edition["catalogEdition"]
    if publication["status"] != "pass" or publication["partial"]:
        errors.append("partial or failed catalog publication cannot advance the pilot")
    published_at = _timestamp(publication["publishedAt"], "catalog publication time")
    reviewed_at = _timestamp(review["reviewedAt"], "review cohort completion time")
    if published_at < reviewed_at:
        errors.append("catalog publication predates review cohort completion")
    catalog_key_valid_from = _timestamp(
        catalog_key["validFrom"], "catalog signing key validity start"
    )
    catalog_key_valid_until = _timestamp(
        catalog_key["validUntil"], "catalog signing key validity end"
    )
    if not (catalog_key_valid_from <= published_at < catalog_key_valid_until):
        errors.append("catalog signing key was not valid at publication time")
    errors.extend(
        _freshness_errors(
            published_at,
            evaluation,
            maximum_age_seconds,
            "catalog publication receipt",
        )
    )
    observations = publication["observations"]
    if sum(item["locationType"] == "primary" for item in observations) != 1 or not any(item["locationType"] == "mirror" for item in observations):
        errors.append("catalog publication requires one primary and an independent mirror")
    published_subject = publication["publishedSubject"]
    expected_entry_digests = [edition["entryDigest"] for edition in publication["editions"]]
    last_edition = publication["editions"][-1]
    if (
        published_subject["catalogRevision"] != last_edition["catalogRevision"]
        or published_subject["catalogEdition"] != last_edition["catalogEdition"]
        or published_subject["entryDigests"] != expected_entry_digests
        or published_subject["subjectDigest"] != last_edition["subjectDigest"]
        or published_subject["signatureSiblingDigest"]
        != last_edition["signatureSiblingDigest"]
    ):
        errors.append("published catalog subject does not bind the reviewed edition sequence")
    subject_digests = {
        edition["subjectDigest"] for edition in publication["editions"]
    }
    signature_sibling_digests = {
        edition["signatureSiblingDigest"] for edition in publication["editions"]
    }
    if (
        len(subject_digests) != len(publication["editions"])
        or len(signature_sibling_digests) != len(publication["editions"])
    ):
        errors.append("catalog editions do not bind distinct signed subjects")
    if any(
        item["subjectDigest"] != published_subject["subjectDigest"]
        or item["signatureSiblingDigest"] != published_subject["signatureSiblingDigest"]
        or item["status"] != "pass"
        for item in observations
    ):
        errors.append("primary and mirrors do not observe the exact signed catalog subject")
    for item in observations:
        observed_at = _timestamp(item["observedAt"], f"catalog observation {item['locationId']}")
        errors.extend(
            _freshness_errors(
                observed_at,
                evaluation,
                maximum_age_seconds,
                f"catalog observation {item['locationId']}",
            )
        )
        if observed_at < published_at:
            errors.append(f"catalog observation {item['locationId']} predates publication")
    control_planes = {item["controlPlaneId"] for item in observations}
    if len(control_planes) != len(observations):
        errors.append("catalog publication observations are not control-plane distinct")
    return sorted(set(errors))


COLLECTOR_LIFECYCLE_STATE_FIELDS = (
    "preExistingInstall",
    "preExistingRunning",
    "preExistingStoppedStartedBySmoke",
    "installedByThisRun",
    "cleanupSucceeded",
)


def _collector_lifecycle_errors(
    runtime: dict[str, Any], details: dict[str, Any]
) -> list[str]:
    values = {field: details.get(field) for field in COLLECTOR_LIFECYCLE_STATE_FIELDS}
    if any(not isinstance(value, bool) for value in values.values()):
        return ["live-network collector lifecycle state is incomplete or malformed"]

    errors: list[str] = []
    pre_existing = values["preExistingInstall"]
    pre_existing_running = values["preExistingRunning"]
    pre_existing_stopped_started = values["preExistingStoppedStartedBySmoke"]
    installed_by_this_run = values["installedByThisRun"]
    if runtime["preexistingApp"] is not pre_existing:
        errors.append("live-network collector initial app state differs from runtime receipt")
    if values["cleanupSucceeded"] is not True:
        errors.append("live-network collector cleanup did not succeed")
    if (
        installed_by_this_run is pre_existing
        or (pre_existing_running and not pre_existing)
        or (
            pre_existing_stopped_started
            and (not pre_existing or pre_existing_running)
        )
        or (pre_existing and not pre_existing_running and not pre_existing_stopped_started)
    ):
        errors.append("live-network collector lifecycle state is contradictory")
    if pre_existing_running and (
        details.get("preExistingRunningStoppedForSmoke") is not True
        or details.get("restoreSucceeded") is not True
    ):
        errors.append(
            "live-network collector did not prove restoration of the pre-existing running app"
        )
    if pre_existing_stopped_started and (
        details.get("preExistingStoppedRestoredByLifecycle") is not True
        and details.get("preExistingStoppedRestoreSucceeded") is not True
    ):
        errors.append(
            "live-network collector did not prove restoration of the pre-existing stopped app"
        )
    return errors


def _runtime_errors(
    contract: dict[str, Any],
    review: dict[str, Any],
    approval: dict[str, Any],
    publication: dict[str, Any],
    runtime: dict[str, Any],
    collector_summary: dict[str, Any],
    evaluation: datetime,
    maximum_age_seconds: int,
) -> list[str]:
    errors: list[str] = []
    try:
        spki = _spki(runtime["nodeAttestationPublicKeySpkiBase64"], "pilot node attestation key")
        if _digest_bytes(spki) != runtime["nodeAttestationFingerprint"]:
            errors.append("pilot node attestation fingerprint is invalid")
        if runtime["nodeAttestationFingerprint"] != approval["nodeAttestationFingerprint"]:
            errors.append("runtime receipt node key is not authenticated by pilot approval")
        errors.extend(
            _node_attestation_role_errors(
                contract, runtime["nodeAttestationFingerprint"]
            )
        )
        node_key = {"publicKeySpkiBase64": runtime["nodeAttestationPublicKeySpkiBase64"]}
        errors.extend(_signed_receipt_errors(runtime, "receiptDigest", node_key, "protected runtime drill"))
    except ValueError as exc:
        errors.append(str(exc))
    app = contract["externalApp"]
    node = contract["protectedPilotNode"]
    release = contract["release"]
    if runtime["pilotId"] != contract["pilotId"] or runtime["appId"] != app["appId"] or runtime["pilotNodeId"] != node["nodeId"]:
        errors.append("runtime receipt pilot, app, or node differs")
    if (
        runtime["provenance"]["repositoryIdentity"]
        != contract["repository"]["identity"]
        or runtime["provenance"]["workflowPath"]
        != RUNTIME_PRODUCER_WORKFLOW
        or runtime["provenance"]["workflowCommit"]
        != contract["repository"]["sourceCommit"]
        or runtime["provenance"]["environment"]
        != RUNTIME_PRODUCER_ENVIRONMENT
    ):
        errors.append(
            "runtime provenance is not the protected node-side producer at the certified source commit"
        )
    daemon_identity = runtime["daemonIdentity"]
    if daemon_identity != {
        "identitySource": "managed-daemon-product-attestation-v1",
        "releaseId": release["releaseId"],
        "buildVersion": release["buildVersion"],
        "sourceCommit": contract["repository"]["sourceCommit"],
        "protectedReleaseRootDigest": contract["authorities"][
            "protectedReleaseRootDigest"
        ],
        "productDistributionDigest": release["productDistributionDigest"],
        "managedDaemon": True,
        "appHostVerificationPolicy": "stable-1.0-pilot-publisher-v1",
        "observedAt": daemon_identity["observedAt"],
    }:
        errors.append(
            "managed daemon identity does not match the certified product and AppHost policy"
        )
    if runtime["publisherApprovalDigest"] != approval["receiptDigest"] or runtime["catalogPublicationDigest"] != publication["receiptDigest"]:
        errors.append("runtime receipt does not bind publisher approval and catalog publication")
    collector = runtime["collector"]
    if (
        collector["kind"] != "live-network-beta-smoke"
        or collector["transportReused"] is not True
        or collector["localhostOnly"] is not True
        or collector["redirectsDisabled"] is not True
        or collector["status"] != "pass"
        or collector["redactionStatus"] != "pass"
    ):
        errors.append("runtime receipt does not authenticate the existing live-network collector")
    collector_binding = contract["evidence"].get("collectorSummary")
    if (
        collector_binding is None
        or collector["summaryFileName"] != collector_binding["fileName"]
        or collector["summaryDigest"] != collector_binding["digest"]
        or collector["summarySize"] != collector_binding["size"]
    ):
        errors.append("runtime receipt does not bind the exact live-network collector summary bytes")
    expected_collector_ids = (
        "live-network-beta.preflight",
        "live-network-beta.catalog-usk-fetch",
        "live-network-beta.app-install-update-rollback",
        "live-network-beta.content-fetch",
        "live-network-beta.feed-subscription",
        "live-network-beta.profile-publish",
        "live-network-beta.trust-statement-publish-import",
        "live-network-beta.app-service-score",
        "live-network-beta.interop-perf-budget",
        "live-network-beta.redaction",
    )
    evidence_rows = collector_summary["evidence"]
    if tuple(row["id"] for row in evidence_rows) != expected_collector_ids:
        errors.append("live-network collector evidence is incomplete, duplicated, or reordered")
    required_collector_ids = set(expected_collector_ids) - {
        "live-network-beta.app-service-score"
    }
    if any(
        row["status"] != "pass" or row["requiredForReleaseCandidate"] is not True
        for row in evidence_rows
        if row["id"] in required_collector_ids
    ):
        errors.append("live-network collector has a failed or non-required release-candidate gate")
    lifecycle = next(
        (row for row in evidence_rows if row["id"] == "live-network-beta.app-install-update-rollback"),
        None,
    )
    lifecycle_details = lifecycle.get("details", {}) if isinstance(lifecycle, dict) else {}
    if (
        not isinstance(lifecycle_details, dict)
        or lifecycle_details.get("appId") != app["appId"]
        or lifecycle_details.get("catalogId") != publication["catalogId"]
    ):
        errors.append("live-network collector lifecycle evidence differs")
    else:
        errors.extend(_collector_lifecycle_errors(runtime, lifecycle_details))
    if (
        collector_summary["kind"] != "live-network-beta-smoke"
        or collector_summary["mode"] != "release-candidate"
        or collector_summary["enabled"] is not True
        or collector_summary["required"] is not True
        or collector_summary["status"] != "pass"
        or collector_summary["node"]["localhostOnly"] is not True
        or collector_summary["redaction"] != {
            "status": "pass",
            "forbiddenPatternsChecked": True,
            "rawBodiesStored": False,
            "privateInsertUrisStored": False,
            "localPathsStored": False,
        }
    ):
        errors.append("live-network collector summary is not a passing local release-candidate run")
    if (
        collector_summary["node"]["baseUrlShape"]
        not in COLLECTOR_LOOPBACK_BASE_URL_SHAPES
    ):
        errors.append("live-network collector endpoint shape is not canonical loopback")
    if runtime["normalStableRegistryDigest"] != node["normalStableRegistryDigest"]:
        errors.append("runtime receipt uses a different normal Stable key registry")
    if runtime["normalStableRegistryDigest"] != approval["normalStableRegistryDigest"]:
        errors.append(
            "runtime receipt normal Stable registry is not authenticated by the publisher approval"
        )
    if runtime["pilotRegistryDigest"] != node["pilotRegistryDigest"]:
        errors.append("runtime receipt uses a different pilot key registry")
    if runtime["catalogRegistryDigest"] != node["catalogRegistryDigest"]:
        errors.append("runtime receipt uses a different catalog key registry")
    if len(
        {
            runtime["normalStableRegistryDigest"],
            runtime["catalogRegistryDigest"],
            runtime["pilotRegistryDigest"],
        }
    ) != 3:
        errors.append("runtime receipt does not isolate all three registry trust roots")
    required_events = (
        "pilot-registry-installed", "beta-catalog-refreshed", "reviewed-v1-installed",
        "rejected-v2-absent", "corrected-v2-catalog-refreshed", "corrected-v2-updated",
        "caution-v3-catalog-refreshed", "caution-v3-blocked-without-acknowledgement",
        "caution-v3-consent-recorded", "caution-v3-updated", "corrected-v2-rollback",
        "app-removed-or-restored", "catalog-removed-or-restored", "pilot-registry-removed-or-quarantined",
    )
    if tuple(event["event"] for event in runtime["events"]) != required_events or [event["sequence"] for event in runtime["events"]] != list(range(1, 15)):
        errors.append("runtime drill event sequence is incomplete or reordered")
    rows = {row["cohortId"]: row for row in contract["cohort"]}
    events = {event["event"]: event for event in runtime["events"]}
    expected_event_status = {name: "pass" for name in required_events}
    expected_event_status["rejected-v2-absent"] = "blocked-as-required"
    expected_event_status["caution-v3-blocked-without-acknowledgement"] = "blocked-as-required"
    for event_name, expected_status in expected_event_status.items():
        if events.get(event_name, {}).get("status") != expected_status:
            errors.append(f"runtime event {event_name} does not have required status {expected_status}")
    publication_editions = dict(
        zip(
            ("version-1-reviewed", "version-2-corrected", "version-3-caution"),
            publication["editions"],
            strict=True,
        )
    )
    refreshes = {
        "beta-catalog-refreshed": "version-1-reviewed",
        "corrected-v2-catalog-refreshed": "version-2-corrected",
        "caution-v3-catalog-refreshed": "version-3-caution",
    }
    for event_name, cohort_id in refreshes.items():
        event = events.get(event_name, {})
        row = rows[cohort_id]
        edition = publication_editions[cohort_id]
        expected_refresh = {
            "status": "pass",
            "version": row["appVersion"],
            "bundleDigest": row["bundleDigest"],
            "publisherKeyId": app["publisherKeyId"],
            "reviewStatus": edition["decision"],
            "warningCodes": edition["cautionWarnings"],
            "catalogRevision": edition["catalogRevision"],
            "catalogEdition": edition["catalogEdition"],
            "catalogEntryDigest": edition["entryDigest"],
            "catalogSubjectDigest": edition["subjectDigest"],
            "catalogSignatureSiblingDigest": edition["signatureSiblingDigest"],
        }
        if any(event.get(field) != value for field, value in expected_refresh.items()):
            errors.append(
                f"runtime event {event_name} does not bind the exact beta catalog edition subject"
            )
    identities = {
        "reviewed-v1-installed": (rows["version-1-reviewed"], "reviewed"),
        "corrected-v2-updated": (rows["version-2-corrected"], "reviewed"),
        "caution-v3-updated": (rows["version-3-caution"], "caution"),
        "corrected-v2-rollback": (rows["version-2-corrected"], "reviewed"),
    }
    for event_name, (row, review_status) in identities.items():
        event = events.get(event_name, {})
        if (
            event.get("status") != "pass" or event.get("version") != row["appVersion"]
            or event.get("bundleDigest") != row["bundleDigest"] or event.get("publisherKeyId") != app["publisherKeyId"]
            or event.get("reviewStatus") != review_status or event.get("sandboxStatus") != "pass"
            or event.get("appDataBoundaryStatus") != "pass" or event.get("permissionsDigest") is None
        ):
            errors.append(f"runtime event {event_name} does not bind the exact installed subject")
    corrected_update = events.get("corrected-v2-updated", {})
    corrected_rollback = events.get("corrected-v2-rollback", {})
    if corrected_rollback.get("permissionsDigest") != corrected_update.get(
        "permissionsDigest"
    ):
        errors.append(
            "runtime rollback permission metadata differs from corrected version 2 update"
        )
    rejected = events.get("rejected-v2-absent", {})
    rejected_row = rows["version-2-rejected"]
    if (
        rejected.get("status") != "blocked-as-required"
        or rejected.get("version") != rejected_row["appVersion"]
        or rejected.get("bundleDigest") != rejected_row["bundleDigest"]
        or rejected.get("publisherKeyId") != app["publisherKeyId"]
        or rejected.get("reviewStatus") not in {"rejected", "resubmission_requested"}
    ):
        errors.append("runtime did not prove the rejected version absent and blocked")
    caution_blocked = events.get("caution-v3-blocked-without-acknowledgement", {})
    caution_consent = events.get("caution-v3-consent-recorded", {})
    caution_update = events.get("caution-v3-updated", {})
    caution_row = rows["version-3-caution"]
    warnings = next(row["cautionWarnings"] for row in review["rows"] if row["cohortId"] == "version-3-caution")
    caution_subject = {
        "version": caution_row["appVersion"],
        "bundleDigest": caution_row["bundleDigest"],
        "publisherKeyId": app["publisherKeyId"],
        "reviewStatus": "caution",
        "warningCodes": warnings,
    }
    if (
        any(caution_blocked.get(field) != value for field, value in caution_subject.items())
        or caution_blocked.get("permissionsDigest") is None
        or caution_blocked.get("status") != "blocked-as-required"
        or caution_blocked.get("consentSnapshotDigest") is not None
    ):
        errors.append("caution blocked event does not bind the exact caution subject")
    if (
        any(caution_consent.get(field) != value for field, value in caution_subject.items())
        or caution_consent.get("permissionsDigest") is None
        or caution_consent.get("status") != "pass"
        or caution_consent.get("consentSnapshotDigest") is None
    ):
        errors.append("caution consent event does not bind the exact caution subject")
    if caution_update.get("consentSnapshotDigest") != caution_consent.get("consentSnapshotDigest") or caution_update.get("warningCodes") != warnings:
        errors.append("caution update does not preserve consent and warning metadata")
    if not (
        caution_blocked.get("permissionsDigest")
        == caution_consent.get("permissionsDigest")
        == caution_update.get("permissionsDigest")
    ):
        errors.append(
            "caution consent permission metadata differs from the blocked or applied update"
        )
    corrected = rows["version-2-corrected"]
    if runtime["finalVersion"] != corrected["appVersion"] or runtime["finalBundleDigest"] != corrected["bundleDigest"] or runtime["finalPublisherKeyId"] != app["publisherKeyId"] or not runtime["rollbackExact"]:
        errors.append("runtime rollback is not the exact corrected version 2 subject")
    app_cleanup_statuses = (
        {"pass", "not-required"} if runtime["preexistingApp"] else {"pass"}
    )
    catalog_cleanup_statuses = (
        {"pass", "not-required"} if runtime["preexistingCatalog"] else {"pass"}
    )
    if runtime["appCleanupStatus"] not in app_cleanup_statuses:
        errors.append("app cleanup status does not match the pre-existing state")
    if runtime["catalogCleanupStatus"] not in catalog_cleanup_statuses:
        errors.append("catalog cleanup status does not match the pre-existing state")
    if (
        runtime["status"] != "pass"
        or runtime["partial"]
        or not runtime["cleanStateRestored"]
        or runtime["appCleanupStatus"] not in app_cleanup_statuses
        or runtime["catalogCleanupStatus"] not in catalog_cleanup_statuses
        or runtime["registryCleanupStatus"] not in {"pass", "quarantined"}
    ):
        errors.append("runtime cleanup is partial, failed, or hidden as success")
    completed_at = _timestamp(runtime["completedAt"], "runtime completion time")
    publication_at = _timestamp(publication["publishedAt"], "catalog publication time")
    reviewed_at = _timestamp(review["reviewedAt"], "review cohort completion time")
    approval_from = _timestamp(approval["validFrom"], "publisher approval start")
    approval_until = _timestamp(approval["validUntil"], "publisher approval expiry")
    collector_started_at = _timestamp(
        collector_summary["startedAt"], "live-network collector start time"
    )
    collector_finished_at = _timestamp(
        collector_summary["finishedAt"], "live-network collector completion time"
    )
    daemon_observed_at = _timestamp(
        daemon_identity["observedAt"], "managed daemon identity observation time"
    )
    if collector_finished_at < collector_started_at:
        errors.append("live-network collector completion predates its start")
    if daemon_observed_at < max(reviewed_at, publication_at):
        errors.append("managed daemon identity observation predates review or catalog publication")
    if daemon_observed_at > collector_started_at:
        errors.append("managed daemon identity was not observed before collector execution")
    if not approval_from <= daemon_observed_at < approval_until:
        errors.append("managed daemon identity observation is outside the publisher approval window")
    if collector_started_at < max(reviewed_at, publication_at):
        errors.append(
            "live-network collector execution predates review or catalog publication"
        )
    if completed_at < max(
        reviewed_at, publication_at, daemon_observed_at, collector_finished_at
    ):
        errors.append("runtime drill completion predates review, publication, or collector completion")
    if not approval_from <= completed_at < approval_until:
        errors.append("runtime drill completion is outside the publisher approval window")
    errors.extend(
        _freshness_errors(
            daemon_observed_at,
            evaluation,
            maximum_age_seconds,
            "managed daemon identity observation",
        )
    )
    errors.extend(
        _freshness_errors(
            collector_started_at,
            evaluation,
            maximum_age_seconds,
            "live-network collector start",
        )
    )
    errors.extend(
        _freshness_errors(
            collector_finished_at,
            evaluation,
            maximum_age_seconds,
            "live-network collector completion",
        )
    )
    errors.extend(
        _freshness_errors(
            completed_at,
            evaluation,
            maximum_age_seconds,
            "runtime drill receipt",
        )
    )
    return sorted(set(errors))


def _selected_rc_freeze_expectations(
    contract: dict[str, Any],
    protected: dict[str, Any],
    independent: dict[str, Any],
    freeze: dict[str, Any],
    inventory: dict[str, Any],
    binding: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, list[str]]:
    """Derive PR-293 expectations only from independently authenticated release roots."""

    errors: list[str] = []
    dispatch = protected.get("dispatchPackage")
    validation = dispatch.get("gaValidation") if isinstance(dispatch, dict) else None
    publication = dispatch.get("gaPublication") if isinstance(dispatch, dict) else None
    selected_rc = validation.get("selectedRc") if isinstance(validation, dict) else None
    published_rc = publication.get("selectedRc") if isinstance(publication, dict) else None
    independent_rc = independent.get("selectedRc")
    if (
        not isinstance(selected_rc, dict)
        or not isinstance(published_rc, dict)
        or not isinstance(independent_rc, dict)
    ):
        return None, None, ["PR-291 or PR-292 root lacks the selected RC identity"]
    if published_rc != selected_rc:
        errors.append("PR-291 validation and publication select different RC subjects")

    for protected_field, independent_field in (
        ("runId", "runId"),
        ("runAttempt", "runAttempt"),
        ("artifactName", "artifactName"),
        ("artifactDigest", "artifactDigest"),
        ("freezeDigest", "freezeDigest"),
        ("productDigest", "productDigest"),
    ):
        if str(selected_rc.get(protected_field)) != str(
            independent_rc.get(independent_field)
        ):
            errors.append(
                f"PR-291 and PR-292 selected RC {protected_field} identities differ"
            )
    if (
        independent_rc.get("workflowPath") != SELECTED_RC_WORKFLOW
        or independent_rc.get("workflowCommit")
        != contract["repository"]["sourceCommit"]
    ):
        errors.append("PR-292 selected RC does not use the certified protected RC workflow")
    if (
        selected_rc.get("productDigest")
        != contract["release"]["productDistributionDigest"]
        or independent_rc.get("subjectInventoryDigest")
        != independent.get("subjectInventoryDigest")
    ):
        errors.append("selected RC product or subject inventory differs from PR-292")

    errors.extend(
        supply_chain_core.self_digest_errors(
            inventory,
            "subjectInventoryDigest",
            "PR-292 subject inventory",
        )
    )
    if (
        inventory.get("releaseId") != contract["release"]["releaseId"]
        or inventory.get("buildVersion") != contract["release"]["buildVersion"]
        or inventory.get("sourceCommit") != contract["repository"]["sourceCommit"]
        or inventory.get("subjectInventoryDigest")
        != independent.get("subjectInventoryDigest")
        or inventory.get("subjectInventoryDigest")
        != independent_rc.get("subjectInventoryDigest")
    ):
        errors.append("PR-292 subject inventory differs from the authenticated root")

    errors.extend(
        f"selected RC freeze: {error}" for error in rc_freeze.validate_freeze_shape(freeze)
    )
    candidate = freeze.get("candidate")
    frozen_catalog = freeze.get("stableCatalog")
    if not isinstance(candidate, dict) or not isinstance(frozen_catalog, dict):
        errors.append("selected RC freeze lacks its candidate or Stable catalog subject")
        return selected_rc, None, sorted(set(errors))
    if (
        binding.get("digest") != independent_rc.get("freezeFileDigest")
        or freeze.get("contentDigest") != selected_rc.get("freezeDigest")
        or freeze.get("contentDigest") != independent_rc.get("freezeDigest")
    ):
        errors.append("selected RC freeze bytes or content digest differ from PR-291 or PR-292")
    if (
        candidate.get("releaseId") != contract["release"]["releaseId"]
        or candidate.get("buildVersion") != str(contract["release"]["buildVersion"])
        or candidate.get("sourceCommit") != contract["repository"]["sourceCommit"]
        or candidate.get("sourceRef")
        != f"refs/heads/release/{contract['release']['buildVersion']}"
        or candidate.get("productionDistributionDigest")
        != contract["release"]["productDistributionDigest"]
    ):
        errors.append("selected RC freeze candidate differs from the certified release")
    if (
        frozen_catalog.get("revision") != selected_rc.get("catalogRevision")
        or frozen_catalog.get("catalogDigest") != selected_rc.get("catalogDigest")
    ):
        errors.append("selected RC freeze catalog differs from the PR-291 selection")
    subjects = inventory.get("subjects")
    subject_rows = subjects if isinstance(subjects, list) else []
    catalog_rows = [
        row
        for row in subject_rows
        if isinstance(row, dict) and row.get("subjectKey") == "stable-catalog"
    ]
    signature_rows = [
        row
        for row in subject_rows
        if isinstance(row, dict)
        and row.get("subjectKey") == "stable-catalog-signature"
    ]
    if len(catalog_rows) != 1 or len(signature_rows) != 1:
        errors.append("PR-292 subject inventory lacks unique catalog and signature subjects")
    else:
        catalog_row = catalog_rows[0]
        signature_row = signature_rows[0]
        if (
            catalog_row.get("subjectClass") != "catalog"
            or catalog_row.get("reproducibilityClass") != "byte-identical"
            or catalog_row.get("digest") != frozen_catalog.get("catalogDigest")
            or signature_row.get("subjectClass") != "catalog"
            or signature_row.get("reproducibilityClass") != "byte-identical"
            or signature_row.get("digest") != frozen_catalog.get("signatureDigest")
            or not isinstance(catalog_row.get("size"), int)
            or catalog_row["size"] <= 0
            or not isinstance(signature_row.get("size"), int)
            or signature_row["size"] <= 0
        ):
            errors.append(
                "PR-292 catalog or signature subject differs from the selected RC freeze"
            )

    provenance = binding.get("provenance")
    if not isinstance(provenance, dict):
        errors.append("selected RC freeze lacks protected artifact provenance")
    else:
        if (
            provenance.get("repositoryIdentity") != contract["repository"]["identity"]
            or provenance.get("workflowPath") != independent_rc.get("workflowPath")
            or provenance.get("workflowCommit") != independent_rc.get("workflowCommit")
            or str(provenance.get("runId")) != str(independent_rc.get("runId"))
            or str(provenance.get("runAttempt"))
            != str(independent_rc.get("runAttempt"))
            or provenance.get("artifactName") != independent_rc.get("artifactName")
            or provenance.get("artifactDigest") != independent_rc.get("artifactDigest")
            or provenance.get("environment") != SELECTED_RC_ENVIRONMENT
            or provenance.get("conclusion") != "success"
        ):
            errors.append("selected RC freeze provenance differs from the PR-292 selection")
        coordinate = {
            "repository": provenance.get("repositoryIdentity", "").removeprefix(
                "github.com/"
            ),
            "workflowPath": provenance.get("workflowPath"),
            "workflowCommit": provenance.get("workflowCommit"),
            "runId": provenance.get("runId"),
            "runAttempt": provenance.get("runAttempt"),
            "artifactName": provenance.get("artifactName"),
            "artifactDigest": provenance.get("artifactDigest"),
        }
        errors.extend(
            _github_actions_coordinate_errors(
                coordinate,
                label="selected RC freeze",
            )
        )
    return selected_rc, frozen_catalog, sorted(set(errors))


def _authority_root_errors(contract: dict[str, Any], evidence_dir: Path | None) -> list[str]:
    errors: list[str] = []
    expected_coordinates = {
        "protectedRelease": (
            ".github/workflows/stable-1.0-protected-release-closeout.yml",
            "stable-1-0-protected-release-closeout",
        ),
        "independentReproducibility": (
            ".github/workflows/stable-1.0-independent-reproducibility.yml",
            "stable-1.0-independent-reproducibility-external-receipt",
        ),
        "catalogAuthority": (
            catalog_authority_closeout.WORKFLOW,
            catalog_authority_closeout.ENVIRONMENT,
        ),
        "runtimeDrill": (
            RUNTIME_PRODUCER_WORKFLOW,
            RUNTIME_PRODUCER_ENVIRONMENT,
        ),
    }

    def authenticate(field: str) -> list[str]:
        binding = contract["evidence"].get(field)
        if binding is None:
            return []
        provenance = binding["provenance"]
        workflow, environment = expected_coordinates[field]
        item_errors: list[str] = []
        if (
            provenance["repositoryIdentity"] != contract["repository"]["identity"]
            or provenance["workflowPath"] != workflow
            or provenance["workflowCommit"] != contract["repository"]["sourceCommit"]
            or provenance["environment"] != environment
            or provenance["conclusion"] != "success"
        ):
            item_errors.append(f"{field} protected producer provenance differs")
        coordinate = {
            "repository": provenance["repositoryIdentity"].removeprefix("github.com/"),
            "workflowPath": provenance["workflowPath"],
            "workflowCommit": provenance["workflowCommit"],
            "runId": provenance["runId"],
            "runAttempt": provenance["runAttempt"],
            "artifactName": provenance["artifactName"],
            "artifactDigest": provenance["artifactDigest"],
        }
        item_errors.extend(
            _github_actions_coordinate_errors(
                coordinate,
                label=f"{field} protected root",
                required_job_name=(
                    RUNTIME_PRODUCER_JOB if field == "runtimeDrill" else None
                ),
                required_job_steps=(
                    RUNTIME_PRODUCER_STEPS if field == "runtimeDrill" else ()
                ),
            )
        )
        return item_errors

    errors.extend(authenticate("runtimeDrill"))

    protected, protected_errors = _bound_artifact_json(
        contract,
        evidence_dir,
        "protectedRelease",
        "stable-1.0-protected-release-execution-summary.json",
        "stable-1.0-protected-release-execution-summary-v1.schema.json",
    )
    errors.extend(protected_errors)
    errors.extend(authenticate("protectedRelease"))
    protected_valid = protected is not None and not protected_errors
    if protected is not None:
        classification = protected["evidenceClassification"]
        if (
            protected["kind"] != "stable-1.0-protected-release-execution-summary"
            or protected["releaseId"] != contract["release"]["releaseId"]
            or protected["buildVersion"] != str(contract["release"]["buildVersion"])
            or protected["candidateCommit"] != contract["repository"]["sourceCommit"]
            or protected["contractDigest"]
            != contract["authorities"]["protectedReleaseRootDigest"]
            or protected["status"] != "pass"
            or protected["lifecycleState"] != "publicly-observed"
            or classification["protectedRcOperation"] != "completed"
            or classification["gaValidation"] != "completed"
            or classification["gaPublication"] != "completed"
            or classification["publicObservation"] != "completed"
        ):
            errors.append("PR-291 protected release root is not authentic, operational, and publicly observed")
            protected_valid = False

    independent, independent_errors = _bound_artifact_json(
        contract,
        evidence_dir,
        "independentReproducibility",
        "stable-1.0-independent-reproducibility-summary.json",
        "stable-1.0-independent-reproducibility-summary-v1.schema.json",
    )
    errors.extend(independent_errors)
    errors.extend(authenticate("independentReproducibility"))
    inventory, inventory_errors = _bound_artifact_json(
        contract,
        evidence_dir,
        "independentReproducibility",
        catalog_authority.SUBJECT_INVENTORY_FILE,
        "stable-1.0-release-subject-inventory-v1.schema.json",
    )
    errors.extend(inventory_errors)
    independent_valid = independent is not None and not independent_errors
    if independent is not None:
        summary_errors = [
            f"PR-292 independent reproducibility root: {error}"
            for error in independent_summary_errors(independent)
        ]
        errors.extend(summary_errors)
        if summary_errors:
            independent_valid = False
        if (
            independent["releaseId"] != contract["release"]["releaseId"]
            or independent["buildVersion"] != contract["release"]["buildVersion"]
            or independent["sourceCommit"] != contract["repository"]["sourceCommit"]
            or independent["selectedRc"]["productDigest"]
            != contract["release"]["productDistributionDigest"]
            or independent["summaryDigest"]
            != contract["authorities"]["independentReproducibilityDigest"]
            or independent["operational"] is not True
        ):
            errors.append("PR-292 independent reproducibility root differs or is not operational")
            independent_valid = False

    freeze, freeze_errors = _bound_json(
        contract,
        evidence_dir,
        "selectedRcFreeze",
        RC_FREEZE_SCHEMA,
    )
    errors.extend(freeze_errors)
    selected_rc: dict[str, Any] | None = None
    frozen_catalog: dict[str, Any] | None = None
    expectation_errors: list[str] = []
    freeze_binding = contract["evidence"].get("selectedRcFreeze")
    if (
        protected_valid
        and independent_valid
        and inventory is not None
        and not inventory_errors
        and freeze is not None
        and not freeze_errors
        and isinstance(freeze_binding, dict)
    ):
        selected_rc, frozen_catalog, expectation_errors = (
            _selected_rc_freeze_expectations(
                contract,
                protected,
                independent,
                freeze,
                inventory,
                freeze_binding,
            )
        )
        errors.extend(expectation_errors)

    catalog_path, catalog_raw, catalog_errors = _bound_file(
        contract, evidence_dir, "catalogAuthority", None
    )
    del catalog_raw
    errors.extend(catalog_errors)
    errors.extend(authenticate("catalogAuthority"))
    if (
        catalog_path is not None
        and independent_valid
        and selected_rc is not None
        and frozen_catalog is not None
        and not expectation_errors
    ):
        catalog_binding = contract["evidence"]["catalogAuthority"]
        if catalog_binding["digest"] != catalog_binding["provenance"]["artifactDigest"]:
            errors.append("catalogAuthority retained artifact digest differs from protected provenance")
        catalog_summary: dict[str, Any] | None = None
        try:
            catalog_summary = _catalog_authority_summary(catalog_path)
        except (KeyError, OSError, ValueError, zipfile.BadZipFile):
            errors.append("PR-293 catalog authority artifact is unsafe or malformed")
        if catalog_summary is not None:
            subject = catalog_summary.get("catalogSubject")
            inventory_subjects = {
                row["subjectKey"]: row
                for row in inventory["subjects"]
                if row["subjectKey"]
                in {"stable-catalog", "stable-catalog-signature"}
            }
            if (
                not isinstance(subject, dict)
                or subject.get("catalogSize")
                != inventory_subjects["stable-catalog"]["size"]
                or subject.get("signatureSize")
                != inventory_subjects["stable-catalog-signature"]["size"]
            ):
                errors.append(
                    "PR-293 catalog authority subject sizes differ from the PR-292 inventory"
                )
            state, artifact_errors = catalog_authority_closeout.verify_artifact(
                catalog_path,
                expected_digest=contract["evidence"]["catalogAuthority"]["digest"],
                contract_root=contract["authorities"]["protectedReleaseRootDigest"],
                release_id=contract["release"]["releaseId"],
                build_version=contract["release"]["buildVersion"],
                source_commit=contract["repository"]["sourceCommit"],
                selected_rc=selected_rc,
                frozen_catalog=frozen_catalog,
                independent_digests={
                    "summaryDigest": independent["summaryDigest"],
                    "resultDigest": independent["reproducibilityResultDigest"],
                    "subjectInventoryDigest": independent["subjectInventoryDigest"],
                },
            )
            errors.extend(
                f"PR-293 catalog authority root: {error}" for error in artifact_errors
            )
            if (
                state not in catalog_authority_closeout.OPERATIONAL_STATES
                or catalog_summary.get("summaryDigest")
                != contract["authorities"]["catalogAuthorityDigest"]
                or catalog_summary.get("keysetDigest")
                != contract["authorities"]["keysetDigest"]
            ):
                errors.append("PR-293 catalog authority root differs or is not operational")
    return sorted(set(errors))


def _summary(
    contract: dict[str, Any], mode: str, stages: dict[str, tuple[bool, str | None]], errors: list[str]
) -> dict[str, Any]:
    fixture = contract["fixtureOnly"] or contract["selfTest"]
    stage_ok = {name: value[0] for name, value in stages.items()}
    external = stage_ok.get("handoff", False) and not fixture
    review = external and stage_ok.get("review", False)
    publication = review and stage_ok.get("publication", False)
    runtime = publication and stage_ok.get("runtime", False)
    roots = runtime and stage_ok.get("roots", False)
    operational = roots and not errors
    fixture_complete = (
        fixture
        and not errors
        and all(
            stage_ok.get(stage, False)
            for stage in ("preflight", "handoff", "review", "publication", "runtime")
        )
    )
    if errors:
        state = "partial" if any(stage_ok.values()) else "blocked"
        status = "partial" if any(stage_ok.values()) else "fail"
    elif fixture_complete:
        state = "fixture-verification-complete"
        status = "pass"
    elif operational:
        state = "operational-pilot-complete"
        status = "pass"
    elif runtime:
        state = "runtime-drill-complete"
        status = "pass"
    elif publication:
        state = "beta-catalog-published"
        status = "pass"
    elif review:
        state = "review-cohort-complete"
        status = "pass"
    elif external:
        state = "external-handoff-authenticated"
        status = "pass"
    else:
        state = "preflight-passed"
        status = "pass"
    evidence_status: dict[str, tuple[str, str | None]] = {
        EVIDENCE_IDS[0]: ("pass" if external else "fixture-only" if fixture and stage_ok.get("handoff") else "pending", stages.get("handoff", (False, None))[1]),
        EVIDENCE_IDS[1]: ("pass" if external else "fixture-only" if fixture and stage_ok.get("handoff") else "pending", stages.get("handoff", (False, None))[1]),
        EVIDENCE_IDS[2]: ("pass" if runtime else "fixture-only" if fixture and stage_ok.get("runtime") else "pending", stages.get("runtime", (False, None))[1]),
        EVIDENCE_IDS[3]: ("pass" if review else "fixture-only" if fixture and stage_ok.get("review") else "pending", stages.get("review", (False, None))[1]),
        EVIDENCE_IDS[4]: ("pass" if runtime else "fixture-only" if fixture and stage_ok.get("runtime") else "pending", stages.get("runtime", (False, None))[1]),
        EVIDENCE_IDS[5]: ("pass" if publication else "fixture-only" if fixture and stage_ok.get("publication") else "pending", stages.get("publication", (False, None))[1]),
        EVIDENCE_IDS[6]: ("pass" if runtime else "fixture-only" if fixture and stage_ok.get("runtime") else "pending", stages.get("runtime", (False, None))[1]),
        EVIDENCE_IDS[7]: ("pass" if review else "fixture-only" if fixture and stage_ok.get("review") else "pending", stages.get("review", (False, None))[1]),
        EVIDENCE_IDS[8]: ("pass" if not errors else "fail", None),
    }
    summary: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": "stable-1.0-third-party-app-pilot-summary",
        "pilotId": contract["pilotId"],
        "releaseId": contract["release"]["releaseId"],
        "buildVersion": contract["release"]["buildVersion"],
        "sourceCommit": contract["repository"]["sourceCommit"],
        "mode": mode,
        "status": status,
        "state": state,
        "implementationComplete": True,
        "fixtureVerificationComplete": fixture_complete,
        "externalHandoffAuthenticated": external,
        "reviewCohortComplete": review,
        "betaCatalogPublished": publication,
        "runtimeDrillComplete": runtime,
        "operationalPilotComplete": operational,
        "fixtureOnly": contract["fixtureOnly"],
        "selfTest": contract["selfTest"],
        "operational": operational,
        "authorityDigests": {
            "protectedRelease": contract["authorities"]["protectedReleaseRootDigest"],
            "independentReproducibility": contract["authorities"]["independentReproducibilityDigest"],
            "catalogAuthority": contract["authorities"]["catalogAuthorityDigest"],
            "keyset": contract["authorities"]["keysetDigest"],
        },
        "externalApp": {
            "appId": contract["externalApp"]["appId"],
            "sourceRepositoryIdentity": contract["externalApp"]["source"]["repositoryIdentity"],
            "sourceRevision": contract["externalApp"]["source"]["revision"],
            "publisherKeyId": contract["externalApp"]["publisherKeyId"],
            "publisherFingerprint": contract["externalApp"]["publisherFingerprint"],
        },
        "evidence": [
            {"id": item, "status": evidence_status[item][0], "digest": evidence_status[item][1]}
            for item in EVIDENCE_IDS
        ],
        "blockers": sorted(set(_blocker_code(error) for error in errors))[:128],
        "summaryDigest": ZERO_DIGEST,
    }
    summary["summaryDigest"] = _semantic_digest(summary, "summaryDigest")
    return summary


def _blocker_code(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")
    return (normalized or "verification-failed")[:160]


def _report(summary: dict[str, Any]) -> str:
    lines = [
        "# Stable 1.0 external third-party app pilot",
        "",
        f"- Pilot: `{summary['pilotId']}`",
        f"- Mode: `{summary['mode']}`",
        f"- Status: `{summary['status']}`",
        f"- State: `{summary['state']}`",
        f"- Operational: `{'yes' if summary['operational'] else 'no'}`",
        "",
        "This report is an offline verification result. It is not evidence that an external developer, protected review, beta publication, or live runtime drill occurred unless `operational` is true and every protected receipt was authenticated.",
        "",
        "## Evidence",
        "",
    ]
    lines.extend(f"- `{row['id']}`: `{row['status']}`" for row in summary["evidence"])
    if summary["blockers"]:
        lines.extend(("", "## Blockers", ""))
        lines.extend(f"- `{blocker}`" for blocker in summary["blockers"])
    return "\n".join(lines) + "\n"


def run(
    workspace_root: Path,
    execution_contract: Path,
    mode: str,
    out_dir: Path | None = None,
    evidence_dir: Path | None = None,
) -> int:
    """Verify one pilot phase and emit only redacted, deterministic outputs."""

    if mode not in MODES:
        raise ValueError("unsupported third-party pilot mode")
    workspace = workspace_root.resolve()
    contract_path = _confined_existing_path(
        workspace,
        execution_contract,
        "third-party pilot contract",
        directory=False,
    )
    contract = read_json(contract_path)
    if not isinstance(contract, dict):
        raise ValueError("third-party pilot contract is not an object")
    schema_errors = validate_schema(contract, EXECUTION_SCHEMA)
    if schema_errors:
        raise ValueError("third-party pilot contract failed its closed schema: " + "; ".join(schema_errors[:8]))
    if scan_value(_redaction_view(contract)):
        raise ValueError("third-party pilot contract contains prohibited or unredacted material")
    policy, policy_digest = _policy(workspace)
    del policy_digest
    evaluation = _verification_time(contract, policy)
    output = _confined_directory(workspace, out_dir or Path("build/release-certification/stable-third-party-pilot") / mode, "third-party pilot output")
    if any(output.iterdir()):
        raise ValueError("third-party pilot output directory must be empty")
    resolved_evidence: Path | None = None
    if evidence_dir is not None:
        resolved_evidence = _confined_existing_path(
            workspace,
            evidence_dir,
            "third-party pilot evidence directory",
            directory=True,
        )

    errors: list[str] = []
    key_errors, by_role = _key_errors(contract, evaluation)
    errors.extend(key_errors)
    errors.extend(_externality_errors(contract, policy, by_role, evaluation))
    errors.extend(_cohort_contract_errors(contract))
    errors.extend(_pilot_node_contract_errors(contract))
    if (contract["fixtureOnly"] or contract["selfTest"]) and contract["requestedState"] not in {
        "planned",
        "preflight-passed",
        "blocked",
        "partial",
    }:
        errors.append("fixture or self-test contract requests an operational state")
    if contract["repository"]["identity"] != policy["repositoryIdentity"] or contract["authorities"]["catalogChannel"] != policy["requiredCatalogChannel"]:
        errors.append("contract repository or catalog channel differs from policy")
    stages: dict[str, tuple[bool, str | None]] = {"preflight": (not errors, None)}
    handoff: dict[str, Any] | None = None
    review: dict[str, Any] | None = None
    approval: dict[str, Any] | None = None
    publication: dict[str, Any] | None = None
    runtime: dict[str, Any] | None = None

    required_rank = list(MODES).index(mode)
    if required_rank >= 1:
        handoff, stage_errors = _bound_json(contract, resolved_evidence, "externalHandoff", HANDOFF_SCHEMA)
        if not stage_errors:
            if not stages["preflight"][0]:
                stage_errors.append("external handoff validation blocked by invalid preflight")
            elif handoff is not None and resolved_evidence is not None:
                stage_errors.extend(
                    _handoff_errors(
                        contract, handoff, resolved_evidence, policy, evaluation
                    )
                )
        errors.extend(stage_errors)
        digest = contract["evidence"]["externalHandoff"]["digest"] if contract["evidence"]["externalHandoff"] else None
        stages["handoff"] = (stages["preflight"][0] and not stage_errors, digest)
    if required_rank >= 2:
        review, review_errors = _bound_json(contract, resolved_evidence, "reviewCohort", REVIEW_SCHEMA)
        approval, approval_errors = _bound_json(contract, resolved_evidence, "publisherApproval", APPROVAL_SCHEMA)
        if not stages.get("handoff", (False, None))[0]:
            review_errors.append("review validation blocked by invalid external handoff")
            approval_errors.append("publisher approval validation blocked by invalid external handoff")
        elif not review_errors and handoff is not None and review is not None and "app-reviewer" in by_role:
            review_errors.extend(
                _review_errors(
                    contract,
                    handoff,
                    review,
                    by_role["app-reviewer"],
                    evaluation,
                    policy["freshness"]["maximumReceiptAgeSeconds"],
                )
            )
        if not approval_errors and handoff is not None and approval is not None and "app-reviewer" in by_role:
            approval_errors.extend(
                _approval_errors(
                    contract,
                    handoff,
                    approval,
                    by_role["app-reviewer"],
                    evaluation,
                    policy["freshness"]["maximumReceiptAgeSeconds"],
                )
            )
        stage_errors = [*review_errors, *approval_errors]
        errors.extend(stage_errors)
        digest = contract["evidence"]["reviewCohort"]["digest"] if contract["evidence"]["reviewCohort"] else None
        stages["review"] = (
            stages.get("handoff", (False, None))[0] and not stage_errors,
            digest,
        )
    if required_rank >= 3:
        publication, stage_errors = _bound_json(contract, resolved_evidence, "catalogPublication", PUBLICATION_SCHEMA)
        if not stages.get("review", (False, None))[0]:
            stage_errors.append("catalog publication validation blocked by invalid review cohort")
        elif not stage_errors and review is not None and publication is not None and "catalog-signing" in by_role:
            stage_errors.extend(
                _publication_errors(
                    contract,
                    review,
                    publication,
                    by_role["catalog-signing"],
                    evaluation,
                    policy["freshness"]["maximumReceiptAgeSeconds"],
                )
            )
        errors.extend(stage_errors)
        digest = contract["evidence"]["catalogPublication"]["digest"] if contract["evidence"]["catalogPublication"] else None
        stages["publication"] = (
            stages.get("review", (False, None))[0] and not stage_errors,
            digest,
        )
    if required_rank >= 4:
        runtime, stage_errors = _bound_json(contract, resolved_evidence, "runtimeDrill", RUNTIME_SCHEMA)
        collector_summary, collector_errors = _bound_json(
            contract, resolved_evidence, "collectorSummary", COLLECTOR_SCHEMA
        )
        stage_errors.extend(collector_errors)
        if not stages.get("publication", (False, None))[0]:
            stage_errors.append(
                "runtime validation blocked by invalid review or catalog publication"
            )
        elif not stage_errors and (
            review is not None
            and approval is not None
            and publication is not None
            and runtime is not None
            and collector_summary is not None
        ):
            stage_errors.extend(
                _runtime_errors(
                    contract,
                    review,
                    approval,
                    publication,
                    runtime,
                    collector_summary,
                    evaluation,
                    policy["freshness"]["maximumReceiptAgeSeconds"],
                )
            )
        errors.extend(stage_errors)
        digest = contract["evidence"]["runtimeDrill"]["digest"] if contract["evidence"]["runtimeDrill"] else None
        stages["runtime"] = (
            stages.get("publication", (False, None))[0] and not stage_errors,
            digest,
        )
    if required_rank >= 5:
        root_errors = (
            _authority_root_errors(contract, resolved_evidence)
            if stages.get("runtime", (False, None))[0]
            else ["authority-root validation blocked by invalid runtime drill"]
        )
        errors.extend(root_errors)
        stages["roots"] = (
            stages.get("runtime", (False, None))[0] and not root_errors,
            None,
        )

    errors = sorted(set(errors))
    summary = _summary(contract, mode, stages, errors)
    summary_schema_errors = validate_schema(summary, SUMMARY_SCHEMA)
    if summary_schema_errors:
        raise ValueError("generated third-party pilot summary failed its closed schema: " + "; ".join(summary_schema_errors[:8]))
    report = _report(summary)
    generated_findings = scan_value([summary, report])
    if generated_findings:
        raise ValueError("generated third-party pilot outputs failed redaction validation")
    write_json(output / MODE_FILES[mode], summary)
    if MODE_FILES[mode] != SUMMARY_FILE:
        write_json(output / SUMMARY_FILE, summary)
    write_text(output / REPORT_FILE, report)
    write_json(output / REDACTION_FILE, {
        "schemaVersion": 1,
        "kind": "stable-1.0-third-party-app-pilot-redaction",
        "status": "pass",
        "findingCount": 0,
        "findings": [],
    })
    return 0 if not errors else 1

"""Side-effect-free Stable 1.0 catalog key and publication authority."""

from __future__ import annotations

import base64
import copy
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import stat
from typing import Any, Iterable
from urllib.parse import quote, unquote_to_bytes, urlsplit, urlunsplit

from ..io import read_json, read_json_bytes, write_bytes, write_json, write_text
from ..redaction import scan_value
from ..schema_validation import validate_schema


EXECUTION_SCHEMA = "stable-1.0-key-ceremony-execution-v1.schema.json"
RECEIPT_SCHEMA = "stable-1.0-key-ceremony-receipt-v1.schema.json"
TRANSPARENCY_SCHEMA = "stable-1.0-public-key-transparency-v1.schema.json"
PUBLICATION_PLAN_SCHEMA = "stable-1.0-catalog-publication-plan-v1.schema.json"
PUBLICATION_RECEIPT_SCHEMA = "stable-1.0-catalog-publication-receipt-v1.schema.json"
ROTATION_DRILL_SCHEMA = "stable-1.0-catalog-rotation-drill-v1.schema.json"
DRILL_RECEIPTS_SCHEMA = "stable-1.0-catalog-drill-receipts-v1.schema.json"
AUTHORITY_SUMMARY_SCHEMA = "stable-1.0-catalog-authority-summary-v1.schema.json"
MIRROR_OBSERVATION_SCHEMA = "stable-1.0-catalog-mirror-observation-v1.schema.json"
POLICY_FILE = "stable-1.0-catalog-authority-policy.json"

PROTECTED_RELEASE_SUMMARY_FILE = "stable-1.0-protected-release-execution-summary.json"
INDEPENDENT_SUMMARY_FILE = "stable-1.0-independent-reproducibility-summary.json"
SUBJECT_INVENTORY_FILE = "stable-1.0-release-subject-inventory.json"
FROZEN_CATALOG_FILE = "cryptad-app-catalog.properties"
FROZEN_SIGNATURE_FILE = "cryptad-app-catalog.signature"
ROLLBACK_CATALOG_FILE = "stable-1.0-rollback-app-catalog.properties"
ROLLBACK_SIGNATURE_FILE = "stable-1.0-rollback-app-catalog.signature"
GA_PLAN_FILE = "stable-1.0-ga-publication-plan.json"
GA_RECEIPT_FILE = "stable-1.0-ga-publication-receipt.json"
GA_OBSERVATION_FILE = "stable-1.0-protected-release-public-observation.json"
LIVE_PUBLICATION_FILE = "stable-1.0-live-usk-publication.json"
MIRROR_OBSERVATION_FILE = "stable-1.0-catalog-mirror-observation.json"
PREVIOUS_TRANSPARENCY_FILE = "stable-1.0-previous-public-key-transparency.json"
PREVIOUS_TRANSPARENCY_SIGNATURE_FILE = "stable-1.0-previous-public-key-transparency.signature"
RECOVERY_QUORUM_RECEIPT_FILE = "stable-1.0-protected-recovery-quorum-receipt.json"
DRILL_RECEIPTS_FILE = "stable-1.0-catalog-drill-receipts.json"

CEREMONY_SUMMARY_FILE = "stable-1.0-key-ceremony-summary.json"
CEREMONY_RECEIPT_FILE = "stable-1.0-key-ceremony-receipt.json"
TRANSPARENCY_FILE = "stable-1.0-public-key-transparency.json"
TRANSPARENCY_SIGNATURE_FILE = "stable-1.0-public-key-transparency.signature"
PUBLICATION_PLAN_FILE = "stable-1.0-catalog-publication-plan.json"
PUBLICATION_RECEIPT_FILE = "stable-1.0-catalog-publication-receipt.json"
ROTATION_DRILL_FILE = "stable-1.0-catalog-rotation-drill.json"
AUTHORITY_SUMMARY_FILE = "stable-1.0-catalog-authority-summary.json"
AUTHORITY_REPORT_FILE = "stable-1.0-catalog-authority-report.md"
REDACTION_FILE = "stable-1.0-catalog-authority-redaction-report.json"
CATALOG_REGISTRY_FILE = "stable-1.0-catalog-trusted-keys.properties"
APP_REGISTRY_FILE = "stable-1.0-app-trusted-keys.properties"
REVIEWER_REGISTRY_FILE = "stable-1.0-reviewer-trusted-keys.properties"
MAX_LIVE_PUBLICATION_RESULT_BYTES = 64 * 1024

MODES = (
    "prepare-ceremony",
    "verify-ceremony",
    "prepare-publication",
    "verify-publication",
    "verify-rotation-drill",
    "closeout",
)
ROLES = frozenset(
    {
        "catalog-signing",
        "first-party-app-signing",
        "app-reviewer",
        "offline-recovery",
    }
)
ROUTINE_ROLES = ROLES.difference({"offline-recovery"})
PROTECTED_RECOVERY_APPROVALS = 2
PROTECTED_RECOVERY_APPROVAL_ROLE = "stable-release-manager"
PROTECTED_RECOVERY_ENVIRONMENT = "stable-1-0-key-ceremony"
ACTIVE_LIFECYCLES = frozenset({"staged", "active", "retiring"})
HISTORICAL_LIFECYCLES = frozenset({"retired", "revoked"})
_LIFECYCLE_RANK = {
    "staged": 0,
    "active": 1,
    "retiring": 2,
    "retired": 3,
    "revoked": 4,
}
_COMPROMISE_RANK = {
    "uncompromised": 0,
    "suspected": 1,
    "compromised": 2,
}
REQUIRED_DRILLS = frozenset(
    {
        "planned-catalog-key-rotation",
        "compromised-catalog-key-recovery",
        "app-signing-key-rotation",
        "reviewer-key-rotation",
        "emergency-replacement-catalog",
        "catalog-rollback",
    }
)
ZERO_DIGEST = "sha256:" + "0" * 64
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")

_PRIVATE_MATERIAL = re.compile(
    r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----|"
    r"-----BEGIN OPENSSH PRIVATE KEY-----|"
    r"\b(?:bearer|authorization|set-cookie|cookie)\s*[:= ]|"
    r"\b(?:form[_ -]?password|private[_ -]?insert|private[_ -]?key)\b",
    re.IGNORECASE,
)
_ABSOLUTE_PATH = re.compile(r"(?:^|[\s\"'])/(?:home|tmp|var|private|Users|runner)/|[A-Za-z]:\\|\\\\")
_PUBLIC_USK = re.compile(
    r"^crypta:USK@(?P<routing>[A-Za-z0-9~-]{43}),(?P<crypto>[A-Za-z0-9~-]{43}),"
    r"AQACAAE/(?P<name>[A-Za-z0-9._-]{1,128})/(?P<edition>[1-9][0-9]{0,9})/"
    r"cryptad-app-catalog\.properties$"
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


def _digest(value: Any) -> str:
    return _digest_bytes(_canonical_bytes(value))


def _file_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _semantic_digest(value: dict[str, Any], field: str) -> str:
    normalized = copy.deepcopy(value)
    normalized[field] = ZERO_DIGEST
    return _digest(normalized)


def _timestamp(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp is missing an offset")
    return parsed.astimezone(dt.timezone.utc)


def _policy(workspace_root: Path) -> tuple[dict[str, Any], str]:
    path = workspace_root / "tools" / "release-certification" / POLICY_FILE
    value = read_json(path)
    if not isinstance(value, dict):
        raise ValueError("Stable catalog authority policy is malformed")
    expected = _semantic_digest(value, "policyDigest")
    if value.get("policyDigest") != expected:
        raise ValueError("Stable catalog authority policy digest is invalid")
    return value, expected


def _policy_contract_errors(policy: dict[str, Any]) -> list[str]:
    """Require the checked-in policy to match every enforced closed contract."""

    expected = {
        "schemaVersion": 1,
        "kind": "stable-1.0-catalog-authority-policy",
        "policyId": "cryptad-stable-1.0-catalog-authority",
        "releaseMilestone": "Stable 1.0",
        "algorithm": "Ed25519",
        "requiredRoles": sorted(ROLES),
        "routineSigningRoles": sorted(ROUTINE_ROLES),
        "ceremonyTypes": [
            "compromise-recovery",
            "emergency-replacement",
            "genesis",
            "planned-rotation",
        ],
        "lifecycleStates": ["active", "retired", "retiring", "revoked", "staged"],
        "compromiseStates": ["compromised", "suspected", "uncompromised"],
        "proofOfPossession": {
            "currentKeysetLifecycles": sorted(ACTIVE_LIFECYCLES),
            "retainedHistoricalLifecycles": sorted(HISTORICAL_LIFECYCLES),
            "offlineRecoveryRoutineProofAllowed": False,
        },
        "requiredDrills": sorted(REQUIRED_DRILLS),
        "publication": {
            "minimumIndependentMirrors": 1,
            "networkPrimaryType": "network-primary",
            "requiredChannel": "stable",
            "requireExactSignatureSibling": True,
            "requireRevisionAndEditionAdvanceOnSubjectChange": True,
            "mirrorsAreTrustAuthorities": False,
        },
        "recovery": {
            "routineSigningAllowed": False,
            "genesisRequiresProtectedApproval": True,
            "successorRequiresPriorRecoveryAuthorization": True,
            "compromiseQuorumRequiresProtectedAuthentication": True,
            "protectedQuorumApprovals": PROTECTED_RECOVERY_APPROVALS,
            "protectedQuorumApprovalRole": PROTECTED_RECOVERY_APPROVAL_ROLE,
            "protectedQuorumEnvironment": PROTECTED_RECOVERY_ENVIRONMENT,
        },
        "evidence": {
            "localModesAreSideEffectFree": True,
            "fixtureOperationalCompletionAllowed": False,
            "workflowDefinitionIsOperationalEvidence": False,
            "publicKeysAllowedOnlyInTransparencyAndRegistries": True,
        },
        "bounds": {
            "maximumKeys": 64,
            "maximumMirrors": 8,
            "maximumCatalogBytes": 1048576,
            "maximumSignatureBytes": 65536,
        },
    }
    actual = {name: policy.get(name) for name in expected}
    if actual != expected:
        return ["checked-in catalog authority policy differs from the enforced closed contract"]
    return []


def _spki_bytes(key: dict[str, Any]) -> bytes:
    try:
        raw = base64.b64decode(key["publicKeySpkiBase64"], validate=True)
    except (KeyError, ValueError) as exc:
        raise ValueError("public Ed25519 SPKI is malformed") from exc
    if len(raw) != len(SPKI_PREFIX) + 32 or not raw.startswith(SPKI_PREFIX):
        raise ValueError("public key is not canonical Ed25519 SubjectPublicKeyInfo")
    return raw


def _raw_public_key(key: dict[str, Any]) -> bytes:
    return _spki_bytes(key)[len(SPKI_PREFIX) :]


# Bounded RFC 8032 verification. Production signing never occurs in this engine.
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = x * _I % _P
    if x & 1:
        x = _P - x
    return x


_BY = 4 * pow(5, _P - 2, _P) % _P
_BX = _xrecover(_BY)
_B = (_BX, _BY, 1, _BX * _BY % _P)
_IDENTITY_ENCODING = bytes.fromhex("01" + "00" * 31)


def _edwards_add(left: tuple[int, int, int, int], right: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * _D * t1 * t2 % _P
    d = 2 * z1 * z2 % _P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return e * f % _P, g * h % _P, f * g % _P, e * h % _P


def _scalarmult(point: tuple[int, int, int, int], scalar: int) -> tuple[int, int, int, int]:
    result = (0, 1, 1, 0)
    addend = point
    while scalar:
        if scalar & 1:
            result = _edwards_add(result, addend)
        addend = _edwards_add(addend, addend)
        scalar >>= 1
    return result


def _decode_point(encoded: bytes) -> tuple[int, int, int, int]:
    if len(encoded) != 32:
        raise ValueError("Ed25519 point has the wrong length")
    value = int.from_bytes(encoded, "little")
    y = value & ((1 << 255) - 1)
    if y >= _P:
        raise ValueError("Ed25519 point is non-canonical")
    x = _xrecover(y)
    if (x & 1) != (value >> 255):
        x = _P - x
    if (-x * x + y * y - 1 - _D * x * x * y * y) % _P:
        raise ValueError("Ed25519 point is not on the curve")
    return x, y, 1, x * y % _P


def _encode_point(point: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = point
    zi = pow(z, _P - 2, _P)
    affine_x = x * zi % _P
    affine_y = y * zi % _P
    return (affine_y | ((affine_x & 1) << 255)).to_bytes(32, "little")


def _verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        public_point = _decode_point(public_key)
        encoded_r = signature[:32]
        r_point = _decode_point(encoded_r)
    except ValueError:
        return False
    # Require the public key and R to be non-identity members of the prime-order
    # subgroup. Otherwise a small-order key can satisfy the verification
    # equation without proving possession of an Ed25519 secret.
    for encoded, point in ((public_key, public_point), (encoded_r, r_point)):
        canonical = _encode_point(point)
        if canonical != encoded or canonical == _IDENTITY_ENCODING:
            return False
        if _encode_point(_scalarmult(point, _L)) != _IDENTITY_ENCODING:
            return False
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= _L:
        return False
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public_key + message).digest(), "little"
    ) % _L
    return _encode_point(_scalarmult(_B, scalar)) == _encode_point(
        _edwards_add(r_point, _scalarmult(public_point, challenge))
    )


def _decode_signature(value: str | None, label: str) -> bytes:
    if value is None:
        raise ValueError(f"{label} is missing")
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ValueError(f"{label} is malformed") from exc
    if len(raw) != 64:
        raise ValueError(f"{label} must be one Ed25519 signature")
    return raw


def _keyset_subject(manifest: dict[str, Any]) -> dict[str, Any]:
    keyset = manifest["keyset"]
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-public-keyset-subject",
        "keysetVersion": keyset["keysetVersion"],
        "previousKeysetDigest": keyset["previousKeysetDigest"],
        "ceremony": manifest["ceremony"],
        "release": manifest["release"],
        "bindings": manifest["bindings"],
        "keys": [
            {
                name: key[name]
                for name in (
                    "keyId",
                    "role",
                    "algorithm",
                    "publicKeySpkiBase64",
                    "publicKeyFingerprintSha256",
                    "lifecycle",
                    "validFrom",
                    "validUntil",
                    "predecessorKeyId",
                    "successorKeyId",
                    "compromiseState",
                    "publicTransparencyEligible",
                )
            }
            for key in sorted(keyset["keys"], key=lambda row: row["keyId"])
        ],
    }


def _proof_statement(manifest: dict[str, Any], key: dict[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-key-proof-of-possession",
        "domain": "cryptad-stable-1.0-key-proof-of-possession-v1",
        "ceremonyId": manifest["ceremony"]["ceremonyId"],
        "releaseMilestone": manifest["ceremony"]["releaseMilestone"],
        "keyRole": key["role"],
        "keyId": key["keyId"],
        "algorithm": key["algorithm"],
        "publicKeyFingerprintSha256": key["publicKeyFingerprintSha256"],
        "validFrom": key["validFrom"],
        "validUntil": key["validUntil"],
        "predecessorKeyId": key["predecessorKeyId"],
        "successorKeyId": key["successorKeyId"],
        "keysetDigest": manifest["keyset"]["keysetDigest"],
    }


def _historical_proof_errors(
    manifest: dict[str, Any], key: dict[str, Any], statement: dict[str, Any]
) -> list[str]:
    """Validate an earlier proof statement without requiring a historical key to sign again."""

    errors: list[str] = []
    expected = {
        "schemaVersion": 1,
        "kind": "stable-1.0-key-proof-of-possession",
        "domain": "cryptad-stable-1.0-key-proof-of-possession-v1",
        "releaseMilestone": manifest["ceremony"]["releaseMilestone"],
        "keyRole": key["role"],
        "keyId": key["keyId"],
        "algorithm": key["algorithm"],
        "publicKeyFingerprintSha256": key["publicKeyFingerprintSha256"],
        "validFrom": key["validFrom"],
        "validUntil": key["validUntil"],
        "predecessorKeyId": key["predecessorKeyId"],
    }
    if any(statement.get(name) != value for name, value in expected.items()):
        errors.append(f"key {key['keyId']} retained proof does not bind its historical public identity")
    if not isinstance(statement.get("ceremonyId"), str):
        errors.append(f"key {key['keyId']} retained proof lacks its originating ceremony")
    if statement.get("successorKeyId") not in {None, key["successorKeyId"]}:
        errors.append(f"key {key['keyId']} retained proof names an unrelated successor")
    if statement.get("keysetDigest") == manifest["keyset"]["keysetDigest"]:
        errors.append(f"key {key['keyId']} retained proof must originate from an earlier keyset")
    return errors


def _recovery_statement(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-keyset-transition-authorization",
        "domain": "cryptad-stable-1.0-keyset-transition-authorization-v1",
        "ceremonyId": manifest["ceremony"]["ceremonyId"],
        "ceremonyType": manifest["ceremony"]["ceremonyType"],
        "releaseMilestone": manifest["ceremony"]["releaseMilestone"],
        "release": manifest["release"],
        "protectedReleaseContractDigest": manifest["bindings"]["protectedReleaseContractDigest"],
        "independentReproducibilityResultDigest": manifest["bindings"]["independentReproducibilityResultDigest"],
        "keysetVersion": manifest["keyset"]["keysetVersion"],
        "previousKeysetDigest": manifest["keyset"]["previousKeysetDigest"],
        "keysetDigest": manifest["keyset"]["keysetDigest"],
        "transparencySigningKeyId": manifest["transparency"]["signingKeyId"],
        "effectiveAt": manifest["ceremony"]["effectiveAt"],
    }


def _validate_lineage(keys: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    by_id = {key["keyId"]: key for key in keys}
    edges: dict[str, str] = {}
    for key in keys:
        predecessor = key["predecessorKeyId"]
        successor = key["successorKeyId"]
        if predecessor == key["keyId"] or successor == key["keyId"]:
            errors.append(f"key {key['keyId']} has a self-referential rotation link")
        if predecessor is not None:
            linked = by_id.get(predecessor)
            if linked is None:
                errors.append(f"key {key['keyId']} names an unavailable predecessor")
            elif linked["role"] != key["role"] or linked["successorKeyId"] != key["keyId"]:
                errors.append(f"key {key['keyId']} predecessor link is not reciprocal and same-role")
        if successor is not None:
            linked = by_id.get(successor)
            if linked is None:
                errors.append(f"key {key['keyId']} names an unavailable successor")
            elif linked["role"] != key["role"] or linked["predecessorKeyId"] != key["keyId"]:
                errors.append(f"key {key['keyId']} successor link is not reciprocal and same-role")
            if key["keyId"] in edges:
                errors.append(f"key {key['keyId']} has duplicate successor links")
            edges[key["keyId"]] = successor
    for start in edges:
        seen: set[str] = set()
        current: str | None = start
        while current in edges:
            if current in seen:
                errors.append("key predecessor/successor graph contains a cycle")
                break
            seen.add(current)
            current = edges[current]
    return sorted(set(errors))


def _validate_keyset(manifest: dict[str, Any], verify_signatures: bool) -> tuple[list[str], dict[str, dict[str, Any]]]:
    errors: list[str] = []
    keys = manifest["keyset"]["keys"]
    effective_at = _timestamp(manifest["ceremony"]["effectiveAt"])
    by_id: dict[str, dict[str, Any]] = {}
    fingerprints: set[str] = set()
    roles: set[str] = set()
    for key in keys:
        key_id = key["keyId"]
        if key_id in by_id:
            errors.append(f"duplicate key id: {key_id}")
        by_id[key_id] = key
        fingerprint = key["publicKeyFingerprintSha256"]
        if fingerprint in fingerprints:
            errors.append("one public-key fingerprint is reused across roles or key ids")
        fingerprints.add(fingerprint)
        roles.add(key["role"])
        try:
            spki = _spki_bytes(key)
            if fingerprint != _digest_bytes(spki):
                errors.append(f"key {key_id} public-key fingerprint does not match its SPKI")
        except ValueError as exc:
            errors.append(str(exc))
            continue
        try:
            valid_from = _timestamp(key["validFrom"])
            valid_until = _timestamp(key["validUntil"])
            if valid_from >= valid_until:
                errors.append(f"key {key_id} has an invalid validity window")
            elif key["lifecycle"] in ACTIVE_LIFECYCLES and not (
                valid_from <= effective_at < valid_until
            ):
                errors.append(f"key {key_id} is not valid at the ceremony effective time")
        except ValueError:
            errors.append(f"key {key_id} has an invalid validity timestamp")
        if key["lifecycle"] in ACTIVE_LIFECYCLES and key["compromiseState"] != "uncompromised":
            errors.append(f"key {key_id} is active while suspected or compromised")
        if key["lifecycle"] == "revoked" and key["compromiseState"] == "uncompromised":
            errors.append(f"revoked key {key_id} lacks a compromise state")
        if not key["publicTransparencyEligible"]:
            errors.append(f"key {key_id} is excluded from the required public transparency set")
        proof = key["proofOfPossession"]
        if key["role"] == "offline-recovery":
            if proof != {
                "proofType": "not-applicable-recovery",
                "statement": None,
                "statementDigest": None,
                "signatureBase64": None,
            }:
                errors.append("offline recovery key must not carry routine proof-of-possession material")
            continue
        statement = proof["statement"]
        expected_type = (
            "current-keyset"
            if key["lifecycle"] in ACTIVE_LIFECYCLES
            else "retained-historical"
        )
        if proof["proofType"] != expected_type:
            errors.append(
                f"key {key_id} lifecycle requires a {expected_type} proof of possession"
            )
        if not isinstance(statement, dict):
            errors.append(f"key {key_id} proof statement is missing")
            continue
        if expected_type == "current-keyset":
            if statement != _proof_statement(manifest, key):
                errors.append(f"key {key_id} current proof statement is invalid")
        else:
            errors.extend(_historical_proof_errors(manifest, key, statement))
        statement_bytes = _canonical_bytes(statement)
        if proof["statementDigest"] != _digest_bytes(statement_bytes):
            errors.append(f"key {key_id} proof statement digest is invalid")
        if verify_signatures:
            try:
                signature = _decode_signature(proof["signatureBase64"], f"key {key_id} proof signature")
                if not _verify_ed25519(_raw_public_key(key), statement_bytes, signature):
                    errors.append(f"key {key_id} proof of possession is invalid")
            except ValueError as exc:
                errors.append(str(exc))
    if roles != ROLES:
        errors.append("keyset must contain every role in the closed Stable ecosystem role set")
    expected_keyset_digest = _digest(_keyset_subject(manifest))
    if manifest["keyset"]["keysetDigest"] != expected_keyset_digest:
        errors.append("keyset digest does not match the canonical public keyset subject")
    ceremony_type = manifest["ceremony"]["ceremonyType"]
    previous = manifest["keyset"]["previousKeysetDigest"]
    if ceremony_type == "genesis" and (previous is not None or manifest["keyset"]["keysetVersion"] != 1):
        errors.append("genesis must use keyset version 1 without a predecessor")
    if ceremony_type != "genesis" and (previous is None or manifest["keyset"]["keysetVersion"] <= 1):
        errors.append("successor ceremonies require a prior keyset digest and version advance")
    if ceremony_type == "planned-rotation" and not any(
        key["predecessorKeyId"] is not None or key["successorKeyId"] is not None
        for key in keys
    ):
        errors.append("planned rotation must contain an authenticated predecessor/successor transition")
    ceremony = manifest["ceremony"]
    try:
        if _timestamp(ceremony["preparedAt"]) > effective_at:
            errors.append("ceremony preparation occurs after its effective time")
        generated = _timestamp(manifest["transparency"]["generatedAt"])
        transparency_effective = _timestamp(manifest["transparency"]["effectiveAt"])
        if generated < effective_at or generated > transparency_effective:
            errors.append("transparency generation/effective ordering is invalid")
        if manifest["fixtureOnly"] != (ceremony["custodyClass"] == "fixture-memory-only"):
            errors.append("ceremony custody classification does not match fixture status")
    except ValueError:
        errors.append("ceremony governance timestamps are invalid")
    errors.extend(_validate_lineage(keys))
    return sorted(set(errors)), by_id


def _validate_recovery(manifest: dict[str, Any], by_id: dict[str, dict[str, Any]], verify_signatures: bool) -> list[str]:
    errors: list[str] = []
    authorization = manifest["recoveryAuthorization"]
    statement = _recovery_statement(manifest)
    statement_bytes = _canonical_bytes(statement)
    if authorization["statementDigest"] != _digest_bytes(statement_bytes):
        errors.append("recovery authorization statement digest is invalid")
    if authorization["authorizationType"] == "protected-recovery-quorum":
        approval = manifest["ceremony"]["approvalQuorum"]
        if manifest["ceremony"]["ceremonyType"] not in {"compromise-recovery", "emergency-replacement"}:
            errors.append("protected recovery quorum is allowed only for recovery or emergency replacement")
        if approval != {
            "requiredApprovals": PROTECTED_RECOVERY_APPROVALS,
            "approvalRole": PROTECTED_RECOVERY_APPROVAL_ROLE,
            "protectedEnvironment": PROTECTED_RECOVERY_ENVIRONMENT,
        }:
            errors.append("protected recovery quorum does not select the fixed recovery governance")
        if authorization["protectedRecoveryQuorumDigest"] is None:
            errors.append("protected recovery quorum authorization lacks its authenticated digest")
        if authorization["signatureBase64"] is not None or authorization["signingRecoveryKeyId"] is not None:
            errors.append("protected recovery quorum cannot also claim a recovery-key signature")
        return errors
    key_id = authorization["signingRecoveryKeyId"]
    key = by_id.get(key_id) if isinstance(key_id, str) else None
    if key is None or key["role"] != "offline-recovery":
        errors.append("recovery authorization signer is not the declared recovery key")
        return errors
    if key["lifecycle"] not in {"active", "retiring"} or key["compromiseState"] != "uncompromised":
        errors.append("recovery key is not active, uncompromised, and authorized")
    if authorization["protectedRecoveryQuorumDigest"] is not None:
        errors.append("recovery signature authorization cannot carry a protected quorum digest")
    if verify_signatures:
        try:
            signature = _decode_signature(authorization["signatureBase64"], "recovery authorization signature")
            if not _verify_ed25519(_raw_public_key(key), statement_bytes, signature):
                errors.append("offline recovery transition signature is invalid")
        except ValueError as exc:
            errors.append(str(exc))
    return errors


def _canonical_location_uri(location: dict[str, Any]) -> str:
    value = location["publicUri"]
    if location["locationType"] in {"network-primary", "network-mirror"}:
        if _PUBLIC_USK.fullmatch(value) is None:
            raise ValueError("network catalog locations must be public Crypta USK catalog sources")
        return value
    split = urlsplit(value)
    if (
        split.scheme != "https"
        or not split.netloc
        or split.username is not None
        or split.password is not None
        or split.query
        or split.fragment
        or split.hostname is None
    ):
        raise ValueError("public web mirrors must be canonical credential-free HTTPS locations")
    try:
        host = split.hostname.encode("idna").decode("ascii").lower()
        port = split.port
        decoded_path = unquote_to_bytes(split.path).decode("utf-8", "strict")
    except (UnicodeError, ValueError) as exc:
        raise ValueError("public web mirrors must use canonical HTTPS identifiers") from exc
    if port not in {None, 443}:
        raise ValueError("public web mirrors must use the protected collector HTTPS port 443")
    if any(ord(character) < 32 for character in decoded_path) or "\\" in decoded_path:
        raise ValueError("public web mirrors must use canonical HTTPS paths")
    normalized_path = posixpath.normpath(decoded_path)
    if not normalized_path.startswith("/"):
        normalized_path = "/" + normalized_path
    if decoded_path.endswith("/") and normalized_path != "/":
        normalized_path += "/"
    if ":" in host:
        host = f"[{host}]"
    canonical_path = quote(normalized_path, safe="/-._~")
    return urlunsplit(("https", host, canonical_path, "", ""))


def _catalog_subject(catalog: dict[str, Any]) -> dict[str, Any]:
    return {
        name: catalog[name]
        for name in (
            "catalogId",
            "channel",
            "revision",
            "uskEdition",
            "catalogDigest",
            "catalogSize",
            "signatureDigest",
            "signatureSize",
            "signingKeyId",
            "signingKeyFingerprintSha256",
        )
    }


def _key_valid_at(key: dict[str, Any], instant: dt.datetime | None) -> bool:
    if instant is None:
        return False
    try:
        return _timestamp(key["validFrom"]) <= instant < _timestamp(key["validUntil"])
    except (AttributeError, KeyError, TypeError, ValueError):
        return False


def _mirror_collection_errors(
    manifest: dict[str, Any],
    mirror: dict[str, Any],
    by_id: dict[str, dict[str, Any]],
) -> list[str]:
    """Validate actual protected collection times and catalog-key eligibility."""

    try:
        reviewed_at = max(
            _timestamp(row["observedAt"])
            for row in manifest["publication"]["observations"]
        )
        collection_started_at = _timestamp(mirror["collectionStartedAt"])
        collection_completed_at = _timestamp(mirror["collectionCompletedAt"])
        signer = by_id.get(manifest["catalog"]["signingKeyId"])
        rollback = manifest["publication"]["rollback"]
        rollback_signer = by_id.get(rollback["signingKeyId"])
        if (
            reviewed_at > collection_started_at
            or collection_started_at - reviewed_at > dt.timedelta(minutes=15)
            or collection_completed_at < collection_started_at
            or collection_completed_at - reviewed_at > dt.timedelta(minutes=15)
            or signer is None
            or signer["role"] != "catalog-signing"
            or signer["lifecycle"] != "active"
            or signer["compromiseState"] != "uncompromised"
            or not _key_valid_at(signer, collection_completed_at)
        ):
            return [
                "independent mirror collection window or catalog-signer lifecycle is invalid"
            ]
        if (
            rollback_signer is None
            or rollback_signer["role"] != "catalog-signing"
            or rollback_signer["publicKeyFingerprintSha256"]
            != rollback["signingKeyFingerprintSha256"]
            or rollback_signer["lifecycle"]
            not in {"active", "retiring", "retired"}
            or rollback_signer["compromiseState"] != "uncompromised"
            or not _key_valid_at(rollback_signer, collection_completed_at)
        ):
            return [
                "independent mirror collection completed outside the rollback-signer support window"
            ]
    except (AttributeError, KeyError, TypeError, ValueError):
        return ["independent mirror collection timestamps are invalid"]
    return []


def _validate_publication(
    manifest: dict[str, Any],
    by_id: dict[str, dict[str, Any]],
    require_observations: bool,
    rollback_drill_completed_at: str | None = None,
    require_drills: bool = False,
) -> list[str]:
    errors: list[str] = []
    try:
        verification_instants = [
            _timestamp(manifest["transparency"]["effectiveAt"])
        ]
        if require_observations:
            verification_instants.extend(
                _timestamp(row["observedAt"])
                for row in manifest["publication"]["observations"]
            )
        if require_drills:
            if rollback_drill_completed_at is None:
                raise ValueError("authenticated rollback drill timestamp is unavailable")
            verification_instants.append(_timestamp(rollback_drill_completed_at))
        verification_at = max(verification_instants)
    except ValueError:
        verification_at = None
        errors.append("publication key eligibility timestamp is invalid")
    publication = manifest["publication"]
    primary = publication["networkPrimary"]
    mirrors = publication["mirrors"]
    if primary["locationType"] != "network-primary":
        errors.append("network primary has the wrong closed location type")
    primary_match = _PUBLIC_USK.fullmatch(primary["publicUri"])
    if (
        primary_match is not None
        and int(primary_match.group("edition")) != manifest["catalog"]["uskEdition"]
    ):
        errors.append("network primary URI edition does not match the frozen catalog edition")
    aliases: set[str] = set()
    for location in [primary, *mirrors]:
        try:
            canonical = _canonical_location_uri(location)
            if canonical in aliases:
                errors.append("publication locations contain a duplicate or alias")
            aliases.add(canonical)
        except ValueError as exc:
            errors.append(str(exc))
        if location["trustAuthority"] is not False:
            errors.append("publication mirror is represented as a trust authority")
    if any(mirror["locationType"] == "network-primary" for mirror in mirrors):
        errors.append("mirror list contains another primary")
    independent = [
        mirror
        for mirror in mirrors
        if mirror["operatorId"] != primary["operatorId"]
        or mirror["providerId"] != primary["providerId"]
        or mirror["controlPlaneId"] != primary["controlPlaneId"]
    ]
    if not independent:
        errors.append(
            "at least one mirror must have an independent operator, provider, or control plane"
        )
    catalog = manifest["catalog"]
    signer = by_id.get(catalog["signingKeyId"])
    if signer is None or signer["role"] != "catalog-signing":
        errors.append("frozen catalog signer is not a catalog-signing key")
    elif (
        signer["publicKeyFingerprintSha256"] != catalog["signingKeyFingerprintSha256"]
        or signer["lifecycle"] != "active"
        or signer["compromiseState"] != "uncompromised"
        or not _key_valid_at(signer, verification_at)
    ):
        errors.append("frozen catalog signer is not an active authorized catalog key")
    rollback = publication["rollback"]
    rollback_location = {
        "locationType": "network-mirror" if rollback["publicUri"].startswith("crypta:") else "public-web-mirror",
        "publicUri": rollback["publicUri"],
    }
    try:
        _canonical_location_uri(rollback_location)
        rollback_match = _PUBLIC_USK.fullmatch(rollback["publicUri"])
        if rollback_match is not None and int(rollback_match.group("edition")) != rollback["uskEdition"]:
            errors.append("rollback URI edition does not match the rollback subject")
    except ValueError as exc:
        errors.append(str(exc))
    if rollback["revision"] >= catalog["revision"] or rollback["uskEdition"] >= catalog["uskEdition"]:
        errors.append("rollback subject must use an older revision and USK edition")
    if rollback["catalogId"] != catalog["catalogId"] or rollback["channel"] != catalog["channel"]:
        errors.append("rollback subject must preserve the Stable catalog identity")
    if rollback["catalogDigest"] == catalog["catalogDigest"]:
        errors.append("rollback subject must have different catalog bytes")
    if rollback["signatureDigest"] == catalog["signatureDigest"]:
        errors.append("rollback subject must have a distinct detached signature")
    rollback_signer = by_id.get(rollback["signingKeyId"])
    if (
        rollback_signer is None
        or rollback_signer["role"] != "catalog-signing"
        or rollback_signer["publicKeyFingerprintSha256"] != rollback["signingKeyFingerprintSha256"]
        or rollback_signer["lifecycle"] not in {"active", "retiring", "retired"}
        or rollback_signer["compromiseState"] != "uncompromised"
        or not _key_valid_at(rollback_signer, verification_at)
    ):
        errors.append(
            "rollback signer is unavailable, out of window, revoked, compromised, or role-confused"
        )
    observations = publication["observations"]
    if require_observations:
        expected_ids = {location["locationId"] for location in [primary, *mirrors]}
        observed_ids = {row["locationId"] for row in observations}
        if observed_ids != expected_ids or len(observations) != len(expected_ids):
            errors.append("publication observations do not cover each exact location once")
        expected_subject = _catalog_subject(catalog)
        for observation in observations:
            if observation["status"] != "exact-match":
                errors.append(f"location {observation['locationId']} did not return the exact authorized subject")
            if any(observation[name] != expected_subject[name] for name in expected_subject):
                errors.append(f"location {observation['locationId']} returned a mismatched catalog or signature subject")
        if publication["requestedState"] != "observed":
            errors.append("complete observations cannot be represented as a partial publication state")
    elif publication["requestedState"] == "observed" and not observations:
        errors.append("publication claims observed state without observations")
    return sorted(set(errors))


def _validate_drills(
    manifest: dict[str, Any],
    require_complete: bool,
    evidence_dir: Path | None,
) -> tuple[list[str], dict[str, str]]:
    errors: list[str] = []
    authenticated_completion_times: dict[str, str] = {}
    drills = manifest["drills"]
    types = [row["drillType"] for row in drills]
    if len(types) != len(set(types)):
        errors.append("rotation and recovery drills contain a duplicate type")
    if require_complete and set(types) != REQUIRED_DRILLS:
        errors.append("rotation and recovery drills do not cover the closed required set")
    for row in drills:
        if row["fixtureOnly"] != manifest["fixtureOnly"]:
            errors.append(f"drill {row['drillType']} fixture classification is inconsistent")
        if require_complete and (row["status"] != "pass" or row["completedAt"] is None):
            errors.append(f"drill {row['drillType']} did not pass")
        if row["completedAt"] is not None:
            try:
                if _timestamp(row["completedAt"]) < _timestamp(manifest["ceremony"]["effectiveAt"]):
                    errors.append(f"drill {row['drillType']} predates the effective ceremony")
            except ValueError:
                errors.append(f"drill {row['drillType']} has an invalid completion time")
    if not require_complete:
        return sorted(set(errors)), authenticated_completion_times
    if manifest["fixtureOnly"]:
        authenticated_completion_times = {
            row["drillType"]: row["completedAt"]
            for row in drills
            if row["completedAt"] is not None
        }
        return sorted(set(errors)), authenticated_completion_times
    if evidence_dir is None:
        errors.append("operational drill verification requires exact protected drill receipts")
        return sorted(set(errors)), authenticated_completion_times
    root, inspection_errors = _inspect_evidence_directory(evidence_dir)
    errors.extend(inspection_errors)
    if root is None:
        return sorted(set(errors)), authenticated_completion_times
    try:
        receipts, _ = _evidence_json(root, DRILL_RECEIPTS_FILE)
        errors.extend(validate_schema(receipts, DRILL_RECEIPTS_SCHEMA))
        errors.extend(_identity_errors(receipts, manifest))
        expected_bindings = {
            name: manifest["bindings"][name]
            for name in (
                "protectedReleaseSummaryDigest",
                "protectedReleaseContractDigest",
                "independentReproducibilitySummaryDigest",
                "independentReproducibilityResultDigest",
                "independentSubjectInventoryDigest",
            )
        }
        if (
            receipts.get("ceremonyId") != manifest["ceremony"]["ceremonyId"]
            or receipts.get("keysetDigest") != manifest["keyset"]["keysetDigest"]
            or receipts.get("bindings") != expected_bindings
            or receipts.get("catalogSubject") != _catalog_subject(manifest["catalog"])
            or receipts.get("fixtureOnly") is not False
            or receipts.get("operational") is not True
            or receipts.get("status") != "pass"
        ):
            errors.append("protected drill receipts do not bind the exact catalog authority")
        if receipts.get("bundleDigest") != _semantic_digest(receipts, "bundleDigest"):
            errors.append("protected drill receipt bundle self-digest is invalid")
        if _sensitive_findings(receipts):
            errors.append("protected drill receipts failed redaction validation")
        receipt_rows = receipts.get("drills", [])
        receipt_types = [
            row.get("drillType") for row in receipt_rows if isinstance(row, dict)
        ]
        if set(receipt_types) != REQUIRED_DRILLS or len(receipt_types) != len(
            REQUIRED_DRILLS
        ):
            errors.append("protected drill receipts do not cover each required type once")
        receipts_by_type = {
            row["drillType"]: row for row in receipt_rows if isinstance(row, dict)
        }
        for row in drills:
            receipt = receipts_by_type.get(row["drillType"])
            if receipt is None:
                errors.append(f"drill {row['drillType']} lacks an authenticated receipt")
                continue
            if receipt.get("receiptDigest") != _semantic_digest(
                receipt, "receiptDigest"
            ):
                errors.append(f"drill {row['drillType']} receipt self-digest is invalid")
            if (
                row["status"] != receipt.get("status")
                or row["completedAt"] != receipt.get("completedAt")
                or row["subjectDigest"] != receipt.get("receiptDigest")
            ):
                errors.append(
                    f"drill {row['drillType']} does not match its authenticated receipt"
                )
            completed_at = receipt.get("completedAt")
            if isinstance(completed_at, str):
                authenticated_completion_times[row["drillType"]] = completed_at
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(str(exc))
    return sorted(set(errors)), authenticated_completion_times


def _transparency_artifact(manifest: dict[str, Any]) -> dict[str, Any]:
    keyset = manifest["keyset"]
    artifact: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": "stable-1.0-public-key-transparency",
        "keysetVersion": keyset["keysetVersion"],
        "keysetDigest": keyset["keysetDigest"],
        "previousKeysetDigest": keyset["previousKeysetDigest"],
        "ceremonyId": manifest["ceremony"]["ceremonyId"],
        "ceremonyType": manifest["ceremony"]["ceremonyType"],
        "governance": {
            name: manifest["ceremony"][name]
            for name in ("preparedAt", "effectiveAt", "custodyClass", "approvalQuorum")
        },
        "release": {
            name: manifest["release"][name]
            for name in ("releaseId", "buildVersion", "sourceCommit")
        },
        "bindings": {
            name: manifest["bindings"][name]
            for name in (
                "protectedReleaseSummaryDigest",
                "protectedReleaseContractDigest",
                "independentReproducibilitySummaryDigest",
                "independentReproducibilityResultDigest",
                "independentSubjectInventoryDigest",
            )
        },
        "keys": [],
        "catalog": _catalog_subject(manifest["catalog"]),
        "locations": [manifest["publication"]["networkPrimary"], *manifest["publication"]["mirrors"]],
        "transparencySigningKeyId": manifest["transparency"]["signingKeyId"],
        "recoveryAuthorization": {
            "authorizationType": manifest["recoveryAuthorization"]["authorizationType"],
            "signingRecoveryKeyId": manifest["recoveryAuthorization"]["signingRecoveryKeyId"],
            "statementDigest": manifest["recoveryAuthorization"]["statementDigest"],
            "signatureDigest": (
                _digest_bytes(base64.b64decode(manifest["recoveryAuthorization"]["signatureBase64"], validate=True))
                if manifest["recoveryAuthorization"]["signatureBase64"] is not None
                else None
            ),
            "protectedRecoveryQuorumDigest": manifest["recoveryAuthorization"]["protectedRecoveryQuorumDigest"],
        },
        "generatedAt": manifest["transparency"]["generatedAt"],
        "effectiveAt": manifest["transparency"]["effectiveAt"],
        "selfDigest": ZERO_DIGEST,
    }
    for key in sorted(keyset["keys"], key=lambda row: row["keyId"]):
        proof = key["proofOfPossession"]
        signature = proof["signatureBase64"]
        artifact["keys"].append(
            {
                name: key[name]
                for name in (
                    "keyId",
                    "role",
                    "algorithm",
                    "publicKeySpkiBase64",
                    "publicKeyFingerprintSha256",
                    "lifecycle",
                    "validFrom",
                    "validUntil",
                    "predecessorKeyId",
                    "successorKeyId",
                    "compromiseState",
                    "publicTransparencyEligible",
                )
            }
            | {
                "proofType": proof["proofType"],
                "proofCeremonyId": (
                    proof["statement"]["ceremonyId"]
                    if isinstance(proof["statement"], dict)
                    else None
                ),
                "proofKeysetDigest": (
                    proof["statement"]["keysetDigest"]
                    if isinstance(proof["statement"], dict)
                    else None
                ),
                "proofStatementDigest": proof["statementDigest"] if key["role"] in ROUTINE_ROLES else None,
                "proofSignatureDigest": (
                    _digest_bytes(base64.b64decode(signature, validate=True))
                    if signature is not None and key["role"] in ROUTINE_ROLES
                    else None
                ),
            }
        )
    artifact["selfDigest"] = _semantic_digest(artifact, "selfDigest")
    return artifact


def _validate_transparency_signature(manifest: dict[str, Any], artifact: dict[str, Any], by_id: dict[str, dict[str, Any]], required: bool) -> tuple[list[str], bytes | None]:
    encoded = manifest["transparency"]["signatureBase64"]
    if encoded is None:
        return (["public key transparency signature is missing"] if required else []), None
    recovery_id = manifest["transparency"]["signingKeyId"]
    recovery_key = by_id.get(recovery_id) if isinstance(recovery_id, str) else None
    if recovery_key is None or recovery_key["role"] != "offline-recovery":
        return ["public key transparency signature lacks a recovery-key verifier"], None
    try:
        generated_at = _timestamp(manifest["transparency"]["generatedAt"])
        valid_from = _timestamp(recovery_key["validFrom"])
        valid_until = _timestamp(recovery_key["validUntil"])
    except (KeyError, TypeError, ValueError):
        return ["public key transparency signer has invalid eligibility timestamps"], None
    if (
        recovery_key["lifecycle"] not in {"active", "retiring"}
        or recovery_key["compromiseState"] != "uncompromised"
        or not valid_from <= generated_at < valid_until
    ):
        return ["public key transparency signer is not eligible at generation time"], None
    try:
        signature = _decode_signature(encoded, "public key transparency signature")
    except ValueError as exc:
        return [str(exc)], None
    if not _verify_ed25519(_raw_public_key(recovery_key), _canonical_bytes(artifact), signature):
        return ["public key transparency signature is invalid"], signature
    return [], signature


def _sensitive_findings(value: Any, *, allow_public_keys: bool = False, allow_public_usk: bool = True) -> list[str]:
    findings: list[str] = []

    def visit(item: Any, path: str) -> None:
        if isinstance(item, dict):
            for key, nested in item.items():
                lowered = key.lower().replace("_", "").replace("-", "")
                if any(marker in lowered for marker in ("privatekey", "privateinsert", "formpassword", "bearertoken", "authorizationheader", "cookie")):
                    findings.append(f"{path}.{key} uses a prohibited sensitive field")
                if "publickeyspkibase64" in lowered and not allow_public_keys:
                    findings.append(f"{path}.{key} exposes public-key bytes outside a dedicated artifact")
                visit(nested, f"{path}.{key}")
        elif isinstance(item, list):
            for index, nested in enumerate(item):
                visit(nested, f"{path}[{index}]")
        elif isinstance(item, str):
            scrubbed = item.replace("crypta:USK@", "") if allow_public_usk else item
            if _PRIVATE_MATERIAL.search(scrubbed) or re.search(r"\b(?:SSK|USK)@", scrubbed):
                findings.append(f"{path} contains private-key or insert-key-shaped material")
            if _ABSOLUTE_PATH.search(item):
                findings.append(f"{path} contains an absolute local path")
            findings.extend(
                f"{path} contains prohibited {finding['category']} material"
                for finding in scan_value(item)
            )

    visit(value, "$")
    return sorted(set(findings))


def _registry_text(keys: Iterable[dict[str, Any]]) -> str:
    rows = sorted(keys, key=lambda row: row["keyId"])
    lines = ["trusted.keys.version=2"]
    for index, key in enumerate(rows):
        lines.extend(
            (
                f"key.{index}.id={key['keyId']}",
                "key.%d.algorithm=Ed25519" % index,
                f"key.{index}.public.key.base64={key['publicKeySpkiBase64']}",
                f"key.{index}.status={_routine_registry_status(key)}",
                f"key.{index}.valid.from={key['validFrom']}",
                f"key.{index}.valid.until={key['validUntil']}",
            )
        )
    return "\n".join(lines)


def _app_registry_text(keys: Iterable[dict[str, Any]]) -> str:
    rows = sorted(keys, key=lambda row: row["keyId"])
    lines = ["trusted.keys.version=2"]
    for index, key in enumerate(rows):
        lines.extend(
            (
                f"key.{index}.id={key['keyId']}",
                "key.%d.algorithm=Ed25519" % index,
                f"key.{index}.public.key.base64={key['publicKeySpkiBase64']}",
                f"key.{index}.status={_routine_registry_status(key)}",
                f"key.{index}.valid.from={key['validFrom']}",
                f"key.{index}.valid.until={key['validUntil']}",
            )
        )
    return "\n".join(lines)


def _routine_registry_status(key: dict[str, Any]) -> str:
    """Project compromise state into the closed runtime lifecycle policy."""

    if key["lifecycle"] == "revoked" or key["compromiseState"] != "uncompromised":
        return "revoked"
    return key["lifecycle"]


def _reviewer_registry_text(keys: Iterable[dict[str, Any]]) -> str:
    rows = sorted(keys, key=lambda row: row["keyId"])
    lines = ["trusted.reviewers.version=2"]
    for index, key in enumerate(rows, start=1):
        if key["lifecycle"] == "revoked" or key["compromiseState"] != "uncompromised":
            status = "revoked"
        elif key["lifecycle"] == "retired":
            status = "retired"
        else:
            status = "active"
        lines.extend(
            (
                f"reviewer.{index}.id={key['keyId']}",
                f"reviewer.{index}.algorithm=Ed25519",
                f"reviewer.{index}.public.key.base64={key['publicKeySpkiBase64']}",
                f"reviewer.{index}.status={status}",
                f"reviewer.{index}.valid.from={key['validFrom']}",
                f"reviewer.{index}.valid.until={key['validUntil']}",
            )
        )
        if key["predecessorKeyId"] is not None:
            lines.append(f"reviewer.{index}.rotates.from={key['predecessorKeyId']}")
        if key["successorKeyId"] is not None:
            lines.append(f"reviewer.{index}.rotates.to={key['successorKeyId']}")
    return "\n".join(lines)


def _write_registries(output: Path, manifest: dict[str, Any]) -> None:
    keys = manifest["keyset"]["keys"]
    routine = [
        key
        for key in keys
        if key["lifecycle"] != "staged"
    ]
    write_text(
        output / CATALOG_REGISTRY_FILE,
        _registry_text(
            key for key in routine if key["role"] == "catalog-signing"
        ),
    )
    write_text(
        output / APP_REGISTRY_FILE,
        _app_registry_text(
            key for key in routine if key["role"] == "first-party-app-signing"
        ),
    )
    write_text(
        output / REVIEWER_REGISTRY_FILE,
        _reviewer_registry_text(
            key
            for key in keys
            if key["role"] == "app-reviewer" and key["lifecycle"] != "staged"
        ),
    )


def _key_receipts(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key in sorted(manifest["keyset"]["keys"], key=lambda row: row["keyId"]):
        proof = key["proofOfPossession"]
        encoded = proof["signatureBase64"]
        rows.append(
            {
                "keyId": key["keyId"],
                "role": key["role"],
                "publicKeyFingerprintSha256": key["publicKeyFingerprintSha256"],
                "lifecycle": key["lifecycle"],
                "compromiseState": key["compromiseState"],
                "proofType": proof["proofType"],
                "proofCeremonyId": (
                    proof["statement"]["ceremonyId"]
                    if isinstance(proof["statement"], dict)
                    else None
                ),
                "proofKeysetDigest": (
                    proof["statement"]["keysetDigest"]
                    if isinstance(proof["statement"], dict)
                    else None
                ),
                "proofStatementDigest": proof["statementDigest"] if key["role"] in ROUTINE_ROLES else None,
                "proofSignatureDigest": _digest_bytes(base64.b64decode(encoded, validate=True)) if encoded is not None else None,
            }
        )
    return rows


def _ceremony_receipt(manifest: dict[str, Any], policy_digest: str, artifact: dict[str, Any], transparency_signature: bytes | None, valid: bool) -> dict[str, Any]:
    authorization = manifest["recoveryAuthorization"]
    auth_signature = authorization["signatureBase64"]
    fixture = manifest["fixtureOnly"]
    receipt: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": "stable-1.0-key-ceremony-receipt",
        "ceremonyId": manifest["ceremony"]["ceremonyId"],
        "ceremonyType": manifest["ceremony"]["ceremonyType"],
        "releaseId": manifest["release"]["releaseId"],
        "buildVersion": manifest["release"]["buildVersion"],
        "sourceCommit": manifest["release"]["sourceCommit"],
        "policyDigest": policy_digest,
        "keysetVersion": manifest["keyset"]["keysetVersion"],
        "previousKeysetDigest": manifest["keyset"]["previousKeysetDigest"],
        "keysetDigest": manifest["keyset"]["keysetDigest"],
        "protectedReleaseSummaryDigest": manifest["bindings"]["protectedReleaseSummaryDigest"],
        "protectedReleaseContractDigest": manifest["bindings"]["protectedReleaseContractDigest"],
        "independentReproducibilitySummaryDigest": manifest["bindings"]["independentReproducibilitySummaryDigest"],
        "independentReproducibilityResultDigest": manifest["bindings"]["independentReproducibilityResultDigest"],
        "independentSubjectInventoryDigest": manifest["bindings"]["independentSubjectInventoryDigest"],
        "keys": _key_receipts(manifest),
        "recoveryAuthorization": {
            "authorizationType": authorization["authorizationType"],
            "signingRecoveryKeyId": authorization["signingRecoveryKeyId"],
            "statementDigest": authorization["statementDigest"],
            "signatureDigest": _digest_bytes(base64.b64decode(auth_signature, validate=True)) if auth_signature is not None else None,
            "protectedRecoveryQuorumDigest": authorization["protectedRecoveryQuorumDigest"],
        },
        "transparencyDigest": artifact["selfDigest"],
        "transparencySignatureDigest": _digest_bytes(transparency_signature) if transparency_signature is not None else ZERO_DIGEST,
        "fixtureOnly": fixture,
        "operational": False,
        "state": "fixture-verification-complete" if valid and fixture else ("partial" if valid else "blocked"),
        "authenticatedAt": manifest["transparency"]["generatedAt"],
        "receiptDigest": ZERO_DIGEST,
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }
    findings = _sensitive_findings(receipt)
    if findings:
        receipt["state"] = "blocked"
        receipt["redaction"] = {"status": "fail", "findingCount": len(findings), "findings": findings}
    receipt["receiptDigest"] = _semantic_digest(receipt, "receiptDigest")
    return receipt


def _publication_plan(manifest: dict[str, Any], policy_digest: str) -> dict[str, Any]:
    plan: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": "stable-1.0-catalog-publication-plan",
        "release": manifest["release"],
        "bindings": manifest["bindings"],
        "policyDigest": policy_digest,
        "keysetDigest": manifest["keyset"]["keysetDigest"],
        "catalog": manifest["catalog"],
        "networkPrimary": manifest["publication"]["networkPrimary"],
        "mirrors": manifest["publication"]["mirrors"],
        "rollback": manifest["publication"]["rollback"],
        "mutationBoundary": "protected-live-usk-publication-only",
        "sideEffectFree": True,
        "planDigest": ZERO_DIGEST,
    }
    plan["planDigest"] = _semantic_digest(plan, "planDigest")
    return plan


def _publication_receipt(
    manifest: dict[str, Any],
    plan: dict[str, Any],
    errors: list[str],
    live_result_digest: str | None = None,
    mirror_observation_digest: str | None = None,
) -> dict[str, Any]:
    complete = not errors and manifest["publication"]["requestedState"] == "observed"
    receipt: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": "stable-1.0-catalog-publication-receipt",
        "releaseId": manifest["release"]["releaseId"],
        "buildVersion": manifest["release"]["buildVersion"],
        "sourceCommit": manifest["release"]["sourceCommit"],
        "planDigest": plan["planDigest"],
        "keysetDigest": manifest["keyset"]["keysetDigest"],
        "catalog": manifest["catalog"],
        "networkPrimary": manifest["publication"]["networkPrimary"],
        "mirrors": manifest["publication"]["mirrors"],
        "rollback": manifest["publication"]["rollback"],
        "observations": manifest["publication"]["observations"],
        "livePublicationResultDigest": live_result_digest,
        "mirrorObservationReceiptDigest": mirror_observation_digest,
        "publicationState": "fixture-observed" if complete and manifest["fixtureOnly"] else ("verified-partial" if complete else "partial"),
        "operational": False,
        "blockers": errors,
        "receiptDigest": ZERO_DIGEST,
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }
    findings = _sensitive_findings(receipt)
    if findings:
        receipt["publicationState"] = "partial"
        receipt["blockers"] = sorted(set(receipt["blockers"] + findings))
        receipt["redaction"] = {"status": "fail", "findingCount": len(findings), "findings": findings}
    receipt["receiptDigest"] = _semantic_digest(receipt, "receiptDigest")
    return receipt


def _summary(manifest: dict[str, Any], mode: str, policy_digest: str, errors: list[str], *, ceremony_valid: bool, publication_valid: bool, drills_valid: bool) -> dict[str, Any]:
    fixture = manifest["fixtureOnly"]
    verified = not errors
    if not verified:
        state = "blocked"
    elif fixture:
        state = "fixture-verification-complete"
    elif mode in {"prepare-ceremony", "prepare-publication"}:
        state = "implementation-complete"
    else:
        state = "partial"
    summary: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": "stable-1.0-catalog-authority-summary",
        "mode": mode,
        "releaseId": manifest["release"]["releaseId"],
        "buildVersion": manifest["release"]["buildVersion"],
        "sourceCommit": manifest["release"]["sourceCommit"],
        "policyDigest": policy_digest,
        "protectedReleaseSummaryDigest": manifest["bindings"]["protectedReleaseSummaryDigest"],
        "protectedReleaseContractDigest": manifest["bindings"]["protectedReleaseContractDigest"],
        "independentReproducibilitySummaryDigest": manifest["bindings"]["independentReproducibilitySummaryDigest"],
        "independentReproducibilityResultDigest": manifest["bindings"]["independentReproducibilityResultDigest"],
        "independentSubjectInventoryDigest": manifest["bindings"]["independentSubjectInventoryDigest"],
        "keysetDigest": manifest["keyset"]["keysetDigest"],
        "catalogSubject": _catalog_subject(manifest["catalog"]),
        "checks": {
            "ceremony": "pass" if ceremony_valid else "fail",
            "publication": "pass" if publication_valid else "fail",
            "rotationAndRollbackDrills": "pass" if drills_valid else "fail",
            "roleSpecificRegistries": "pass" if ceremony_valid else "fail",
            "redaction": "pass" if not _sensitive_findings(errors) else "fail",
        },
        "fixtureOnly": fixture,
        "operational": False,
        "state": state,
        "status": "pass" if verified else "fail",
        "blockers": sorted(set(errors)),
        "generatedAt": manifest["transparency"]["generatedAt"],
        "summaryDigest": ZERO_DIGEST,
    }
    summary["summaryDigest"] = _semantic_digest(summary, "summaryDigest")
    return summary


def _report(summary: dict[str, Any]) -> str:
    blockers = summary["blockers"]
    blocker_lines = "\n".join(f"- {item}" for item in blockers) if blockers else "- None."
    return f"""# Stable 1.0 catalog authority report

This report records side-effect-free verification for `{summary['releaseId']}` build `{summary['buildVersion']}`.

## Result

- Mode: `{summary['mode']}`
- Status: `{summary['status']}`
- State: `{summary['state']}`
- Operational completion: `false`
- Fixture-only evidence: `{str(summary['fixtureOnly']).lower()}`
- Keyset digest: `{summary['keysetDigest']}`

## Blockers

{blocker_lines}

The local command did not perform or prove a production key ceremony, live USK publication,
mirror observation, key rotation, or rollback. Those states require separately authenticated
protected workflow receipts.
"""


def _inspect_evidence_directory(path: Path) -> tuple[Path | None, list[str]]:
    errors: list[str] = []
    if path.is_symlink() or not path.is_dir():
        return None, ["protected evidence directory is missing or unsafe"]
    resolved = path.resolve()
    seen_names: set[str] = set()
    file_count = 0
    total_size = 0
    forbidden_names = {".ds_store", "__macosx"}
    archive_suffixes = {".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z"}
    for root, directories, files in os.walk(path, followlinks=False):
        for name in [*directories, *files]:
            candidate = Path(root) / name
            folded = str(candidate.relative_to(path)).casefold()
            if folded in seen_names:
                errors.append("protected evidence contains a case-colliding path")
            seen_names.add(folded)
            if name.casefold() in forbidden_names or name.startswith("._"):
                errors.append("protected evidence contains forbidden archive metadata")
            metadata = candidate.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                errors.append("protected evidence contains a symbolic link")
            elif candidate.is_file() and metadata.st_nlink != 1:
                errors.append("protected evidence contains a hard-linked file")
            elif not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                errors.append("protected evidence contains a special file")
            if stat.S_ISREG(metadata.st_mode):
                file_count += 1
                total_size += metadata.st_size
                if candidate.suffix.casefold() in archive_suffixes:
                    errors.append("protected evidence contains an uninspected nested archive")
    if file_count > 64 or total_size > 32 * 1024 * 1024:
        errors.append("protected evidence exceeds its file-count or byte bound")
    return resolved, sorted(set(errors))


def _output_directory(workspace: Path, requested: Path) -> Path:
    """Create one empty-capable output directory without following path aliases."""

    resolved_workspace = workspace.resolve()
    if ".." in requested.parts:
        raise ValueError("Stable catalog authority output contains traversal")
    target = requested if requested.is_absolute() else resolved_workspace / requested
    try:
        relative = target.relative_to(resolved_workspace)
    except ValueError as exc:
        raise ValueError(
            "Stable catalog authority output must remain inside the workspace"
        ) from exc

    def validate_components() -> None:
        current = resolved_workspace
        for part in relative.parts:
            current /= part
            if current.is_symlink():
                raise ValueError(
                    "Stable catalog authority output contains a symbolic-link component"
                )
            if current.exists() and not current.is_dir():
                raise ValueError(
                    "Stable catalog authority output contains a non-directory component"
                )

    validate_components()
    target.mkdir(parents=True, exist_ok=True)
    validate_components()
    resolved = target.resolve()
    try:
        resolved.relative_to(resolved_workspace)
    except ValueError as exc:
        raise ValueError(
            "Stable catalog authority output must remain inside the workspace"
        ) from exc
    if resolved.is_symlink() or not resolved.is_dir():
        raise ValueError("Stable catalog authority output directory is unsafe")
    return resolved


def _evidence_bytes(root: Path, name: str) -> bytes:
    candidate = root / name
    if candidate.parent != root or candidate.is_symlink() or not candidate.is_file():
        raise ValueError(f"required protected evidence member is missing: {name}")
    metadata = candidate.stat(follow_symlinks=False)
    if metadata.st_nlink != 1 or metadata.st_size > 16 * 1024 * 1024:
        raise ValueError(f"required protected evidence member is unsafe: {name}")
    return candidate.read_bytes()


def _evidence_json(root: Path, name: str) -> tuple[dict[str, Any], bytes]:
    encoded = _evidence_bytes(root, name)
    value = read_json_bytes(encoded, name)
    if not isinstance(value, dict):
        raise ValueError(f"protected evidence member is not an object: {name}")
    return value, encoded


def _bounded_regular_file_bytes(path: Path, label: str, maximum: int) -> bytes:
    """Read one bounded regular single-link file without following an unsafe target."""

    if maximum < 1 or path.is_symlink():
        raise ValueError(f"{label} is missing or unsafe")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"{label} is missing or unsafe") from exc
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or not 1 <= metadata.st_size <= maximum
        ):
            raise ValueError(f"{label} is outside its byte bound or unsafe")
        value = stream.read(maximum + 1)
        if len(value) != metadata.st_size or len(value) > maximum:
            raise ValueError(
                f"{label} changed while it was read or exceeded its byte bound"
            )
        return value


def _key_transition_errors(
    previous_key: dict[str, Any], current_key: dict[str, Any]
) -> list[str]:
    """Reject lifecycle rollback or compromise-state clearing for one retained identity."""

    errors: list[str] = []
    key_id = previous_key.get("keyId")
    previous_lifecycle = previous_key.get("lifecycle")
    current_lifecycle = current_key.get("lifecycle")
    if (
        previous_lifecycle in _LIFECYCLE_RANK
        and current_lifecycle in _LIFECYCLE_RANK
        and _LIFECYCLE_RANK[current_lifecycle]
        < _LIFECYCLE_RANK[previous_lifecycle]
    ):
        errors.append(f"successor keyset reverses previous key lifecycle: {key_id}")
    previous_compromise = previous_key.get("compromiseState")
    current_compromise = current_key.get("compromiseState")
    if (
        previous_compromise in _COMPROMISE_RANK
        and current_compromise in _COMPROMISE_RANK
        and _COMPROMISE_RANK[current_compromise]
        < _COMPROMISE_RANK[previous_compromise]
    ):
        errors.append(
            f"successor keyset clears previous key compromise state: {key_id}"
        )
    return errors


def _retained_proof_provenance(key: dict[str, Any]) -> dict[str, str]:
    """Derive the proof commitment stored in a signed transparency key row."""

    proof = key.get("proofOfPossession")
    if not isinstance(proof, dict):
        raise ValueError(f"key {key.get('keyId')} retained proof is missing")
    statement = proof.get("statement")
    if not isinstance(statement, dict):
        raise ValueError(f"key {key.get('keyId')} retained proof statement is missing")
    signature = _decode_signature(
        proof.get("signatureBase64"),
        f"key {key.get('keyId')} retained proof signature",
    )
    ceremony_id = statement.get("ceremonyId")
    keyset_digest = statement.get("keysetDigest")
    statement_digest = proof.get("statementDigest")
    if not all(
        isinstance(value, str)
        for value in (ceremony_id, keyset_digest, statement_digest)
    ):
        raise ValueError(
            f"key {key.get('keyId')} retained proof provenance is incomplete"
        )
    return {
        "proofCeremonyId": ceremony_id,
        "proofKeysetDigest": keyset_digest,
        "proofStatementDigest": statement_digest,
        "proofSignatureDigest": _digest_bytes(signature),
    }


def _previous_recovery_errors(
    root: Path,
    manifest: dict[str, Any],
    by_id: dict[str, dict[str, Any]],
) -> list[str]:
    """Authenticate a successor transition against the preceding public keyset."""

    errors: list[str] = []
    authorization = manifest["recoveryAuthorization"]
    if manifest["ceremony"]["ceremonyType"] == "genesis":
        return errors
    try:
        previous, _ = _evidence_json(root, PREVIOUS_TRANSPARENCY_FILE)
        signature = _evidence_bytes(root, PREVIOUS_TRANSPARENCY_SIGNATURE_FILE)
        errors.extend(validate_schema(previous, TRANSPARENCY_SCHEMA))
        if previous.get("selfDigest") != _semantic_digest(previous, "selfDigest"):
            errors.append("previous public key transparency self-digest is invalid")
        if previous.get("keysetDigest") != manifest["keyset"]["previousKeysetDigest"]:
            errors.append("successor keyset does not name the authenticated previous keyset")
        if previous.get("keysetVersion") != manifest["keyset"]["keysetVersion"] - 1:
            errors.append("successor keyset version does not immediately follow the previous keyset")
        if previous.get("release") != {
            name: manifest["release"][name]
            for name in ("releaseId", "buildVersion", "sourceCommit")
        }:
            errors.append("previous keyset belongs to a different Stable release identity")
        previous_signer_id = previous.get("transparencySigningKeyId")
        previous_key_rows = [
            row for row in previous.get("keys", []) if isinstance(row, dict)
        ]
        previous_keys = {row.get("keyId"): row for row in previous_key_rows}
        previous_fingerprints = {
            row.get("publicKeyFingerprintSha256"): row for row in previous_key_rows
        }
        if len(previous_keys) != len(previous_key_rows):
            errors.append("previous transparency artifact contains duplicate key ids")
        if len(previous_fingerprints) != len(previous_key_rows):
            errors.append(
                "previous transparency artifact contains duplicate public-key fingerprints"
            )
        current_keys = manifest["keyset"]["keys"]
        current_by_id = {row["keyId"]: row for row in current_keys}
        current_by_fingerprint = {
            row["publicKeyFingerprintSha256"]: row for row in current_keys
        }
        immutable_identity_fields = (
            "role",
            "algorithm",
            "publicKeySpkiBase64",
            "publicKeyFingerprintSha256",
        )
        for previous_key in previous_key_rows:
            previous_key_id = previous_key.get("keyId")
            current_key = current_by_id.get(previous_key_id)
            if current_key is None:
                errors.append(
                    f"successor keyset omits previous key identity: {previous_key_id}"
                )
            elif any(
                current_key.get(name) != previous_key.get(name)
                for name in immutable_identity_fields
            ):
                errors.append(
                    f"successor keyset changes previous public identity: {previous_key_id}"
                )
            if isinstance(current_key, dict):
                errors.extend(_key_transition_errors(previous_key, current_key))
                if (
                    current_key.get("role") in ROUTINE_ROLES
                    and current_key.get("lifecycle") in HISTORICAL_LIFECYCLES
                ):
                    try:
                        retained_provenance = _retained_proof_provenance(
                            current_key
                        )
                    except ValueError as exc:
                        errors.append(str(exc))
                    else:
                        previous_provenance = {
                            name: previous_key.get(name)
                            for name in (
                                "proofCeremonyId",
                                "proofKeysetDigest",
                                "proofStatementDigest",
                                "proofSignatureDigest",
                            )
                        }
                        if retained_provenance != previous_provenance:
                            errors.append(
                                "successor keyset substitutes retained proof provenance: "
                                f"{previous_key_id}"
                            )
            fingerprint_owner = current_by_fingerprint.get(
                previous_key.get("publicKeyFingerprintSha256")
            )
            if (
                not isinstance(fingerprint_owner, dict)
                or fingerprint_owner.get("keyId") != previous_key_id
            ):
                errors.append(
                    f"successor keyset reassigns previous public-key fingerprint: {previous_key_id}"
                )
        previous_signer = previous_keys.get(previous_signer_id)
        try:
            previous_generated_at = _timestamp(previous["generatedAt"])
            previous_valid_from = _timestamp(previous_signer["validFrom"])
            previous_valid_until = _timestamp(previous_signer["validUntil"])
        except (KeyError, TypeError, ValueError):
            previous_generated_at = None
            previous_valid_from = None
            previous_valid_until = None
        if (
            not isinstance(previous_signer, dict)
            or previous_signer.get("role") != "offline-recovery"
            or previous_signer.get("lifecycle") not in {"active", "retiring"}
            or previous_signer.get("compromiseState") != "uncompromised"
            or previous_generated_at is None
            or previous_valid_from is None
            or previous_valid_until is None
            or not previous_valid_from <= previous_generated_at < previous_valid_until
        ):
            errors.append("previous transparency artifact lacks an authorized recovery signer")
        elif len(signature) != 64 or not _verify_ed25519(
            _raw_public_key(previous_signer), _canonical_bytes(previous), signature
        ):
            errors.append("previous public key transparency detached signature is invalid")
        if authorization["authorizationType"] == "recovery-signature":
            current_signer_id = authorization.get("signingRecoveryKeyId")
            current_signer = by_id.get(current_signer_id)
            if (
                previous_signer_id != current_signer_id
                or not isinstance(current_signer, dict)
                or not isinstance(previous_signer, dict)
                or current_signer.get("publicKeyFingerprintSha256")
                != previous_signer.get("publicKeyFingerprintSha256")
            ):
                errors.append(
                    "successor transition was not authorized by the previous recovery root"
                )
    except (KeyError, ValueError) as exc:
        errors.append(str(exc))
    return sorted(set(errors))


def _protected_recovery_quorum_errors(root: Path, manifest: dict[str, Any]) -> list[str]:
    """Authenticate the bounded protected-quorum exception for compromised recovery."""

    authorization = manifest["recoveryAuthorization"]
    if authorization["authorizationType"] != "protected-recovery-quorum":
        return []
    errors: list[str] = []
    expected_fields = {
        "schemaVersion",
        "kind",
        "releaseId",
        "buildVersion",
        "sourceCommit",
        "ceremonyId",
        "keysetDigest",
        "recoveryStatementDigest",
        "protectedEnvironment",
        "approvalRole",
        "requiredApprovals",
        "recordedApprovals",
        "fixtureOnly",
        "operational",
        "status",
        "receiptDigest",
    }
    try:
        receipt, encoded = _evidence_json(root, RECOVERY_QUORUM_RECEIPT_FILE)
        if set(receipt) != expected_fields:
            errors.append("protected recovery quorum receipt is not a closed record")
        ceremony = manifest["ceremony"]
        approval = ceremony["approvalQuorum"]
        if _file_digest(encoded) != authorization["protectedRecoveryQuorumDigest"]:
            errors.append("protected recovery quorum receipt digest does not match")
        if receipt.get("receiptDigest") != _semantic_digest(receipt, "receiptDigest"):
            errors.append("protected recovery quorum receipt self-digest is invalid")
        expected = {
            "schemaVersion": 1,
            "kind": "stable-1.0-protected-recovery-quorum-receipt",
            "releaseId": manifest["release"]["releaseId"],
            "buildVersion": manifest["release"]["buildVersion"],
            "sourceCommit": manifest["release"]["sourceCommit"],
            "ceremonyId": ceremony["ceremonyId"],
            "keysetDigest": manifest["keyset"]["keysetDigest"],
            "recoveryStatementDigest": authorization["statementDigest"],
            "protectedEnvironment": approval["protectedEnvironment"],
            "approvalRole": approval["approvalRole"],
            "requiredApprovals": approval["requiredApprovals"],
            "fixtureOnly": False,
            "operational": True,
            "status": "pass",
        }
        for field, value in expected.items():
            if receipt.get(field) != value:
                errors.append("protected recovery quorum receipt does not bind the exact transition")
                break
        recorded = receipt.get("recordedApprovals")
        if not isinstance(recorded, int) or isinstance(recorded, bool) or recorded < approval["requiredApprovals"] or recorded > 16:
            errors.append("protected recovery quorum receipt lacks the required approvals")
    except (KeyError, ValueError) as exc:
        errors.append(str(exc))
    return sorted(set(errors))


def _identity_errors(value: dict[str, Any], manifest: dict[str, Any]) -> list[str]:
    release = manifest["release"]
    errors: list[str] = []
    if value.get("releaseId") != release["releaseId"]:
        errors.append("protected evidence release identity does not match")
    if str(value.get("buildVersion")) != str(release["buildVersion"]):
        errors.append("protected evidence build identity does not match")
    commit = value.get("sourceCommit", value.get("candidateCommit"))
    if commit != release["sourceCommit"]:
        errors.append("protected evidence source commit does not match")
    return errors


def _catalog_sidecar_errors(
    catalog_bytes: bytes,
    signature_bytes: bytes,
    manifest: dict[str, Any],
    by_id: dict[str, dict[str, Any]],
) -> list[str]:
    errors: list[str] = []
    catalog = manifest["catalog"]
    if _file_digest(catalog_bytes) != catalog["catalogDigest"] or len(catalog_bytes) != catalog["catalogSize"]:
        errors.append("exact frozen catalog bytes do not match the authenticated catalog subject")
    if _file_digest(signature_bytes) != catalog["signatureDigest"] or len(signature_bytes) != catalog["signatureSize"]:
        errors.append("exact detached signature bytes do not match the authenticated catalog subject")
    try:
        text = signature_bytes.decode("utf-8")
        properties: dict[str, str] = {}
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise ValueError("malformed catalog signature sidecar")
            key, value = line.split("=", 1)
            if key in properties:
                raise ValueError("duplicate catalog signature property")
            properties[key] = value
        expected_fields = {
            "catalog.signature.version",
            "catalog.signature.algorithm",
            "catalog.signature.key.id",
            "catalog.signature.payload",
            "catalog.signature.value.base64",
        }
        if set(properties) != expected_fields:
            raise ValueError("catalog signature sidecar has a missing or unknown property")
        if (
            properties["catalog.signature.version"] != "1"
            or properties["catalog.signature.algorithm"] != "Ed25519"
            or properties["catalog.signature.payload"] != FROZEN_CATALOG_FILE
            or properties["catalog.signature.key.id"] != catalog["signingKeyId"]
        ):
            raise ValueError("catalog signature metadata does not match the frozen subject")
        signer = by_id.get(catalog["signingKeyId"])
        if signer is None:
            raise ValueError("catalog signature key is absent from the catalog registry")
        signature = _decode_signature(
            properties["catalog.signature.value.base64"],
            "catalog detached signature",
        )
        if not _verify_ed25519(_raw_public_key(signer), catalog_bytes, signature):
            raise ValueError("catalog detached signature does not verify exact frozen bytes")
    except (UnicodeDecodeError, ValueError) as exc:
        errors.append(str(exc))
    return errors


def _validate_bound_evidence(
    manifest: dict[str, Any],
    mode: str,
    evidence_dir: Path | None,
    live_publication_result: Path | None,
    by_id: dict[str, dict[str, Any]],
) -> tuple[list[str], str | None, str | None]:
    if evidence_dir is None:
        if manifest["fixtureOnly"]:
            return [], None, None
        return ["non-fixture authority verification requires exact protected evidence files"], None, None
    root, errors = _inspect_evidence_directory(evidence_dir)
    if root is None:
        return errors, None, None
    errors.extend(_previous_recovery_errors(root, manifest, by_id))
    errors.extend(_protected_recovery_quorum_errors(root, manifest))
    bindings = manifest["bindings"]
    try:
        protected, protected_bytes = _evidence_json(root, PROTECTED_RELEASE_SUMMARY_FILE)
        errors.extend(validate_schema(protected, "stable-1.0-protected-release-execution-summary-v1.schema.json"))
        errors.extend(_identity_errors(protected, manifest))
        if _file_digest(protected_bytes) != bindings["protectedReleaseSummaryDigest"]:
            errors.append("exact PR-291 protected release summary digest does not match")
        if (
            protected.get("status") != "pass"
            or protected.get("lifecycleState") != "publicly-observed"
            or protected.get("contractDigest") != bindings["protectedReleaseContractDigest"]
        ):
            errors.append("PR-291 protected release root is not publicly observed and exact")

        independent, independent_bytes = _evidence_json(root, INDEPENDENT_SUMMARY_FILE)
        errors.extend(validate_schema(independent, "stable-1.0-independent-reproducibility-summary-v1.schema.json"))
        errors.extend(_identity_errors(independent, manifest))
        if _file_digest(independent_bytes) != bindings["independentReproducibilitySummaryDigest"]:
            errors.append("exact PR-292 independent reproducibility summary digest does not match")
        if (
            independent.get("status") != "independently-reproduced"
            or independent.get("lifecycleState") != "independently-reproduced"
            or independent.get("operational") is not True
            or independent.get("fixture") is not False
            or independent.get("selfTest") is not False
            or independent.get("reproducibilityResultDigest") != bindings["independentReproducibilityResultDigest"]
            or independent.get("subjectInventoryDigest") != bindings["independentSubjectInventoryDigest"]
        ):
            errors.append("PR-292 result is not the exact operational independently reproduced authority")

        inventory, _ = _evidence_json(root, SUBJECT_INVENTORY_FILE)
        errors.extend(validate_schema(inventory, "stable-1.0-release-subject-inventory-v1.schema.json"))
        errors.extend(_identity_errors(inventory, manifest))
        if inventory.get("subjectInventoryDigest") != bindings["independentSubjectInventoryDigest"]:
            errors.append("PR-292 subject inventory digest does not match")
        subjects = {
            row.get("subjectKey"): row
            for row in inventory.get("subjects", [])
            if isinstance(row, dict)
        }
        for key, digest_field, size_field in (
            ("stable-catalog", "catalogDigest", "catalogSize"),
            ("stable-catalog-signature", "signatureDigest", "signatureSize"),
        ):
            row = subjects.get(key)
            if row is None or row.get("digest") != manifest["catalog"][digest_field] or row.get("size") != manifest["catalog"][size_field]:
                errors.append(f"PR-292 subject inventory does not bind the exact {key} subject")
    except ValueError as exc:
        errors.append(str(exc))

    publication_modes = {"prepare-publication", "verify-publication", "closeout"}
    if mode in publication_modes:
        try:
            catalog_bytes = _evidence_bytes(root, FROZEN_CATALOG_FILE)
            signature_bytes = _evidence_bytes(root, FROZEN_SIGNATURE_FILE)
            errors.extend(_catalog_sidecar_errors(catalog_bytes, signature_bytes, manifest, by_id))
            ga_plan, _ = _evidence_json(root, GA_PLAN_FILE)
            ga_receipt, ga_receipt_bytes = _evidence_json(root, GA_RECEIPT_FILE)
            ga_observation, _ = _evidence_json(root, GA_OBSERVATION_FILE)
            errors.extend(validate_schema(ga_plan, "stable-1.0-ga-publication-plan-v1.schema.json"))
            errors.extend(validate_schema(ga_receipt, "stable-1.0-ga-publication-receipt-v1.schema.json"))
            errors.extend(validate_schema(ga_observation, "stable-1.0-protected-release-public-observation-v1.schema.json"))
            for value in (ga_plan, ga_receipt, ga_observation):
                errors.extend(_identity_errors(value, manifest))
            expected_catalog = manifest["catalog"]
            for value in (ga_plan, ga_receipt):
                ga_catalog = value.get("catalog", {})
                for source, target in (
                    ("catalogId", "catalogId"),
                    ("channel", "channel"),
                    ("revision", "revision"),
                    ("catalogDigest", "catalogDigest"),
                    ("signatureDigest", "signatureDigest"),
                    ("signingKeyId", "signingKeyId"),
                ):
                    if ga_catalog.get(source) != expected_catalog[target]:
                        errors.append("GA authority catalog subject does not match the frozen PR-293 subject")
                        break
            if ga_receipt.get("finalVerificationStatus") != "pass" or ga_observation.get("status") != "pass":
                errors.append("GA publication or HTTPS public observation is not complete")
            if ga_observation.get("publicationReceiptDigest") != _file_digest(ga_receipt_bytes):
                errors.append("GA public observation does not bind the exact publication receipt bytes")
        except ValueError as exc:
            errors.append(str(exc))

    if mode in {"verify-rotation-drill", "closeout"} and not manifest["fixtureOnly"]:
        try:
            rollback = manifest["publication"]["rollback"]
            rollback_manifest = {"catalog": rollback}
            rollback_catalog_bytes = _evidence_bytes(root, ROLLBACK_CATALOG_FILE)
            rollback_signature_bytes = _evidence_bytes(root, ROLLBACK_SIGNATURE_FILE)
            rollback_errors = _catalog_sidecar_errors(
                rollback_catalog_bytes,
                rollback_signature_bytes,
                rollback_manifest,
                by_id,
            )
            errors.extend(
                error.replace("frozen", "retained rollback")
                for error in rollback_errors
            )
        except ValueError as exc:
            errors.append(str(exc))

    live_digest: str | None = None
    live_path = live_publication_result
    if live_path is None and (root / LIVE_PUBLICATION_FILE).is_file():
        live_path = root / LIVE_PUBLICATION_FILE
    if live_path is not None:
        try:
            live_bytes = _bounded_regular_file_bytes(
                live_path,
                "live USK publication result",
                MAX_LIVE_PUBLICATION_RESULT_BYTES,
            )
            live = read_json_bytes(live_bytes, LIVE_PUBLICATION_FILE)
            if not isinstance(live, dict):
                raise ValueError("live USK publication result is not an object")
            if _sensitive_findings(live):
                raise ValueError(
                    "live USK publication result failed redaction validation"
                )
            live_digest = _file_digest(live_bytes)
            expected_digest = manifest["catalog"]["catalogDigest"].removeprefix("sha256:")
            expected_signature = manifest["catalog"]["signatureDigest"].removeprefix("sha256:")
            expected_edition = str(manifest["catalog"]["uskEdition"])
            if (
                live.get("mode") != "live"
                or live.get("catalogId") != manifest["catalog"]["catalogId"]
                or live.get("publicCatalogSource") != manifest["publication"]["networkPrimary"]["publicUri"]
                or live.get("edition") != expected_edition
                or live.get("catalogSha256") != expected_digest
                or live.get("signatureSha256") != expected_signature
                or live.get("catalogSigningKeyId") != manifest["catalog"]["signingKeyId"]
                or live.get("catalogInsertStatus") not in {"queued", "existing"}
                or live.get("signatureInsertStatus") not in {"queued", "existing"}
                or live.get("postPublishVerificationStatus") != "verified"
            ):
                errors.append("live USK publication result does not bind the exact publication plan")
        except (OSError, ValueError) as exc:
            errors.append(str(exc))
    elif mode in {"verify-publication", "closeout"} and not manifest["fixtureOnly"]:
        errors.append("protected publication verification requires the sanitized live USK result")

    mirror_digest: str | None = None
    if mode in {"verify-publication", "closeout"} and not manifest["fixtureOnly"]:
        try:
            mirror, mirror_bytes = _evidence_json(root, MIRROR_OBSERVATION_FILE)
            mirror_digest = _file_digest(mirror_bytes)
            errors.extend(validate_schema(mirror, MIRROR_OBSERVATION_SCHEMA))
            errors.extend(_mirror_collection_errors(manifest, mirror, by_id))
            if (
                mirror.get("kind") != "stable-1.0-catalog-mirror-observation"
                or mirror.get("releaseId") != manifest["release"]["releaseId"]
                or str(mirror.get("buildVersion")) != str(manifest["release"]["buildVersion"])
                or mirror.get("sourceCommit") != manifest["release"]["sourceCommit"]
                or mirror.get("catalogSubject") != _catalog_subject(manifest["catalog"])
                or mirror.get("observations") != manifest["publication"]["observations"]
                or mirror.get("schedulerRefreshVerificationStatus") != "pass"
                or mirror.get("status") != "pass"
            ):
                errors.append("independent mirror observation receipt does not bind the exact publication subject")
            expected_receipt_digest = _semantic_digest(mirror, "receiptDigest")
            if mirror.get("receiptDigest") != expected_receipt_digest:
                errors.append("independent mirror observation receipt digest is invalid")
        except (KeyError, ValueError) as exc:
            errors.append(str(exc))
    return sorted(set(errors)), live_digest, mirror_digest


def run(
    workspace_root: Path,
    authority_manifest: Path,
    mode: str,
    out_dir: Path | None = None,
    evidence_dir: Path | None = None,
    live_publication_result: Path | None = None,
) -> int:
    """Run one closed, side-effect-free catalog-authority operation."""

    if mode not in MODES:
        raise ValueError("unsupported Stable catalog authority mode")
    workspace = workspace_root.resolve()
    manifest = read_json(authority_manifest.resolve())
    if not isinstance(manifest, dict):
        raise ValueError("Stable catalog authority manifest is not an object")
    schema_errors = validate_schema(manifest, EXECUTION_SCHEMA)
    if schema_errors:
        raise ValueError("Stable catalog authority manifest failed its closed schema: " + "; ".join(schema_errors[:8]))
    policy, policy_digest = _policy(workspace)
    output = _output_directory(
        workspace,
        out_dir
        or Path("build/release-certification/stable-catalog-authority") / mode,
    )
    if any(output.iterdir()):
        raise ValueError("Stable catalog authority output directory must be empty")

    verify_signatures = mode != "prepare-ceremony"
    key_errors, by_id = _validate_keyset(manifest, verify_signatures)
    recovery_errors = _validate_recovery(manifest, by_id, verify_signatures)
    binding_errors = _policy_contract_errors(policy)
    if not manifest["bindings"]["independentReproducibilityOperational"]:
        binding_errors.append("PR-292 independent reproducibility is not operational")
    if not manifest["bindings"]["providerIndependent"]:
        binding_errors.append("PR-292 evidence is not provider-independent")
    if manifest["release"]["sourceRef"] != f"refs/heads/release/{manifest['release']['buildVersion']}":
        binding_errors.append("release source ref does not match the exact build")
    evidence_errors, live_result_digest, mirror_observation_digest = _validate_bound_evidence(
        manifest,
        mode,
        evidence_dir,
        live_publication_result,
        by_id,
    )
    ceremony_errors = sorted(set(key_errors + recovery_errors + binding_errors))
    require_observations = mode in {"verify-publication", "closeout"}
    require_drills = mode in {"verify-rotation-drill", "closeout"}
    drill_errors, authenticated_drill_times = _validate_drills(
        manifest,
        require_drills,
        evidence_dir,
    )
    publication_errors = _validate_publication(
        manifest,
        by_id,
        require_observations,
        authenticated_drill_times.get("catalog-rollback"),
        require_drills,
    )
    artifact = _transparency_artifact(manifest)
    transparency_errors, transparency_signature = _validate_transparency_signature(
        manifest,
        artifact,
        by_id,
        mode not in {"prepare-ceremony", "prepare-publication"},
    )
    artifact_schema_errors = validate_schema(artifact, TRANSPARENCY_SCHEMA)
    artifact_redaction_errors = _sensitive_findings(artifact, allow_public_keys=True)
    all_errors = sorted(
        set(
            ceremony_errors
            + publication_errors
            + drill_errors
            + transparency_errors
            + artifact_schema_errors
            + artifact_redaction_errors
            + evidence_errors
        )
    )

    plan = _publication_plan(manifest, policy_digest)
    plan_schema_errors = validate_schema(plan, PUBLICATION_PLAN_SCHEMA)
    receipt = _ceremony_receipt(
        manifest,
        policy_digest,
        artifact,
        transparency_signature,
        not ceremony_errors and not transparency_errors,
    )
    receipt_errors = validate_schema(receipt, RECEIPT_SCHEMA)
    all_errors = sorted(set(all_errors + receipt_errors + plan_schema_errors))
    publication_receipt = _publication_receipt(
        manifest,
        plan,
        publication_errors + evidence_errors,
        live_result_digest,
        mirror_observation_digest,
    )
    publication_receipt_errors = validate_schema(
        publication_receipt,
        PUBLICATION_RECEIPT_SCHEMA,
    )
    all_errors = sorted(set(all_errors + publication_receipt_errors))
    summary = _summary(
        manifest,
        mode,
        policy_digest,
        all_errors,
        ceremony_valid=not ceremony_errors and not transparency_errors,
        publication_valid=not publication_errors,
        drills_valid=not drill_errors,
    )

    ceremony_summary = {
        "schemaVersion": 1,
        "kind": "stable-1.0-key-ceremony-summary",
        "ceremonyId": manifest["ceremony"]["ceremonyId"],
        "ceremonyType": manifest["ceremony"]["ceremonyType"],
        "keysetDigest": manifest["keyset"]["keysetDigest"],
        "keyCount": len(manifest["keyset"]["keys"]),
        "roleCounts": {role: sum(key["role"] == role for key in manifest["keyset"]["keys"]) for role in sorted(ROLES)},
        "fixtureOnly": manifest["fixtureOnly"],
        "operational": False,
        "state": summary["state"],
        "blockers": summary["blockers"],
    }
    drill_artifact = {
        "schemaVersion": 1,
        "kind": "stable-1.0-catalog-rotation-drill",
        "fixtureOnly": manifest["fixtureOnly"],
        "operational": False,
        "status": "pass" if not drill_errors and require_drills else "not-run",
        "drills": manifest["drills"],
        "blockers": drill_errors,
    }
    generated_schema_errors = validate_schema(summary, AUTHORITY_SUMMARY_SCHEMA) + validate_schema(
        drill_artifact,
        ROTATION_DRILL_SCHEMA,
    )
    if generated_schema_errors:
        raise ValueError(
            "generated Stable catalog authority output failed its closed schema: "
            + "; ".join(generated_schema_errors[:8])
        )
    report_text = _report(summary)
    redaction_findings = sorted(
        set(
            _sensitive_findings(
                [
                    ceremony_summary,
                    receipt,
                    plan,
                    publication_receipt,
                    drill_artifact,
                    summary,
                    report_text,
                ]
            )
            + _sensitive_findings(artifact, allow_public_keys=True)
        )
    )
    if redaction_findings:
        raise ValueError(
            "generated Stable catalog authority output failed redaction validation"
        )
    write_json(output / CEREMONY_SUMMARY_FILE, ceremony_summary)
    write_json(output / CEREMONY_RECEIPT_FILE, receipt)
    write_json(output / TRANSPARENCY_FILE, artifact)
    if transparency_signature is not None:
        write_bytes(output / TRANSPARENCY_SIGNATURE_FILE, transparency_signature)
    write_json(output / PUBLICATION_PLAN_FILE, plan)
    write_json(output / PUBLICATION_RECEIPT_FILE, publication_receipt)
    write_json(output / ROTATION_DRILL_FILE, drill_artifact)
    _write_registries(output, manifest)
    write_json(output / AUTHORITY_SUMMARY_FILE, summary)
    write_text(output / AUTHORITY_REPORT_FILE, report_text)
    write_json(output / REDACTION_FILE, {
        "schemaVersion": 1,
        "kind": "stable-1.0-catalog-authority-redaction",
        "status": "pass",
        "findingCount": 0,
        "findings": [],
        "publicKeyMaterialLimitedTo": [TRANSPARENCY_FILE, CATALOG_REGISTRY_FILE, APP_REGISTRY_FILE, REVIEWER_REGISTRY_FILE],
    })
    print(f"stable-catalog-authority: {AUTHORITY_SUMMARY_FILE}")
    return 0 if summary["status"] == "pass" else 1

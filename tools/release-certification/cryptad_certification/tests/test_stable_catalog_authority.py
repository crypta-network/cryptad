"""Tests for the Stable catalog key ceremony and publication authority."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from cryptad_certification.cli import build_parser
from cryptad_certification.engines import stable_1_0_catalog_authority as authority
from cryptad_certification.io import read_json, read_json_bytes, write_json
from cryptad_certification.schema_validation import validate_schema

PUBLIC_USK_PRIMARY = (
    "crypta:USK@sdFxM0Z4zx4-gXhGwzXAVYvOUi6NRfdGbyJa797bNAg,"
    "ZP4aASnyZax8nYOvCOlUebegsmbGQIXfVzw7iyOsXEc,AQACAAE/stable/9/"
    "cryptad-app-catalog.properties"
)
PUBLIC_USK_ROLLBACK = PUBLIC_USK_PRIMARY.replace("/9/", "/8/")


def _fixture_seed(label: str) -> bytes:
    return hashlib.sha256(("non-production-test-key:" + label).encode()).digest()


def _fixture_keypair(label: str) -> tuple[bytes, bytes]:
    seed = _fixture_seed(label)
    expanded = hashlib.sha512(seed).digest()
    scalar_bytes = bytearray(expanded[:32])
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 63
    scalar_bytes[31] |= 64
    scalar = int.from_bytes(scalar_bytes, "little")
    public_key = authority._encode_point(authority._scalarmult(authority._B, scalar))
    return seed, public_key


def _fixture_sign(seed: bytes, public_key: bytes, message: bytes) -> bytes:
    expanded = hashlib.sha512(seed).digest()
    scalar_bytes = bytearray(expanded[:32])
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 63
    scalar_bytes[31] |= 64
    scalar = int.from_bytes(scalar_bytes, "little")
    nonce = int.from_bytes(hashlib.sha512(expanded[32:] + message).digest(), "little") % authority._L
    encoded_r = authority._encode_point(authority._scalarmult(authority._B, nonce))
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public_key + message).digest(), "little"
    ) % authority._L
    encoded_s = ((nonce + challenge * scalar) % authority._L).to_bytes(32, "little")
    return encoded_r + encoded_s


def _encoded_signature(seed: bytes, public_key: bytes, value: object) -> str:
    return base64.b64encode(
        _fixture_sign(seed, public_key, authority._canonical_bytes(value))
    ).decode()


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _key(role: str, key_id: str) -> tuple[dict[str, object], bytes, bytes]:
    seed, public = _fixture_keypair(key_id)
    spki = authority.SPKI_PREFIX + public
    value: dict[str, object] = {
        "keyId": key_id,
        "role": role,
        "algorithm": "Ed25519",
        "publicKeySpkiBase64": base64.b64encode(spki).decode(),
        "publicKeyFingerprintSha256": authority._digest_bytes(spki),
        "lifecycle": "active",
        "validFrom": "2026-08-20T00:00:00Z",
        "validUntil": "2028-08-20T00:00:00Z",
        "predecessorKeyId": None,
        "successorKeyId": None,
        "compromiseState": "uncompromised",
        "publicTransparencyEligible": True,
        "proofOfPossession": {
            "proofType": (
                "not-applicable-recovery"
                if role == "offline-recovery"
                else "current-keyset"
            ),
            "statement": None,
            "statementDigest": None,
            "signatureBase64": None,
        },
    }
    return value, seed, public


def _manifest() -> dict[str, object]:
    keys_and_material = [
        _key("catalog-signing", "stable-catalog-fixture-1"),
        _key("first-party-app-signing", "stable-app-fixture-1"),
        _key("app-reviewer", "stable-reviewer-fixture-1"),
        _key("offline-recovery", "stable-recovery-fixture-1"),
    ]
    keys = [row[0] for row in keys_and_material]
    manifest: dict[str, object] = {
        "schemaVersion": 1,
        "kind": "stable-1.0-key-ceremony-execution",
        "fixtureOnly": True,
        "ceremony": {
            "ceremonyId": "stable-1.0-fixture-genesis",
            "ceremonyType": "genesis",
            "releaseMilestone": "Stable 1.0",
            "preparedAt": "2026-08-20T00:00:00Z",
            "effectiveAt": "2026-08-21T00:00:00Z",
            "custodyClass": "fixture-memory-only",
            "approvalQuorum": {
                "requiredApprovals": 2,
                "approvalRole": "stable-release-manager",
                "protectedEnvironment": "stable-1-0-key-ceremony",
            },
        },
        "release": {
            "releaseId": "stable-1.0-fixture",
            "buildVersion": 293,
            "sourceCommit": "a" * 40,
            "sourceRef": "refs/heads/release/293",
        },
        "bindings": {
            "protectedReleaseSummaryDigest": _digest("1"),
            "protectedReleaseContractDigest": _digest("2"),
            "protectedReleaseLifecycleState": "publicly-observed",
            "independentReproducibilitySummaryDigest": _digest("3"),
            "independentReproducibilityResultDigest": _digest("4"),
            "independentSubjectInventoryDigest": _digest("5"),
            "independentReproducibilityOperational": True,
            "providerIndependent": True,
        },
        "keyset": {
            "keysetVersion": 1,
            "previousKeysetDigest": None,
            "keysetDigest": _digest("0"),
            "keys": keys,
        },
        "recoveryAuthorization": {
            "authorizationType": "recovery-signature",
            "signingRecoveryKeyId": "stable-recovery-fixture-1",
            "statementDigest": _digest("0"),
            "signatureBase64": None,
            "protectedRecoveryQuorumDigest": None,
        },
        "catalog": {
            "catalogId": "crypta-stable-apps",
            "channel": "stable",
            "revision": 9,
            "uskEdition": 9,
            "catalogDigest": _digest("6"),
            "catalogSize": 4096,
            "signatureDigest": _digest("7"),
            "signatureSize": 192,
            "signingKeyId": "stable-catalog-fixture-1",
            "signingKeyFingerprintSha256": keys[0]["publicKeyFingerprintSha256"],
            "freezeDigest": _digest("8"),
            "productDigest": _digest("9"),
            "selectedRcDigest": _digest("a"),
        },
        "publication": {
            "networkPrimary": {
                "locationId": "network-primary",
                "locationType": "network-primary",
                "publicUri": PUBLIC_USK_PRIMARY,
                "operatorId": "crypta-release",
                "providerId": "crypta-network",
                "controlPlaneId": "primary-node",
                "trustAuthority": False,
            },
            "mirrors": [
                {
                    "locationId": "independent-web-mirror",
                    "locationType": "public-web-mirror",
                    "publicUri": "https://mirror.example.test/stable/cryptad-app-catalog.properties",
                    "operatorId": "fixture-mirror-operator",
                    "providerId": "fixture-mirror-provider",
                    "controlPlaneId": "fixture-mirror-control",
                    "trustAuthority": False,
                }
            ],
            "rollback": {
                "publicUri": PUBLIC_USK_ROLLBACK,
                "catalogId": "crypta-stable-apps",
                "channel": "stable",
                "revision": 8,
                "uskEdition": 8,
                "catalogDigest": _digest("b"),
                "catalogSize": 4080,
                "signatureDigest": _digest("c"),
                "signatureSize": 192,
                "signingKeyId": "stable-catalog-fixture-1",
                "signingKeyFingerprintSha256": keys[0]["publicKeyFingerprintSha256"],
            },
            "observations": [],
            "requestedState": "planned",
        },
        "drills": [
            {
                "drillType": drill_type,
                "status": "pass",
                "fixtureOnly": True,
                "subjectDigest": _digest(character),
                "completedAt": "2026-08-22T00:00:00Z",
            }
            for drill_type, character in zip(sorted(authority.REQUIRED_DRILLS), "def012", strict=True)
        ],
        "transparency": {
            "generatedAt": "2026-08-22T01:00:00Z",
            "effectiveAt": "2026-08-23T00:00:00Z",
            "signingKeyId": "stable-recovery-fixture-1",
            "signatureBase64": None,
        },
    }
    keyset = manifest["keyset"]
    assert isinstance(keyset, dict)
    keyset["keysetDigest"] = authority._digest(authority._keyset_subject(manifest))
    for key, seed, public in keys_and_material:
        if key["role"] == "offline-recovery":
            continue
        statement = authority._proof_statement(manifest, key)
        proof = key["proofOfPossession"]
        assert isinstance(proof, dict)
        proof["statement"] = statement
        proof["statementDigest"] = authority._digest(statement)
        proof["signatureBase64"] = _encoded_signature(seed, public, statement)
    recovery = manifest["recoveryAuthorization"]
    assert isinstance(recovery, dict)
    recovery_statement = authority._recovery_statement(manifest)
    recovery["statementDigest"] = authority._digest(recovery_statement)
    recovery["signatureBase64"] = _encoded_signature(
        keys_and_material[-1][1], keys_and_material[-1][2], recovery_statement
    )
    artifact = authority._transparency_artifact(manifest)
    transparency = manifest["transparency"]
    assert isinstance(transparency, dict)
    transparency["signatureBase64"] = _encoded_signature(
        keys_and_material[-1][1], keys_and_material[-1][2], artifact
    )
    publication = manifest["publication"]
    catalog = manifest["catalog"]
    assert isinstance(publication, dict) and isinstance(catalog, dict)
    subject = authority._catalog_subject(catalog)
    publication["observations"] = [
        {
            "locationId": location["locationId"],
            "observedAt": "2026-08-22T02:00:00Z",
            "status": "exact-match",
            **subject,
        }
        for location in [publication["networkPrimary"], *publication["mirrors"]]
    ]
    publication["requestedState"] = "observed"
    return manifest


def _reseal(manifest: dict[str, object]) -> None:
    """Recompute fixture-only digests and signatures after a test mutation."""

    keyset = manifest["keyset"]
    assert isinstance(keyset, dict)
    keys = keyset["keys"]
    assert isinstance(keys, list)
    previous_keyset_digest = str(keyset["keysetDigest"])
    keyset["keysetDigest"] = authority._digest(authority._keyset_subject(manifest))
    for key in keys:
        assert isinstance(key, dict)
        if key["role"] == "offline-recovery":
            key["proofOfPossession"] = {
                "proofType": "not-applicable-recovery",
                "statement": None,
                "statementDigest": None,
                "signatureBase64": None,
            }
            continue
        proof = key["proofOfPossession"]
        assert isinstance(proof, dict)
        if key["lifecycle"] in authority.HISTORICAL_LIFECYCLES:
            statement = proof.get("statement")
            if not isinstance(statement, dict):
                statement = authority._proof_statement(manifest, key)
                statement["keysetDigest"] = previous_keyset_digest
                seed, public = _fixture_keypair(str(key["keyId"]))
                proof["statement"] = statement
                proof["statementDigest"] = authority._digest(statement)
                proof["signatureBase64"] = _encoded_signature(
                    seed, public, statement
                )
            proof["proofType"] = "retained-historical"
            continue
        seed, public = _fixture_keypair(str(key["keyId"]))
        statement = authority._proof_statement(manifest, key)
        key["proofOfPossession"] = {
            "proofType": "current-keyset",
            "statement": statement,
            "statementDigest": authority._digest(statement),
            "signatureBase64": _encoded_signature(seed, public, statement),
        }
    recovery = manifest["recoveryAuthorization"]
    assert isinstance(recovery, dict)
    statement = authority._recovery_statement(manifest)
    recovery["statementDigest"] = authority._digest(statement)
    if recovery["authorizationType"] == "recovery-signature":
        signer_id = str(recovery["signingRecoveryKeyId"])
        seed, public = _fixture_keypair(signer_id)
        recovery["signatureBase64"] = _encoded_signature(seed, public, statement)
    artifact = authority._transparency_artifact(manifest)
    transparency = manifest["transparency"]
    assert isinstance(transparency, dict)
    signer_id = str(transparency["signingKeyId"])
    seed, public = _fixture_keypair(signer_id)
    transparency["signatureBase64"] = _encoded_signature(seed, public, artifact)


def _drill_receipt_bundle(manifest: dict[str, object]) -> dict[str, object]:
    """Build deterministic fixture evidence in the protected receipt shape."""

    receipt_rows = []
    for index, claimed in enumerate(manifest["drills"]):
        receipt = {
            "drillType": claimed["drillType"],
            "status": "pass",
            "completedAt": claimed["completedAt"],
            "evidenceDigests": [_digest(format(index, "x"))],
            "receiptDigest": authority.ZERO_DIGEST,
        }
        receipt["receiptDigest"] = authority._semantic_digest(
            receipt, "receiptDigest"
        )
        claimed["subjectDigest"] = receipt["receiptDigest"]
        receipt_rows.append(receipt)
    bindings = manifest["bindings"]
    bundle = {
        "schemaVersion": 1,
        "kind": "stable-1.0-catalog-drill-receipts",
        "releaseId": manifest["release"]["releaseId"],
        "buildVersion": manifest["release"]["buildVersion"],
        "sourceCommit": manifest["release"]["sourceCommit"],
        "ceremonyId": manifest["ceremony"]["ceremonyId"],
        "keysetDigest": manifest["keyset"]["keysetDigest"],
        "bindings": {
            name: bindings[name]
            for name in (
                "protectedReleaseSummaryDigest",
                "protectedReleaseContractDigest",
                "independentReproducibilitySummaryDigest",
                "independentReproducibilityResultDigest",
                "independentSubjectInventoryDigest",
            )
        },
        "catalogSubject": authority._catalog_subject(manifest["catalog"]),
        "protectedEnvironment": "stable-1-0-catalog-drill-acceptance",
        "approvalRole": "stable-release-manager",
        "requiredApprovals": 2,
        "recordedApprovals": 2,
        "fixtureOnly": False,
        "operational": True,
        "status": "pass",
        "drills": receipt_rows,
        "bundleDigest": authority.ZERO_DIGEST,
    }
    bundle["bundleDigest"] = authority._semantic_digest(bundle, "bundleDigest")
    return bundle


class StableCatalogAuthorityTest(unittest.TestCase):
    def test_ed25519_verifier_accepts_rfc8032_vector_and_rejects_identity_forgery(self) -> None:
        public_key = bytes.fromhex(
            "d75a980182b10ab7d54bfed3c964073a"
            "0ee172f3daa62325af021a68f707511a"
        )
        signature = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a"
            "84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46b"
            "d25bf5f0595bbe24655141438e7a100b"
        )

        self.assertTrue(authority._verify_ed25519(public_key, b"", signature))
        self.assertFalse(
            authority._verify_ed25519(
                bytes.fromhex("01" + "00" * 31),
                b"forged",
                bytes.fromhex("01" + "00" * 31) + bytes(32),
            )
        )
        negative_zero_identity = bytes.fromhex("01" + "00" * 30 + "80")
        forged_scalar = 7
        canonical_r = authority._encode_point(
            authority._scalarmult(authority._B, forged_scalar)
        )
        self.assertFalse(
            authority._verify_ed25519(
                negative_zero_identity,
                b"forged",
                canonical_r + forged_scalar.to_bytes(32, "little"),
            )
        )
        self.assertFalse(
            authority._verify_ed25519(
                public_key,
                b"forged",
                negative_zero_identity + bytes(32),
            )
        )

    def setUp(self) -> None:
        self.workspace = Path(__file__).resolve().parents[4]
        (self.workspace / "build").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(
            dir=self.workspace / "build",
            prefix="stable-catalog-authority-test-",
        )
        self.root = Path(self.temporary.name)
        self.run_index = 0

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_manifest(
        self,
        manifest: dict[str, object],
        mode: str = "closeout",
        evidence_dir: Path | None = None,
    ) -> tuple[int, Path]:
        self.run_index += 1
        input_file = self.root / f"{mode}-{self.run_index}.json"
        output = self.root / f"out-{mode}-{self.run_index}"
        write_json(input_file, manifest)
        return (
            authority.run(
                self.workspace,
                input_file,
                mode,
                output,
                evidence_dir=evidence_dir,
            ),
            output,
        )

    def write_previous_transparency(self, manifest: dict[str, object]) -> None:
        """Write the exact signed predecessor artifact used by transition tests."""

        write_json(
            self.root / authority.PREVIOUS_TRANSPARENCY_FILE,
            authority._transparency_artifact(manifest),
        )
        (self.root / authority.PREVIOUS_TRANSPARENCY_SIGNATURE_FILE).write_bytes(
            base64.b64decode(
                manifest["transparency"]["signatureBase64"], validate=True
            )
        )

    def test_valid_fixture_closeout_writes_closed_outputs_without_operational_claim(self) -> None:
        code, output = self.run_manifest(_manifest())

        summary = read_json(output / authority.AUTHORITY_SUMMARY_FILE)
        receipt = read_json(output / authority.CEREMONY_RECEIPT_FILE)

        self.assertEqual(0, code)
        self.assertEqual("fixture-verification-complete", summary["state"])
        self.assertFalse(summary["operational"])
        self.assertEqual("fixture-verification-complete", receipt["state"])
        self.assertFalse(receipt["operational"])
        self.assertEqual([], validate_schema(receipt, authority.RECEIPT_SCHEMA))
        self.assertTrue((output / authority.TRANSPARENCY_SIGNATURE_FILE).is_file())

    def test_all_modes_are_side_effect_free_and_fixture_bounded(self) -> None:
        for mode in authority.MODES:
            with self.subTest(mode=mode):
                code, output = self.run_manifest(_manifest(), mode)
                summary = read_json(output / authority.AUTHORITY_SUMMARY_FILE)
                self.assertEqual(0, code)
                self.assertFalse(summary["operational"])
                self.assertNotIn("ceremony-authenticated", json.dumps(summary))
                self.assertNotIn("network-primary-published", json.dumps(summary))

    def test_nonfixture_local_closeout_without_exact_evidence_is_blocked(self) -> None:
        manifest = _manifest()
        manifest["fixtureOnly"] = False
        for drill in manifest["drills"]:
            drill["fixtureOnly"] = False

        code, output = self.run_manifest(manifest)

        summary = read_json(output / authority.AUTHORITY_SUMMARY_FILE)
        self.assertEqual(1, code)
        self.assertEqual("blocked", summary["state"])
        self.assertFalse(summary["operational"])
        self.assertIn("exact protected evidence", " ".join(summary["blockers"]))

    def test_planned_rotation_is_authorized_by_previous_recovery_root(self) -> None:
        previous = _manifest()
        write_json(
            self.root / authority.PREVIOUS_TRANSPARENCY_FILE,
            authority._transparency_artifact(previous),
        )
        (self.root / authority.PREVIOUS_TRANSPARENCY_SIGNATURE_FILE).write_bytes(
            base64.b64decode(previous["transparency"]["signatureBase64"], validate=True)
        )
        successor = copy.deepcopy(previous)
        successor["ceremony"]["ceremonyId"] = "stable-1.0-fixture-rotation"
        successor["ceremony"]["ceremonyType"] = "planned-rotation"
        successor["keyset"]["keysetVersion"] = 2
        successor["keyset"]["previousKeysetDigest"] = previous["keyset"]["keysetDigest"]
        old_catalog_key = successor["keyset"]["keys"][0]
        new_catalog_key, _, _ = _key(
            "catalog-signing", "stable-catalog-fixture-2"
        )
        old_catalog_key["lifecycle"] = "retiring"
        old_catalog_key["successorKeyId"] = new_catalog_key["keyId"]
        new_catalog_key["lifecycle"] = "staged"
        new_catalog_key["predecessorKeyId"] = old_catalog_key["keyId"]
        successor["keyset"]["keys"].append(new_catalog_key)
        _reseal(successor)
        key_errors, by_id = authority._validate_keyset(successor, True)

        transition_errors = authority._previous_recovery_errors(
            self.root, successor, by_id
        )

        self.assertEqual([], key_errors)
        self.assertEqual([], transition_errors)

    def test_planned_rotation_after_protected_quorum_uses_transparency_signer(
        self,
    ) -> None:
        previous = _manifest()
        previous["ceremony"]["ceremonyType"] = "compromise-recovery"
        previous["keyset"]["keysetVersion"] = 2
        previous["keyset"]["previousKeysetDigest"] = _digest("e")
        authorization = previous["recoveryAuthorization"]
        authorization["authorizationType"] = "protected-recovery-quorum"
        authorization["signingRecoveryKeyId"] = None
        authorization["signatureBase64"] = None
        authorization["protectedRecoveryQuorumDigest"] = _digest("f")
        _reseal(previous)
        write_json(
            self.root / authority.PREVIOUS_TRANSPARENCY_FILE,
            authority._transparency_artifact(previous),
        )
        (self.root / authority.PREVIOUS_TRANSPARENCY_SIGNATURE_FILE).write_bytes(
            base64.b64decode(
                previous["transparency"]["signatureBase64"], validate=True
            )
        )
        successor = copy.deepcopy(previous)
        successor["ceremony"]["ceremonyId"] = "stable-1.0-fixture-post-recovery"
        successor["ceremony"]["ceremonyType"] = "planned-rotation"
        successor["keyset"]["keysetVersion"] = 3
        successor["keyset"]["previousKeysetDigest"] = previous["keyset"][
            "keysetDigest"
        ]
        successor_authorization = successor["recoveryAuthorization"]
        successor_authorization["authorizationType"] = "recovery-signature"
        successor_authorization["signingRecoveryKeyId"] = (
            "stable-recovery-fixture-1"
        )
        successor_authorization["protectedRecoveryQuorumDigest"] = None
        _reseal(successor)
        _, by_id = authority._validate_keyset(successor, True)

        errors = authority._previous_recovery_errors(self.root, successor, by_id)

        self.assertEqual([], errors)

    def test_successor_keyset_cannot_prune_authenticated_key_identity(self) -> None:
        previous = _manifest()
        self.write_previous_transparency(previous)
        successor = copy.deepcopy(previous)
        prior_catalog_key = successor["keyset"]["keys"].pop(0)
        replacement, _, _ = _key(
            "catalog-signing", "stable-catalog-fixture-recovery-successor"
        )
        successor["keyset"]["keys"].append(replacement)
        successor["ceremony"]["ceremonyType"] = "compromise-recovery"
        successor["keyset"]["keysetVersion"] = 2
        successor["keyset"]["previousKeysetDigest"] = previous["keyset"][
            "keysetDigest"
        ]
        authorization = successor["recoveryAuthorization"]
        authorization["authorizationType"] = "protected-recovery-quorum"
        authorization["signingRecoveryKeyId"] = None
        authorization["signatureBase64"] = None
        authorization["protectedRecoveryQuorumDigest"] = _digest("f")
        _reseal(successor)
        by_id = {key["keyId"]: key for key in successor["keyset"]["keys"]}

        errors = authority._previous_recovery_errors(self.root, successor, by_id)

        self.assertIn(
            "successor keyset omits previous key identity: "
            + prior_catalog_key["keyId"],
            errors,
        )

    def test_successor_keyset_cannot_move_authenticated_identity_across_roles(
        self,
    ) -> None:
        previous = _manifest()
        self.write_previous_transparency(previous)
        successor = copy.deepcopy(previous)
        prior_catalog_key = successor["keyset"]["keys"][0]
        prior_catalog_key["role"] = "first-party-app-signing"
        replacement, _, _ = _key(
            "catalog-signing", "stable-catalog-fixture-role-successor"
        )
        successor["keyset"]["keys"].append(replacement)
        successor["ceremony"]["ceremonyType"] = "compromise-recovery"
        successor["keyset"]["keysetVersion"] = 2
        successor["keyset"]["previousKeysetDigest"] = previous["keyset"][
            "keysetDigest"
        ]
        authorization = successor["recoveryAuthorization"]
        authorization["authorizationType"] = "protected-recovery-quorum"
        authorization["signingRecoveryKeyId"] = None
        authorization["signatureBase64"] = None
        authorization["protectedRecoveryQuorumDigest"] = _digest("f")
        _reseal(successor)
        by_id = {key["keyId"]: key for key in successor["keyset"]["keys"]}

        errors = authority._previous_recovery_errors(self.root, successor, by_id)

        self.assertIn(
            "successor keyset changes previous public identity: "
            "stable-catalog-fixture-1",
            errors,
        )

    def test_successor_keyset_cannot_reassign_authenticated_fingerprint(self) -> None:
        previous = _manifest()
        self.write_previous_transparency(previous)
        successor = copy.deepcopy(previous)
        prior_catalog_key = successor["keyset"]["keys"].pop(0)
        replacement, _, _ = _key(
            "catalog-signing", "stable-catalog-fixture-fingerprint-successor"
        )
        alias = copy.deepcopy(prior_catalog_key)
        alias["keyId"] = "stable-app-fixture-catalog-key-alias"
        alias["role"] = "first-party-app-signing"
        successor["keyset"]["keys"].extend((replacement, alias))
        successor["ceremony"]["ceremonyType"] = "compromise-recovery"
        successor["keyset"]["keysetVersion"] = 2
        successor["keyset"]["previousKeysetDigest"] = previous["keyset"][
            "keysetDigest"
        ]
        authorization = successor["recoveryAuthorization"]
        authorization["authorizationType"] = "protected-recovery-quorum"
        authorization["signingRecoveryKeyId"] = None
        authorization["signatureBase64"] = None
        authorization["protectedRecoveryQuorumDigest"] = _digest("f")
        _reseal(successor)
        by_id = {key["keyId"]: key for key in successor["keyset"]["keys"]}

        errors = authority._previous_recovery_errors(self.root, successor, by_id)

        self.assertIn(
            "successor keyset reassigns previous public-key fingerprint: "
            "stable-catalog-fixture-1",
            errors,
        )

    def test_successor_keyset_cannot_reverse_lifecycle_or_compromise_state(
        self,
    ) -> None:
        cases = (
            (
                "revoked",
                "compromised",
                "active",
                "uncompromised",
                (
                    "successor keyset reverses previous key lifecycle",
                    "successor keyset clears previous key compromise state",
                ),
            ),
            (
                "retired",
                "uncompromised",
                "active",
                "uncompromised",
                ("successor keyset reverses previous key lifecycle",),
            ),
            (
                "retired",
                "suspected",
                "retired",
                "uncompromised",
                ("successor keyset clears previous key compromise state",),
            ),
            (
                "revoked",
                "compromised",
                "revoked",
                "suspected",
                ("successor keyset clears previous key compromise state",),
            ),
        )
        for (
            previous_lifecycle,
            previous_compromise,
            current_lifecycle,
            current_compromise,
            expected_errors,
        ) in cases:
            with self.subTest(
                previous_lifecycle=previous_lifecycle,
                previous_compromise=previous_compromise,
                current_lifecycle=current_lifecycle,
                current_compromise=current_compromise,
            ):
                previous = _manifest()
                previous_key = previous["keyset"]["keys"][0]
                previous_key["lifecycle"] = previous_lifecycle
                previous_key["compromiseState"] = previous_compromise
                _reseal(previous)
                self.write_previous_transparency(previous)
                successor = copy.deepcopy(previous)
                successor["ceremony"]["ceremonyId"] = (
                    "stable-1.0-fixture-monotonic-transition"
                )
                successor["ceremony"]["ceremonyType"] = "compromise-recovery"
                successor["keyset"]["keysetVersion"] = 2
                successor["keyset"]["previousKeysetDigest"] = previous[
                    "keyset"
                ]["keysetDigest"]
                current_key = successor["keyset"]["keys"][0]
                current_key["lifecycle"] = current_lifecycle
                current_key["compromiseState"] = current_compromise
                _reseal(successor)
                key_errors, by_id = authority._validate_keyset(successor, True)

                transition_errors = authority._previous_recovery_errors(
                    self.root, successor, by_id
                )

                self.assertEqual([], key_errors)
                for expected_error in expected_errors:
                    self.assertIn(expected_error, " ".join(transition_errors))

    def test_protected_quorum_recovery_retains_revoked_identity_without_resigning(
        self,
    ) -> None:
        previous = _manifest()
        self.write_previous_transparency(previous)
        successor = copy.deepcopy(previous)
        predecessor = successor["keyset"]["keys"][0]
        retained_signature = predecessor["proofOfPossession"]["signatureBase64"]
        replacement, _, _ = _key(
            "catalog-signing", "stable-catalog-fixture-quorum-successor"
        )
        predecessor["lifecycle"] = "revoked"
        predecessor["compromiseState"] = "compromised"
        predecessor["successorKeyId"] = replacement["keyId"]
        replacement["predecessorKeyId"] = predecessor["keyId"]
        successor["keyset"]["keys"].append(replacement)
        successor["ceremony"]["ceremonyType"] = "compromise-recovery"
        successor["keyset"]["keysetVersion"] = 2
        successor["keyset"]["previousKeysetDigest"] = previous["keyset"][
            "keysetDigest"
        ]
        authorization = successor["recoveryAuthorization"]
        authorization["authorizationType"] = "protected-recovery-quorum"
        authorization["signingRecoveryKeyId"] = None
        authorization["signatureBase64"] = None
        authorization["protectedRecoveryQuorumDigest"] = _digest("f")
        _reseal(successor)
        key_errors, by_id = authority._validate_keyset(successor, True)

        transition_errors = authority._previous_recovery_errors(
            self.root, successor, by_id
        )

        self.assertEqual([], key_errors)
        self.assertEqual([], transition_errors)
        self.assertEqual(
            retained_signature,
            predecessor["proofOfPossession"]["signatureBase64"],
        )

    def test_fresh_post_revocation_proof_cannot_replace_authenticated_proof(
        self,
    ) -> None:
        previous = _manifest()
        self.write_previous_transparency(previous)
        successor = copy.deepcopy(previous)
        predecessor = successor["keyset"]["keys"][0]
        replacement, _, _ = _key(
            "catalog-signing", "stable-catalog-fixture-proof-successor"
        )
        predecessor["lifecycle"] = "revoked"
        predecessor["compromiseState"] = "compromised"
        predecessor["successorKeyId"] = replacement["keyId"]
        replacement["predecessorKeyId"] = predecessor["keyId"]
        successor["keyset"]["keys"].append(replacement)
        successor["ceremony"]["ceremonyId"] = (
            "stable-1.0-fixture-proof-substitution"
        )
        successor["ceremony"]["ceremonyType"] = "compromise-recovery"
        successor["keyset"]["keysetVersion"] = 2
        successor["keyset"]["previousKeysetDigest"] = previous["keyset"][
            "keysetDigest"
        ]
        _reseal(successor)
        proof = predecessor["proofOfPossession"]
        forged_statement = copy.deepcopy(proof["statement"])
        forged_statement["ceremonyId"] = "stable-1.0-forged-after-revocation"
        forged_statement["keysetDigest"] = _digest("f")
        seed, public = _fixture_keypair(predecessor["keyId"])
        proof["statement"] = forged_statement
        proof["statementDigest"] = authority._digest(forged_statement)
        proof["signatureBase64"] = _encoded_signature(
            seed, public, forged_statement
        )
        key_errors, by_id = authority._validate_keyset(successor, True)

        transition_errors = authority._previous_recovery_errors(
            self.root, successor, by_id
        )

        self.assertEqual([], key_errors)
        self.assertIn(
            "successor keyset substitutes retained proof provenance: "
            "stable-catalog-fixture-1",
            transition_errors,
        )

    def test_retained_proof_provenance_survives_multiple_successor_keysets(
        self,
    ) -> None:
        previous = _manifest()
        self.write_previous_transparency(previous)
        successor = copy.deepcopy(previous)
        predecessor = successor["keyset"]["keys"][0]
        replacement, _, _ = _key(
            "catalog-signing", "stable-catalog-fixture-proof-lineage-successor"
        )
        predecessor["lifecycle"] = "revoked"
        predecessor["compromiseState"] = "compromised"
        predecessor["successorKeyId"] = replacement["keyId"]
        replacement["predecessorKeyId"] = predecessor["keyId"]
        successor["keyset"]["keys"].append(replacement)
        successor["ceremony"]["ceremonyId"] = "stable-1.0-fixture-proof-lineage-2"
        successor["ceremony"]["ceremonyType"] = "compromise-recovery"
        successor["keyset"]["keysetVersion"] = 2
        successor["keyset"]["previousKeysetDigest"] = previous["keyset"][
            "keysetDigest"
        ]
        _reseal(successor)
        _, successor_by_id = authority._validate_keyset(successor, True)
        self.assertEqual(
            [],
            authority._previous_recovery_errors(
                self.root, successor, successor_by_id
            ),
        )
        retained_proof = copy.deepcopy(predecessor["proofOfPossession"])
        self.write_previous_transparency(successor)
        third = copy.deepcopy(successor)
        third["ceremony"]["ceremonyId"] = "stable-1.0-fixture-proof-lineage-3"
        third["ceremony"]["ceremonyType"] = "planned-rotation"
        third["keyset"]["keysetVersion"] = 3
        third["keyset"]["previousKeysetDigest"] = successor["keyset"][
            "keysetDigest"
        ]
        authorization = third["recoveryAuthorization"]
        authorization["authorizationType"] = "recovery-signature"
        authorization["signingRecoveryKeyId"] = "stable-recovery-fixture-1"
        authorization["protectedRecoveryQuorumDigest"] = None
        _reseal(third)
        key_errors, third_by_id = authority._validate_keyset(third, True)

        transition_errors = authority._previous_recovery_errors(
            self.root, third, third_by_id
        )

        self.assertEqual([], key_errors)
        self.assertEqual([], transition_errors)
        third_predecessor = third["keyset"]["keys"][0]
        self.assertEqual(retained_proof, third_predecessor["proofOfPossession"])

    def test_previous_transparency_signer_substitution_fails_closed(self) -> None:
        previous = _manifest()
        replacement, _, _ = _key(
            "offline-recovery", "stable-recovery-fixture-2"
        )
        previous["keyset"]["keys"].append(replacement)
        _reseal(previous)
        artifact = authority._transparency_artifact(previous)
        artifact["transparencySigningKeyId"] = replacement["keyId"]
        artifact["selfDigest"] = authority._semantic_digest(artifact, "selfDigest")
        write_json(self.root / authority.PREVIOUS_TRANSPARENCY_FILE, artifact)
        (self.root / authority.PREVIOUS_TRANSPARENCY_SIGNATURE_FILE).write_bytes(
            base64.b64decode(
                previous["transparency"]["signatureBase64"], validate=True
            )
        )
        successor = copy.deepcopy(previous)
        successor["ceremony"]["ceremonyId"] = "stable-1.0-fixture-rotation"
        successor["ceremony"]["ceremonyType"] = "planned-rotation"
        successor["keyset"]["keysetVersion"] = 2
        successor["keyset"]["previousKeysetDigest"] = previous["keyset"][
            "keysetDigest"
        ]
        _reseal(successor)
        _, by_id = authority._validate_keyset(successor, True)

        errors = authority._previous_recovery_errors(self.root, successor, by_id)

        self.assertIn(
            "previous public key transparency detached signature is invalid", errors
        )

    def test_successor_recovery_key_cannot_self_authorize_rotation(self) -> None:
        previous = _manifest()
        write_json(
            self.root / authority.PREVIOUS_TRANSPARENCY_FILE,
            authority._transparency_artifact(previous),
        )
        (self.root / authority.PREVIOUS_TRANSPARENCY_SIGNATURE_FILE).write_bytes(
            base64.b64decode(previous["transparency"]["signatureBase64"], validate=True)
        )
        successor = copy.deepcopy(previous)
        successor["ceremony"]["ceremonyId"] = "stable-1.0-fixture-rotation"
        successor["ceremony"]["ceremonyType"] = "planned-rotation"
        successor["keyset"]["keysetVersion"] = 2
        successor["keyset"]["previousKeysetDigest"] = previous["keyset"]["keysetDigest"]
        successor["keyset"]["keys"][-1], _, _ = _key(
            "offline-recovery", "stable-recovery-fixture-2"
        )
        successor["recoveryAuthorization"]["signingRecoveryKeyId"] = (
            "stable-recovery-fixture-2"
        )
        successor["transparency"]["signingKeyId"] = "stable-recovery-fixture-2"
        old_catalog_key = successor["keyset"]["keys"][0]
        new_catalog_key, _, _ = _key(
            "catalog-signing", "stable-catalog-fixture-2"
        )
        old_catalog_key["lifecycle"] = "retiring"
        old_catalog_key["successorKeyId"] = new_catalog_key["keyId"]
        new_catalog_key["lifecycle"] = "staged"
        new_catalog_key["predecessorKeyId"] = old_catalog_key["keyId"]
        successor["keyset"]["keys"].append(new_catalog_key)
        _reseal(successor)
        _, by_id = authority._validate_keyset(successor, True)

        transition_errors = authority._previous_recovery_errors(
            self.root, successor, by_id
        )

        self.assertIn(
            "successor transition was not authorized by the previous recovery root",
            transition_errors,
        )

    def test_compromise_recovery_requires_exact_protected_quorum_receipt(self) -> None:
        manifest = _manifest()
        manifest["fixtureOnly"] = False
        manifest["ceremony"]["ceremonyType"] = "compromise-recovery"
        manifest["ceremony"]["custodyClass"] = "offline-quorum"
        manifest["keyset"]["keysetVersion"] = 2
        manifest["keyset"]["previousKeysetDigest"] = _digest("e")
        authorization = manifest["recoveryAuthorization"]
        authorization["authorizationType"] = "protected-recovery-quorum"
        authorization["signingRecoveryKeyId"] = None
        authorization["signatureBase64"] = None
        authorization["protectedRecoveryQuorumDigest"] = _digest("0")
        for drill in manifest["drills"]:
            drill["fixtureOnly"] = False
        _reseal(manifest)
        receipt = {
            "schemaVersion": 1,
            "kind": "stable-1.0-protected-recovery-quorum-receipt",
            "releaseId": manifest["release"]["releaseId"],
            "buildVersion": manifest["release"]["buildVersion"],
            "sourceCommit": manifest["release"]["sourceCommit"],
            "ceremonyId": manifest["ceremony"]["ceremonyId"],
            "keysetDigest": manifest["keyset"]["keysetDigest"],
            "recoveryStatementDigest": authorization["statementDigest"],
            "protectedEnvironment": manifest["ceremony"]["approvalQuorum"][
                "protectedEnvironment"
            ],
            "approvalRole": manifest["ceremony"]["approvalQuorum"]["approvalRole"],
            "requiredApprovals": manifest["ceremony"]["approvalQuorum"][
                "requiredApprovals"
            ],
            "recordedApprovals": manifest["ceremony"]["approvalQuorum"][
                "requiredApprovals"
            ],
            "fixtureOnly": False,
            "operational": True,
            "status": "pass",
            "receiptDigest": authority.ZERO_DIGEST,
        }
        receipt["receiptDigest"] = authority._semantic_digest(receipt, "receiptDigest")
        receipt_path = self.root / authority.RECOVERY_QUORUM_RECEIPT_FILE
        write_json(receipt_path, receipt)
        authorization["protectedRecoveryQuorumDigest"] = authority._file_digest(
            receipt_path.read_bytes()
        )

        exact_errors = authority._protected_recovery_quorum_errors(
            self.root, manifest
        )
        authorization["protectedRecoveryQuorumDigest"] = _digest("f")
        substituted_errors = authority._protected_recovery_quorum_errors(
            self.root, manifest
        )

        self.assertEqual([], exact_errors)
        self.assertIn(
            "protected recovery quorum receipt digest does not match",
            substituted_errors,
        )

    def test_protected_recovery_quorum_requires_fixed_governance(self) -> None:
        manifest = _manifest()
        manifest["ceremony"]["ceremonyType"] = "compromise-recovery"
        authorization = manifest["recoveryAuthorization"]
        authorization["authorizationType"] = "protected-recovery-quorum"
        authorization["signingRecoveryKeyId"] = None
        authorization["signatureBase64"] = None
        authorization["protectedRecoveryQuorumDigest"] = _digest("e")
        manifest["ceremony"]["approvalQuorum"]["approvalRole"] = (
            "caller-selected-role"
        )

        errors = authority._validate_recovery(manifest, {}, False)

        self.assertIn(
            "protected recovery quorum does not select the fixed recovery governance",
            errors,
        )

    def test_role_specific_registries_do_not_cross_trust_roots(self) -> None:
        manifest = _manifest()
        retired_catalog_key, _, _ = _key(
            "catalog-signing", "stable-catalog-fixture-0"
        )
        retired_catalog_key["lifecycle"] = "retired"
        retired_catalog_key["validFrom"] = "2025-08-20T00:00:00Z"
        retired_catalog_key["validUntil"] = "2026-08-20T00:00:00Z"
        manifest["keyset"]["keys"].append(retired_catalog_key)
        retiring_catalog_key, _, _ = _key(
            "catalog-signing", "stable-catalog-fixture-0-retiring"
        )
        retiring_catalog_key["lifecycle"] = "retiring"
        manifest["keyset"]["keys"].append(retiring_catalog_key)
        revoked_catalog_key, _, _ = _key(
            "catalog-signing", "stable-catalog-fixture-revoked"
        )
        revoked_catalog_key["lifecycle"] = "revoked"
        revoked_catalog_key["compromiseState"] = "compromised"
        manifest["keyset"]["keys"].append(revoked_catalog_key)
        staged_catalog_key, _, _ = _key(
            "catalog-signing", "stable-catalog-fixture-staged"
        )
        staged_catalog_key["lifecycle"] = "staged"
        manifest["keyset"]["keys"].append(staged_catalog_key)
        compromised_retired_app_key, _, _ = _key(
            "first-party-app-signing", "stable-app-fixture-retired-compromised"
        )
        compromised_retired_app_key["lifecycle"] = "retired"
        compromised_retired_app_key["compromiseState"] = "suspected"
        manifest["keyset"]["keys"].append(compromised_retired_app_key)
        staged_app_key, _, _ = _key(
            "first-party-app-signing", "stable-app-fixture-staged"
        )
        staged_app_key["lifecycle"] = "staged"
        manifest["keyset"]["keys"].append(staged_app_key)
        revoked_reviewer, _, _ = _key(
            "app-reviewer", "stable-reviewer-fixture-revoked"
        )
        revoked_reviewer["lifecycle"] = "revoked"
        revoked_reviewer["compromiseState"] = "compromised"
        manifest["keyset"]["keys"].append(revoked_reviewer)
        compromised_retired_reviewer, _, _ = _key(
            "app-reviewer", "stable-reviewer-fixture-retired-compromised"
        )
        compromised_retired_reviewer["lifecycle"] = "retired"
        compromised_retired_reviewer["compromiseState"] = "suspected"
        manifest["keyset"]["keys"].append(compromised_retired_reviewer)
        staged_reviewer, _, _ = _key(
            "app-reviewer", "stable-reviewer-fixture-staged"
        )
        staged_reviewer["lifecycle"] = "staged"
        manifest["keyset"]["keys"].append(staged_reviewer)
        _reseal(manifest)

        code, output = self.run_manifest(manifest)

        catalog = (output / authority.CATALOG_REGISTRY_FILE).read_text()
        apps = (output / authority.APP_REGISTRY_FILE).read_text()
        reviewers = (output / authority.REVIEWER_REGISTRY_FILE).read_text()

        def status_for(registry: str, key_id: str) -> str | None:
            properties = dict(
                line.split("=", 1) for line in registry.splitlines() if "=" in line
            )
            for name, value in properties.items():
                if name.endswith(".id") and value == key_id:
                    return properties.get(name.removesuffix(".id") + ".status")
            return None

        self.assertEqual(0, code)
        self.assertIn("stable-catalog-fixture-1", catalog)
        self.assertIn("trusted.keys.version=2", catalog)
        self.assertIn("key.0.status=retired", catalog)
        self.assertIn("key.0.valid.from=2025-08-20T00:00:00Z", catalog)
        self.assertIn("key.0.valid.until=2026-08-20T00:00:00Z", catalog)
        self.assertIn("key.1.status=retiring", catalog)
        self.assertIn("key.1.valid.from=2026-08-20T00:00:00Z", catalog)
        self.assertIn("key.1.valid.until=2028-08-20T00:00:00Z", catalog)
        self.assertIn("key.2.status=active", catalog)
        self.assertEqual(
            "revoked", status_for(catalog, "stable-catalog-fixture-revoked")
        )
        self.assertNotIn("stable-catalog-fixture-staged", catalog)
        self.assertNotIn("stable-app-fixture-1", catalog)
        self.assertIn("stable-app-fixture-1", apps)
        self.assertIn("trusted.keys.version=2", apps)
        self.assertEqual("active", status_for(apps, "stable-app-fixture-1"))
        self.assertEqual(
            "revoked",
            status_for(apps, "stable-app-fixture-retired-compromised"),
        )
        self.assertNotIn("stable-app-fixture-staged", apps)
        self.assertNotIn("stable-catalog-fixture-1", apps)
        self.assertIn("stable-reviewer-fixture-1", reviewers)
        self.assertRegex(
            reviewers,
            r"reviewer\.2\.id=stable-reviewer-fixture-retired-compromised\n"
            r"(?:reviewer\.2\.[^\n]+\n){2}reviewer\.2\.status=revoked",
        )
        self.assertRegex(
            reviewers,
            r"reviewer\.3\.id=stable-reviewer-fixture-revoked\n"
            r"(?:reviewer\.3\.[^\n]+\n){2}reviewer\.3\.status=revoked",
        )
        self.assertNotIn("stable-reviewer-fixture-staged", reviewers)
        self.assertNotIn("stable-recovery-fixture-1", catalog + apps + reviewers)

    def test_operational_drills_require_exact_authenticated_receipts(self) -> None:
        manifest = _manifest()
        manifest["fixtureOnly"] = False
        for row in manifest["drills"]:
            row["fixtureOnly"] = False
        bundle = _drill_receipt_bundle(manifest)
        write_json(self.root / authority.DRILL_RECEIPTS_FILE, bundle)

        valid_errors, completed = authority._validate_drills(
            manifest, True, self.root
        )
        manifest["drills"][0]["subjectDigest"] = _digest("f")
        substituted_errors, _ = authority._validate_drills(
            manifest, True, self.root
        )
        (self.root / authority.DRILL_RECEIPTS_FILE).unlink()
        missing_errors, _ = authority._validate_drills(manifest, True, self.root)

        self.assertEqual([], valid_errors)
        self.assertEqual(
            manifest["drills"][-1]["completedAt"],
            completed[manifest["drills"][-1]["drillType"]],
        )
        self.assertIn("does not match its authenticated receipt", " ".join(substituted_errors))
        self.assertIn("required protected evidence member is missing", " ".join(missing_errors))

    def test_duplicate_key_id_or_public_fingerprint_fails_closed(self) -> None:
        for mutation in ("id", "fingerprint"):
            with self.subTest(mutation=mutation):
                manifest = _manifest()
                keys = manifest["keyset"]["keys"]
                if mutation == "id":
                    keys[1]["keyId"] = keys[0]["keyId"]
                else:
                    keys[1]["publicKeyFingerprintSha256"] = keys[0]["publicKeyFingerprintSha256"]

                code, output = self.run_manifest(manifest)

                self.assertEqual(1, code)
                self.assertEqual("blocked", read_json(output / authority.AUTHORITY_SUMMARY_FILE)["state"])

    def test_recovery_key_cannot_carry_routine_proof(self) -> None:
        manifest = _manifest()
        recovery = manifest["keyset"]["keys"][-1]
        recovery["proofOfPossession"]["signatureBase64"] = manifest["keyset"]["keys"][0]["proofOfPossession"]["signatureBase64"]

        code, output = self.run_manifest(manifest)

        self.assertEqual(1, code)
        self.assertIn("routine proof", " ".join(read_json(output / authority.AUTHORITY_SUMMARY_FILE)["blockers"]))

    def test_missing_or_substituted_proof_and_recovery_signatures_fail(self) -> None:
        cases = []
        missing = _manifest()
        missing["keyset"]["keys"][0]["proofOfPossession"]["signatureBase64"] = None
        cases.append(missing)
        substituted = _manifest()
        substituted["recoveryAuthorization"]["signatureBase64"] = substituted["keyset"]["keys"][0]["proofOfPossession"]["signatureBase64"]
        cases.append(substituted)
        transparency = _manifest()
        transparency["transparency"]["signatureBase64"] = transparency["keyset"]["keys"][0]["proofOfPossession"]["signatureBase64"]
        cases.append(transparency)
        for manifest in cases:
            with self.subTest():
                code, _ = self.run_manifest(manifest)
                self.assertEqual(1, code)

    def test_historical_routine_key_reuses_authenticated_proof_without_resigning(
        self,
    ) -> None:
        manifest = _manifest()
        predecessor = manifest["keyset"]["keys"][0]
        retained_proof = copy.deepcopy(predecessor["proofOfPossession"])
        previous_keyset_digest = manifest["keyset"]["keysetDigest"]
        successor, _, _ = _key(
            "catalog-signing", "stable-catalog-fixture-successor"
        )
        predecessor["lifecycle"] = "revoked"
        predecessor["compromiseState"] = "compromised"
        predecessor["successorKeyId"] = successor["keyId"]
        successor["predecessorKeyId"] = predecessor["keyId"]
        manifest["keyset"]["keys"].append(successor)
        manifest["keyset"]["keysetVersion"] = 2
        manifest["keyset"]["previousKeysetDigest"] = previous_keyset_digest
        manifest["ceremony"]["ceremonyType"] = "compromise-recovery"

        fixture_keypair = _fixture_keypair

        def available_keypair(label: str) -> tuple[bytes, bytes]:
            if label == predecessor["keyId"]:
                raise AssertionError("historical predecessor private material was requested")
            return fixture_keypair(label)

        with mock.patch(
            f"{__name__}._fixture_keypair", side_effect=available_keypair
        ):
            _reseal(manifest)
        errors, _ = authority._validate_keyset(manifest, True)

        historical = predecessor["proofOfPossession"]
        self.assertEqual([], errors)
        self.assertEqual("retained-historical", historical["proofType"])
        self.assertEqual(retained_proof["statement"], historical["statement"])
        self.assertEqual(
            retained_proof["statementDigest"], historical["statementDigest"]
        )
        self.assertEqual(
            retained_proof["signatureBase64"], historical["signatureBase64"]
        )
        self.assertNotEqual(
            manifest["keyset"]["keysetDigest"],
            historical["statement"]["keysetDigest"],
        )
        transparency_key = next(
            row
            for row in authority._transparency_artifact(manifest)["keys"]
            if row["keyId"] == predecessor["keyId"]
        )
        receipt_key = next(
            row
            for row in authority._key_receipts(manifest)
            if row["keyId"] == predecessor["keyId"]
        )
        for row in (transparency_key, receipt_key):
            self.assertEqual("retained-historical", row["proofType"])
            self.assertEqual(
                historical["statement"]["ceremonyId"], row["proofCeremonyId"]
            )
            self.assertEqual(
                historical["statement"]["keysetDigest"], row["proofKeysetDigest"]
            )

    def test_historical_proof_substitution_and_current_key_replay_fail_closed(
        self,
    ) -> None:
        manifest = _manifest()
        historical = manifest["keyset"]["keys"][0]
        historical["lifecycle"] = "retired"
        _reseal(manifest)
        historical["proofOfPossession"]["statement"][
            "publicKeyFingerprintSha256"
        ] = _digest("f")
        historical_errors, _ = authority._validate_keyset(manifest, True)

        replay = _manifest()
        current = replay["keyset"]["keys"][0]
        current["proofOfPossession"]["proofType"] = "retained-historical"
        replay_errors, _ = authority._validate_keyset(replay, True)

        self.assertIn(
            "retained proof does not bind its historical public identity",
            " ".join(historical_errors),
        )
        self.assertIn(
            "lifecycle requires a current-keyset proof of possession",
            " ".join(replay_errors),
        )

    def test_planned_rotation_after_predecessor_retirement_does_not_resign_it(
        self,
    ) -> None:
        manifest = _manifest()
        predecessor = manifest["keyset"]["keys"][0]
        retained_signature = predecessor["proofOfPossession"]["signatureBase64"]
        previous_keyset_digest = manifest["keyset"]["keysetDigest"]
        successor, _, _ = _key(
            "catalog-signing", "stable-catalog-fixture-planned-successor"
        )
        predecessor["lifecycle"] = "retired"
        predecessor["successorKeyId"] = successor["keyId"]
        successor["predecessorKeyId"] = predecessor["keyId"]
        manifest["keyset"]["keys"].append(successor)
        manifest["keyset"]["keysetVersion"] = 2
        manifest["keyset"]["previousKeysetDigest"] = previous_keyset_digest
        manifest["ceremony"]["ceremonyType"] = "planned-rotation"
        fixture_keypair = _fixture_keypair

        def available_keypair(label: str) -> tuple[bytes, bytes]:
            if label == predecessor["keyId"]:
                raise AssertionError("retired predecessor private material was requested")
            return fixture_keypair(label)

        with mock.patch(
            f"{__name__}._fixture_keypair", side_effect=available_keypair
        ):
            _reseal(manifest)
        errors, _ = authority._validate_keyset(manifest, True)

        self.assertEqual([], errors)
        self.assertEqual(
            retained_signature,
            predecessor["proofOfPossession"]["signatureBase64"],
        )

    def test_transparency_signer_must_be_eligible_at_generation_time(self) -> None:
        cases = (
            ("staged", "uncompromised", "2026-08-20T00:00:00Z", "2028-08-20T00:00:00Z"),
            ("retired", "uncompromised", "2026-08-20T00:00:00Z", "2028-08-20T00:00:00Z"),
            ("revoked", "compromised", "2026-08-20T00:00:00Z", "2028-08-20T00:00:00Z"),
            ("active", "compromised", "2026-08-20T00:00:00Z", "2028-08-20T00:00:00Z"),
            ("active", "uncompromised", "2026-08-23T00:00:00Z", "2028-08-20T00:00:00Z"),
            ("active", "uncompromised", "2026-08-20T00:00:00Z", "2026-08-22T01:00:00Z"),
        )
        for lifecycle, compromise, valid_from, valid_until in cases:
            with self.subTest(
                lifecycle=lifecycle,
                compromise=compromise,
                valid_from=valid_from,
                valid_until=valid_until,
            ):
                manifest = _manifest()
                signer, _, _ = _key(
                    "offline-recovery", "stable-transparency-fixture-2"
                )
                signer["lifecycle"] = lifecycle
                signer["compromiseState"] = compromise
                signer["validFrom"] = valid_from
                signer["validUntil"] = valid_until
                manifest["keyset"]["keys"].append(signer)
                manifest["transparency"]["signingKeyId"] = signer["keyId"]
                _reseal(manifest)

                code, output = self.run_manifest(manifest)

                blockers = " ".join(
                    read_json(output / authority.AUTHORITY_SUMMARY_FILE)["blockers"]
                )
                self.assertEqual(1, code)
                self.assertIn(
                    "public key transparency signer is not eligible at generation time",
                    blockers,
                )

    def test_previous_transparency_signer_must_be_valid_at_generation_time(self) -> None:
        previous = _manifest()
        previous_recovery = previous["keyset"]["keys"][-1]
        previous_recovery["validUntil"] = "2026-08-22T01:00:00Z"
        _reseal(previous)
        write_json(
            self.root / authority.PREVIOUS_TRANSPARENCY_FILE,
            authority._transparency_artifact(previous),
        )
        (self.root / authority.PREVIOUS_TRANSPARENCY_SIGNATURE_FILE).write_bytes(
            base64.b64decode(
                previous["transparency"]["signatureBase64"], validate=True
            )
        )
        successor = copy.deepcopy(previous)
        successor["ceremony"]["ceremonyId"] = "stable-1.0-fixture-rotation"
        successor["ceremony"]["ceremonyType"] = "planned-rotation"
        successor["keyset"]["keysetVersion"] = 2
        successor["keyset"]["previousKeysetDigest"] = previous["keyset"][
            "keysetDigest"
        ]
        _reseal(successor)
        _, by_id = authority._validate_keyset(successor, True)

        errors = authority._previous_recovery_errors(self.root, successor, by_id)

        self.assertIn(
            "previous transparency artifact lacks an authorized recovery signer",
            errors,
        )

    def test_invalid_window_revoked_active_key_and_lineage_cycle_fail(self) -> None:
        cases = []
        invalid_window = _manifest()
        invalid_window["keyset"]["keys"][0]["validUntil"] = invalid_window["keyset"]["keys"][0]["validFrom"]
        cases.append(invalid_window)
        compromised_active = _manifest()
        compromised_active["keyset"]["keys"][0]["compromiseState"] = "compromised"
        cases.append(compromised_active)
        cycle = _manifest()
        first = cycle["keyset"]["keys"][0]
        second = copy.deepcopy(first)
        second["keyId"] = "stable-catalog-fixture-2"
        first["predecessorKeyId"] = second["keyId"]
        first["successorKeyId"] = second["keyId"]
        second["predecessorKeyId"] = first["keyId"]
        second["successorKeyId"] = first["keyId"]
        cycle["keyset"]["keys"].append(second)
        cases.append(cycle)
        for manifest in cases:
            with self.subTest():
                code, _ = self.run_manifest(manifest)
                self.assertEqual(1, code)

    def test_pr291_pr292_fixture_or_provider_substitution_fails(self) -> None:
        for field in ("independentReproducibilityOperational", "providerIndependent"):
            with self.subTest(field=field):
                manifest = _manifest()
                manifest["bindings"][field] = False
                code, _ = self.run_manifest(manifest)
                self.assertEqual(1, code)

    def test_checked_in_policy_must_match_every_enforced_closed_contract(self) -> None:
        policy_path = (
            self.workspace
            / "tools"
            / "release-certification"
            / authority.POLICY_FILE
        )
        policy = read_json(policy_path)
        substituted = copy.deepcopy(policy)
        substituted["publication"]["minimumIndependentMirrors"] = 0

        self.assertEqual([], authority._policy_contract_errors(policy))
        self.assertTrue(authority._policy_contract_errors(substituted))

    def test_publication_requires_exact_distinct_subjects_and_independent_mirror(self) -> None:
        cases = []
        duplicate = _manifest()
        duplicate["publication"]["mirrors"][0]["locationType"] = "network-mirror"
        duplicate["publication"]["mirrors"][0]["publicUri"] = duplicate["publication"]["networkPrimary"]["publicUri"]
        cases.append(duplicate)
        web_alias = _manifest()
        aliased_mirror = copy.deepcopy(web_alias["publication"]["mirrors"][0])
        aliased_mirror["locationId"] = "aliased-web-mirror"
        aliased_mirror["publicUri"] = (
            "https://MIRROR.EXAMPLE.TEST:443/stable/../stable/"
            "%63ryptad-app-catalog.properties"
        )
        web_alias["publication"]["mirrors"].append(aliased_mirror)
        cases.append(web_alias)
        non_collector_port = _manifest()
        non_collector_port["publication"]["mirrors"][0]["publicUri"] = (
            "https://mirror.example.test:8443/stable/cryptad-app-catalog.properties"
        )
        cases.append(non_collector_port)
        dependent = _manifest()
        for name in ("operatorId", "providerId", "controlPlaneId"):
            dependent["publication"]["mirrors"][0][name] = dependent["publication"]["networkPrimary"][name]
        cases.append(dependent)
        drift = _manifest()
        drift["publication"]["observations"][0]["signatureDigest"] = _digest("f")
        cases.append(drift)
        stale = _manifest()
        stale["publication"]["observations"][1]["status"] = "stale"
        cases.append(stale)
        for manifest in cases:
            with self.subTest():
                code, _ = self.run_manifest(manifest, "verify-publication")
                self.assertEqual(1, code)

    def test_publication_accepts_mirror_independence_on_any_declared_axis(self) -> None:
        for independent_axis in ("operatorId", "providerId", "controlPlaneId"):
            with self.subTest(independent_axis=independent_axis):
                manifest = _manifest()
                primary = manifest["publication"]["networkPrimary"]
                mirror = manifest["publication"]["mirrors"][0]
                for axis in ("operatorId", "providerId", "controlPlaneId"):
                    mirror[axis] = primary[axis]
                mirror[independent_axis] = f"independent-{independent_axis}"
                _reseal(manifest)

                code, _ = self.run_manifest(manifest, "verify-publication")

                self.assertEqual(0, code)

    def test_publication_rejects_mirror_without_an_independent_axis(self) -> None:
        manifest = _manifest()
        primary = manifest["publication"]["networkPrimary"]
        mirror = manifest["publication"]["mirrors"][0]
        for axis in ("operatorId", "providerId", "controlPlaneId"):
            mirror[axis] = primary[axis]
        _reseal(manifest)

        code, output = self.run_manifest(manifest, "verify-publication")

        blockers = read_json(output / authority.AUTHORITY_SUMMARY_FILE)["blockers"]
        self.assertEqual(1, code)
        self.assertIn(
            "at least one mirror must have an independent operator, provider, or control plane",
            blockers,
        )

    def test_transparency_schema_requires_authenticated_signing_key_identity(
        self,
    ) -> None:
        artifact = authority._transparency_artifact(_manifest())
        artifact.pop("transparencySigningKeyId")

        errors = validate_schema(artifact, authority.TRANSPARENCY_SCHEMA)

        self.assertTrue(
            any("transparencySigningKeyId" in error for error in errors), errors
        )

    def test_current_catalog_signer_must_be_active_at_transparency_effective_time(
        self,
    ) -> None:
        cases = []
        retiring = _manifest()
        retiring["keyset"]["keys"][0]["lifecycle"] = "retiring"
        cases.append(retiring)
        expired = _manifest()
        expired["keyset"]["keys"][0]["validUntil"] = expired["transparency"][
            "effectiveAt"
        ]
        cases.append(expired)
        for manifest in cases:
            with self.subTest():
                _reseal(manifest)

                code, output = self.run_manifest(manifest, "verify-publication")

                blockers = " ".join(
                    read_json(output / authority.AUTHORITY_SUMMARY_FILE)["blockers"]
                )
                self.assertEqual(1, code)
                self.assertIn(
                    "frozen catalog signer is not an active authorized catalog key",
                    blockers,
                )

    def test_retired_rollback_signer_must_be_valid_at_transparency_effective_time(
        self,
    ) -> None:
        manifest = _manifest()
        rollback_signer, _, _ = _key(
            "catalog-signing", "stable-catalog-fixture-rollback"
        )
        rollback_signer["lifecycle"] = "retired"
        rollback_signer["validFrom"] = "2025-08-20T00:00:00Z"
        rollback_signer["validUntil"] = manifest["transparency"]["effectiveAt"]
        manifest["keyset"]["keys"].append(rollback_signer)
        manifest["publication"]["rollback"]["signingKeyId"] = rollback_signer[
            "keyId"
        ]
        manifest["publication"]["rollback"][
            "signingKeyFingerprintSha256"
        ] = rollback_signer["publicKeyFingerprintSha256"]
        _reseal(manifest)

        code, output = self.run_manifest(manifest, "verify-publication")

        blockers = " ".join(
            read_json(output / authority.AUTHORITY_SUMMARY_FILE)["blockers"]
        )
        self.assertEqual(1, code)
        self.assertIn("rollback signer is unavailable", blockers)

    def test_retired_rollback_signer_is_eligible_during_support_window(self) -> None:
        manifest = _manifest()
        rollback_signer, _, _ = _key(
            "catalog-signing", "stable-catalog-fixture-rollback"
        )
        rollback_signer["lifecycle"] = "retired"
        manifest["keyset"]["keys"].append(rollback_signer)
        manifest["publication"]["rollback"]["signingKeyId"] = rollback_signer[
            "keyId"
        ]
        manifest["publication"]["rollback"][
            "signingKeyFingerprintSha256"
        ] = rollback_signer["publicKeyFingerprintSha256"]
        _reseal(manifest)
        _, by_id = authority._validate_keyset(manifest, True)

        errors = authority._validate_publication(manifest, by_id, True)

        self.assertEqual([], errors)

    def test_rollback_signer_must_remain_valid_at_authenticated_drill_time(
        self,
    ) -> None:
        manifest = _manifest()
        rollback_signer, _, _ = _key(
            "catalog-signing", "stable-catalog-fixture-rollback"
        )
        rollback_signer["lifecycle"] = "retired"
        rollback_signer["validUntil"] = "2026-08-24T00:00:00Z"
        manifest["keyset"]["keys"].append(rollback_signer)
        manifest["publication"]["rollback"]["signingKeyId"] = rollback_signer[
            "keyId"
        ]
        manifest["publication"]["rollback"][
            "signingKeyFingerprintSha256"
        ] = rollback_signer["publicKeyFingerprintSha256"]
        rollback_drill = next(
            row
            for row in manifest["drills"]
            if row["drillType"] == "catalog-rollback"
        )
        rollback_drill["completedAt"] = "2026-08-25T00:00:00Z"
        _reseal(manifest)

        code, output = self.run_manifest(manifest, "verify-rotation-drill")

        blockers = " ".join(
            read_json(output / authority.AUTHORITY_SUMMARY_FILE)["blockers"]
        )
        self.assertEqual(1, code)
        self.assertIn("rollback signer is unavailable, out of window", blockers)

    def test_catalog_signers_must_remain_valid_at_authenticated_observation_time(
        self,
    ) -> None:
        for signer_role in ("current", "rollback"):
            with self.subTest(signer_role=signer_role):
                manifest = _manifest()
                if signer_role == "current":
                    signer = manifest["keyset"]["keys"][0]
                else:
                    signer, _, _ = _key(
                        "catalog-signing", "stable-catalog-fixture-rollback"
                    )
                    signer["lifecycle"] = "retired"
                    manifest["keyset"]["keys"].append(signer)
                    manifest["publication"]["rollback"]["signingKeyId"] = signer[
                        "keyId"
                    ]
                    manifest["publication"]["rollback"][
                        "signingKeyFingerprintSha256"
                    ] = signer["publicKeyFingerprintSha256"]
                signer["validUntil"] = "2026-08-24T00:00:00Z"
                for observation in manifest["publication"]["observations"]:
                    observation["observedAt"] = "2026-08-25T00:00:00Z"
                _reseal(manifest)

                code, output = self.run_manifest(manifest, "verify-publication")

                blockers = " ".join(
                    read_json(output / authority.AUTHORITY_SUMMARY_FILE)["blockers"]
                )
                self.assertEqual(1, code)
                expected = (
                    "frozen catalog signer is not an active authorized catalog key"
                    if signer_role == "current"
                    else "rollback signer is unavailable, out of window"
                )
                self.assertIn(expected, blockers)

    def test_mirror_collection_must_finish_in_window_with_an_eligible_signer(self) -> None:
        manifest = _manifest()
        keys = manifest["keyset"]["keys"]
        rollback_signer, _, _ = _key(
            "catalog-signing", "stable-catalog-fixture-rollback-collection"
        )
        rollback_signer["lifecycle"] = "retired"
        rollback_signer["validUntil"] = "2026-08-22T02:03:00Z"
        keys.append(rollback_signer)
        rollback = manifest["publication"]["rollback"]
        rollback["signingKeyId"] = rollback_signer["keyId"]
        rollback["signingKeyFingerprintSha256"] = rollback_signer[
            "publicKeyFingerprintSha256"
        ]
        by_id = {key["keyId"]: key for key in keys}
        mirror = {
            "collectionStartedAt": "2026-08-22T02:01:00Z",
            "collectionCompletedAt": "2026-08-22T02:02:00Z",
        }

        valid = authority._mirror_collection_errors(manifest, mirror, by_id)
        delayed = copy.deepcopy(mirror)
        delayed["collectionCompletedAt"] = "2026-08-22T02:15:01Z"
        delayed_errors = authority._mirror_collection_errors(manifest, delayed, by_id)
        signer = by_id[manifest["catalog"]["signingKeyId"]]
        signer["validUntil"] = "2026-08-22T02:02:00Z"
        expired_errors = authority._mirror_collection_errors(manifest, mirror, by_id)
        signer["validUntil"] = "2028-08-20T00:00:00Z"
        rollback_signer["validUntil"] = mirror["collectionCompletedAt"]
        rollback_expired_errors = authority._mirror_collection_errors(
            manifest, mirror, by_id
        )

        self.assertEqual([], valid)
        self.assertIn("collection window", " ".join(delayed_errors))
        self.assertIn("catalog-signer lifecycle", " ".join(expired_errors))
        self.assertIn(
            "rollback-signer support window", " ".join(rollback_expired_errors)
        )

    def test_exact_catalog_and_detached_signature_bytes_are_verified(self) -> None:
        manifest = _manifest()
        catalog_bytes = b"catalog.id=crypta-stable-apps\ncatalog.entries=\n"
        seed, public_key = _fixture_keypair("stable-catalog-fixture-1")
        signature = base64.b64encode(
            _fixture_sign(seed, public_key, catalog_bytes)
        ).decode()
        signature_bytes = (
            "catalog.signature.version=1\n"
            "catalog.signature.algorithm=Ed25519\n"
            "catalog.signature.key.id=stable-catalog-fixture-1\n"
            "catalog.signature.payload=cryptad-app-catalog.properties\n"
            f"catalog.signature.value.base64={signature}\n"
        ).encode()
        manifest["catalog"]["catalogDigest"] = authority._file_digest(catalog_bytes)
        manifest["catalog"]["catalogSize"] = len(catalog_bytes)
        manifest["catalog"]["signatureDigest"] = authority._file_digest(signature_bytes)
        manifest["catalog"]["signatureSize"] = len(signature_bytes)
        key_errors, by_id = authority._validate_keyset(manifest, True)

        exact_errors = authority._catalog_sidecar_errors(
            catalog_bytes,
            signature_bytes,
            manifest,
            by_id,
        )
        drift_errors = authority._catalog_sidecar_errors(
            catalog_bytes + b"# drift\n",
            signature_bytes,
            manifest,
            by_id,
        )

        self.assertEqual([], key_errors)
        self.assertEqual([], exact_errors)
        self.assertTrue(drift_errors)

    def test_partial_publication_cannot_be_complete(self) -> None:
        manifest = _manifest()
        manifest["publication"]["observations"] = manifest["publication"]["observations"][:1]
        manifest["publication"]["requestedState"] = "partial"

        code, output = self.run_manifest(manifest, "verify-publication")

        receipt = read_json(output / authority.PUBLICATION_RECEIPT_FILE)
        self.assertEqual(1, code)
        self.assertEqual("partial", receipt["publicationState"])
        self.assertFalse(receipt["operational"])

    def test_post_queue_failure_result_produces_digest_bound_partial_receipt(
        self,
    ) -> None:
        manifest = _manifest()
        input_file = self.root / "post-queue-failure-manifest.json"
        output = self.root / "post-queue-failure-output"
        evidence = self.root / "post-queue-failure-evidence"
        live_result = self.root / "post-queue-failure-live-result.json"
        evidence.mkdir()
        write_json(input_file, manifest)
        public_catalog_source = manifest["publication"]["networkPrimary"]["publicUri"]
        write_json(
            live_result,
            {
                "schemaVersion": 1,
                "mode": "live",
                "catalogId": manifest["catalog"]["catalogId"],
                "catalogFile": "cryptad-app-catalog.properties",
                "catalogSignatureFile": "cryptad-app-catalog.signature",
                "publicCatalogSource": public_catalog_source,
                "publicSignatureSource": public_catalog_source.rsplit("/", 1)[0]
                + "/cryptad-app-catalog.signature",
                "resolvedCatalogSource": None,
                "edition": str(manifest["catalog"]["uskEdition"]),
                "catalogSha256": manifest["catalog"]["catalogDigest"].removeprefix(
                    "sha256:"
                ),
                "signatureSha256": manifest["catalog"][
                    "signatureDigest"
                ].removeprefix("sha256:"),
                "catalogSigningKeyId": manifest["catalog"]["signingKeyId"],
                "entryCount": 7,
                "catalogInsertStatus": "queued",
                "signatureInsertStatus": "queued",
                "postPublishVerificationStatus": "failed",
                "schedulerRefreshVerificationStatus": "not_run",
                "warnings": [
                    "post_publish_fetch_verification_failed",
                    "staging_sidecars_retained_until_live_insert_completion",
                ],
            },
        )

        code = authority.run(
            self.workspace,
            input_file,
            "prepare-publication",
            output,
            evidence_dir=evidence,
            live_publication_result=live_result,
        )

        receipt = read_json(output / authority.PUBLICATION_RECEIPT_FILE)
        redaction = read_json(output / authority.REDACTION_FILE)
        self.assertEqual(1, code)
        self.assertEqual("partial", receipt["publicationState"])
        self.assertFalse(receipt["operational"])
        self.assertEqual(
            authority._file_digest(live_result.read_bytes()),
            receipt["livePublicationResultDigest"],
        )
        self.assertIn(
            "live USK publication result does not bind the exact publication plan",
            receipt["blockers"],
        )
        self.assertEqual("pass", receipt["redaction"]["status"])
        self.assertEqual("pass", redaction["status"])
        self.assertEqual(0, redaction["findingCount"])

    def test_compromised_signer_cannot_authorize_current_or_rollback_catalog(self) -> None:
        manifest = _manifest()
        signer = manifest["keyset"]["keys"][0]
        signer["lifecycle"] = "revoked"
        signer["compromiseState"] = "compromised"

        code, output = self.run_manifest(manifest)

        blockers = " ".join(read_json(output / authority.AUTHORITY_SUMMARY_FILE)["blockers"])
        self.assertEqual(1, code)
        self.assertIn("rollback signer", blockers)

    def test_private_material_and_absolute_paths_fail_redaction(self) -> None:
        manifest = _manifest()
        manifest["publication"]["mirrors"][0]["publicUri"] = "https://mirror.example.test/-----BEGIN PRIVATE KEY-----"
        output = self.root / "redaction-rejected"
        input_file = self.root / "redaction-rejected.json"
        write_json(input_file, manifest)

        with self.assertRaisesRegex(ValueError, "failed redaction validation"):
            authority.run(self.workspace, input_file, "closeout", output)

        self.assertEqual([], list(output.iterdir()))

    def test_output_directory_symlink_is_rejected_before_writes(self) -> None:
        input_file = self.root / "symlink-output.json"
        write_json(input_file, _manifest())
        actual = self.root / "actual-output"
        actual.mkdir()
        alias = self.root / "output-alias"
        alias.symlink_to(actual, target_is_directory=True)

        with self.assertRaisesRegex(ValueError, "symbolic-link component"):
            authority.run(self.workspace, input_file, "closeout", alias)

        self.assertEqual([], list(actual.iterdir()))

    def test_output_directory_symlinked_ancestor_is_rejected_before_creation(
        self,
    ) -> None:
        input_file = self.root / "symlink-ancestor-output.json"
        write_json(input_file, _manifest())
        actual = self.root / "actual-parent"
        actual.mkdir()
        alias = self.root / "parent-alias"
        alias.symlink_to(actual, target_is_directory=True)

        with self.assertRaisesRegex(ValueError, "symbolic-link component"):
            authority.run(
                self.workspace,
                input_file,
                "closeout",
                alias / "nested-output",
            )

        self.assertFalse((actual / "nested-output").exists())

    def test_output_directory_outside_workspace_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as external:
            with self.assertRaisesRegex(ValueError, "remain inside the workspace"):
                authority._output_directory(
                    self.workspace,
                    Path(external) / "catalog-authority",
                )

    def test_bounded_live_publication_result_when_at_limit_expect_exact_bytes(
        self,
    ) -> None:
        result = self.root / "bounded-live-publication.json"
        expected = b"x" * authority.MAX_LIVE_PUBLICATION_RESULT_BYTES
        result.write_bytes(expected)

        actual = authority._bounded_regular_file_bytes(
            result,
            "live USK publication result",
            authority.MAX_LIVE_PUBLICATION_RESULT_BYTES,
        )

        self.assertEqual(expected, actual)

    def test_bounded_live_publication_result_when_file_is_unsafe_expect_rejected(
        self,
    ) -> None:
        oversized = self.root / "oversized-live-publication.json"
        oversized.write_bytes(
            b"x" * (authority.MAX_LIVE_PUBLICATION_RESULT_BYTES + 1)
        )
        empty = self.root / "empty-live-publication.json"
        empty.touch()
        original = self.root / "original-live-publication.json"
        original.write_text("{}", encoding="utf-8")
        hard_link = self.root / "hard-linked-live-publication.json"
        hard_link.hardlink_to(original)
        symbolic_link = self.root / "symlinked-live-publication.json"
        symbolic_link.symlink_to(original)

        for candidate in (oversized, empty, hard_link, symbolic_link):
            with self.subTest(candidate=candidate.name):
                with self.assertRaisesRegex(
                    ValueError, "missing or unsafe|outside its byte bound or unsafe"
                ):
                    authority._bounded_regular_file_bytes(
                        candidate,
                        "live USK publication result",
                        authority.MAX_LIVE_PUBLICATION_RESULT_BYTES,
                    )

    def test_explicit_live_publication_result_when_oversized_expect_bounded_blocker(
        self,
    ) -> None:
        evidence = self.root / "oversized-live-evidence"
        evidence.mkdir()
        oversized = self.root / "explicit-oversized-live-publication.json"
        oversized.write_bytes(
            b"x" * (authority.MAX_LIVE_PUBLICATION_RESULT_BYTES + 1)
        )
        manifest = _manifest()
        by_id = {key["keyId"]: key for key in manifest["keyset"]["keys"]}

        errors, live_digest, _ = authority._validate_bound_evidence(
            manifest,
            "prepare-ceremony",
            evidence,
            oversized,
            by_id,
        )

        self.assertIsNone(live_digest)
        self.assertIn(
            "live USK publication result is outside its byte bound or unsafe",
            errors,
        )

    def test_generated_redaction_finding_aborts_every_mode_before_writes(self) -> None:
        for mode in authority.MODES:
            with self.subTest(mode=mode):
                output = self.root / f"generated-redaction-{mode}"
                input_file = self.root / f"generated-redaction-{mode}.json"
                write_json(input_file, _manifest())

                with mock.patch.object(
                    authority,
                    "_report",
                    return_value="-----BEGIN PRIVATE KEY-----",
                ), self.assertRaisesRegex(ValueError, "failed redaction validation"):
                    authority.run(self.workspace, input_file, mode, output)

                self.assertEqual([], list(output.iterdir()))

    def test_nonempty_output_directory_fails_before_generation(self) -> None:
        output = self.root / "nonempty-output"
        output.mkdir()
        marker = output / "stale-summary.json"
        marker.write_text("stale", encoding="utf-8")
        input_file = self.root / "nonempty-output.json"
        write_json(input_file, _manifest())

        with self.assertRaisesRegex(ValueError, "must be empty"):
            authority.run(self.workspace, input_file, "closeout", output)

        self.assertEqual("stale", marker.read_text(encoding="utf-8"))

    def test_private_insert_key_disguised_with_public_scheme_fails(self) -> None:
        private_insert = (
            f"crypta:USK@{'A' * 43},{'B' * 43},AQECAAE/stable/9/"
            "cryptad-app-catalog.properties"
        )
        manifest = _manifest()
        manifest["publication"]["networkPrimary"]["publicUri"] = private_insert

        key_errors, by_id = authority._validate_keyset(manifest, True)

        self.assertEqual([], key_errors)
        self.assertTrue(authority._validate_publication(manifest, by_id, False))

    def test_public_key_bytes_exist_only_in_dedicated_artifacts(self) -> None:
        _, output = self.run_manifest(_manifest())
        ordinary = [
            authority.CEREMONY_SUMMARY_FILE,
            authority.CEREMONY_RECEIPT_FILE,
            authority.PUBLICATION_PLAN_FILE,
            authority.PUBLICATION_RECEIPT_FILE,
            authority.ROTATION_DRILL_FILE,
            authority.AUTHORITY_SUMMARY_FILE,
            authority.AUTHORITY_REPORT_FILE,
            authority.REDACTION_FILE,
        ]
        for filename in ordinary:
            self.assertNotIn("publicKeySpkiBase64", (output / filename).read_text(), filename)
        self.assertIn("publicKeySpkiBase64", (output / authority.TRANSPARENCY_FILE).read_text())

    def test_strict_json_loader_rejects_duplicate_fields(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate field"):
            read_json_bytes(b'{"kind":"one","kind":"two"}', "duplicate fixture")

    def test_cli_exposes_one_closed_catalog_authority_command(self) -> None:
        parsed = build_parser().parse_args(
            [
                "stable-catalog-authority",
                "--mode",
                "verify-ceremony",
                "--authority-manifest",
                "authority.json",
            ]
        )

        self.assertEqual("stable-catalog-authority", parsed.command)
        self.assertEqual("verify-ceremony", parsed.mode)
        self.assertEqual(Path("authority.json"), parsed.authority_manifest)

    def test_execution_and_output_schemas_are_closed(self) -> None:
        manifest = _manifest()
        artifact = authority._transparency_artifact(manifest)
        plan = authority._publication_plan(manifest, _digest("a"))
        receipt = authority._publication_receipt(manifest, plan, [])
        mirror_receipt = {
            "kind": "stable-1.0-catalog-mirror-observation",
            "releaseId": manifest["release"]["releaseId"],
            "buildVersion": manifest["release"]["buildVersion"],
            "sourceCommit": manifest["release"]["sourceCommit"],
            "catalogSubject": authority._catalog_subject(manifest["catalog"]),
            "collectionStartedAt": "2026-08-22T02:01:00Z",
            "collectionCompletedAt": "2026-08-22T02:02:00Z",
            "observations": manifest["publication"]["observations"],
            "schedulerRefreshVerificationStatus": "pass",
            "status": "pass",
            "receiptDigest": _digest("b"),
        }

        self.assertEqual([], validate_schema(manifest, authority.EXECUTION_SCHEMA))
        self.assertEqual([], validate_schema(artifact, authority.TRANSPARENCY_SCHEMA))
        self.assertEqual([], validate_schema(plan, authority.PUBLICATION_PLAN_SCHEMA))
        self.assertEqual([], validate_schema(receipt, authority.PUBLICATION_RECEIPT_SCHEMA))
        self.assertEqual(
            [], validate_schema(mirror_receipt, authority.MIRROR_OBSERVATION_SCHEMA)
        )
        artifact["unexpected"] = True
        self.assertTrue(validate_schema(artifact, authority.TRANSPARENCY_SCHEMA))
        plan["unexpected"] = True
        receipt["unexpected"] = True
        mirror_receipt["unexpected"] = True
        self.assertTrue(validate_schema(plan, authority.PUBLICATION_PLAN_SCHEMA))
        self.assertTrue(validate_schema(receipt, authority.PUBLICATION_RECEIPT_SCHEMA))
        self.assertTrue(
            validate_schema(mirror_receipt, authority.MIRROR_OBSERVATION_SCHEMA)
        )


if __name__ == "__main__":
    unittest.main()

"""Admission ordering/lifetime regressions; crypto/native execution has a separate lane."""
from contextlib import contextmanager
import json
import io
import hashlib
import zipfile
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import cross_version_product_admission as products
import maintenance_runtime_companion as companion
import maintenance_runtime_metadata as metadata


class EncryptedProductAdmissionTests(unittest.TestCase):
    def test_private_canaries_stay_private_and_closed_capability_is_unusable(self):
        closed = []
        row = {"role": "previous", "artifactDigest": "sha256:" + "a" * 64,
               "sealedRuntimeBinding": {"ciphertextDigest": "sha256:" + "b" * 64},
               "appMatrix": [{"appId": "PRIVATE-APP-CANARY"}],
               "runtimeBinding": {"metadataDigest": "PRIVATE-HASH-CANARY"},
               "requiredAppIds": ["PRIVATE-APP-CANARY"],
               "futurePrivateField": "PRIVATE-FUTURE-CANARY",
               "_runtimeContext": SimpleNamespace(close=lambda: closed.append(True))}
        authority = products.AuthenticatedProducts(products._SEAL, "plan", {"previous": row})
        self.assertIn("PRIVATE-APP-CANARY", json.dumps(authority.private_identities()))
        self.assertNotIn("PRIVATE", json.dumps(authority.public_identities()))
        authority.close()
        authority.close()
        self.assertEqual([True], closed)
        for method in (authority.public_identities, authority.private_identities, authority.package_paths):
            with self.assertRaisesRegex(products.ProductAdmissionError, "context-closed"):
                method()

    def test_serialized_success_cannot_construct_capability(self):
        with self.assertRaisesRegex(products.ProductAdmissionError, "not-produced"):
            products.AuthenticatedProducts({"authenticated": True}, "plan", {})

    def test_pure_v3_consumer_validates_exact_sealed_roster_without_opening(self):
        from cryptad_certification.tests.test_cross_version_product_admission import CrossVersionProductAdmissionTest, archive
        original, node, _ = CrossVersionProductAdmissionTest().maintenance_fixture()
        with zipfile.ZipFile(io.BytesIO(original.content)) as source:
            files = {name: source.read(name) for name in source.namelist()}
        name = "freeze/" + products.maintenance.CANDIDATE_FREEZE_FILE
        freeze = json.loads(files[name])
        ciphertext = b"opaque ciphertext; no local decryption performed by this test"
        descriptor = {"schemaVersion": 1, "kind": "maintenance-runtime-companion",
                      "mode": "selected-federation", "purpose": companion.PURPOSE,
                      "recipientPolicy": companion.POLICY_ID, "recipientEpoch": 1,
                      "ciphertext": companion._identity(companion.CIPHERTEXT, ciphertext)}
        raw = json.dumps(descriptor).encode()
        freeze["predecessorObservation"]["sourceCommit"] = "a" * 40
        freeze.update(schemaVersion=3, runtimeMetadata=companion._identity(companion.DESCRIPTOR, raw))
        files[name] = json.dumps(freeze).encode()
        files["freeze/runtime/" + companion.DESCRIPTOR] = raw
        files["freeze/runtime/" + companion.CIPHERTEXT] = ciphertext
        freeze_digest = "sha256:" + hashlib.sha256(files[name]).hexdigest()
        with tempfile.TemporaryDirectory() as temporary, patch.object(companion, "open_companion") as opening:
            root = Path(temporary).resolve()
            original.content = archive(files)
            row = products.verify_maintenance_artifact(original, node, freeze_digest, root / "selected")
            self.assertNotIn("runtimeBinding", row)
            self.assertIn("sealedRuntimeBinding", row)
            opening.assert_not_called()
            files["freeze/runtime/projection-inventory.json"] = b"PRIVATE"
            original.content = archive(files)
            with self.assertRaisesRegex(products.ProductAdmissionError, "unbound-member"):
                products.verify_maintenance_artifact(original, node, freeze_digest, root / "extra")

    def run_admission(self, *, bad_attestation=False, native_failure=False):
        order = []
        coordinates = {"sourceFamily": "stable-maintenance-freeze", "sourceCommit": "b" * 40,
                       "runId": 7, "runAttempt": 2}
        original = SimpleNamespace(coordinates=coordinates)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            def verify(_original, _node, _digest, selected):
                selected.mkdir(mode=0o700)
                transfer = selected / "runtime"
                transfer.mkdir(mode=0o700)
                for name in (products.maintenance.CANDIDATE_FREEZE_FILE, "checksums.txt", "package.tar.gz"):
                    (selected / name).write_bytes(b"public")
                for name in ("runtime-companion.json", "runtime-companion.cms"):
                    (transfer / name).write_bytes(b"sealed")
                return {"path": selected / "package.tar.gz", "transferRoot": transfer,
                        "_freeze": {}, "sealedRuntimeBinding": {"ciphertextDigest": "sealed"}}
            def attest(args, _env):
                order.append(Path(args[2]).name)
                return [] if bad_attestation else [{"verificationResult": {"signature": {"certificate": {
                    "runInvocationURI": "https://github.com/crypta-network/cryptad/actions/runs/7/attempts/2"}}}}]
            @contextmanager
            def opening(_freeze, _transfer, parent):
                order.append("decrypt")
                with tempfile.TemporaryDirectory(dir=parent) as temporary_private:
                    private = Path(temporary_private)
                    (private / "runtime-subjects.json").write_bytes(b"PRIVATE-MANIFEST")
                    try:
                        yield private
                    finally:
                        order.append("closed")
            def native(*_args):
                order.append("native")
                if native_failure:
                    raise ValueError("synthetic failure")
                return {key: "private" for key in ("contractSnapshotDigest", "contractSemanticDigest",
                    "baselineRegistryDigest", "shippedCohortDigest", "experimentCohortDigest", "provenance", "contractVersion")}
            with patch.object(products, "authenticate_original", return_value=original), \
                    patch.object(products, "verify_maintenance_artifact", side_effect=verify), \
                    patch.object(products, "_gh", side_effect=attest), \
                    patch.object(products, "_environment", return_value={}), \
                    patch.object(companion, "open_companion", side_effect=opening), \
                    patch.object(metadata, "verify_private_runtime", side_effect=native, create=True), \
                    patch.object(products, "_bind_runtime_roster"):
                selection = {"coordinates": coordinates, "freezeDigest": "sha256:" + "c" * 64}
                if bad_attestation or native_failure:
                    with self.assertRaises(products.ProductAdmissionError):
                        products.authenticate_maintenance_product(selection, {}, root / "original")
                else:
                    row = products.authenticate_maintenance_product(selection, {}, root / "original")
                    self.assertTrue(row["runtimeRoot"].is_dir())
                    products.close_runtime_context(row)
                    self.assertFalse(row["runtimeRoot"].exists())
        return order

    def test_all_outer_attestations_precede_decrypt_and_no_plaintext_is_attested(self):
        order = self.run_admission()
        self.assertEqual([products.maintenance.CANDIDATE_FREEZE_FILE, "checksums.txt", "package.tar.gz",
                          "runtime-companion.json", "runtime-companion.cms", "decrypt", "native", "closed"], order)

    def test_failed_original_member_attestation_never_decrypts(self):
        order = self.run_admission(bad_attestation=True)
        self.assertNotIn("decrypt", order)

    def test_native_failure_closes_private_opening(self):
        self.assertEqual(["decrypt", "native", "closed"], self.run_admission(native_failure=True)[-3:])

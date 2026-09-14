"""Prospective encrypted evidence stays offline until an explicit owner collects originals."""
import copy
import datetime as dt
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from cryptad_certification import phase_12_runtime_adapters as runtime
from cryptad_certification.tests import test_cross_version_product_admission as product_fixtures
from cryptad_certification.tests.test_phase_12_runtime_adapters import AS_OF


class EncryptedPhase12Tests(unittest.TestCase):
    # macOS exposes its temporary root through /var -> /private/var. Resolve only fixture-owned
    # paths before passing them to the owner, whose rejection of symlinked scratch is intentional.
    def product(self):
        owner = runtime._protected("cross_version_product_admission")
        import maintenance_runtime_companion as companion
        original, node, _ = product_fixtures.CrossVersionProductAdmissionTest().maintenance_fixture()
        with zipfile.ZipFile(io.BytesIO(original.content)) as source:
            files = {name: source.read(name) for name in source.namelist()}
        name = "freeze/" + owner.maintenance.CANDIDATE_FREEZE_FILE
        freeze = json.loads(files[name])
        descriptor = {"schemaVersion": 1, "kind": "maintenance-runtime-companion", "mode": "selected-federation",
                      "purpose": companion.PURPOSE, "recipientPolicy": companion.POLICY_ID, "recipientEpoch": 1,
                      "ciphertext": companion._identity(companion.CIPHERTEXT, b"opaque")}
        raw = json.dumps(descriptor).encode()
        freeze.update(schemaVersion=3, runtimeMetadata=companion._identity(companion.DESCRIPTOR, raw))
        freeze["predecessorObservation"]["sourceCommit"] = "a" * 40
        files[name] = json.dumps(freeze).encode()
        files["freeze/runtime/" + companion.DESCRIPTOR] = raw
        files["freeze/runtime/" + companion.CIPHERTEXT] = b"opaque"
        payload = product_fixtures.archive(files)
        from original_artifact_authentication import PRODUCERS
        coordinates = {**original.coordinates, "repository": "crypta-network/cryptad", "jobId": 1,
                       "jobName": PRODUCERS["stable-maintenance-freeze"][2], "artifactId": 1,
                       "artifactDigest": "sha256:" + hashlib.sha256(payload).hexdigest(), "artifactSize": len(payload)}
        selection = {"original": coordinates, "node": node,
                     "freezeDigest": "sha256:" + hashlib.sha256(files[name]).hexdigest()}
        return {"selection.json": json.dumps(selection).encode(), "product.zip": payload}

    def test_local_sealed_product_never_opens_or_collects_originals(self):
        inputs = self.product()
        owner = runtime._protected("cross_version_product_admission")
        import maintenance_runtime_companion as companion
        with tempfile.TemporaryDirectory() as temporary, patch.object(owner, "authenticate_original") as collect, \
                patch.object(companion, "open_companion") as opening:
            result = runtime.verify("product-admission", inputs, AS_OF, Path(temporary).resolve())
        self.assertIn("product-encrypted-private-original-context-required", result["blockers"])
        self.assertIn("sealedRuntimeBinding", result)
        self.assertNotIn("runtimeBinding", result)
        self.assertEqual("unverified", result["dimensions"]["originalProvenance"])
        collect.assert_not_called()
        opening.assert_not_called()

    def test_explicit_product_collection_closes_private_context_and_projects_only_sealed_identity(self):
        inputs = self.product()
        owner = runtime._protected("cross_version_product_admission")
        selection = json.loads(inputs["selection.json"])
        proof = {"coordinates": selection["original"], "members": runtime.ORIGINAL_MEMBERS["product-admission"]}
        closed = []
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary).resolve()
            local = runtime.verify("product-admission", inputs, AS_OF, scratch)
            row = {"sourceCommit": selection["node"]["sourceCommit"], "buildVersion": "301",
                   "artifactDigest": selection["node"]["artifactDigest"],
                   "sealedRuntimeBinding": local["sealedRuntimeBinding"],
                   "runtimeBinding": {"metadataDigest": "PRIVATE-DIGEST-CANARY"},
                   "_runtimeContext": SimpleNamespace(close=lambda: closed.append(True))}
            with patch.object(owner, "authenticate_maintenance_product", return_value=row) as collect:
                result = runtime.collect_and_verify("product-admission", inputs, AS_OF, scratch, proof)
        collect.assert_called_once()
        self.assertEqual([True], closed)
        self.assertNotIn("product-encrypted-private-original-context-required", result["blockers"])
        self.assertIn("frozen-api-app-cohort", result["coverage"]["observed"])
        self.assertNotIn("PRIVATE-DIGEST-CANARY", json.dumps(result))

    def test_predecessor_relation_is_rederived_and_actual_product_substitution_rejected(self):
        owner = runtime._protected("cross_version_product_admission")
        previous = {"releaseId": "previous", "buildVersion": "301", "artifactDigest": "sha256:" + "a" * 64,
                    "sourceCommit": "b" * 40, "predecessorReleaseBinding": {"forged": True}}
        observation = {"releaseId": "previous", "buildVersion": "301", "productDigest": previous["artifactDigest"],
                       "sourceCommit": previous["sourceCommit"], "baselineDigest": "sha256:" + "c" * 64,
                       "publicationReceiptDigest": "sha256:" + "d" * 64,
                       "latestPublishedPointerDigest": "sha256:" + "e" * 64, "observedAt": AS_OF}
        candidate = {"buildVersion": "302", "artifactDigest": "sha256:" + "f" * 64,
                     "maintenanceFreezeDigest": "sha256:" + "1" * 64, "predecessorObservation": observation}
        owner.bind_predecessor(candidate, previous)
        self.assertNotIn("forged", previous["predecessorReleaseBinding"])
        self.assertEqual(candidate["maintenanceFreezeDigest"], previous["predecessorReleaseBinding"]["candidateFreezeDigest"])
        with self.assertRaisesRegex(owner.ProductAdmissionError, "actual-predecessor-mismatch"):
            owner.bind_predecessor(candidate, {**previous, "sourceCommit": "0" * 40})

    def fixture(self):
        from test_maintenance_runtime_projection import MaintenanceRuntimeProjectionTest
        owner = runtime._protected("cross_version_product_admission")
        projection = runtime._protected("maintenance_runtime_projection")
        plan, events, checkpoint, rows = MaintenanceRuntimeProjectionTest().runtime_fixture()
        for row in rows:
            row["sealedRuntimeBinding"] = {"descriptor": {"fileName": "runtime-companion.json",
                "digest": "sha256:" + "a" * 64, "sizeBytes": 100}, "ciphertextDigest": "sha256:" + "b" * 64}
        public = [owner.public_product_identity(row) for row in rows]
        now = dt.datetime(2026, 1, 1, 0, 10, tzinfo=dt.timezone.utc)
        measured = projection.project(plan, events, checkpoint, rows, public_products=public, now=now)
        payloads = {key: json.dumps(value).encode() for key, value in
                    (("plan.json", plan), ("events.json", events), ("checkpoint.json", checkpoint), ("products.json", public))}
        final = {"schemaVersion": 5, "maintenanceMeasurements": measured, "admittedProductsDigest": runtime.soak.digest(public)}
        observation = runtime.soak.verify(plan, events, checkpoint, now=now)
        return owner, plan, rows, payloads, final, observation, now.isoformat()

    def test_sealed_supervisor_authorization_commits_same_safe_products_and_rejects_downgrade(self):
        from cryptad_certification.tests.test_phase_12_runtime_adapters import supervisor_fixture
        _owner, plan, _rows, payloads, projected, _observation, cutoff = self.fixture()
        values = {name: json.loads(raw) for name, raw in payloads.items()}
        now = dt.datetime.fromisoformat(cutoff)
        chain = supervisor_fixture(plan, values["events.json"], values["checkpoint.json"])
        final, start, authorize = (row["report"] for row in chain)
        for report in (final, start, authorize):
            report.update(schemaVersion=5, admittedProductsDigest=projected["admittedProductsDigest"])
        final["maintenanceMeasurements"] = projected["maintenanceMeasurements"]
        final["observation"] = runtime.soak.verify(plan, values["events.json"], values["checkpoint.json"], now=now)
        def rebind(rows):
            finish, began, approval = (row["report"] for row in rows)
            for report in (finish, began):
                report["approvalReportDigest"] = runtime.soak.digest(approval)
            began["previousReportDigest"] = runtime.soak.digest(approval)
            finish["previousReportDigest"] = runtime.soak.digest(began)
        rebind(chain)
        authority = runtime._AuthenticatedSupervisor(chain, runtime._ORIGINAL_SUPERVISOR)
        self.assertEqual(final, runtime._supervisor_relationships(authority, values, now)[0])
        for mutation in ("digest", "downgrade"):
            changed = copy.deepcopy(chain)
            approval = changed[-1]["report"]
            if mutation == "digest":
                approval["admittedProductsDigest"] = "sha256:" + "f" * 64
            else:
                approval["schemaVersion"] = 1
                approval.pop("admittedProductsDigest")
            rebind(changed)
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "authorized-products-substituted"):
                runtime._supervisor_relationships(
                    runtime._AuthenticatedSupervisor(changed, runtime._ORIGINAL_SUPERVISOR), values, now)

    def test_authenticated_supervisor_alone_cannot_recreate_private_native_context(self):
        owner, plan, rows, payloads, final, observation, cutoff = self.fixture()
        authority = runtime._AuthenticatedSupervisor([], runtime._ORIGINAL_SUPERVISOR)
        with tempfile.TemporaryDirectory() as temporary, patch.object(runtime, "_supervisor_relationships", return_value=(final, observation)), \
                patch.object(owner, "authenticate_maintenance_product") as collect:
            result = runtime.verify_authenticated("maintenance-measurements", payloads, cutoff, Path(temporary).resolve(), authority)
        self.assertIn("maintenance-encrypted-private-original-context-required", result["blockers"])
        collect.assert_not_called()

    def test_private_owner_capability_recomputes_native_relations_without_network(self):
        owner, plan, rows, payloads, final, observation, cutoff = self.fixture()
        # This fixture authority proves API separation only; no operational provenance is issued.
        capability = owner.AuthenticatedProducts(owner._SEAL, runtime.soak.digest(plan), {row["role"]: row for row in rows})
        authority = runtime._AuthenticatedSupervisor([], runtime._ORIGINAL_SUPERVISOR, private_products=capability)
        # Match the established role-sorted public identity convention.
        payloads["products.json"] = json.dumps(capability.public_identities()).encode()
        projection = runtime._protected("maintenance_runtime_projection")
        values = {name: json.loads(raw) for name, raw in payloads.items()}
        final["maintenanceMeasurements"] = projection.project(plan, values["events.json"], values["checkpoint.json"],
            capability.private_identities(), public_products=values["products.json"], now=dt.datetime.fromisoformat(cutoff))
        final["admittedProductsDigest"] = runtime.soak.digest(values["products.json"])
        with tempfile.TemporaryDirectory() as temporary, patch.object(runtime, "_supervisor_relationships", return_value=(final, observation)), \
                patch.object(owner, "authenticate_maintenance_product") as collect:
            result = runtime.verify_authenticated("maintenance-measurements", payloads, cutoff, Path(temporary).resolve(), authority)
        self.assertEqual("pass", result["components"]["subjectAdmission"])
        self.assertIn("maintenance-required-consumer-adapters-incomplete", result["blockers"])
        self.assertNotIn("runtimeBinding", json.dumps(result))
        collect.assert_not_called()
        capability.close()
        with self.assertRaises(ValueError):
            authority.private_products()

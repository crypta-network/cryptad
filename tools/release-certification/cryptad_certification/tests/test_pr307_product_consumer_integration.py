"""Real native selected-federation producer/CMS/admission with synthetic original transports.

Selection transport and provider authority are test seams; maintenance CMS, signed native
subjects, exact package export and private consumer revalidation execute real implementations.
"""
import io
import datetime as dt
import zipfile
import hashlib
import copy
import json
import os
from pathlib import Path
import subprocess
import shutil
import unittest
from unittest.mock import patch

from cryptad_certification.tests import test_pr304_product_consumer_integration as legacy
import federation_selection as selection
import test_pr305_native_projection as fixtures


class EncryptedProductConsumerIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (legacy.ROOT / "build/cryptad-dist/lib/cryptad.jar").is_file():
            raise AssertionError("PR307 native lane requires assembleCryptadDist")
        try:
            legacy.ProductConsumerIntegrationTest.setUpClass()
        except unittest.SkipTest:
            raise AssertionError("PR307 native lane prerequisites unavailable") from None
        except Exception:
            raise AssertionError("pr307-product-integration-prerequisite-failed") from None
        cls.addClassCleanup(legacy.ProductConsumerIntegrationTest.tearDownClass)

    def test_real_native_producer_cms_handoff_and_private_product_consumer(self):
        self._stage = "setup"
        harness = legacy.ProductConsumerIntegrationTest(methodName="runTest")
        try:
            harness.setUp()
            self.addCleanup(harness.tearDown)
            self._execute(harness)
        except Exception as error:
            locations = []
            for _ in range(8):
                trace = error.__traceback__
                while trace.tb_next is not None:
                    trace = trace.tb_next
                locations.append(type(error).__name__ + ":" + Path(trace.tb_frame.f_code.co_filename).name
                                 + ":" + str(trace.tb_lineno))
                error = error.__cause__ or error.__context__
                if error is None:
                    break
            raise AssertionError("pr307-product-consumer-integration-failed:" + self._stage + ":"
                                 + ",".join(locations)) from None

    def _execute(self, h):
        self._stage = "fixture-preparation"
        distribution = h.work / "packaged-daemon"
        shutil.copytree(legacy.ROOT / "build/cryptad-dist", distribution, symlinks=True)
        # The prospective package embeds the exact executable later launched by the dedicated
        # catalog role, not the API-only stand-in used by the older compatibility fixture.
        h.api_jars = [distribution / "lib/cryptad.jar"]
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=legacy.ROOT, check=True,
                                capture_output=True, text=True).stdout.strip()
        fixture = h.work / "federated-fixture"
        classes = h.work / "fixture-classes"
        classes.mkdir()
        cp = str(h.tool / "lib/*")
        subprocess.run([str(h.java / "bin/javac"), "-cp", cp, "-d", str(classes), str(
            legacy.ROOT / "platform-appcatalog/src/test/java/network/crypta/platform/appcatalog/Pr305SignedCatalogFixture.java")],
            check=True, capture_output=True, timeout=60)
        subprocess.run([str(h.java / "bin/java"), "-cp", str(classes) + os.pathsep + cp,
            "network.crypta.platform.appcatalog.Pr305SignedCatalogFixture", str(fixture)],
            check=True, capture_output=True, timeout=60)
        exported = subprocess.run([str(h.java / "bin/java"), "-cp", cp,
            "network.crypta.platform.api.PackagedApiExport"], check=True, capture_output=True, timeout=60)
        contract = json.loads(exported.stdout)
        snapshot, registry = h.work / "contract.json", h.work / "registry.json"
        snapshot.write_text(contract["contractSnapshot"])
        registry.write_text(contract["baselineRegistry"])

        class Transport:
            def add(self, family, files):
                return h.artifact(family, files)

        self._stage = "original-selection"
        source, upstream, authority, evidence = fixtures._source_artifacts(fixture, Transport())
        policy = fixtures._selection_policy(fixture, source)
        for member in policy["members"]:
            if member["original"] is None:
                Path(member["path"]).chmod(0o600)
        policy_path = h.work / "selection-policy.json"
        policy_path.write_bytes(fixtures._json(policy))
        policy_path.chmod(0o600)
        envelopes = {}

        def cms(raw, _root, *, decrypt=False):
            if decrypt:
                if raw not in envelopes:
                    raise selection.SelectionFailure("synthetic-envelope-substituted")
                return envelopes[raw]
            encrypted = b"synthetic-cms:" + hashlib.sha256(raw).digest()
            envelopes[encrypted] = raw
            return encrypted

        for name, value in (("authenticate_original", h.fetch), ("POLICY", policy_path),
                            ("Path", fixtures._SyntheticRootOwnedPath), ("_cms", cms),
                            ("_gh", legacy.projection._gh), ("_environment", lambda: {})):
            h.stack.enter_context(patch.object(selection, name, value))
        with patch.dict(os.environ, {"GITHUB_WORKFLOW_REF": selection.REPOSITORY + "/" + selection.WORKFLOW + "@refs/heads/develop"}):
            selection.produce_selection(h.work, h.work / "selection.cms")
        selection_original = h.artifact("federation-selection", {selection.MEMBER: (h.work / "selection.cms").read_bytes()})
        authenticated = selection.authenticate_selection(selection_original, h.work)
        # Freeze only the ordinary cohort that the maintenance publication format supports.
        self._stage = "ordinary-maintenance-product"
        base_inputs = h.cohort("stable-1.0-maintenance-302", commit)
        with patch.object(h, "cohort", return_value=base_inputs):
            freeze, package, _legacy_inventory, selected = h.freeze(302, commit)

        def cohort():
            base_value, path, _inventory, _origin, product_root = base_inputs
            value = copy.deepcopy(base_value)
            members = {"catalog": "A1/catalog.properties", "catalogSignature": "A1/cryptad-app-catalog.signature",
                       "bundle": "A1/bundle.zip", "submission": "A1/submission.zip"}
            row = {"appId": "pr305-fixture", "original": source, "originalInventory": upstream,
                   "catalogOriginal": None, "members": members, "catalogKeyId": "catalog-a",
                   "sourceAuthorityRoot": authority, "sourceEvidenceDigest": evidence, "requiredForRelease": True}
            for field, filename in (("catalogKeys", "catalog-keys.properties"),
                                    ("publisherKeys", "publisher-keys.properties"), ("reviewerKeys", "reviewer-keys.properties")):
                row[field] = str(fixture / filename)
                row[field + "Digest"] = legacy.products.file_digest(fixture / filename)
            # This prospective cohort selects the reviewed synthetic federation pilot as its
            # external member. The historical cohort and its original projection stay intact.
            value["sources"] = [member for member in value["sources"]
                                if member["original"]["sourceFamily"] != "third-party-pilot"] + [row]
            value["authorityRoots"]["thirdPartyPilot"] = authority
            value["schemaVersion"] = 2
            value["federationSelections"] = [{"appId": "pr305-fixture", "original": selection_original,
                "contextId": "a1", "contextDigest": authenticated.context("a1")["digest"], "generation": 7}]
            value["admissionContract"] = {"snapshotPath": str(snapshot), "registryPath": str(registry),
                "snapshotDigest": legacy.products.file_digest(snapshot), "registryDigest": legacy.products.file_digest(registry)}
            path.chmod(0o600)
            path.write_bytes(fixtures._json(value))
            output = h.work / "selected-v4.json"
            with patch.object(legacy.projection, "COHORT_FILE", path):
                inventory = legacy.projection.produce_cohort(h.work, output)
            origin = h.artifact("app-subject-projection", {"platform-api-1.x-app-subject-inventory.cms": cms(output.read_bytes(), h.work)})
            original = legacy.projection.authenticate_inventory(origin, h.work,
                expected_cohort_digest=inventory["cohortDigest"], expected_inventory_version=4)
            self.assertTrue(original.matches(inventory))
            return value, path, inventory, origin, product_root

        self._stage = "private-projection"
        _cohort, policy_path, inventory, projection_origin, _products = cohort()
        from test_maintenance_runtime_companion import CompanionTransportTest
        import maintenance_runtime_companion as companion
        from maintenance_runtime_transfer import copy_runtime
        crypto = CompanionTransportTest("test_real_randomized_roundtrip_and_owned_cleanup")
        crypto.setUp()
        self.addCleanup(crypto.doCleanups)
        # The new preparation is current; historical fixture freezes retain their own clocks.
        h.stack.enter_context(patch.object(legacy.metadata, "datetime", dt.datetime))
        transfer = crypto.root / "sealed-runtime"
        self._stage = "native-private-freeze"
        with patch.object(legacy.projection, "COHORT_FILE", policy_path):
            sealed = legacy.metadata.seal_private_freeze(freeze, package, transfer,
                projection_origin=projection_origin, private_root=h.work)
        self.assertEqual(3, sealed["schemaVersion"])
        self.assertEqual(freeze["assets"], sealed["assets"])
        self.assertEqual(freeze["checksumsDigest"], sealed["checksumsDigest"])
        committed = {path.name: path.read_bytes() for path in transfer.iterdir()}
        self.assertEqual({companion.DESCRIPTOR, companion.CIPHERTEXT}, set(committed))
        for canary in (b"pr305-fixture", inventory["cohortDigest"].encode(), b"federationSelection"):
            self.assertNotIn(canary, b"".join(committed.values()))
        self._stage = "exact-handoffs"
        for name in ("prepared", "validated", "retry"):
            destination = crypto.root / name
            copy_runtime(sealed, transfer, destination, package)
            self.assertEqual(committed, {path.name: path.read_bytes() for path in destination.iterdir()})
        with zipfile.ZipFile(io.BytesIO(h.fetch(selected["maintenanceProduct"]["coordinates"], h.work).content)) as original:
            files = {name: original.read(name) for name in original.namelist() if not name.startswith("freeze/runtime/")}
        freeze_bytes = legacy.metadata.canonical_bytes(sealed)
        files["freeze/" + legacy.products.maintenance.CANDIDATE_FREEZE_FILE] = freeze_bytes
        files.update({"freeze/runtime/" + name: raw for name, raw in committed.items()})
        coordinates = h.artifact("stable-maintenance-freeze", files, commit,
            "stable-1-0-maintenance-frozen-" + sealed["releaseId"] + "-302-1-1")
        selected_product = {"coordinates": coordinates, "freezeDigest": legacy.metadata.digest_bytes(freeze_bytes)}
        ordinary = legacy.metadata.read_json((package.parent / "runtime/runtime-subjects.json").read_bytes())
        native = legacy.metadata.read_json((package.parent / "runtime/native-admissions.json").read_bytes())
        by_id = {row["appId"]: row for row in native}
        node = next(row for row in legacy.fixture_plan()["nodes"] if row["role"] == "candidate-sender")
        node.update(artifactDigest=legacy.products.file_digest(package), artifactSize=package.stat().st_size,
            sourceCommit=commit, contractVersion=ordinary["contractVersion"],
            appDigests=sorted(by_id[app]["bundleDigest"] for app in ordinary["rolePolicy"]["candidate-sender"]))
        self._stage = "original-authenticated-private-native-admission"
        member_attestations = []
        original_attestation_transport = legacy.products._gh
        def attest(arguments, environment):
            member_attestations.append(Path(arguments[2]).name)
            return original_attestation_transport(arguments, environment)
        with patch.object(legacy.projection, "COHORT_FILE", policy_path), \
                patch.object(legacy.products, "_gh", side_effect=attest):
            admitted = legacy.products.authenticate_maintenance_product(selected_product, node, h.work / "sealed-admitted")
        self.assertEqual([legacy.products.maintenance.CANDIDATE_FREEZE_FILE, "checksums.txt", package.name,
                          companion.DESCRIPTOR, companion.CIPHERTEXT], member_attestations)
        try:
            self.assertTrue(admitted["appMatrix"])
            self.assertNotIn("pr305-fixture", admitted["requiredAppIds"])
            private_inventory = legacy.metadata.read_json((admitted["runtimeRoot"] / "projection-inventory.json").read_bytes())
            self.assertEqual(4, private_inventory["schemaVersion"])
            self.assertIn("pr305-fixture", private_inventory["requiredAppIds"])
            private_native = legacy.metadata.read_json((admitted["runtimeRoot"] / "native-admissions.json").read_bytes())
            scoped = next(row for row in private_native if row["appId"] == "pr305-fixture")
            self.assertEqual(3, scoped["schemaVersion"])
            self.assertEqual("accepted", scoped["nativeAdmission"])
            public = json.dumps(legacy.products.public_product_identity(admitted)).encode()
            for canary in (b"pr305-fixture", private_inventory["cohortDigest"].encode(),
                           legacy.products.file_digest(admitted["runtimeRoot"] / "projection-inventory.json").encode()):
                self.assertNotIn(canary, public)
            authority = legacy.products.AuthenticatedProducts(legacy.products._SEAL, legacy.products.digest({"test": 307}),
                                                             {node["role"]: admitted})
            contract = legacy.metadata.read_json((admitted["runtimeRoot"] / "snapshot.json").read_bytes())
            self.assertTrue(authority.verify_runtime_contract(node["role"], contract))
            with self.assertRaises(legacy.products.ProductAdmissionError):
                authority.verify_runtime_contract(node["role"], {"contract": {"contractVersion": 0}})
        finally:
            opened = admitted["runtimeRoot"]
            legacy.products.close_runtime_context(admitted)
        self.assertFalse(opened.exists())
        self.assertEqual(committed, {path.name: path.read_bytes() for path in transfer.iterdir()})
        self._stage = "protected-original-validation-context"
        import maintenance_runtime_validation as validation
        source_path = h.work / "runtime-validation-source.json"
        source_path.write_bytes(legacy.metadata.canonical_bytes(selected_product))
        source_path.chmod(0o600)
        with self.assertRaises(validation.RuntimeValidationError):
            validation.require_context(sealed, transfer, package)
        with patch.object(validation, "SOURCE", source_path), patch.object(legacy.projection, "COHORT_FILE", policy_path):
            with validation.original_context(sealed, package, freeze_digest=selected_product["freezeDigest"]):
                validation.require_context(sealed, transfer, package)
                with self.assertRaises(validation.RuntimeValidationError):
                    validation.require_context({**sealed, "releaseId": "other"}, transfer, package)
        with self.assertRaises(validation.RuntimeValidationError):
            validation.require_context(sealed, transfer, package)

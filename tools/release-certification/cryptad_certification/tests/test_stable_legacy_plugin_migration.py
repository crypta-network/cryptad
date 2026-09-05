"""Local observation validation cannot manufacture authentic migration evidence."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from cryptad_certification.engines import stable_legacy_plugin_migration as pilot


def observation():
    digest = "sha256:" + "a" * 64
    return {
        "schemaVersion": 1,
        "kind": "sharesite-migration-local-observation",
        "operationId": "01234567-89ab-4def-8123-456789abcdef",
        "classification": "synthetic",
        "source": {"repository": pilot.SOURCE_REPOSITORY, "revision": pilot.SOURCE_REVISION, "profile": pilot.PROFILE},
        "adapter": {"sourceCommit": "b" * 40, "artifactDigest": digest},
        "target": {
            "appId": "site-publisher", "version": "1.0.0", "baseline": "1.0",
            "bundleDigest": digest, "manifestDigest": digest, "catalogDigest": digest,
            "signatureDigest": digest, "publisherFingerprint": digest,
        },
        "selectedCount": 2,
        "excludedCounts": {"textile": 1, "deleted": 2},
        "outcomes": {key: "not-observed" for key in pilot.CHECKS},
    }


class StableLegacyPluginMigrationTest(unittest.TestCase):
    def test_local_format_claims_remain_unverified_and_synthetic(self):
        value = observation()
        value["outcomes"].update({key: "pass" for key in pilot.CHECKS})
        result = pilot.summarize(value, "verify-migration")
        self.assertEqual("local-observation-validated", result["status"])
        self.assertEqual("synthetic", result["classification"])
        self.assertEqual("not-independently-observed", result["formatVerification"])
        self.assertEqual("not-authenticated", result["realDataMigration"])
        self.assertEqual("not-observed", result["publication"])
        self.assertFalse(result["promotionReady"])

    def test_operator_label_cannot_authenticate_real_data(self):
        value = observation()
        value["classification"] = "operator-local-unverified"
        result = pilot.summarize(value, "verify-runtime")
        self.assertEqual("blocked", result["status"])
        self.assertEqual("not-authenticated", result["runtimeObservation"])
        self.assertEqual("not-authenticated", result["realDataMigration"])

    def test_resealed_receipt_and_caller_authority_are_rejected(self):
        for field in ("receiptDigest", "authority", "runtimeProducer", "operationallyComplete"):
            with self.subTest(field=field):
                value = observation()
                value[field] = "sha256:" + "a" * 64
                with self.assertRaisesRegex(ValueError, "fields-invalid"):
                    pilot.summarize(value, "closeout")

    def test_closeout_cannot_promote_all_passing_local_claims(self):
        value = observation()
        value["outcomes"] = {key: "pass" for key in pilot.CHECKS}
        result = pilot.summarize(value, "closeout")
        self.assertEqual("blocked", result["releaseEligibility"])
        self.assertFalse(result["operationallyComplete"])
        self.assertIn("pr296-protected-subject-projection-pending", result["prerequisites"])
        self.assertIn("protected-migration-producer-not-configured", result["prerequisites"])

    def test_closed_allowlist_rejects_private_data_and_echoes_nothing(self):
        for field in ("text", "name", "oldReadUri", "sourceHash", "sourcePath", "insertSSK"):
            for container in (None, "source", "target", "adapter", "excludedCounts", "outcomes"):
                with self.subTest(field=field, container=container):
                    value = observation()
                    selected = value if container is None else value[container]
                    selected[field] = "PRIVATE_CANARY /home/private-owner"
                    with self.assertRaises(ValueError) as caught:
                        pilot.validate_observation(value)
                    self.assertNotIn("PRIVATE_CANARY", str(caught.exception))
                    self.assertNotIn("private-owner", str(caught.exception))
                    self.assertNotIn(field, str(caught.exception))

    def test_wrong_source_profile_bundle_or_baseline_is_rejected(self):
        changes = (("source", "revision", "c" * 40), ("source", "profile", "textile-v1"),
                   ("target", "appId", "publisher"), ("target", "baseline", "1.1"),
                   ("target", "bundleDigest", "not-a-digest"), ("adapter", "sourceCommit", "main"))
        for container, field, new in changes:
            with self.subTest(field=field):
                value = observation()
                value[container][field] = new
                with self.assertRaises(ValueError):
                    pilot.validate_observation(value)

    def test_empty_and_oversized_selection_cannot_look_successful(self):
        for count in (0, -1, True, 17, "2"):
            value = observation()
            value["selectedCount"] = count
            with self.assertRaisesRegex(ValueError, "selection-empty-or-oversized"):
                pilot.validate_observation(value)

    def test_partial_cleanup_and_missing_publication_stay_separate(self):
        value = observation()
        value["outcomes"]["cleanup"] = "fail"
        value["outcomes"]["importCommit"] = "pass"
        result = pilot.summarize(value, "verify-migration")
        self.assertEqual("failed", result["status"])
        self.assertEqual(["cleanup"], result["failedLocalChecks"])
        self.assertEqual("pass", result["reportedLocalOutcomes"]["importCommit"])
        self.assertEqual("not-observed", result["publication"])
        self.assertEqual("unsupported", result["sameUskContinuity"])

    def test_real_and_managed_classification_cannot_be_self_asserted(self):
        for classification in ("genuine-operator-migration", "managed-runtime", "upstream-format-verified"):
            value = observation()
            value["classification"] = classification
            with self.assertRaisesRegex(ValueError, "classification-not-authorized"):
                pilot.validate_observation(value)

    def test_private_field_in_duplicate_json_error_does_not_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "input.json").write_text('{"PRIVATE_CANARY":1,"PRIVATE_CANARY":2}')
            with self.assertRaises(ValueError) as caught:
                pilot.run(root, Path("input.json"), "preflight", Path("out"))
            self.assertEqual("migration-observation-json-invalid", str(caught.exception))
            self.assertFalse((root / "out").exists())

    def test_io_confines_new_outputs_and_never_copies_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input.json"
            source.write_text(json.dumps(observation()))
            original = source.read_bytes()
            self.assertEqual(0, pilot.run(root, Path("input.json"), "preflight", Path("out")))
            self.assertEqual({"summary.json", "report.md", "redaction-report.json"}, {path.name for path in (root / "out").iterdir()})
            self.assertEqual(original, source.read_bytes())
            with self.assertRaisesRegex(ValueError, "output-must-be-new"):
                pilot.run(root, Path("input.json"), "preflight", Path("out"))
            with self.assertRaisesRegex(ValueError, "path-invalid"):
                pilot.run(root, Path("input.json"), "preflight", Path("../escape"))
            (root / "link.json").symlink_to(source)
            with self.assertRaisesRegex(ValueError, "link-rejected"):
                pilot.run(root, Path("link.json"), "preflight", Path("other"))

    def test_runtime_command_returns_failure_and_sanitized_blocked_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "input.json").write_text(json.dumps(observation()))
            self.assertEqual(1, pilot.run(root, Path("input.json"), "verify-runtime", Path("out")))
            summary = json.loads((root / "out/summary.json").read_text())
            self.assertEqual("blocked", summary["status"])

    def test_oversized_input_is_rejected_without_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "input.json").write_bytes(b" " * (pilot.MAX_OBSERVATION_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "file-invalid"):
                pilot.run(root, Path("input.json"), "preflight", Path("out"))
            self.assertFalse((root / "out").exists())


if __name__ == "__main__":
    unittest.main()

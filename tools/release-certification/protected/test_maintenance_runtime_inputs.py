"""Input boundary tests; fixture coordinates confer no original producer authority."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import maintenance_runtime_inputs as inputs


class RuntimeInputsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.intake = self.root / "intake"
        self.intake.mkdir()
        self.coordinates = {"repository": "crypta-network/cryptad", "sourceFamily": "app-subject-projection",
            "sourceCommit": "a" * 40, "runId": 1, "runAttempt": 1, "jobId": 1,
            "jobName": "projection", "artifactId": 1, "artifactName": "projection",
            "artifactDigest": "sha256:" + "b" * 64, "artifactSize": 100}

    def marker(self):
        (self.intake / "mode.json").write_text(json.dumps(inputs.MARKER))

    def test_marker_has_no_private_coordinates_and_requires_exact_roster(self):
        self.marker()
        self.assertTrue(inputs.detect_private_inputs(self.intake))
        (self.intake / "cohort.json").write_text('{"private":"canary"}')
        with self.assertRaises(inputs.RuntimeInputsError):
            inputs.detect_private_inputs(self.intake)

    def test_legacy_selected_cohort_is_rejected_before_acquisition(self):
        (self.intake / "cohort.json").write_text('{"schemaVersion":2}')
        with patch("app_subject_projection._cohort") as cohort:
            with self.assertRaises(inputs.RuntimeInputsError):
                inputs.projection_origin(self.intake)
        cohort.assert_not_called()

    def test_legacy_public_coordinates_preserve_their_meaning(self):
        (self.intake / "cohort.json").write_text('{"schemaVersion":1}')
        (self.intake / "projection-selection.json").write_text(json.dumps({"coordinates": self.coordinates}))
        self.assertFalse(inputs.detect_private_inputs(self.intake))
        self.assertEqual(inputs.projection_origin(self.intake), self.coordinates)

    def test_marker_cannot_supply_pointer_or_policy(self):
        for value in ({**inputs.MARKER, "coordinates": self.coordinates},
                      {"schemaVersion": True, "mode": "selected-federation"},
                      {"schemaVersion": 1, "mode": "unknown"}):
            with self.subTest(value=value):
                (self.intake / "mode.json").write_text(json.dumps(value))
                with self.assertRaises(inputs.RuntimeInputsError):
                    inputs.detect_private_inputs(self.intake)

    def test_fixed_private_pointer_and_existing_cohort_are_both_required(self):
        self.marker()
        pointer = self.root / "provisioned.json"
        pointer.write_text(json.dumps({"coordinates": self.coordinates}))
        pointer.chmod(0o600)
        with patch.object(inputs, "PROJECTION_FILE", pointer), patch("app_subject_projection._cohort", return_value={"schemaVersion":2}):
            # The owner check is tested independently; synthetic policy is not installed into /etc.
            info = pointer.stat()
            from types import SimpleNamespace
            owner = SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_gid=inputs.os.getegid())
            # Exercise the closed pointer reader under an explicit synthetic root-owner fixture.
            # Real file ownership rejection remains covered immediately below on this user runner.
            original_regular = inputs._regular
            pointer_raw = pointer.read_bytes()
            def read(path, maximum):
                return pointer_raw if path == pointer else original_regular(path, maximum)
            original_stat = Path.stat
            def file_stat(path, *args, **kwargs):
                return owner if path == pointer else original_stat(path, *args, **kwargs)
            with patch.object(inputs, "_regular", side_effect=read), patch.object(Path, "stat", file_stat):
                self.assertEqual(inputs.projection_origin(self.intake), self.coordinates)
                owner.st_mode = 0o100640
                self.assertEqual(inputs.projection_origin(self.intake), self.coordinates)
                owner.st_gid = inputs.os.getegid() + 1
                with patch.object(inputs.os, "geteuid", return_value=1001):
                    with self.assertRaises(inputs.RuntimeInputsError):
                        inputs.projection_origin(self.intake)
                with patch.object(inputs.os, "geteuid", return_value=0):
                    self.assertEqual(inputs.projection_origin(self.intake), self.coordinates)
                owner.st_gid = inputs.os.getegid()
                owner.st_mode = 0o100644
                with self.assertRaises(inputs.RuntimeInputsError):
                    inputs.projection_origin(self.intake)
            if info.st_uid != 0:
                with self.assertRaises(inputs.RuntimeInputsError):
                    inputs.projection_origin(self.intake)
            pointer.chmod(0o644)
            with self.assertRaises(inputs.RuntimeInputsError):
                inputs.projection_origin(self.intake)
            pointer.unlink()
            with self.assertRaises(inputs.RuntimeInputsError):
                inputs.projection_origin(self.intake)

    def test_symbolic_marker_and_duplicate_json_fail(self):
        outside = self.root / "marker"
        outside.write_text(json.dumps(inputs.MARKER))
        marker = self.intake / "mode.json"
        marker.symlink_to(outside)
        with self.assertRaises(inputs.RuntimeInputsError):
            inputs.detect_private_inputs(self.intake)
        marker.unlink()
        marker.write_text('{"schemaVersion":1,"schemaVersion":1,"mode":"selected-federation"}')
        with self.assertRaises(inputs.RuntimeInputsError):
            inputs.detect_private_inputs(self.intake)


if __name__ == "__main__":
    unittest.main()

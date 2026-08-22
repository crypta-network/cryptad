"""Characterization suite for security-response tooling."""

from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from cryptad_certification.engines import security_response_runbook as security
from cryptad_certification.io import write_json


def _binding() -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-catalog-authority-evidence-binding",
        "summaryDigest": "sha256:" + "1" * 64,
        "protectedEvidenceDigest": "sha256:" + "2" * 64,
        "state": "rotation-drill-complete",
        "keysetDigest": "sha256:" + "3" * 64,
        "transparencyDigest": "sha256:" + "4" * 64,
        "catalogSigningKeyId": "stable-catalog-key-2026",
        "catalogSigningKeyFingerprintSha256": "sha256:" + "5" * 64,
        "fixtureOnly": False,
        "operational": True,
    }


class SecurityResponseCharacterizationTest(unittest.TestCase):
    def test_existing_security_response_scenarios(self) -> None:
        result = security.self_test()
        self.assertEqual("pass", result["status"])

    def test_catalog_rotation_rejects_self_asserted_catalog_authority_binding(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binding_path = root / "catalog-authority-binding.json"
            artifact_path = root / "catalog-signing-key-rotation.json"
            write_json(binding_path, _binding())

            with self.assertRaisesRegex(
                ValueError,
                "cannot authenticate protected operational evidence",
            ):
                security.drill_create(
                    security.DEFAULT_MODEL,
                    "catalog-signing-key-rotation",
                    artifact_path,
                    catalog_authority_path=binding_path,
                )

            self.assertFalse(artifact_path.exists())

    def test_run_all_rejects_catalog_authority_before_writing_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binding_path = root / "catalog-authority-binding.json"
            output_dir = root / "drills"
            summary_path = root / "summary.json"
            write_json(binding_path, _binding())

            with self.assertRaisesRegex(
                ValueError,
                "cannot authenticate protected operational evidence",
            ):
                security.drill_run_all(
                    security.DEFAULT_MODEL,
                    output_dir,
                    summary_path,
                    catalog_authority_path=binding_path,
                )

            self.assertFalse(output_dir.exists())
            self.assertFalse(summary_path.exists())

    def test_catalog_rotation_rejects_substituted_authority(self) -> None:
        artifact = security.drill_artifact(
            {},
            security.model_drills(security.load_model(security.DEFAULT_MODEL))[
                "catalog-signing-key-rotation"
            ],
            "catalog-signing-key-rotation",
            "stable-security-drill",
            "2026-08-20T00:00:00Z",
            "release-candidate",
            "release-operations",
            False,
            _binding(),
        )
        substituted = copy.deepcopy(artifact)
        substituted["catalogAuthority"]["summaryDigest"] = substituted["catalogAuthority"][
            "protectedEvidenceDigest"
        ]

        result = security.validate_v2_drill_artifact(substituted)

        self.assertFalse(result["ok"])
        self.assertTrue(
            any("must be distinct" in error for error in result["errors"])
        )

    def test_catalog_rotation_artifact_rejects_self_asserted_operational_authority(
        self,
    ) -> None:
        artifact = security.drill_artifact(
            {},
            security.model_drills(security.load_model(security.DEFAULT_MODEL))[
                "catalog-signing-key-rotation"
            ],
            "catalog-signing-key-rotation",
            "stable-security-drill",
            "2026-08-20T00:00:00Z",
            "release-candidate",
            "release-operations",
            False,
            _binding(),
        )

        result = security.validate_v2_drill_artifact(artifact)

        with tempfile.TemporaryDirectory() as directory:
            artifact_path = Path(directory) / "forged-catalog-authority-drill.json"
            write_json(artifact_path, artifact)
            verified = security.drill_verify(artifact_path)

        self.assertFalse(result["ok"])
        self.assertTrue(
            any(
                "cannot authenticate protected operational evidence" in error
                for error in result["errors"]
            )
        )
        self.assertEqual("fail", verified["status"])
        self.assertTrue(
            any(
                "cannot authenticate protected operational evidence" in error
                for error in verified["errors"]
            )
        )

    def test_catalog_rotation_without_catalog_authority_remains_compatible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact_path = Path(directory) / "catalog-signing-key-rotation.json"

            artifact = security.drill_create(
                security.DEFAULT_MODEL,
                "catalog-signing-key-rotation",
                artifact_path,
            )
            verified = security.drill_verify(artifact_path)

        self.assertNotIn("catalogAuthority", artifact)
        self.assertEqual("pass", verified["status"])

    def test_unrelated_drill_cannot_select_catalog_authority(self) -> None:
        errors = security.validate_catalog_authority_binding(
            "reviewer-key-compromise", _binding()
        )

        self.assertEqual(
            ["catalog-authority evidence is selected for an unrelated drill"], errors
        )

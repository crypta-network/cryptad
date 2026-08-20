from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from cryptad_certification.engines import stable_1_0_independent_handoff as handoff
from cryptad_certification.engines.stable_1_0_supply_chain_core import semantic_digest


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="utf-8",
    )


class StableIndependentHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temporary.name)
        self.original = self.workspace / "original"
        self.producer = self.original / "producer"
        self.authentication = self.original / "authentication"
        self.inputs = self.workspace / "phase"
        for directory in (self.producer / "subjects", self.producer / "payload-manifests", self.authentication, self.inputs):
            directory.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _fixture(self) -> Path:
        manifest_inputs = {}
        for key, name in handoff.INPUT_FILES.items():
            path = self.inputs / name
            _write(path, {"kind": key})
            manifest_inputs[key] = path.relative_to(self.workspace).as_posix()
        manifest = self.inputs / "manifest.json"
        _write(manifest, {"inputs": manifest_inputs})

        subject = self.producer / "subjects/cryptad.jar"
        subject.write_bytes(b"primary-subject")
        package = self.producer / "subjects/cryptad.deb"
        package.write_bytes(b"primary-package")
        payload = {
            "subjectKey": "linux.amd64.deb",
            "publishedSubjectDigest": _digest(package.read_bytes()),
            "manifestDigest": "sha256:" + "0" * 64,
        }
        payload["manifestDigest"] = semantic_digest(payload, "manifestDigest")
        payload_path = self.producer / "payload-manifests/linux.amd64.deb.json"
        _write(payload_path, payload)
        evidence = [{"verificationResult": {"statement": {"subject": []}}}]
        evidence_path = self.authentication / "producer-attestations.json"
        _write(evidence_path, evidence)
        receipt = {
            "sourceCommit": "1" * 40,
            "builderIdentity": {
                "workflowRef": "github.com/crypta-network/cryptad/.github/workflows/stable-1.0-supply-chain.yml@" + "1" * 40,
                "runId": 7,
                "runAttempt": 1,
                "jobName": "candidate-producer",
                "artifactAttestationDigest": _digest(evidence_path.read_bytes()),
            },
            "builderExecutions": [
                {
                    "runnerOs": "linux",
                    "runnerArchitecture": "amd64",
                    "runnerImageIdentity": "ubuntu-24.04@fixture",
                    "runnerImageDigest": _digest(b"runner"),
                }
            ],
            "buildStartedAt": "2026-08-18T00:00:00Z",
            "buildCompletedAt": "2026-08-18T00:10:00Z",
            "subjects": [
                {
                    "subjectKey": "cryptad-core",
                    "fileName": "cryptad.jar",
                    "digest": _digest(subject.read_bytes()),
                    "size": subject.stat().st_size,
                    "payloadManifestDigest": None,
                },
                {
                    "subjectKey": "linux.amd64.deb",
                    "fileName": "cryptad.deb",
                    "digest": _digest(package.read_bytes()),
                    "size": package.stat().st_size,
                    "payloadManifestDigest": payload["manifestDigest"],
                },
            ],
        }
        _write(self.original / "derived-producer-builder-receipt.json", receipt)
        return manifest

    def test_stage_primary_when_repeated_expect_identical_closed_bundle(self) -> None:
        manifest = self._fixture()
        first = self.workspace / "first"
        second = self.workspace / "second"
        first_bundle = self.workspace / "first-bundle" / handoff.PRIMARY_BUNDLE
        second_bundle = self.workspace / "second-bundle" / handoff.PRIMARY_BUNDLE

        handoff.stage_primary_handoff(
            self.workspace,
            manifest,
            self.original,
            first,
            first_bundle,
            "refs/heads/release/3",
        )
        handoff.stage_primary_handoff(
            self.workspace,
            manifest,
            self.original,
            second,
            second_bundle,
            "refs/heads/release/3",
        )

        self.assertEqual(
            first_bundle.read_bytes(),
            second_bundle.read_bytes(),
        )
        with zipfile.ZipFile(first_bundle) as archive:
            self.assertEqual(
                [
                    "payload-manifests/linux.amd64.deb.json",
                    "subjects/cryptad.deb",
                    "subjects/cryptad.jar",
                ],
                archive.namelist(),
            )
            self.assertTrue(all(row.compress_type == zipfile.ZIP_STORED for row in archive.infolist()))
            self.assertTrue(all(row.date_time == (1980, 1, 1, 0, 0, 0) for row in archive.infolist()))
        self.assertTrue((first / handoff.PRIMARY_GITHUB_EVIDENCE).is_file())
        self.assertFalse((first / handoff.PRIMARY_BUNDLE).exists())
        self.assertFalse((first / handoff.PRIMARY_AUTHORITY).exists())

    def test_stage_primary_when_manifest_path_escapes_expect_rejection(self) -> None:
        manifest = self._fixture()
        value = json.loads(manifest.read_text(encoding="utf-8"))
        value["inputs"]["buildMaterials"] = "../outside.json"
        _write(manifest, value)

        with self.assertRaises((ValueError, FileNotFoundError)):
            handoff.stage_primary_handoff(
                self.workspace,
                manifest,
                self.original,
                self.workspace / "output",
                self.workspace / "subject-bundle" / handoff.PRIMARY_BUNDLE,
                "refs/heads/release/3",
            )

    def test_stage_primary_when_bundle_is_inside_comparison_handoff_expect_rejection(self) -> None:
        manifest = self._fixture()
        output = self.workspace / "output"

        with self.assertRaisesRegex(ValueError, "outside the bounded comparison handoff"):
            handoff.stage_primary_handoff(
                self.workspace,
                manifest,
                self.original,
                output,
                output / handoff.PRIMARY_BUNDLE,
                "refs/heads/release/3",
            )

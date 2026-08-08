"""Focused tests for Stable supply-chain evidence in release certification."""

from __future__ import annotations

import base64
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from cryptad_certification.engines import release_certification
from cryptad_certification.engines.stable_1_0_supply_chain import EVIDENCE_IDS
from cryptad_certification.engines.stable_1_0_supply_chain_core import semantic_digest
from cryptad_certification.io import read_json, write_json
from cryptad_certification.tests.support import workspace_root


RELEASE_ID = "stable-1-0-maintenance-301"
BUILD_VERSION = "301"
SOURCE_COMMIT = "a" * 40
SOURCE_REF = "commit:" + SOURCE_COMMIT
HANDOFF_KEY = b"s" * 32
HANDOFF_KEY_BASE64 = base64.b64encode(HANDOFF_KEY).decode("ascii")


def _promotion_summary() -> dict[str, object]:
    policy = read_json(
        workspace_root()
        / "tools/release-certification/stable-1.0-supply-chain-policy.json"
    )
    assert isinstance(policy, dict)
    digest = "sha256:" + "1" * 64
    value: dict[str, object] = {
        "schemaVersion": 1,
        "kind": "stable-1.0-supply-chain-promotion-summary",
        "releaseId": RELEASE_ID,
        "buildVersion": int(BUILD_VERSION),
        "tag": f"v{BUILD_VERSION}",
        "sourceCommit": SOURCE_COMMIT,
        "sourceRef": SOURCE_REF,
        "policyDigest": policy["policyDigest"],
        "mode": "evaluate-promotion",
        "status": "pass",
        "promotionReady": True,
        "candidateIdentityDigest": digest,
        "candidateFreezeDigest": digest,
        "productDigest": digest,
        "predecessorReleaseId": "stable-1-0-ga-300",
        "predecessorBuildVersion": 300,
        "predecessorProductDigest": digest,
        "packageMatrixDigest": digest,
        "packageAuthenticationDigest": digest,
        "selectedSubjectInventoryDigest": digest,
        "vulnerabilitySummaryDigest": digest,
        "vulnerabilityReverseIndexDigest": digest,
        "resolvedDependencySnapshotDigest": digest,
        "componentInventoryDigest": digest,
        "subjectInventoryDigest": digest,
        "sbomDigest": digest,
        "licenseInventoryDigest": digest,
        "buildMaterialsDigest": digest,
        "primaryBuilderReceiptDigest": digest,
        "verifierBuilderReceiptDigest": digest,
        "comparisonPlanDigest": digest,
        "reproducibilityResultDigest": digest,
        "evidence": [
            {"evidenceId": evidence_id, "status": "pass", "nonWaivable": True}
            for evidence_id in EVIDENCE_IDS
            if evidence_id != "stable-supply-chain.publication"
        ],
        "blockers": [],
        "waivers": [],
        "artifacts": [],
        "redaction": {
            "status": "pass",
            "privatePathsExcluded": True,
            "credentialsExcluded": True,
            "privateUrisExcluded": True,
            "embargoedVulnerabilityDataExcluded": True,
            "sideEffectsPerformed": False,
        },
        "summaryDigest": "sha256:" + "0" * 64,
    }
    value["summaryDigest"] = semantic_digest(value, "summaryDigest")
    return value


def _write_authenticated_handoff(path: Path, summary: dict[str, object]) -> None:
    summary_digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    handoff: dict[str, object] = {
        "schemaVersion": 1,
        "kind": "stable-1.0-supply-chain-promotion-handoff",
        "repository": "crypta-network/cryptad",
        "workflow": (
            "crypta-network/cryptad/.github/workflows/"
            f"stable-1.0-supply-chain.yml@{summary['sourceCommit']}"
        ),
        "workflowCommit": summary["sourceCommit"],
        "runId": "1001",
        "runAttempt": "1",
        "operation": "compare-evaluate",
        "releaseId": RELEASE_ID,
        "buildVersion": BUILD_VERSION,
        "sourceCommit": summary["sourceCommit"],
        "artifactName": f"stable-1.0-supply-chain-{RELEASE_ID}-comparison",
        "producerArtifactDigest": "sha256:" + "d" * 64,
        "summaryFileName": "stable-1.0-supply-chain-summary.json",
        "summaryByteDigest": summary_digest,
        "attestationSubjectDigest": summary_digest,
        "attestationVerified": True,
        "denySelfHostedRunners": True,
        "authenticationStatus": "pass",
        "authenticationAlgorithm": "hmac-sha256",
        "authenticationTag": "sha256:" + "0" * 64,
    }
    handoff["authenticationTag"] = (
        release_certification.stable_supply_chain_handoff_authentication_tag(
            handoff, HANDOFF_KEY
        )
    )
    write_json(
        path.with_name("stable-1.0-supply-chain-summary-provenance.json"),
        handoff,
    )


def _settings(
    root: Path,
    summary: Path | None,
    *,
    required: bool,
) -> SimpleNamespace:
    return SimpleNamespace(
        workspace_root=root,
        out_dir=root / "build/release-certification",
        stable_supply_chain_summary=summary,
        stable_supply_chain_required=required,
        stable_supply_chain_candidate_release_id=RELEASE_ID,
        stable_supply_chain_candidate_build_version=BUILD_VERSION,
        stable_supply_chain_candidate_source_commit=SOURCE_COMMIT,
        stable_supply_chain_candidate_source_ref=SOURCE_REF,
        stable_vulnerability_summary=None,
        stable_vulnerability_required=False,
        live_network_beta_required=False,
    )


class ReleaseCertificationStableSupplyChainTest(unittest.TestCase):
    def test_canonical_promotion_summary_passes_nonwaivable_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "stable-1.0-supply-chain-summary.json"
            summary = _promotion_summary()
            write_json(path, summary)
            _write_authenticated_handoff(path, summary)

            with mock.patch.dict(
                os.environ,
                {
                    release_certification.STABLE_SUPPLY_CHAIN_HANDOFF_KEY_ENV: (
                        HANDOFF_KEY_BASE64
                    )
                },
            ):
                evidence = release_certification.stable_supply_chain_evidence(
                    path,
                    root,
                    root / "out",
                    RELEASE_ID,
                    BUILD_VERSION,
                    SOURCE_COMMIT,
                    SOURCE_REF,
                    SOURCE_COMMIT,
                    required=True,
                )

        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual(evidence.status, "pass", evidence.details)
        self.assertTrue(evidence.details["authenticated"])
        self.assertTrue(evidence.details["protectedProducerAuthenticated"])

    def test_self_asserted_attestation_flags_without_handoff_key_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "stable-1.0-supply-chain-summary.json"
            summary = _promotion_summary()
            write_json(path, summary)
            _write_authenticated_handoff(path, summary)

            with mock.patch.dict(
                os.environ,
                {release_certification.STABLE_SUPPLY_CHAIN_HANDOFF_KEY_ENV: ""},
            ):
                evidence = release_certification.stable_supply_chain_evidence(
                    path,
                    root,
                    root / "out",
                    RELEASE_ID,
                    BUILD_VERSION,
                    SOURCE_COMMIT,
                    SOURCE_REF,
                    SOURCE_COMMIT,
                    required=True,
                )

        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual(evidence.status, "fail")
        self.assertFalse(evidence.details["protectedProducerAuthenticated"])
        self.assertIn(
            "configured supply-chain handoff authentication key is invalid",
            evidence.details["validationErrors"],
        )

    def test_tampered_provenance_fails_handoff_authentication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "stable-1.0-supply-chain-summary.json"
            summary = _promotion_summary()
            write_json(path, summary)
            _write_authenticated_handoff(path, summary)
            handoff_path = path.with_name(
                "stable-1.0-supply-chain-summary-provenance.json"
            )
            handoff = read_json(handoff_path)
            handoff["runId"] = "1002"
            write_json(handoff_path, handoff)

            with mock.patch.dict(
                os.environ,
                {
                    release_certification.STABLE_SUPPLY_CHAIN_HANDOFF_KEY_ENV: (
                        HANDOFF_KEY_BASE64
                    )
                },
            ):
                evidence = release_certification.stable_supply_chain_evidence(
                    path,
                    root,
                    root / "out",
                    RELEASE_ID,
                    BUILD_VERSION,
                    SOURCE_COMMIT,
                    SOURCE_REF,
                    SOURCE_COMMIT,
                    required=True,
                )

        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual(evidence.status, "fail")
        self.assertIn(
            "configured supply-chain producer handoff authentication failed",
            evidence.details["validationErrors"],
        )

    def test_authenticated_summary_for_another_checkout_commit_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "stable-1.0-supply-chain-summary.json"
            summary = _promotion_summary()
            write_json(path, summary)
            _write_authenticated_handoff(path, summary)

            with mock.patch.dict(
                os.environ,
                {
                    release_certification.STABLE_SUPPLY_CHAIN_HANDOFF_KEY_ENV: (
                        HANDOFF_KEY_BASE64
                    )
                },
            ):
                evidence = release_certification.stable_supply_chain_evidence(
                    path,
                    root,
                    root / "out",
                    RELEASE_ID,
                    BUILD_VERSION,
                    SOURCE_COMMIT,
                    SOURCE_REF,
                    "b" * 40,
                    required=True,
                )

        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual(evidence.status, "fail")
        self.assertIn(
            "current checkout source commit differs from the expected Stable supply-chain candidate",
            evidence.details["validationErrors"],
        )

    def test_authenticated_summary_source_ref_must_match_immutable_candidate(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "stable-1.0-supply-chain-summary.json"
            summary = _promotion_summary()
            summary["sourceRef"] = "commit:" + "b" * 40
            summary["summaryDigest"] = semantic_digest(summary, "summaryDigest")
            write_json(path, summary)
            _write_authenticated_handoff(path, summary)

            with mock.patch.dict(
                os.environ,
                {
                    release_certification.STABLE_SUPPLY_CHAIN_HANDOFF_KEY_ENV: (
                        HANDOFF_KEY_BASE64
                    )
                },
            ):
                evidence = release_certification.stable_supply_chain_evidence(
                    path,
                    root,
                    root / "out",
                    RELEASE_ID,
                    BUILD_VERSION,
                    SOURCE_COMMIT,
                    SOURCE_REF,
                    SOURCE_COMMIT,
                    required=True,
                )

        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual(evidence.status, "fail")
        self.assertIn(
            "configured supply-chain summary source ref differs",
            evidence.details["validationErrors"],
        )

    def test_self_digested_summary_without_protected_handoff_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "stable-1.0-supply-chain-summary.json"
            write_json(path, _promotion_summary())

            with mock.patch.dict(
                os.environ,
                {
                    release_certification.STABLE_SUPPLY_CHAIN_HANDOFF_KEY_ENV: (
                        HANDOFF_KEY_BASE64
                    )
                },
            ):
                evidence = release_certification.stable_supply_chain_evidence(
                    path,
                    root,
                    root / "out",
                    RELEASE_ID,
                    BUILD_VERSION,
                    SOURCE_COMMIT,
                    SOURCE_REF,
                    SOURCE_COMMIT,
                    required=True,
                )

        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual(evidence.status, "fail")
        self.assertFalse(evidence.details["protectedProducerAuthenticated"])
        self.assertIn(
            "configured supply-chain producer handoff is missing, unreadable, or malformed",
            evidence.details["validationErrors"],
        )

    def test_substituted_producer_artifact_digest_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "stable-1.0-supply-chain-summary.json"
            summary = _promotion_summary()
            write_json(path, summary)
            _write_authenticated_handoff(path, summary)
            handoff_path = path.with_name(
                "stable-1.0-supply-chain-summary-provenance.json"
            )
            handoff = read_json(handoff_path)
            handoff["producerArtifactDigest"] = "caller-selected"
            write_json(handoff_path, handoff)

            with mock.patch.dict(
                os.environ,
                {
                    release_certification.STABLE_SUPPLY_CHAIN_HANDOFF_KEY_ENV: (
                        HANDOFF_KEY_BASE64
                    )
                },
            ):
                evidence = release_certification.stable_supply_chain_evidence(
                    path,
                    root,
                    root / "out",
                    RELEASE_ID,
                    BUILD_VERSION,
                    SOURCE_COMMIT,
                    SOURCE_REF,
                    SOURCE_COMMIT,
                    required=True,
                )

        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual(evidence.status, "fail")
        self.assertIn(
            "configured supply-chain producer handoff artifact digest is invalid",
            evidence.details["validationErrors"],
        )

    def test_promotion_summary_cannot_preclaim_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "stable-1.0-supply-chain-summary.json"
            summary = _promotion_summary()
            summary["evidence"].append(
                {
                    "evidenceId": "stable-supply-chain.publication",
                    "status": "pass",
                    "nonWaivable": True,
                }
            )
            summary["summaryDigest"] = semantic_digest(summary, "summaryDigest")
            write_json(path, summary)
            _write_authenticated_handoff(path, summary)

            with mock.patch.dict(
                os.environ,
                {
                    release_certification.STABLE_SUPPLY_CHAIN_HANDOFF_KEY_ENV: (
                        HANDOFF_KEY_BASE64
                    )
                },
            ):
                evidence = release_certification.stable_supply_chain_evidence(
                    path,
                    root,
                    root / "out",
                    RELEASE_ID,
                    BUILD_VERSION,
                    SOURCE_COMMIT,
                    SOURCE_REF,
                    SOURCE_COMMIT,
                    required=True,
                )

        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual(evidence.status, "fail")
        self.assertIn(
            "promotion summary falsely claims Stable supply-chain publication passed",
            evidence.details["validationErrors"],
        )

    def test_parser_accepts_closed_supply_chain_options(self) -> None:
        parser = release_certification.build_parser()

        args = parser.parse_args(
            [
                "--stable-supply-chain-summary",
                "summary.json",
                "--require-stable-supply-chain",
                "--stable-supply-chain-candidate-release-id",
                RELEASE_ID,
                "--stable-supply-chain-candidate-build-version",
                BUILD_VERSION,
                "--stable-supply-chain-candidate-source-commit",
                SOURCE_COMMIT,
                "--stable-supply-chain-candidate-source-ref",
                SOURCE_REF,
            ]
        )

        self.assertEqual(args.stable_supply_chain_summary, Path("summary.json"))
        self.assertTrue(args.require_stable_supply_chain)
        self.assertEqual(args.stable_supply_chain_candidate_release_id, RELEASE_ID)
        self.assertEqual(
            args.stable_supply_chain_candidate_build_version, BUILD_VERSION
        )
        self.assertEqual(
            args.stable_supply_chain_candidate_source_commit, SOURCE_COMMIT
        )
        self.assertEqual(args.stable_supply_chain_candidate_source_ref, SOURCE_REF)

    def test_absent_required_summary_is_nonwaivable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = _settings(root, None, required=True)

            evidence = release_certification.stable_supply_chain_evidence(
                None,
                root,
                settings.out_dir,
                RELEASE_ID,
                BUILD_VERSION,
                SOURCE_COMMIT,
                SOURCE_REF,
                SOURCE_COMMIT,
                required=True,
            )

        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual(evidence.status, "missing")
        self.assertTrue(evidence.details["nonWaivable"])
        gate = release_certification.evaluate_stable_supply_chain_gate(
            {evidence.id: evidence.to_json()}, settings
        )
        self.assertIsNotNone(gate)
        assert gate is not None
        self.assertEqual(gate.status, "fail")
        self.assertTrue(gate.release_blocker)
        self.assertEqual(
            gate.details["unwaivableFailureEvidenceIds"],
            [release_certification.STABLE_SUPPLY_CHAIN_EVIDENCE_ID],
        )

    def test_malformed_summary_fails_without_echoing_contents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "summary.json"
            write_json(path, {"privateToken": "must-not-be-reported"})

            evidence = release_certification.stable_supply_chain_evidence(
                path,
                root,
                root / "out",
                RELEASE_ID,
                BUILD_VERSION,
                SOURCE_COMMIT,
                SOURCE_REF,
                SOURCE_COMMIT,
                required=True,
            )

        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual(evidence.status, "fail")
        self.assertFalse(evidence.details["authenticated"])
        self.assertNotIn("must-not-be-reported", str(evidence.to_json()))

    def test_configured_gate_is_required_by_ecosystem_rc(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = _settings(root, root / "summary.json", required=False)

            evidence_ids = (
                release_certification.conditional_ecosystem_rc_required_evidence_ids(
                    settings
                )
            )
            gate_ids = release_certification.conditional_ecosystem_rc_required_gate_ids(
                settings, {}
            )

        self.assertIn(
            release_certification.STABLE_SUPPLY_CHAIN_EVIDENCE_ID, evidence_ids
        )
        self.assertIn(release_certification.STABLE_SUPPLY_CHAIN_GATE_ID, gate_ids)

    def test_pass_evidence_cannot_be_waived_or_downgraded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = _settings(root, root / "summary.json", required=True)
            item = release_certification.EvidenceItem(
                release_certification.STABLE_SUPPLY_CHAIN_EVIDENCE_ID,
                "pass",
                True,
                "Authenticated supply-chain evidence passed.",
                "stable-supply-chain-summary",
                {"authenticated": True, "promotionReady": True, "nonWaivable": True},
            )

            gate = release_certification.evaluate_stable_supply_chain_gate(
                {item.id: item.to_json()}, settings
            )

        self.assertIsNotNone(gate)
        assert gate is not None
        self.assertEqual(gate.status, "pass")
        self.assertFalse(gate.release_blocker)
        self.assertIn(
            release_certification.STABLE_SUPPLY_CHAIN_EVIDENCE_ID,
            release_certification.NONWAIVABLE_EVIDENCE_IDS,
        )


if __name__ == "__main__":
    unittest.main()

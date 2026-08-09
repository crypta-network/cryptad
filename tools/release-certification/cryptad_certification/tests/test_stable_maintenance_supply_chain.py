"""Stable maintenance integration with PR-289 supply-chain governance."""

from __future__ import annotations

import dataclasses
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptad_certification import selftest
from cryptad_certification.cli import build_parser
from cryptad_certification.engines import release_certification_core
from cryptad_certification.engines.stable_1_0_maintenance import (
    _supply_chain_companion_assets,
    _supply_chain_promotion_errors,
)
from cryptad_certification.engines.stable_1_0_maintenance_core import (
    Candidate,
    LoadedJson,
    Predecessor,
)
from cryptad_certification.engines.stable_1_0_rc_core import file_digest
from cryptad_certification.engines.stable_1_0_supply_chain import (
    EVIDENCE_IDS as SUPPLY_CHAIN_EVIDENCE_IDS,
)
from cryptad_certification.engines.stable_1_0_supply_chain_core import (
    PUBLICATION_ROLE_FILES,
    canonical_json_bytes as supply_chain_canonical_json_bytes,
    semantic_digest as supply_chain_semantic_digest,
    sha256_digest as supply_chain_sha256_digest,
)
from cryptad_certification.io import read_json, write_json
from cryptad_certification.manifest import COMMAND_NAMES
from cryptad_certification.models import RunContext
from cryptad_certification.tests.support import workspace_root
from cryptad_certification.tests.test_stable_maintenance import (
    BUILD,
    COMMIT,
    RELEASE_ID,
    _candidate,
    _context,
    _digest,
    _ga_and_predecessor,
)


def _supply_chain_summary(candidate: Candidate, predecessor: Predecessor) -> dict[str, object]:
    supply_policy = read_json(
        workspace_root()
        / "tools/release-certification/stable-1.0-supply-chain-policy.json"
    )
    assert isinstance(supply_policy, dict)
    package_projection = {
        "packages": sorted(
            [
                {
                    "packageKey": row["packageKey"],
                    "digest": row["digest"],
                }
                for row in candidate.assets
            ],
            key=lambda row: str(row["packageKey"]),
        )
    }
    value: dict[str, object] = {
        "schemaVersion": 1,
        "kind": "stable-1.0-supply-chain-promotion-summary",
        "releaseId": RELEASE_ID,
        "buildVersion": int(BUILD),
        "tag": f"v{BUILD}",
        "sourceCommit": COMMIT,
        "sourceRef": f"commit:{COMMIT}",
        "policyDigest": supply_policy["policyDigest"],
        "mode": "evaluate-promotion",
        "status": "pass",
        "promotionReady": True,
        "candidateIdentityDigest": supply_chain_sha256_digest(
            supply_chain_canonical_json_bytes(candidate.input_value)
        ),
        "candidateFreezeDigest": candidate.freeze_digest,
        "productDigest": candidate.product_digest,
        "predecessorReleaseId": predecessor.release_id,
        "predecessorBuildVersion": int(predecessor.build_version),
        "predecessorProductDigest": predecessor.product_digest,
        "packageMatrixDigest": supply_chain_sha256_digest(
            supply_chain_canonical_json_bytes(package_projection)
        ),
        "packageAuthenticationDigest": _digest("d"),
        "selectedSubjectInventoryDigest": _digest("1"),
        "vulnerabilitySummaryDigest": None,
        "vulnerabilityReverseIndexDigest": _digest("2"),
        "resolvedDependencySnapshotDigest": _digest("3"),
        "componentInventoryDigest": _digest("4"),
        "subjectInventoryDigest": _digest("5"),
        "sbomDigest": _digest("6"),
        "licenseInventoryDigest": _digest("7"),
        "buildMaterialsDigest": _digest("8"),
        "primaryBuilderReceiptDigest": _digest("9"),
        "verifierBuilderReceiptDigest": _digest("a"),
        "comparisonPlanDigest": _digest("b"),
        "reproducibilityResultDigest": _digest("c"),
        "evidence": [
            {"evidenceId": evidence_id, "status": "pass", "nonWaivable": True}
            for evidence_id in SUPPLY_CHAIN_EVIDENCE_IDS
            if evidence_id != "stable-supply-chain.publication"
        ],
        "blockers": [],
        "waivers": [],
        "artifacts": [
            {
                "name": role,
                "digest": supply_chain_sha256_digest(role.encode("utf-8")),
                "size": index + 1,
            }
            for index, role in enumerate(PUBLICATION_ROLE_FILES)
            if role != "supply-chain-summary"
        ],
        "redaction": {
            "status": "pass",
            "privatePathsExcluded": True,
            "credentialsExcluded": True,
            "privateUrisExcluded": True,
            "embargoedVulnerabilityDataExcluded": True,
            "sideEffectsPerformed": False,
        },
        "summaryDigest": _digest("0"),
    }
    value["summaryDigest"] = supply_chain_semantic_digest(value, "summaryDigest")
    return value


def _write_supply_chain_handoff(
    context: RunContext,
    path: Path,
    summary: dict[str, object],
) -> dict[str, object]:
    artifact_name = f"stable-1.0-supply-chain-{RELEASE_ID}-comparison"
    artifact_digest = _digest("d")
    metadata = context.manifest.policies["metadata"]
    metadata.update(
        {
            "stableSupplyChainRunId": "1001",
            "stableSupplyChainRunAttempt": "1",
            "stableSupplyChainArtifactName": artifact_name,
            "stableSupplyChainArtifactDigest": artifact_digest,
        }
    )
    handoff: dict[str, object] = {
        "schemaVersion": 1,
        "kind": "stable-1.0-supply-chain-promotion-handoff",
        "repository": "crypta-network/cryptad",
        "workflow": (
            "crypta-network/cryptad/.github/workflows/"
            f"stable-1.0-supply-chain.yml@{COMMIT}"
        ),
        "workflowCommit": COMMIT,
        "runId": "1001",
        "runAttempt": "1",
        "operation": "compare-evaluate",
        "releaseId": RELEASE_ID,
        "buildVersion": BUILD,
        "sourceCommit": COMMIT,
        "artifactName": artifact_name,
        "producerArtifactDigest": artifact_digest,
        "summaryFileName": "stable-1.0-supply-chain-summary.json",
        "summaryByteDigest": file_digest(path),
        "attestationSubjectDigest": file_digest(path),
        "attestationVerified": True,
        "denySelfHostedRunners": True,
        "authenticationStatus": "pass",
        "authenticationAlgorithm": "hmac-sha256",
        "authenticationTag": _digest("pending-supply-chain-handoff-tag"),
    }
    handoff["authenticationTag"] = (
        release_certification_core.stable_supply_chain_handoff_authentication_tag(
            handoff,
            b"stable-supply-chain-test-key-v1!",
        )
    )
    write_json(path.with_name("stable-1.0-supply-chain-summary-provenance.json"), handoff)
    return handoff


def _supply_chain_handoff_environment() -> dict[str, str]:
    return {
        release_certification_core.STABLE_SUPPLY_CHAIN_HANDOFF_KEY_ENV: (
            "c3RhYmxlLXN1cHBseS1jaGFpbi10ZXN0LWtleS12MSE="
        )
    }


class StableMaintenanceSupplyChainTest(unittest.TestCase):
    """Supply-chain promotion handoff and registration contracts."""

    def test_companion_assets_bind_policy_roles_and_exact_summary_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_target = (
                root
                / "tools/release-certification/stable-1.0-supply-chain-policy.json"
            )
            policy_target.parent.mkdir(parents=True)
            shutil.copyfile(
                workspace_root()
                / "tools/release-certification/stable-1.0-supply-chain-policy.json",
                policy_target,
            )
            candidate = _candidate(root)
            predecessor = _ga_and_predecessor()[1]
            value = _supply_chain_summary(candidate, predecessor)
            path = root / "stable-1.0-supply-chain-summary.json"
            write_json(path, value)
            loaded = LoadedJson(
                "supplyChainPromotionSummary", path, value, file_digest(path)
            )

            rows = _supply_chain_companion_assets(_context(root), loaded)
            summary_size = path.stat().st_size

        self.assertEqual([row["role"] for row in rows], list(PUBLICATION_ROLE_FILES))
        self.assertEqual(rows[-1]["digest"], loaded.digest)
        self.assertEqual(rows[-1]["sizeBytes"], summary_size)
        self.assertEqual(
            rows[-1]["publicUri"],
            "https://github.com/crypta-network/cryptad/releases/download/"
            f"v{BUILD}/stable-1.0-supply-chain-summary.json",
        )

    def test_supply_chain_summary_binds_exact_candidate_and_predecessor(self) -> None:
        """Pre-activation frozen candidates retain their historical validation contract."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_target = (
                root
                / "tools/release-certification/stable-1.0-supply-chain-policy.json"
            )
            policy_target.parent.mkdir(parents=True)
            shutil.copyfile(
                workspace_root()
                / "tools/release-certification/stable-1.0-supply-chain-policy.json",
                policy_target,
            )
            candidate = _candidate(root)
            predecessor = _ga_and_predecessor()[1]
            value = _supply_chain_summary(candidate, predecessor)
            path = root / "stable-1.0-supply-chain-summary.json"
            write_json(path, value)
            loaded = LoadedJson(
                "supplyChainPromotionSummary", path, value, file_digest(path)
            )

            errors = _supply_chain_promotion_errors(
                _context(root), loaded, candidate, predecessor
            )

        self.assertEqual(errors, [])

    def test_governed_supply_chain_summary_requires_protected_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_target = (
                root
                / "tools/release-certification/stable-1.0-supply-chain-policy.json"
            )
            policy_target.parent.mkdir(parents=True)
            shutil.copyfile(
                workspace_root()
                / "tools/release-certification/stable-1.0-supply-chain-policy.json",
                policy_target,
            )
            candidate = dataclasses.replace(
                _candidate(root), frozen_at="2026-08-04T00:00:00Z"
            )
            predecessor = _ga_and_predecessor()[1]
            value = _supply_chain_summary(candidate, predecessor)
            path = root / "stable-1.0-supply-chain-summary.json"
            write_json(path, value)
            loaded = LoadedJson(
                "supplyChainPromotionSummary", path, value, file_digest(path)
            )

            errors = _supply_chain_promotion_errors(
                _context(root), loaded, candidate, predecessor
            )

        self.assertIn(
            "Stable supply-chain summary lacks its protected producer handoff", errors
        )

    def test_governed_supply_chain_summary_authenticates_exact_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_target = (
                root
                / "tools/release-certification/stable-1.0-supply-chain-policy.json"
            )
            policy_target.parent.mkdir(parents=True)
            shutil.copyfile(
                workspace_root()
                / "tools/release-certification/stable-1.0-supply-chain-policy.json",
                policy_target,
            )
            candidate = dataclasses.replace(
                _candidate(root), frozen_at="2026-08-04T00:00:00Z"
            )
            predecessor = _ga_and_predecessor()[1]
            value = _supply_chain_summary(candidate, predecessor)
            path = root / "stable-1.0-supply-chain-summary.json"
            write_json(path, value)
            context = _context(root)
            _write_supply_chain_handoff(context, path, value)
            loaded = LoadedJson(
                "supplyChainPromotionSummary", path, value, file_digest(path)
            )

            with mock.patch.dict(os.environ, _supply_chain_handoff_environment()):
                errors = _supply_chain_promotion_errors(
                    context, loaded, candidate, predecessor
                )

        self.assertEqual(errors, [])

    def test_governed_supply_chain_summary_rejects_unkeyed_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_target = (
                root
                / "tools/release-certification/stable-1.0-supply-chain-policy.json"
            )
            policy_target.parent.mkdir(parents=True)
            shutil.copyfile(
                workspace_root()
                / "tools/release-certification/stable-1.0-supply-chain-policy.json",
                policy_target,
            )
            candidate = dataclasses.replace(
                _candidate(root), frozen_at="2026-08-04T00:00:00Z"
            )
            predecessor = _ga_and_predecessor()[1]
            value = _supply_chain_summary(candidate, predecessor)
            path = root / "stable-1.0-supply-chain-summary.json"
            write_json(path, value)
            context = _context(root)
            _write_supply_chain_handoff(context, path, value)
            loaded = LoadedJson(
                "supplyChainPromotionSummary", path, value, file_digest(path)
            )

            with mock.patch.dict(os.environ, {}, clear=True):
                errors = _supply_chain_promotion_errors(
                    context, loaded, candidate, predecessor
                )

        self.assertIn(
            "configured supply-chain handoff authentication key is invalid",
            errors,
        )

    def test_governed_supply_chain_summary_rejects_manifest_handoff_substitution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_target = (
                root
                / "tools/release-certification/stable-1.0-supply-chain-policy.json"
            )
            policy_target.parent.mkdir(parents=True)
            shutil.copyfile(
                workspace_root()
                / "tools/release-certification/stable-1.0-supply-chain-policy.json",
                policy_target,
            )
            candidate = dataclasses.replace(
                _candidate(root), frozen_at="2026-08-04T00:00:00Z"
            )
            predecessor = _ga_and_predecessor()[1]
            value = _supply_chain_summary(candidate, predecessor)
            path = root / "stable-1.0-supply-chain-summary.json"
            write_json(path, value)
            context = _context(root)
            _write_supply_chain_handoff(context, path, value)
            context.manifest.policies["metadata"][
                "stableSupplyChainArtifactDigest"
            ] = _digest("e")
            loaded = LoadedJson(
                "supplyChainPromotionSummary", path, value, file_digest(path)
            )

            with mock.patch.dict(os.environ, _supply_chain_handoff_environment()):
                errors = _supply_chain_promotion_errors(
                    context, loaded, candidate, predecessor
                )

        self.assertIn(
            "Stable supply-chain producer handoff differs from manifest "
            "stableSupplyChainArtifactDigest",
            errors,
        )

    def test_supply_chain_promotion_does_not_accept_publication_as_passing(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_target = (
                root
                / "tools/release-certification/stable-1.0-supply-chain-policy.json"
            )
            policy_target.parent.mkdir(parents=True)
            shutil.copyfile(
                workspace_root()
                / "tools/release-certification/stable-1.0-supply-chain-policy.json",
                policy_target,
            )
            candidate = _candidate(root)
            predecessor = _ga_and_predecessor()[1]
            value = _supply_chain_summary(candidate, predecessor)
            value["evidence"].append(
                {
                    "evidenceId": "stable-supply-chain.publication",
                    "status": "pass",
                    "nonWaivable": True,
                }
            )
            value["summaryDigest"] = supply_chain_semantic_digest(
                value, "summaryDigest"
            )
            path = root / "stable-1.0-supply-chain-summary.json"
            write_json(path, value)
            loaded = LoadedJson(
                "supplyChainPromotionSummary", path, value, file_digest(path)
            )

            errors = _supply_chain_promotion_errors(
                _context(root), loaded, candidate, predecessor
            )

        self.assertIn(
            "Stable supply-chain promotion summary falsely claims publication passed",
            errors,
        )

    def test_supply_chain_summary_rejects_substituted_predecessor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_target = (
                root
                / "tools/release-certification/stable-1.0-supply-chain-policy.json"
            )
            policy_target.parent.mkdir(parents=True)
            shutil.copyfile(
                workspace_root()
                / "tools/release-certification/stable-1.0-supply-chain-policy.json",
                policy_target,
            )
            candidate = _candidate(root)
            predecessor = _ga_and_predecessor()[1]
            value = _supply_chain_summary(candidate, predecessor)
            value["predecessorProductDigest"] = _digest("d")
            value["summaryDigest"] = supply_chain_semantic_digest(
                value, "summaryDigest"
            )
            path = root / "stable-1.0-supply-chain-summary.json"
            write_json(path, value)
            loaded = LoadedJson(
                "supplyChainPromotionSummary", path, value, file_digest(path)
            )

            errors = _supply_chain_promotion_errors(
                _context(root), loaded, candidate, predecessor
            )

        self.assertIn(
            "Stable supply-chain summary predecessorProductDigest differs", errors
        )

    def test_command_and_selftest_are_registered(self) -> None:
        self.assertIn("stable-maintenance", COMMAND_NAMES)
        self.assertEqual(
            selftest.SUITE_MODULES["stable-maintenance"],
            [
                "cryptad_certification.tests.test_stable_maintenance",
                "cryptad_certification.tests.test_stable_maintenance_supply_chain",
                "cryptad_certification.tests.test_stable_maintenance_authorization_compatibility",
                "cryptad_certification.tests.test_stable_maintenance_publication",
                "cryptad_certification.tests.test_stable_maintenance_workflows",
            ],
        )
        parsed = build_parser().parse_args(["stable-maintenance", "--self-test"])
        self.assertEqual(parsed.command, "stable-maintenance")
        self.assertTrue(parsed.self_test)

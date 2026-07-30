"""Cross-component regression tests for Stable backport predecessor handoffs."""

from __future__ import annotations

import copy
import datetime as dt
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from cryptad_certification import cli
from cryptad_certification.io import read_json
from cryptad_certification.models import OutputSpec, ReleaseSpec, RunManifest

from ..engines import stable_1_0_backport as engine
from ..engines.stable_1_0_backport_core import (
    phase_intake_composition_digest,
    permitted_carried_obligation_ids,
)
from ..engines.stable_1_0_rc_core import ValidationState

RELEASE_CERTIFICATION_ROOT = Path(__file__).resolve().parents[2]
DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64


class StableBackportPredecessorIntegrationTest(unittest.TestCase):
    def test_authenticated_closure_unblocks_routine_lane_and_binds_digest(self) -> None:
        baseline = {
            "hotfixFollowUp": {
                "status": "open",
                "blocksRoutineMaintenance": True,
            }
        }
        closed_follow_up = {
            "status": "closed",
            "blocksRoutineMaintenance": False,
        }
        authority = SimpleNamespace(
            outstanding_follow_up=closed_follow_up,
            follow_up_closure_digest=DIGEST,
        )
        closure_loaded = (Path("closure.json"), {"status": "closed"}, DIGEST)

        effective, closure_digest = (
            engine._closure_adjusted_predecessor_baseline(  # noqa: SLF001
                baseline,
                authority,
                closure_loaded,
            )
        )
        queue = {"obligations": [], "carriedObligationIds": []}
        policy = read_json(
            RELEASE_CERTIFICATION_ROOT
            / "stable-1.0-backport-release-train-policy.json"
        )
        permitted, errors = permitted_carried_obligation_ids(
            queue,
            None,
            lane="routine-maintenance",
            policy=policy,
            predecessor_baseline=effective,
        )

        self.assertEqual(permitted, [])
        self.assertEqual(errors, [])
        self.assertEqual(closure_digest, DIGEST)
        self.assertEqual(baseline["hotfixFollowUp"]["status"], "open")
        self.assertEqual(effective["hotfixFollowUp"]["status"], "closed")
        unbound_queue = {
            "policyDigest": DIGEST,
            "repositoryIdentity": "github.com/crypta-network/cryptad",
            "queueId": "stable-queue-build-301",
            "previousQueueDigest": OTHER_DIGEST,
            "latestMaintenancePointerDigest": DIGEST,
            "hotfixFollowUpClosureDigest": None,
            "lifecycleLedgerDigest": DIGEST,
            "fixes": [],
            "obligations": [],
        }
        bound_queue = copy.deepcopy(unbound_queue)
        bound_queue["hotfixFollowUpClosureDigest"] = closure_digest
        self.assertNotEqual(
            phase_intake_composition_digest(unbound_queue),
            phase_intake_composition_digest(bound_queue),
        )
        with self.assertRaisesRegex(
            ValueError,
            "closure differs from the authenticated predecessor authority",
        ):
            engine._closure_adjusted_predecessor_baseline(  # noqa: SLF001
                baseline,
                authority,
                (Path("closure.json"), {"status": "closed"}, OTHER_DIGEST),
            )

    def test_optional_closure_is_loaded_for_exact_source_provenance(self) -> None:
        closure = (Path("closure.json"), {"status": "closed"}, DIGEST)

        def load(_context: object, key: str, *, required: bool) -> object:
            if key == "hotfixFollowUpClosure":
                self.assertFalse(required)
                return closure
            return None

        with mock.patch.object(engine, "load_object", side_effect=load):
            inputs = engine._load_inputs(mock.sentinel.context)  # noqa: SLF001

        self.assertEqual(inputs["hotfixFollowUpClosure"], closure)

    def test_full_validation_binds_closure_without_public_disclosure(self) -> None:
        validation = engine._build_validation(  # noqa: SLF001
            generated_at="2026-01-15T12:00:00Z",
            mode="evaluate",
            train_id="stable-train-301",
            release={
                "releaseId": "stable-maintenance-301",
                "releaseClass": "maintenance",
                "buildVersion": "301",
                "tag": "v301",
            },
            policy_digest=DIGEST,
            queue_digest=DIGEST,
            plan_digest=DIGEST,
            candidate_digest=DIGEST,
            predecessor_commit="a" * 40,
            candidate_commit="b" * 40,
            accepted=[],
            deferred=[],
            evidence_results=[],
            unaccounted=[],
            state=ValidationState(),
            authorization=None,
            hotfix_follow_up_closure_digest=OTHER_DIGEST,
        )
        public = engine._public_validation(  # noqa: SLF001
            validation,
            [],
            DIGEST,
        )

        self.assertEqual(
            validation["hotfixFollowUpClosureDigest"],
            OTHER_DIGEST,
        )
        self.assertNotIn("hotfixFollowUpClosureDigest", public)

    def test_train_authorization_cannot_predate_the_closure(self) -> None:
        cutoff = engine._latest_authorized_input_time(  # noqa: SLF001
            {"generatedAt": "2026-01-15T09:00:00Z", "fixes": []},
            dt.datetime(2026, 1, 15, 10, tzinfo=dt.timezone.utc),
            hotfix_follow_up_closure={
                "generatedAt": "2026-01-15T10:30:00Z",
                "closedAt": "2026-01-15T11:00:00Z",
            },
        )

        self.assertEqual(
            cutoff,
            dt.datetime(2026, 1, 15, 11, tzinfo=dt.timezone.utc),
        )


class StableBackportManifestIntegrationTest(unittest.TestCase):
    @staticmethod
    def _manifest() -> RunManifest:
        required_inputs = {
            "stableBackportPolicy",
            "stableFixIntake",
            "stableGaPromotionSummary",
            "stableGaValidation",
            "stableGaAuthorizationSummary",
            "stableGaPublicationPlan",
            "stableGaPublicationReceipt",
            "stableGaChecksums",
            "stableGaProvenance",
            "stableGaMaintenanceBaseline",
            "stableLifecyclePolicy",
            "predecessorPublicationReceipt",
            "predecessorBaseline",
            "previousStableLifecycleLedger",
            "previousStableLifecycleDescriptor",
            "previousStableLifecycleAuthorization",
            "previousStableLifecyclePublicationPlan",
            "previousStableLifecyclePublicationReceipt",
            "stableLifecyclePublicObservationReceipt",
        }
        return RunManifest(
            path=Path("manifest.json"),
            release=ReleaseSpec("stable-maintenance-301", "301", "stable-review"),
            output=OutputSpec(Path("build/release-certification")),
            requirements={},
            inputs={key: f"inputs/{key}.json" for key in required_inputs},
            policies={
                "releaseClass": "maintenance",
                "backportReleaseLane": "routine-maintenance",
                "candidateSourceBranch": "release/301",
                "candidateSourceCommit": "b" * 40,
                "candidateSourceRef": "commit:" + "b" * 40,
                "candidateBaseCommit": "a" * 40,
                "developmentLineageCommit": "a" * 40,
                "expectedPredecessorBuild": "300",
                "expectedPredecessorReleaseId": "stable-1-0-ga-300",
                "expectedPredecessorProductDigest": DIGEST,
            },
            execution={},
            commands={"stable-backport": {"mode": "evaluate"}},
        )

    def test_manifest_requires_complete_predecessor_identity(self) -> None:
        manifest = self._manifest()
        cli._validate_stable_backport_manifest(manifest)  # noqa: SLF001
        for field in (
            "expectedPredecessorReleaseId",
            "expectedPredecessorProductDigest",
        ):
            with self.subTest(field=field):
                incomplete = copy.deepcopy(manifest)
                incomplete.policies.pop(field)
                with self.assertRaisesRegex(
                    ValueError,
                    "complete canonical immediate predecessor",
                ):
                    cli._validate_stable_backport_manifest(  # noqa: SLF001
                        incomplete
                    )

    def test_ga_genesis_example_names_all_predecessor_identity_placeholders(
        self,
    ) -> None:
        example = read_json(
            RELEASE_CERTIFICATION_ROOT
            / "manifests/stable-1.0-backport.example.json"
        )

        self.assertEqual(
            {
                key
                for key in example["policies"]
                if key.startswith("expectedPredecessor")
            },
            {
                "expectedPredecessorBuild",
                "expectedPredecessorProductDigest",
                "expectedPredecessorReleaseId",
            },
        )


if __name__ == "__main__":
    unittest.main()

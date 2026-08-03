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
    FIX_STATES,
    phase_intake_composition_digest,
    permitted_carried_obligation_ids,
)
from ..engines.stable_1_0_rc_core import ValidationState

RELEASE_CERTIFICATION_ROOT = Path(__file__).resolve().parents[2]
DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
THIRD_DIGEST = "sha256:" + "c" * 64
NOW = dt.datetime(2026, 1, 15, 12, tzinfo=dt.timezone.utc)


class StableBackportSelectedScopeIntegrationTest(unittest.TestCase):
    def test_exact_overdue_high_remediation_can_use_routine_train(self) -> None:
        incident_id = "sv-overduehighcase0001"
        binding = {
            "incidentOpaqueId": incident_id,
            "severity": "high",
            "vulnerabilityPublicProjectionDigest": DIGEST,
        }
        summary = {
            "caseSummaries": [
                {
                    "caseOpaqueId": incident_id,
                    "severity": "high",
                    "publicProjectionDigest": DIGEST,
                    "blockingStablePromotion": True,
                }
            ],
            "blockingStablePromotion": True,
            "blockingCaseOpaqueIds": [incident_id],
        }
        context = SimpleNamespace(manifest=SimpleNamespace(policies={}))
        with mock.patch(
            "cryptad_certification.stable_vulnerability_summary.load_summary",
            return_value=(summary, []),
        ):
            errors = engine.promotion_errors(
                context,
                release_class="routine-maintenance",
                incident_ids={incident_id},
                security_bindings=[binding],
                evaluation_clock=NOW,
            )

        self.assertEqual(errors, [])

    def test_hotfix_cannot_relabel_high_case_as_critical(self) -> None:
        incident_id = "sv-overduehighcase0001"
        summary = {
            "caseSummaries": [
                {
                    "caseOpaqueId": incident_id,
                    "severity": "high",
                    "publicProjectionDigest": DIGEST,
                    "blockingStablePromotion": True,
                }
            ],
            "blockingStablePromotion": True,
            "blockingCaseOpaqueIds": [incident_id],
        }
        binding = {
            "incidentOpaqueId": incident_id,
            "severity": "critical",
            "vulnerabilityPublicProjectionDigest": DIGEST,
        }
        context = SimpleNamespace(manifest=SimpleNamespace(policies={}))

        with mock.patch(
            "cryptad_certification.stable_vulnerability_summary.load_summary",
            return_value=(summary, []),
        ):
            errors = engine.promotion_errors(
                context,
                release_class="security-hotfix",
                incident_ids={incident_id},
                security_bindings=[binding],
                evaluation_clock=NOW,
            )

        self.assertIn(
            "PR-288 security fix severity differs from the authenticated case summary",
            errors,
        )

    def test_hotfix_can_remediate_one_of_multiple_blocking_cases(self) -> None:
        selected_id = "sv-selectedcritical0001"
        unrelated_id = "sv-unrelatedcritical01"
        binding = {
            "incidentOpaqueId": selected_id,
            "severity": "critical",
            "vulnerabilityPublicProjectionDigest": DIGEST,
        }
        context = SimpleNamespace(manifest=SimpleNamespace(policies={}))

        for unrelated_severity in ("critical", "high"):
            summary = {
                "caseSummaries": [
                    {
                        "caseOpaqueId": selected_id,
                        "severity": "critical",
                        "publicProjectionDigest": DIGEST,
                        "blockingStablePromotion": True,
                    },
                    {
                        "caseOpaqueId": unrelated_id,
                        "severity": unrelated_severity,
                        "publicProjectionDigest": OTHER_DIGEST,
                        "blockingStablePromotion": True,
                    },
                ],
                "blockingStablePromotion": True,
                "blockingCaseOpaqueIds": [selected_id, unrelated_id],
            }
            with self.subTest(
                unrelated_severity=unrelated_severity
            ), mock.patch(
                "cryptad_certification.stable_vulnerability_summary.load_summary",
                return_value=(summary, []),
            ):
                errors = engine.promotion_errors(
                    context,
                    release_class="security-hotfix",
                    incident_ids={selected_id},
                    security_bindings=[binding],
                    evaluation_clock=NOW,
                )

            self.assertEqual(errors, [])

    def test_nonblocking_fix_still_binds_protected_case_severity(self) -> None:
        incident_id = "sv-nonblockingcase00001"
        summary = {
            "caseSummaries": [
                {
                    "caseOpaqueId": incident_id,
                    "severity": "moderate",
                    "publicProjectionDigest": DIGEST,
                    "blockingStablePromotion": False,
                }
            ],
            "blockingStablePromotion": False,
            "blockingCaseOpaqueIds": [],
        }
        binding = {
            "incidentOpaqueId": incident_id,
            "severity": "high",
            "vulnerabilityPublicProjectionDigest": DIGEST,
        }
        context = SimpleNamespace(manifest=SimpleNamespace(policies={}))

        with mock.patch(
            "cryptad_certification.stable_vulnerability_summary.load_summary",
            return_value=(summary, []),
        ):
            errors = engine.promotion_errors(
                context,
                release_class="routine-maintenance",
                incident_ids={incident_id},
                security_bindings=[binding],
                evaluation_clock=NOW,
            )

        self.assertIn(
            "PR-288 security fix severity differs from the authenticated case summary",
            errors,
        )

    def test_routine_train_cannot_carry_unrelated_or_critical_blocker(self) -> None:
        selected_id = "sv-selectedhighcase0001"
        context = SimpleNamespace(manifest=SimpleNamespace(policies={}))
        binding = {
            "incidentOpaqueId": selected_id,
            "severity": "high",
            "vulnerabilityPublicProjectionDigest": DIGEST,
        }
        scenarios = (
            ("sv-unrelatedhighcase01", "high"),
            (selected_id, "critical"),
        )
        for blocking_id, severity in scenarios:
            summary = {
                "caseSummaries": [
                    {
                        "caseOpaqueId": blocking_id,
                        "severity": severity,
                        "publicProjectionDigest": DIGEST,
                        "blockingStablePromotion": True,
                    }
                ],
                "blockingStablePromotion": True,
                "blockingCaseOpaqueIds": [blocking_id],
            }
            with self.subTest(blocking_id=blocking_id, severity=severity), mock.patch(
                "cryptad_certification.stable_vulnerability_summary.load_summary",
                return_value=(summary, []),
            ):
                errors = engine.promotion_errors(
                    context,
                    release_class="routine-maintenance",
                    incident_ids={selected_id},
                    security_bindings=[binding],
                    evaluation_clock=NOW,
                )

            self.assertIn(
                "Stable vulnerability summary blocks routine Stable promotion",
                errors,
            )

    def test_completion_does_not_reapply_current_promotion_blockers(self) -> None:
        context = SimpleNamespace(manifest=SimpleNamespace(policies={}))
        with mock.patch.object(
            engine,
            "promotion_errors",
            return_value=["current blocker"],
        ) as promotion_gate:
            errors = engine._current_vulnerability_promotion_errors(  # noqa: SLF001
                context,
                mode="verify-release-completion",
                release_class="security-hotfix",
                incident_ids={"sv-abcdefghijklmnopqrst"},
                security_bindings=[],
                evaluation_clock=NOW,
            )

        self.assertEqual([], errors)
        promotion_gate.assert_not_called()

    def test_unpublished_train_still_uses_the_current_promotion_gate(self) -> None:
        context = SimpleNamespace(manifest=SimpleNamespace(policies={}))
        with mock.patch.object(
            engine,
            "promotion_errors",
            return_value=["current blocker"],
        ) as promotion_gate:
            errors = engine._current_vulnerability_promotion_errors(  # noqa: SLF001
                context,
                mode="validate-authorization",
                release_class="routine-maintenance",
                incident_ids=set(),
                security_bindings=[],
                evaluation_clock=NOW,
            )

        self.assertEqual(["current blocker"], errors)
        promotion_gate.assert_called_once_with(
            context,
            release_class="routine-maintenance",
            incident_ids=set(),
            security_bindings=[],
            evaluation_clock=NOW,
        )

    def test_vulnerability_blocker_scope_excludes_unselected_incidents(self) -> None:
        selected_incident = "sv-selectedincident0001"
        deferred_incident = "sv-deferredincident0001"
        opposite_lane_incident = "sv-routineincident00001"
        fixes = [
            {
                "classification": "security-fix",
                "releaseLane": "security-hotfix",
                "state": "accepted",
                "security": {
                    "incidentOpaqueId": selected_incident,
                    "vulnerabilityPublicProjectionDigest": DIGEST,
                },
            },
            {
                "classification": "security-fix",
                "releaseLane": None,
                "state": "deferred",
                "security": {
                    "incidentOpaqueId": deferred_incident,
                    "vulnerabilityPublicProjectionDigest": OTHER_DIGEST,
                },
            },
            {
                "classification": "security-fix",
                "releaseLane": "routine-maintenance",
                "state": "verified",
                "security": {
                    "incidentOpaqueId": opposite_lane_incident,
                    "vulnerabilityPublicProjectionDigest": THIRD_DIGEST,
                },
            },
        ]
        selected, _deferred, _rejected, _superseded = engine._fix_sets(  # noqa: SLF001
            fixes,
            "security-hotfix",
        )
        incident_ids, bindings = engine._vulnerability_promotion_scope(  # noqa: SLF001
            selected
        )

        self.assertEqual(incident_ids, {selected_incident})
        self.assertEqual(
            [row["incidentOpaqueId"] for row in bindings],
            [selected_incident],
        )
        context = SimpleNamespace(manifest=SimpleNamespace(policies={}))
        for blocking_incident in (deferred_incident, opposite_lane_incident):
            with self.subTest(blocking_incident=blocking_incident), mock.patch(
                "cryptad_certification.stable_vulnerability_summary.load_summary",
                return_value=(
                    {
                        "caseSummaries": [
                            {
                                "caseOpaqueId": selected_incident,
                                "severity": "critical",
                                "publicProjectionDigest": DIGEST,
                            }
                        ],
                        "blockingStablePromotion": True,
                        "blockingCaseOpaqueIds": [blocking_incident],
                    },
                    [],
                ),
            ):
                errors = engine.promotion_errors(
                    context,
                    release_class="security-hotfix",
                    incident_ids=incident_ids,
                    security_bindings=bindings,
                    evaluation_clock=NOW,
                )

            self.assertIn(
                "security-hotfix train does not carry exactly one authenticated "
                "blocking vulnerability case",
                errors,
            )

    def test_summary_fix_counts_account_for_every_closed_state(self) -> None:
        fixes = [{"state": state} for state in FIX_STATES]

        counts = engine._fix_counts(fixes)  # noqa: SLF001

        self.assertEqual(counts["total"], len(FIX_STATES))
        self.assertEqual(
            counts["total"],
            sum(value for key, value in counts.items() if key != "total"),
        )
        for state in FIX_STATES:
            self.assertEqual(counts[state], 1)


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

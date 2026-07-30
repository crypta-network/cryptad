"""Queue immutability regression tests for Stable 1.0 release-train governance."""

from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest

from cryptad_certification.stable_backport_git import GitInspector

from ..engines import stable_1_0_backport as engine
from ..engines.stable_1_0_backport_core import (
    build_queue,
    canonical_identity_digest,
    intake_errors,
    semantic_digest,
)
from .test_stable_backport import (
    FIX_ID,
    GENERATED,
    NOW,
    Fixture,
    _bind_intake_evidence,
    _digest,
    _fix,
    _intake,
    _security_fix,
)


class StableBackportQueueIntegrityTest(unittest.TestCase):
    def test_rejected_fixes_reenter_triage_without_clearing_critical_scope(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            inspector = GitInspector(
                fixture.root,
                expected_repository_identity="github.com/crypta-network/cryptad",
            )
            for critical in (False, True):
                with self.subTest(critical=critical):
                    rejected = (
                        _security_fix(
                            inspector,
                            fixture.fix_commit,
                            fixture.candidate,
                        )
                        if critical
                        else _fix(
                            inspector,
                            fixture.fix_commit,
                            fixture.candidate,
                        )
                    )
                    rejected["stateTransitions"] = rejected[
                        "stateTransitions"
                    ][:2]
                    rejected["stateTransitions"].append(
                        {
                            "sequence": 2,
                            "from": "triaged",
                            "to": "rejected",
                            "occurredAt": "2026-01-15T04:00:00Z",
                            "actorRole": (
                                "stable-security-decision-manager"
                                if critical
                                else "stable-triage-manager"
                            ),
                            "reasonCode": "not-reproducible",
                            "evidenceDigest": _digest("d"),
                        }
                    )
                    rejected["state"] = "rejected"
                    if not critical:
                        rejected["disposition"] = "rejected"
                        rejected["releaseLane"] = None
                    rejected_intake = _intake(
                        fixture.policy_digest, rejected
                    )
                    rejected_queue, errors = build_queue(
                        rejected_intake,
                        None,
                        policy_digest=fixture.policy_digest,
                        latest_maintenance_pointer_digest=_digest("b"),
                        lifecycle_ledger_digest=_digest("d"),
                        repository_identity="github.com/crypta-network/cryptad",
                        candidate_commit=fixture.candidate,
                    )
                    self.assertEqual(errors, [])
                    self.assertEqual(
                        rejected_queue["criticalFixIds"],
                        [FIX_ID] if critical else [],
                    )

                    retriaged = copy.deepcopy(rejected)
                    retriaged["state"] = "triaged"
                    retriaged["stateTransitions"].append(
                        {
                            "sequence": len(retriaged["stateTransitions"]),
                            "from": "rejected",
                            "to": "triaged",
                            "occurredAt": GENERATED,
                            "actorRole": (
                                "stable-security-decision-manager"
                                if critical
                                else "stable-triage-manager"
                            ),
                            "reasonCode": "new-evidence-authorized",
                            "evidenceDigest": _digest("e"),
                        }
                    )
                    if not critical:
                        retriaged["disposition"] = "routine-maintenance"
                        retriaged["releaseLane"] = "routine-maintenance"
                    retriaged_intake = _intake(
                        fixture.policy_digest, retriaged
                    )
                    retriaged_intake["previousQueueDigest"] = rejected_queue[
                        "queueDigest"
                    ]
                    _bind_intake_evidence(
                        retriaged_intake,
                        rejected_queue,
                        policy_digest=fixture.policy_digest,
                        candidate_commit=fixture.candidate,
                    )
                    self.assertEqual(
                        intake_errors(
                            retriaged_intake,
                            fixture.policy,
                            policy_digest=fixture.policy_digest,
                            repository_identity=(
                                "github.com/crypta-network/cryptad"
                            ),
                            now=NOW,
                        ),
                        [],
                    )

                    retriaged_queue, errors = build_queue(
                        retriaged_intake,
                        rejected_queue,
                        policy_digest=fixture.policy_digest,
                        latest_maintenance_pointer_digest=_digest("b"),
                        lifecycle_ledger_digest=_digest("d"),
                        repository_identity="github.com/crypta-network/cryptad",
                        candidate_commit=fixture.candidate,
                    )

                    self.assertEqual(errors, [])
                    self.assertEqual(
                        retriaged_queue["criticalFixIds"],
                        [FIX_ID] if critical else [],
                    )
                    self.assertEqual(
                        retriaged_queue["fixes"][0]["state"], "triaged"
                    )

    def test_obligation_resolution_requires_new_and_then_immutable_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            first, errors = build_queue(
                fixture.intake,
                None,
                policy_digest=fixture.policy_digest,
                latest_maintenance_pointer_digest=_digest("b"),
                lifecycle_ledger_digest=_digest("d"),
                repository_identity="github.com/crypta-network/cryptad",
                candidate_commit=fixture.candidate,
            )
            self.assertEqual(errors, [])
            obligation = {
                "obligationId": "reconcile-develop-301",
                "obligationType": "post-release-develop-merge",
                "sourceTrainId": "stable-train-301",
                "sourceFixIds": [FIX_ID],
                "status": "open",
                "generatedAt": GENERATED,
                "resolvedAt": None,
                "evidenceDigest": _digest("d"),
            }
            open_intake = copy.deepcopy(fixture.intake)
            open_intake["previousQueueDigest"] = first["queueDigest"]
            open_intake["obligations"] = [obligation]
            _bind_intake_evidence(
                open_intake,
                first,
                policy_digest=fixture.policy_digest,
                candidate_commit=fixture.candidate,
            )
            opened, errors = build_queue(
                open_intake,
                first,
                policy_digest=fixture.policy_digest,
                latest_maintenance_pointer_digest=_digest("b"),
                lifecycle_ledger_digest=_digest("d"),
                repository_identity="github.com/crypta-network/cryptad",
                candidate_commit=fixture.candidate,
            )
            self.assertEqual(errors, [])

            reused_intake = copy.deepcopy(open_intake)
            reused_intake["previousQueueDigest"] = opened["queueDigest"]
            reused_intake["obligations"][0]["status"] = "resolved"
            reused_intake["obligations"][0]["resolvedAt"] = (
                "2026-01-15T12:00:00Z"
            )
            _bind_intake_evidence(
                reused_intake,
                opened,
                policy_digest=fixture.policy_digest,
                candidate_commit=fixture.candidate,
            )
            _reused, errors = build_queue(
                reused_intake,
                opened,
                policy_digest=fixture.policy_digest,
                latest_maintenance_pointer_digest=_digest("b"),
                lifecycle_ledger_digest=_digest("d"),
                repository_identity="github.com/crypta-network/cryptad",
                candidate_commit=fixture.candidate,
            )
            self.assertTrue(any("new exact evidence" in error for error in errors))

            resolved_intake = copy.deepcopy(reused_intake)
            resolved_intake["obligations"][0]["evidenceDigest"] = _digest("e")
            _bind_intake_evidence(
                resolved_intake,
                opened,
                policy_digest=fixture.policy_digest,
                candidate_commit=fixture.candidate,
            )
            resolved, errors = build_queue(
                resolved_intake,
                opened,
                policy_digest=fixture.policy_digest,
                latest_maintenance_pointer_digest=_digest("b"),
                lifecycle_ledger_digest=_digest("d"),
                repository_identity="github.com/crypta-network/cryptad",
                candidate_commit=fixture.candidate,
            )
            self.assertEqual(errors, [])

            rewritten_intake = copy.deepcopy(resolved_intake)
            rewritten_intake["previousQueueDigest"] = resolved["queueDigest"]
            rewritten_intake["obligations"][0]["evidenceDigest"] = _digest("f")
            rewritten_intake["obligations"][0]["resolvedAt"] = (
                "2026-01-15T12:30:00Z"
            )
            _bind_intake_evidence(
                rewritten_intake,
                resolved,
                policy_digest=fixture.policy_digest,
                candidate_commit=fixture.candidate,
            )
            _rewritten, errors = build_queue(
                rewritten_intake,
                resolved,
                policy_digest=fixture.policy_digest,
                latest_maintenance_pointer_digest=_digest("b"),
                lifecycle_ledger_digest=_digest("d"),
                repository_identity="github.com/crypta-network/cryptad",
                candidate_commit=fixture.candidate,
            )
            self.assertTrue(
                any("rewrites its resolution evidence" in error for error in errors)
            )

    def test_landed_fix_provenance_is_immutable_across_queue_transitions(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            first, errors = build_queue(
                fixture.intake,
                None,
                policy_digest=fixture.policy_digest,
                latest_maintenance_pointer_digest=_digest("b"),
                lifecycle_ledger_digest=_digest("d"),
                repository_identity="github.com/crypta-network/cryptad",
                candidate_commit=fixture.candidate,
            )
            self.assertEqual(errors, [])
            changed_intake = copy.deepcopy(fixture.intake)
            changed_intake["previousQueueDigest"] = first["queueDigest"]
            changed_intake["fixes"][0]["provenance"][
                "reviewerAuthorizationDigest"
            ] = _digest("f")
            _bind_intake_evidence(
                changed_intake,
                first,
                policy_digest=fixture.policy_digest,
                candidate_commit=fixture.candidate,
            )

            _changed, errors = build_queue(
                changed_intake,
                first,
                policy_digest=fixture.policy_digest,
                latest_maintenance_pointer_digest=_digest("b"),
                lifecycle_ledger_digest=_digest("d"),
                repository_identity="github.com/crypta-network/cryptad",
                candidate_commit=fixture.candidate,
            )

            self.assertTrue(
                any("rewrites immutable landed provenance" in error for error in errors)
            )

    def test_scheduled_train_assignment_requires_an_explicit_deferral(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            first, errors = build_queue(
                fixture.intake,
                None,
                policy_digest=fixture.policy_digest,
                latest_maintenance_pointer_digest=_digest("b"),
                lifecycle_ledger_digest=_digest("d"),
                repository_identity="github.com/crypta-network/cryptad",
                candidate_commit=fixture.candidate,
            )
            self.assertEqual(errors, [])
            rewritten_intake = copy.deepcopy(fixture.intake)
            rewritten_intake["previousQueueDigest"] = first["queueDigest"]
            rewritten_intake["fixes"][0]["schedule"][
                "targetTrainId"
            ] = "stable-train-302"
            _bind_intake_evidence(
                rewritten_intake,
                first,
                policy_digest=fixture.policy_digest,
                candidate_commit=fixture.candidate,
            )

            _rewritten, errors = build_queue(
                rewritten_intake,
                first,
                policy_digest=fixture.policy_digest,
                latest_maintenance_pointer_digest=_digest("b"),
                lifecycle_ledger_digest=_digest("d"),
                repository_identity="github.com/crypta-network/cryptad",
                candidate_commit=fixture.candidate,
            )

            self.assertTrue(
                any(
                    "rewrites immutable scheduled train assignment" in error
                    for error in errors
                ),
                errors,
            )

            scheduled_intake = copy.deepcopy(fixture.intake)
            scheduled_fix = scheduled_intake["fixes"][0]
            scheduled_fix["state"] = "scheduled"
            scheduled_fix["stateTransitions"] = scheduled_fix[
                "stateTransitions"
            ][:4]
            _bind_intake_evidence(
                scheduled_intake,
                None,
                policy_digest=fixture.policy_digest,
                candidate_commit=fixture.candidate,
            )
            scheduled_queue, errors = build_queue(
                scheduled_intake,
                None,
                policy_digest=fixture.policy_digest,
                latest_maintenance_pointer_digest=_digest("b"),
                lifecycle_ledger_digest=_digest("d"),
                repository_identity="github.com/crypta-network/cryptad",
                candidate_commit=fixture.candidate,
            )
            self.assertEqual(errors, [])
            deferred_intake = copy.deepcopy(scheduled_intake)
            deferred_intake["previousQueueDigest"] = scheduled_queue[
                "queueDigest"
            ]
            deferred_fix = deferred_intake["fixes"][0]
            deferred_at = "2026-01-15T11:00:00Z"
            deferred_fix["state"] = "deferred"
            deferred_fix["disposition"] = "deferred"
            deferred_fix["releaseLane"] = None
            deferred_fix["stateTransitions"].append(
                {
                    "sequence": len(deferred_fix["stateTransitions"]),
                    "from": "scheduled",
                    "to": "deferred",
                    "occurredAt": deferred_at,
                    "actorRole": "stable-triage-manager",
                    "reasonCode": "target-train-reconsidered",
                    "evidenceDigest": _digest("e"),
                }
            )
            deferred_fix["schedule"].update(
                {
                    "decisionAt": deferred_at,
                    "targetTrainId": None,
                    "reviewAt": "2026-01-16T11:00:00Z",
                    "rationale": "Explicitly reconsider the intended train.",
                }
            )
            _bind_intake_evidence(
                deferred_intake,
                scheduled_queue,
                policy_digest=fixture.policy_digest,
                candidate_commit=fixture.candidate,
            )

            _deferred, errors = build_queue(
                deferred_intake,
                scheduled_queue,
                policy_digest=fixture.policy_digest,
                latest_maintenance_pointer_digest=_digest("b"),
                lifecycle_ledger_digest=_digest("d"),
                repository_identity="github.com/crypta-network/cryptad",
                candidate_commit=fixture.candidate,
            )

            self.assertEqual(errors, [])

    def test_security_identity_and_routing_are_preserved_across_queue_snapshots(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            inspector = GitInspector(
                fixture.root,
                expected_repository_identity="github.com/crypta-network/cryptad",
            )
            security_fix = _security_fix(
                inspector,
                fixture.fix_commit,
                fixture.candidate,
            )
            previous_intake = _intake(fixture.policy_digest, security_fix)
            previous_queue, previous_errors = build_queue(
                previous_intake,
                None,
                policy_digest=fixture.policy_digest,
                latest_maintenance_pointer_digest=_digest("b"),
                lifecycle_ledger_digest=_digest("d"),
                repository_identity="github.com/crypta-network/cryptad",
                candidate_commit=fixture.candidate,
            )
            self.assertEqual(previous_errors, [])
            rewritten_intake = copy.deepcopy(previous_intake)
            rewritten_intake["previousQueueDigest"] = previous_queue["queueDigest"]
            rewritten = rewritten_intake["fixes"][0]
            rewritten["severity"] = "high"
            rewritten["security"]["severity"] = "high"
            rewritten["security"]["publicProjectionDigest"] = semantic_digest(
                {
                    "fixId": rewritten["fixId"],
                    "incidentOpaqueId": rewritten["security"]["incidentOpaqueId"],
                    "advisoryOpaqueId": rewritten["security"]["advisoryOpaqueId"],
                    "severity": "high",
                    "disclosureState": rewritten["security"]["disclosureState"],
                    "publicSafeSummary": rewritten["security"]["publicSafeSummary"],
                }
            )
            rewritten["disposition"] = "routine-maintenance"
            rewritten["releaseLane"] = "routine-maintenance"
            _bind_intake_evidence(
                rewritten_intake,
                previous_queue,
                policy_digest=fixture.policy_digest,
                candidate_commit=fixture.candidate,
            )

            _rewritten_queue, errors = build_queue(
                rewritten_intake,
                previous_queue,
                policy_digest=fixture.policy_digest,
                latest_maintenance_pointer_digest=_digest("b"),
                lifecycle_ledger_digest=_digest("d"),
                repository_identity="github.com/crypta-network/cryptad",
                candidate_commit=fixture.candidate,
            )

            self.assertTrue(
                any("rewrites immutable severity" in row for row in errors),
                errors,
            )
            self.assertTrue(
                any("rewrites immutable security severity" in row for row in errors),
                errors,
            )
            self.assertTrue(
                any("rewrites release routing" in row for row in errors),
                errors,
            )

    def test_incident_scope_conflicts_compare_every_prior_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            inspector = GitInspector(
                fixture.root,
                expected_repository_identity="github.com/crypta-network/cryptad",
            )
            fixes = []
            for index, (suffix, component) in enumerate(
                (
                    ("aaaaaaaaaaaaaaaa", "component-a"),
                    ("bbbbbbbbbbbbbbbb", "component-b"),
                    ("cccccccccccccccc", "component-b"),
                ),
                start=1,
            ):
                fix = _security_fix(
                    inspector,
                    fixture.fix_commit,
                    fixture.candidate,
                    severity="high",
                )
                fix["fixId"] = f"stable-fix-{suffix}"
                fix["affectedScope"]["components"] = [component]
                candidate_commit = str(index) * 40
                fix["provenance"]["candidateCommit"] = candidate_commit
                for evidence in fix["evidence"]:
                    evidence["candidateCommit"] = candidate_commit
                if index == 3:
                    fix["disposition"] = "rejected"
                    fix["releaseLane"] = None
                fix["security"]["publicProjectionDigest"] = semantic_digest(
                    {
                        "fixId": fix["fixId"],
                        "incidentOpaqueId": fix["security"]["incidentOpaqueId"],
                        "advisoryOpaqueId": fix["security"]["advisoryOpaqueId"],
                        "severity": fix["security"]["severity"],
                        "disclosureState": fix["security"]["disclosureState"],
                        "publicSafeSummary": fix["security"]["publicSafeSummary"],
                    }
                )
                fix["publicProjectionDigest"] = semantic_digest(
                    {
                        "fixId": fix["fixId"],
                        "classification": fix["classification"],
                        "publicSummary": fix["publicSummary"],
                    }
                )
                fixes.append(fix)
            intake = _intake(fixture.policy_digest, fixes[0])
            intake["fixes"] = fixes
            intake["publicProjectionDigest"] = semantic_digest(
                {
                    "fixIds": [fix["fixId"] for fix in fixes],
                    "obligations": [],
                }
            )
            intake["intakeDigest"] = canonical_identity_digest(
                intake, "intakeDigest"
            )

            errors = intake_errors(
                intake,
                fixture.policy,
                policy_digest=fixture.policy_digest,
                repository_identity="github.com/crypta-network/cryptad",
                now=NOW,
            )

            self.assertTrue(
                any("overlapping contradictory scope" in row for row in errors),
                errors,
            )

    def test_security_hotfix_rejects_mixed_incident_or_advisory_scope(
        self,
    ) -> None:
        critical = {
            "classification": "security-fix",
            "security": {
                "severity": "critical",
                "incidentOpaqueId": "incident-opaque-287",
                "advisoryOpaqueId": "advisory-opaque-287",
            }
        }
        mixed = copy.deepcopy(critical)
        mixed["security"]["advisoryOpaqueId"] = "advisory-opaque-288"
        mixed_incident = copy.deepcopy(critical)
        mixed_incident["security"]["incidentOpaqueId"] = "incident-opaque-288"

        engine._validate_security_hotfix_fix_set([critical])  # noqa: SLF001

        for changed in (mixed, mixed_incident):
            with self.subTest(security=changed["security"]), self.assertRaisesRegex(
                ValueError, "one critical incident"
            ):
                engine._validate_security_hotfix_fix_set(  # noqa: SLF001
                    [critical, changed]
                )
        with self.assertRaisesRegex(ValueError, "one critical incident"):
            engine._validate_security_hotfix_fix_set(  # noqa: SLF001
                [
                    critical,
                    {
                        "classification": "packaging-installer-fix",
                        "security": None,
                    },
                ]
            )

    def test_engine_source_contains_no_git_or_publication_mutator(self) -> None:
        source = Path(engine.__file__).read_text(encoding="utf-8")
        for forbidden in (
            "subprocess.run",
            "gh pr create",
            "git push",
            "git tag",
            "create_git_ref",
            "create_release",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

if __name__ == "__main__":
    unittest.main()

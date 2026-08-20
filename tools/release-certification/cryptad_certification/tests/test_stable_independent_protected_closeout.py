"""PR-292 integration tests for PR-291 protected-release closeout."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptad_certification.engines import stable_1_0_protected_release as protected
from cryptad_certification.io import write_json
from cryptad_certification.tests import test_stable_protected_release as base
from cryptad_certification.tests.stable_independent_protected_fixture import (
    _independent_test_policy,
    _independent_policy_authority_patch,
    _independent_reproducibility_evidence,
    _rebind_independent_reproducibility_artifact,
    _sealed,
)
from cryptad_certification.tests.support import workspace_root

_configure_publication_receipt = base._configure_publication_receipt


class StableIndependentProtectedCloseoutTests(unittest.TestCase):
    """Authenticate PR-292 evidence again at the PR-291 closeout boundary."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.contract = base._contract(self.root)
        self.policy = json.loads(
            (
                workspace_root()
                / "tools/release-certification/stable-1.0-protected-release-policy.json"
            ).read_text(encoding="utf-8")
        )
        github_auth = mock.patch.object(
            protected, "_github_actions_coordinate_errors", return_value=[]
        )
        github_auth.start()
        self.addCleanup(github_auth.stop)
        source_auth = mock.patch.object(protected, "_source_errors", return_value=[])
        source_auth.start()
        self.addCleanup(source_auth.stop)

    def test_closeout_accepts_authentic_provider_distinct_operational_artifact(self) -> None:
        contract = copy.deepcopy(self.contract)
        _configure_publication_receipt(self.root, contract)
        _independent_reproducibility_evidence(
            self.root,
            contract,
            self.policy,
        )

        with mock.patch.object(
            protected, "_policy_errors", return_value=[]
        ), _independent_policy_authority_patch():
            findings, statuses = protected._closeout(  # noqa: SLF001
                self.root,
                contract,
                self.policy,
            )

        self.assertEqual([], findings)
        self.assertEqual(
            "independently-reproduced",
            statuses["independentReproducibility"],
        )

    def test_closeout_rejects_independent_summary_bound_to_wrong_selected_rc(self) -> None:
        for field, expected_finding in (
            ("freezeFileDigest", "different selected RC freeze"),
            ("productDigest", "different selected RC product bytes"),
        ):
            with self.subTest(field=field):
                contract = copy.deepcopy(self.contract)
                _configure_publication_receipt(self.root, contract)
                members = _independent_reproducibility_evidence(
                    self.root,
                    contract,
                    self.policy,
                )
                summary_path = members[
                    "stable-1.0-independent-reproducibility-summary.json"
                ]
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                summary["selectedRc"][field] = "sha256:" + "e" * 64
                summary["summaryDigest"] = protected.supply_chain_semantic_digest(
                    summary,
                    "summaryDigest",
                )
                write_json(summary_path, summary)
                _rebind_independent_reproducibility_artifact(
                    self.root, contract, members
                )

                with mock.patch.object(
                    protected, "_policy_errors", return_value=[]
                ), _independent_policy_authority_patch():
                    findings, statuses = protected._closeout(  # noqa: SLF001
                        self.root,
                        contract,
                        self.policy,
                    )

                self.assertEqual("pending", statuses["independentReproducibility"])
                self.assertTrue(
                    any(expected_finding in item for item in findings),
                    findings,
                )

    def test_closeout_rejects_different_selected_rc_supply_chain_authority(self) -> None:
        contract = copy.deepcopy(self.contract)
        _configure_publication_receipt(self.root, contract)
        members = _independent_reproducibility_evidence(
            self.root,
            contract,
            self.policy,
        )
        summary_path = members[
            "stable-1.0-independent-reproducibility-summary.json"
        ]
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["selectedRc"]["supplyChain"]["runId"] = "999"
        summary = _sealed(summary, "summaryDigest")
        write_json(summary_path, summary)
        _rebind_independent_reproducibility_artifact(self.root, contract, members)

        with mock.patch.object(
            protected, "_policy_errors", return_value=[]
        ), _independent_policy_authority_patch():
            findings, _statuses = protected._closeout(  # noqa: SLF001
                self.root,
                contract,
                self.policy,
            )

        self.assertTrue(
            any("different supply-chain authority" in item for item in findings),
            findings,
        )

    def test_closeout_rejects_same_provider_independence(self) -> None:
        contract = copy.deepcopy(self.contract)
        _configure_publication_receipt(self.root, contract)
        _independent_reproducibility_evidence(
            self.root,
            contract,
            self.policy,
            same_provider=True,
        )

        with mock.patch.object(
            protected, "_policy_errors", return_value=[]
        ), _independent_policy_authority_patch():
            findings, statuses = protected._closeout(  # noqa: SLF001
                self.root, contract, self.policy
            )

        self.assertEqual("blocked", statuses["independentReproducibility"])
        self.assertTrue(
            any("not authenticated operational success" in item for item in findings),
            findings,
        )

    def test_closeout_rejects_fixture_and_self_test_independence(self) -> None:
        for classification in ("fixture", "self-test"):
            with self.subTest(classification=classification):
                contract = copy.deepcopy(self.contract)
                _configure_publication_receipt(self.root, contract)
                _independent_reproducibility_evidence(
                    self.root,
                    contract,
                    self.policy,
                    fixture=classification == "fixture",
                    self_test=classification == "self-test",
                )

                with mock.patch.object(
                    protected, "_policy_errors", return_value=[]
                ), _independent_policy_authority_patch():
                    findings, statuses = protected._closeout(  # noqa: SLF001
                        self.root, contract, self.policy
                    )

                self.assertEqual("pending", statuses["independentReproducibility"])
                self.assertTrue(
                    any("fixture, self-test" in item for item in findings), findings
                )

    def test_closeout_rejects_resealed_member_substitution(self) -> None:
        contract = copy.deepcopy(self.contract)
        _configure_publication_receipt(self.root, contract)
        members = _independent_reproducibility_evidence(
            self.root,
            contract,
            self.policy,
        )
        receipt_path = members["stable-1.0-independent-builder-receipt.json"]
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["providerProfileId"] = "substituted-external-profile-v1"
        receipt["receiptDigest"] = protected.supply_chain_semantic_digest(
            receipt, "receiptDigest"
        )
        write_json(receipt_path, receipt)
        _rebind_independent_reproducibility_artifact(self.root, contract, members)

        with mock.patch.object(
            protected, "_policy_errors", return_value=[]
        ), _independent_policy_authority_patch():
            findings, statuses = protected._closeout(  # noqa: SLF001
                self.root, contract, self.policy
            )

        self.assertEqual("pending", statuses["independentReproducibility"])
        self.assertTrue(
            any("externalBuilderReceiptDigest differs" in item for item in findings),
            findings,
        )

    def test_closeout_rejects_consistently_resealed_plan_and_result_rows(self) -> None:
        contract = copy.deepcopy(self.contract)
        _configure_publication_receipt(self.root, contract)
        members = _independent_reproducibility_evidence(
            self.root, contract, self.policy
        )
        plan_path = members["stable-1.0-rebuild-comparison-plan.json"]
        result_path = members["stable-1.0-reproducibility-report.json"]
        summary_path = members[
            "stable-1.0-independent-reproducibility-summary.json"
        ]
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        result = json.loads(result_path.read_text(encoding="utf-8"))
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        plan["comparisons"][0]["fileName"] = "resealed-substitute.jar"
        plan = _sealed(plan, "planDigest")
        result["comparisonPlanDigest"] = plan["planDigest"]
        result = _sealed(result, "resultDigest")
        summary["comparisonPlanDigest"] = plan["planDigest"]
        summary["reproducibilityResultDigest"] = result["resultDigest"]
        summary = _sealed(summary, "summaryDigest")
        write_json(plan_path, plan)
        write_json(result_path, result)
        write_json(summary_path, summary)
        _rebind_independent_reproducibility_artifact(self.root, contract, members)

        with mock.patch.object(
            protected, "_policy_errors", return_value=[]
        ), _independent_policy_authority_patch():
            findings, statuses = protected._closeout(  # noqa: SLF001
                self.root, contract, self.policy
            )

        self.assertEqual("pending", statuses["independentReproducibility"])
        self.assertTrue(
            any("not derived from the exact retained receipts" in item for item in findings),
            findings,
        )

    def test_receipt_semantics_reject_candidate_bound_digest_and_partition_substitution(
        self,
    ) -> None:
        contract = copy.deepcopy(self.contract)
        _configure_publication_receipt(self.root, contract)
        members = _independent_reproducibility_evidence(
            self.root, contract, self.policy
        )
        summary = json.loads(
            members[
                "stable-1.0-independent-reproducibility-summary.json"
            ].read_text(encoding="utf-8")
        )
        primary = json.loads(
            members["stable-1.0-primary-builder-receipt.json"].read_text(
                encoding="utf-8"
            )
        )
        external = json.loads(
            members["stable-1.0-independent-builder-receipt.json"].read_text(
                encoding="utf-8"
            )
        )
        supply_chain_policy = json.loads(
            (
                workspace_root()
                / "tools/release-certification/stable-1.0-supply-chain-policy.json"
            ).read_text(encoding="utf-8")
        )
        primary_by_execution = {
            row["executionId"]: row for row in primary["builderExecutions"]
        }
        independent_policy = _independent_test_policy()

        baseline = protected._independent_receipt_semantic_errors(  # noqa: SLF001
            summary, primary, external, supply_chain_policy, independent_policy
        )
        candidate_bound = copy.deepcopy(external)
        first = candidate_bound["builderExecutions"][0]
        first["subjectSetDigest"] = primary_by_execution[first["executionId"]][
            "subjectSetDigest"
        ]
        candidate_bound = _sealed(candidate_bound, "receiptDigest")
        partition_substitution = copy.deepcopy(external)
        partition_substitution["builderExecutions"][0]["subjectKeys"] = external[
            "builderExecutions"
        ][1]["subjectKeys"]
        partition_substitution = _sealed(partition_substitution, "receiptDigest")
        producer_recipe_substitution = copy.deepcopy(external)
        producer_recipe_substitution["buildTasks"] = primary["buildTasks"]
        producer_recipe_substitution = _sealed(
            producer_recipe_substitution, "receiptDigest"
        )
        task_partition_substitution = copy.deepcopy(external)
        changed_execution = next(
            row
            for row in task_partition_substitution["builderExecutions"]
            if row["executionId"] == "portable-apps"
        )
        changed_execution["taskSet"] = primary_by_execution[
            changed_execution["executionId"]
        ]["taskSet"]
        changed_execution["taskSetDigest"] = protected._semantic_digest(  # noqa: SLF001
            changed_execution["taskSet"]
        )
        task_partition_substitution = _sealed(
            task_partition_substitution, "receiptDigest"
        )

        candidate_errors = protected._independent_receipt_semantic_errors(  # noqa: SLF001
            summary,
            primary,
            candidate_bound,
            supply_chain_policy,
            independent_policy,
        )
        partition_errors = protected._independent_receipt_semantic_errors(  # noqa: SLF001
            summary,
            primary,
            partition_substitution,
            supply_chain_policy,
            independent_policy,
        )
        producer_recipe_errors = protected._independent_receipt_semantic_errors(  # noqa: SLF001
            summary,
            primary,
            producer_recipe_substitution,
            supply_chain_policy,
            independent_policy,
        )
        task_partition_errors = protected._independent_receipt_semantic_errors(  # noqa: SLF001
            summary,
            primary,
            task_partition_substitution,
            supply_chain_policy,
            independent_policy,
        )

        self.assertEqual([], baseline)
        self.assertIn(
            f"external builder execution {first['executionId']} candidate-free subject-set digest differs",
            candidate_errors,
        )
        self.assertTrue(
            any("subject keys differ from the authenticated partition" in error for error in partition_errors),
            partition_errors,
        )
        self.assertIn(
            "external builder task set differs from the independent verifier policy",
            producer_recipe_errors,
        )
        self.assertTrue(
            any(
                "task set differs from the independent verifier policy" in error
                for error in task_partition_errors
            ),
            task_partition_errors,
        )

    def test_closeout_rejects_resealed_provider_independence_projection(self) -> None:
        contract = copy.deepcopy(self.contract)
        _configure_publication_receipt(self.root, contract)
        members = _independent_reproducibility_evidence(
            self.root, contract, self.policy
        )
        summary_path = members[
            "stable-1.0-independent-reproducibility-summary.json"
        ]
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["providerIndependence"]["verifier"]["providerId"] = (
            "resealed-provider.example"
        )
        summary["providerIndependence"] = _sealed(
            summary["providerIndependence"], "evaluationDigest"
        )
        summary = _sealed(summary, "summaryDigest")
        write_json(summary_path, summary)
        _rebind_independent_reproducibility_artifact(self.root, contract, members)

        with mock.patch.object(
            protected, "_policy_errors", return_value=[]
        ), _independent_policy_authority_patch():
            findings, statuses = protected._closeout(  # noqa: SLF001
                self.root, contract, self.policy
            )

        self.assertEqual("pending", statuses["independentReproducibility"])
        self.assertTrue(
            any("not derived from retained authorities" in item for item in findings),
            findings,
        )

    def test_closeout_preserves_comparison_failed_status(self) -> None:
        contract = copy.deepcopy(self.contract)
        _configure_publication_receipt(self.root, contract)
        _independent_reproducibility_evidence(
            self.root,
            contract,
            self.policy,
            status="comparison-failed",
        )

        with mock.patch.object(
            protected, "_policy_errors", return_value=[]
        ), _independent_policy_authority_patch():
            findings, statuses = protected._closeout(  # noqa: SLF001
                self.root, contract, self.policy
            )

        self.assertEqual(
            "comparison-failed", statuses["independentReproducibility"]
        )
        self.assertTrue(
            any("comparison did not pass exactly" in item for item in findings),
            findings,
        )


if __name__ == "__main__":
    unittest.main()

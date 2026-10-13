"""Offline checks for the closed PR-317 one-attempt host runner."""
import hashlib
import unittest
from pathlib import Path
import json
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

import installation
import pr317_budget_runtime_evidence as evidence
import pr317_budget_runtime_runner as runner


DIGEST = "sha256:" + "a" * 64


def guest():
    value = {"schemaVersion": 1,
        "kind": "pr317-installed-composed-budget-lifecycle-observation",
        "executionClass": evidence.EXECUTION_CLASS, "selectionDigest": DIGEST,
        "privateEvidenceDigest": DIGEST,
        "evidenceClass": "installed-four-role-private-observer", "topologyRoles": 4,
        "namespaceTransportImplemented": True, "fiveCaseDriversImplemented": False,
        "observedCases": ["import-concurrency"],
        "notObservedCases": [case for case in evidence.CASES
                             if case != "import-concurrency"],
        "ownerCancellationDirection": "not-observed", "cleanupState": "completed",
        "historicalPr315AcceptanceTransferred": False,
        "historicalPr316AcceptanceTransferred": False,
        "finiteNativeAcceptance": False, "fullAppBudgets": "not-observed",
        "originalProtectedAuthority": False, "independentSecurityReview": False,
        "releaseEligible": False, "phaseComplete": False}
    value.update(identity={"sourceCommit": "b" * 40, "bundleIdentity": "c" * 64},
        runtimePolicy={}, campaignDeadlineMonotonicNs=1,
        workloadAcceptance="incomplete-pr317-private-evidence-not-verified",
        protectedExecutionEnabled=False)
    return value


class BudgetRuntimeRunnerTest(unittest.TestCase):
    def test_node_epoch_is_derived_from_terminal_controller_and_all_app_contexts(self):
        role_digest = "sha256:" + "b" * 64
        private = {"contexts": {app_id: {"roleEpochDigest": role_digest}
                                for app_id in evidence.APP_IDS}}
        terminal = {"controllerRecords": {"candidate-sender": {"record": {
            "roleEpochDigest": role_digest}}}}

        self.assertEqual("b" * 32, runner._expected_node_epoch(private, terminal))
        private["contexts"][evidence.APP_IDS[0]]["roleEpochDigest"] = DIGEST
        with self.assertRaisesRegex(ValueError, "node-epoch-invalid"):
            runner._expected_node_epoch(private, terminal)
        private["contexts"][evidence.APP_IDS[0]]["roleEpochDigest"] = role_digest
        terminal["controllerRecords"]["candidate-sender"]["record"][
            "roleEpochDigest"] = DIGEST
        with self.assertRaisesRegex(ValueError, "node-epoch-invalid"):
            runner._expected_node_epoch(private, terminal)

    def test_host_evidence_module_roster_matches_closed_contract(self):
        modules = runner._host_evidence_modules()

        self.assertEqual(set(runner.fixtures.contract.HOST_EVIDENCE_PATHS), set(modules))
        for name, module in modules.items():
            expected = (runner.ROOT /
                runner.fixtures.contract.HOST_EVIDENCE_PATHS[name]).resolve()
            self.assertEqual(expected, Path(module.__file__).resolve())

    def test_source_module_check_rejects_substituted_host_dependency(self):
        arguments = SimpleNamespace(source=runner.ROOT)
        runner._source_modules(arguments)

        with patch.object(runner.installed.runtime, "__file__", runner.__file__), \
                self.assertRaisesRegex(ValueError, "executing-source-mismatch"):
            runner._source_modules(arguments)

    def test_candidate_identity_recomputes_fixed_app_cohort(self):
        apps = {app_id: "sha256:" + str(index) * 64
                for index, app_id in enumerate(runner.fixtures.APP_IDS, 1)}
        selected = [apps[app_id] for app_id in runner.fixtures.APP_IDS]
        plan = {"nodes": [{"role": "candidate-sender", "appDigests": selected}]}

        node, digest = runner._candidate_identity(plan, {"apps": apps})

        self.assertEqual(plan["nodes"][0], node)
        self.assertEqual(runner.fixtures.canonical_digest(selected), digest)
        plan["nodes"][0]["appDigests"][0] = DIGEST
        with self.assertRaisesRegex(ValueError, "app-cohort-invalid"):
            runner._candidate_identity(plan, {"apps": apps})

    def test_private_evidence_digest_authenticates_exact_retained_bytes(self):
        raw = b'{\n  "schemaVersion": 1\n}\n'
        validated = {"schemaVersion": 1}
        with patch.object(runner.shared, "_private_bytes", return_value=raw), \
                patch.object(runner.evidence, "decode_private", return_value=validated):
            value, digest = runner._private_evidence(Path("private.json"))

        self.assertEqual(validated, value)
        self.assertEqual("sha256:" + hashlib.sha256(raw).hexdigest(), digest)
        self.assertNotEqual(evidence.canonical_digest(validated), digest)

    def test_failure_path_retains_closed_privacy_and_watcher_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "attempt"
            output.mkdir(mode=0o700)
            args = SimpleNamespace(output=output, source=Path(temporary))
            completed = SimpleNamespace(stdout="a" * 40 + "\n")
            with patch.object(runner.subprocess, "run", return_value=completed), \
                    patch.object(runner.pressure_watch, "verify_launch_ready",
                                 side_effect=ValueError("not ready")), \
                    patch.object(runner, "_scan_budget_privacy",
                                 return_value={"filesScanned": 0, "bytesScanned": 0,
                                               "sourceCloneExcluded": True}):
                runner._retain_failure(args, ValueError("private detail"))
            value = json.loads((output / "failure.private.json").read_text())
            self.assertEqual("execution-failed-private-reconciliation-required",
                             value["reason"])
            self.assertEqual("passed", value["privacy"]["status"])
            self.assertFalse(value["releaseEligible"])

    def test_runner_selection_and_evidence_are_test_kit_only(self):
        for name in ("pr317_budget_selection.py", "pr317_budget_runtime_evidence.py",
                     "pr317_budget_runtime_runner.py"):
            relative = "tools/release-certification/restricted/" + name
            self.assertIn(relative, installation.TEST_SEAMS)
            self.assertFalse(installation.production_member(relative))

    def test_driver_result_is_closed_and_keeps_cancellation_gap(self):
        self.assertEqual(guest(), runner._driver_observation(guest()))
        changed = guest()
        changed["ownerCancellationDirection"] = "observed"
        with self.assertRaises(ValueError):
            runner._driver_observation(changed)

    def test_public_projection_cannot_upgrade_phase_or_full_budget(self):
        value = evidence.failed_projection("installed-runtime-not-executed")
        self.assertEqual(value, runner._closed_public(value))
        for field, selected in (("phaseComplete", True),
                                ("fullAppBudgets", "observed"),
                                ("ownerCancelledInstalledDirection", True)):
            changed = dict(value, **{field: selected})
            with self.assertRaises(ValueError):
                runner._closed_public(changed)

    def test_cli_has_no_case_campaign_or_publication_selector(self):
        actions = {action.dest for action in runner.parser()._actions}
        self.assertNotIn("case", actions)
        self.assertNotIn("campaign", actions)
        self.assertNotIn("publish", actions)
        self.assertIn("probe", actions)
        self.assertIn("fixture_manifest_digest", actions)

    def test_invalid_fixed_digests_are_rejected_by_cli(self):
        with self.assertRaises(SystemExit):
            runner.main(["--source", ".", "--output", "out",
                "--prepared-image", "image", "--qemu-root", "qemu", "--seed", "seed",
                "--ssh-key", "key", "--known-hosts", "known",
                "--prepared-fixtures", "fixtures", "--storage-root", "storage",
                "--product-source-commit", "bad", "--prepared-image-digest", "bad",
                "--fixture-manifest-digest", "bad", "--storage-budget-bytes", "1",
                "--min-free-bytes", "1", "--memory-budget-bytes", "1",
                "--min-host-memory-bytes", "1"])


if __name__ == "__main__":
    unittest.main()

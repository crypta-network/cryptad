"""Offline control/selection tests; no installed observation is fabricated."""
from contextlib import nullcontext
import copy
import os
from pathlib import Path
import stat
import subprocess
import sys
import json
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import pr318_storage_admin as admin
import pr318_storage_selection as selection
import pr318_storage_runtime_runner as runner
import pr318_storage_runtime_evidence as evidence
import test_pr317_budget_selection as legacy_fixture
import restricted_workload_launcher as launcher
import restricted_workload_prepare as preparation
import bounded_process
import cross_version_installed_storage_budgets as collector
from cryptad_certification.tests import test_composed_budget_storage_evidence as vectors


def selected():
    with patch.object(legacy_fixture, "selection", selection):
        plan, private, authorization = legacy_fixture.closed_selection()
    tools = authorization["budgetSelection"]["toolIdentities"]
    plan["composedBudgetInputs"]["collectorDigest"] = selection.canonical_digest({
        key: tools[key] for key in ('installedDriver', 'localBudgetAdapter', 'schedulerRuntime',
            'evidenceOracle', 'storageOracle', 'administrator', 'roleClients', 'runtimeEvidence')})
    authorization["budgetSelection"]["composedBudgetInputs"] = dict(plan["composedBudgetInputs"])
    authorization["budgetSelection"]["timePlan"] = {
        "boundaryEpochSecond": 36000, "selectedAtEpochSecond": 35500,
        "startMarginSeconds": 10, "requestDeadlineMillis": 45000}
    authorization["budgetSelection"]["statementFingerprint"] = "c" * 64
    resign(plan, authorization)
    return plan, private, authorization


def resign(plan, authorization):
    authorization["planDigest"] = selection.canonical_digest(plan)
    authorization["selectionDigest"] = selection.canonical_digest({
        "executionClass": authorization["executionClass"],
        "planDigest": authorization["planDigest"],
        "budgetSelection": authorization["budgetSelection"]})


def clock_sample(epoch_nanos, monotonic_nanos, guest_offset=0):
    return {"hostEpochBeforeNanos": epoch_nanos,
            "hostMonotonicBeforeNanos": monotonic_nanos,
            "guestEpochNanos": epoch_nanos + 50_000_000 + guest_offset,
            "hostMonotonicAfterNanos": monotonic_nanos + 100_000_000,
            "hostEpochAfterNanos": epoch_nanos + 100_000_000}


def host_selection():
    plan, private, authorization = selected()
    budget = authorization["budgetSelection"]
    fixture = {key: copy.deepcopy(budget[key]) for key in
               ("timePlan", "toolIdentities", "permissions", "caseIds", "environment",
                "normalizedConfiguration", "failurePolicy", "statementDigest",
                "statementFingerprint")}
    fixture.update(apps=copy.deepcopy(budget["appBundleDigests"]),
                   trustDigest=budget["trustedKeysDigest"], sourceCommit="d" * 40,
                   runtimeDigest="sha256:" + "e" * 64, maxSeconds=600, maxOperations=1000)
    fixture["products"] = {name: {"sourceCommit": marker * 40,
        "artifactDigest": "sha256:" + marker * 64, "artifactSize": 100,
        "packageTarget": "linux-x64", "contractVersion": 26}
        for name, marker in (("candidate", "a"), ("previous", "b"))}
    for node in plan["nodes"]:
        product = fixture["products"]["previous" if node["role"] == "previous" else "candidate"]
        node.update(product, product="cryptad", runtimeDigest=fixture["runtimeDigest"])
    plan.update(producer={"sourceCommit": fixture["sourceCommit"]}, requestedSeconds=600)
    authorization.update(maxSeconds=600, maxOperations=1000)
    resign(plan, authorization)
    return {"plan": plan, "private": private, "authorization": authorization}, fixture


class SelectionTest(unittest.TestCase):
    def test_historical_materialization_retains_its_tools_without_campaign_inputs(self):
        _value, fixture = host_selection()
        with patch.object(selection.os, 'geteuid', return_value=0), \
                patch.object(selection, 'verify', return_value=fixture), \
                patch.object(selection.preparation, 'configuration_identity',
                    side_effect=lambda role, trust, execution_class:
                        'sha256:' + str(selection.ROLES.index(role) + 4) * 64), \
                patch.object(selection.runtime, 'runner_identity', return_value={
                    'sourceCommit': fixture['sourceCommit'], 'runnerDigest': 'sha256:' + 'e' * 64,
                    'adapterDigest': 'sha256:' + 'f' * 64}):
            result = selection.materialize_selection(selection.FIXED_GUEST_ROOT,
                Path('/owned/source'), 'sha256:' + 'f' * 64, fixture['sourceCommit'])
        self.assertTrue(selection.verify_selection_contract(**result))
        self.assertNotIn('budgetCampaignInputs', result['plan'])

    def test_statement_verifier_returns_one_product_fingerprint(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "fixtures"
            source = Path(temporary) / "source"
            package = Path(temporary) / "package"
            (root / "jdk/bin").mkdir(parents=True)
            (package / "lib").mkdir(parents=True)
            verifier = source / selection.TOOL_PATHS["statementVerifier"]
            verifier.parent.mkdir(parents=True)
            verifier.write_text("fixed source identity")
            selected = {"products": {"candidate": {
                "artifactDigest": "sha256:" + "a" * 64, "artifactSize": 1}}}
            def fingerprint_run(arguments, **_kwargs):
                if any("Pr317SignedBudgetStatementVerifier" in value for value in arguments):
                    Path(arguments[-1]).write_text("c" * 64)
                return b""
            with patch.object(selection.runtime, "extract_package", return_value=package), \
                    patch.object(bounded_process, "run", side_effect=fingerprint_run):
                self.assertEqual("c" * 64,
                                 selection._verify_statement_signature(root, source, selected))
            def invalid_fingerprint_run(arguments, **_kwargs):
                if any("Pr317SignedBudgetStatementVerifier" in value for value in arguments):
                    Path(arguments[-1]).write_text("invalid")
                return b""
            with patch.object(selection.runtime, "extract_package", return_value=package), \
                    patch.object(bounded_process, "run", side_effect=invalid_fingerprint_run), \
                    self.assertRaisesRegex(ValueError, "statement-fingerprint-invalid"):
                selection._verify_statement_signature(root, source, selected)

    def test_private_decoder_rejects_non_mapping_nested_values(self):
        base = {"schemaVersion": 1, "kind": "pr318-private-storage-budget",
                "selectionDigest": "sha256:" + "a" * 64,
                "contexts": {app_id: {} for app_id in evidence.APP_IDS},
                "attempts": [{"caseId": case} for case in evidence.CASES],
                "composedBudgetEvidence": {"schemaVersion": 4, "causalCases": []},
                "composedBudgetCoverage": {"fullAppBudgets": "not-observed"}}
        for field, replacement in (("attempts", ["bad"]),
                                   ("composedBudgetEvidence", []),
                                   ("composedBudgetCoverage", [])):
            with self.subTest(field=field):
                changed = {**base, field: replacement}
                with self.assertRaisesRegex(ValueError, "pr318-private-shape-invalid"):
                    evidence.decode_private(json.dumps(changed).encode())

    def test_host_rejects_rehashed_fixture_substitutions(self):
        original, fixture = host_selection()
        self.assertEqual(original["authorization"]["selectionDigest"],
                         runner._selection(original, fixture, Path("/unused")))
        mutations = [
            (("authorization", "budgetSelection", "timePlan", "boundaryEpochSecond"), 39600),
            (("authorization", "budgetSelection", "toolIdentities", "statementVerifier"),
             "sha256:" + "f" * 64),
            (("authorization", "budgetSelection", "statementFingerprint"), "f" * 64),
            (("authorization", "maxSeconds"), 601),
            (("authorization", "maxOperations"), 1001),
            (("plan", "requestedSeconds"), 601),
            (("plan", "producer", "sourceCommit"), "f" * 40),
        ]
        for index, _role in enumerate(selection.ROLES):
            for name, value in (("sourceCommit", "f" * 40),
                                ("artifactDigest", "sha256:" + "f" * 64),
                                ("artifactSize", 101), ("packageTarget", "linux-arm64"),
                                ("contractVersion", 27), ("runtimeDigest", "sha256:" + "f" * 64)):
                mutations.append((("plan", "nodes", index, name), value))
        for path, replacement in mutations:
            with self.subTest(path=path):
                changed = copy.deepcopy(original)
                target = changed
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = replacement
                if path[-1] == "boundaryEpochSecond":
                    target["selectedAtEpochSecond"] += 3600
                resign(changed["plan"], changed["authorization"])
                self.assertTrue(selection.verify_selection_contract(
                    changed["plan"], changed["private"], changed["authorization"]))
                with self.assertRaisesRegex(ValueError, "host-fixture-binding-invalid"):
                    runner._selection(changed, fixture, Path("/unused"))

    def test_observed_window_must_match_selected_immutable_time_plan(self):
        _plan, _private, authorization = selected()
        row = {"caseId": "window-crossing", "timePlan": {
            **authorization["budgetSelection"]["timePlan"],
            "observedReservationEpochSecond": 35995, "releasedAtEpochSecond": 36000}}
        runner._selected_time_plan({"storageCases": [row]}, authorization)
        runner._selected_time_plan({"storageCases": []}, authorization)
        for field in authorization["budgetSelection"]["timePlan"]:
            with self.subTest(field=field):
                changed = copy.deepcopy(row)
                changed["timePlan"][field] += 1
                with self.assertRaisesRegex(ValueError, "host-time-plan-substituted"):
                    runner._selected_time_plan({"storageCases": [changed]}, authorization)

    def test_observed_graph_target_must_match_prepared_statement(self):
        _plan, _private, authorization = selected()
        fingerprint = authorization["budgetSelection"]["statementFingerprint"]
        attachment = {"storageCases": [
            {"selectedFingerprint": fingerprint}, {"selectedFingerprint": fingerprint}]}
        runner._selected_statement(attachment, authorization)
        attachment["storageCases"][1]["selectedFingerprint"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "host-statement-fingerprint-substituted"):
            runner._selected_statement(attachment, authorization)

    def test_installed_boundary_requires_independent_host_utc_alignment(self):
        _plan, _private, authorization = selected()
        boundary_nanos = authorization["budgetSelection"]["timePlan"][
            "boundaryEpochSecond"] * 10**9
        report = {"storageClock": {
            "before": clock_sample(boundary_nanos - 20_000_000_000, 1_000_000_000),
            "after": clock_sample(boundary_nanos + 20_000_000_000, 41_000_000_000)}}
        attachment = {"storageCases": [{"caseId": "window-crossing"}]}
        runner._clock_binding(report, attachment, authorization)
        for mutation in ("offset", "wall-jump", "wrong-boundary"):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(report)
                selected_authorization = copy.deepcopy(authorization)
                if mutation == "offset":
                    changed["storageClock"]["before"]["guestEpochNanos"] += 30_000_000_000
                elif mutation == "wall-jump":
                    changed["storageClock"]["before"]["hostEpochAfterNanos"] += 5_000_000_000
                else:
                    selected_authorization["budgetSelection"]["timePlan"][
                        "boundaryEpochSecond"] += 3600
                with self.assertRaisesRegex(ValueError, "pr318-host-(guest-clock|utc-boundary)"):
                    runner._clock_binding(changed, attachment, selected_authorization)

    def test_start_failure_retains_administrator_diagnostic_before_cleanup(self):
        order = []
        def start(role):
            raise ValueError("startup-failed")
        adapter = SimpleNamespace(plan={}, private={}, authorization={}, root=Path("/unused"),
            active_start_role="candidate-sender", active_start_stage="readiness", start=start,
            cleanup=lambda: order.append("cleanup") or "complete")
        with patch.object(selection.contract, "verify_selection_contract", return_value=True), \
                patch.object(collector, "_checkpoint", side_effect=lambda *args: order.append("checkpoint")):
            with self.assertRaisesRegex(ValueError, "startup-failed"):
                collector.run_storage_lane(adapter, lambda command: None,
                    on_start_failure=lambda role, stage: order.append((role, stage)))
        self.assertEqual([("candidate-sender", "readiness"), "checkpoint", "cleanup"], order)

    def test_prospective_contract_and_launcher_preserve_old_class(self):
        plan, private, authorization = selected()
        self.assertTrue(selection.verify_selection_contract(plan, private, authorization))
        self.assertTrue(preparation.valid_execution_selection(plan, private, authorization))
        arguments, environment = launcher.command("candidate-sender", selection.EXECUTION_CLASS)
        self.assertEqual(selection.ENVIRONMENT, {name: environment[name] for name in selection.ENVIRONMENT})
        self.assertIn("--cap-drop", arguments)
        self.assertEqual(launcher.BUDGET_EXECUTION_CLASS, launcher.budget_launcher_policy()["executionClass"])
        legacy_plan, legacy_private, legacy_authorization = legacy_fixture.closed_selection()
        self.assertFalse(selection.verify_selection_contract(legacy_plan, legacy_private, legacy_authorization))

    def test_time_plan_rejects_minute_boundary_unbounded_hold_and_arbitrary_target(self):
        plan, private, authorization = selected()
        for name, value in (("boundaryEpochSecond", 36060), ("startMarginSeconds", 3600),
                            ("requestDeadlineMillis", 3600000), ("targetPath", "/tmp/other")):
            changed = copy.deepcopy(authorization)
            changed["budgetSelection"]["timePlan"][name] = value
            resign(plan, changed)
            self.assertFalse(selection.verify_selection_contract(plan, private, changed))

    def test_boundary_ineligible_never_opens_request_or_resets_selected_time(self):
        adapter = SimpleNamespace(deadline=10)
        with patch.object(collector.time, "time", return_value=36000), \
                patch.object(collector.transport, "_new_content_key") as key:
            result, attempt = collector._boundary_case(adapter, None, b"", {
                "boundaryEpochSecond": 36000, "startMarginSeconds": 10})
        self.assertIsNone(result)
        self.assertEqual("window-not-reached", attempt["reason"])
        key.assert_not_called()

    def test_graph_partial_enumeration_is_not_unchanged_state(self):
        class Handle:
            def request(self, method, path, principal):
                return (200, {"statements": []}) if path.endswith("statements") else (
                    200, {"trustGraph": {"statementCount": 1}})
        with self.assertRaisesRegex(collector.runtime.RuntimeFailure, "enumeration-incomplete"):
            collector._graph(Handle())

    def test_host_evidence_roster_uses_actual_modules_and_fixed_admin_tool(self):
        self.assertEqual(set(runner._host_evidence_modules()), set(selection.HOST_EVIDENCE_PATHS))
        self.assertEqual("tools/release-certification/restricted/pr318_storage_admin.py",
                         selection.TOOL_PATHS["administrator"])

    def test_root_receipts_are_required_and_observer_substitution_is_rejected(self):
        receipt = {"restriction": {"phase": "restricted"}, "restoration": {"phase": "restored"}}
        private = {"composedBudgetEvidence": {"storageCases": [{
            "caseId": "partial-rate-write", "roleGeneration": "b" * 64, "adminReceipt": receipt}]}}
        terminal = {"controllerRecords": {"candidate-sender": {"record": {"generation": "b" * 64}}}}
        diagnostics = {"storageFaultReceipts": [receipt["restriction"], receipt["restoration"]],
                       "storageAccessCleanup": "completed", "storageSelectionDigest": "chosen"}
        runner._original_admin_receipts(private, diagnostics, terminal, "chosen")
        for field, value in (("storageFaultReceipts", []), ("storageAccessCleanup", "failed"),
                             ("storageSelectionDigest", "substituted")):
            with self.assertRaisesRegex(ValueError, "original-admin-receipt-mismatch"):
                runner._original_admin_receipts(private, {**diagnostics, field: value}, terminal, "chosen")
        changed = copy.deepcopy(private)
        changed["composedBudgetEvidence"]["storageCases"][0]["adminReceipt"]["restriction"]["mode"] = 0
        with self.assertRaisesRegex(ValueError, "original-admin-receipt-mismatch"):
            runner._original_admin_receipts(changed, diagnostics, terminal, "chosen")

    def test_checkpoint_retains_unknown_native_failure_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            collector._checkpoint(root, {"phase": "before", "operationId": 17})
            collector._checkpoint(root, {"phase": "interrupted", "native": None})
            lines = (root / collector.ATTEMPTS_FILE).read_text().splitlines()
            self.assertEqual(2, len(lines))
            (root / collector.ATTEMPTS_FILE).unlink()
            (root / collector.ATTEMPTS_FILE).symlink_to(root / "unrelated")
            with self.assertRaises(OSError):
                collector._checkpoint(root, {"phase": "before"})
            self.assertFalse((root / "unrelated").exists())

    def test_private_checkpoint_is_typed_and_never_accepts_credentials(self):
        row = {"caseId": "window-crossing", "phase": "before",
               "native": {"work": {}, "budget": {}}, "timePlan": {},
               "graph": [{"sourceUri": "USK@private/selected/0"}]}
        raw = json.dumps(row).encode() + b"\n"
        self.assertEqual([row], evidence.decode_checkpoints(raw))
        with self.assertRaisesRegex(ValueError, "checkpoint-invalid"):
            evidence.decode_checkpoints(b'{"arbitrary":"value"}\n')
        row["native"]["session"] = "must-not-retain"
        with self.assertRaisesRegex(ValueError, "secret-field"):
            evidence.decode_checkpoints(json.dumps(row).encode())

    def test_fixed_path_runner_imports_outside_checkout_without_pythonpath(self):
        environment = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run([sys.executable, str(Path(runner.__file__).resolve()), "--help"],
                cwd=temporary, env=environment, capture_output=True, timeout=30)
        self.assertEqual(0, result.returncode, result.stderr.decode())

    def test_actual_collector_row_and_snapshot_adapter_reach_owning_consumer(self):
        """Synthetic native input exercises real adapters; the verifier is not mocked."""
        for case in collector.CASES:
            with self.subTest(case=case):
                vector = vectors.installed(case)
                adapter = SimpleNamespace(
                    nodes={collector.transport.ROLE: {"generation": vectors.GENERATION}},
                    journal=SimpleNamespace(node_epochs={("", collector.transport.ROLE): vectors.NODE}))

                def capture(name, graph):
                    selected = vector[name]
                    native = {"work": {"collectorEpoch": vectors.EPOCH,
                        "lastSequence": selected["sequence"], "dropped": 0,
                        "events": [event for event in vector["events"]
                                   if event["sequence"] <= selected["sequence"]]},
                        "budget": {"valid": True, "rates": selected["rates"]}}

                    class Handle:
                        def request(self, method, path, principal=None):
                            if path.endswith("runtime-observation"):
                                return 200, native
                            if path.endswith("/statements"):
                                return 200, {"statements": graph}
                            if path.endswith("/status"):
                                return 200, {"trustGraph": {"statementCount": len(graph)}}
                            raise AssertionError(path)
                    return collector._snapshot(Handle())

                before_raw, before = capture("before", vector["graphBefore"])
                _, during = capture("during", vector["graphBefore"])
                _, after = capture("after", vector["graphAfter"])
                final_raw, recovery = capture("recoveryAfter", vector["graphRecovery"])
                fingerprint = collector._fingerprint({"value": {"importResult": {
                    "documentFingerprint": vector["selectedFingerprint"]}}})
                row = collector._case(adapter, case, vector["variant"], before_raw, before,
                    during, after, recovery, vector["graphBefore"], vector["graphAfter"],
                    vector["graphRecovery"], vector["requestStatus"], 200, final_raw,
                    selected_fingerprint=fingerprint, admin_receipt=vector["adminReceipt"],
                    time_plan=vector["timePlan"])
                result = vectors.StorageContractTests().derive(row)
                self.assertIn(case, result["observedCases"])
                self.assertEqual("not-observed", result["fullAppBudgets"])


class AdministratorTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / "state" / admin.ROLE
        for parts in admin.TARGETS.values():
            target = self.state / "data/node/apps" / Path(*parts)
            target.mkdir(parents=True, mode=0o700)
            for parent in (target, *target.parents):
                if parent == self.root:
                    break
                parent.chmod(0o700)
        self.campaign = {"executionClass": admin.EXECUTION_CLASS,
                         "budgetSelectionDigest": "sha256:" + "a" * 64,
                         "deadlineMonotonicNs": 10**20}
        self.record = {"generation": "b" * 64}
        self.user = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        self.workload = SimpleNamespace(ROOT=self.root, locked=nullcontext,
            retained=lambda handle: (self.campaign, admin.ROLE, self.record),
            account=lambda role: self.user, admit=lambda campaign: None,
            exact=lambda *args: None, manager=lambda *args: {})

    def test_restore_access_keeps_counter_contents_and_never_replays_phase(self):
        target = self.state / "data/node/apps/network-budget/_cryptad_global"
        counter = target / "trust_graph_import.properties"
        counter.write_text("count=7\n")
        faults = admin.FixedStorageFaults(self.workload, "a" * 64)
        # Offline harness substitutes root admission/UID probe, not daemon results.
        # The descriptor-relative traversal and chmod/restoration operate on real files.
        with patch.object(admin.os, "geteuid", return_value=0), \
                patch.object(admin, "_fixed_mount"), \
                patch.object(admin, "_probe_denied") as probe:
            receipt = faults.request("partial-rate-write:restrict")
            self.assertEqual(0o500, stat.S_IMODE(target.stat().st_mode))
            self.assertTrue(receipt["roleUidDenied"])
            self.assertEqual(self.user.pw_uid, probe.call_args.args[1])
            restored = faults.request("partial-rate-write:restore")
            self.assertEqual(0o700, stat.S_IMODE(target.stat().st_mode))
            self.assertFalse(restored["contentsRestored"])
            self.assertEqual("count=7\n", counter.read_text())
            with self.assertRaisesRegex(ValueError, "transition-invalid"):
                faults.request("partial-rate-write:restrict")

    def test_target_symlink_and_caller_path_are_rejected_without_mutation(self):
        target = self.state / "data/node/apps/trust-graph/statements"
        target.rmdir()
        target.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            admin._open_target(self.state, admin.TARGETS["graph-store-unavailable"], os.getuid())
        faults = admin.FixedStorageFaults(self.workload, "a" * 64)
        with self.assertRaisesRegex(ValueError, "command-invalid"):
            faults.request("/tmp/other:restrict")


if __name__ == "__main__":
    unittest.main()

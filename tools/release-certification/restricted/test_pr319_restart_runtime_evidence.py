"""Substitution/privacy vectors; these records never claim real installed execution."""
import copy
import json
import unittest

import pr319_restart_runtime_evidence as evidence
from cryptad_certification import composed_budget_restart_evidence as oracle
from cryptad_certification.tests import test_composed_budget_restart_evidence as vectors


def bound_vector(variant="settled-graceful"):
    row = vectors.process(variant)
    row["evidenceClass"] = oracle.INSTALLED
    if variant != "settled-graceful":
        row["transition"]["exitCode"] = None
    selection = "sha256:" + "d" * 64
    data = {"device": 1, "inode": 2}
    row["dataIdentity"]["fileKey"] = evidence.canonical_digest(data)
    for phase in ("before", "after", "recovery"):
        sample = row[phase]
        for binding in sample["scopeBindings"]:
            if binding["appId"] == "selected-app":
                binding["appId"] = "feed-reader"
        for usage in sample["diagnostics"]["usage"]:
            if usage["appId"] == "selected-app":
                usage["appId"] = "feed-reader"
        sample["diagnostics"]["usage"].sort(key=lambda r: (r["appId"], r["operation"]))
    campaign, boot, handle = "c" * 64, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "e" * 64
    def base(generation, invocation, now):
        return {"schemaVersion": 1, "kind": "pr319-trusted-transition", "role": "candidate-sender",
            "campaign": campaign, "generation": generation, "managerInvocation": invocation,
            "bootId": boot, "selectionDigest": selection, "deadlineMonotonicNs": 10000,
            "observedMonotonicNs": now, "dataIdentity": data}
    phase_receipts = []
    for phase, pid, ticks, generation, invocation, now in (
            ("before", 101, 100, "a" * 64, "a" * 32, 100),
            ("after", 202, 200, "b" * 64, "b" * 32, 300),
            ("recovery", 202, 200, "b" * 64, "b" * 32, 400)):
        sample = row[phase]
        receipt = base(generation, invocation, now) | {"caseId": "restart",
            "phase": "snapshot" if phase != "after" else "readback",
            "daemon": {"hostPid": pid, "hostParentPid": 99, "startTicks": ticks,
                "pidNamespace": "pid:[" + str(pid) + "]", "namespacePids": [pid, 2],
                "executableDigest": "sha256:" + "1" * 64,
                "networkNamespaceIdentity": [4, 5], "mountNamespaceIdentity": [4, 6],
                "userNamespaceIdentity": [4, 7], "rssBytes": 100000, "processThreads": 10,
                "noNewPrivileges": True, "effectiveCapabilities": 0},
            "captureSource": "administrator-fixed-file-store-readback", "capturedMonotonicNs": now,
            "durableUsage": copy.deepcopy(sample["diagnostics"]["usage"]),
            "graphFacts": copy.deepcopy(sample["graph"])}
        scopes = {r["appId"]: r["scope"] for r in sample["scopeBindings"]}
        native = {"work": copy.deepcopy(sample["nativeSnapshot"]),
            "budget": {k: copy.deepcopy(v) for k, v in sample["diagnostics"].items() if k != "usage"}}
        native["budget"]["rates"] = [{"operation": r["operation"], "scope": scopes[r["appId"]],
            "count": r["count"], "windowStartEpochSecond": int(oracle._time(r["windowStart"]))}
            for r in receipt["durableUsage"]]
        phase_receipts.append({"caseId": row["caseId"], "variant": variant, "phase": phase,
                               "receipt": receipt, "native": native})
    stop = {"campaign": campaign, "generation": "a" * 64, "managerInvocation": "a" * 32,
            "bootId": boot, "membership": "only-stop-helper", "descendantCgroups": 0}
    purpose = "graceful" if variant == "settled-graceful" else "abrupt-inflight" if variant == "inflight-abrupt" else "abrupt-settled"
    terminal = base("a" * 64, "a" * 32, 200) | {"caseId": purpose, "phase": "terminal",
        "daemon": phase_receipts[0]["receipt"]["daemon"], "pidfdDeathObserved": True,
        "stopReceipt": stop, "effectiveStopProfile": {"Type": "exec", "KillMode": "control-group",
            "KillSignal": "15", "FinalKillSignal": "9", "SendSIGKILL": "yes",
            "TimeoutStopUSec": "20s", "Restart": "no"}}
    if variant == "settled-graceful":
        terminal.update(gracefulExitObserved=True,
            kernelExit={"source": "linux-ptrace-exit-event", "normalExit": True, "exitCode": 0,
                        "signal": None, "waitStatus": 0},
            terminalManager={"Result": "success", "ExecMainCode": "1", "ExecMainStatus": "0"})
    else:
        terminal["forcedSignal"] = "SIGKILL"
        terminal["startedMonotonicNs"] = 150
        terminal["daemon"] = dict(terminal["daemon"], rssBytes=200000, processThreads=20)
    contexts, originals_context = {}, {}
    for phase in ("before", "after"):
        receipt = next(p["receipt"] for p in phase_receipts if p["phase"] == phase)
        role_digest = evidence.canonical_digest({"handle": handle, **{k: receipt[k] for k in
            ("generation", "managerInvocation", "bootId")}})
        app_contexts = {app: {"appId": app, "role": "candidate-sender",
            "roleEpochDigest": role_digest,
            "daemonEpochDigest": evidence.canonical_digest({k: receipt["daemon"][k]
                for k in ("hostPid", "startTicks", "pidNamespace")}),
            "workerEpochDigest": evidence.canonical_digest({"app": app, "epoch": phase}),
            "sessionDigest": "sha256:" + "f" * 64} for app in evidence.APP_IDS}
        contexts[phase] = app_contexts
        originals_context[receipt["generation"]] = {"handle": handle,
            **{k: receipt[k] for k in ("generation", "managerInvocation", "bootId")}, "apps": app_contexts}
    original_receipts = [phase_receipts[0]["receipt"], terminal,
                         phase_receipts[1]["receipt"], phase_receipts[2]["receipt"]]
    retained_receipts = copy.deepcopy(original_receipts)
    if variant != "settled-graceful":
        intent = base("a" * 64, "a" * 32, 160) | {"caseId": purpose, "phase": "fault-intent",
            "daemon": copy.deepcopy(terminal["daemon"]), "intendedSignal": "SIGKILL",
            "startedMonotonicNs": 150}
        retained_receipts.insert(1, intent)
    attachment = {"schemaVersion": 5, "restartCases": [row], "diagnosticsCases": []}
    private = {"schemaVersion": 1, "kind": "pr319-private-restart-budget", "selectionDigest": selection,
        "contexts": contexts["after"], "attempts": [], "composedBudgetEvidence": attachment,
        "composedBudgetCoverage": {"fullAppBudgets": "not-observed",
            "observedCases": sorted(oracle.derive_cases(attachment))}, "originalReceipts": original_receipts,
        "phaseReceipts": phase_receipts, "epochContexts": [{"caseId": row["caseId"], "variant": variant, **contexts}]}
    diagnostics = {"restartSelectionDigest": selection, "restartAccessCleanup": "completed",
        "restartFaultReceipts": retained_receipts,
        "restartOriginalStops": {"a" * 64: stop}, "restartBootstrapContexts": originals_context}
    host_terminal = {"controllerRecords": {"candidate-sender": {"record": {"state": "quiescent",
        "handle": handle, "campaign": campaign, "bootId": boot,
        "generation": "b" * 64, "managerInvocation": "b" * 32}}}}
    return private, diagnostics, host_terminal, selection


def diagnostic_vector(variant="enumeration-only"):
    private, originals, host_terminal, selection = bound_vector()
    row = vectors.diagnostics(variant)
    row["evidenceClass"] = oracle.INSTALLED
    row["fault"]["targetAppId"] = "feed-reader"
    before_receipt = private["phaseReceipts"][0]["receipt"]
    phases = []
    for name, now in (("before", 100), ("during", 200), ("after", 300), ("recovery", 400)):
        sample = row[name]
        for binding in sample["scopeBindings"]:
            if binding["appId"] == "selected-app":
                binding["appId"] = "feed-reader"
        for usage in sample["diagnostics"]["usage"]:
            if usage["appId"] == "selected-app":
                usage["appId"] = "feed-reader"
        sample["diagnostics"]["usage"].sort(key=lambda r: (r["appId"], r["operation"]))
        receipt = copy.deepcopy(before_receipt)
        receipt.update(observedMonotonicNs=now, capturedMonotonicNs=now,
                       durableUsage=sample["diagnostics"]["usage"], graphFacts=[])
        native = {"work": sample["nativeSnapshot"],
            "budget": {k: v for k, v in sample["diagnostics"].items() if k != "usage"}}
        scopes = {r["appId"]: r["scope"] for r in sample["scopeBindings"]}
        native["budget"]["rates"] = [{"operation": r["operation"], "scope": scopes[r["appId"]],
            "count": r["count"], "windowStartEpochSecond": int(oracle._time(r["windowStart"]))}
            for r in receipt["durableUsage"]]
        phases.append({"caseId": "diagnostics-unavailable", "variant": variant,
                       "phase": name, "receipt": receipt, "native": native})
    case = "diagnostics-enumeration" if variant == "enumeration-only" else "diagnostics-required-key"
    base = {k: v for k, v in before_receipt.items() if k not in
        {"daemon", "durableUsage", "graphFacts", "captureSource", "capturedMonotonicNs"}}
    before = {"device": 1, "inode": 5, "uid": 1000, "gid": 1000, "mode": 448}
    after = dict(before, mode=192 if variant == "enumeration-only" else 128)
    restricted = base | {"caseId": case, "phase": "restricted", "observedMonotonicNs": 150,
        "targetClass": "synthetic-feed-reader-scope", "before": before, "after": after,
        "roleUidEnumerationDenied": True, "roleUidExactKeyReadable": variant == "enumeration-only"}
    restored = {k: v for k, v in base.items() if k != "dataIdentity"} | {
        "caseId": case, "phase": "restored", "observedMonotonicNs": 250,
        "before": after, "after": before, "contentsRestored": False, "selectedPathUnchanged": True}
    stream = [phases[0]["receipt"], restricted, phases[1]["receipt"], restored,
              phases[2]["receipt"], phases[3]["receipt"]]
    attachment = {"schemaVersion": 5, "restartCases": [], "diagnosticsCases": [row]}
    initial_contexts = originals["restartBootstrapContexts"]["a" * 64]["apps"]
    private.update(composedBudgetEvidence=attachment, composedBudgetCoverage={"fullAppBudgets": "not-observed",
        "observedCases": sorted(oracle.derive_cases(attachment))}, contexts=initial_contexts,
        phaseReceipts=phases, originalReceipts=copy.deepcopy(stream), epochContexts=[])
    originals.update(restartFaultReceipts=copy.deepcopy(stream), restartOriginalStops={})
    host_terminal["controllerRecords"]["candidate-sender"]["record"].update(
        generation="a" * 64, managerInvocation="a" * 32)
    return private, originals, host_terminal, selection


class OriginalWitnessTest(unittest.TestCase):
    def test_both_diagnostic_permission_variants_match_real_shape_originals(self):
        for variant in ("enumeration-only", "required-key-unreadable"):
            with self.subTest(variant=variant):
                self.assertTrue(evidence.validate_originals(*diagnostic_vector(variant)))

    def test_later_valid_view_cannot_replace_invalid_middle_interval(self):
        private, originals, terminal, selection = diagnostic_vector()
        row = private["composedBudgetEvidence"]["diagnosticsCases"][0]
        row["during"]["diagnostics"] = copy.deepcopy(row["after"]["diagnostics"])
        with self.assertRaisesRegex(ValueError, "diagnostic-source-substitution"):
            evidence.validate_originals(private, originals, terminal, selection)

    def test_write_fault_receipt_cannot_be_relabelled_as_enumeration_fault(self):
        private, originals, terminal, selection = diagnostic_vector()
        originals["restartFaultReceipts"][1]["roleUidExactKeyReadable"] = False
        private["originalReceipts"] = copy.deepcopy(originals["restartFaultReceipts"])
        with self.assertRaisesRegex(ValueError, "diagnostic-fault-substitution"):
            evidence.validate_originals(private, originals, terminal, selection)

    def test_restore_contents_or_path_substitution_rejects_diagnostic_credit(self):
        for field in ("contentsRestored", "selectedPathUnchanged"):
            private, originals, terminal, selection = diagnostic_vector()
            receipt = originals["restartFaultReceipts"][3]
            receipt[field] = not receipt[field]
            private["originalReceipts"] = copy.deepcopy(originals["restartFaultReceipts"])
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "diagnostic-fault-substitution"):
                evidence.validate_originals(private, originals, terminal, selection)

    def test_consistency_vector_matches_separate_original_stream(self):
        for variant in ("settled-graceful", "settled-abrupt", "inflight-abrupt"):
            with self.subTest(variant=variant):
                self.assertTrue(evidence.validate_originals(*bound_vector(variant)))

    def test_forced_restart_requires_exactly_one_retained_fault_intent(self):
        for variant in ("settled-abrupt", "inflight-abrupt"):
            for duplicate in (False, True):
                private, originals, terminal, selection = bound_vector(variant)
                stream = originals["restartFaultReceipts"]
                intent = stream.pop(1)
                if duplicate:
                    stream[1:1] = [intent, copy.deepcopy(intent)]
                with self.subTest(variant=variant, duplicate=duplicate), self.assertRaisesRegex(
                        ValueError, "forced-intent-missing"):
                    evidence.validate_originals(private, originals, terminal, selection)

    def test_forced_intent_must_bind_same_daemon_selection_generation_and_signal(self):
        for variant in ("settled-abrupt", "inflight-abrupt"):
            for field, replacement in (
                    ("generation", "f" * 64), ("managerInvocation", "f" * 32),
                    ("selectionDigest", "sha256:" + "f" * 64), ("bootId", "other-boot"),
                    ("campaign", "f" * 64), ("daemon", {"hostPid": 999, "startTicks": 100,
                                                         "pidNamespace": "pid:[999]"}),
                    ("dataIdentity", {"device": 1, "inode": 99}), ("intendedSignal", "SIGTERM"),
                    ("deadlineMonotonicNs", 9999), ("startedMonotonicNs", 151)):
                private, originals, terminal, selection = bound_vector(variant)
                originals["restartFaultReceipts"][1][field] = replacement
                with self.subTest(variant=variant, field=field), self.assertRaises(ValueError):
                    evidence.validate_originals(private, originals, terminal, selection)

    def test_forced_intent_requires_pretermination_time_and_receipt_order(self):
        for variant in ("settled-abrupt", "inflight-abrupt"):
            for now in (99, 149, 200, 201):
                private, originals, terminal, selection = bound_vector(variant)
                originals["restartFaultReceipts"][1]["observedMonotonicNs"] = now
                with self.subTest(variant=variant, now=now), self.assertRaisesRegex(
                        ValueError, "forced-intent-order-invalid"):
                    evidence.validate_originals(private, originals, terminal, selection)
            for index in (0, 2, 3):
                private, originals, terminal, selection = bound_vector(variant)
                stream = originals["restartFaultReceipts"]
                intent = stream.pop(1)
                stream.insert(index, intent)
                with self.subTest(variant=variant, index=index), self.assertRaisesRegex(
                        ValueError, "forced-intent-order-invalid"):
                    evidence.validate_originals(private, originals, terminal, selection)

    def test_forced_restart_accepts_independently_changed_resource_samples(self):
        for variant in ("settled-abrupt", "inflight-abrupt"):
            for field, replacement in (("rssBytes", 300000), ("processThreads", 30)):
                private, originals, terminal, selection = bound_vector(variant)
                for receipt in originals["restartFaultReceipts"][1:3]:
                    receipt["daemon"] = dict(receipt["daemon"], **{field: replacement})
                private["originalReceipts"][1] = copy.deepcopy(originals["restartFaultReceipts"][2])
                with self.subTest(variant=variant, field=field):
                    self.assertTrue(evidence.validate_originals(private, originals, terminal, selection))

    def test_matching_forced_receipts_cannot_substitute_immutable_daemon_identity(self):
        for variant in ("settled-abrupt", "inflight-abrupt"):
            for field, replacement in (("hostPid", 102), ("startTicks", 101),
                    ("executableDigest", "sha256:" + "2" * 64), ("pidNamespace", "pid:[102]"),
                    ("namespacePids", [101, 3]), ("networkNamespaceIdentity", [4, 8]),
                    ("mountNamespaceIdentity", [4, 8]), ("userNamespaceIdentity", [4, 8])):
                private, originals, terminal, selection = bound_vector(variant)
                for receipt in originals["restartFaultReceipts"][1:3]:
                    receipt["daemon"] = dict(receipt["daemon"], **{field: replacement})
                private["originalReceipts"][1] = copy.deepcopy(originals["restartFaultReceipts"][2])
                with self.subTest(variant=variant, field=field), self.assertRaisesRegex(
                        ValueError, "forced-intent-substitution"):
                    evidence.validate_originals(private, originals, terminal, selection)

    def test_intent_and_terminal_must_preserve_the_exact_same_daemon_sample(self):
        for variant in ("settled-abrupt", "inflight-abrupt"):
            for field, replacement in (("rssBytes", 300000), ("processThreads", 30)):
                private, originals, terminal, selection = bound_vector(variant)
                receipt = originals["restartFaultReceipts"][2]
                receipt["daemon"] = dict(receipt["daemon"], **{field: replacement})
                private["originalReceipts"][1] = copy.deepcopy(receipt)
                with self.subTest(variant=variant, field=field), self.assertRaisesRegex(
                        ValueError, "forced-intent-substitution"):
                    evidence.validate_originals(private, originals, terminal, selection)

    def test_self_consistent_substituted_guest_receipt_is_rejected(self):
        private, originals, terminal, selection = bound_vector()
        for changed_field, replacement in (("generation", "f" * 64), ("bootId", "other-boot")):
            changed = copy.deepcopy(private)
            changed["originalReceipts"][1][changed_field] = replacement
            with self.subTest(field=changed_field), self.assertRaisesRegex(ValueError, "receipt-stream-substitution"):
                evidence.validate_originals(changed, originals, terminal, selection)

    def test_wrong_actual_stop_or_worker_epoch_never_authenticates_guest(self):
        private, originals, terminal, selection = bound_vector()
        changed = copy.deepcopy(originals)
        changed["restartOriginalStops"]["a" * 64]["managerInvocation"] = "f" * 32
        with self.assertRaisesRegex(ValueError, "stop-original-substitution"):
            evidence.validate_originals(private, changed, terminal, selection)
        changed = copy.deepcopy(originals)
        changed["restartBootstrapContexts"]["b" * 64]["apps"]["feed-reader"]["workerEpochDigest"] = "changed"
        with self.assertRaisesRegex(ValueError, "bootstrap-original-substitution"):
            evidence.validate_originals(private, changed, terminal, selection)

    def test_reused_scope_or_fabricated_metadata_cannot_replace_file_readback(self):
        private, originals, terminal, selection = bound_vector()
        for modify in (
            lambda p: p["composedBudgetEvidence"]["restartCases"][0]["after"]["scopeBindings"][-1].update(scope=3),
            lambda p: p["composedBudgetEvidence"]["restartCases"][0]["after"]["diagnostics"]["usage"][0].update(count=0),
            lambda p: p["composedBudgetEvidence"]["restartCases"][0]["after"]["graph"][0].update(updatedAt=vectors.stamp(vectors.W1+2))):
            changed = copy.deepcopy(private)
            modify(changed)
            with self.assertRaises(ValueError):
                evidence.validate_originals(changed, originals, terminal, selection)

    def test_wrapper_success_cannot_replace_true_kernel_exit(self):
        private, originals, terminal, selection = bound_vector()
        original = originals["restartFaultReceipts"][1]
        original["kernelExit"].update(normalExit=False, exitCode=None, signal=9, waitStatus=9)
        private["originalReceipts"][1] = copy.deepcopy(original)
        with self.assertRaisesRegex(ValueError, "graceful-kernel-exit-substitution"):
            evidence.validate_originals(private, originals, terminal, selection)


class PrivacyTest(unittest.TestCase):
    def test_private_checkpoint_preserves_expected_invalid_interval(self):
        row = vectors.diagnostics()
        checkpoint = {"caseId": "diagnostics-unavailable", "variant": "enumeration-only",
                      "phase": "during", "sample": row["during"]}
        self.assertEqual([checkpoint], evidence.decode_checkpoints(json.dumps(checkpoint).encode()))
        checkpoint["phase"] = "invented"
        with self.assertRaises(ValueError):
            evidence.decode_checkpoints(json.dumps(checkpoint).encode())

    def test_original_diagnostics_allows_only_typed_original_subjects(self):
        _, diagnostics, _, _ = bound_vector()
        diagnostics["classification"] = "private-kernel-diagnostics-not-acceptance"
        receipt = diagnostics["restartFaultReceipts"][0]
        receipt["graphFacts"][0]["document"]["marker"] = "PR319_PRIVATE_GRAPH_CANARY"
        raw = json.dumps(diagnostics).encode()
        self.assertEqual(diagnostics, evidence.decode_original_diagnostics(raw))
        diagnostics["extraPublicCanary"] = "PR319_PRIVATE_LEAK_CANARY"
        with self.assertRaisesRegex(ValueError, "diagnostic-unapproved-payload"):
            evidence.decode_original_diagnostics(json.dumps(diagnostics).encode())
        diagnostics.pop("extraPublicCanary")
        receipt["arbitraryPrivateCanary"] = "PR319_PRIVATE_LEAK_CANARY"
        with self.assertRaisesRegex(ValueError, "receipt-fields-invalid"):
            evidence.decode_original_diagnostics(json.dumps(diagnostics).encode())

    def test_encoded_private_canaries_are_rejected_on_public_surfaces(self):
        import base64
        self.assertTrue(evidence.payload_exposed(b"PR319_PRIVATE_CANARY"))
        self.assertTrue(evidence.payload_exposed(base64.b64encode(b"PR319_PRIVATE_CANARY")))
        self.assertTrue(evidence.payload_exposed(b"PR319%5FPRIVATE%5FCANARY"))
        self.assertFalse(evidence.payload_exposed(b'{"status":"incomplete"}'))

    def test_private_decode_rejects_duplicate_fields_and_token_canary(self):
        private, _, _, _ = bound_vector()
        self.assertEqual(private, evidence.decode_private(json.dumps(private).encode()))
        with self.assertRaises(ValueError):
            evidence.decode_private(b'{"schemaVersion":1,"schemaVersion":1}')
        private["contexts"]["feed-reader"]["session"] = "PRIVATE_BEARER_CANARY"
        with self.assertRaisesRegex(ValueError, "secret-field"):
            evidence.decode_private(json.dumps(private).encode())

    def test_censored_owner_tail_remains_visible_and_cannot_make_overall_pass(self):
        private, _, _, selection = bound_vector('inflight-abrupt')
        public = evidence.public_projection(private, source_identity_digest='sha256:' + 'a' * 64,
            selection_digest=selection, cleanup_verified=True, guest_stopped=True,
            watcher_finished=True, privacy_verified=True)
        self.assertEqual(['inflight-abrupt'], public['censoredVariants'])
        self.assertEqual('incomplete', public['status'])
        self.assertFalse(public['phaseComplete'])

    def test_public_projection_emits_only_fixed_codes_and_scoped_completion(self):
        private, _, _, selection = bound_vector()
        public = evidence.public_projection(private, source_identity_digest="sha256:" + "a" * 64,
            selection_digest=selection, cleanup_verified=True, guest_stopped=True,
            watcher_finished=True, privacy_verified=True)
        self.assertEqual("incomplete", public["status"])
        self.assertEqual(["graceful-restart"], public["observedCases"])
        self.assertFalse(public["phaseComplete"])
        self.assertFalse(public["releaseEligible"])
        self.assertEqual("not-observed", public["fullAppBudgets"])
        raw = json.dumps(public)
        for canary in ("feed-reader", "pidNamespace", "inode", "documentFingerprint", selection):
            self.assertNotIn(canary, raw)
        with self.assertRaisesRegex(ValueError, "terminal-evidence-incomplete"):
            evidence.public_projection(private, source_identity_digest="sha256:" + "a" * 64,
                selection_digest=selection, cleanup_verified=False, guest_stopped=True,
                watcher_finished=True, privacy_verified=True)


if __name__ == "__main__":
    unittest.main()

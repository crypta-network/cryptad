"""Closed unit checks for the namespace-bound PR-317 observer adapter."""
from __future__ import annotations

import copy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import cross_version_installed_budgets as budgets


def context(app_id="feed-reader"):
    return {"appId": app_id, "role": "candidate-sender", "handle": "a" * 64,
            "generation": "b" * 64, "managerInvocation": "c" * 32,
            "bootId": "01234567-89ab-cdef-0123-456789abcdef",
            "daemonEpoch": {"startTicks": 1},
            "worker": {"fixtureProcess": {"startTicks": 2}},
            "origin": "http://127.0.0.1:21001", "session": "private-session",
            "sessionExpiresAt": "2026-10-12T20:00:00Z"}


def snapshot(sequence, events, *, active=0, graph=0):
    return {"retainedStatements": graph,
            "work": {"known": True, "collectorEpoch":
                     "01234567-89ab-cdef-0123-456789abcdef",
                     "lastSequence": sequence, "dropped": 0, "events": events},
            "budget": {"valid": True, "activeFamilyLeases": active,
                       "reservedFamilyRates": 0, "rates": []}}


def event(sequence, kind, operation_id=7, operation="trust_graph_import", scope=3):
    return {"sequence": sequence, "observedAt": "2026-10-12T19:00:00Z",
            "elapsedNanos": sequence, "kind": kind, "operation": operation,
            "windowStartEpochSecond": 0, "value": 0,
            "operationId": operation_id, "scope": scope,
            "sourceEpoch": None, "sourceSequence": 0,
            "sourceSampledAtEpochMillis": 0}


class InstalledBudgetAdapterTest(unittest.TestCase):
    def test_import_finds_fixed_helpers_without_pythonpath_or_checkout_working_directory(self):
        script = """
import sys
sys.path.insert(0, sys.argv[1])
original = list(sys.path)
import cross_version_installed_budgets as budgets
assert budgets.composed.__name__ == 'cryptad_certification.composed_budget_evidence'
assert budgets.pressure.__name__ == 'cryptad_certification.runtime_pressure_evidence'
assert sys.path == original
"""
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, '-I', '-B', '-c', script,
                 str(Path(budgets.__file__).resolve().parent)],
                cwd=directory, capture_output=True, text=True, timeout=15, check=False)

        self.assertEqual(0, result.returncode, result.stderr)

    def test_start_readiness_failure_kills_and_reaps_spawned_client(self):
        class Channel:
            def poll(self, _):
                return True

            def recv(self):
                raise EOFError()

            def close(self):
                pass

        class Process:
            exitcode = None

            def __init__(self, **_):
                self.live = False
                self.killed = False

            def start(self):
                self.live = True

            def is_alive(self):
                return self.live

            def kill(self):
                self.killed = True
                self.live = False

            def join(self, _):
                pass

        parent, child, process = Channel(), Channel(), Process()
        context_factory = type("Context", (), {
            "Pipe": lambda _self, duplex=True: (parent, child),
            "Process": lambda _self, **_kwargs: process})()
        with patch.object(budgets.multiprocessing, "get_context",
                          return_value=context_factory), self.assertRaises(EOFError):
            budgets.FixedClientProcess.start(
                context(), {"method": "GET", "path": "/api/v1/trust-graph/statements"},
                budgets.time.monotonic() + 1)
        self.assertTrue(process.killed)

    def test_request_and_owner_deadlines_remain_distinct_selected_bounds(self):
        adapter = type("Adapter", (), {
            "deadline": budgets.time.monotonic() + 1000,
            "authorization": {"budgetSelection": {"failurePolicy": {
                "requestDeadlineMillis": 45000,
                "ownerAcknowledgmentDeadlineMillis": 12000}}}})()
        started = budgets.time.monotonic()

        request_deadline = budgets._request_deadline(adapter)

        self.assertLessEqual(request_deadline, started + 45.1)
        self.assertEqual(12, budgets._policy_seconds(
            adapter, "ownerAcknowledgmentDeadlineMillis"))

    def test_context_is_exact_role_bound_and_redacted_for_evidence(self):
        selected = context()
        self.assertEqual(selected, budgets._context(selected, "feed-reader"))
        evidence = budgets._context_evidence(selected)
        self.assertEqual({"appId", "role", "roleEpochDigest", "daemonEpochDigest",
                          "workerEpochDigest", "originDigest", "sessionDigest",
                          "sessionExpiryDigest"}, set(evidence))
        self.assertNotIn(selected["session"], str(evidence))
        self.assertNotIn(selected["origin"], str(evidence))

    def test_context_rejects_free_form_identity_and_management_origin(self):
        for mutate in (
                lambda value: value.update(appId="unknown"),
                lambda value: value.update(role="candidate-recipient"),
                lambda value: value.update(origin="http://127.0.0.1:19402"),
                lambda value: value.update(extra=True)):
            selected = context()
            mutate(selected)
            with self.assertRaises(budgets.runtime.RuntimeFailure):
                budgets._context(selected)

    def test_denial_only_context_can_bind_recipient_transport_epoch(self):
        selected = context()
        selected.update(role="candidate-recipient", handle="d" * 64,
                        generation="e" * 64, managerInvocation="f" * 32)
        self.assertEqual(selected, budgets._context(
            selected, expected_role="candidate-recipient"))
        with self.assertRaises(budgets.runtime.RuntimeFailure):
            budgets._context(selected)

    def test_fixed_http_connection_cannot_reconnect(self):
        connection = budgets._FixedHttp("127.0.0.1", 19402)
        with self.assertRaisesRegex(budgets.runtime.RuntimeFailure,
                                    "implicit-reconnect-forbidden"):
            connection.connect()

    def test_request_policy_rejects_redirect_or_arbitrary_endpoint_before_io(self):
        class NoIo:
            def settimeout(self, _):
                self.fail = True

            def close(self):
                pass

        for path in ("http://example.test/", "/api/v1/operator/runtime-observation",
                     "/api/v1/trust-graph/import-uri?redirect=x", "/api/v1/../private"):
            with self.assertRaises(budgets.runtime.RuntimeFailure):
                budgets._request_over_socket(NoIo(), context(),
                    {"method": "POST", "path": path, "parameters": {}},
                    budgets.time.monotonic() + 1)

    def test_active_holds_distinguish_concurrency_and_rate_reservation(self):
        rows = [event(1, "CONCURRENCY_HELD"), event(2, "RATE_RESERVED")]
        held = budgets._active_holds(snapshot(2, rows))
        self.assertEqual({"concurrency", "rate"}, {row["kind"] for row in held})
        rows += [event(3, "CONCURRENCY_RELEASED")]
        held = budgets._active_holds(snapshot(3, rows))
        self.assertEqual(["rate"], [row["kind"] for row in held])

    def test_principal_denial_snapshot_must_be_completely_unchanged(self):
        before = snapshot(0, [])
        after = copy.deepcopy(before)
        self.assertTrue(budgets._unchanged_native(before, after))
        after["budget"]["rates"] = [{"operation": "trust_graph_import",
            "scope": 3, "windowStartEpochSecond": 1, "count": 1}]
        self.assertFalse(budgets._unchanged_native(before, after))

    def test_causal_case_requires_complete_contiguous_window(self):
        start = event(2, "COMPOSED_DIRECT_IMPORT_START")
        finish = event(4, "REQUEST_FAILED")
        before = snapshot(1, [])
        during = snapshot(2, [start], active=2)
        after = snapshot(4, [start, finish])
        with self.assertRaisesRegex(budgets.runtime.RuntimeFailure,
                                    "causal-sequence-gap"):
            budgets._causal_case("import-concurrency", before, during, after,
                operation_id=7, roles={7: "contender-parent"},
                request_outcome="denied", owner_outcome="not-applicable")

    def test_selection_binds_exact_class_roster_and_five_cases(self):
        apps = {"candidate-sender": list(budgets.APP_IDS),
                "candidate-recipient": [], "previous": [], "relay-no-apps": []}
        private = {"root": "/var/lib/cryptad-cross-version/experiments/" + budgets.EXPERIMENT,
                   "nodes": {role: {"apps": [{"appId": app} for app in selected]}
                             for role, selected in apps.items()}}
        plan = {"experimentId": budgets.EXPERIMENT}
        digest = budgets.runtime.canonical_digest(plan)
        selected = {"caseIds": list(budgets.CASES)}
        authorization = {"executionClass": budgets.EXECUTION_CLASS,
                         "planDigest": digest, "budgetSelection": selected,
                         "selectionDigest": budgets.runtime.canonical_digest({
                             "executionClass": budgets.EXECUTION_CLASS,
                             "planDigest": digest, "budgetSelection": selected})}
        adapter = type("Adapter", (), {"plan": plan, "private": private,
                                        "authorization": authorization})()
        self.assertEqual(authorization["selectionDigest"],
                         budgets._validate_selection(adapter))
        changed = copy.deepcopy(adapter)
        changed.authorization["budgetSelection"]["caseIds"].pop()
        with self.assertRaisesRegex(budgets.runtime.RuntimeFailure,
                                    "execution-class-unbound"):
            budgets._validate_selection(changed)


if __name__ == "__main__":
    unittest.main()

"""Private/public boundary checks for the PR-317 installed budget result."""
import json
import base64
import unittest

import pr317_budget_runtime_evidence as evidence


DIGEST = "sha256:" + "a" * 64
EPOCH = "01234567-89ab-cdef-0123-456789abcdef"


def private():
    contexts = {}
    for app_id in evidence.APP_IDS:
        contexts[app_id] = {"appId": app_id, "role": "candidate-sender",
            "roleEpochDigest": DIGEST, "daemonEpochDigest": DIGEST,
            "workerEpochDigest": DIGEST, "originDigest": DIGEST,
            "sessionDigest": DIGEST, "sessionExpiryDigest": DIGEST}
    attempts = [{"kind": "principal-denials", "wrongRole": 401,
        "wrongOrigin": 401, "invalidSession": 401, "collectorEpoch": EPOCH,
        "beforeSequence": 1, "afterSequence": 1},
        {"kind": "causal-case-attempt", "caseId": "retry", "status": "observed"},
        {"kind": "causal-case-attempt", "caseId": "import-concurrency",
         "status": "observed"},
        {"kind": "causal-case-attempt", "caseId": "fetch-concurrency",
         "status": "observed"},
        {"kind": "causal-case-attempt", "caseId": "cancellation",
         "status": "not-observed", "reason": "abandoned-owner-not-active",
         "ownerCancellation": "not-observed"},
        {"kind": "causal-case-attempt", "caseId": "timeout",
         "status": "not-observed", "reason": "normal-owner-ack-unobserved"}]
    coverage = {"schemaVersion": 1, "kind": "composed-budget-coverage",
        "requiredCases": [], "observedCases": [], "missingCases": [],
        "evidenceClass": "native-observation-local-consistency",
        "originalAuthentication": "not-established",
        "fullAppBudgets": "not-observed", "releaseEligible": False}
    attachment = {"schemaVersion": 3, "collectorEpoch": EPOCH,
        "nodeEpoch": "b" * 32, "workloadDigest": DIGEST,
        "productDigest": DIGEST, "sourceCommit": "c" * 40,
        "appCohortDigest": DIGEST, "collectorDigest": DIGEST,
        "configurationDigest": DIGEST, "segments": [], "causalCases": []}
    return {"schemaVersion": 1, "kind": evidence.PRIVATE_KIND,
        "executionClass": evidence.EXECUTION_CLASS, "selectionDigest": DIGEST,
        "window": {"startedMonotonicNs": 1, "finishedMonotonicNs": 2},
        "contexts": contexts, "attempts": attempts,
        "nativeWindow": {"before": {"work": {"collectorEpoch": EPOCH}, "budget": {}},
                         "after": {"work": {"collectorEpoch": EPOCH}, "budget": {}}},
        "composedBudgetEvidence": attachment, "composedBudgetCoverage": coverage,
        "observedCases": [], "notObservedCases": list(evidence.CASES),
        "remainingHardCases": list(evidence.HARD_CASES)}


class BudgetRuntimeEvidenceTest(unittest.TestCase):
    def test_private_result_preserves_all_cases_and_false_full_claim(self):
        value = private()
        self.assertEqual(value, evidence.validate_private_observation(value))
        self.assertEqual(value, evidence.decode_private(json.dumps(value).encode()))
        projected = evidence.public_projection(value,
            source_identity_digest=DIGEST, selection_digest=DIGEST,
            cleanup_verified=True, guest_stopped=True, watcher_finished=True,
            privacy_verified=True)
        self.assertEqual("incomplete", projected["status"])
        self.assertTrue(projected["namespaceTransportImplemented"])
        self.assertTrue(projected["terminalCleanupVerified"])
        self.assertNotIn("selectionDigest", projected)
        self.assertEqual(list(evidence.CASES), projected["notObservedCases"])
        self.assertEqual(["cancellation"], projected["unsupportedInstalledCases"])
        self.assertNotIn("cancellation", projected["installedDriverCases"])
        self.assertEqual("not-observed", projected["fullAppBudgets"])
        self.assertFalse(projected["ownerCancelledInstalledDirection"])
        self.assertFalse(projected["phaseComplete"])

    def test_private_result_rejects_session_or_insert_capability(self):
        for field, selected in (("session", "secret"), ("insertUri", "USK@private")):
            value = private()
            value["attempts"][0][field] = selected
            with self.assertRaises(ValueError):
                evidence.validate_private_observation(value)

    def test_private_result_rejects_credential_relabelled_as_unknown_attempt_field(self):
        value = private()
        value["attempts"][0]["reason"] = "opaqueBrowserCredentialValue"
        self.assertFalse(evidence.payload_exposed(json.dumps(value).encode()))

        with self.assertRaisesRegex(ValueError, "principal-attempt-invalid"):
            evidence.validate_private_observation(value)

    def test_private_result_rejects_missing_five_case_attempt(self):
        value = private()
        value["attempts"].pop()
        with self.assertRaisesRegex(ValueError, "attempt-roster"):
            evidence.validate_private_observation(value)

    def test_private_result_accepts_closed_cancellation_and_timeout_outcomes(self):
        value = private()
        value["attempts"][4] = {"kind": "causal-case-attempt",
            "caseId": "cancellation", "status": "abandonment-observed",
            "ownerCancellation": "not-observed", "contenderStatus": 429,
            "beforeSequence": 1, "duringSequence": 2, "afterSequence": 3}
        value["attempts"][5] = {"kind": "causal-case-attempt",
            "caseId": "timeout", "status": "observed"}
        evidence.validate_private_observation(value)

        changed = private()
        changed["attempts"][4]["reason"] = "abandoned-owner-terminal-unknown"
        evidence.validate_private_observation(changed)

        timeout_reasons = {
            "request-did-not-time-out": True,
            "delayed-owner-tail-not-observed": False,
            "retained-slot-not-denied": True,
            "normal-owner-ack-unobserved": False,
            "timeout-recovery-failed": True,
            "timeout-operation-identities-missing": False,
        }
        for reason, has_status in timeout_reasons.items():
            changed = private()
            changed["attempts"][5] = {"kind": "causal-case-attempt",
                "caseId": "timeout", "status": "not-observed", "reason": reason}
            if has_status:
                changed["attempts"][5]["httpStatus"] = 500
            with self.subTest(reason=reason):
                evidence.validate_private_observation(changed)

    def test_private_result_rejects_full_budget_upgrade(self):
        value = private()
        value["composedBudgetCoverage"]["fullAppBudgets"] = "observed"
        with self.assertRaisesRegex(ValueError, "coverage-invalid"):
            evidence.validate_private_observation(value)

    def test_private_result_rejects_malformed_native_window_with_closed_error(self):
        for malformed in (None, {}, {"before": {}, "after": {}},
                          {"before": {"work": None}, "after": {"work": {}}}):
            value = private()
            value["nativeWindow"] = malformed
            with self.subTest(malformed=malformed), self.assertRaisesRegex(
                    ValueError, "native-window-invalid"):
                evidence.validate_private_observation(value)
            with self.subTest(decoded=malformed), self.assertRaisesRegex(
                    ValueError, "native-window-invalid"):
                evidence.decode_private(json.dumps(value).encode())

    def test_failed_projection_is_closed_and_identifier_free(self):
        value = evidence.failed_projection("installed-runtime-not-executed")
        self.assertEqual("failed", value["status"])
        self.assertFalse(value["releaseEligible"])
        self.assertFalse(value["phaseComplete"])
        self.assertEqual(list(evidence.HARD_CASES), value["remainingHardCases"])

    def test_privacy_scanner_detects_raw_corpus_and_session_fields(self):
        self.assertTrue(evidence.payload_exposed(b'{"session":"secret"}'))
        self.assertTrue(evidence.payload_exposed(b'PR309_PRIVATE_BODY_CANARY'))
        self.assertTrue(evidence.payload_exposed(b'USK@private'))
        self.assertTrue(evidence.payload_exposed(b'PR309_PRIVATE_BODY%5FCANARY'))
        self.assertTrue(evidence.payload_exposed(
            base64.b64encode(b'PR309_PRIVATE_BODY_CANARY')))
        self.assertFalse(evidence.payload_exposed(b'{"sessionDigest":"sha256:safe"}'))


if __name__ == "__main__":
    unittest.main()

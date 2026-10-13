"""Validate and project the private PR-317 installed budget lifecycle observation."""
from __future__ import annotations

import hashlib
import base64
import json
import re
import urllib.parse


EXECUTION_CLASS = "pr317-namespace-bound-composed-budget-v1"
PRIVATE_KIND = "pr317-private-composed-budget-lifecycle"
PRIVATE_FILENAME = "pr317-composed-budget-lifecycle.private.json"
PUBLIC_KIND = "pr317-composed-budget-lifecycle-assessment"
CASES = ("import-concurrency", "fetch-concurrency", "timeout", "cancellation", "retry")
HARD_CASES = ("window-crossing", "partial-rate-write", "graph-store-unavailable",
              "graceful-restart", "abrupt-restart", "diagnostics-unavailable", "privacy")
APP_IDS = ("feed-reader", "budget-importer", "budget-no-trust", "budget-no-fetch")
MAX_PRIVATE_BYTES = 4 * 1024 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_ATTEMPT_CASES = ("retry", "import-concurrency", "fetch-concurrency",
                  "cancellation", "timeout")


def canonical_digest(value):
    return "sha256:" + hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def payload_exposed(raw):
    """Detect private corpus/session material in retained public-candidate surfaces."""
    if not isinstance(raw, bytes):
        return True
    markers = (b"PR309_PRIVATE_", b'"session":', b'"browserSessionToken":',
               b'"insertUri":', b"SSK@", b"USK@", b"CHK@", b"CRYPTAD_APP_TOKEN")
    decoded = urllib.parse.unquote_to_bytes(raw)
    if any(marker in raw or marker in decoded for marker in markers):
        return True
    for token in re.findall(rb"[A-Za-z0-9+/]{16,}={0,2}", raw):
        try:
            candidate = base64.b64decode(token, validate=True)
        except ValueError:
            continue
        if any(marker in candidate for marker in markers):
            return True
    return False


def _exact(value, fields, code):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError(code)
    return value


def _safe_tree(value, depth=0):
    """Reject credential/URI/path-shaped private output, including digest-key relabeling."""
    if depth > 32:
        raise ValueError("pr317-private-depth-limit")
    if isinstance(value, dict):
        forbidden = {"session", "browserSessionToken", "insertUri", "statementBase64",
                     "privateKey", "formPassword", "commandLine", "absolutePath"}
        if set(value) & forbidden:
            raise ValueError("pr317-private-secret-field")
        for key, selected in value.items():
            if not isinstance(key, str) or len(key) > 128:
                raise ValueError("pr317-private-key-invalid")
            _safe_tree(selected, depth + 1)
    elif isinstance(value, list):
        if len(value) > 8192:
            raise ValueError("pr317-private-list-limit")
        for selected in value:
            _safe_tree(selected, depth + 1)
    elif isinstance(value, str):
        if len(value) > 8192 or "SSK@" in value or "USK@" in value \
                or "CHK@" in value or "CRYPTAD_APP_TOKEN" in value \
                or value.startswith(("/var/", "/root/", "/tmp/", "/home/")):
            raise ValueError("pr317-private-string-invalid")
    elif value is not None and type(value) not in {bool, int, float}:
        raise ValueError("pr317-private-value-invalid")


def _sequence(value):
    return type(value) is int and 0 <= value <= 2**53 - 1


def _http_status(value):
    return type(value) is int and 100 <= value <= 599


def _validate_principal_attempt(value):
    _exact(value, {"kind", "wrongRole", "wrongOrigin", "invalidSession",
        "collectorEpoch", "beforeSequence", "afterSequence"},
        "pr317-private-principal-attempt-invalid")
    if (value["kind"] != "principal-denials"
            or any(value[name] != 401 for name in
                   ("wrongRole", "wrongOrigin", "invalidSession"))
            or re.fullmatch(r"[0-9a-f-]{36}", str(value["collectorEpoch"])) is None
            or not _sequence(value["beforeSequence"])
            or not _sequence(value["afterSequence"])
            or value["beforeSequence"] > value["afterSequence"]):
        raise ValueError("pr317-private-principal-attempt-invalid")


def _validate_cancellation_attempt(value):
    base = {"kind", "caseId", "status", "ownerCancellation"}
    if value.get("status") == "not-observed":
        _exact(value, base | {"reason"}, "pr317-private-cancellation-attempt-invalid")
        if value.get("reason") not in {
                "abandoned-owner-not-active", "abandoned-owner-terminal-unknown"}:
            raise ValueError("pr317-private-cancellation-attempt-invalid")
    elif value.get("status") == "abandonment-observed":
        _exact(value, base | {"contenderStatus", "beforeSequence", "duringSequence",
            "afterSequence"}, "pr317-private-cancellation-attempt-invalid")
        sequences = [value.get(name) for name in
                     ("beforeSequence", "duringSequence", "afterSequence")]
        if (not _http_status(value.get("contenderStatus"))
                or not all(_sequence(sequence) for sequence in sequences)
                or sequences != sorted(sequences) or len(set(sequences)) != len(sequences)):
            raise ValueError("pr317-private-cancellation-attempt-invalid")
    else:
        raise ValueError("pr317-private-cancellation-attempt-invalid")
    if (value.get("kind") != "causal-case-attempt"
            or value.get("caseId") != "cancellation"
            or value.get("ownerCancellation") != "not-observed"):
        raise ValueError("pr317-private-cancellation-attempt-invalid")


def _validate_timeout_attempt(value):
    base = {"kind", "caseId", "status"}
    if value.get("status") == "observed":
        _exact(value, base, "pr317-private-timeout-attempt-invalid")
    elif value.get("status") == "not-observed":
        reason = value.get("reason")
        with_status = {"request-did-not-time-out", "retained-slot-not-denied",
                       "timeout-recovery-failed"}
        without_status = {"delayed-owner-tail-not-observed", "normal-owner-ack-unobserved",
                          "timeout-operation-identities-missing"}
        fields = base | {"reason", "httpStatus"} if reason in with_status else base | {"reason"}
        _exact(value, fields, "pr317-private-timeout-attempt-invalid")
        if (reason not in with_status | without_status
                or (reason in with_status and not _http_status(value.get("httpStatus")))):
            raise ValueError("pr317-private-timeout-attempt-invalid")
    else:
        raise ValueError("pr317-private-timeout-attempt-invalid")
    if (value.get("kind") != "causal-case-attempt"
            or value.get("caseId") != "timeout"):
        raise ValueError("pr317-private-timeout-attempt-invalid")


def _validate_attempts(attempts):
    if not isinstance(attempts, list):
        raise ValueError("pr317-private-attempts-invalid")
    if len(attempts) != len(_ATTEMPT_CASES) + 1:
        raise ValueError("pr317-private-attempt-roster-invalid")
    _validate_principal_attempt(attempts[0])
    causal = attempts[1:]
    if [row.get("caseId") if isinstance(row, dict) else None for row in causal] \
            != list(_ATTEMPT_CASES):
        raise ValueError("pr317-private-attempt-roster-invalid")
    for row in causal[:3]:
        _exact(row, {"kind", "caseId", "status"}, "pr317-private-causal-attempt-invalid")
        if row["kind"] != "causal-case-attempt" or row["status"] != "observed":
            raise ValueError("pr317-private-causal-attempt-invalid")
    _validate_cancellation_attempt(causal[3])
    _validate_timeout_attempt(causal[4])


def _validate_native_window(value):
    _exact(value, {"before", "after"}, "pr317-private-native-window-invalid")
    epochs = []
    for name in ("before", "after"):
        snapshot = value[name]
        if (not isinstance(snapshot, dict)
                or not isinstance(snapshot.get("work"), dict)
                or not isinstance(snapshot.get("budget"), dict)):
            raise ValueError("pr317-private-native-window-invalid")
        epoch = snapshot["work"].get("collectorEpoch")
        if re.fullmatch(r"[0-9a-f-]{36}", str(epoch)) is None:
            raise ValueError("pr317-private-native-window-invalid")
        epochs.append(epoch)
    if len(set(epochs)) != 1:
        raise ValueError("pr317-private-native-window-invalid")
    return epochs[0]


def decode_private(raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_PRIVATE_BYTES:
        raise ValueError("pr317-private-bytes-invalid")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("pr317-private-duplicate-field")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("pr317-private-number-invalid")))
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError("pr317-private-json-invalid") from None
    return validate_private_observation(value)


def validate_private_observation(value):
    _exact(value, {"schemaVersion", "kind", "executionClass", "selectionDigest",
        "window", "contexts", "attempts", "nativeWindow", "composedBudgetEvidence",
        "composedBudgetCoverage", "observedCases", "notObservedCases",
        "remainingHardCases"}, "pr317-private-shape-invalid")
    if (value["schemaVersion"] != 1 or value["kind"] != PRIVATE_KIND
            or value["executionClass"] != EXECUTION_CLASS
            or _DIGEST.fullmatch(str(value["selectionDigest"])) is None):
        raise ValueError("pr317-private-contract-invalid")
    window = _exact(value["window"], {"startedMonotonicNs", "finishedMonotonicNs"},
                    "pr317-private-window-invalid")
    if (type(window["startedMonotonicNs"]) is not int
            or type(window["finishedMonotonicNs"]) is not int
            or not 0 < window["startedMonotonicNs"] < window["finishedMonotonicNs"]):
        raise ValueError("pr317-private-window-invalid")
    contexts = _exact(value["contexts"], APP_IDS, "pr317-private-contexts-invalid")
    context_fields = {"appId", "role", "roleEpochDigest", "daemonEpochDigest",
        "workerEpochDigest", "originDigest", "sessionDigest", "sessionExpiryDigest"}
    for app_id, context in contexts.items():
        _exact(context, context_fields, "pr317-private-context-invalid")
        if (context["appId"] != app_id or context["role"] != "candidate-sender"
                or any(_DIGEST.fullmatch(str(context[key])) is None
                       for key in context_fields - {"appId", "role"})):
            raise ValueError("pr317-private-context-invalid")
    _validate_attempts(value["attempts"])
    observed, missing = value["observedCases"], value["notObservedCases"]
    if (not isinstance(observed, list) or not isinstance(missing, list)
            or set(observed) | set(missing) != set(CASES)
            or set(observed) & set(missing) or len(observed) != len(set(observed))
            or len(missing) != len(set(missing))
            or value["remainingHardCases"] != list(HARD_CASES)):
        raise ValueError("pr317-private-case-roster-invalid")
    coverage = value["composedBudgetCoverage"]
    if (not isinstance(coverage, dict)
            or coverage.get("schemaVersion") != 1
            or coverage.get("fullAppBudgets") != "not-observed"
            or coverage.get("releaseEligible") is not False
            or sorted(set(coverage.get("observedCases", [])) & set(CASES)) != sorted(observed)):
        raise ValueError("pr317-private-coverage-invalid")
    native_epoch = _validate_native_window(value["nativeWindow"])
    attachment = value["composedBudgetEvidence"]
    if (not isinstance(attachment, dict) or attachment.get("schemaVersion") != 3
            or attachment.get("collectorEpoch") != native_epoch
            or [row.get("caseId") for row in attachment.get("causalCases", [])]
               != [case for case in CASES if case in observed]):
        raise ValueError("pr317-private-attachment-invalid")
    _safe_tree(value)
    return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                 allow_nan=False))


def _projection(status, reasons, source_digest, observed, terminal=False):
    return {"schemaVersion": 1, "kind": PUBLIC_KIND,
        "executionClass": EXECUTION_CLASS, "status": status,
        "reasons": list(reasons), "sourceIdentityDigest": source_digest,
        "topologyRoles": 4,
        "consumerCases": list(CASES),
        "installedDriverCases": [case for case in CASES if case != "cancellation"],
        "unsupportedInstalledCases": ["cancellation"],
        "observedCases": list(observed),
        "notObservedCases": [case for case in CASES if case not in observed],
        "remainingHardCases": list(HARD_CASES),
        "namespaceTransportImplemented": terminal,
        "terminalCleanupVerified": terminal,
        "ownerCancelledInstalledDirection": False,
        "historicalPr315AcceptanceTransferred": False,
        "historicalPr316AcceptanceTransferred": False,
        "finiteNativeAcceptance": False, "fullAppBudgets": "not-observed",
        "originalProtectedAuthority": False, "independentSecurityReview": False,
        "releaseEligible": False, "phaseComplete": False}


def public_projection(value, *, source_identity_digest, selection_digest,
                      cleanup_verified, guest_stopped, watcher_finished,
                      privacy_verified):
    value = validate_private_observation(value)
    if (_DIGEST.fullmatch(str(source_identity_digest)) is None
            or _DIGEST.fullmatch(str(selection_digest)) is None
            or value["selectionDigest"] != selection_digest):
        raise ValueError("pr317-public-binding-invalid")
    terminal = all((cleanup_verified is True, guest_stopped is True,
                    watcher_finished is True, privacy_verified is True))
    complete = terminal and not value["notObservedCases"]
    reasons = ([] if complete else ["selected-case-observation-incomplete"]
               if terminal else ["terminal-evidence-incomplete"])
    return _projection("observed" if complete else "incomplete", reasons,
        source_identity_digest, value["observedCases"], terminal)


def failed_projection(reason, *, source_identity_digest=None, selection_digest=None):
    if not isinstance(reason, str) or re.fullmatch(r"[a-z][a-z0-9-]{1,100}", reason) is None:
        reason = "private-evidence-invalid"
    for value in (source_identity_digest, selection_digest):
        if value is not None and _DIGEST.fullmatch(str(value)) is None:
            raise ValueError("pr317-failure-digest-invalid")
    return _projection("failed", [reason], source_identity_digest, [])

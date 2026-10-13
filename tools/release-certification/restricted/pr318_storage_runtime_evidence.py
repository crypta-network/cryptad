"""Small private/public boundary for the PR-318 installed test class."""
from __future__ import annotations

import json
import math

import pr317_budget_runtime_evidence as legacy
from cryptad_certification import composed_budget_storage_evidence as storage

EXECUTION_CLASS = "pr318-fixed-window-partial-store-v1"
PUBLIC_KIND = "pr318-storage-budget-assessment"
MAX_PRIVATE_BYTES = 4 * 1024 * 1024
APP_IDS = legacy.APP_IDS
CASES = ("window-crossing", "partial-rate-write", "graph-store-unavailable")
canonical_digest = legacy.canonical_digest
payload_exposed = legacy.payload_exposed


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("pr318-private-duplicate-key")
        result[key] = value
    return result


def _private_tree(value, depth=0):
    """Bound private graph/native content without publishing it or admitting secrets."""
    if depth > 32:
        raise ValueError("pr318-private-depth-invalid")
    if isinstance(value, dict):
        if set(value) & {"session", "browserSessionToken", "insertUri", "privateKey",
                         "formPassword", "commandLine", "statementBase64"}:
            raise ValueError("pr318-private-secret-field")
        for key, child in value.items():
            if not isinstance(key, str) or len(key) > 128:
                raise ValueError("pr318-private-key-invalid")
            _private_tree(child, depth + 1)
    elif isinstance(value, list):
        if len(value) > 8192:
            raise ValueError("pr318-private-list-invalid")
        for child in value:
            _private_tree(child, depth + 1)
    elif isinstance(value, str):
        if len(value) > 8192 or "CRYPTAD_APP_TOKEN" in value:
            raise ValueError("pr318-private-string-invalid")
    elif value is not None and (type(value) not in {bool, int, float}
                               or type(value) is float and not math.isfinite(value)):
        raise ValueError("pr318-private-value-invalid")


def decode_checkpoints(raw):
    """Decode bounded partial observations; these never themselves award case credit."""
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_PRIVATE_BYTES:
        raise ValueError("pr318-private-size-invalid")
    lines = raw.splitlines()
    if not 1 <= len(lines) <= 32:
        raise ValueError("pr318-private-checkpoint-count-invalid")
    rows = []
    for line in lines:
        row = json.loads(line, object_pairs_hook=_unique)
        if not isinstance(row, dict):
            raise ValueError("pr318-private-checkpoint-invalid")
        phase = row.get("phase")
        fields = {
            "before": {"caseId", "phase", "native", "graph",
                       "timePlan" if row.get("caseId") == "window-crossing" else "selectedFingerprint"},
            "restricted": {"caseId", "phase", "receipt"},
            "restored": {"caseId", "phase", "receipt"},
            "response": {"caseId", "phase", "native", "graph", "requestStatus"},
            "reserved": {"caseId", "phase", "native", "timePlan"},
            "attempt-completed": {"phase", "attempt", "row"},
            "interrupted": {"phase", "status"} | ({"native"} if "native" in row else set()),
        }.get(phase)
        if fields is None or set(row) != fields or "caseId" in row and row["caseId"] not in CASES:
            raise ValueError("pr318-private-checkpoint-invalid")
        if "native" in row and row["native"] is not None:
            native = row["native"]
            if (not isinstance(native, dict) or not isinstance(native.get("work"), dict)
                    or not isinstance(native.get("budget"), dict)):
                raise ValueError("pr318-private-native-checkpoint-invalid")
        if phase == "interrupted" and row["status"] != "unknown":
            raise ValueError("pr318-private-checkpoint-invalid")
        if "graph" in row and not isinstance(row["graph"], list):
            raise ValueError("pr318-private-graph-checkpoint-invalid")
        _private_tree(row)
        rows.append(row)
    return rows


def decode_private(raw):
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_PRIVATE_BYTES:
        raise ValueError("pr318-private-size-invalid")
    value = json.loads(raw, object_pairs_hook=_unique)
    attempts = value.get("attempts") if isinstance(value, dict) else None
    attachment = value.get("composedBudgetEvidence") if isinstance(value, dict) else None
    coverage = value.get("composedBudgetCoverage") if isinstance(value, dict) else None
    if (not isinstance(value, dict) or set(value) != {"schemaVersion", "kind",
            "selectionDigest", "contexts", "attempts", "composedBudgetEvidence",
            "composedBudgetCoverage"}
            or value["schemaVersion"] != 1 or value["kind"] != "pr318-private-storage-budget"
            or not isinstance(value["contexts"], dict) or set(value["contexts"]) != set(APP_IDS)
            or not isinstance(attempts, list) or any(not isinstance(row, dict) for row in attempts)
            or [row.get("caseId") for row in attempts] != list(CASES)
            or not isinstance(attachment, dict) or attachment.get("schemaVersion") != 4
            or attachment.get("causalCases") != []
            or not isinstance(coverage, dict)
            or coverage.get("fullAppBudgets") != "not-observed"):
        raise ValueError("pr318-private-shape-invalid")
    # Graph identities and source metadata deliberately remain in this private file.
    # The owning consumer validates every row before public projection is reachable.
    _private_tree(value)
    return value


def _projection(status, reasons, observed, identity=None, variants=None):
    variants = variants or storage.derive_variants({"storageCases": []})
    return {"schemaVersion": 1, "kind": PUBLIC_KIND, "executionClass": EXECUTION_CLASS,
            "status": status, "reasons": reasons, "observedCases": observed,
            "notObservedCases": [case for case in CASES if case not in observed],
            "sourceIdentityDigest": identity, "evidenceClass": "installed-real-time-filesystem",
            "topologyRoles": 4, "fullAppBudgets": "not-observed", "phaseComplete": False,
            "releaseEligible": False, "ownerCancelledInstalledDirection": False,
            "verifiedVariants": variants["verifiedVariants"],
            "unobservedVariants": variants["unobservedVariants"]}


def failed_projection(reason):
    return _projection("failed", [reason], [])


def public_projection(private, *, source_identity_digest, selection_digest,
                      cleanup_verified, guest_stopped, watcher_finished, privacy_verified):
    if (not all((cleanup_verified, guest_stopped, watcher_finished, privacy_verified))
            or private["selectionDigest"] != selection_digest):
        raise ValueError("pr318-terminal-evidence-incomplete")
    observed = [case for case in CASES
                if case in private["composedBudgetCoverage"]["observedCases"]]
    return _projection("observed" if observed == list(CASES) else "incomplete", [],
                       observed, source_identity_digest,
                       storage.derive_variants(private["composedBudgetEvidence"]))

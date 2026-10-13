"""Bind installed cross-epoch claims to separately retained administrator originals.

This verifier is a host evidence consumer, not an execution or approval authority.
Native consistency, original witness matching, terminal cleanup and public projection
remain separate checks. No private scope, graph, process or receipt identity is public.
"""
from __future__ import annotations

import json
import re
import base64
import urllib.parse

import pr317_budget_runtime_evidence as legacy
import pr318_storage_runtime_evidence as privacy
from cryptad_certification import composed_budget_restart_evidence as oracle

EXECUTION_CLASS = "pr319-composed-budget-restart-diagnostics-v1"
PUBLIC_KIND = "pr319-restart-budget-assessment"
APP_IDS = legacy.APP_IDS
CASES = oracle.CASES
MAX_PRIVATE_BYTES = 4 * 1024 * 1024
canonical_digest = legacy.canonical_digest
FIELDS = {"schemaVersion", "kind", "selectionDigest", "contexts", "attempts",
          "composedBudgetEvidence", "composedBudgetCoverage", "originalReceipts",
          "phaseReceipts", "epochContexts"}


def _need(condition, code):
    if not condition:
        raise ValueError("pr319-original-" + code)


def _unique(pairs):
    value = {}
    for key, child in pairs:
        _need(key not in value, "duplicate-key")
        value[key] = child
    return value


def decode_private(raw):
    _need(isinstance(raw, bytes) and 0 < len(raw) <= MAX_PRIVATE_BYTES, "size-invalid")
    value = json.loads(raw, object_pairs_hook=_unique,
        parse_constant=lambda _v: (_ for _ in ()).throw(ValueError("pr319-private-value-invalid")))
    _need(isinstance(value, dict) and set(value) == FIELDS
          and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
          and value["kind"] == "pr319-private-restart-budget", "shape-invalid")
    _need(isinstance(value["contexts"], dict) and set(value["contexts"]) == set(APP_IDS)
          and isinstance(value["composedBudgetEvidence"], dict)
          and value["composedBudgetEvidence"].get("schemaVersion") == 5
          and isinstance(value["composedBudgetCoverage"], dict)
          and value["composedBudgetCoverage"].get("fullAppBudgets") == "not-observed"
          and all(isinstance(value[k], list) and len(value[k]) <= 128 for k in
              ("attempts", "originalReceipts", "phaseReceipts", "epochContexts")), "shape-invalid")
    _need(re.fullmatch("sha256:[a-f0-9]{64}", str(value["selectionDigest"])) is not None,
          "selection-invalid")
    privacy._private_tree(value)
    return value


def decode_checkpoints(raw):
    _need(isinstance(raw, bytes) and 0 < len(raw) <= MAX_PRIVATE_BYTES, "checkpoint-size-invalid")
    lines = raw.splitlines()
    _need(0 < len(lines) <= 64, "checkpoint-count-invalid")
    result = []
    for line in lines:
        row = json.loads(line, object_pairs_hook=_unique)
        _need(isinstance(row, dict), "checkpoint-shape-invalid")
        if row.get("phase") == "interrupted":
            _need(set(row) == {"phase", "status"} and row["status"] == "unknown",
                  "checkpoint-interrupted-invalid")
        else:
            _need(set(row) in ({"caseId", "variant", "phase", "sample"},
                              {"caseId", "variant", "phase", "receipt"})
                  and row.get("caseId") in CASES
                  and row.get("variant") in oracle.REQUIRED_VARIANTS[row["caseId"]],
                  "checkpoint-shape-invalid")
            if "sample" in row:
                _need(row["phase"] in {"before", "during", "after", "recovery"},
                      "checkpoint-phase-invalid")
                oracle._phase(row["sample"])
            else:
                _need(row["phase"] == "terminal" and isinstance(row["receipt"], dict),
                      "checkpoint-terminal-invalid")
                receipt = row["receipt"]
                _receipt(receipt, receipt.get("selectionDigest"))
        privacy._private_tree(row)
        result.append(row)
    return result


def payload_exposed(raw):
    if legacy.payload_exposed(raw) or not isinstance(raw, bytes):
        return True
    marker = b"PR319_PRIVATE_"
    if marker in raw or marker in urllib.parse.unquote_to_bytes(raw):
        return True
    for token in re.findall(rb"[A-Za-z0-9+/]{16,}={0,2}", raw):
        try:
            if marker in base64.b64decode(token, validate=True):
                return True
        except ValueError:
            pass
    return False


def decode_original_diagnostics(raw):
    """Typed private allowance applies only to the original root capture's fixed subjects."""
    _need(isinstance(raw, bytes) and 0 < len(raw) <= 262144, "diagnostic-size-invalid")
    value = json.loads(raw, object_pairs_hook=_unique,
        parse_constant=lambda _v: (_ for _ in ()).throw(ValueError("pr319-private-value-invalid")))
    fields = {"restartFaultReceipts", "restartSelectionDigest", "restartAccessCleanup",
              "restartOriginalStops", "restartBootstrapContexts"}
    _need(isinstance(value, dict) and fields <= set(value)
          and value.get("classification") == "private-kernel-diagnostics-not-acceptance"
          and value["restartAccessCleanup"] in {"completed", "restoration-required"}
          and re.fullmatch("sha256:[a-f0-9]{64}", str(value["restartSelectionDigest"]))
          and isinstance(value["restartFaultReceipts"], list)
          and len(value["restartFaultReceipts"]) <= 128
          and isinstance(value["restartOriginalStops"], dict)
          and isinstance(value["restartBootstrapContexts"], dict), "diagnostic-shape-invalid")
    for receipt in value["restartFaultReceipts"]:
        _receipt(receipt, value["restartSelectionDigest"])
        _closed_receipt(receipt)
        case = receipt["caseId"]
        phases = {"restart": {"snapshot", "readback"}, "graceful": {"pin", "terminal"},
            "abrupt-settled": {"fault-intent", "terminal"},
            "abrupt-inflight": {"fault-intent", "terminal"},
            "diagnostics-enumeration": {"restricted", "restored"},
            "diagnostics-required-key": {"restricted", "restored"}}
        _need(case in phases and receipt["phase"] in phases[case], "diagnostic-purpose-invalid")
    _need(all(re.fullmatch("[a-f0-9]{64}", str(generation)) for field in
        ("restartOriginalStops", "restartBootstrapContexts") for generation in value[field]),
        "diagnostic-generation-invalid")
    privacy._private_tree(value)
    remainder = {k: v for k, v in value.items() if k not in fields}
    _need(not payload_exposed(json.dumps(remainder, sort_keys=True).encode()),
          "diagnostic-unapproved-payload")
    return value


def _receipt(value, selection):
    _need(isinstance(value, dict) and value.get("schemaVersion") == 1
          and value.get("kind") == "pr319-trusted-transition"
          and value.get("role") == "candidate-sender"
          and value.get("selectionDigest") == selection
          and re.fullmatch("[a-f0-9]{64}", str(value.get("generation")))
          and re.fullmatch("[a-f0-9]{32}", str(value.get("managerInvocation")))
          and isinstance(value.get("bootId"), str)
          and type(value.get("observedMonotonicNs")) is int
          and type(value.get("deadlineMonotonicNs")) is int
          and 0 < value["observedMonotonicNs"] < value["deadlineMonotonicNs"], "receipt-invalid")


def _closed_receipt(value):
    base = {"schemaVersion", "kind", "caseId", "phase", "role", "campaign", "generation",
            "managerInvocation", "bootId", "selectionDigest", "deadlineMonotonicNs", "observedMonotonicNs"}
    case, phase = value.get("caseId"), value.get("phase")
    extras = None
    if case == "restart" and phase in {"snapshot", "readback"}:
        extras = {"daemon", "dataIdentity", "durableUsage", "graphFacts", "captureSource", "capturedMonotonicNs"}
    elif case == "graceful" and phase == "pin":
        extras = {"daemon", "dataIdentity", "effectiveStopProfile"}
    elif case == "graceful" and phase == "terminal":
        extras = {"daemon", "dataIdentity", "kernelExit", "effectiveStopProfile", "terminalManager",
                  "pidfdDeathObserved", "gracefulExitObserved", "stopReceipt"}
    elif case in {"abrupt-settled", "abrupt-inflight"} and phase == "terminal":
        extras = {"daemon", "dataIdentity", "effectiveStopProfile", "forcedSignal", "pidfdDeathObserved",
                  "startedMonotonicNs", "stopReceipt"}
    elif case in {"abrupt-settled", "abrupt-inflight"} and phase == "fault-intent":
        extras = {"daemon", "dataIdentity", "intendedSignal", "startedMonotonicNs"}
    elif case in {"diagnostics-enumeration", "diagnostics-required-key"} and phase == "restricted":
        extras = {"dataIdentity", "targetClass", "before", "after", "roleUidEnumerationDenied",
                  "roleUidExactKeyReadable"}
    elif case in {"diagnostics-enumeration", "diagnostics-required-key"} and phase == "restored":
        extras = {"before", "after", "contentsRestored", "selectedPathUnchanged"}
    _need(extras is not None and set(value) == base | extras, "receipt-fields-invalid")


def _rates(phase, native, receipt):
    """Actual strict native enumeration must match the independently read file records."""
    diagnostic, budget = phase["diagnostics"], native["budget"]
    _need(all(diagnostic[k] == budget[k] for k in
          ("valid", "observedAt", "activeFamilyLeases", "reservedFamilyRates")),
          "diagnostic-source-substitution")
    if budget["valid"] is not True:
        _need(budget["valid"] is False and budget["rates"] == [] and diagnostic["usage"] == [],
              "invalid-interval-zero-credit")
        return
    usage = receipt["durableUsage"]
    _need(diagnostic["usage"] == usage and len(usage) == len(budget["rates"]),
          "durable-view-substitution")
    _need(usage == sorted(usage, key=lambda r: (r["appId"], r["operation"])),
          "file-order-invalid")
    scopes = {r["appId"]: r["scope"] for r in phase["scopeBindings"]}
    _need(set(scopes) == {r["appId"] for r in usage} | {"_cryptad_global", "_cryptad_operator"},
          "unbound-app-scope")
    expected = [{"operation": row["operation"], "scope": scopes[row["appId"]],
        "windowStartEpochSecond": int(oracle._time(row["windowStart"])),
        "count": row["count"]} for row in usage]
    _need(expected == budget["rates"], "scope-identity-substitution")


def _phase(raw, checkpoint, selection, data, collector_scopes):
    receipt, native = checkpoint["receipt"], checkpoint["native"]
    _receipt(receipt, selection)
    _need(receipt.get("caseId") == "restart" and receipt.get("phase") in {"snapshot", "readback"}
          and receipt.get("dataIdentity") == data, "phase-data-substitution")
    _need(raw["pid"] == receipt["daemon"]["hostPid"], "phase-daemon-substitution")
    _need(raw["nativeSnapshot"] == {k: native["work"][k] for k in
          ("version", "lastSequence", "dropped", "events", "collectorEpoch")}
          and raw["collectorEpoch"] == native["work"]["collectorEpoch"], "native-source-substitution")
    _rates(raw, native, receipt)
    _need(sorted(raw["graph"], key=lambda r: r["documentFingerprint"]) ==
          sorted(receipt["graphFacts"], key=lambda r: r["documentFingerprint"]),
          "graph-metadata-substitution")
    epoch = raw["collectorEpoch"]
    known = collector_scopes.setdefault(epoch, {})
    if raw["diagnostics"]["valid"] is False:
        _need(known and known == {r["appId"]: r["scope"] for r in raw["scopeBindings"]},
              "invalid-interval-scope-substitution")
    for row in raw["scopeBindings"]:
        app, scope = row["appId"], row["scope"]
        _need(app in APP_IDS or app in {"_cryptad_global", "_cryptad_operator"},
              "app-principal-unselected")
        _need(app not in known or known[app] == scope, "same-epoch-scope-substitution")
        known[app] = scope


def _context(contexts, receipt, actual, handle):
    _need(isinstance(actual, dict) and all(actual.get(k) == receipt.get(k) for k in
          ("generation", "managerInvocation", "bootId")) and actual.get("handle") == handle
          and actual.get("apps") == contexts and set(contexts) == set(APP_IDS),
          "bootstrap-original-substitution")
    expected_role = canonical_digest({"handle": handle, **{k: receipt[k] for k in
        ("generation", "managerInvocation", "bootId")}})
    daemon = receipt["daemon"]
    expected_daemon = canonical_digest({k: daemon[k] for k in ("hostPid", "startTicks", "pidNamespace")})
    for app, context in contexts.items():
        _need(context.get("appId") == app and context.get("role") == "candidate-sender"
              and context.get("roleEpochDigest") == expected_role
              and context.get("daemonEpochDigest") == expected_daemon, "context-epoch-substitution")


def _transition(raw, original, before, after, diagnostics):
    transition = raw["transition"]
    _need(original["daemon"]["hostPid"] == raw["before"]["pid"]
          and original["pidfdDeathObserved"] is True
          and original["generation"] == before["generation"]
          and original["managerInvocation"] == before["managerInvocation"]
          and original["generation"] != after["generation"]
          and original["managerInvocation"] != after["managerInvocation"]
          and after["daemon"]["startTicks"] > original["daemon"]["startTicks"]
          and original["bootId"] == before["bootId"] == after["bootId"]
          and original["dataIdentity"] == before["dataIdentity"] == after["dataIdentity"]
          and raw["dataIdentity"]["fileKey"] == canonical_digest(original["dataIdentity"]),
          "restart-identity-substitution")
    stop = original["stopReceipt"]
    _need(diagnostics["restartOriginalStops"].get(original["generation"]) == stop
          and stop.get("membership") == "only-stop-helper" and stop.get("descendantCgroups") == 0
          and all(stop.get(k) == original.get(k) for k in
              ("campaign", "generation", "managerInvocation", "bootId")), "stop-original-substitution")
    _need(transition["oldPid"] == original["daemon"]["hostPid"]
          and transition["newPid"] == after["daemon"]["hostPid"]
          and transition["aliveBefore"] is True and transition["deadBeforeRestart"] is True,
          "transition-substitution")
    graceful = raw["variant"] == "settled-graceful"
    required_profile = {"Type": "exec", "KillMode": "control-group", "KillSignal": "15",
        "FinalKillSignal": "9", "SendSIGKILL": "yes", "TimeoutStopUSec": "20s", "Restart": "no"}
    _need(all(original["effectiveStopProfile"].get(k) == v for k, v in required_profile.items()),
          "stop-profile-substitution")
    if graceful:
        kernel, manager = original["kernelExit"], original["terminalManager"]
        _need(original["gracefulExitObserved"] is True
              and kernel["source"] == "linux-ptrace-exit-event" and kernel["normalExit"] is True
              and kernel["exitCode"] == 0 and kernel["signal"] is None and kernel["waitStatus"] == 0
              and manager["Result"] == "success" and manager["ExecMainCode"] == "1"
              and manager["ExecMainStatus"] == "0" and transition["exitCode"] == 0
              and transition["kind"] == "graceful" and transition["forced"] is False,
              "graceful-kernel-exit-substitution")
    else:
        _need(original["forcedSignal"] == "SIGKILL" and transition["exitCode"] is None
              and transition["kind"] == "forced" and transition["forced"] is True,
              "forced-daemon-substitution")


def _forced_intent(actual, original, before, after):
    """The administrator must retain a bound intent before the forced daemon death."""
    intents = [r for r in actual if r["caseId"] == original["caseId"]
               and r["phase"] == "fault-intent"]
    _need(len(intents) == 1, "forced-intent-missing")
    intent = intents[0]
    bindings = ("campaign", "generation", "managerInvocation", "bootId", "selectionDigest",
                "deadlineMonotonicNs", "daemon", "dataIdentity", "startedMonotonicNs")
    # Separate kernel samples may differ in RSS and thread count for the same daemon.
    identity_fields = ("hostPid", "startTicks", "executableDigest", "pidNamespace", "namespacePids",
                       "networkNamespaceIdentity", "mountNamespaceIdentity", "userNamespaceIdentity")
    _need(all(intent[k] == original[k] for k in bindings)
          and all(intent[k] == before[k] for k in bindings if k not in {"daemon", "startedMonotonicNs"})
          and all(intent["daemon"][k] == before["daemon"][k] for k in identity_fields)
          and intent["intendedSignal"] == original["forcedSignal"] == "SIGKILL",
          "forced-intent-substitution")
    started = intent["startedMonotonicNs"]
    _need(type(started) is int and before["observedMonotonicNs"] < started
          <= intent["observedMonotonicNs"] < original["observedMonotonicNs"]
          < after["observedMonotonicNs"]
          and actual.index(before) < actual.index(intent) < actual.index(original) < actual.index(after),
          "forced-intent-order-invalid")


def validate_originals(private, diagnostics, terminal, selection_digest):
    """Match guest claims against independently captured root/admin history in strict order."""
    try:
        _need(private["selectionDigest"] == diagnostics["restartSelectionDigest"] == selection_digest
              and diagnostics["restartAccessCleanup"] == "completed", "authority-missing")
        actual = diagnostics["restartFaultReceipts"]
        _need(isinstance(actual, list) and len(actual) <= 128 and actual, "receipt-stream-missing")
        for receipt in actual:
            _receipt(receipt, selection_digest)
            _closed_receipt(receipt)
        supplied = private["originalReceipts"]
        _need(supplied == [r for r in actual if r.get("phase") != "fault-intent"],
              "receipt-stream-substitution")
        record = terminal["controllerRecords"]["candidate-sender"]["record"]
        _need(record["state"] == "quiescent", "terminal-owner-not-quiescent")
        _need(all(r["campaign"] == record["campaign"] and r["bootId"] == record["bootId"]
                  for r in actual), "campaign-substitution")
        handle = record["handle"]
        rows = private["composedBudgetEvidence"]["restartCases"] + private["composedBudgetEvidence"]["diagnosticsCases"]
        row_map = {(r["caseId"], r["variant"]): r for r in rows}
        _need(len(row_map) == len(rows), "variant-replayed")
        checkpoints, scopes = {}, {}
        data = actual[0].get("dataIdentity")
        _need(isinstance(data, dict), "retained-data-missing")
        for checkpoint in private["phaseReceipts"]:
            _need(set(checkpoint) == {"caseId", "variant", "phase", "receipt", "native"},
                  "phase-receipt-fields")
            key = checkpoint["caseId"], checkpoint["variant"]
            phase = checkpoint["phase"]
            identity = (*key, phase)
            _need(key in row_map and phase in row_map[key] and identity not in checkpoints
                  and checkpoint["receipt"] in supplied, "phase-receipt-substitution")
            checkpoints[identity] = checkpoint
            _phase(row_map[key][phase], checkpoint, selection_digest, data, scopes)
        epoch_contexts = {(r["caseId"], r["variant"]): r for r in private["epochContexts"]}
        _need(len(epoch_contexts) == len(private["epochContexts"]), "context-replayed")
        for key, row in row_map.items():
            names = ("before", "during", "after", "recovery") if key[0] == "diagnostics-unavailable" else (
                "before", "after", "recovery")
            _need(all((*key, name) in checkpoints for name in names), "phase-original-missing")
            phase_receipts = {n: checkpoints[(*key, n)]["receipt"] for n in names}
            if key[0] == "diagnostics-unavailable":
                case = "diagnostics-enumeration" if key[1] == "enumeration-only" else "diagnostics-required-key"
                restrictions = [r for r in actual if r["caseId"] == case and r["phase"] == "restricted"]
                restorations = [r for r in actual if r["caseId"] == case and r["phase"] == "restored"]
                _need(len(restrictions) == len(restorations) == 1, "diagnostic-fault-missing")
                restricted, restored = restrictions[0], restorations[0]
                _need(restricted["roleUidEnumerationDenied"] is True
                      and restricted["roleUidExactKeyReadable"] is (key[1] == "enumeration-only")
                      and restored["contentsRestored"] is False and restored["selectedPathUnchanged"] is True
                      and restricted["before"] == restored["after"]
                      and restricted["after"] == restored["before"]
                      and row["fault"] == {"kind": key[1], "targetAppId": "feed-reader",
                          "requiredKeyReadable": restricted["roleUidExactKeyReadable"],
                          "enumerationReadable": False, "restored": True, "contentsRestored": False},
                      "diagnostic-fault-substitution")
                _need(all(phase_receipts[n]["generation"] == restricted["generation"] for n in names)
                      and phase_receipts["before"]["observedMonotonicNs"] < restricted["observedMonotonicNs"]
                      < phase_receipts["during"]["observedMonotonicNs"] < restored["observedMonotonicNs"]
                      < phase_receipts["after"]["observedMonotonicNs"], "diagnostic-interval-substitution")
            else:
                case = {"settled-graceful": "graceful", "settled-abrupt": "abrupt-settled",
                        "inflight-abrupt": "abrupt-inflight"}[key[1]]
                matches = [r for r in actual if r["caseId"] == case and r["phase"] == "terminal"]
                _need(len(matches) == 1, "terminal-fault-missing")
                original = matches[0]
                if key[1] != "settled-graceful":
                    _forced_intent(actual, original, phase_receipts["before"], phase_receipts["after"])
                _transition(row, original, phase_receipts["before"], phase_receipts["after"], diagnostics)
                _need(phase_receipts["before"]["observedMonotonicNs"] < original["observedMonotonicNs"]
                      < phase_receipts["after"]["observedMonotonicNs"], "restart-time-substitution")
                contexts = epoch_contexts[key]
                for name in ("before", "after"):
                    receipt = phase_receipts[name]
                    actual_context = diagnostics["restartBootstrapContexts"][receipt["generation"]]
                    _context(contexts[name], receipt, actual_context, handle)
                _need(all(contexts["before"][app][field] != contexts["after"][app][field]
                      for app in APP_IDS for field in ("roleEpochDigest", "daemonEpochDigest", "workerEpochDigest")),
                      "stale-app-context")
        observed = oracle.derive_cases(private["composedBudgetEvidence"])
        _need(set(private["composedBudgetCoverage"]["observedCases"]) == observed,
              "coverage-substitution")
        _need(private["phaseReceipts"], "final-phase-missing")
        final_receipt = private["phaseReceipts"][-1]["receipt"]
        _need(all(final_receipt[k] == record.get(k) for k in
                  ("generation", "managerInvocation", "bootId", "campaign")), "final-owner-substitution")
        _context(private["contexts"], final_receipt,
                 diagnostics["restartBootstrapContexts"][final_receipt["generation"]], handle)
        return True
    except (KeyError, TypeError, AttributeError, IndexError) as error:
        raise ValueError("pr319-original-record-incomplete") from error


def _projection(status, reasons, observed, identity=None, variants=None, censored=None):
    variants = variants or {"verifiedVariants": [], "unobservedVariants": sorted(
        variant for values in oracle.REQUIRED_VARIANTS.values() for variant in values)}
    return {"schemaVersion": 1, "kind": PUBLIC_KIND, "executionClass": EXECUTION_CLASS,
        "status": status, "reasons": reasons, "observedCases": observed,
        "notObservedCases": [case for case in CASES if case not in observed],
        "sourceIdentityDigest": identity, "evidenceClass": oracle.INSTALLED,
        "topologyRoles": 4, "fullAppBudgets": "not-observed", "phaseComplete": False,
        "releaseEligible": False, "ownerCancelledInstalledDirection": False,
        "verifiedVariants": variants["verifiedVariants"],
        "unobservedVariants": variants["unobservedVariants"],
        "censoredVariants": censored or []}


def failed_projection(reason):
    _need(isinstance(reason, str) and re.fullmatch("[a-z][a-z0-9-]{1,100}", reason),
          "public-reason-invalid")
    return _projection("failed", [reason], [])


def public_projection(private, *, source_identity_digest, selection_digest,
                      cleanup_verified, guest_stopped, watcher_finished, privacy_verified):
    _need(all(v is True for v in (cleanup_verified, guest_stopped, watcher_finished, privacy_verified))
          and private["selectionDigest"] == selection_digest, "terminal-evidence-incomplete")
    _need(re.fullmatch("sha256:[a-f0-9]{64}", str(source_identity_digest)), "public-source-invalid")
    observed = oracle.derive_cases(private["composedBudgetEvidence"])
    _need(set(private["composedBudgetCoverage"]["observedCases"]) == observed, "coverage-substitution")
    censored = sorted(row['variant'] for row in private['composedBudgetEvidence']['restartCases']
                      if row['tailStatus'] == 'censored')
    return _projection("observed" if observed == set(CASES) and not censored else "incomplete", [],
        [case for case in CASES if case in observed], source_identity_digest,
        oracle.derive_variants(private["composedBudgetEvidence"]), censored)

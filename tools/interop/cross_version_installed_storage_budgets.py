"""Finite PR-318 installed observations using the PR-317 role-bound clients.

Every request uses a controller-transferred connection and normal AppHost authority.
Filesystem changes are fixed administrator-kit phases on its inherited private channel.
Unobserved boundaries and failed cleanup remain failed/incomplete observations.
"""
from __future__ import annotations

import json
import hashlib
import os
import re
import stat
from pathlib import Path
import time

import cross_version_installed_budgets as transport

runtime = transport.runtime
installed = transport.installed
pressure = transport.pressure
EXECUTION_CLASS = "pr318-fixed-window-partial-store-v1"
EXPERIMENT = "pr318-fixed-window-partial-store"
CASES = ("window-crossing", "partial-rate-write", "graph-store-unavailable")
PRIVATE_FILE = "pr318-storage-budget.private.json"
ATTEMPTS_FILE = "pr318-storage-attempts.private.jsonl"


def _checkpoint(root, value):
    """Retain original observations during the attempt, including interrupted paths."""
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
    descriptor = os.open(Path(root) / ATTEMPTS_FILE,
                         os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o077
                or info.st_size + len(raw) > 4 * 1024 * 1024):
            transport.fail("storage-attempt-retention-unsafe")
        with os.fdopen(os.dup(descriptor), "ab") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)


def _graph(handle):
    status, value = handle.request("GET", "/api/v1/trust-graph/statements", principal="app")
    if status != 200 or not isinstance(value.get("statements"), list):
        transport.fail("storage-graph-readback-unavailable")
    rows = value["statements"]
    # The unfiltered production route returns all summaries. Independently require
    # its owning store count; a partial response cannot masquerade as no mutation.
    status, summary = handle.request("GET", "/api/v1/trust-graph/status", principal="app")
    if status != 200 or summary.get("trustGraph", {}).get("statementCount") != len(rows):
        transport.fail("storage-graph-enumeration-incomplete")
    return rows


def _snapshot(handle):
    raw = transport._snapshot(handle)
    result = transport._evidence_snapshot(raw)
    result["retainedStatements"] = len(_graph(handle))
    if not result["budgetValid"]:
        result["rates"] = None
    return raw, result


def _request(adapter, handle, statement, uri=None, *, response=False):
    task = {"method": "POST", "path": "/api/v1/trust-graph/import-uri" if uri else
            "/api/v1/trust-graph/import", "parameters": {"uri": uri} if uri else
            {"document": statement.decode("utf-8")}}
    with transport._start_client(adapter, handle.context, task) as client:
        client.release()
        result = client.result()
        return result if response else result["status"]


def _fingerprint(response):
    value = response.get("value", {}).get("importResult", {}).get("documentFingerprint")
    if re.fullmatch("[0-9a-f]{64}", str(value)) is None:
        transport.fail("storage-selected-fingerprint-unavailable")
    return value


def _case(adapter, case, variant, before_raw, before, during, after, recovery,
          graph_before, graph_after, graph_recovery, request_status, recovery_status,
          final_raw, *, selected_fingerprint, admin_receipt=None, time_plan=None, uri=False):
    events = transport._events(final_raw, before["sequence"])
    kind = "COMPOSED_URI_IMPORT_START" if case == "window-crossing" or uri else "COMPOSED_DIRECT_IMPORT_START"
    parents = transport._composed_parents(events, kind)
    if not parents:
        transport.fail("storage-operation-unobserved")
    return {"caseId": case, "variant": variant,
        "evidenceClass": "installed-real-time-filesystem", "operationId": parents[0],
        "selectedFingerprint": selected_fingerprint,
        "roleGeneration": adapter.nodes[transport.ROLE]["generation"],
        "collectorEpoch": before_raw["work"]["collectorEpoch"],
        "nodeEpoch": adapter.journal.node_epochs[("", transport.ROLE)],
        "before": before, "during": during, "after": after, "recoveryAfter": recovery,
        "events": events, "adminReceipt": admin_receipt, "timePlan": time_plan,
        "requestStatus": request_status, "recoveryStatus": recovery_status,
        "graphBefore": graph_before, "graphAfter": graph_after, "graphRecovery": graph_recovery}


def _filesystem_case(adapter, handle, statement, case, administrator, checkpoint):
    # A legitimate priming operation establishes readable directories/records. Its
    # charge is outside this case's before snapshot, never written by the test kit.
    prime = _request(adapter, handle, statement, response=True)
    if prime["status"] != 200:
        transport.fail("storage-prime-failed")
    selected_fingerprint = _fingerprint(prime)
    graph_before = _graph(handle)
    before_raw, before = _snapshot(handle)
    checkpoint({"caseId": case, "phase": "before", "native": before_raw,
                "graph": graph_before, "selectedFingerprint": selected_fingerprint})
    restriction = None
    try:
        restriction = administrator(case + ":restrict")
        checkpoint({"caseId": case, "phase": "restricted", "receipt": restriction})
        _, during = _snapshot(handle)
        status = _request(adapter, handle, statement)
        after_raw, after = _snapshot(handle)
        graph_after = _graph(handle)
        checkpoint({"caseId": case, "phase": "response", "native": after_raw,
                    "graph": graph_after, "requestStatus": status})
    finally:
        # Parent also retains emergency restoration authority if observer disappears.
        restoration = administrator(case + ":restore")
        checkpoint({"caseId": case, "phase": "restored", "receipt": restoration})
    if restriction is None or status != 503:
        transport.fail("storage-denial-unobserved")
    # Normal complete diagnostics read persisted budget files after access restoration.
    restored_raw, restored = _snapshot(handle)
    if restored["budgetValid"] is not True or restored["rates"] != after["rates"]:
        transport.fail("storage-readback-incomplete")
    recovery_status = _request(adapter, handle, statement)
    final_raw, recovery = _snapshot(handle)
    graph_recovery = _graph(handle)
    return _case(adapter, case, "direct-readable-directory-denial", before_raw, before,
        during, after, recovery, graph_before, graph_after, graph_recovery,
        status, recovery_status, final_raw,
        selected_fingerprint=selected_fingerprint,
        admin_receipt={"restriction": restriction, "restoration": restoration})


def _boundary_case(adapter, handle, statement, selected, checkpoint=lambda value: None,
                   *, contender=None, recovery_handle=None, selected_fingerprint=None):
    boundary = selected["boundaryEpochSecond"]
    margin = selected["startMarginSeconds"]
    now = time.time()
    # Selection precedes launch. Never silently pick a later boundary or reset deadlines.
    if now >= boundary - margin or adapter.deadline - time.monotonic() < boundary - now + 45:
        return None, {"caseId": "window-crossing", "status": "not-observed",
                      "reason": "window-not-reached"}
    key = transport._new_content_key(adapter)
    while time.time() < boundary - margin:
        if time.monotonic() >= adapter.deadline - 45:
            return None, {"caseId": "window-crossing", "status": "not-observed",
                          "reason": "window-not-reached"}
        time.sleep(min(.25, max(0, boundary - margin - time.time())))
    graph_before = _graph(handle)
    before_raw, before = _snapshot(handle)
    checkpoint({"caseId": "window-crossing", "phase": "before",
                "native": before_raw, "graph": graph_before, "timePlan": selected})
    task = {"method": "POST", "path": "/api/v1/trust-graph/import-uri",
            "parameters": {"uri": key["uri"]}}
    with transport._start_client(adapter, handle.context, task) as client:
        client.release()
        during_raw = transport._wait_for(adapter, handle, before["sequence"],
            lambda snapshot, rows: any(row["kind"] == "RATE_RESERVED" and
                row.get("operation") == "trust_graph_import" and
                row.get("windowStartEpochSecond") == boundary - 3600 for row in rows)
                and any(row["kind"] == "FETCH_INVOKED" for row in rows)
                and not any(row["kind"] in {"FETCH_SUCCEEDED", "FETCH_FAILED"} for row in rows),
            maximum=min(5, max(.1, boundary - time.time())))
        if during_raw is None or time.time() >= boundary:
            # Release the same owned key within its original request deadline so a
            # failed timing observation does not strand the import's transient hold.
            transport._publish(adapter, key, statement)
            try:
                failed_status = client.result()["status"]
            except runtime.RuntimeFailure:
                failed_status = None
            failed_raw, failed_after = _snapshot(handle)
            return None, {"caseId": "window-crossing", "status": "not-observed",
                          "reason": "reservation-not-observed-before-boundary",
                          "requestStatus": failed_status,
                          "before": before, "after": failed_after,
                          "events": transport._events(failed_raw, before["sequence"])}
        observed = time.time()
        checkpoint({"caseId": "window-crossing", "phase": "reserved",
                    "native": during_raw, "timePlan": selected})
        during = transport._evidence_snapshot(during_raw)
        during["retainedStatements"] = len(_graph(handle))
        while time.time() < boundary:
            time.sleep(min(.05, boundary - time.time()))
        released = time.time()
        if contender is not None and _request(adapter, contender, statement) != 200:
            transport.fail("storage-contested-charge-unobserved")
        transport._publish(adapter, key, statement)
        status = client.result()["status"]
    after_raw, after = _snapshot(handle)
    graph_after = _graph(handle)
    recovery_response = _request(adapter, recovery_handle or handle, statement, response=True)
    recovery_status = recovery_response["status"]
    final_raw, recovery = _snapshot(handle)
    row = _case(adapter, "window-crossing", "contested-capacity" if contender else "available-capacity", before_raw, before,
        during, after, recovery, graph_before, graph_after, _graph(handle), status,
        recovery_status, final_raw, selected_fingerprint=selected_fingerprint or _fingerprint(recovery_response),
        time_plan={**selected,
            "observedReservationEpochSecond": observed, "releasedAtEpochSecond": released})
    return row, {"caseId": "window-crossing", "status": "executed"}


def _uri_filesystem_variant(adapter, handle, statement, case, variant, administrator, checkpoint):
    """Deny a real child write, post-fetch commit, or URI graph write without quota mutation."""
    prime = _request(adapter, handle, statement, response=True)
    if prime["status"] != 200:
        transport.fail("storage-prime-failed")
    fingerprint = _fingerprint(prime)
    key = transport._new_content_key(adapter)
    deferred = variant == "uri-import-commit-denial"
    if not deferred:
        transport._publish(adapter, key, statement)
    graph_before = _graph(handle)
    before_raw, before = _snapshot(handle)
    checkpoint({"caseId": case, "phase": "before", "native": before_raw,
                "graph": graph_before, "selectedFingerprint": fingerprint})
    restriction = None
    task = {"method": "POST", "path": "/api/v1/trust-graph/import-uri",
            "parameters": {"uri": key["uri"]}}
    with transport._start_client(adapter, handle.context, task) as client:
        try:
            if deferred:
                client.release()
                active = transport._wait_for(adapter, handle, before["sequence"],
                    lambda _snapshot, events: any(e["kind"] == "FETCH_INVOKED" for e in events)
                    and not any(e["kind"] in {"FETCH_SUCCEEDED", "FETCH_FAILED"} for e in events))
                if active is None:
                    transport.fail("storage-commit-fetch-premise-unobserved")
            restriction = administrator(case + ":restrict")
            checkpoint({"caseId": case, "phase": "restricted", "receipt": restriction})
            _, during = _snapshot(handle)
            if deferred:
                transport._publish(adapter, key, statement)
            else:
                client.release()
            status = client.result()["status"]
            after_raw, after = _snapshot(handle)
            graph_after = _graph(handle)
            checkpoint({"caseId": case, "phase": "response", "native": after_raw,
                        "graph": graph_after, "requestStatus": status})
        finally:
            if restriction is not None:
                restoration = administrator(case + ":restore")
                checkpoint({"caseId": case, "phase": "restored", "receipt": restoration})
    if status != 503:
        transport.fail("storage-denial-unobserved")
    _, restored = _snapshot(handle)
    if not restored["budgetValid"] or restored["rates"] != after["rates"]:
        transport.fail("storage-readback-incomplete")
    recovery_status = _request(adapter, handle, statement, key["uri"])
    final_raw, recovery = _snapshot(handle)
    return _case(adapter, case, variant, before_raw, before, during, after, recovery,
        graph_before, graph_after, _graph(handle), status, recovery_status, final_raw,
        selected_fingerprint=fingerprint,
        admin_receipt={"restriction": restriction, "restoration": restoration}, uri=True)


def run_complete_storage_variant(adapter, administrator, *, leave_running_for_administrator=False,
                                 on_start_failure=None):
    """Run one prospectively selected direction; compose separate originals in the owner campaign."""
    import pr320_storage_contract as contract
    from cryptad_certification.composed_budget_storage_evidence import derive_complete_storage
    if not contract.verify_selection_contract(adapter.plan, adapter.private, adapter.authorization):
        transport.fail("complete-storage-selection-invalid")
    selected = contract.selected_profile(adapter.authorization["executionClass"])
    checkpoint = lambda value: _checkpoint(adapter.root, value)
    completed = False
    try:
        for role in runtime.ROLES:
            adapter.start(role)
        adapter.connect()
        handles, statement = transport._bootstrap_apps(adapter)
        handle = handles[transport.APP_IDS[0]]
        if transport._snapshot(handle).get("budgetConfiguration") != selected["normalizedConfiguration"]["budgetConfiguration"]:
            transport.fail("complete-storage-effective-configuration-mismatch")
        case, variant = selected["caseId"], selected["variant"]
        if case == "window-crossing":
            kwargs = {}
            if variant == "contested-capacity":
                prime = _request(adapter, handles["budget-importer"], statement, response=True)
                if prime["status"] != 200:
                    transport.fail("storage-contested-prime-failed")
                kwargs = {"contender": handle, "recovery_handle": handles["budget-no-fetch"],
                          "selected_fingerprint": _fingerprint(prime)}
            row, attempt = _boundary_case(adapter, handle, statement,
                adapter.authorization["budgetSelection"]["timePlan"], checkpoint, **kwargs)
        elif variant.startswith("uri-"):
            row = _uri_filesystem_variant(adapter, handle, statement, case, variant, administrator, checkpoint)
            attempt = {"caseId": case, "status": "executed"}
        else:
            row = _filesystem_case(adapter, handle, statement, case, administrator, checkpoint)
            attempt = {"caseId": case, "status": "executed"}
        component = {"schemaVersion": 1, "kind": "composed-budget-storage-component",
                     "storageCases": [] if row is None else [row]}
        coverage = derive_complete_storage(component)
        private = {"schemaVersion": 1, "kind": "pr320-private-storage-budget",
            "selectionDigest": adapter.authorization["selectionDigest"],
            "executionClass": selected["executionClass"],
            "contexts": {app: transport._context_evidence(value.context) for app, value in handles.items()},
            "attempts": [attempt], "storageComponent": component, "storageCoverage": coverage}
        checkpoint({"phase": "attempt-completed", "attempt": attempt, "row": row})
        # Same safe exclusive writer, independent fixed filename and separate public projection.
        raw = json.dumps(private, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        if len(raw) > 4 * 1024 * 1024:
            transport.fail("complete-storage-private-size-limit")
        descriptor = os.open(Path(adapter.root) / "pr320-storage-budget.private.json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        from cryptad_certification.composed_budget_journal_member import append_member
        final_epoch = transport._snapshot(handle)['work']['collectorEpoch'] if row is None else row['collectorEpoch']
        append_member(adapter.journal, 'storage-component', json.dumps(
            component, sort_keys=True, separators=(',', ':'), allow_nan=False).encode(), collector_epoch=final_epoch)
        completed = True
        return {"schemaVersion": 1, "kind": "pr320-installed-storage-budget-observation",
            "executionClass": selected["executionClass"], "selectionDigest": private["selectionDigest"],
            "privateEvidenceDigest": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "evidenceClass": "installed-real-time-filesystem", "caseId": case, "variant": variant,
            "status": "executed" if row else "not-observed", "fullAppBudgets": "not-observed",
            "phaseComplete": False, "releaseEligible": False,
            "cleanupState": "administrator-required" if leave_running_for_administrator else "observer-owned"}
    except Exception:
        if getattr(adapter, "active_start_role", None) is not None and on_start_failure is not None:
            on_start_failure(adapter.active_start_role, getattr(adapter, "active_start_stage", "unavailable"))
        checkpoint({"phase": "interrupted", "status": "unknown"})
        raise
    finally:
        if (not completed or not leave_running_for_administrator) and adapter.cleanup() != "complete":
            transport.fail("complete-storage-cleanup-required")


def validate_complete_guest_observation(value, expected_selection_digest=None):
    import pr320_storage_contract as contract
    fields = {"schemaVersion", "kind", "executionClass", "selectionDigest",
        "privateEvidenceDigest", "evidenceClass", "caseId", "variant", "status",
        "fullAppBudgets", "phaseComplete", "releaseEligible", "cleanupState"}
    if not isinstance(value, dict) or set(value) != fields:
        transport.fail("complete-storage-observation-invalid")
    selected = contract.selected_profile(value["executionClass"])
    if (type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1
            or value["kind"] != "pr320-installed-storage-budget-observation"
            or (value["caseId"], value["variant"]) != (selected["caseId"], selected["variant"])
            or value["evidenceClass"] != "installed-real-time-filesystem"
            or value["status"] not in {"executed", "not-observed"}
            or value["fullAppBudgets"] != "not-observed"
            or value["releaseEligible"] is not False or value["phaseComplete"] is not False
            or value["cleanupState"] not in {"administrator-required", "observer-owned", "completed"}
            or any(re.fullmatch(r"sha256:[0-9a-f]{64}", str(value[name])) is None
                   for name in ("selectionDigest", "privateEvidenceDigest"))
            or expected_selection_digest is not None and value["selectionDigest"] != expected_selection_digest):
        transport.fail("complete-storage-observation-invalid")
    return value


def attach_complete_guest_context(value, identity, runtime_policy, campaign_deadline):
    validate_complete_guest_observation(value)
    return {**value, "identity": identity, "runtimePolicy": runtime_policy,
        "campaignDeadlineMonotonicNs": campaign_deadline,
        "workloadAcceptance": "incomplete-pr320-private-evidence-not-verified",
        "protectedExecutionEnabled": False}


def run_storage_lane(adapter, administrator, *, leave_running_for_administrator=False,
                     on_start_failure=None):
    from pr318_storage_contract import verify_selection_contract
    if not verify_selection_contract(adapter.plan, adapter.private, adapter.authorization):
        transport.fail("storage-selection-invalid")
    if not callable(administrator):
        transport.fail("storage-administrator-required")
    if on_start_failure is not None and not callable(on_start_failure):
        transport.fail("storage-start-diagnostic-invalid")
    completed = False
    handles = {}
    checkpoint = lambda value: _checkpoint(adapter.root, value)
    try:
        for role in runtime.ROLES:
            adapter.start(role)
        adapter.connect()
        handles, statement = transport._bootstrap_apps(adapter)
        handle = handles[transport.APP_IDS[0]]
        selected = adapter.authorization["budgetSelection"]
        # Effective operator configuration must equal the prospectively signed selection.
        initial = transport._snapshot(handle)
        actual = initial.get("budgetConfiguration")
        if actual != selected["normalizedConfiguration"]["budgetConfiguration"]:
            transport.fail("storage-effective-configuration-mismatch")
        rows, attempts = [], []
        boundary, attempt = _boundary_case(adapter, handle, statement, selected["timePlan"], checkpoint)
        attempts.append(attempt)
        checkpoint({"phase": "attempt-completed", "attempt": attempt, "row": boundary})
        if boundary is not None:
            rows.append(boundary)
        for case in CASES[1:]:
            rows.append(_filesystem_case(adapter, handle, statement, case, administrator, checkpoint))
            attempts.append({"caseId": case, "status": "executed"})
            checkpoint({"phase": "attempt-completed", "attempt": attempts[-1], "row": rows[-1]})
        final = transport._snapshot(handle)
        node = next(row for row in adapter.plan["nodes"] if row["role"] == transport.ROLE)
        attachment = {"schemaVersion": 4, "collectorEpoch": final["work"]["collectorEpoch"],
            "nodeEpoch": adapter.journal.node_epochs[("", transport.ROLE)],
            "workloadDigest": adapter.plan["workloadInputs"]["scheduler"],
            "productDigest": node["artifactDigest"], "sourceCommit": node["sourceCommit"],
            "appCohortDigest": transport.pressure.baseline.digest(node["appDigests"]),
            **adapter.plan["composedBudgetInputs"], "segments": [], "causalCases": [],
            "storageCases": rows}
        coverage = transport.composed.derive(attachment,
            workload_digest=attachment["workloadDigest"], product_digest=node["artifactDigest"],
            source_commit=node["sourceCommit"], app_cohort_digest=attachment["appCohortDigest"],
            node_epoch=attachment["nodeEpoch"], collector_digest=attachment["collectorDigest"],
            configuration_digest=attachment["configurationDigest"])
        private = {"schemaVersion": 1, "kind": "pr318-private-storage-budget",
            "selectionDigest": adapter.authorization["selectionDigest"],
            "contexts": {app: transport._context_evidence(value.context)
                         for app, value in handles.items()},
            "attempts": attempts, "composedBudgetEvidence": attachment,
            "composedBudgetCoverage": coverage}
        raw = json.dumps(private, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        if len(raw) > 4 * 1024 * 1024:
            transport.fail("storage-private-size-limit")
        descriptor = os.open(Path(adapter.root) / PRIVATE_FILE,
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(raw)
        result = {"schemaVersion": 1, "kind": "pr318-installed-storage-budget-observation",
            "executionClass": EXECUTION_CLASS, "selectionDigest": adapter.authorization["selectionDigest"],
            "privateEvidenceDigest": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "evidenceClass": "installed-real-time-filesystem",
            "observedCases": [case for case in CASES if case in coverage["observedCases"]],
            "fullAppBudgets": "not-observed", "phaseComplete": False, "releaseEligible": False,
            "cleanupState": "administrator-required" if leave_running_for_administrator else "observer-owned"}
        completed = True
        return result
    except Exception:
        if getattr(adapter, "active_start_role", None) is not None and on_start_failure is not None:
            try:
                on_start_failure(adapter.active_start_role,
                                 getattr(adapter, "active_start_stage", "unavailable"))
            except (OSError, ValueError, runtime.RuntimeFailure):
                pass
        # Original checkpoint rows already exist if this final diagnostic cannot be
        # collected. Unknown response/owner state is never replaced by a fixture value.
        failed = {"phase": "interrupted", "status": "unknown"}
        if handles:
            try:
                failed["native"] = transport._snapshot(handles[transport.APP_IDS[0]])
            except Exception:
                failed["native"] = None
        try:
            checkpoint(failed)
        except (OSError, ValueError, runtime.RuntimeFailure):
            pass
        raise
    finally:
        if (not completed or not leave_running_for_administrator) and adapter.cleanup() != "complete":
            transport.fail("storage-terminal-reconciliation-required")


def validate_guest_observation(value, expected_selection_digest=None):
    fields = {"schemaVersion", "kind", "executionClass", "selectionDigest", "evidenceClass",
              "observedCases", "privateEvidenceDigest", "fullAppBudgets", "phaseComplete", "releaseEligible", "cleanupState"}
    if (not isinstance(value, dict) or set(value) != fields
            or value["schemaVersion"] != 1 or value["executionClass"] != EXECUTION_CLASS
            or value["kind"] != "pr318-installed-storage-budget-observation"
            or value["evidenceClass"] != "installed-real-time-filesystem"
            or value["fullAppBudgets"] != "not-observed"
            or value["phaseComplete"] is not False or value["releaseEligible"] is not False
            or value["cleanupState"] not in {"administrator-required", "observer-owned", "completed"}
            or not isinstance(value["observedCases"], list)
            or value["observedCases"] != [case for case in CASES if case in value["observedCases"]]
            or expected_selection_digest is not None and
               value["selectionDigest"] != expected_selection_digest):
        transport.fail("storage-guest-observation-invalid")
    return value


def attach_guest_context(value, identity, runtime_policy, campaign_deadline):
    validate_guest_observation(value)
    return {**value, "identity": identity, "runtimePolicy": runtime_policy,
            "campaignDeadlineMonotonicNs": campaign_deadline,
            "workloadAcceptance": "incomplete-pr318-private-evidence-not-verified",
            "protectedExecutionEnabled": False}

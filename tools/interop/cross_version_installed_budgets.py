#!/usr/bin/env python3
"""Namespace-bound installed composed-budget workload for the PR-317 execution class.

The root controller owns role lifecycle and creates every network connection.  This module runs
inside the unprivileged observer and never opens a direct node connection, launches a local node,
signals a role process, or reads a role filesystem.  Concurrent requests use spawn-created trusted
observer clients: each client receives one immutable app context and one controller-transferred
HTTP socket, then applies one absolute deadline to request, headers, and complete response bytes.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import http.client
import json
import multiprocessing
import os
from pathlib import Path
import re
import socket
import time
import urllib.parse

import cross_version_runtime as runtime
import cross_version_workload as installed

with runtime.fixed_helper_imports():
    from cryptad_certification import composed_budget_evidence as composed
    from cryptad_certification import runtime_pressure_evidence as pressure


EXECUTION_CLASS = "pr317-namespace-bound-composed-budget-v1"
EXPERIMENT = "pr317-namespace-bound-composed-budget"
PRIVATE_KIND = "pr317-private-composed-budget-lifecycle"
PRIVATE_FILE = "pr317-composed-budget-lifecycle.private.json"
APP_IDS = ("feed-reader", "budget-importer", "budget-no-trust", "budget-no-fetch")
CASES = ("import-concurrency", "fetch-concurrency", "timeout", "cancellation", "retry")
ROLE = "candidate-sender"
CONTEXT_FIELDS = frozenset(("appId", "role", "handle", "generation", "managerInvocation",
    "bootId", "daemonEpoch", "worker", "origin", "session", "sessionExpiresAt"))
ROLE_EPOCH = ("handle", "generation", "managerInvocation", "bootId")
MAX_BODY = 2 * 1024 * 1024
MAX_CHILD_RESULT = 64 * 1024


def fail(code):
    raise runtime.RuntimeFailure("installed-budget-" + code)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("response-duplicate-field")
        result[key] = value
    return result


def _context(value, app_id=None, expected_role=ROLE):
    """Validate the controller-derived immutable app and role context."""
    origin = urllib.parse.urlsplit(value.get("origin", "")) if isinstance(value, dict) else None
    if (not isinstance(value, dict) or set(value) != CONTEXT_FIELDS
            or expected_role not in runtime.ROLES or value.get("role") != expected_role
            or value.get("appId") not in APP_IDS
            or app_id is not None and value.get("appId") != app_id
            or re.fullmatch("[a-f0-9]{64}", str(value.get("handle"))) is None
            or re.fullmatch("[a-f0-9]{64}", str(value.get("generation"))) is None
            or re.fullmatch("[a-f0-9]{32}", str(value.get("managerInvocation"))) is None
            or re.fullmatch("[a-f0-9-]{36}", str(value.get("bootId"))) is None
            or not isinstance(value.get("daemonEpoch"), dict)
            or not isinstance(value.get("worker"), dict)
            or not isinstance(value.get("origin"), str)
            or origin.scheme != "http" or origin.hostname != "127.0.0.1"
            or origin.username is not None or origin.password is not None
            or origin.port is None or not 1024 <= origin.port <= 65535
            or origin.port == 19402 or origin.path not in {"", "/"}
            or origin.query or origin.fragment
            or not isinstance(value.get("session"), str)
            or not 1 <= len(value["session"]) <= 4096
            or value.get("sessionExpiresAt") is None):
        fail("app-context-invalid")
    return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":")))


def _context_evidence(value):
    """Retain correlation digests without session, origin, PID, or process-token material."""
    value = _context(value)
    digest = lambda selected: runtime.canonical_digest(selected)
    return {"appId": value["appId"], "role": value["role"],
            "roleEpochDigest": digest({key: value[key] for key in ROLE_EPOCH}),
            "daemonEpochDigest": digest(value["daemonEpoch"]),
            "workerEpochDigest": digest(value["worker"]),
            "originDigest": digest(value["origin"]),
            "sessionDigest": digest(value["session"]),
            "sessionExpiryDigest": digest(value["sessionExpiresAt"])}


def _remaining(deadline, maximum=30):
    value = min(maximum, deadline - time.monotonic())
    if value <= 0:
        fail("absolute-deadline")
    return value


def _policy_seconds(adapter, name):
    policy = adapter.authorization.get("budgetSelection", {}).get("failurePolicy", {})
    value = policy.get(name)
    if type(value) is not int or not 1000 <= value <= 60000:
        fail("failure-policy-invalid")
    return value / 1000


def _request_deadline(adapter):
    return min(adapter.deadline,
               time.monotonic() + _policy_seconds(adapter, "requestDeadlineMillis"))


def _start_client(adapter, context, task, *, expected_role=ROLE):
    return FixedClientProcess.start(context, task, _request_deadline(adapter),
        cleanup_seconds=_policy_seconds(adapter, "clientCleanupMillis"),
        expected_role=expected_role)


def _observe(control, context, deadline):
    value = control.request("observe", context["handle"], timeout=_remaining(deadline))
    if (not isinstance(value, dict) or value.get("state") != "running"
            or any(value.get(key) != context[key] for key in ROLE_EPOCH)):
        fail("role-context-changed")
    return value


def _connected_http(control, context, deadline):
    """Acquire one role-bound socket and fence it by observations on both sides."""
    _observe(control, context, deadline)
    response, connected = control.request(
        "connect-http", context["handle"], timeout=_remaining(deadline))
    try:
        if response != {"status": "connected"} or connected.getpeername() != ("127.0.0.1", 19402):
            fail("http-peer-invalid")
        _observe(control, context, deadline)
        connected.settimeout(_remaining(deadline))
        return connected
    except BaseException:
        connected.close()
        raise


class _FixedHttp(http.client.HTTPConnection):
    def connect(self):
        fail("implicit-reconnect-forbidden")


def _request_over_socket(connected, context, task, deadline, *, abandon=False):
    """Send one fixed app request without DNS, proxy, redirect, or per-read deadline reset."""
    method = task.get("method")
    path = task.get("path")
    parameters = task.get("parameters", {})
    if (method not in {"GET", "POST"} or not isinstance(path, str)
            or not path.startswith("/api/v1/") or "?" in path or ".." in path
            or not isinstance(parameters, dict)
            or any(not isinstance(key, str) or not isinstance(value, str)
                   for key, value in parameters.items())):
        fail("request-shape-invalid")
    allowed = {
        ("GET", "/api/v1/trust-graph/statements"),
        ("POST", "/api/v1/trust-graph/import"),
        ("POST", "/api/v1/trust-graph/import-uri"),
        ("POST", "/api/v1/content/fetch"),
    }
    if (method, path) not in allowed:
        fail("request-route-not-approved")
    origin = task.get("origin", context["origin"])
    session = task.get("session", context["session"])
    if not isinstance(origin, str) or not isinstance(session, str) or len(session) > 4096:
        fail("request-principal-invalid")
    encoded = urllib.parse.urlencode(parameters).encode() if method == "POST" else None
    if encoded is not None and len(encoded) > 1024 * 1024:
        fail("request-body-limit")
    headers = {"Accept": "application/json", "Origin": origin,
               "X-Crypta-App-Session": session}
    if encoded is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Content-Length"] = str(len(encoded))
    connection = _FixedHttp("127.0.0.1", 19402, timeout=_remaining(deadline, 50))
    connection.sock = connected
    try:
        connected.settimeout(_remaining(deadline, 50))
        connection.request(method, path, body=encoded, headers=headers)
        if abandon:
            return {"status": "abandoned-after-request-write", "bodyDigest": None,
                    "bodyBytes": 0}
        connected.settimeout(_remaining(deadline, 50))
        response = connection.getresponse()
        body = bytearray()
        while True:
            connected.settimeout(_remaining(deadline, 50))
            block = response.read1(min(65536, MAX_BODY + 1 - len(body)))
            if not block:
                break
            body.extend(block)
            if len(body) > MAX_BODY:
                fail("response-body-limit")
        declared = response.headers.get("Content-Length")
        if declared is not None and (not declared.isdecimal() or int(declared) != len(body)):
            fail("response-framing-invalid")
        value = {} if response.status == 204 and not body else json.loads(
            bytes(body), object_pairs_hook=_unique)
        if not isinstance(value, dict):
            fail("response-shape-invalid")
        return {"status": response.status,
                "bodyDigest": "sha256:" + hashlib.sha256(body).hexdigest(),
                "bodyBytes": len(body), "value": value}
    except (OSError, ValueError, http.client.HTTPException) as error:
        raise runtime.RuntimeFailure("installed-budget-http-failed") from error
    finally:
        connection.close()


def _child(channel, context, task, deadline, expected_role):
    """Trusted spawned observer client; the management socket never reaches an app process."""
    connected = None
    try:
        context = _context(context, expected_role=expected_role)
        control = installed.WorkloadClient()
        connected = _connected_http(control, context, deadline)
        channel.send({"state": "ready"})
        command = channel.recv()
        if command not in {"request", "abandon"}:
            fail("child-command-invalid")
        result = _request_over_socket(
            connected, context, task, deadline, abandon=command == "abandon")
        connected = None  # _request_over_socket owns/closed the connection.
        channel.send({"state": "complete", "result": result})
    except BaseException as error:
        code = str(error)
        if re.fullmatch("[a-z][a-z0-9-]{1,120}", code) is None:
            code = "child-request-failed"
        try:
            channel.send({"state": "failed", "reason": code})
        except (BrokenPipeError, EOFError, OSError):
            pass
    finally:
        if connected is not None:
            connected.close()
        channel.close()


@dataclass
class FixedClientProcess:
    """One spawn-owned role socket and immutable app session with explicit barrier release."""

    process: multiprocessing.Process
    channel: object
    deadline: float
    cleanup_seconds: float

    @classmethod
    def start(cls, context, task, deadline, *, cleanup_seconds=5,
              expected_role=ROLE):
        if not isinstance(cleanup_seconds, (int, float)) or not 0 < cleanup_seconds <= 10:
            fail("client-cleanup-policy-invalid")
        selected = multiprocessing.get_context("spawn")
        parent, child = selected.Pipe(duplex=True)
        process = selected.Process(target=_child,
                                   args=(child, context, task, deadline, expected_role),
                                   daemon=False)
        process.start()
        child.close()
        instance = cls(process, parent, deadline, cleanup_seconds)
        try:
            message = instance._receive()
        except BaseException:
            instance.close()
            raise
        if message != {"state": "ready"}:
            instance.close()
            fail("client-not-ready")
        return instance

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _receive(self):
        remaining = _remaining(self.deadline, 60)
        if not self.channel.poll(remaining):
            fail("client-result-timeout")
        value = self.channel.recv()
        if (not isinstance(value, dict) or value.get("state") not in
                {"ready", "complete", "failed"}):
            fail("client-result-invalid")
        return value

    def release(self, *, abandon=False):
        if not self.process.is_alive():
            fail("client-not-live-at-release")
        self.channel.send("abandon" if abandon else "request")

    def result(self):
        value = self._receive()
        self.process.join(_remaining(self.deadline, 60))
        if self.process.is_alive():
            fail("client-not-reaped")
        if self.process.exitcode != 0 or value.get("state") != "complete":
            reason = value.get("reason") if isinstance(value, dict) else None
            if not isinstance(reason, str) or re.fullmatch("[a-z][a-z0-9-]{1,120}", reason) is None:
                reason = "client-request-failed"
            fail(reason)
        return value["result"]

    def close(self):
        try:
            self.channel.close()
        finally:
            if self.process.is_alive():
                self.process.kill()
            self.process.join(self.cleanup_seconds)
            if self.process.is_alive():
                fail("client-cleanup-unreaped")


class BudgetAppHandle(runtime.AppHandle):
    """Normal AppHost management plus a controller-authenticated budget app session."""

    def __init__(self, supervisor, app_id, role=ROLE):
        if app_id not in APP_IDS:
            fail("app-id-not-approved")
        if role not in runtime.ROLES:
            fail("app-role-not-approved")
        super().__init__(supervisor, role, app_id)
        self.base, self.api = "http://127.0.0.1:19402", "http://127.0.0.1:19402/api/v1"
        self.opener = installed._RoleHttp(supervisor, role)
        self.context = None

    def bind(self, context):
        context = _context(context, self.app_id)
        expected = self.supervisor.nodes.get(ROLE)
        if not isinstance(expected, dict) or any(context[key] != expected[key] for key in ROLE_EPOCH):
            fail("bootstrap-role-epoch-mismatch")
        self.origin, self.session = context["origin"], context["session"]
        self.session_expires_at = context["sessionExpiresAt"]
        self.context = context
        return self


def _bootstrap_apps(adapter):
    """Install the exact selected roster, then ask the controller to bind all sessions."""
    adapter.app_budget_lane = True
    host = BudgetAppHandle(adapter, APP_IDS[0])
    host.host_bootstrap()
    status, contract = host.request("GET", "/api/v1/platform/contract")
    selected = next(row for row in adapter.plan["nodes"] if row["role"] == ROLE)
    if status != 200 or contract.get("contract", {}).get("contractVersion") != selected["contractVersion"]:
        fail("product-api-binding-mismatch")
    status, inventory = host.request("GET", "/api/v1/apps")
    if status != 200 or inventory.get("apps") != []:
        fail("initial-app-inventory-not-empty")
    handles = {}
    for app_id in APP_IDS:
        handle = BudgetAppHandle(adapter, app_id)
        handle.password = host.password
        status, value = handle.request("POST", "/api/v1/apps/install",
            {"stagedDir": "/inputs/apps/" + app_id})
        if status != 201 or value.get("app", {}).get("appId") != app_id:
            fail("signed-app-install-failed")
        status, _ = handle.request("POST", "/api/v1/apps/" + app_id + "/start")
        if status not in {200, 201}:
            fail("signed-app-start-failed")
        handles[app_id] = handle
    adapter.next_operation()
    response = adapter.control.request("bootstrap-budget", adapter.handles[ROLE])
    if not isinstance(response, dict) or set(response) != {"apps", "corpus"} \
            or not isinstance(response["apps"], dict) or set(response["apps"]) != set(APP_IDS):
        fail("bootstrap-response-invalid")
    for app_id in APP_IDS:
        handles[app_id].bind(response["apps"][app_id])
        adapter.apps[(ROLE, app_id)] = handles[app_id]
    corpus = response["corpus"]
    if (not isinstance(corpus, dict)
            or set(corpus) != {"statementBase64", "statementDigest"}
            or not isinstance(corpus["statementBase64"], str)
            or re.fullmatch("sha256:[a-f0-9]{64}", str(corpus["statementDigest"])) is None):
        fail("bootstrap-corpus-invalid")
    import base64
    try:
        statement = base64.b64decode(corpus["statementBase64"], validate=True)
    except ValueError:
        fail("bootstrap-corpus-invalid")
    if (not 1 <= len(statement) <= 65536
            or "sha256:" + hashlib.sha256(statement).hexdigest() != corpus["statementDigest"]):
        fail("bootstrap-corpus-invalid")
    return handles, statement


def _snapshot(handle):
    status, value = handle.request("GET", "/api/v1/operator/runtime-observation")
    if status != 200 or not isinstance(value.get("budget"), dict) \
            or not isinstance(value.get("work"), dict):
        fail("native-observation-unavailable")
    return value


def _unchanged_native(before, after):
    return (before["work"].get("collectorEpoch") == after["work"].get("collectorEpoch")
            and before["work"].get("lastSequence") == after["work"].get("lastSequence")
            and before["work"].get("dropped") == after["work"].get("dropped")
            and before["budget"].get("valid") is True
            and after["budget"].get("valid") is True
            and before["budget"].get("rates") == after["budget"].get("rates")
            and before["budget"].get("activeFamilyLeases") ==
                after["budget"].get("activeFamilyLeases")
            and before["budget"].get("reservedFamilyRates") ==
                after["budget"].get("reservedFamilyRates"))


def _new_content_key(adapter):
    """Create an owned unpublished SSK/USK pair through the role-bound FCP port."""
    with adapter.client(ROLE) as client:
        insert, request = runtime.interop.generate_ssk(client, adapter.next_operation())
    return {
        "uri": runtime.interop.usk_from_ssk(request, "pr317-budget", 0),
        "insertUri": runtime.interop.usk_from_ssk(insert, "pr317-budget", 0),
    }


def _publish(adapter, selected, payload):
    """Fulfill one preselected owned key without exposing its insert capability."""
    with adapter.client(ROLE) as client:
        runtime.interop.put_and_wait_for_success(
            client, adapter.next_operation(), selected["insertUri"], payload,
            "application/json", local_request_only=True, uri_fallback=selected["uri"])


def _events(snapshot, after_sequence):
    work = snapshot["work"]
    rows = [row for row in work.get("events", [])
            if type(row.get("sequence")) is int and row["sequence"] > after_sequence]
    rows.sort(key=lambda row: row["sequence"])
    return rows


def _wait_for(adapter, handle, after_sequence, predicate, maximum=8):
    """Poll complete native snapshots without treating absence as a successful zero."""
    deadline = min(adapter.deadline, time.monotonic() + maximum)
    last = None
    while time.monotonic() < deadline:
        last = _snapshot(handle)
        rows = _events(last, after_sequence)
        if (last["budget"].get("valid") is True
                and last["work"].get("known") is True
                and not last["work"].get("dropped") and predicate(last, rows)):
            return last
        time.sleep(min(.05, max(0, deadline - time.monotonic())))
    return None


def _active_holds(snapshot):
    """Reconstruct per-operation holds from the complete bounded event prefix."""
    values = {}
    for event in snapshot["work"].get("events", []):
        kind = event.get("kind")
        if kind not in {"CONCURRENCY_HELD", "CONCURRENCY_RELEASED",
                        "RATE_RESERVED", "RATE_RESERVATION_RELEASED"}:
            continue
        family = ("concurrency" if kind.startswith("CONCURRENCY") else "rate")
        key = (event.get("operationId"), event.get("operation"), event.get("scope"), family)
        values[key] = values.get(key, 0) + (1 if kind in {
            "CONCURRENCY_HELD", "RATE_RESERVED"} else -1)
        if values[key] < 0:
            fail("native-hold-underflow")
    return [{"operationId": key[0], "operation": key[1], "scope": key[2],
             "kind": key[3], "count": count}
            for key, count in sorted(values.items()) if count]


def _evidence_snapshot(snapshot):
    work, budget = snapshot["work"], snapshot["budget"]
    return {"sequence": work["lastSequence"], "budgetValid": budget["valid"],
            "droppedEvents": work["dropped"], "rates": budget["rates"],
            "holds": _active_holds(snapshot),
            "retainedStatements": snapshot.get("retainedStatements")}


def _graph_count(handle):
    status, value = handle.request("GET", "/api/v1/trust-graph/statements", principal="app")
    rows = value.get("statements") if isinstance(value, dict) else None
    if status != 200 or not isinstance(rows, list):
        fail("graph-state-unavailable")
    return len(rows)


def _with_graph(handle, snapshot):
    value = json.loads(json.dumps(snapshot, sort_keys=True, separators=(",", ":")))
    value["retainedStatements"] = _graph_count(handle)
    return value


def _operation_rows(events, roles):
    parents = {}
    for event in events:
        if event["kind"] == "COMPOSED_CHILD":
            parents[event["operationId"]] = event["value"]
    ids = sorted({event["operationId"] for event in events if event["operationId"] > 0})
    return [{"operationId": operation_id,
             "parentOperationId": parents.get(operation_id),
             "role": roles.get(operation_id, "support"),
             "scope": next(event["scope"] for event in events
                           if event["operationId"] == operation_id)}
            for operation_id in ids]


def _rate_attribution(events):
    return [{"operationId": event["operationId"], "operation": event["operation"],
             "scope": event["scope"],
             "windowStartEpochSecond": event["windowStartEpochSecond"], "delta": 1}
            for event in events if event["kind"] == "RATE_CHARGED"]


def _causal_case(case, before, during, after, *, operation_id, roles,
                 request_outcome, owner_outcome, retry_of=None,
                 unresolved=False, censored=False):
    events = _events(after, before["work"]["lastSequence"])
    if not events or events[0]["sequence"] != before["work"]["lastSequence"] + 1 \
            or events[-1]["sequence"] != after["work"]["lastSequence"]:
        fail("causal-sequence-incomplete")
    if any(second["sequence"] != first["sequence"] + 1
           for first, second in zip(events, events[1:])):
        fail("causal-sequence-gap")
    epoch = after["work"]["collectorEpoch"]
    if any(snapshot["work"]["collectorEpoch"] != epoch
           for snapshot in (before, during, after)):
        fail("causal-collector-epoch-changed")
    scope = next(event["scope"] for event in events
                 if event["operationId"] == operation_id)
    return {"caseId": case, "collectorEpoch": epoch, "nodeEpoch": None,
            "scope": scope, "operationId": operation_id,
            "sequenceStart": events[0]["sequence"],
            "sequenceEnd": events[-1]["sequence"],
            "budgetValid": all(snapshot["budget"]["valid"] for snapshot in
                               (before, during, after)),
            "droppedEvents": max(snapshot["work"]["dropped"] for snapshot in
                                 (before, during, after)),
            "requestOutcome": request_outcome, "ownerOutcome": owner_outcome,
            "unresolved": unresolved, "censored": censored,
            "retryOfOperationId": retry_of,
            "operations": _operation_rows(events, roles), "events": events,
            "snapshots": {"before": _evidence_snapshot(before),
                          "during": _evidence_snapshot(during),
                          "after": _evidence_snapshot(after)},
            "rateAttribution": _rate_attribution(events)}


def _composed_parents(events, start_kind):
    return [event["operationId"] for event in events if event["kind"] == start_kind]


def _roles_for_parent(events, parent, prefix):
    roles = {parent: prefix + "-parent"}
    linked = [event["operationId"] for event in events
              if event["kind"] == "COMPOSED_CHILD" and event["value"] == parent]
    for operation_id in linked:
        group = [event for event in events if event["operationId"] == operation_id]
        if any(event["operation"] == "trust_graph_import" for event in group):
            roles[operation_id] = prefix + "-import"
        elif any(event["operation"] in {
                "foreground_content_fetch", "content_fetch_global"} for event in group):
            roles[operation_id] = prefix + "-fetch"
        else:
            fail("causal-child-family-unknown")
    return roles


def _expect_status(result, allowed, code):
    if result.get("status") not in allowed:
        fail(code)


def _run_concurrency_case(adapter, handles, statement, case):
    """Drive real import/fetch overlap with an unpublished owned key and finite fulfillment."""
    if case not in {"import-concurrency", "fetch-concurrency"}:
        fail("concurrency-case-invalid")
    holder_app = APP_IDS[0]
    contender_app = APP_IDS[0] if case == "import-concurrency" else APP_IDS[1]
    holder_key = _new_content_key(adapter)
    before = _with_graph(handles[holder_app], _snapshot(handles[holder_app]))
    with _start_client(adapter, handles[holder_app].context, {
            "method": "POST", "path": "/api/v1/trust-graph/import-uri",
            "parameters": {"uri": holder_key["uri"]}}) as holder:
        holder.release()
        during = _wait_for(adapter, handles[holder_app], before["work"]["lastSequence"],
            lambda snapshot, rows: (
                snapshot["budget"].get("activeFamilyLeases", 0) >= 4
                and any(row["kind"] == "FETCH_INVOKED" for row in rows)
                and not any(row["kind"] in {"FETCH_SUCCEEDED", "FETCH_FAILED"}
                            for row in rows)), maximum=10)
        if during is None:
            fail("holder-not-observed")
        during = _with_graph(handles[holder_app], during)
        contender_task = ({"method": "POST", "path": "/api/v1/trust-graph/import",
                           "parameters": {"document": statement.decode("utf-8")}}
                          if case == "import-concurrency" else
                          {"method": "POST", "path": "/api/v1/trust-graph/import-uri",
                           "parameters": {"uri": holder_key["uri"]}})
        with _start_client(
                adapter, handles[contender_app].context, contender_task) as contender:
            contender.release()
            contender_result = contender.result()
        _expect_status(contender_result, {429}, "contender-not-denied")
        _publish(adapter, holder_key, statement)
        holder_result = holder.result()
        _expect_status(holder_result, {200}, "holder-not-completed")
    recovery_task = ({"method": "POST", "path": "/api/v1/trust-graph/import",
                      "parameters": {"document": statement.decode("utf-8")}}
                     if case == "import-concurrency" else
                     {"method": "POST", "path": "/api/v1/trust-graph/import-uri",
                      "parameters": {"uri": holder_key["uri"]}})
    with _start_client(
            adapter, handles[contender_app].context, recovery_task) as recovery:
        recovery.release()
        recovery_result = recovery.result()
    _expect_status(recovery_result, {200}, "post-release-recovery-failed")
    after = _with_graph(handles[holder_app], _snapshot(handles[holder_app]))
    events = _events(after, before["work"]["lastSequence"])
    holder_parents = _composed_parents(events, "COMPOSED_URI_IMPORT_START")
    contender_kind = ("COMPOSED_DIRECT_IMPORT_START" if case == "import-concurrency"
                      else "COMPOSED_URI_IMPORT_START")
    contender_parents = _composed_parents(events, contender_kind)
    if case == "fetch-concurrency":
        if len(holder_parents) < 3:
            fail("concurrency-parent-count-invalid")
        holder_parent, contender_parent, recovery_parent = holder_parents[:3]
    else:
        recovery_parents = _composed_parents(events, "COMPOSED_DIRECT_IMPORT_START")
        if len(holder_parents) != 1 or len(contender_parents) < 2:
            fail("concurrency-parent-count-invalid")
        holder_parent, contender_parent, recovery_parent = (
            holder_parents[0], contender_parents[0], contender_parents[1])
    roles = {}
    roles.update(_roles_for_parent(events, holder_parent, "holder"))
    roles.update(_roles_for_parent(events, contender_parent, "contender"))
    roles.update(_roles_for_parent(events, recovery_parent, "recovery"))
    return _causal_case(case, before, during, after, operation_id=contender_parent,
        roles=roles, request_outcome="denied", owner_outcome="not-applicable")


def _run_retry_case(adapter, handles, statement):
    selected = _new_content_key(adapter)
    _publish(adapter, selected, statement)
    handle = handles[APP_IDS[1]]
    before = _with_graph(handle, _snapshot(handle))
    task = {"method": "POST", "path": "/api/v1/trust-graph/import-uri",
            "parameters": {"uri": selected["uri"]}}
    with _start_client(adapter, handle.context, task) as prior:
        prior.release(abandon=True)
        prior_result = prior.result()
    if prior_result.get("status") != "abandoned-after-request-write":
        fail("retry-prior-not-abandoned")
    during = _wait_for(adapter, handle, before["work"]["lastSequence"],
        lambda _snapshot_value, rows: any(row["kind"] == "REQUEST_SUCCEEDED" for row in rows),
        maximum=_policy_seconds(adapter, "requestDeadlineMillis"))
    if during is None:
        fail("retry-prior-terminal-unobserved")
    during = _with_graph(handle, during)
    with _start_client(adapter, handle.context, task) as retry:
        retry.release()
        retry_result = retry.result()
    _expect_status(retry_result, {200}, "retry-response-failed")
    after = _with_graph(handle, _snapshot(handle))
    events = _events(after, before["work"]["lastSequence"])
    parents = _composed_parents(events, "COMPOSED_URI_IMPORT_START")
    if len(parents) != 2:
        fail("retry-parent-count-invalid")
    prior_parent, retry_parent = parents
    roles = {}
    roles.update(_roles_for_parent(events, prior_parent, "prior"))
    roles.update(_roles_for_parent(events, retry_parent, "retry"))
    return _causal_case("retry", before, during, after, operation_id=retry_parent,
        roles=roles, request_outcome="response-lost-retry-succeeded",
        owner_outcome="not-applicable", retry_of=prior_parent)


def _run_abandonment_case(adapter, handles, statement):
    """Exercise installed disconnect honestly; it is not owner-cancelled coverage."""
    selected = _new_content_key(adapter)
    holder = handles[APP_IDS[0]]
    contender = handles[APP_IDS[1]]
    before = _with_graph(holder, _snapshot(holder))
    task = {"method": "POST", "path": "/api/v1/trust-graph/import-uri",
            "parameters": {"uri": selected["uri"]}}
    with _start_client(adapter, holder.context, task) as process:
        process.release(abandon=True)
        result = process.result()
    if result.get("status") != "abandoned-after-request-write":
        fail("cancellation-client-not-abandoned")
    during = _wait_for(adapter, holder, before["work"]["lastSequence"],
        lambda snapshot, rows: snapshot["budget"].get("activeFamilyLeases", 0) >= 4
            and any(row["kind"] == "FETCH_INVOKED" for row in rows), maximum=8)
    if during is None:
        return {"status": "not-observed", "reason": "abandoned-owner-not-active"}
    during = _with_graph(holder, during)
    with _start_client(adapter, contender.context, task) as blocked:
        blocked.release()
        blocked_result = blocked.result()
    _publish(adapter, selected, statement)
    after = _wait_for(adapter, holder, before["work"]["lastSequence"],
        lambda snapshot, rows: snapshot["budget"].get("activeFamilyLeases") == 0
            and any(row["kind"] in {"FETCH_SUCCEEDED", "FETCH_OWNER_TERMINATED"}
                    for row in rows),
        maximum=_policy_seconds(adapter, "ownerAcknowledgmentDeadlineMillis"))
    if after is None:
        return {"status": "not-observed", "reason": "abandoned-owner-terminal-unknown"}
    after = _with_graph(holder, after)
    return {"status": "abandonment-observed", "contenderStatus": blocked_result["status"],
            "beforeSequence": before["work"]["lastSequence"],
            "duringSequence": during["work"]["lastSequence"],
            "afterSequence": after["work"]["lastSequence"]}


def _run_timeout_case(adapter, handles, statement):
    """Attempt a real short content-fetch timeout; require a separately observed owner tail."""
    selected = _new_content_key(adapter)
    handle = handles[APP_IDS[0]]
    contender_handle = handles[APP_IDS[1]]
    before = _with_graph(handle, _snapshot(handle))
    task = {"method": "POST", "path": "/api/v1/trust-graph/import-uri",
            "parameters": {"uri": selected["uri"]}}
    with _start_client(adapter, handle.context, task) as primary:
        primary.release()
        result = primary.result()
    if result.get("status") not in {502, 504}:
        return None, {"status": "not-observed", "reason": "request-did-not-time-out",
                      "httpStatus": result.get("status")}
    during = _snapshot(handle)
    rows = _events(during, before["work"]["lastSequence"])
    if (not any(row["kind"] == "FETCH_TERMINATION_UNKNOWN" for row in rows)
            or during["budget"].get("activeFamilyLeases", 0) == 0
            or any(row["kind"] == "FETCH_OWNER_TERMINATED" for row in rows)):
        return None, {"status": "not-observed", "reason": "delayed-owner-tail-not-observed"}
    during = _with_graph(handle, during)
    contender_task = {"method": "POST", "path": "/api/v1/trust-graph/import-uri",
        "parameters": {"uri": selected["uri"]}}
    with _start_client(
            adapter, contender_handle.context, contender_task) as contender:
        contender.release()
        contender_result = contender.result()
    if contender_result.get("status") != 429:
        return None, {"status": "not-observed", "reason": "retained-slot-not-denied",
                      "httpStatus": contender_result.get("status")}
    acknowledged = _wait_for(adapter, handle, before["work"]["lastSequence"],
        lambda snapshot, tail: snapshot["budget"].get("activeFamilyLeases") == 0
            and any(row["kind"] == "FETCH_OWNER_TERMINATED" for row in tail),
        maximum=_policy_seconds(adapter, "ownerAcknowledgmentDeadlineMillis"))
    if acknowledged is None:
        return None, {"status": "not-observed", "reason": "normal-owner-ack-unobserved"}
    recovery_task = {"method": "POST", "path": "/api/v1/trust-graph/import",
        "parameters": {"document": statement.decode("utf-8")}}
    with _start_client(adapter, handle.context, recovery_task) as recovery:
        recovery.release()
        recovery_result = recovery.result()
    if recovery_result.get("status") != 200:
        return None, {"status": "not-observed", "reason": "timeout-recovery-failed",
                      "httpStatus": recovery_result.get("status")}
    after = _snapshot(handle)
    after = _with_graph(handle, after)
    events = _events(after, before["work"]["lastSequence"])
    primary = _composed_parents(events, "COMPOSED_URI_IMPORT_START")
    recovery = _composed_parents(events, "COMPOSED_DIRECT_IMPORT_START")
    if len(primary) != 2 or len(recovery) != 1:
        return None, {"status": "not-observed", "reason": "timeout-operation-identities-missing"}
    primary_id, contender_id, recovery_id = primary[0], primary[1], recovery[0]
    roles = {}
    roles.update(_roles_for_parent(events, primary_id, "primary"))
    roles.update(_roles_for_parent(events, contender_id, "contender"))
    roles.update(_roles_for_parent(events, recovery_id, "recovery"))
    causal = _causal_case("timeout", before, during, after,
        operation_id=primary_id, roles=roles, request_outcome="timed-out",
        owner_outcome="normal-ack")
    return causal, {"status": "observed"}


def _save_private(root, value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(raw) > 4 * 1024 * 1024:
        fail("private-evidence-limit")
    target = Path(root) / PRIVATE_FILE
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _validate_selection(adapter):
    plan_digest = runtime.canonical_digest(adapter.plan)
    selected = adapter.authorization.get("budgetSelection")
    selection_digest = runtime.canonical_digest({"executionClass": EXECUTION_CLASS,
        "planDigest": plan_digest, "budgetSelection": selected})
    expected_apps = {ROLE: list(APP_IDS), "candidate-recipient": [], "previous": [],
                     "relay-no-apps": []}
    if (adapter.authorization.get("executionClass") != EXECUTION_CLASS
            or adapter.plan.get("experimentId") != EXPERIMENT
            or adapter.private.get("root") !=
                "/var/lib/cryptad-cross-version/experiments/" + EXPERIMENT
            or any([app.get("appId") for app in
                    adapter.private["nodes"][role].get("apps", [])] != expected_apps[role]
                   for role in runtime.ROLES)
            or adapter.authorization.get("planDigest") != plan_digest
            or adapter.authorization.get("selectionDigest") != selection_digest
            or not isinstance(selected, dict)
            or selected.get("caseIds") != list(CASES)):
        fail("execution-class-unbound")
    return selection_digest


def run_budget_lane(adapter, *, leave_running_for_administrator=False,
                    on_start_failure=None):
    """Execute the fixed installed class and retain honest per-direction observations.

    The deterministic native tests are the authority for pathological owner timing.  Installed
    directions are attempted only after an actual native holder is observed; a direction that
    cannot sustain the required overlap is retained as ``not-observed`` rather than promoted.
    """
    selection_digest = _validate_selection(adapter)
    if on_start_failure is not None and not callable(on_start_failure):
        fail("start-diagnostic-invalid")
    completed = False
    started = time.monotonic_ns()
    attempts = []
    contexts = {}
    try:
        for role in runtime.ROLES:
            adapter.start(role)
        adapter.connect()
        handles, statement = _bootstrap_apps(adapter)
        contexts = {app_id: handles[app_id].context for app_id in APP_IDS}
        context_evidence = {app_id: _context_evidence(contexts[app_id])
                            for app_id in APP_IDS}
        before = _snapshot(handles[APP_IDS[0]])
        recipient_host = BudgetAppHandle(adapter, APP_IDS[0], "candidate-recipient")
        recipient_host.host_bootstrap()
        recipient_before = _snapshot(recipient_host)

        # Installed execution first proves independent role/app principal binding.  These denials
        # are prerequisites shared by the five causal cases, not additional mandatory cases.
        wrong_role = dict(contexts[APP_IDS[0]], handle=adapter.handles["candidate-recipient"],
                          role="candidate-recipient",
                          generation=adapter.nodes["candidate-recipient"]["generation"],
                          managerInvocation=adapter.nodes["candidate-recipient"]["managerInvocation"],
                          bootId=adapter.nodes["candidate-recipient"]["bootId"])
        denial_task = {"method": "GET", "path": "/api/v1/trust-graph/statements",
                       "parameters": {}}
        with _start_client(adapter, wrong_role, denial_task,
                expected_role="candidate-recipient") as wrong:
            wrong.release()
            wrong_result = wrong.result()
        if wrong_result["status"] != 401:
            fail("wrong-role-session-not-denied")
        recipient_after = _snapshot(recipient_host)
        if not _unchanged_native(recipient_before, recipient_after):
            fail("wrong-role-native-work-observed")
        with _start_client(adapter, contexts[APP_IDS[0]], {
                **denial_task, "origin": contexts[APP_IDS[1]]["origin"]}) as cross:
            cross.release()
            cross_result = cross.result()
        if cross_result["status"] != 401:
            fail("wrong-app-origin-not-denied")
        with _start_client(adapter, contexts[APP_IDS[0]], {
                **denial_task, "session": "pr317-invalid-session"}) as invalid:
            invalid.release()
            invalid_result = invalid.result()
        if invalid_result["status"] != 401:
            fail("invalid-session-not-denied")
        after_denials = _snapshot(handles[APP_IDS[0]])
        if not _unchanged_native(before, after_denials):
            fail("invalid-principal-native-work-observed")
        attempts.append({"kind": "principal-denials", "wrongRole": wrong_result["status"],
                         "wrongOrigin": cross_result["status"],
                         "invalidSession": invalid_result["status"],
                         "collectorEpoch": after_denials["work"].get("collectorEpoch"),
                         "beforeSequence": before["work"].get("lastSequence"),
                         "afterSequence": after_denials["work"].get("lastSequence")})

        causal_cases = [_run_retry_case(adapter, handles, statement)]
        attempts.append({"kind": "causal-case-attempt", "caseId": "retry",
                         "status": "observed"})
        for case in ("import-concurrency", "fetch-concurrency"):
            causal_cases.append(_run_concurrency_case(
                adapter, handles, statement, case))
            attempts.append({"kind": "causal-case-attempt", "caseId": case,
                             "status": "observed"})
        abandonment = _run_abandonment_case(adapter, handles, statement)
        attempts.append({"kind": "causal-case-attempt", "caseId": "cancellation",
                         **abandonment,
                         "ownerCancellation": "not-observed"})
        timeout_case, timeout_attempt = _run_timeout_case(
            adapter, handles, statement)
        attempts.append({"kind": "causal-case-attempt", "caseId": "timeout",
                         **timeout_attempt})
        if timeout_case is not None:
            causal_cases.append(timeout_case)
        causal_cases.sort(key=lambda row: CASES.index(row["caseId"]))
        node_epoch = adapter.journal.node_epochs[("", ROLE)]
        for row in causal_cases:
            row["nodeEpoch"] = node_epoch
        selected_node = next(row for row in adapter.plan["nodes"] if row["role"] == ROLE)
        final = _snapshot(handles[APP_IDS[0]])
        attachment = {"schemaVersion": 3,
            "collectorEpoch": final["work"]["collectorEpoch"],
            "nodeEpoch": node_epoch,
            "workloadDigest": adapter.plan["workloadInputs"]["scheduler"],
            "productDigest": selected_node["artifactDigest"],
            "sourceCommit": selected_node["sourceCommit"],
            "appCohortDigest": pressure.baseline.digest(selected_node["appDigests"]),
            "collectorDigest": adapter.plan["composedBudgetInputs"]["collectorDigest"],
            "configurationDigest": adapter.plan["composedBudgetInputs"]["configurationDigest"],
            "segments": [], "causalCases": causal_cases}
        adapter.journal.append("operation", role=ROLE, scenario="app-budgets",
            outcome="partial", operation="composed-budget-attachment",
            composed_budget_evidence=attachment)
        coverage = composed.derive_journal(adapter.plan, adapter.journal.events)
        observed = [case for case in CASES if case in coverage["observedCases"]]
        missing = [case for case in CASES if case not in observed]
        private = {"schemaVersion": 1, "kind": PRIVATE_KIND,
            "executionClass": EXECUTION_CLASS, "selectionDigest": selection_digest,
            "window": {"startedMonotonicNs": started,
                       "finishedMonotonicNs": time.monotonic_ns()},
            "contexts": context_evidence, "attempts": attempts,
            "nativeWindow": {"before": before, "after": final},
            "composedBudgetEvidence": attachment,
            "composedBudgetCoverage": coverage,
            "observedCases": observed, "notObservedCases": missing,
            "remainingHardCases": ["window-crossing", "partial-rate-write",
                "graph-store-unavailable", "graceful-restart", "abrupt-restart",
                "diagnostics-unavailable", "privacy"]}
        digest = _save_private(adapter.root, private)
        result = {"schemaVersion": 1,
            "kind": "pr317-installed-composed-budget-lifecycle-observation",
            "executionClass": EXECUTION_CLASS, "selectionDigest": selection_digest,
            "privateEvidenceDigest": digest,
            "evidenceClass": "installed-four-role-private-observer",
            "topologyRoles": len(adapter.nodes), "namespaceTransportImplemented": True,
            "fiveCaseDriversImplemented": False, "observedCases": observed,
            "notObservedCases": missing, "ownerCancellationDirection": "not-observed",
            "cleanupState": ("administrator-required" if leave_running_for_administrator
                             else "observer-owned"),
            "historicalPr315AcceptanceTransferred": False,
            "historicalPr316AcceptanceTransferred": False,
            "finiteNativeAcceptance": False, "fullAppBudgets": "not-observed",
            "originalProtectedAuthority": False, "independentSecurityReview": False,
            "releaseEligible": False, "phaseComplete": False}
        completed = True
        return result
    except Exception:
        if getattr(adapter, "active_start_role", None) is not None \
                and on_start_failure is not None:
            try:
                on_start_failure(adapter.active_start_role,
                                 getattr(adapter, "active_start_stage", "unavailable"))
            except (OSError, ValueError, runtime.RuntimeFailure):
                pass
        raise
    finally:
        if (not completed or not leave_running_for_administrator) \
                and adapter.cleanup() != "complete":
            fail("terminal-reconciliation-required")


def validate_guest_observation(value, expected_selection_digest=None):
    """Validate the closed pre-cleanup result without reading its private causal payload."""
    fields = {"schemaVersion", "kind", "executionClass", "selectionDigest",
        "privateEvidenceDigest", "evidenceClass", "topologyRoles",
        "namespaceTransportImplemented", "fiveCaseDriversImplemented", "observedCases",
        "notObservedCases", "ownerCancellationDirection", "cleanupState",
        "historicalPr315AcceptanceTransferred", "historicalPr316AcceptanceTransferred",
        "finiteNativeAcceptance", "fullAppBudgets", "originalProtectedAuthority",
        "independentSecurityReview", "releaseEligible", "phaseComplete"}
    if (not isinstance(value, dict) or set(value) != fields
            or value["schemaVersion"] != 1
            or value["kind"] != "pr317-installed-composed-budget-lifecycle-observation"
            or value["executionClass"] != EXECUTION_CLASS
            or value["evidenceClass"] != "installed-four-role-private-observer"
            or value["topologyRoles"] != 4
            or value["namespaceTransportImplemented"] is not True
            or value["fiveCaseDriversImplemented"] is not False
            or value["ownerCancellationDirection"] != "not-observed"
            or value["cleanupState"] not in {"administrator-required", "completed"}
            or any(value[key] is not False for key in (
                "historicalPr315AcceptanceTransferred",
                "historicalPr316AcceptanceTransferred", "finiteNativeAcceptance",
                "originalProtectedAuthority", "independentSecurityReview",
                "releaseEligible", "phaseComplete"))
            or value["fullAppBudgets"] != "not-observed"
            or re.fullmatch("sha256:[a-f0-9]{64}", str(value["selectionDigest"])) is None
            or re.fullmatch("sha256:[a-f0-9]{64}", str(value["privateEvidenceDigest"])) is None
            or expected_selection_digest is not None
                and value["selectionDigest"] != expected_selection_digest
            or not isinstance(value["observedCases"], list)
            or not isinstance(value["notObservedCases"], list)
            or set(value["observedCases"]) | set(value["notObservedCases"]) != set(CASES)
            or set(value["observedCases"]) & set(value["notObservedCases"])
            or any(case not in CASES for case in
                   value["observedCases"] + value["notObservedCases"])):
        raise ValueError("pr317-guest-observation-invalid")
    return value


def attach_guest_context(value, identity, runtime_policy, campaign_deadline):
    """Attach administrator-owned identity without upgrading installed case observations."""
    validate_guest_observation(value)
    return {**value, "identity": identity, "runtimePolicy": runtime_policy,
            "campaignDeadlineMonotonicNs": campaign_deadline,
            "workloadAcceptance": "incomplete-pr317-private-evidence-not-verified",
            "protectedExecutionEnabled": False}

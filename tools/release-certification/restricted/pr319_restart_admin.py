"""Closed root test-kit transitions for one authenticated synthetic daemon.

The observer names a fixed purpose, never a PID, signal, path, mode, unit or
command. Linux pidfds bind forced death. A short PTRACE_SEIZE/TRACEEXIT witness
observes the selected JVM's kernel exit status for graceful classification;
unsupported ptrace providers fail rather than substitute wrapper/log claims.
The trusted parent retains descriptors and restores access/detaches on failure.
"""
from __future__ import annotations

import ctypes
import errno
import json
import os
from pathlib import Path
import select
import secrets
import signal
import socket
import stat
import re
import subprocess
import sys
import time

from pr318_storage_admin import _fixed_mount, _identity, _open_target

EXECUTION_CLASS = "pr319-composed-budget-restart-diagnostics-v1"
ROLE = "candidate-sender"
TARGET = ("network-budget", "feed-reader")
COUNTER = "trust_graph_import.properties"
COMMANDS = ("graceful:pin", "graceful:terminal", "abrupt-settled:terminate",
            "abrupt-inflight:terminate", "restart:readback", "restart:snapshot",
            "diagnostics-enumeration:restrict", "diagnostics-enumeration:restore",
            "diagnostics-required-key:restrict", "diagnostics-required-key:restore")
PROFILE_FIELDS = ("Type", "KillMode", "KillSignal", "FinalKillSignal", "SendSIGKILL",
                  "TimeoutStopUSec", "Restart", "Result", "ExecMainCode", "ExecMainStatus")
PTRACE_SEIZE, PTRACE_INTERRUPT, PTRACE_DETACH = 0x4206, 0x4207, 17
PTRACE_GETEVENTMSG, PTRACE_CONT = 0x4201, 7
PTRACE_O_TRACEEXIT, PTRACE_EVENT_EXIT = 0x40, 6
WAIT_WALL = 0x40000000


def _ptrace(request, pid, data=0):
    if sys.platform != "linux":
        raise ValueError("pr319-linux-ptrace-required")
    library = ctypes.CDLL(None, use_errno=True)
    library.ptrace.restype = ctypes.c_long
    value = library.ptrace(ctypes.c_uint(request), ctypes.c_int(pid),
                           ctypes.c_void_p(0), data)
    if value == -1:
        raise OSError(ctypes.get_errno(), "pr319-kernel-exit-witness-unavailable")
    return value


class KernelExitWitness:
    """Trace only the already kernel-bound JVM leader; never stop it at setup."""

    def __init__(self, pid):
        self.pid, self.attached, self.stopped = pid, False, False
        _ptrace(PTRACE_SEIZE, pid, ctypes.c_void_p(PTRACE_O_TRACEEXIT))
        self.attached = True

    def observe(self, deadline):
        while time.monotonic() < deadline:
            waited, status = os.waitpid(self.pid, os.WNOHANG | WAIT_WALL)
            if not waited:
                time.sleep(.01)
                continue
            if not os.WIFSTOPPED(status):
                self.attached = False
                raise ValueError("pr319-kernel-exit-event-missing")
            self.stopped = True
            if status >> 16 == PTRACE_EVENT_EXIT:
                message = ctypes.c_ulong()
                _ptrace(PTRACE_GETEVENTMSG, self.pid, ctypes.byref(message))
                observed = time.monotonic_ns()
                self.close()
                value = int(message.value)
                return {"source": "linux-ptrace-exit-event", "waitStatus": value,
                        "normalExit": os.WIFEXITED(value),
                        "exitCode": os.WEXITSTATUS(value) if os.WIFEXITED(value) else None,
                        "signal": os.WTERMSIG(value) if os.WIFSIGNALED(value) else None,
                        "observedMonotonicNs": observed}
            # Deliver real signal-delivery stops, but do not inject synthetic SIGTRAP.
            delivered = os.WSTOPSIG(status)
            _ptrace(PTRACE_CONT, self.pid,
                    ctypes.c_void_p(0 if status >> 16 else delivered))
            self.stopped = False
        raise ValueError("pr319-kernel-exit-witness-timeout")

    def close(self):
        if not self.attached:
            return
        try:
            if not self.stopped:
                _ptrace(PTRACE_INTERRUPT, self.pid)
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    waited, status = os.waitpid(self.pid, os.WNOHANG | WAIT_WALL)
                    if waited:
                        if not os.WIFSTOPPED(status):
                            self.attached = False
                            return
                        self.stopped = True
                        break
                    time.sleep(.01)
                if not self.stopped:
                    raise ValueError("pr319-tracer-detach-unconfirmed")
            _ptrace(PTRACE_DETACH, self.pid)
            self.attached = False
            self.stopped = False
        except (ProcessLookupError, ChildProcessError):
            self.attached = False


def _profile(workload):
    result = subprocess.run(["/usr/bin/systemctl", "show", workload.unit(ROLE),
        "--no-pager", "--property=" + ",".join(PROFILE_FIELDS)],
        stdin=subprocess.DEVNULL, capture_output=True, env=workload.ENV,
        timeout=3, check=True)
    if len(result.stdout) > 4096 or len(result.stderr) > 4096:
        raise ValueError("pr319-manager-profile-limit")
    value = dict(line.split("=", 1) for line in result.stdout.decode("ascii").splitlines()
                 if "=" in line)
    if set(value) != set(PROFILE_FIELDS) or any(len(v) > 128 for v in value.values()):
        raise ValueError("pr319-manager-profile-invalid")
    required = {"Type": "exec", "KillMode": "control-group", "KillSignal": "15",
                "FinalKillSignal": "9", "SendSIGKILL": "yes",
                "TimeoutStopUSec": "20s", "Restart": "no"}
    if any(value[k] != v for k, v in required.items()):
        raise ValueError("pr319-manager-stop-profile-changed")
    return value


def _data(workload, uid):
    state = workload.ROOT / "state" / ROLE
    _fixed_mount(state)
    descriptor = _open_target(state, (), uid)
    try:
        root = state.stat(follow_symlinks=False)
        node_apps = os.fstat(descriptor)
        with open("/proc/self/mountinfo", "rb") as source:
            raw = source.read(1048577)
        if len(raw) > 1048576:
            raise ValueError("pr319-mount-inventory-limit")
        rows = [line.split() for line in raw.decode("ascii").splitlines()
                if len(line.split()) >= 6 and line.split()[4] == str(state)]
        if len(rows) != 1:
            raise ValueError("pr319-owned-role-mount-required")
        return {"roleRoot": _identity(root), "appStoreRoot": _identity(node_apps),
                "bootId": workload.boot(), "mountSource": "cryptad-workload-" + ROLE,
                "filesystem": "tmpfs", "mountIdentity": {
                    "mountId": rows[0][0], "mountParent": rows[0][1],
                    "majorMinor": rows[0][2], "root": rows[0][3]}}
    finally:
        os.close(descriptor)


def _daemon(workload, record):
    """Find the sole selected outer-namespace JDK from trusted fixed cgroup members."""
    launch = workload.read(workload.ROOT / "roles" / ROLE / "launch.json")
    expected = launch.get("javaDigest")
    if not isinstance(expected, str) or not expected.startswith("sha256:"):
        raise ValueError("pr319-jdk-selection-invalid")
    group = workload.group(ROLE)
    with os.scandir(group) as entries:
        for count, entry in enumerate(entries):
            if count >= 256 or entry.is_dir(follow_symlinks=False) or entry.is_symlink():
                raise ValueError("pr319-role-cgroup-invalid")
    raw = (group / "cgroup.procs").read_bytes()
    if len(raw) > 8192 or len(raw.split()) > 512:
        raise ValueError("pr319-role-membership-limit")
    matches = []
    uid = workload.account(ROLE).pw_uid
    for pid in sorted(set(map(int, raw.split()))):
        try:
            row = workload._process(pid, ROLE, uid)
        except (FileNotFoundError, ProcessLookupError):
            continue
        if row["executableDigest"] == expected and len(row["namespacePids"]) == 2:
            matches.append(row)
    if len(matches) != 1:
        raise ValueError("pr319-daemon-not-unique")
    row = matches[0]
    descriptor = os.pidfd_open(row["hostPid"])
    try:
        current = workload._process(row["hostPid"], ROLE, uid)
        epoch_fields = ("hostPid", "hostParentPid", "startTicks", "namespacePids",
                        "executableDigest", "networkNamespaceIdentity",
                        "mountNamespaceIdentity", "userNamespaceIdentity")
        if any(current[k] != row[k] for k in epoch_fields) or select.select([descriptor], [], [], 0)[0]:
            raise ValueError("pr319-daemon-epoch-changed")
        workload.exact(ROLE, record, workload.manager(ROLE, "show"))
        return row, descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _probe_access(descriptor, uid, gid, enumeration_only, deadline):
    """Measure actual readdir/open under the daemon UID, without opening for writing."""
    child = os.fork()
    if child == 0:
        try:
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
            try:
                # A root-opened directory FD may keep readdir authority after chmod.
                # Open a NEW descriptor under the role identity, as the JVM does.
                probe_directory = os.open(".", os.O_RDONLY | os.O_DIRECTORY,
                                          dir_fd=descriptor)
                try:
                    os.listdir(probe_directory)
                finally:
                    os.close(probe_directory)
            except OSError as error:
                if error.errno != errno.EACCES:
                    os._exit(2)
            else:
                os._exit(3)
            try:
                counter = os.open(COUNTER, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
            except OSError as error:
                os._exit(0 if not enumeration_only and error.errno == errno.EACCES else 4)
            else:
                os.close(counter)
                os._exit(0 if enumeration_only else 5)
        except BaseException:
            os._exit(6)
    while time.monotonic() < deadline:
        waited, status = os.waitpid(child, os.WNOHANG)
        if waited:
            if status != 0:
                raise ValueError("pr319-role-access-premise-unobserved")
            return
        time.sleep(.01)
    os.kill(child, signal.SIGKILL)
    os.waitpid(child, 0)
    raise ValueError("pr319-role-access-probe-timeout")


def _private_read(parent, name, uid, maximum):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != uid
                or before.st_mode & 0o022 or before.st_dev != os.fstat(parent).st_dev
                or before.st_nlink != 1 or not 0 < before.st_size <= maximum):
            raise ValueError("pr319-capture-member-unsafe")
        pieces, total = [], 0
        while total <= maximum:
            block = os.read(fd, min(8192, maximum + 1 - total))
            if not block:
                break
            pieces.append(block)
            total += len(block)
        after = os.fstat(fd)
        selected = os.stat(name, dir_fd=parent, follow_symlinks=False)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if total != before.st_size or any(getattr(before, k) != getattr(x, k)
                for x in (after, selected) for k in fields):
            raise ValueError("pr319-capture-member-changed")
        return b"".join(pieces)
    finally:
        os.close(fd)


def _properties(raw):
    """Decode the bounded Properties.store representation; reject ambiguous records."""
    def unescape(value):
        def replace(match):
            escape = match.group(1)
            if escape.startswith("u"):
                return chr(int(escape[1:], 16))
            return {"t": "\t", "n": "\n", "r": "\r", "f": "\f"}.get(escape, escape)
        return re.sub(r"\\(u[0-9a-fA-F]{4}|.)", replace, value)
    result = {}
    for line in raw.decode("utf-8", errors="strict").splitlines():
        if not line or line.startswith(("#", "!")):
            continue
        matched = re.fullmatch(r"([A-Za-z][A-Za-z0-9]*)=(.*)", line)
        if matched is None or matched[1] in result:
            raise ValueError("pr319-capture-properties-invalid")
        result[matched[1]] = unescape(matched[2])
    return result


def _names(descriptor, maximum):
    names = []
    with os.scandir(descriptor) as entries:
        for entry in entries:
            if len(names) >= maximum:
                raise ValueError("pr319-capture-member-limit")
            names.append(entry.name)
    return sorted(names)


def _store_capture(workload, uid):
    """Two fixed nonrecursive file-store subjects, bounded and independently read."""
    state = workload.ROOT / "state" / ROLE
    budget = _open_target(state, ("network-budget",), uid)
    usage, graph, visited, total = [], [], 0, 0
    try:
        scopes = _names(budget, 16)
        for scope in scopes:
            if scope not in ("feed-reader", "budget-importer", "budget-no-trust",
                             "budget-no-fetch", "_cryptad_global", "_cryptad_operator"):
                raise ValueError("pr319-capture-scope-unselected")
            directory = os.open(scope, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=budget)
            try:
                info = os.fstat(directory)
                if info.st_uid != uid or info.st_dev != os.fstat(budget).st_dev:
                    raise ValueError("pr319-capture-scope-unsafe")
                names = _names(directory, 16)
                for name in names:
                    visited += 1
                    if visited > 256:
                        raise ValueError("pr319-capture-member-limit")
                    if name.startswith(".app-network-budget-") and name.endswith(".tmp"):
                        raise ValueError("pr319-capture-inflight-write")
                    if re.fullmatch(r"[a-z_]+\.properties", name) is None:
                        raise ValueError("pr319-capture-member-invalid")
                    raw = _private_read(directory, name, uid, 8192)
                    total += len(raw)
                    value = _properties(raw)
                    required = {"version", "appId", "operation", "windowStart", "windowSeconds", "count"}
                    allowed = required | {"lastDecisionAt", "lastDecision", "nextAvailableAt"}
                    if (not required <= set(value) or set(value) - allowed
                            or value["version"] != "1" or value["appId"] != scope
                            or name != value["operation"] + ".properties"
                            or re.fullmatch("[0-9]+", value["count"]) is None
                            or value["windowSeconds"] not in ("60", "3600")):
                        raise ValueError("pr319-capture-counter-invalid")
                    from restricted_workload_launcher import BUDGET_ENVIRONMENT
                    families = {"foreground_content_fetch": "FOREGROUND_CONTENT_FETCH_PER_APP_PER_MINUTE",
                        "content_fetch_global": "FOREGROUND_CONTENT_FETCH_GLOBAL_PER_MINUTE",
                        "trust_graph_import": "TRUST_GRAPH_IMPORT_" +
                            ("GLOBAL" if scope == "_cryptad_global" else "PER_APP") + "_PER_HOUR",
                        "subscription_poll": "SUBSCRIPTION_POLL_" +
                            ("GLOBAL" if scope == "_cryptad_global" else "PER_APP") + "_PER_HOUR"}
                    if value["operation"] not in families:
                        raise ValueError("pr319-capture-family-unselected")
                    limit = int(BUDGET_ENVIRONMENT["CRYPTAD_APP_NETWORK_BUDGET_" + families[value["operation"]]])
                    usage.append({"appId": scope, "operation": value["operation"],
                        "windowStart": value["windowStart"], "windowSeconds": int(value["windowSeconds"]),
                        "count": int(value["count"]), "limit": limit, "lastDecisionAt": value.get("lastDecisionAt"),
                        "lastDecision": value.get("lastDecision"),
                        "nextAvailableAt": value.get("nextAvailableAt")})
                selected_directory = os.stat(scope, dir_fd=budget, follow_symlinks=False)
                if (not stat.S_ISDIR(selected_directory.st_mode)
                        or (selected_directory.st_dev, selected_directory.st_ino) != (info.st_dev, info.st_ino)):
                    raise ValueError("pr319-capture-scope-substituted")
            finally:
                os.close(directory)
    finally:
        os.close(budget)
    statements = _open_target(state, ("trust-graph", "statements"), uid)
    try:
        names = _names(statements, 16)
        for name in names:
            if re.fullmatch(r"[a-f0-9]{64}\.properties", name) is None:
                raise ValueError("pr319-capture-graph-member-invalid")
            raw = _private_read(statements, name, uid, 65536)
            total += len(raw)
            if total > 131072:
                raise ValueError("pr319-capture-total-limit")
            value = _properties(raw)
            optional = {"sourceUri", "sourceUriHash", "sourceLabel", "sourceUriKind", "subscriptionId"}
            expected = {"version", "documentFingerprint", "payloadHash", "signatureVerified", "source",
                        "importedAt", "updatedAt", "documentBytes", "documentJson"} | optional
            required = expected - optional
            if (not required <= set(value) or set(value) - expected or value["version"] != "1"
                    or value["signatureVerified"] not in ("true", "false")
                    or value["documentFingerprint"] + ".properties" != name):
                raise ValueError("pr319-capture-graph-invalid")
            graph.append({k: value.get(k) for k in sorted(expected - {
                "version", "documentJson", "documentBytes", "signatureVerified"})} |
                {"document": json.loads(value["documentJson"]),
                 "signatureVerified": value["signatureVerified"] == "true"})
    finally:
        os.close(statements)
    if total > 131072:
        raise ValueError("pr319-capture-total-limit")
    return {"durableUsage": usage, "graphFacts": graph,
            "captureSource": "administrator-fixed-file-store-readback",
            "capturedMonotonicNs": time.monotonic_ns()}


class FixedRestartFaults:
    def __init__(self, workload, sender_handle):
        self.workload, self.sender_handle = workload, sender_handle
        self.receipts, self.completed = [], set()
        self.attempted = set()
        self.active = self.pinned = self.retained_data = None
        self.restoration_uncertain = False

    def _role(self, cleanup=False):
        workload = self.workload
        campaign, role, record = workload.retained(self.sender_handle)
        if (os.geteuid() != 0 or role != ROLE
                or campaign.get("executionClass") != EXECUTION_CLASS
                or campaign.get("budgetSelectionDigest") is None):
            raise ValueError("pr319-admin-selection-invalid")
        if not cleanup:
            workload.admit(campaign)
            workload.exact(role, record, workload.manager(role, "show"))
        return campaign, record, workload.account(role)

    def _receipt(self, campaign, record, case, phase, **facts):
        value = {"schemaVersion": 1, "kind": "pr319-trusted-transition",
            "caseId": case, "phase": phase, "role": ROLE,
            "campaign": record["campaign"], "generation": record["generation"],
            "managerInvocation": record["managerInvocation"], "bootId": record["bootId"],
            "selectionDigest": campaign["budgetSelectionDigest"],
            "deadlineMonotonicNs": campaign["deadlineMonotonicNs"],
            "observedMonotonicNs": time.monotonic_ns(), **facts}
        self.receipts.append(value)
        return value

    def request(self, command):
        if command not in COMMANDS:
            raise ValueError("pr319-admin-command-invalid")
        with self.workload.locked():
            case, phase = command.split(":")
            if case.startswith("diagnostics-"):
                return self._restrict(case) if phase == "restrict" else self._restore(case)
            if command == "graceful:terminal":
                return self._terminal()
            campaign, record, user = self._role()
            data = _data(self.workload, user.pw_uid)
            if self.active is not None and command != "restart:snapshot":
                raise ValueError("pr319-permission-fault-active")
            if command in {"restart:readback", "restart:snapshot"}:
                if self.retained_data is not None and data != self.retained_data:
                    raise ValueError("pr319-retained-data-changed")
                self.retained_data = data
                row, descriptor = _daemon(self.workload, record)
                os.close(descriptor)
                capture = _store_capture(self.workload, user.pw_uid)
                if _data(self.workload, user.pw_uid) != data:
                    raise ValueError("pr319-capture-data-substituted")
                return self._receipt(campaign, record, case, phase, dataIdentity=data,
                                     daemon=row, **capture)
            if self.pinned is not None or case in self.attempted:
                raise ValueError("pr319-admin-transition-invalid")
            profile = _profile(self.workload)
            row, descriptor = _daemon(self.workload, record)
            self.retained_data = data
            if case == "graceful":
                try:
                    trace = KernelExitWitness(row["hostPid"])
                except BaseException:
                    os.close(descriptor)
                    raise
                self.pinned = (campaign, dict(record), row, descriptor, trace, profile)
                self.attempted.add(case)
                return self._receipt(campaign, record, case, phase,
                    daemon=row, dataIdentity=data, effectiveStopProfile=profile)
            started = time.monotonic_ns()
            try:
                if select.select([descriptor], [], [], 0)[0]:
                    raise ValueError("pr319-daemon-not-alive-before-fault")
                self._receipt(campaign, record, case, "fault-intent", daemon=row,
                    dataIdentity=data, intendedSignal="SIGKILL", startedMonotonicNs=started)
                self.attempted.add(case)
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                if not select.select([descriptor], [], [], 5)[0]:
                    raise ValueError("pr319-forced-daemon-death-unconfirmed")
                self.workload._stop(ROLE, record, "pr319-forced-daemon")
                stop = self.workload.stop_receipt(ROLE, record)
                self.completed.add(case)
                return self._receipt(campaign, record, case, "terminal",
                    daemon=row, dataIdentity=data, effectiveStopProfile=profile,
                    forcedSignal="SIGKILL", pidfdDeathObserved=True,
                    startedMonotonicNs=started, stopReceipt=stop)
            finally:
                os.close(descriptor)

    def _terminal(self):
        if self.pinned is None or self.active is not None:
            raise ValueError("pr319-graceful-not-pinned")
        campaign, record, row, descriptor, trace, profile = self.pinned
        current, retained, user = self._role(cleanup=True)
        if any(retained.get(k) != record.get(k) for k in
               ("generation", "managerInvocation", "bootId", "campaign")):
            raise ValueError("pr319-graceful-role-changed")
        deadline = min(time.monotonic() + 20, campaign["deadlineMonotonicNs"] / 1e9)
        try:
            exit_fact = trace.observe(deadline)
            if not select.select([descriptor], [], [], max(0, deadline-time.monotonic()))[0]:
                raise ValueError("pr319-graceful-daemon-death-unconfirmed")
            # Give the normal wrapper/launcher chain its remaining original time.
            # A service stop before autonomous exit could itself force descendants.
            while time.monotonic() < deadline:
                state = self.workload.manager(ROLE, "show")
                if state["ActiveState"] in {"inactive", "failed"}:
                    break
                time.sleep(.05)
            else:
                raise ValueError("pr319-graceful-manager-exit-unobserved")
            self.workload._stop(ROLE, retained, "pr319-graceful-reconciliation")
            stop = self.workload.stop_receipt(ROLE, retained)
            after_profile = _profile(self.workload)
            valid = (exit_fact["normalExit"] and exit_fact["exitCode"] == 0
                     and after_profile["Result"] == "success"
                     and after_profile["ExecMainCode"] == "1"
                     and after_profile["ExecMainStatus"] == "0")
            if _data(self.workload, user.pw_uid) != self.retained_data:
                raise ValueError("pr319-retained-data-changed")
            self.completed.add("graceful")
            return self._receipt(current, record, "graceful", "terminal",
                daemon=row, dataIdentity=self.retained_data, kernelExit=exit_fact,
                effectiveStopProfile=profile, terminalManager=after_profile,
                pidfdDeathObserved=True, gracefulExitObserved=valid, stopReceipt=stop)
        finally:
            trace.close()
            os.close(descriptor)
            self.pinned = None

    def _restrict(self, case):
        if self.active is not None or self.pinned is not None or case in self.attempted:
            raise ValueError("pr319-admin-transition-invalid")
        campaign, record, user = self._role()
        data = _data(self.workload, user.pw_uid)
        descriptor = _open_target(self.workload.ROOT / "state" / ROLE, TARGET, user.pw_uid)
        original = _identity(os.fstat(descriptor))
        if original["mode"] & 0o700 != 0o700:
            os.close(descriptor)
            raise ValueError("pr319-diagnostic-initial-access-invalid")
        try:
            counter = os.open(COUNTER, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
            try:
                info = os.fstat(counter)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != user.pw_uid or info.st_nlink != 1:
                    raise ValueError("pr319-diagnostic-counter-invalid")
            finally:
                os.close(counter)
        except BaseException:
            os.close(descriptor)
            raise
        mask = 0o444 if case == "diagnostics-enumeration" else 0o555
        self.active = (case, descriptor, original, dict(record), mask)
        self.attempted.add(case)
        os.fchmod(descriptor, original["mode"] & ~mask)
        try:
            _probe_access(descriptor, user.pw_uid, user.pw_gid,
                          case == "diagnostics-enumeration",
                          min(time.monotonic()+3, campaign["deadlineMonotonicNs"]/1e9))
        except BaseException:
            self._restore(case)
            raise
        return self._receipt(campaign, record, case, "restricted", dataIdentity=data,
            targetClass="synthetic-feed-reader-scope", before=original,
            after=_identity(os.fstat(descriptor)), roleUidEnumerationDenied=True,
            roleUidExactKeyReadable=case == "diagnostics-enumeration")

    def _restore(self, case):
        if self.active is None or self.active[0] != case:
            raise ValueError("pr319-admin-transition-invalid")
        _case, descriptor, original, old_record, mask = self.active
        campaign, record, user = self._role(cleanup=True)
        current = _identity(os.fstat(descriptor))
        if (any(current[k] != original[k] for k in ("device", "inode", "uid", "gid"))
                or current["mode"] not in (original["mode"], original["mode"] & ~mask)):
            raise ValueError("pr319-restoration-target-changed")
        safe = all(record.get(k) == old_record.get(k) for k in
                   ("generation", "managerInvocation", "bootId", "campaign"))
        try:
            selected = _open_target(self.workload.ROOT / "state" / ROLE, TARGET, user.pw_uid)
            try:
                safe = safe and _identity(os.fstat(selected)) == current
            finally:
                os.close(selected)
        except (OSError, ValueError):
            safe = False
        os.fchmod(descriptor, original["mode"])
        after = _identity(os.fstat(descriptor))
        os.close(descriptor)
        self.active = None
        self.restoration_uncertain |= not safe
        self.completed.add(case)
        receipt = self._receipt(campaign, old_record, case, "restored", before=current,
            after=after, contentsRestored=False, selectedPathUnchanged=safe)
        if not safe or after != original:
            raise ValueError("pr319-restoration-reconciliation-required")
        return receipt

    def cleanup(self):
        with self.workload.locked():
            if self.pinned is not None:
                _campaign, _record, _row, descriptor, trace, _profile_value = self.pinned
                trace.close()
                os.close(descriptor)
                self.pinned = None
            if self.active is not None:
                self._restore(self.active[0])
        if self.restoration_uncertain:
            raise ValueError("pr319-restoration-reconciliation-required")
        return list(self.receipts)


def configure_sampler(sampler, execution_class, handoff):
    if execution_class == EXECUTION_CLASS:
        sampler.restart_faults = FixedRestartFaults(sampler.workload, handoff["handles"][ROLE])


def serve_restart(sampler, channel, message, flags):
    faults = getattr(sampler, "restart_faults", None)
    try:
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or faults is None or message[:1] != b"R":
            raise ValueError("pr319-admin-unselected")
        result = faults.request(message[1:].decode("ascii"))
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        result = {"error": "pr319-admin-failed"}
    raw = json.dumps(result, sort_keys=True, allow_nan=False).encode()
    if len(raw) > 131072:
        raw = b'{"error":"pr319-admin-response-limit"}'
    channel.sendall(raw)
    return True


def cleanup_sampler(sampler, diagnostics):
    faults = getattr(sampler, "restart_faults", None)
    if faults is not None:
        try:
            diagnostics["restartFaultReceipts"] = faults.cleanup()
            with faults.workload.locked():
                campaign, _role, _record = faults.workload.retained(faults.sender_handle)
                diagnostics["restartSelectionDigest"] = campaign["budgetSelectionDigest"]
                original_stops = {}
                for row in faults.receipts:
                    if row.get("phase") != "terminal" or "stopReceipt" not in row:
                        continue
                    generation = row["generation"]
                    archive = faults.workload.ROOT / "authority" / (
                        ROLE + "-stop-" + generation + ".json")
                    current = faults.workload.ROOT / "authority" / (ROLE + "-stop.json")
                    if archive.exists():
                        saved = faults.workload.read(archive)
                    else:
                        saved = faults.workload.read(current)
                    if saved != row["stopReceipt"]:
                        raise ValueError("pr319-original-stop-substituted")
                    original_stops[generation] = saved
                diagnostics["restartOriginalStops"] = original_stops
                bootstrap_contexts = {}
                for generation in sorted({row["generation"] for row in faults.receipts}):
                    path = faults.workload.ROOT / "authority" / (
                        ROLE + "-budget-bootstrap-" + generation + ".json")
                    bootstrap_contexts[generation] = faults.workload.read(path)
                diagnostics["restartBootstrapContexts"] = bootstrap_contexts
            diagnostics["restartAccessCleanup"] = "completed"
        except (OSError, ValueError, subprocess.SubprocessError):
            diagnostics["restartFaultReceipts"] = list(faults.receipts)
            diagnostics["restartAccessCleanup"] = "restoration-required"


def write_restart_diagnostics(workload, value, *, create=True):
    """Write only the fixed root-private restart capture with its separate finite cap."""
    target = Path("/root/pr315-workload-memory.private.json")
    workload.secured(target.parent, directory=True)
    if (os.geteuid() != 0 or not isinstance(value, dict)
            or value.get("classification") != "private-kernel-diagnostics-not-acceptance"
            or not isinstance(value.get("restartFaultReceipts"), list)
            or len(value["restartFaultReceipts"]) > 128):
        raise ValueError("pr319-private-diagnostics-invalid")
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if not 0 < len(raw) <= 262144:
        raise ValueError("pr319-private-diagnostics-limit")
    temporary = target.with_name("." + target.name + "-" + secrets.token_hex(16))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        if create:
            os.link(temporary, target, follow_symlinks=False)
        else:
            info = target.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077:
                raise ValueError("pr319-private-diagnostics-existing-unsafe")
            os.replace(temporary, target)
        parent = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if temporary.exists():
            temporary.unlink()

"""Fixed administrator-only storage denial for one prospective synthetic role.

This module belongs to the disposable test kit, never the daemon distribution or the
controller RPC service. The observer selects a closed phase, never a path, UID, mode,
mount, command, or record content. Restoration changes access only, preserving charges.
"""
from __future__ import annotations

import errno
import os
from pathlib import Path
import signal
import re
import json
import socket
import stat
import time


EXECUTION_CLASS = "pr318-fixed-window-partial-store-v1"
ROLE = "candidate-sender"
TARGETS = {
    "partial-rate-write": ("network-budget", "_cryptad_global"),
    "graph-store-unavailable": ("trust-graph", "statements"),
}
COMMANDS = tuple(case + ":" + phase for case in TARGETS
                 for phase in ("restrict", "restore"))


def _identity(info):
    return {"device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid,
            "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode)}


def _fixed_mount(state):
    """Require the administrator-prepared role tmpfs, not a shared host directory."""
    rows = []
    raw = Path("/proc/self/mountinfo").read_bytes()
    if len(raw) > 1024 * 1024:
        raise ValueError("pr318-mount-inventory-limit")
    for line in raw.decode("utf-8", errors="strict").splitlines():
        left, separator, right = line.partition(" - ")
        fields, tail = left.split(), right.split()
        if separator and len(fields) >= 6 and len(tail) >= 2 and fields[4] == str(state):
            rows.append((fields, tail))
    if (len(rows) != 1 or rows[0][1][:2] != ["tmpfs", "cryptad-workload-" + ROLE]
            or "rw" not in rows[0][0][5].split(",")):
        raise ValueError("pr318-owned-role-mount-required")


def _open_target(state, parts, uid):
    """Walk descriptor-relative fixed components; never follow an app-created link."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(state, flags)
    try:
        root = os.fstat(descriptor)
        if root.st_uid != uid or root.st_mode & 0o022:
            raise ValueError("pr318-role-root-unsafe")
        for name in ("data", "node", "apps", *parts):
            child = os.open(name, flags, dir_fd=descriptor)
            try:
                info = os.fstat(child)
                if info.st_dev != root.st_dev or info.st_uid != uid or info.st_mode & 0o022:
                    raise ValueError("pr318-target-owner-or-mount-invalid")
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _probe_denied(descriptor, uid, gid, deadline):
    """Require the real role identity to encounter EACCES on a fixed temp create.

    A successful unexpected create is removed by that same child and the test fails;
    existing counters are never opened for writing. The child has no supplementary
    groups and is reaped before any administrator response.
    """
    child = os.fork()
    if child == 0:
        try:
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
            try:
                probe = os.open(".pr318-access-probe", os.O_WRONLY | os.O_CREAT |
                                os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=descriptor)
            except OSError as error:
                os._exit(0 if error.errno == errno.EACCES else 2)
            else:
                os.close(probe)
                os.unlink(".pr318-access-probe", dir_fd=descriptor)
                os._exit(3)
        except BaseException:
            os._exit(4)
    while time.monotonic() < deadline:
        waited, status = os.waitpid(child, os.WNOHANG)
        if waited == child:
            if status != 0:
                raise ValueError("pr318-role-denial-not-observed")
            return
        time.sleep(.01)
    os.kill(child, signal.SIGKILL)
    os.waitpid(child, 0)
    raise ValueError("pr318-role-denial-probe-timeout")


class FixedStorageFaults:
    """Retain restoration descriptors in the trusted administrator parent."""

    def __init__(self, workload, sender_handle):
        self.workload = workload
        self.sender_handle = sender_handle
        self.active = None
        self.completed = set()
        self.receipts = []
        self.restoration_uncertain = False

    def _role(self, *, cleanup=False):
        workload = self.workload
        campaign, role, record = workload.retained(self.sender_handle)
        if (os.geteuid() != 0 or role != ROLE
                or campaign.get("executionClass") != EXECUTION_CLASS
                or campaign.get("budgetSelectionDigest") is None):
            raise ValueError("pr318-admin-selection-invalid")
        if not cleanup:
            workload.admit(campaign)
            workload.exact(role, record, workload.manager(role, "show"))
        return campaign, record, workload.account(role)

    def request(self, command):
        if command not in COMMANDS:
            raise ValueError("pr318-admin-command-invalid")
        case, phase = command.split(":")
        with self.workload.locked():
            return self._restrict(case) if phase == "restrict" else self._restore(case)

    def _restrict(self, case):
        if self.active is not None or case in self.completed:
            raise ValueError("pr318-admin-transition-invalid")
        campaign, record, user = self._role()
        state = self.workload.ROOT / "state" / ROLE
        _fixed_mount(state)
        descriptor = _open_target(state, TARGETS[case], user.pw_uid)
        before = _identity(os.fstat(descriptor))
        if before["mode"] & 0o500 != 0o500 or not before["mode"] & 0o200:
            os.close(descriptor)
            raise ValueError("pr318-target-initial-access-invalid")
        # Retain authority BEFORE changing access, including failed probe paths.
        self.active = (case, descriptor, before, record["generation"])
        os.fchmod(descriptor, before["mode"] & ~0o222)
        try:
            _probe_denied(descriptor, user.pw_uid, user.pw_gid,
                          min(time.monotonic() + 3, campaign["deadlineMonotonicNs"] / 1e9))
        except BaseException:
            self._restore(case)
            raise
        receipt = {"caseId": case, "phase": "restricted", "targetClass": case,
                   "before": before, "after": _identity(os.fstat(descriptor)),
                   "roleUidDenied": True, "generation": record["generation"],
                   "observedMonotonicNs": time.monotonic_ns()}
        self.receipts.append(receipt)
        return receipt

    def _restore(self, case):
        if self.active is None or self.active[0] != case:
            raise ValueError("pr318-admin-transition-invalid")
        _campaign, record, user = self._role(cleanup=True)
        _case, descriptor, original, generation = self.active
        current = _identity(os.fstat(descriptor))
        if (generation != record["generation"]
                or any(current[key] != original[key] for key in ("device", "inode", "uid", "gid"))
                or current["mode"] != original["mode"] & ~0o222):
            raise ValueError("pr318-restoration-target-changed")
        # Verify the still-selected pathname reaches the retained inode as well.
        try:
            selected = _open_target(self.workload.ROOT / "state" / ROLE,
                                    TARGETS[case], user.pw_uid)
        except (OSError, ValueError):
            # The retained inode is still ours even when the pathname was replaced.
            # Restore its access, never touch the replacement, and reject completion.
            os.fchmod(descriptor, original["mode"])
            os.close(descriptor)
            self.active = None
            self.restoration_uncertain = True
            raise ValueError("pr318-restoration-path-changed") from None
        try:
            if _identity(os.fstat(selected)) != current:
                os.fchmod(descriptor, original["mode"])
                os.close(descriptor)
                self.active = None
                self.restoration_uncertain = True
                raise ValueError("pr318-restoration-path-changed")
            os.fchmod(descriptor, original["mode"])
            after = _identity(os.fstat(descriptor))
            if after != original:
                raise ValueError("pr318-restoration-unconfirmed")
        finally:
            os.close(selected)
        receipt = {"caseId": case, "phase": "restored", "targetClass": case,
                   "before": current, "after": after, "contentsRestored": False,
                   "generation": generation, "observedMonotonicNs": time.monotonic_ns()}
        self.receipts.append(receipt)
        os.close(descriptor)
        self.active = None
        self.completed.add(case)
        return receipt

    def cleanup(self):
        """Restore even after observer failure/expiry; never replace counter contents."""
        if self.active is not None:
            with self.workload.locked():
                self._restore(self.active[0])
        if self.restoration_uncertain:
            raise ValueError("pr318-restoration-reconciliation-required")
        return list(self.receipts)


def configure_sampler(sampler, execution_class, handoff):
    if execution_class == EXECUTION_CLASS:
        sampler.storage_faults = FixedStorageFaults(
            sampler.workload, handoff["handles"][ROLE])


def serve_storage(sampler, channel, message, flags):
    """Closed kit channel; no extension to the production controller protocol."""
    faults = getattr(sampler, "storage_faults", None)
    try:
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or faults is None:
            raise ValueError("pr318-storage-admin-unselected")
        result = faults.request(message[1:].decode("ascii"))
    except (OSError, ValueError, UnicodeError):
        result = {"error": "pr318-storage-admin-failed"}
    channel.sendall(json.dumps(result, sort_keys=True).encode())
    return True


def cleanup_sampler(sampler, diagnostics):
    faults = getattr(sampler, "storage_faults", None)
    if faults is not None:
        try:
            diagnostics["storageFaultReceipts"] = faults.cleanup()
            with faults.workload.locked():
                campaign, _role, _record = faults.workload.retained(faults.sender_handle)
                diagnostics["storageSelectionDigest"] = campaign["budgetSelectionDigest"]
            diagnostics["storageAccessCleanup"] = "completed"
        except (OSError, ValueError):
            # The driver's normal role/cgroup cleanup must run even if access cannot
            # be restored. Its final success gate separately rejects this status.
            diagnostics["storageAccessCleanup"] = "restoration-required"


def run_observer(adapter, channel, campaign_deadline, diagnostic):
    from cross_version_installed_storage_budgets import run_storage_lane

    def administrator(command):
        if command not in COMMANDS or channel is None:
            raise ValueError("pr318-storage-command-invalid")
        remaining = min(5, campaign_deadline / 1e9 - time.monotonic())
        if remaining <= 0:
            raise ValueError("pr318-storage-command-expired")
        channel.settimeout(remaining)
        channel.sendall(b"K" + command.encode("ascii"))
        raw, _ancillary, flags, _address = channel.recvmsg(8193)
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(raw) > 8192:
            raise ValueError("pr318-storage-receipt-invalid")
        result = json.loads(raw)
        if not isinstance(result, dict) or "error" in result:
            raise ValueError("pr318-storage-admin-failed")
        return result

    return run_storage_lane(adapter, administrator,
        leave_running_for_administrator=True, on_start_failure=diagnostic)


def controller_bootstrap_failure_snapshot(workload):
    """Copy only a closed root-private bootstrap phase before service teardown."""
    path = Path('/run/cryptad-workload/bootstrap-failure.private.json')
    try:
        value = workload.read(path)
    except FileNotFoundError:
        return {'status': 'not-observed'}
    except (OSError, ValueError):
        return {'status': 'unavailable-or-unsafe'}
    stages = {'authority', 'installed-app', 'launch-redirect',
              'origin-parse', 'app-runtime', 'session-bootstrap', 'recheck'}
    try:
        if (not isinstance(value, dict) or set(value) != {
                'schemaVersion', 'kind', 'stage', 'role', 'exceptionType',
                'errorCode', 'controllerPid', 'bootId',
                'startedMonotonicNs', 'observedMonotonicNs'}
                or value['schemaVersion'] != 1
                or value['kind'] != 'pr315-controller-bootstrap-failure-phase'
                or value['stage'] not in stages
                or value['role'] not in ('candidate-sender', 'candidate-recipient', 'previous', 'relay-no-apps', 'unknown')
                or re.fullmatch(r'[A-Za-z][A-Za-z0-9]{0,127}',
                    value['exceptionType']) is None
                or re.fullmatch(r'[a-z][a-z0-9-]{1,100}',
                    value['errorCode']) is None
                or value['bootId'] != workload.boot()
                or type(value['controllerPid']) is not int
                or value['controllerPid'] <= 1
                or type(value['startedMonotonicNs']) is not int
                or type(value['observedMonotonicNs']) is not int
                or not 0 < value['startedMonotonicNs'] <
                    value['observedMonotonicNs'] <= time.monotonic_ns()):
            raise ValueError('workload-bootstrap-diagnostic-invalid')
        return {'status': 'captured', 'record': value,
                'classification': 'private-bootstrap-diagnostic-not-acceptance'}
    except (KeyError, TypeError, ValueError):
        return {'status': 'unavailable-or-unsafe'}

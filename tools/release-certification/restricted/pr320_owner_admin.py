"""Kit-only delivery to the exact signed process owner; no token crosses this boundary."""
from __future__ import annotations
import array
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import select
import struct
import time

import pr320_cancellation_contract as contract
from pr320_budget_contract import PROCESS_SOCKET_NAME
from pr318_storage_admin import _fixed_mount

ROLE, APP = 'candidate-sender', 'feed-reader'


def _original_state(workload):
    """Read the fixed role directly while its daemon and private store still exist."""
    from restricted_workload_controller import _prospective_budget_native
    from pr319_restart_admin import _store_capture
    status, _headers, raw = _prospective_budget_native()
    if status != 200 or not 1 <= len(raw) <= 4 * 1024 * 1024:
        raise ValueError('pr320-owner-native-original-unavailable')
    native = json.loads(raw)
    if not isinstance(native, dict) or not isinstance(native.get('work'), dict) or not isinstance(native.get('budget'), dict):
        raise ValueError('pr320-owner-native-original-invalid')
    store = _store_capture(workload, workload.account(ROLE).pw_uid)
    for row in store['durableUsage']:
        row.pop('limit')
    for row in store['graphFacts']:
        row.pop('document')
    return {'native': native, 'store': store}


class OwnerStimulus:
    def __init__(self, workload, sender_handle):
        self.workload, self.handle, self.receipts = workload, sender_handle, []
        self.started = False
        self.worker_pidfd = None
        self.native_before = None

    def start(self, uri):
        if (self.started or not isinstance(uri, str) or not 1 <= len(uri) <= 4096
                or not uri.startswith(('SSK@', 'USK@')) or any(ord(c) < 32 for c in uri)):
            raise ValueError('pr320-owner-stimulus-invalid')
        workload = self.workload
        from restricted_workload_controller import _http, runtime_object
        from restricted_workload_network import _connect_port, HTTP_PORT
        from restricted_workload_app import require_budget_listener
        with workload.locked():
            campaign, role, record = workload.retained(self.handle)
            if os.geteuid() != 0 or role != ROLE or campaign.get('executionClass') != contract.EXECUTION_CLASS:
                raise ValueError('pr320-owner-role-invalid')
            workload.admit(campaign)
            workload.exact(role, record, workload.manager(role, 'show'))
            uid = workload.account(role).pw_uid
            status, _headers, body = _http(_connect_port(role, HTTP_PORT),
                '/api/v1/apps/' + APP + '/runtime', {'Accept': 'application/json'})
            if status != 200:
                raise ValueError('pr320-owner-app-unavailable')
            binding = require_budget_listener(role, APP, runtime_object(body), HTTP_PORT)
            state = workload.ROOT / 'state' / role
            _fixed_mount(state)
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            directory = os.open(state, flags)
            try:
                device = os.fstat(directory).st_dev
                for name in ('run', 'apps', APP):
                    child = os.open(name, flags, dir_fd=directory)
                    info = os.fstat(child)
                    if info.st_uid != uid or info.st_dev != device or info.st_mode & 0o022:
                        os.close(child)
                        raise ValueError('pr320-owner-socket-directory-invalid')
                    os.close(directory)
                    directory = child
                before = os.stat(PROCESS_SOCKET_NAME, dir_fd=directory, follow_symlinks=False)
                if not stat.S_ISSOCK(before.st_mode) or before.st_uid != uid or stat.S_IMODE(before.st_mode) != 0o600:
                    raise ValueError('pr320-owner-socket-invalid')
                with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as channel:
                    channel.settimeout(5)
                    channel.connect('/proc/self/fd/' + str(directory) + '/' + PROCESS_SOCKET_NAME)
                    peer_pid, peer_uid, _peer_gid = struct.unpack('3i', channel.getsockopt(
                        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
                    if peer_uid != uid or peer_pid != binding['worker']['fixtureProcess']['hostPid']:
                        raise ValueError('pr320-owner-socket-peer-invalid')
                    self.worker_pidfd = os.pidfd_open(peer_pid)
                    if select.select([self.worker_pidfd], [], [], 0)[0]:
                        raise ValueError('pr320-owner-worker-exited')
                    after = os.stat(PROCESS_SOCKET_NAME, dir_fd=directory, follow_symlinks=False)
                    if (before.st_dev, before.st_ino, before.st_uid, before.st_mode) != (
                            after.st_dev, after.st_ino, after.st_uid, after.st_mode):
                        raise ValueError('pr320-owner-socket-changed')
                    deadline = min(campaign['deadlineMonotonicNs'], time.monotonic_ns() + 45_000_000_000)
                    task = {'schemaVersion': 1, 'uri': uri, 'deadlineMonotonicNs': deadline}
                    with _connect_port(role, HTTP_PORT) as connected:
                        self.native_before = _original_state(workload)
                        self.started = True
                        receipt = {'schemaVersion': 1, 'kind': 'pr320-original-process-owner',
                            'selectionDigest': campaign['budgetSelectionDigest'], 'appId': APP,
                            'generation': record['generation'], 'managerInvocation': record['managerInvocation'],
                            'bootId': record['bootId'], 'handle': self.handle,
                            'daemon': binding['daemon'], 'worker': binding['worker'],
                            'taskDigest': contract.canonical_digest(task), 'status': 'task-intent',
                            'observedMonotonicNs': time.monotonic_ns()}
                        self.receipts.append(receipt)
                        # Retain original intent before sending; observer failure cannot erase it.
                        workload.write(workload.ROOT / 'authority/pr320-owner-stimulus.json',
                                       {'receipts': list(self.receipts)}, create=True)
                        channel.sendmsg([json.dumps(task, sort_keys=True).encode()], [(
                            socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [connected.fileno()]))])
                    raw, _ancillary, message_flags, _address = channel.recvmsg(1025)
                    if message_flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or raw != b'{"state":"request-written"}':
                        raise ValueError('pr320-owner-write-unobserved')
                    # Worker identity is checked after task admission; never inspect its environment.
                    if require_budget_listener(role, APP, runtime_object(body), HTTP_PORT) != binding:
                        raise ValueError('pr320-owner-worker-changed')
                    written = {**receipt, 'status': 'request-written', 'observedMonotonicNs': time.monotonic_ns()}
                    self.receipts.append(written)
                    workload.write(workload.ROOT / 'authority/pr320-owner-stimulus.json',
                                   {'receipts': list(self.receipts)})
                    return written
            finally:
                os.close(directory)

    def stopped(self):
        if (self.worker_pidfd is None or not self.receipts
                or self.receipts[-1]['status'] != 'request-written'
                or not select.select([self.worker_pidfd], [], [], 0)[0]):
            raise ValueError('pr320-owner-process-death-unobserved')
        value = {**self.receipts[-1], 'status': 'worker-death-observed',
                 'observedMonotonicNs': time.monotonic_ns()}
        self.receipts.append(value)
        self.workload.write(self.workload.ROOT / 'authority/pr320-owner-stimulus.json',
                            {'receipts': list(self.receipts)})
        return value


def configure_sampler(sampler, execution_class, handoff):
    if execution_class == contract.EXECUTION_CLASS:
        sampler.owner_stimulus = OwnerStimulus(sampler.workload, handoff['handles'][ROLE])


def serve_owner(sampler, channel, message, flags):
    try:
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or not hasattr(sampler, 'owner_stimulus'):
            raise ValueError('pr320-owner-unselected')
        command = json.loads(message[1:])
        if not isinstance(command, dict):
            raise ValueError('pr320-owner-command-invalid')
        if set(command) == {'action', 'uri'} and command['action'] == 'start':
            value = sampler.owner_stimulus.start(command['uri'])
        elif command == {'action': 'stopped'}:
            value = sampler.owner_stimulus.stopped()
        else:
            raise ValueError('pr320-owner-command-invalid')
    except (OSError, ValueError, KeyError, TypeError):
        value = {'error': 'pr320-owner-administrator-failed'}
    channel.sendall(json.dumps(value, sort_keys=True).encode())
    return True


def cleanup_sampler(sampler, diagnostics):
    stimulus = getattr(sampler, 'owner_stimulus', None)
    if stimulus is None:
        return
    workload = stimulus.workload
    try:
        with workload.locked():
            campaign, _role, record = workload.retained(stimulus.handle)
            if stimulus.started:
                saved = workload.read(workload.ROOT / 'authority/pr320-owner-stimulus.json')
                if saved != {'receipts': list(stimulus.receipts)}:
                    raise ValueError('pr320-owner-original-substituted')
            diagnostics['ownerSelectionDigest'] = campaign['budgetSelectionDigest']
            diagnostics['ownerBootstrapContext'] = workload.read(workload.ROOT / 'authority' / (
                ROLE + '-budget-bootstrap-' + record['generation'] + '.json'))
            original = {'schemaVersion': 1, 'kind': 'pr320-original-owner-native',
                'selectionDigest': campaign['budgetSelectionDigest'],
                'before': stimulus.native_before, 'after': _original_state(workload)}
            raw = json.dumps(original, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
            if not 1 <= len(raw) <= 4 * 1024 * 1024:
                raise ValueError('pr320-owner-native-original-size-invalid')
            descriptor = os.open(workload.ROOT / 'authority/pr320-owner-original-native.json',
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'wb') as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            diagnostics['ownerNativeOriginalDigest'] = 'sha256:' + hashlib.sha256(raw).hexdigest()
        diagnostics['ownerOriginalCollection'] = 'complete'
    except (OSError, ValueError, KeyError, TypeError):
        diagnostics['ownerOriginalCollection'] = 'incomplete'
    finally:
        diagnostics['ownerStimulusReceipts'] = list(stimulus.receipts)
        if stimulus.worker_pidfd is not None:
            os.close(stimulus.worker_pidfd)
            stimulus.worker_pidfd = None


def run_observer(adapter, channel, campaign_deadline, diagnostic):
    from cross_version_installed_owner_budgets import run_owner_lane
    def administrator(action, uri=None):
        remaining = min(8, campaign_deadline / 1e9 - time.monotonic())
        if channel is None or remaining <= 0:
            raise ValueError('pr320-owner-administrator-unavailable')
        channel.settimeout(remaining)
        command = {'action': action, 'uri': uri} if action == 'start' else {'action': action}
        if command != {'action': 'stopped'} and (action != 'start' or not isinstance(uri, str)):
            raise ValueError('pr320-owner-command-invalid')
        channel.sendall(b'O' + json.dumps(command).encode())
        raw, _ancillary, flags, _address = channel.recvmsg(8193)
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(raw) > 8192:
            raise ValueError('pr320-owner-receipt-invalid')
        value = json.loads(raw)
        if not isinstance(value, dict) or 'error' in value:
            raise ValueError('pr320-owner-administrator-failed')
        return value
    return run_owner_lane(adapter, administrator, leave_running_for_administrator=True,
                          on_start_failure=diagnostic)

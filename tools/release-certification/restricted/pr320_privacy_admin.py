"""Fixed root-owned private readback and browser collection; no observer-selected target."""
from __future__ import annotations
import datetime as dt
import copy
import urllib.parse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import time

import pr319_restart_admin as historical
import pr320_privacy_contract as contract

ROLE = 'candidate-sender'
COMMANDS = ('privacy:snapshot', 'privacy:browser', 'privacy:expired-session',
            'privacy:stale-worker-before', 'privacy:stale-worker-after')
NAMESPACE, KEY = 'pr320-privacy', 'pr320-private-app-data-key'
MAX_LOG_BYTES = 2 * 1024 * 1024
ORIGINALS_FILE = 'pr320-privacy-originals.private.json'
MAX_ORIGINAL_BYTES = 8 * 1024 * 1024
MAX_REPLY_BYTES = 2 * 1024 * 1024
REPLY_CHUNK_BYTES = 16 * 1024
REPLY_MAGIC = b'PR320-privacy-reply-v1\0'
REPLY_SECONDS = 65


def _write_root(workload, filename, value):
    _need(filename in {ORIGINALS_FILE, 'pr320-privacy-browser-failure.json',
                       'pr320-privacy-browser-original.json'})
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    _need(0 < len(raw) <= MAX_ORIGINAL_BYTES and os.geteuid() == 0)
    directory = os.open(workload.ROOT / 'authority', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory)
        _need(info.st_uid == 0 and not info.st_mode & 0o077)
        fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(directory)
    finally:
        os.close(directory)
    return {'privacyOriginalsFile': filename, 'privacyOriginalsBytes': len(raw),
            'privacyOriginalsDigest': 'sha256:' + hashlib.sha256(raw).hexdigest()}


def _need(condition):
    if not condition:
        raise ValueError('pr320-privacy-admin-invalid')


def _read_log(directory, name, uid, maximum):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        before = os.fstat(fd)
        _need(stat.S_ISREG(before.st_mode) and before.st_uid == uid and before.st_nlink == 1
              and not before.st_mode & 0o022 and 0 <= before.st_size <= maximum)
        raw = os.read(fd, maximum + 1)
        after = os.fstat(fd)
        selected = os.stat(name, dir_fd=directory, follow_symlinks=False)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        _need(len(raw) == before.st_size and len(raw) <= maximum
              and all(getattr(before, key) == getattr(info, key) for info in (after, selected) for key in fields))
        return raw.decode('utf-8')
    finally:
        os.close(fd)


def _logs(workload, uid, generation):
    _need(isinstance(generation, str) and re.fullmatch('[0-9a-f]{32}', generation) is not None)
    state = workload.ROOT / 'state' / ROLE
    historical._fixed_mount(state)
    parent = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(parent)
        _need(info.st_uid == uid and not info.st_mode & 0o022)
        directory = os.open('logs', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            _need(os.fstat(directory).st_uid == uid and os.fstat(directory).st_dev == info.st_dev)
            names = historical._names(directory, 32)
            capture_name = 'stdio-' + generation
            _need(capture_name in names)
            result, total = {}, 0
            for name in names:
                if name == capture_name:
                    selected = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                    try:
                        info = os.fstat(selected)
                        _need(info.st_uid == uid and not info.st_mode & 0o077)
                        members = historical._names(selected, 3)
                        _need({'stdout.private.log', 'stderr.private.log'} <= set(members)
                              and set(members) <= {'stdout.private.log', 'stderr.private.log', 'stdio.private.json'})
                        for member in members:
                            _need(member not in result)
                            raw = _read_log(selected, member, uid, MAX_LOG_BYTES)
                            total += len(raw.encode())
                            _need(total <= MAX_LOG_BYTES)
                            result[member] = raw
                    finally:
                        os.close(selected)
                    continue
                _need(re.fullmatch('[A-Za-z0-9._-]{1,128}', name) is not None)
                _need(name not in result)
                raw = _read_log(directory, name, uid, MAX_LOG_BYTES)
                total += len(raw.encode())
                _need(total <= MAX_LOG_BYTES)
                result[name] = raw
            return result
        finally:
            os.close(directory)
    finally:
        os.close(parent)


def _app_data(workload, uid):
    key_hash = hashlib.sha256(KEY.encode()).hexdigest()
    prefix = ('durable-app-data', 'feed-reader', '.cryptad-app-data',
              'namespaces', NAMESPACE, 'records', key_hash)
    directory = historical._open_target(workload.ROOT / 'state' / ROLE, prefix, uid)
    try:
        raw = historical._private_read(directory, 'current.properties', uid, 8192)
        pointer = historical._properties(raw)
        _need(set(pointer) == {'version', 'appId', 'namespace', 'key', 'generation'}
              and pointer['version'] == '1' and pointer['appId'] == 'feed-reader'
              and pointer['namespace'] == NAMESPACE and pointer['key'] == KEY
              and re.fullmatch('g-[0-9a-f]{40}', pointer['generation']) is not None)
        generations = os.open('generations', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            selected = os.open(pointer['generation'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                               dir_fd=generations)
            try:
                info = os.fstat(selected)
                _need(info.st_uid == uid and info.st_dev == os.fstat(directory).st_dev)
                metadata = historical._properties(historical._private_read(selected, 'record.properties', uid, 8192))
                value = historical._private_read(selected, 'value.bin', uid, 16384)
                _need(metadata.get('appId') == 'feed-reader' and metadata.get('namespace') == NAMESPACE
                      and metadata.get('key') == KEY and metadata.get('sha256') == hashlib.sha256(value).hexdigest()
                      and metadata.get('valueBytes') == str(len(value)))
            finally:
                os.close(selected)
        finally:
            os.close(generations)
        _need(raw == historical._private_read(directory, 'current.properties', uid, 8192))
        return {'metadata': metadata, 'valueBase64': base64.b64encode(value).decode()}
    finally:
        os.close(directory)


class FixedPrivacyCollector:
    def __init__(self, workload, handle):
        self.workload, self.handle, self.receipts = workload, handle, []
        self.boundary_evidence = {}

    def _role(self, cleanup=False):
        campaign, role, record = self.workload.retained(self.handle)
        _need(os.geteuid() == 0 and role == ROLE
              and campaign.get('executionClass') == contract.EXECUTION_CLASS
              and campaign.get('budgetSelectionDigest') is not None)
        if not cleanup:
            self.workload.admit(campaign)
            self.workload.exact(role, record, self.workload.manager(role, 'show'))
        return campaign, record, self.workload.account(role)

    def _boundary_context(self, record, supplied, app_id):
        _need(isinstance(supplied, dict) and set(supplied) == {'appOrigin', 'appSession', 'sessionExpiresAt'})
        original = self.workload.read(self.workload.ROOT / 'authority' /
            ('candidate-sender-budget-bootstrap-' + record['generation'] + '.json'))
        expected = original['apps'][app_id]
        _need(all(contract.canonical_digest(supplied[key]) == expected[target] for key, target in
            (('appOrigin', 'originDigest'), ('appSession', 'sessionDigest'),
             ('sessionExpiresAt', 'sessionExpiryDigest'))))
        return expected

    def _worker(self, app_id, context):
        from restricted_workload_controller import _http, runtime_object
        from restricted_workload_network import connect
        from restricted_workload_app import require_budget_listener
        port = urllib.parse.urlsplit(context['appOrigin']).port
        code, _headers, raw = _http(connect(ROLE, 'http'), '/api/v1/apps/' + app_id + '/runtime',
                                     {'Accept': 'application/json'})
        _need(code == 200)
        runtime = runtime_object(raw)
        return require_budget_listener(ROLE, app_id, runtime, port), runtime

    def _denial(self, context):
        # Independently observe the response and unchanged native counters in the selected role.
        from restricted_workload_controller import _http, _prospective_budget_native
        from restricted_workload_network import connect
        from pr320_privacy_runtime_evidence import _same_native
        def snapshot():
            code, _headers, raw = _prospective_budget_native()
            _need(code == 200)
            return json.loads(raw)
        before = snapshot()
        code, _headers, raw = _http(connect(ROLE, 'http'), '/api/v1/operator/support-bundle',
            {'Accept':'application/json','Origin':context['appOrigin'],
             'X-Crypta-App-Session':context['appSession']})
        body = json.loads(raw)
        after = snapshot()
        _need(code in {401,403} and isinstance(body,dict) and body and _same_native(before,after))
        return {'status':code,'body':body,'beforeNative':before,'afterNative':after}

    def _boundary(self, command, record, supplied):
        app_id = 'feed-reader' if command == 'privacy:expired-session' else 'budget-importer'
        context = self._boundary_context(record, supplied, app_id)
        now = time.time_ns()
        if command != 'privacy:stale-worker-after':
            binding, _runtime = self._worker(app_id, supplied)
            _need(contract.canonical_digest(binding['worker']) == context['workerEpochDigest']
                  and contract.canonical_digest(binding['daemon']) == context['daemonEpochDigest'])
            result = {'kind': command, 'appId': app_id, 'context': context, 'binding': binding,
                      'observedEpochNs': now, 'observedMonotonicNs': time.monotonic_ns()}
            if command == 'privacy:expired-session':
                expires = dt.datetime.fromisoformat(supplied['sessionExpiresAt'].replace('Z', '+00:00'))
                _need(expires.tzinfo is not None and now >= int(expires.timestamp() * 10**9))
                result['expiresAt'] = supplied['sessionExpiresAt']
                result['denial'] = self._denial(supplied)
                current_binding, _runtime = self._worker(app_id,supplied)
                _need(current_binding == binding)
                result['observedEpochNs'] = time.time_ns()
                result['observedMonotonicNs'] = time.monotonic_ns()
                self.boundary_evidence['expiredSession'] = result
            else:
                expires = dt.datetime.fromisoformat(supplied['sessionExpiresAt'].replace('Z', '+00:00'))
                _need(expires.tzinfo is not None and now < int(expires.timestamp() * 10**9))
                result['expiresAt'] = supplied['sessionExpiresAt']
                self.boundary_evidence['staleWorkerBefore'] = result
            return result
        before = self.boundary_evidence['staleWorkerBefore']
        from restricted_workload_controller import _http, runtime_object
        from restricted_workload_network import connect
        code, _headers, raw = _http(connect(ROLE, 'http'), '/api/v1/apps/budget-importer/runtime',
                                   {'Accept': 'application/json'})
        runtime = runtime_object(raw)
        _need(code == 200 and runtime.get('running') is False and runtime.get('pid') is None
              and now < int(dt.datetime.fromisoformat(before['expiresAt'].replace('Z', '+00:00')).timestamp() * 10**9))
        dead = []
        for key in ('appHostLeader', 'fixtureProcess'):
            process = before['binding']['worker'][key]
            try:
                raw_stat = (Path('/proc') / str(process['hostPid']) / 'stat').read_text()
                current_ticks = int(raw_stat.rsplit(')', 1)[1].split()[19])
                _need(current_ticks != process['startTicks'])
            except (FileNotFoundError, ProcessLookupError):
                pass
            dead.append(dict(process, dead=True))
        denial = self._denial(supplied)
        now = time.time_ns()
        _need(now < int(dt.datetime.fromisoformat(before['expiresAt'].replace('Z', '+00:00')).timestamp() * 10**9))
        result = {'kind': command, 'appId': app_id, 'context': context, 'runtime': runtime, 'denial':denial,
                  'terminatedWorkers': dead, 'observedEpochNs': now,
                  'observedMonotonicNs': time.monotonic_ns()}
        self.boundary_evidence['staleWorkerAfter'] = result
        return result

    def request(self, command, browser_context=None):
        _need(command in COMMANDS)
        with self.workload.locked():
            campaign, record, user = self._role()
            if command in {'privacy:expired-session', 'privacy:stale-worker-before', 'privacy:stale-worker-after'}:
                return self._boundary(command, record, browser_context)
            if command == 'privacy:browser':
                from pr320_privacy_browser_admin import collect_browser
                receipt = collect_browser(self.workload, campaign, record, user, browser_context)
            else:
                data = historical._data(self.workload, user.pw_uid)
                daemon, pidfd = historical._daemon(self.workload, record)
                os.close(pidfd)
                receipt = {'schemaVersion': 1, 'kind': 'pr320-original-privacy-readback',
                    'role': ROLE, 'generation': record['generation'],
                    'managerInvocation': record['managerInvocation'], 'bootId': record['bootId'],
                    'selectionDigest': campaign['budgetSelectionDigest'], 'daemon': daemon,
                    'dataIdentity': data, **historical._store_capture(self.workload, user.pw_uid),
                    'appData': _app_data(self.workload, user.pw_uid),
                    'logs': _logs(self.workload, user.pw_uid, record['managerInvocation']),
                    'observedMonotonicNs': time.monotonic_ns(),
                    'boundaryEvidence': copy.deepcopy(self.boundary_evidence)}
                _need(historical._data(self.workload, user.pw_uid) == data)
            self.receipts.append(receipt)
            return receipt


def configure_sampler(sampler, execution_class, handoff):
    if execution_class == contract.EXECUTION_CLASS:
        sampler.privacy_collector = FixedPrivacyCollector(sampler.workload, handoff['handles'][ROLE])


def _send_reply(channel, raw, deadline):
    """Retain complete JSON bytes within bounded seqpacket messages and one deadline."""
    _need(isinstance(raw, bytes) and 0 < len(raw) <= MAX_REPLY_BYTES)
    header = REPLY_MAGIC + len(raw).to_bytes(4, 'big') + hashlib.sha256(raw).digest()
    previous_timeout = channel.gettimeout()
    if previous_timeout is not None:
        _need(previous_timeout > 0)
        deadline = min(deadline, time.monotonic() + previous_timeout)

    def send(packet):
        remaining = deadline - time.monotonic()
        _need(remaining > 0)
        channel.settimeout(remaining)
        channel.sendall(packet)

    try:
        send(header)
        for index, offset in enumerate(range(0, len(raw), REPLY_CHUNK_BYTES)):
            send(index.to_bytes(4, 'big') + raw[offset:offset + REPLY_CHUNK_BYTES])
    finally:
        channel.settimeout(previous_timeout)


def _receive_reply(channel, deadline):
    """Reject incomplete, reordered, substituted or oversized replies before decoding."""
    def packet(maximum):
        remaining = deadline - time.monotonic()
        _need(remaining > 0)
        channel.settimeout(remaining)
        raw, ancillary, flags, _address = channel.recvmsg(maximum + 1)
        _need(raw and not ancillary and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
              and len(raw) <= maximum)
        return raw

    header = packet(len(REPLY_MAGIC) + 36)
    _need(len(header) == len(REPLY_MAGIC) + 36 and header.startswith(REPLY_MAGIC))
    size = int.from_bytes(header[len(REPLY_MAGIC):len(REPLY_MAGIC) + 4], 'big')
    _need(0 < size <= MAX_REPLY_BYTES)
    original = bytearray()
    for index in range((size + REPLY_CHUNK_BYTES - 1) // REPLY_CHUNK_BYTES):
        expected = min(REPLY_CHUNK_BYTES, size - len(original))
        chunk = packet(REPLY_CHUNK_BYTES + 4)
        _need(len(chunk) == expected + 4 and int.from_bytes(chunk[:4], 'big') == index)
        original.extend(chunk[4:])
    _need(hashlib.sha256(original).digest() == header[-32:])
    return bytes(original)


def serve_privacy(sampler, channel, message, flags):
    deadline = time.monotonic() + REPLY_SECONDS
    collector = getattr(sampler, 'privacy_collector', None)
    try:
        _need(collector is not None and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
              and message[:1] == b'Q' and len(message) <= 8192)
        request = json.loads(message[1:])
        _need(isinstance(request, dict) and set(request) in ({'command'}, {'command', 'browserContext'}))
        result = collector.request(request['command'], request.get('browserContext'))
    except (OSError, ValueError, KeyError, TypeError, UnicodeError):
        result = {'error': 'pr320-privacy-collector-failed'}
    raw = json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    if len(raw) > MAX_REPLY_BYTES:
        raw = b'{"error":"pr320-privacy-collector-budget"}'
    _send_reply(channel, raw, deadline)
    return True


def cleanup_sampler(sampler, diagnostics):
    collector = getattr(sampler, 'privacy_collector', None)
    if collector is None:
        return
    try:
        with collector.workload.locked():
            campaign, record, _user = collector._role(cleanup=True)
            collector.bootstrap = collector.workload.read(
                collector.workload.ROOT / 'authority' / ('candidate-sender-budget-bootstrap-' + record['generation'] + '.json'))
            diagnostics['privacyCollectorCleanup'] = 'completed'
    except (OSError, ValueError, KeyError, TypeError):
        diagnostics['privacyCollectorCleanup'] = 'original-capture-incomplete'


def cleanup_final(sampler, diagnostics):
    """Capture pipe EOF receipts after role termination while the owned tmpfs remains mounted."""
    collector = getattr(sampler, 'privacy_collector', None)
    if collector is None:
        return
    try:
        with collector.workload.locked():
            _campaign, _record, user = collector._role(cleanup=True)
            logs = _logs(collector.workload, user.pw_uid, _record['managerInvocation'])
            failure = None
            failure_file = collector.workload.ROOT / 'authority/pr320-privacy-browser-failure.json'
            if failure_file.exists():
                from pr320_privacy_browser_admin import _private_file
                from cryptad_certification.io import read_json_bytes
                failure = read_json_bytes(_private_file(failure_file, MAX_ORIGINAL_BYTES, owner=0), 'browser-failure')
            original = {'schemaVersion': 1, 'kind': 'pr320-private-privacy-originals',
                'selectionDigest': _campaign['budgetSelectionDigest'],
                'bootstrapContext': getattr(collector, 'bootstrap', None), 'receipts': collector.receipts,
                'finalLogs': logs, 'cleanupStatus': diagnostics.get('privacyCollectorCleanup', 'original-capture-incomplete'),
                'browserFailure': failure}
            diagnostics.update(_write_root(collector.workload, ORIGINALS_FILE, original))
    except (OSError, ValueError, KeyError, TypeError):
        diagnostics['privacyCollectorCleanup'] = 'original-capture-incomplete'


def run_observer(adapter, channel, deadline, diagnostic):
    from cross_version_installed_privacy_budgets import run_privacy_lane

    class Administrator:
        browser_context = None
        boundary_context = None

        def __call__(self, command):
            _need(channel is not None and command in COMMANDS)
            reply_deadline = min(time.monotonic() + REPLY_SECONDS, deadline / 1e9)
            remaining = reply_deadline - time.monotonic()
            _need(remaining > 0)
            channel.settimeout(remaining)
            request = {'command': command}
            if command == 'privacy:browser':
                request['browserContext'] = self.browser_context
            elif command != 'privacy:snapshot':
                request['browserContext'] = self.boundary_context
            channel.sendall(b'Q' + json.dumps(request, separators=(',', ':')).encode())
            raw = _receive_reply(channel, reply_deadline)
            value = json.loads(raw)
            _need(isinstance(value, dict) and 'error' not in value)
            return value

    return run_privacy_lane(adapter, Administrator(), leave_running_for_administrator=True,
                            on_start_failure=diagnostic)

#!/usr/bin/python3
"""Tokenless fixed role controller. This service has no original-provider credentials.

Only the observer UID can use the private socket. Each request names an already retained
role handle and one fixed method. Service death stops bound role units through systemd.
"""
import array
from contextlib import contextmanager
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import time
import urllib.parse

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
import restricted_workload as workload

SOCKET = Path('/run/cryptad-workload/control.sock')
STARTUP = Path('/run/cryptad-workload/startup.json')
REQUEST_PROGRESS = Path('/run/cryptad-workload/request-progress.private.json')
BOOTSTRAP_FAILURE = Path('/run/cryptad-workload/bootstrap-failure.private.json')
BOOTSTRAP_STAGES = frozenset({'authority', 'installed-app',
    'launch-redirect', 'origin-parse', 'app-runtime',
    'session-bootstrap', 'recheck'})
STARTUP_STAGES = frozenset({'entry', 'installation-verified', 'reconciled', 'listening'})
METHODS = frozenset({'start', 'observe', 'stop', 'connect-fcp',
                     'connect-http', 'bootstrap-mail'})
REQUEST_PHASES = frozenset({'executing', 'replied', 'failed'})
EXCHANGE_CASES = {'connect-fcp': 'own-management', 'bootstrap-mail': 'dynamic-app-bootstrap'}
OBSERVER_CONTROL_REQUEST = re.compile(rb'\{"method":"pr315-observer-control","handle":"([0-9a-f]{64})"\}\n')
OBSERVER_ENDPOINT_REQUEST = re.compile(rb'\{"method":"pr315-arbitrary-endpoint","handle":"([0-9a-f]{64})"\}\n')
DENIED_RESPONSE = b'{"error":"restricted-workload-request-failed"}\n'


@contextmanager
def deadline(seconds=15):
    def expired(_signum, _frame):
        workload.reject('request-deadline')
    previous = signal.signal(signal.SIGALRM, expired)
    started = time.monotonic()
    outer = signal.getitimer(signal.ITIMER_REAL)
    signal.setitimer(signal.ITIMER_REAL, min(seconds, outer[0]) if outer[0] else seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, max(.001, outer[0] - (time.monotonic() - started)) if outer[0] else 0,
                         outer[1])
        signal.signal(signal.SIGALRM, previous)


def request(raw):
    def pairs(rows):
        value = {}
        for name, entry in rows:
            if name in value:
                workload.reject('duplicate-request-field')
            value[name] = entry
        return value
    if not 1 <= len(raw) <= 256:
        workload.reject('request-limit')
    value = json.loads(raw, object_pairs_hook=pairs)
    if (not isinstance(value, dict) or set(value) != {'method', 'handle'}
            or not isinstance(value['method'], str) or value['method'] not in METHODS
            or not isinstance(value['handle'], str)
            or re.fullmatch('[a-f0-9]{64}', value['handle']) is None):
        workload.reject('request-invalid')
    return value


def _audit_exchange(method, handle, request_raw, response_raw, started, finished):
    """Retain only root-observed digests for two fixed successful controller exchanges."""
    case_id = EXCHANGE_CASES.get(method)
    if case_id is None:
        return
    try:
        with workload.locked():
            _campaign, role, record = workload.retained(handle)
            if role != 'candidate-sender':
                return
            workload.exact(role, record, workload.manager(role, 'show'))
            value = {'schemaVersion': 1, 'kind': 'pr315-fixed-exchange-audit',
                'caseId': case_id, 'method': method, 'role': role,
                'managerInvocation': record['managerInvocation'], 'bootId': record['bootId'],
                'cgroupIdentity': record['cgroupIdentity'],
                'requestDigest': hashlib.sha256(request_raw).hexdigest(),
                'responseDigest': hashlib.sha256(response_raw).hexdigest(),
                'startedMonotonicNs': started, 'finishedMonotonicNs': finished,
                'serverRequests': 1}
            workload.write(workload.ROOT / 'authority' / (case_id + '-exchange.json'), value)
    except (OSError, ValueError, KeyError, TypeError):
        # Audit absence cannot turn a successful existing connection into an error.
        # The host verifier will leave the case inconclusive without this root record.
        pass


def _own_start_ticks():
    return int(Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19])


def _request_progress(method, phase, started, error=None):
    """Keep one root-only latest RPC phase without exposing a handle or granting credit."""
    if (os.geteuid() != 0 or method not in METHODS or phase not in REQUEST_PHASES
            or type(started) is not int or started <= 0):
        return
    try:
        value = {'schemaVersion': 1,
            'kind': 'pr315-controller-request-progress',
            'classification': 'private-runtime-diagnostic-not-acceptance',
            'pid': os.getpid(), 'processStartTicks': _own_start_ticks(),
            'bootId': workload.boot(),
            'method': method, 'phase': phase,
            'startedMonotonicNs': started,
            'observedMonotonicNs': time.monotonic_ns()}
        if error is not None:
            value['exceptionType'] = type(error).__name__[:64]
        workload.write(REQUEST_PROGRESS, value, mode=0o600)
    except Exception:
        # This diagnostic cannot change a controller response or its deadline.
        pass


def _controller_process():
    """Identify this serving process against its fixed active systemd unit."""
    unit = 'cryptad-workload-controller.service'
    selected = subprocess.run(['/usr/bin/systemctl', 'show', unit,
        '--property=InvocationID,ActiveState,SubState,MainPID,ControlGroup', '--no-pager'],
        stdin=subprocess.DEVNULL, capture_output=True, env=workload.ENV, timeout=5, check=True)
    if len(selected.stdout) > 8192 or selected.stderr:
        workload.reject('controller-target-unavailable')
    state = dict(line.split('=', 1) for line in selected.stdout.decode().splitlines() if '=' in line)
    path = '/system.slice/' + unit
    if (set(state) != {'InvocationID', 'ActiveState', 'SubState', 'MainPID', 'ControlGroup'}
            or re.fullmatch('[0-9a-f]{32}', state['InvocationID']) is None
            or state['ActiveState'] != 'active' or state['SubState'] != 'running'
            or state['MainPID'] != str(os.getpid()) or state['ControlGroup'] != path
            or Path('/proc/self/cgroup').read_text().strip() != '0::' + path):
        workload.reject('controller-target-changed')
    info = (Path('/sys/fs/cgroup') / path.removeprefix('/')).stat()
    return {'invocationId': state['InvocationID'],
            'cgroupIdentity': [info.st_dev, info.st_ino], 'bootId': workload.boot(),
            'observedMonotonicNs': time.monotonic_ns()}


def _observer_peer(pid, expected_uid):
    """Bind the fixed socket peer to one live kernel PID and UID epoch."""
    if type(pid) is not int or pid <= 1:
        workload.reject('observer-peer-invalid')
    root = Path('/proc') / str(pid)
    status = dict(line.split(':', 1) for line in (root / 'status').read_text().splitlines() if ':' in line)
    if set(map(int, status['Uid'].split())) != {expected_uid}:
        workload.reject('observer-peer-changed')
    stat_fields = (root / 'stat').read_text().rsplit(')', 1)[1].split()
    return {'pid': pid, 'uid': expected_uid, 'startTicks': int(stat_fields[19])}


def _observer_control_denial(connection, handle, peer_pid, peer_uid, request_raw,
                             target_before, request_received_ns):
    """Exercise one fixed forbidden controller method while its target is active."""
    before_peer = _observer_peer(peer_pid, peer_uid)
    current_controller = _controller_process()
    if (target_before['invocationId'] != current_controller['invocationId']
            or target_before['cgroupIdentity'] != current_controller['cgroupIdentity']
            or target_before['bootId'] != current_controller['bootId']
            or target_before['observedMonotonicNs'] >= request_received_ns):
        workload.reject('observer-control-target-changed')
    before = workload.observe(handle)
    with workload.locked():
        campaign, role, record = workload.retained(handle)
        if role != 'candidate-sender' or not isinstance(workload.read(
                workload.ROOT / 'roles/candidate-sender/launch.json').get('probeIdentity'), dict):
            workload.reject('observer-control-cohort-invalid')
        workload.admit(campaign)
        workload.exact(role, record, workload.manager(role, 'show'))
    if (before.get('state') != 'running' or before.get('stateDigest') is None
            or before.get('provenance') != 'controller-kernel-sample'):
        workload.reject('observer-control-target-inactive')
    request_observed = request_received_ns
    connection.sendall(DENIED_RESPONSE)
    response_sent = time.monotonic_ns()
    try:
        after = workload.observe(handle)
        after_controller = _controller_process()
        after_peer = _observer_peer(peer_pid, peer_uid)
        if (before_peer != after_peer or target_before['invocationId'] != after_controller['invocationId']
                or target_before['cgroupIdentity'] != after_controller['cgroupIdentity']
                or target_before['bootId'] != after_controller['bootId']
                or before['managerInvocation'] != after['managerInvocation']
                or before['cgroupIdentity'] != after['cgroupIdentity']
                or before['bootId'] != after['bootId']
                or before['stateDigest'] != after['stateDigest']
                or after.get('state') != 'running'
                or not target_before['observedMonotonicNs']
                    < request_observed < response_sent
                    < after_controller['observedMonotonicNs']):
            return 'pr315-observer-control'
        audit = {'schemaVersion': 1, 'kind': 'pr315-administrator-observer-control-denial',
                 'caseId': 'observer-control', 'actor': before_peer,
                 'targetBefore': target_before, 'targetAfter': after_controller,
                 'senderManagerInvocation': before['managerInvocation'],
                 'senderCgroupIdentity': before['cgroupIdentity'],
                 'senderStateBefore': before['stateDigest'],
                 'senderStateAfter': after['stateDigest'],
                 'requestObservedNs': request_observed,
                 'responseSentNs': response_sent,
                 'requestDigest': hashlib.sha256(request_raw).hexdigest(),
                 'responseDigest': hashlib.sha256(DENIED_RESPONSE).hexdigest()}
        workload.write(workload.ROOT / 'authority/observer-control-denial.json', audit, create=True)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        # The already delivered denial stands; absent audit never grants acceptance.
        pass
    return 'pr315-observer-control'


def _recipient_fcp_control(handle):
    """Prove the exact sibling FCP listener is live through the approved connector."""
    from restricted_workload_network import FCP_PORT
    observed = workload.observe(handle)
    if (observed.get('state') != 'running'
            or observed.get('provenance') != 'controller-kernel-sample'):
        workload.reject('arbitrary-endpoint-target-inactive')
    with workload.connect(handle, 'fcp') as stream:
        if stream.getpeername() != ('127.0.0.1', FCP_PORT):
            workload.reject('arbitrary-endpoint-target-connection-invalid')
        stream.sendall(b'ClientHello\nName=pr315-endpoint-control\nExpectedVersion=2.0\nEndMessage\n')
        deadline_ns = time.monotonic_ns() + 5_000_000_000
        response = bytearray()
        while b'EndMessage\n' not in response and len(response) <= 16384:
            remaining = (deadline_ns - time.monotonic_ns()) / 1e9
            if remaining <= 0:
                workload.reject('arbitrary-endpoint-target-response-timeout')
            stream.settimeout(remaining)
            block = stream.recv(min(1024, 16385 - len(response)))
            if not block:
                workload.reject('arbitrary-endpoint-target-response-incomplete')
            response.extend(block)
        if not response.startswith(b'NodeHello\n') or len(response) > 16384:
            workload.reject('arbitrary-endpoint-target-response-invalid')
    return observed, time.monotonic_ns(), hashlib.sha256(response).hexdigest()


def _recipient_http_control(handle):
    """Prove the current sibling HTTP listener answers a fixed bounded HEAD."""
    from restricted_workload_network import HTTP_PORT
    observed = workload.observe(handle)
    if (observed.get('state') != 'running'
            or observed.get('provenance') != 'controller-kernel-sample'):
        workload.reject('sibling-http-target-inactive')
    with workload.connect(handle, 'http') as stream:
        if stream.getpeername() != ('127.0.0.1', HTTP_PORT):
            workload.reject('sibling-http-target-connection-invalid')
        stream.sendall(b'HEAD / HTTP/1.1\r\nHost: 127.0.0.1:19402\r\nConnection: close\r\n\r\n')
        deadline_ns = time.monotonic_ns() + 5_000_000_000
        response = bytearray()
        while b'\r\n' not in response and len(response) <= 512:
            remaining = (deadline_ns - time.monotonic_ns()) / 1e9
            if remaining <= 0:
                workload.reject('sibling-http-target-response-timeout')
            stream.settimeout(remaining)
            block = stream.recv(min(256, 513 - len(response)))
            if not block:
                workload.reject('sibling-http-target-response-incomplete')
            response.extend(block)
        first = bytes(response).split(b'\r\n', 1)[0]
        if re.fullmatch(rb'HTTP/1\.[01] [2-4][0-9]{2} [ -~]{1,80}', first) is None:
            workload.reject('sibling-http-target-response-invalid')
    return observed, time.monotonic_ns(), hashlib.sha256(first).hexdigest()


def _observer_arbitrary_endpoint_denial(connection, handle, peer_pid, peer_uid,
                                        request_raw, target_before, request_received_ns):
    """Reject one fixed sibling-FCP selector at the actual connector boundary."""
    from restricted_workload_network import NetworkBoundaryError
    before_peer = _observer_peer(peer_pid, peer_uid)
    controller = _controller_process()
    if (target_before['invocationId'] != controller['invocationId']
            or target_before['cgroupIdentity'] != controller['cgroupIdentity']
            or target_before['bootId'] != controller['bootId']
            or target_before['observedMonotonicNs'] >= request_received_ns):
        workload.reject('arbitrary-endpoint-controller-changed')
    with workload.locked():
        campaign, role, sender_record = workload.retained(handle)
        if role != 'candidate-sender' or not isinstance(workload.read(
                workload.ROOT / 'roles/candidate-sender/launch.json').get('probeIdentity'), dict):
            workload.reject('arbitrary-endpoint-cohort-invalid')
        recipient_handle = campaign['handles']['candidate-recipient']
        _campaign, recipient_role, recipient_record = workload.retained(recipient_handle)
        if recipient_role != 'candidate-recipient':
            workload.reject('arbitrary-endpoint-recipient-invalid')
        workload.admit(campaign)
        workload.exact(role, sender_record, workload.manager(role, 'show'))
        workload.exact(recipient_role, recipient_record,
                       workload.manager(recipient_role, 'show'))
    sender_before = workload.observe(handle)
    recipient_before, control_before_ns, control_before_digest = _recipient_fcp_control(
        recipient_handle)
    if (sender_before.get('state') != 'running'
            or sender_before.get('provenance') != 'controller-kernel-sample'
            or not isinstance(sender_before.get('stateDigest'), str)
            or recipient_before['observedMonotonicNs'] >= control_before_ns):
        workload.reject('arbitrary-endpoint-role-inactive')
    attack_started_ns = time.monotonic_ns()
    try:
        selected = workload.connect(handle, 'sibling-fcp')
    except NetworkBoundaryError as error:
        if str(error) != 'restricted-workload-network-rejected':
            raise
    else:
        selected.close()
        workload.reject('arbitrary-endpoint-unexpectedly-connected')
    attack_finished_ns = time.monotonic_ns()
    connection.sendall(DENIED_RESPONSE)
    response_sent_ns = time.monotonic_ns()
    try:
        recipient_after, control_after_ns, control_after_digest = _recipient_fcp_control(
            recipient_handle)
        sender_after = workload.observe(handle)
        controller_after = _controller_process()
        after_peer = _observer_peer(peer_pid, peer_uid)
        role_fields = ('managerInvocation', 'cgroupIdentity', 'bootId')
        if (before_peer != after_peer
                or any(sender_before[key] != sender_after[key] for key in role_fields)
                or any(recipient_before[key] != recipient_after[key] for key in role_fields)
                or sender_before['stateDigest'] != sender_after['stateDigest']
                or not isinstance(sender_before['stateDigest'], str)
                or any(target_before[key] != controller_after[key]
                       for key in ('invocationId', 'cgroupIdentity', 'bootId'))
                or not target_before['observedMonotonicNs'] < request_received_ns
                    < recipient_before['observedMonotonicNs'] < control_before_ns
                    < attack_started_ns < attack_finished_ns < response_sent_ns
                    < recipient_after['observedMonotonicNs'] < control_after_ns
                    < controller_after['observedMonotonicNs']):
            return 'pr315-arbitrary-endpoint'
        fields = ('managerInvocation', 'cgroupIdentity', 'bootId', 'stateDigest',
                  'observedMonotonicNs')
        audit = {'schemaVersion': 1,
                 'kind': 'pr315-administrator-arbitrary-endpoint-denial',
                 'caseId': 'arbitrary-endpoint', 'actor': before_peer,
                 'targetBefore': target_before, 'targetAfter': controller_after,
                 'senderBefore': {key: sender_before[key] for key in fields},
                 'senderAfter': {key: sender_after[key] for key in fields},
                 'recipientBefore': {key: recipient_before[key] for key in fields},
                 'recipientAfter': {key: recipient_after[key] for key in fields},
                 'recipientControlBeforeNs': control_before_ns,
                 'recipientControlAfterNs': control_after_ns,
                 'recipientControlBeforeDigest': control_before_digest,
                 'recipientControlAfterDigest': control_after_digest,
                 'endpointSelection': 'sibling-fcp',
                 'denial': 'restricted-workload-network-rejected',
                 'requestObservedNs': request_received_ns,
                 'attackStartedNs': attack_started_ns,
                 'attackFinishedNs': attack_finished_ns,
                 'responseSentNs': response_sent_ns,
                 'requestDigest': hashlib.sha256(request_raw).hexdigest(),
                 'responseDigest': hashlib.sha256(DENIED_RESPONSE).hexdigest()}
        workload.write(workload.ROOT / 'authority/arbitrary-endpoint-denial.json',
                       audit, create=True)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        # Delivered denial is not an installed witness without the root audit.
        pass
    return 'pr315-arbitrary-endpoint'


def _http(sock, path, headers):
    connection = http.client.HTTPConnection('127.0.0.1', sock.getpeername()[1], timeout=5)
    connection.sock = sock
    try:
        connection.request('GET', path, headers=headers)
        response = connection.getresponse()
        body = response.read(65537)
        if len(body) > 65536:
            workload.reject('bootstrap-output-limit')
        return response.status, dict(response.getheaders()), body
    finally:
        connection.close()


def runtime_object(body):
    """Reject malformed candidate JSON before any runtime or sandbox dereference."""
    value = json.loads(body)
    if not isinstance(value, dict) or not isinstance(value.get('runtime'), dict):
        workload.reject('app-runtime-invalid')
    runtime = value['runtime']
    if not isinstance(runtime.get('sandbox'), dict):
        workload.reject('app-runtime-invalid')
    return runtime


@contextmanager
def bootstrap_phase(stage, role):
    """Retain one root-private fixed failure phase without changing the socket reply."""
    if stage not in BOOTSTRAP_STAGES:
        workload.reject('bootstrap-diagnostic-stage-invalid')
    started = time.monotonic_ns()
    try:
        yield
    except (OSError, ValueError, KeyError, TypeError,
            http.client.HTTPException) as error:
        detail = str(error)
        code = (detail if re.fullmatch(r'[a-z][a-z0-9-]{1,100}', detail)
                and detail.startswith(('app-', 'restricted-', 'workload-',
                                       'request-', 'authority-'))
                else 'unclassified')
        try:
            workload.write(BOOTSTRAP_FAILURE, {
                'schemaVersion': 1,
                'kind': 'pr315-controller-bootstrap-failure-phase',
                'stage': stage,
                'role': role if role in workload.ROLES else 'unknown',
                'exceptionType': type(error).__name__[:128],
                'errorCode': code,
                'controllerPid': os.getpid(),
                'bootId': workload.boot(),
                'startedMonotonicNs': started,
                'observedMonotonicNs': time.monotonic_ns()}, create=True)
        except (OSError, ValueError, KeyError, TypeError):
            pass  # The original request failure remains authoritative.
        raise


def bootstrap(handle):
    """Resolve dynamic app origin only from this role's current daemon launch proof."""
    with workload.locked(), deadline():
        with bootstrap_phase('authority', 'unknown'):
            campaign, role, record = workload.retained(handle)
            workload.admit(campaign)
            workload.exact(role, record, workload.manager(role, 'show'))
        with bootstrap_phase('installed-app', role):
            from restricted_workload_storage import verify_installed_app
            launch = workload.read(workload.ROOT / 'roles' / role / 'launch.json')
            verify_installed_app(workload.ROOT / 'state' / role / 'data/node/apps/installed/mail-prototype',
                launch['mailIdentity'], workload.ROOT / 'authority' / (role + '-app-snapshot'),
                min(time.monotonic() + 5, campaign['deadlineMonotonicNs'] / 1e9))
        with bootstrap_phase('launch-redirect', role):
            from restricted_workload_network import connect, _connect_port, HTTP_PORT
            status, headers, _body = _http(connect(role, 'http'),
                '/apps/mail-prototype/?cryptadIsolatedLaunch', {'Accept': 'text/html'})
            if status not in (301, 302, 303, 307, 308):
                workload.reject('app-launch-unavailable')
        with bootstrap_phase('origin-parse', role):
            location = next((value for key, value in headers.items() if key.lower() == 'location'), '')
            selected = urllib.parse.urlsplit(location)
            if (selected.scheme != 'http' or selected.hostname != '127.0.0.1'
                    or selected.username is not None or selected.password is not None
                    or selected.port is None or not 1024 <= selected.port <= 65535
                    or selected.port == HTTP_PORT or selected.path not in ('/', '/static/') or selected.query):
                workload.reject('app-origin-invalid')
            fragment = urllib.parse.parse_qs(selected.fragment, strict_parsing=True)
            if (set(fragment) != {'cryptadBootstrapNonce'} or len(fragment['cryptadBootstrapNonce']) != 1
                    or re.fullmatch('[A-Za-z0-9_-]{16,512}', fragment['cryptadBootstrapNonce'][0]) is None):
                workload.reject('app-nonce-invalid')
        with bootstrap_phase('app-runtime', role):
            from restricted_workload_app import require_app_listener
            runtime_status, _headers, runtime_body = _http(connect(role, 'http'),
                '/api/v1/apps/mail-prototype/runtime', {'Accept': 'application/json'})
            if runtime_status != 200:
                workload.reject('app-runtime-unavailable')
            binding = require_app_listener(role, runtime_object(runtime_body), selected.port)
        with bootstrap_phase('session-bootstrap', role):
            origin = 'http://127.0.0.1:' + str(selected.port)
            status, _headers, body = _http(_connect_port(role, selected.port),
                '/.well-known/cryptad-bootstrap.json', {'Accept': 'application/json', 'Origin': origin,
                    'X-Crypta-App-Bootstrap-Nonce': fragment['cryptadBootstrapNonce'][0]})
            value = json.loads(body)
            if (status != 200 or not isinstance(value, dict) or value.get('uiOrigin') != origin
                    or not isinstance(value.get('browserSessionToken'), str)
                    or not 1 <= len(value['browserSessionToken']) <= 4096):
                workload.reject('app-bootstrap-invalid')
        with bootstrap_phase('recheck', role):
            workload.current(campaign)
            workload.exact(role, record, workload.manager(role, 'show'))
            runtime_status, _headers, runtime_body = _http(connect(role, 'http'),
                '/api/v1/apps/mail-prototype/runtime', {'Accept': 'application/json'})
            if (runtime_status != 200 or require_app_listener(role, runtime_object(runtime_body),
                                                            selected.port) != binding):
                workload.reject('app-worker-changed')
        # A private response; never inserted into an acceptance/public result.
        return {key: value.get(key) for key in ('uiOrigin', 'browserSessionToken', 'browserSessionExpiresAt')}


def serve(connection, expected_uid, *, revocation_token=None):
    credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
    pid, uid, _gid = struct.unpack('3i', credentials)
    if uid != expected_uid:
        workload.reject('peer-denied')
    connection.settimeout(5)
    first = connection.recv(1)
    if revocation_token is not None and first != b'P':
        workload.reject('revocation-barrier-handshake-required')
    target_before = None
    if first == b'P':
        # A fixed test-only readiness byte establishes an active controller
        # snapshot before the observer can send the forbidden request bytes.
        target_before = _controller_process()
        connection.sendall(b'R')
        raw = bytearray()
    else:
        raw = bytearray(first)
    while b'\n' not in raw:
        block = connection.recv(257 - len(raw))
        if not block:
            workload.reject('request-incomplete')
        raw.extend(block)
        if len(raw) > 256:
            workload.reject('request-limit')
    if raw[-1:] != b'\n' or raw.count(b'\n') != 1:
        workload.reject('request-framing-invalid')
    request_received_ns = time.monotonic_ns()
    probe = OBSERVER_CONTROL_REQUEST.fullmatch(bytes(raw))
    if probe is not None:
        if target_before is None:
            workload.reject('observer-control-handshake-required')
        return _observer_control_denial(connection, probe[1].decode(), pid, uid, bytes(raw),
                                        target_before, request_received_ns)
    probe = OBSERVER_ENDPOINT_REQUEST.fullmatch(bytes(raw))
    if probe is not None:
        if target_before is None:
            workload.reject('arbitrary-endpoint-handshake-required')
        return _observer_arbitrary_endpoint_denial(connection, probe[1].decode(), pid, uid,
                                                   bytes(raw), target_before,
                                                   request_received_ns)
    selected = request(bytes(raw[:-1]))
    method, handle = selected['method'], selected['handle']
    request_raw = bytes(raw)
    if revocation_token is not None:
        campaign = workload.read(workload.ROOT / 'campaign.json')
        if method != 'start' or handle != campaign['handles']['candidate-sender']:
            workload.reject('revocation-barrier-method-invalid')
        revocation_token['requestDigest'] = hashlib.sha256(request_raw).hexdigest()
    started = time.monotonic_ns()
    _request_progress(method, 'executing', started)
    try:
        if method.startswith('connect-'):
            with workload.connect(handle, method.removeprefix('connect-')) as stream:
                rights = array.array('i', [stream.fileno()])
                response_raw = b'{"status":"connected"}\n'
                connection.sendmsg([response_raw], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
        else:
            operation = {'start': workload.start, 'stop': workload.stop, 'observe': workload.observe,
                         'bootstrap-mail': bootstrap}[method]
            result = operation(handle)
            response_raw = json.dumps(result, separators=(',', ':'), allow_nan=False).encode() + b'\n'
            if len(response_raw) > 1024 * 1024:
                workload.reject('response-limit')
            connection.sendall(response_raw)
        _request_progress(method, 'replied', started)
        _audit_exchange(method, handle, request_raw, response_raw, started, time.monotonic_ns())
        return method
    except Exception as error:
        _request_progress(method, 'failed', started, error)
        raise


def handle_request(connection, observer_uid):
    """Contain adversarial protocol errors to this request, preserving owned siblings."""
    from restricted_workload_revocation_barrier import prepare, refused
    with deadline(45):
        token = None
        try:
            token = prepare(connection, observer_uid)
            if token is None:
                serve(connection, observer_uid)
            else:
                serve(connection, observer_uid, revocation_token=token)
            return True
        except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException) as error:
            try:
                connection.sendall(b'{"error":"restricted-workload-request-failed"}\n')
            except OSError:
                pass
            refused(token, error)
            return False


def startup_checkpoint(stage, started, reached, error=None):
    """Best-effort root-private latest runtime state, never history or acceptance authority.

    Fixed internal stages expose no command, candidate output, exception message or private
    selection. The administrator can snapshot this before systemd removes RuntimeDirectory.
    The four-entry timestamp map belongs only to this process startup epoch; repeated error
    observations preserve the first reached time. Diagnostic failure must not change controller
    behavior or replace the original failure.
    """
    try:
        if stage not in STARTUP_STAGES or set(reached) - STARTUP_STAGES:
            return
        observed = time.monotonic_ns()
        reached.setdefault(stage, started if stage == 'entry' else observed)
        record = {'schemaVersion': 2, 'classification': 'private-runtime-diagnostic-not-acceptance',
            'pid': os.getpid(), 'bootId': workload.boot(), 'startedMonotonicNs': started,
            'observedMonotonicNs': observed, 'stage': stage,
            'stageMonotonicNs': dict(reached)}
        if error is not None:
            record['exceptionType'] = type(error).__name__[:128]
        workload.write(STARTUP, record, mode=0o600)
    except Exception:
        pass


def main():
    if len(sys.argv) != 1 or not sys.flags.isolated or not sys.flags.no_site or os.geteuid() != 0:
        workload.reject('fixed-entry-required')
    started, stage = time.monotonic_ns(), 'entry'
    reached = {}
    startup_checkpoint(stage, started, reached)
    try:
        os.environ.clear()
        os.umask(0o077)
        workload.secured(Path(__file__))
        # Verify the same immutable installed code/dependency closure as the existing resolver.
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'restricted'))
        import installation
        installation.verify_execution()
        stage = 'installation-verified'
        startup_checkpoint(stage, started, reached)
        observer = pwd.getpwnam('cryptad-soak')
        if (workload.ROOT / 'campaign.json').exists():
            workload.recover_controller()
        stage = 'reconciled'
        startup_checkpoint(stage, started, reached)
        if SOCKET.exists() or SOCKET.is_symlink():
            workload.reject('socket-reconciliation-required')
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(SOCKET))
        SOCKET.chmod(0o600)
        os.chown(SOCKET, observer.pw_uid, observer.pw_gid)
        server.listen(8)
        stage = 'listening'
        startup_checkpoint(stage, started, reached)
    except Exception as error:
        startup_checkpoint(stage, started, reached, error)
        raise
    last_observer = time.monotonic()
    try:
        while True:
            if (workload.ROOT / 'campaign.json').exists():
                try:
                    workload.current(workload.read(workload.ROOT / 'campaign.json'))
                    # Fixed FCP transactions may take 180 seconds without another RPC.
                    if time.monotonic() - last_observer > 240:
                        workload.reject('observer-lost')
                except ValueError:
                    workload.fence_campaign()
                    workload.reconcile()
                    return 1
            ready, _, _ = select.select([server], [], [], 1)
            if not ready:
                continue
            connection, _ = server.accept()
            with connection:
                if handle_request(connection, observer.pw_uid):
                    last_observer = time.monotonic()
    finally:
        server.close()
        workload.fence_campaign()
        workload.reconcile()
        SOCKET.unlink()


if __name__ == '__main__':
    try:
        result = main()
    except Exception:
        result = 1
    raise SystemExit(result)

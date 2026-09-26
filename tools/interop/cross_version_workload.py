"""Observer adapter for the fixed installed four-role workload profile.

No process is launched locally. Every connection and process sample belongs to the
controller-retained role invocation. This prospective path does not promote historical
same-UID observations, or establish original protected authority.
"""
from __future__ import annotations

import array
from contextlib import contextmanager
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import struct
import time
import urllib.parse
import uuid

import cross_version_runtime as runtime

PROFILE = 'debian13-systemd257-workload-v1'
SOCKET = '/run/cryptad-workload/control.sock'
MAX_RESPONSE = 1024 * 1024
METHODS = {'start', 'observe', 'stop', 'connect-fcp',
           'connect-http', 'bootstrap-mail'}
EPOCH = ('handle', 'generation', 'managerInvocation', 'bootId')


def fail(code):
    raise runtime.RuntimeFailure('workload-' + code)


def retained_deadline(handoff, maximum):
    """Use the administrator's original monotonic epoch, including elapsed preparation."""
    deadline = handoff.get('deadlineMonotonicNs')
    now = time.monotonic_ns()
    if (type(deadline) is not int or type(maximum) is not int or not 30 <= maximum <= 3600
            or not now < deadline <= now + maximum * 10**9):
        fail('retained-deadline-invalid-or-expired')
    return deadline / 10**9


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail('response-duplicate-field')
        result[key] = value
    return result


class WorkloadClient:
    """Only fixed methods and opaque handles cross the installed root-owned socket."""
    def request(self, method, handle):
        if method not in METHODS or not isinstance(handle, str) or not re.fullmatch('[a-f0-9]{64}', handle):
            fail('request-invalid')
        self.last_exchange = None
        descriptors = []
        channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            channel.settimeout(30)
            channel.connect(SOCKET)
            _, uid, _ = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != 0:
                fail('controller-peer-not-root')
            request_raw = json.dumps({'method': method, 'handle': handle}, separators=(',', ':')).encode() + b'\n'
            channel.sendall(request_raw)
            payload = bytearray()
            while b'\n' not in payload:
                data, ancillary, flags, _ = channel.recvmsg(min(65536, MAX_RESPONSE + 1 - len(payload)),
                    socket.CMSG_SPACE(16 * array.array('i').itemsize), socket.MSG_CMSG_CLOEXEC)
                for level, kind, value in ancillary:
                    if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                        fail('controller-ancillary-invalid')
                    fds = array.array('i')
                    fds.frombytes(value[:len(value) - len(value) % fds.itemsize])
                    descriptors.extend(fds)
                if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                    fail('controller-response-truncated')
                if not data:
                    fail('controller-response-incomplete')
                payload.extend(data)
                if len(payload) > MAX_RESPONSE:
                    fail('controller-response-budget')
            if payload.count(b'\n') != 1 or not payload.endswith(b'\n'):
                fail('controller-response-framing')
            value = json.loads(payload, object_pairs_hook=_object)
            if not isinstance(value, dict) or 'error' in value:
                fail('controller-request-rejected')
            if method.startswith('connect-'):
                if len(descriptors) != 1:
                    fail('controller-connection-missing')
                descriptor = descriptors.pop()
                try:
                    connected = socket.socket(fileno=descriptor)
                except BaseException:
                    os.close(descriptor)
                    raise
                try:
                    if connected.family != socket.AF_INET or connected.type != socket.SOCK_STREAM:
                        fail('controller-connection-invalid')
                    connected.getpeername()
                    connected.settimeout(25)
                    self.last_exchange = {'method': method,
                        'requestDigest': hashlib.sha256(request_raw).hexdigest(),
                        'responseDigest': hashlib.sha256(payload).hexdigest()}
                    return value, connected
                except BaseException:
                    connected.close()
                    raise
            if descriptors:
                fail('controller-unexpected-connection')
            self.last_exchange = {'method': method,
                'requestDigest': hashlib.sha256(request_raw).hexdigest(),
                'responseDigest': hashlib.sha256(payload).hexdigest()}
            return value
        except (OSError, ValueError, UnicodeError):
            fail('controller-transport-failed')
        finally:
            channel.close()
            for descriptor in descriptors:
                os.close(descriptor)

    def drop_start_response(self, handle):
        """Send one fixed start request, then close without reading its response."""
        if not isinstance(handle, str) or re.fullmatch('[a-f0-9]{64}', handle) is None:
            fail('lost-start-handle-invalid')
        self.last_exchange = None
        channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            channel.settimeout(5)
            channel.connect(SOCKET)
            _, uid, _ = struct.unpack('3i', channel.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != 0:
                fail('controller-peer-not-root')
            request = b'{"method":"start","handle":"' + handle.encode('ascii') + b'"}\n'
            started = time.monotonic_ns()
            channel.sendall(request)
            finished = time.monotonic_ns()
            if finished <= started:
                fail('lost-start-send-clock-invalid')
            return {'requestDigest': hashlib.sha256(request).hexdigest(),
                    'sendStartedNs': started, 'sendFinishedNs': finished}
        except (OSError, ValueError):
            fail('lost-start-transport-failed')
        finally:
            channel.close()


class ConnectedFcpClient(runtime.BoundedFcpClient):
    """Reuse bounded FCP parsing and handshake over one constrained controller connection."""
    def __init__(self, connected, name, transcript_path, before_send):
        self.before_send = before_send
        self.host, self.port, self.name = '127.0.0.1', 19401, name
        self.transcript_path = transcript_path
        self.sock = connected
        self.file = None
        self.hello = None
        try:
            self.file = connected.makefile('rwb', buffering=0)
            self.send('ClientHello', {'Name': name, 'ExpectedVersion': '2.0'})
            self.hello = self.read_message(30)
            if self.hello.name != 'NodeHello':
                fail('fcp-hello-invalid')
        except BaseException:
            if self.file is not None:
                self.file.close()
            connected.close()
            raise


    def _log_text(self, text):
        raw = text.encode('utf-8')
        fd = os.open(self.transcript_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or info.st_mode & 0o077
                    or info.st_size + len(raw) > 16 * 1024**2):
                fail('fcp-transcript-budget-or-ownership')
            pending = memoryview(raw)
            while pending:
                written = os.write(fd, pending)
                if written <= 0:
                    fail('fcp-transcript-write')
                pending = pending[written:]
        finally:
            os.close(fd)


class _Response:
    def __init__(self, response, connection):
        self.response, self.connection = response, connection
        self.status, self.headers = response.status, response.headers

    def read(self, size):
        return self.response.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        try:
            self.response.close()
        finally:
            self.connection.close()


class _RoleHttp:
    """No DNS, proxy or redirect resolution: one fixed management connection per request."""
    def __init__(self, supervisor, role):
        self.supervisor, self.role = supervisor, role

    def open(self, request, timeout=25):
        selected = urllib.parse.urlsplit(request.full_url)
        if (selected.scheme != 'http' or selected.hostname != '127.0.0.1' or selected.port != 19402
                or selected.username or selected.password or selected.fragment):
            fail('http-target-not-approved')
        connected = self.supervisor.connection(self.role, 'http')
        connection = http.client.HTTPConnection('127.0.0.1', 19402, timeout=timeout)
        connection.sock = connected
        try:
            connection.request(request.get_method(), selected.path + ('?' + selected.query if selected.query else ''),
                               body=request.data, headers=dict(request.header_items()))
            return _Response(connection.getresponse(), connection)
        except BaseException:
            connection.close()
            raise


class InstalledAppHandle(runtime.AppHandle):
    """Retain the existing HTTP route policy and normal signed AppHost installation."""
    def __init__(self, supervisor, role, app_id='mail-prototype'):
        if app_id != 'mail-prototype':
            fail('app-adapter-unsupported')
        super().__init__(supervisor, role, app_id)
        self.base, self.api = 'http://127.0.0.1:19402', 'http://127.0.0.1:19402/api/v1'
        self.opener = _RoleHttp(supervisor, role)

    def refresh_session(self):
        """Accept sessions only after the controller verifies the current app boundary."""
        self.origin = self.session = self.session_expires_at = None
        value = self.isolated_bootstrap()
        origin = runtime.mail_demo.target(value.get('uiOrigin'))
        session = value.get('browserSessionToken')
        if not isinstance(session, str) or not session or len(session) > 4096:
            fail('own-app-bootstrap-invalid')
        if origin == self.base:
            fail('isolated-own-app-origin-required')
        self.origin, self.session = origin, session
        self.session_expires_at = value.get('browserSessionExpiresAt')
        return self

    def isolated_bootstrap(self):
        self.supervisor.next_operation()
        self.supervisor.observe(self.role)
        value = self.supervisor.control.request('bootstrap-mail', self.supervisor.handles[self.role])
        exchanges = getattr(self.supervisor, 'control_exchanges', None)
        observed = getattr(self.supervisor.control, 'last_exchange', None)
        if (self.role == 'candidate-sender' and isinstance(exchanges, dict)
                and isinstance(observed, dict) and observed.get('method') == 'bootstrap-mail'):
            exchanges['dynamic-app-bootstrap'] = dict(observed)
        self.supervisor.observe(self.role)
        # The controller validates nonce, origin and dynamic listener inside the role.
        if not isinstance(value, dict):
            fail('bootstrap-response-invalid')
        return value

    def observe_worker(self):
        status, value = self.request('GET', '/api/v1/apps/mail-prototype/runtime')
        reported = value.get('runtime', {})
        if (status != 200 or reported.get('running') is not True
                or reported.get('sandbox', {}).get('provider') != 'bubblewrap'
                or reported.get('sandbox', {}).get('active') is not True):
            fail('real-app-sandbox-not-observed')
        observation = self.supervisor.observe(self.role)
        self.worker_identity = bind_worker(observation, reported.get('pid'),
                                          self.supervisor.expected_jdk_digests[self.role])
        return self.worker_identity

    def mail_client(self):
        # The historical Mail Client opens direct host-loopback sockets. Never fall back.
        fail('mail-consumer-adapter-unsupported')


class InstalledProbeAppHandle(runtime.AppHandle):
    """Normal signed AppHost installation with a separately measured child process."""

    def __init__(self, supervisor, role):
        if role != 'candidate-sender':
            fail('probe-app-role-unsupported')
        super().__init__(supervisor, role, 'pr315-probe')
        self.base, self.api = 'http://127.0.0.1:19402', 'http://127.0.0.1:19402/api/v1'
        self.opener = _RoleHttp(supervisor, role)

    def observe_worker(self):
        status, value = self.request('GET', '/api/v1/apps/pr315-probe/runtime')
        reported = value.get('runtime', {})
        if (status != 200 or reported.get('running') is not True
                or reported.get('sandbox', {}).get('provider') != 'bubblewrap'
                or reported.get('sandbox', {}).get('active') is not True):
            fail('real-probe-sandbox-not-observed')
        observation = self.supervisor.observe(self.role)
        self.worker_identity = bind_probe_worker(observation, reported.get('pid'),
            self.supervisor.expected_jdk_digests[self.role])
        return self.worker_identity


def bind_probe_worker(observation, api_pid, expected_jdk_digest):
    """Bind the AppHost PID-1 leader to its signed Python child in one kernel sample."""
    if type(api_pid) is not int or api_pid <= 1 or observation.get('provenance') != 'controller-kernel-sample':
        fail('probe-process-hint-invalid')
    rows = observation.get('processes')
    if not isinstance(rows, list) or len(rows) > 512:
        fail('probe-process-sample-invalid')
    matches = [row for row in rows if isinstance(row, dict)
               and isinstance(row.get('namespacePids'), list)
               and len(row['namespacePids']) == 3
               and row['namespacePids'][1] == api_pid
               and row['namespacePids'][-1] == 1]
    if len(matches) != 1:
        fail('probe-process-outside-role')
    leader = matches[0]
    python_digest = runtime.digest_file('/usr/bin/python3')
    children = [row for row in rows if isinstance(row, dict)
                and row.get('hostParentPid') == leader.get('hostPid')
                and isinstance(row.get('namespacePids'), list)
                and len(row['namespacePids']) == 3
                and row['namespacePids'][-1] == 2
                and row.get('pidNamespace') == leader.get('pidNamespace')
                and row.get('mountNamespaceIdentity') == leader.get('mountNamespaceIdentity')
                and row.get('userNamespaceIdentity') == leader.get('userNamespaceIdentity')
                and row.get('networkNamespaceIdentity') == leader.get('networkNamespaceIdentity')
                and row.get('executableDigest') == python_digest]
    if len(children) != 1:
        fail('probe-python-child-unavailable')
    worker = children[0]
    daemons = [row for row in rows if isinstance(row, dict)
               and row.get('executableDigest') == expected_jdk_digest
               and isinstance(row.get('namespacePids'), list)
               and len(row['namespacePids']) == 2]
    if len(daemons) != 1:
        fail('probe-outer-daemon-unavailable')
    outer = daemons[0]
    pid_namespace = re.fullmatch(r'pid:\[([0-9]+)\]', str(worker.get('pidNamespace')))
    if (type(leader.get('hostPid')) is not int or leader['hostPid'] <= 1
            or type(leader.get('startTicks')) is not int or leader['startTicks'] <= 0
            or leader.get('noNewPrivileges') is not True
            or leader.get('effectiveCapabilities') != 0
            or re.fullmatch('sha256:[0-9a-f]{64}', str(leader.get('executableDigest'))) is None
            or type(worker.get('hostPid')) is not int or worker['hostPid'] <= 1
            or worker['namespacePids'][0] != worker['hostPid']
            or leader['namespacePids'][0] != leader['hostPid']
            or type(worker.get('startTicks')) is not int or worker['startTicks'] <= 0
            or worker['startTicks'] < leader['startTicks']
            or worker.get('noNewPrivileges') is not True
            or worker.get('effectiveCapabilities') != 0
            or not isinstance(worker.get('executableDigest'), str)
            or not re.fullmatch('sha256:[0-9a-f]{64}', worker['executableDigest'])
            or pid_namespace is None
            or any(not isinstance(worker.get(key), list) or len(worker[key]) != 2
                   or any(type(part) is not int or part <= 0 for part in worker[key])
                   for key in ('mountNamespaceIdentity', 'userNamespaceIdentity',
                               'networkNamespaceIdentity'))
            or worker['networkNamespaceIdentity'] != observation.get('networkNamespaceIdentity')
            or worker['mountNamespaceIdentity'] == outer.get('mountNamespaceIdentity')):
        fail('probe-process-kernel-boundary-invalid')
    return {'role': 'candidate-sender', 'hostPid': worker['hostPid'],
            'namespacePid': api_pid, 'namespacePids': worker['namespacePids'],
            'startTicks': worker['startTicks'],
            'executableDigest': worker['executableDigest'],
            'mountNamespaceIdentity': worker['mountNamespaceIdentity'],
            'outerMountNamespaceIdentity': outer['mountNamespaceIdentity'],
            'userNamespaceIdentity': worker['userNamespaceIdentity'],
            'pidNamespaceIdentity': int(pid_namespace[1]),
            'managerInvocation': observation['managerInvocation'],
            'cgroupIdentity': observation['cgroupIdentity'],
            'networkNamespaceIdentity': observation['networkNamespaceIdentity'],
            'stateDigest': observation.get('stateDigest'),
            'observedMonotonicNs': observation.get('observedMonotonicNs'),
            'sandboxLeader': {'hostPid': leader['hostPid'],
                              'namespacePids': leader['namespacePids'],
                              'startTicks': leader['startTicks'],
                              'executableDigest': leader['executableDigest'],
                              'mountNamespaceIdentity': leader['mountNamespaceIdentity'],
                              'userNamespaceIdentity': leader['userNamespaceIdentity'],
                              'networkNamespaceIdentity': leader['networkNamespaceIdentity'],
                              'pidNamespaceIdentity': int(pid_namespace[1])},
            'provenance': 'controller-kernel-sample'}


def bind_worker(observation, api_pid, expected_jdk_digest):
    """API PID is a hint resolved only against the controller's current cgroup sample.

    The outer role daemon uses NSpid index 1 in this profile; an AppHost child
    must have an additional inner PID namespace. Require its actual Java descendant in this sample.
    """
    if type(api_pid) is not int or api_pid <= 1 or observation.get('provenance') != 'controller-kernel-sample':
        fail('app-process-hint-invalid')
    rows = observation.get('processes')
    if not isinstance(rows, list) or len(rows) > 512:
        fail('process-sample-invalid')
    processes = {}
    for row in rows:
        pid = row.get('hostPid')
        namespaces = row.get('namespacePids')
        if (type(pid) is not int or pid <= 1 or pid in processes or not isinstance(namespaces, list)
                or not namespaces or namespaces[0] != pid or any(type(value) is not int or value < 1 for value in namespaces)
                or type(row.get('startTicks')) is not int or row['startTicks'] < 1
                or type(row.get('hostParentPid')) is not int
                or row.get('noNewPrivileges') is not True or row.get('effectiveCapabilities') != 0):
            fail('process-sample-invalid')
        processes[pid] = row
    matches = [row for row in rows if len(row['namespacePids']) >= 2 and row['namespacePids'][1] == api_pid]
    worker = matches[0] if len(matches) == 1 else None
    if worker is None:
        fail('app-process-outside-role')
    for row in rows:
        if row.get('executableDigest') != expected_jdk_digest or len(row['namespacePids']) < 3:
            continue
        cursor, visited = row, set()
        for _ in range(64):
            if cursor['hostPid'] == worker['hostPid']:
                return {**{key: observation[key] for key in EPOCH}, 'hostPid': worker['hostPid'],
                        'namespacePid': api_pid, 'startTicks': worker['startTicks'],
                        'javaHostPid': row['hostPid'],
                        'javaStartTicks': row['startTicks'], 'provenance': 'controller-kernel-sample'}
            if cursor['hostPid'] in visited:
                break
            visited.add(cursor['hostPid'])
            child = cursor
            cursor = processes.get(cursor['hostParentPid'])
            if cursor is None or cursor['startTicks'] > child['startTicks']:
                break
    fail('app-java-descendant-not-observed')


def bind_daemon(observation, expected_jdk_digest):
    """Pin the sole outer-namespace Java process from a controller kernel sample."""
    if observation.get('provenance') != 'controller-kernel-sample':
        fail('daemon-process-sample-invalid')
    network = observation.get('networkNamespaceIdentity')
    group = observation.get('cgroupIdentity')
    if any(not isinstance(value, list) or len(value) != 2
           or any(type(part) is not int or part < 1 for part in value)
           for value in (network, group)):
        fail('daemon-process-sample-invalid')
    rows = observation.get('processes')
    if not isinstance(rows, list) or len(rows) > 512:
        fail('daemon-process-sample-invalid')
    matches = []
    for row in rows:
        if not isinstance(row, dict) or row.get('executableDigest') != expected_jdk_digest:
            continue
        namespaces = row.get('namespacePids')
        if not isinstance(namespaces, list) or len(namespaces) != 2:
            continue
        pid = row.get('hostPid')
        ticks = row.get('startTicks')
        if (type(pid) is not int or pid <= 1 or namespaces[0] != pid
                or any(type(value) is not int or value < 1 for value in namespaces)
                or type(ticks) is not int or ticks < 1
                or row.get('networkNamespaceIdentity') != network
                or row.get('noNewPrivileges') is not True
                or row.get('effectiveCapabilities') != 0):
            fail('daemon-process-sample-invalid')
        matches.append({'managerInvocation': observation.get('managerInvocation'),
                        'hostPid': pid, 'startTicks': ticks,
                        'namespacePids': tuple(namespaces),
                        'networkNamespaceIdentity': tuple(network),
                        'cgroupIdentity': tuple(group),
                        'executableDigest': expected_jdk_digest})
    if len(matches) != 1:
        fail('daemon-process-not-unique')
    return matches[0]


def principal_row(role, observation, expected_jdk_digest, daemon=None):
    """Project one fixed installed account and actual outer Java process identity."""
    daemon = daemon or bind_daemon(observation, expected_jdk_digest)
    try:
        account = pwd.getpwnam('cryptad-wl-' + role)
        return {'role': role, 'uid': account.pw_uid, 'gid': account.pw_gid,
                'invocationId': daemon['managerInvocation'],
                'processEpoch': daemon['startTicks'],
                'bootId': uuid.UUID(observation['bootId']).hex,
                'cgroupDigest': runtime.canonical_digest({
                    'role': role, 'identity': daemon['cgroupIdentity']})[7:],
                'networkNamespace': daemon['networkNamespaceIdentity'][1]}
    except (KeyError, TypeError, ValueError):
        fail('kernel-roster-invalid')


def kernel_roster(samples, expected_jdk_digests):
    """Project only fixed role principals from final controller kernel observations."""
    if (not isinstance(samples, dict) or not isinstance(expected_jdk_digests, dict)
            or set(samples) != set(runtime.ROLES) or set(expected_jdk_digests) != set(runtime.ROLES)):
        fail('kernel-roster-incomplete')
    daemons = {role: bind_daemon(samples[role], expected_jdk_digests[role])
               for role in runtime.ROLES}
    try:
        runner_uid = pwd.getpwnam('vmadmin').pw_uid
        rows = [principal_row(role, samples[role], expected_jdk_digests[role], daemons[role])
                for role in runtime.ROLES]
    except (KeyError, TypeError, ValueError):
        fail('kernel-roster-invalid')
    if min(os.geteuid(), runner_uid, *(row['uid'] for row in rows),
           *(row['gid'] for row in rows)) <= 0:
        fail('kernel-roster-principal-invalid')
    return {'observerUid': os.geteuid(), 'runnerUid': runner_uid, 'roles': rows}


class InstalledWorkloadAdapter:
    """Finite observer orchestration over a root-prepared, immutable source-build selection.

    ``handoff`` and exact JDK executable digests come from the controller's retained
    selection, never candidate replies. The supplied journal retains its existing lease.
    Optional ``control`` permits isolated unit tests without an installed socket.
    """
    def __init__(self, plan, private_config, authorization, journal, handoff, expected_jdk_digests=None,
                 *, control=None, counter_sampler=None, lost_start_sampler=None):
        expected_jdk_digests = expected_jdk_digests or handoff.get('expectedJdkDigests', {})
        if (handoff.get('profile') != PROFILE or set(handoff.get('handles', {})) != set(runtime.ROLES)
                or plan.get('provenanceClass') != 'source-build-comparison'
                or set(private_config) != {'root', 'nodes'} or set(private_config['nodes']) != set(runtime.ROLES)
                or len(plan['nodes']) != 4 or {node['role'] for node in plan['nodes']} != set(runtime.ROLES)
                or plan.get('workloadInputs') or plan.get('cohorts')
                or authorization.get('syntheticContent') is not True
                or authorization.get('planDigest') != runtime.canonical_digest(plan)
                or authorization.get('experimentId') != plan.get('experimentId')
                or set(expected_jdk_digests) != set(runtime.ROLES)):
            fail('selection-unsupported')
        if (any(not re.fullmatch('sha256:[0-9a-f]{64}', value) for value in expected_jdk_digests.values())
                or any(not re.fullmatch('[0-9a-f]{64}', value) for value in handoff['handles'].values())
                or len(set(handoff['handles'].values())) != 4):
            fail('selection-identity-invalid')
        for role in runtime.ROLES:
            apps = private_config['nodes'][role].get('apps')
            ids = [app.get('appId') for app in apps] if isinstance(apps, list) else []
            if (not isinstance(apps, list)
                    or role == 'candidate-sender' and ids not in
                        (['mail-prototype'], ['mail-prototype', 'pr315-probe'])
                    or role == 'candidate-recipient' and ids != ['mail-prototype']
                    or role == 'relay-no-apps' and ids != []
                    or role == 'previous' and ids not in ([], ['mail-prototype'])):
                fail('app-selection-unsupported')
        root = Path(private_config['root'])
        lock = getattr(journal, '_lock', None)
        if (not root.is_absolute() or root.is_symlink() or root.resolve() != root
                or root.stat().st_uid != os.geteuid() or root.stat().st_mode & 0o077
                or authorization.get('root') != str(root) or getattr(journal, 'root', None) != root
                or type(lock) is not int):
            fail('observer-private-journal-required')
        actual, retained = os.fstat(lock), (root / 'lease').stat()
        if (actual.st_dev, actual.st_ino) != (retained.st_dev, retained.st_ino):
            fail('observer-journal-lease-changed')
        maximum = authorization.get('maxSeconds')
        if (type(maximum) is not int or not 30 <= maximum <= 3600
                or type(authorization.get('maxOperations')) is not int or not 1 <= authorization['maxOperations'] <= 10000):
            fail('budget-invalid')
        self.plan, self.private, self.authorization, self.journal = plan, private_config, authorization, journal
        self.handles = dict(handoff['handles'])
        self.expected_jdk_digests = dict(expected_jdk_digests)
        self.control = control or WorkloadClient()
        if counter_sampler is not None and not callable(counter_sampler):
            fail('counter-sampler-invalid')
        self.counter_sampler = counter_sampler
        if lost_start_sampler is not None and not callable(lost_start_sampler):
            fail('lost-start-sampler-invalid')
        self.lost_start_sampler = lost_start_sampler
        self.root, self.deadline, self.operations = root, retained_deadline(handoff, maximum), 0
        self.nodes, self.apps, self.outcomes, self.daemon_epochs = {}, {}, {}, {}
        self.control_exchanges = {}
        self.fnp_sample_failure = None
        self.restart_context = self.restart_window = None
        self.initial_role_roster = self.initial_role_window = self.initial_sender_state = None
        self._journal_started_roles = set()
        self.catalog_prepared = None
        self.active_start_role = None
        self.active_start_stage = None

    def remaining(self, limit=180):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            fail('observer-deadline')
        return min(limit, remaining)

    def next_operation(self):
        self.remaining()
        self.operations += 1
        if self.operations > self.authorization['maxOperations']:
            fail('operation-budget')
        return 'op-' + uuid.uuid4().hex

    def emit(self, kind, role='', scenario='', operation='', outcome='pass', counters=None, peer_role='', node_epoch=None):
        return self.journal.append(kind, role=role, scenario=scenario, operation=operation,
            outcome=outcome, counters=counters or {}, peer_role=peer_role, node_epoch=node_epoch)

    def _bound(self, role, value):
        if not isinstance(value, dict) or value.get('handle') != self.handles[role]:
            fail('role-handle-changed')
        if any(value.get(key) != self.nodes[role][key] for key in EPOCH):
            fail('role-invocation-changed')
        return value

    def observe(self, role):
        self.remaining()
        value = self._bound(role, self.control.request('observe', self.handles[role]))
        if value.get('state') != 'running':
            fail('role-not-running')
        pinned = self.daemon_epochs.get(role)
        if pinned is not None and bind_daemon(value, self.expected_jdk_digests[role]) != pinned:
            fail('role-daemon-epoch-changed')
        return value

    def connection(self, role, endpoint):
        if endpoint not in {'fcp', 'http'}:
            fail('endpoint-not-approved')
        self.remaining()
        self.observe(role)
        value, connected = self.control.request('connect-' + endpoint, self.handles[role])
        observed = getattr(self.control, 'last_exchange', None)
        if (role == 'candidate-sender' and endpoint == 'fcp'
                and isinstance(observed, dict) and observed.get('method') == 'connect-fcp'):
            self.control_exchanges['own-management'] = dict(observed)
        try:
            if value != {'status': 'connected'}:
                fail('connection-response-invalid')
            self.observe(role)
            return connected
        except BaseException:
            connected.close()
            raise

    @contextmanager
    def client(self, role):
        client = ConnectedFcpClient(self.connection(role, 'fcp'), 'workload-' + uuid.uuid4().hex,
                                   self.root / ('fcp-' + role + '.log'), self.next_operation)
        try:
            yield client
        finally:
            client.close()

    def start(self, role):
        if role not in runtime.ROLES:
            fail('role-invalid')
        self.active_start_role = role
        self.active_start_stage = 'start-request'
        self.remaining()
        value = self.control.request('start', self.handles[role])
        if (value.get('handle') != self.handles[role] or value.get('state') != 'running'
                or not re.fullmatch('[a-f0-9]{64}', str(value.get('generation')))
                or not re.fullmatch('[a-f0-9]{32}', str(value.get('managerInvocation')))
                or not re.fullmatch('[a-f0-9-]{36}', str(value.get('bootId')))):
            fail('start-identity-invalid')
        self.nodes[role] = value
        self.active_start_stage = 'fcp-get-node'
        deadline = time.monotonic() + self.remaining(180)
        while True:
            try:
                # FCP's general GetNode timeout is longer than this startup budget. Bound
                # the complete attempt, including observation, handshake and trickled frames.
                with runtime.absolute_deadline(deadline - time.monotonic()):
                    with self.client(role) as client:
                        value['reference'] = runtime.interop.get_node_reference(client, 'node-identity')
                break
            except (OSError, runtime.RuntimeFailure, runtime.interop.InteropFailure) as error:
                if time.monotonic() >= deadline:
                    raise runtime.RuntimeFailure('workload-daemon-readiness-timeout') from error
                time.sleep(min(.2, max(0, deadline - time.monotonic())))
        self.active_start_stage = 'daemon-epoch'
        self.daemon_epochs[role] = bind_daemon(self.observe(role), self.expected_jdk_digests[role])
        self.active_start_stage = 'journal-node-start'
        self.emit('node-start', role=role, node_epoch=runtime.canonical_digest({key: value[key] for key in EPOCH})[7:39])
        self._journal_started_roles.add(role)
        self.active_start_role = None
        self.active_start_stage = None
        return value

    def connect(self):
        for role in runtime.ROLES[:-1]:
            with runtime.absolute_deadline(self.remaining(180)), self.client(role) as client, self.client('relay-no-apps') as peer:
                relay, node = self.nodes['relay-no-apps']['reference'], self.nodes[role]['reference']
                runtime.interop.add_peer(client, 'peer-add', relay)
                runtime.interop.add_peer(peer, 'peer-add', node)
                runtime.interop.wait_for_peer_connection(client, peer, node['identity'], relay['identity'], 150)

    def wait_restarted_sender_peer(self):
        """Require both ends of the sender's existing relay link after its JVM restart."""
        with (runtime.absolute_deadline(self.remaining(180)),
              self.client('candidate-sender') as sender,
              self.client('relay-no-apps') as relay):
            sender_ref = self.nodes['candidate-sender']['reference']
            relay_ref = self.nodes['relay-no-apps']['reference']
            runtime.interop.wait_for_peer_connection(sender, relay,
                sender_ref['identity'], relay_ref['identity'], 150)

    def capture_probe_target_roster(self):
        """Persist a pre-app active-target premise before any probe child runs."""
        if len(self.private['nodes']['candidate-sender']['apps']) != 2:
            return
        started = time.monotonic_ns()
        samples = {role: self.observe(role) for role in runtime.ROLES}
        finished = time.monotonic_ns()
        if finished <= started:
            fail('probe-target-window-invalid')
        self.initial_role_roster = kernel_roster(samples, self.expected_jdk_digests)
        self.initial_role_window = {'startedMonotonicNs': started, 'finishedMonotonicNs': finished}
        self.initial_sender_state = samples['candidate-sender'].get('stateDigest')

    def probe_observer_control(self):
        """Send one forbidden fixed method to the installed root controller."""
        if len(self.private['nodes']['candidate-sender']['apps']) != 2:
            return
        if (self.initial_role_roster is None or self.initial_role_window is None
                or not isinstance(self.initial_sender_state, str)):
            fail('observer-control-premise-missing')
        handle = self.handles['candidate-sender']
        request_raw = (b'{"method":"pr315-observer-control","handle":"'
                       + handle.encode() + b'"}\n')
        response_raw = b'{"error":"restricted-workload-request-failed"}\n'
        actor_pid = os.getpid()
        actor_start = int(Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19])
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(self.remaining(50))
            channel.connect(SOCKET)
            _pid, uid, _gid = struct.unpack('3i', channel.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
            if uid != 0:
                fail('observer-control-peer-not-root')
            channel.sendall(b'P')
            if channel.recv(1) != b'R':
                fail('observer-control-target-not-ready')
            channel.sendall(request_raw)
            raw = bytearray()
            while not raw.endswith(b'\n') and len(raw) <= len(response_raw):
                block = channel.recv(len(response_raw) + 1 - len(raw))
                if not block:
                    break
                raw.extend(block)
            if bytes(raw) != response_raw:
                fail('observer-control-denial-not-observed')
        if int(Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19]) != actor_start:
            fail('observer-control-actor-epoch-changed')
        value = {'schemaVersion': 1, 'kind': 'pr315-observer-control-denial-checkpoint',
                 'caseId': 'observer-control', 'actorPid': actor_pid,
                 'actorStartTicks': actor_start,
                 'roleKernelRoster': self.initial_role_roster,
                 'roleKernelRosterWindow': self.initial_role_window,
                 'senderStateBefore': self.initial_sender_state,
                 'requestDigest': hashlib.sha256(request_raw).hexdigest(),
                 'responseDigest': hashlib.sha256(response_raw).hexdigest()}
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        if len(raw) > 8192:
            fail('observer-control-checkpoint-size-limit')
        target = self.root / 'pr315-observer-control.private.json'
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def probe_arbitrary_endpoint(self):
        """Ask the actual controller to reject one fixed sibling-FCP selector."""
        if len(self.private['nodes']['candidate-sender']['apps']) != 2:
            return
        if self.initial_role_roster is None or self.initial_role_window is None:
            fail('arbitrary-endpoint-premise-missing')
        request_raw = (b'{"method":"pr315-arbitrary-endpoint","handle":"'
                       + self.handles['candidate-sender'].encode() + b'"}\n')
        response_raw = b'{"error":"restricted-workload-request-failed"}\n'
        actor_pid = os.getpid()
        actor_start = int(Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19])
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(self.remaining(50))
            channel.connect(SOCKET)
            _pid, uid, _gid = struct.unpack('3i', channel.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
            if uid != 0:
                fail('arbitrary-endpoint-peer-not-root')
            channel.sendall(b'P')
            if channel.recv(1) != b'R':
                fail('arbitrary-endpoint-target-not-ready')
            channel.sendall(request_raw)
            raw = bytearray()
            while not raw.endswith(b'\n') and len(raw) <= len(response_raw):
                block = channel.recv(len(response_raw) + 1 - len(raw))
                if not block:
                    break
                raw.extend(block)
            if bytes(raw) != response_raw:
                fail('arbitrary-endpoint-denial-not-observed')
        if int(Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19]) != actor_start:
            fail('arbitrary-endpoint-actor-epoch-changed')
        value = {'schemaVersion': 1, 'kind': 'pr315-arbitrary-endpoint-denial-checkpoint',
                 'caseId': 'arbitrary-endpoint', 'actorPid': actor_pid,
                 'actorStartTicks': actor_start,
                 'roleKernelRoster': self.initial_role_roster,
                 'roleKernelRosterWindow': self.initial_role_window,
                 'requestDigest': hashlib.sha256(request_raw).hexdigest(),
                 'responseDigest': hashlib.sha256(response_raw).hexdigest()}
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        if len(raw) > 8192:
            fail('arbitrary-endpoint-checkpoint-size-limit')
        target = self.root / 'pr315-arbitrary-endpoint.private.json'
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def retain_probe_checkpoint(self, selected, worker, administrator):
        """Durably retain the controller-kernel AppHost child before later workload faults."""
        if (selected.get('appId') != 'pr315-probe' or self.initial_role_roster is None
                or self.initial_role_window is None or not isinstance(worker, dict)
                or not isinstance(administrator, dict)
                or administrator.get('phase') != 'probe'
                or not isinstance(administrator.get('recordDigest'), str)
                or re.fullmatch('[0-9a-f]{64}', administrator['recordDigest']) is None):
            fail('probe-checkpoint-premise-missing')
        value = {'schemaVersion': 1, 'kind': 'pr315-observer-probe-kernel-checkpoint',
                 'appId': 'pr315-probe', 'bundleDigest': selected['bundleDigest'],
                 'roleKernelRoster': self.initial_role_roster,
                 'roleKernelRosterWindow': self.initial_role_window,
                 'senderStateBefore': self.initial_sender_state,
                 'probeWorker': worker,
                 'administratorRecordDigest': administrator['recordDigest']}
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        if len(raw) > 8192:
            fail('probe-checkpoint-size-limit')
        target = self.root / 'pr315-probe-kernel.private.json'
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def content_chk(self):
        """Insert only the helper-bound public CHK selected for this installed operation."""
        operation = self.next_operation()
        payload = runtime.fixed_pr315_payload(self.plan['producer']['sourceCommit'], operation)
        return runtime.Supervisor.content(self, 'candidate-sender', 'candidate-recipient',
            verify_local_source=True, operation=operation, payload=payload)

    def _fnp_sample(self, phase):
        try:
            sampler = getattr(self, 'counter_sampler', None)
            if sampler is None:
                self.fnp_sample_failure = {'phase': phase,
                                           'failureClass': 'administrator-sampler-unavailable'}
                return None
            value = sampler(phase)
        except (OSError, runtime.RuntimeFailure) as error:
            self.fnp_sample_failure = {'phase': phase, 'failureClass': type(error).__name__[:128]}
            return None
        if (not isinstance(value, dict) or set(value) != {'phase', 'managerInvocation', 'snapshot'}
                or value['phase'] != phase
                or value['managerInvocation'] != self.nodes['candidate-recipient']['managerInvocation']
                or not isinstance(value['snapshot'], dict)):
            self.fnp_sample_failure = {'phase': phase, 'failureClass': 'response-binding-rejected'}
            return None
        return value

    def provision_apps(self):
        for role in runtime.ROLES:
            handle = InstalledAppHandle(self, role)
            handle.host_bootstrap()
            status, contract = handle.request('GET', '/api/v1/platform/contract')
            selected = next(node for node in self.plan['nodes'] if node['role'] == role)
            if status != 200 or contract.get('contract', {}).get('contractVersion') != selected['contractVersion']:
                fail('product-api-binding-mismatch')
            status, inventory = handle.request('GET', '/api/v1/apps')
            if status != 200 or inventory.get('apps') != []:
                fail('initial-app-inventory-not-empty')
            selected_apps = self.private['nodes'][role]['apps']
            if not selected_apps:
                continue
            if (selected_apps[0]['appId'] != 'mail-prototype'
                    or role == 'relay-no-apps'):
                fail('app-selection-unsupported')
            status, installed = handle.request('POST', '/api/v1/apps/install', {'stagedDir': '/inputs/apps/mail-prototype'})
            if status != 201 or installed.get('app', {}).get('appId') != 'mail-prototype':
                fail('signed-app-install-not-admitted')
            status, _ = handle.request('POST', '/api/v1/apps/mail-prototype/start')
            if status not in {200, 201}:
                fail('signed-app-start-failed')
            handle.observe_worker()
            handle.refresh_session()
            self.apps[(role, 'mail-prototype')] = handle
            if role == 'candidate-sender' and len(selected_apps) == 2:
                probe = InstalledProbeAppHandle(self, role)
                probe.password = handle.password
                status, installed = probe.request('POST', '/api/v1/apps/install',
                    {'stagedDir': '/inputs/apps/pr315-probe'})
                if status != 201 or installed.get('app', {}).get('appId') != 'pr315-probe':
                    fail('signed-probe-install-not-admitted')
                status, _ = probe.request('POST', '/api/v1/apps/pr315-probe/start')
                if status not in {200, 201}:
                    fail('signed-probe-start-failed')
                worker = probe.observe_worker()
                if self.counter_sampler is None:
                    fail('probe-administrator-sampler-unavailable')
                administrator = self.counter_sampler('probe')
                self.retain_probe_checkpoint(selected_apps[1], worker, administrator)
                self.apps[(role, 'pr315-probe')] = probe

    def stop(self, role):
        # Stop remains usable after observer deadline; controller ownership scopes it.
        value = self.control.request('stop', self.handles[role])
        unlaunched = (value.get('state') == 'prepared' and role not in self.nodes
                      and role not in self._journal_started_roles
                      and set(value) == {'handle', 'state', 'generation', 'managerInvocation', 'bootId'}
                      and value['generation'] is None and value['managerInvocation'] is None
                      and re.fullmatch('[a-f0-9-]{36}', str(value['bootId'])) is not None)
        if (value.get('state') != 'quiescent' and not unlaunched
                or value.get('handle') != self.handles[role]):
            fail('role-quiescence-unestablished')
        if role in self.nodes:
            self._bound(role, value)
        self.daemon_epochs.pop(role, None)
        if role in self._journal_started_roles:
            self.emit('node-stop', role=role)
            self._journal_started_roles.remove(role)
        return value

    def restart(self, role):
        """New manager epoch over retained role data, without extending approved runtime."""
        before = dict(self.nodes[role])
        before_daemon = self.daemon_epochs[role]
        self.stop(role)
        after = self.start(role)
        if (before['generation'] == after['generation']
                 or before['managerInvocation'] == after['managerInvocation']
                 or before['bootId'] != after['bootId']
                 or self.daemon_epochs[role]['startTicks'] <= before_daemon['startTicks']):
            fail('restart-epoch-invalid')
        app = self.apps.get((role, 'mail-prototype'))
        if app is not None:
            app.host_bootstrap()
            status, value = app.request('GET', '/api/v1/apps')
            expected_apps = [selected['appId'] for selected in self.private['nodes'][role]['apps']]
            if status != 200 or [entry.get('appId') for entry in value.get('apps', [])] != expected_apps:
                fail('restart-installed-app-not-retained')
            status, value = app.request('GET', '/api/v1/apps/mail-prototype/runtime')
            if status != 200:
                fail('restart-app-runtime-unavailable')
            if value.get('runtime', {}).get('running') is not True:
                status, _ = app.request('POST', '/api/v1/apps/mail-prototype/start')
                if status not in {200, 201}:
                    fail('restart-app-start-failed')
            app.observe_worker()
            app.refresh_session()
            probe = self.apps.get((role, 'pr315-probe'))
            if probe is not None:
                # Sender restart rotates the host form password. The probe shares
                # that principal only after the Mail handle re-bootstraps this epoch.
                probe.password = app.password
                status, value = probe.request('GET', '/api/v1/apps/pr315-probe/runtime')
                if status != 200:
                    fail('restart-probe-runtime-unavailable')
                if value.get('runtime', {}).get('running') is not True:
                    status, _ = probe.request('POST', '/api/v1/apps/pr315-probe/start')
                    if status not in {200, 201}:
                        selected = status if type(status) is int and status in {
                            400, 401, 403, 404, 409, 429, 500, 503} else 0
                        fail('restart-probe-start-http-' + str(selected))
                probe.observe_worker()
        return after

    def restart_with_witness(self, role):
        """Bracket one actual manager/JVM restart with controller state observations."""
        started = time.monotonic_ns()
        before = self.observe(role)
        before_identity = principal_row(role, before, self.expected_jdk_digests[role],
                                        self.daemon_epochs[role])
        result = self.restart(role)
        after = self.observe(role)
        after_identity = principal_row(role, after, self.expected_jdk_digests[role],
                                       self.daemon_epochs[role])
        finished = time.monotonic_ns()
        if finished <= started:
            fail('restart-window-clock-invalid')
        self.restart_context = {
            'before': {'roleIdentity': before_identity, 'stateDigest': before.get('stateDigest'),
                       'deadlineNs': before.get('deadlineMonotonicNs'),
                       'observedMonotonicNs': before.get('observedMonotonicNs')},
            'after': {'roleIdentity': after_identity, 'stateDigest': after.get('stateDigest'),
                      'deadlineNs': after.get('deadlineMonotonicNs'),
                      'observedMonotonicNs': after.get('observedMonotonicNs')}}
        self.restart_window = {'startedMonotonicNs': started, 'finishedMonotonicNs': finished}
        return result

    def cleanup(self):
        complete = True
        for role in reversed(runtime.ROLES):
            try:
                self.stop(role)
            except (runtime.RuntimeFailure, OSError):
                complete = False
        self.emit('cleanup', outcome='pass' if complete else 'fail')
        return 'complete' if complete else 'reconciliation-required'

    def run_group_preparation(self, group, *, leave_running_for_administrator=False,
                              on_start_failure=None):
        """Prove the four installed role epochs without claiming positive content work."""
        if group not in ('output-symlink', 'output-fifo', 'output-hardlink',
                         'output-flood', 'output-replacement', 'role-boundary',
                         'authority', 'network-app', 'cancellation',
                         'controller-restart', 'deadline', 'revocation-running',
                         'setsid-double-fork', 'observer-death',
                         'role-readiness-diagnostic', 'lost-start-response') or (
                on_start_failure is not None and not callable(on_start_failure)):
            fail('workload-group-preparation-invalid')
        completed = False
        try:
            lost_start = None
            if group == 'lost-start-response':
                if (self.lost_start_sampler is None
                        or not callable(getattr(self.control, 'drop_start_response', None))):
                    fail('lost-start-observer-boundary-unavailable')
                self.remaining()
                prepared = self.lost_start_sampler('before')
                dropped = self.control.drop_start_response(self.handles['candidate-sender'])
                barrier = self.lost_start_sampler('intent')
                if (not isinstance(prepared, dict) or set(prepared) != {
                        'phase', 'role', 'observedMonotonicNs'}
                        or prepared['phase'] != 'lost-start-before'
                        or prepared['role'] != 'candidate-sender'
                        or type(prepared['observedMonotonicNs']) is not int
                        or not isinstance(dropped, dict) or set(dropped) != {
                        'requestDigest', 'sendStartedNs', 'sendFinishedNs'}
                        or not isinstance(barrier, dict) or set(barrier) != {
                        'phase', 'role', 'generation', 'managerInvocation',
                        'observedMonotonicNs'}
                        or barrier['phase'] != 'lost-start-intent'
                        or barrier['role'] != 'candidate-sender'
                        or not re.fullmatch('[0-9a-f]{64}', str(dropped['requestDigest']))
                        or not re.fullmatch('[0-9a-f]{64}', str(barrier['generation']))
                        or not re.fullmatch('[0-9a-f]{32}', str(barrier['managerInvocation']))
                        or type(dropped['sendStartedNs']) is not int
                        or type(dropped['sendFinishedNs']) is not int
                        or type(barrier['observedMonotonicNs']) is not int
                        or not 0 < prepared['observedMonotonicNs']
                            < dropped['sendStartedNs'] < dropped['sendFinishedNs']
                            < barrier['observedMonotonicNs']):
                    fail('lost-start-barrier-invalid')
                self.start('candidate-sender')
                if any(self.nodes['candidate-sender'][key] != barrier[key]
                       for key in ('generation', 'managerInvocation')):
                    fail('lost-start-duplicate-invocation')
                for role in runtime.ROLES[1:]:
                    self.start(role)
                lost_start = {'administratorBefore': prepared,
                              'droppedRequest': dropped,
                              'administratorBarrier': barrier}
            else:
                for role in runtime.ROLES:
                    self.start(role)
            started = time.monotonic_ns()
            samples = {role: self.observe(role) for role in runtime.ROLES}
            finished = time.monotonic_ns()
            if finished <= started:
                fail('kernel-roster-clock-invalid')
            result = {'profile': PROFILE, 'groupPreparation': group,
                      'topologyRoles': len(self.nodes), 'signedAppWorkers': 0,
                      'newEpoch': False, 'contentRetrieval': 'not-executed-group',
                      'roleKernelRoster': kernel_roster(samples, self.expected_jdk_digests),
                      'roleKernelRosterWindow': {'startedMonotonicNs': started,
                                                 'finishedMonotonicNs': finished}}
            if lost_start is not None:
                result['lostStartResponse'] = lost_start
            if group == 'authority':
                self.capture_probe_target_roster()
                self.probe_observer_control()
                self.probe_arbitrary_endpoint()
            if group == 'network-app':
                self.capture_probe_target_roster()
                self.provision_apps()
                result['signedAppWorkers'] = len(self.apps)
                result['probeAppKernelProcess'] = self.apps[
                    ('candidate-sender', 'pr315-probe')].observe_worker()
            completed = True
            return result
        except Exception:
            if getattr(self, 'active_start_role', None) is not None and on_start_failure is not None:
                try:
                    on_start_failure(self.active_start_role,
                                     getattr(self, 'active_start_stage', 'unavailable'))
                except (OSError, ValueError, runtime.RuntimeFailure):
                    pass
            raise
        finally:
            if (not completed or not leave_running_for_administrator) and self.cleanup() != 'complete':
                fail('terminal-reconciliation-required')

    def run_positive(self, *, leave_running_for_administrator=False, on_start_failure=None):
        """Exercise normal transports, retaining active roles only for administrator teardown."""
        if on_start_failure is not None and not callable(on_start_failure):
            fail('readiness-diagnostic-callback-invalid')
        completed = False
        try:
            for role in runtime.ROLES:
                self.start(role)
            self.connect()
            self.capture_probe_target_roster()
            self.probe_observer_control()
            self.probe_arbitrary_endpoint()
            self.provision_apps()
            self.content_chk()
            before = dict(self.nodes['candidate-sender'])
            after = self.restart_with_witness('candidate-sender')
            new_epoch = (before['generation'] != after['generation']
                         and before['managerInvocation'] != after['managerInvocation']
                         and before['bootId'] == after['bootId'])
            self.wait_restarted_sender_peer()
            before_fnp = self._fnp_sample('before')
            self.content_chk()
            after_fnp = self._fnp_sample('after') if before_fnp is not None else None
            app_started = time.monotonic_ns()
            app_worker = self.apps[('candidate-sender', 'mail-prototype')].observe_worker()
            probe_handle = self.apps.get(('candidate-sender', 'pr315-probe'))
            probe_worker = probe_handle.observe_worker() if probe_handle is not None else None
            app_finished = time.monotonic_ns()
            if app_finished <= app_started:
                fail('app-kernel-clock-invalid')
            roster_started = time.monotonic_ns()
            final_samples = {role: self.observe(role) for role in runtime.ROLES}
            roster_finished = time.monotonic_ns()
            if roster_finished <= roster_started:
                fail('kernel-roster-clock-invalid')
            result = {'profile': PROFILE, 'classification': 'synthetic-source-build-not-original-authority',
                    'topologyRoles': len(self.nodes), 'signedAppWorkers': len(self.apps),
                    'newEpoch': new_epoch,
                    'appKernelProcess': {'role': 'candidate-sender', 'provider': 'bubblewrap',
                        'hostPid': app_worker['hostPid'],
                        'namespacePid': app_worker['namespacePid'],
                        'processEpoch': app_worker['startTicks'],
                        'invocationId': app_worker['managerInvocation'],
                        'javaHostPid': app_worker['javaHostPid'],
                        'javaStartTicks': app_worker['javaStartTicks'],
                        'provenance': app_worker['provenance']},
                    'appKernelWindow': {'startedMonotonicNs': app_started,
                                        'finishedMonotonicNs': app_finished},
                    'probeAppKernelProcess': probe_worker,
                    'controlExchanges': dict(self.control_exchanges),
                    'contentEvidence': getattr(self, 'content_evidence', None),
                    'fnpCounterPair': ({'before': before_fnp, 'after': after_fnp}
                                       if before_fnp is not None and after_fnp is not None else None),
                    'fnpSampleFailure': getattr(self, 'fnp_sample_failure', None),
                    'restartContext': self.restart_context,
                    'restartWindow': self.restart_window,
                    'roleKernelRoster': kernel_roster(final_samples, self.expected_jdk_digests),
                    'roleKernelRosterWindow': {'startedMonotonicNs': roster_started,
                                               'finishedMonotonicNs': roster_finished},
                    'contentRetrieval': self.outcomes.get('network-chk')}
            completed = True
            return result
        except Exception:
            # The administrator must inspect the still-running role before cleanup.
            # A diagnostic failure never changes the original workload error.
            if getattr(self, 'active_start_role', None) is not None and on_start_failure is not None:
                try:
                    on_start_failure(self.active_start_role,
                                     getattr(self, 'active_start_stage', 'unavailable'))
                except (OSError, ValueError, runtime.RuntimeFailure):
                    pass
            raise
        finally:
            if (not completed or not leave_running_for_administrator) and self.cleanup() != 'complete':
                fail('terminal-reconciliation-required')

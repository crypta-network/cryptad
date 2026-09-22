"""Observer adapter for the fixed installed four-role workload profile.

No process is launched locally. Every connection and process sample belongs to the
controller-retained role invocation. This prospective path does not promote historical
same-UID observations, or establish original protected authority.
"""
from __future__ import annotations

import array
from contextlib import contextmanager
import http.client
import json
import os
from pathlib import Path
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
METHODS = {'start', 'observe', 'stop', 'connect-fcp', 'connect-http', 'bootstrap-mail'}
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
        descriptors = []
        channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            channel.settimeout(30)
            channel.connect(SOCKET)
            _, uid, _ = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != 0:
                fail('controller-peer-not-root')
            channel.sendall(json.dumps({'method': method, 'handle': handle}, separators=(',', ':')).encode() + b'\n')
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
                    return value, connected
                except BaseException:
                    connected.close()
                    raise
            if descriptors:
                fail('controller-unexpected-connection')
            return value
        except (OSError, ValueError, UnicodeError):
            fail('controller-transport-failed')
        finally:
            channel.close()
            for descriptor in descriptors:
                os.close(descriptor)


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
                        'startTicks': worker['startTicks'], 'javaHostPid': row['hostPid'],
                        'javaStartTicks': row['startTicks'], 'provenance': 'controller-kernel-sample'}
            if cursor['hostPid'] in visited:
                break
            visited.add(cursor['hostPid'])
            child = cursor
            cursor = processes.get(cursor['hostParentPid'])
            if cursor is None or cursor['startTicks'] > child['startTicks']:
                break
    fail('app-java-descendant-not-observed')


class InstalledWorkloadAdapter:
    """Finite observer orchestration over a root-prepared, immutable source-build selection.

    ``handoff`` and exact JDK executable digests come from the controller's retained
    selection, never candidate replies. The supplied journal retains its existing lease.
    Optional ``control`` permits isolated unit tests without an installed socket.
    """
    def __init__(self, plan, private_config, authorization, journal, handoff, expected_jdk_digests=None, *, control=None):
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
            if (not isinstance(apps, list) or len(apps) > 1
                    or any(app.get('appId') != 'mail-prototype' for app in apps)
                    or (role == 'relay-no-apps' and apps)
                    or (role in {'candidate-sender', 'candidate-recipient'} and len(apps) != 1)):
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
        self.root, self.deadline, self.operations = root, retained_deadline(handoff, maximum), 0
        self.nodes, self.apps, self.outcomes = {}, {}, {}
        self._journal_started_roles = set()
        self.catalog_prepared = None

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
        return value

    def connection(self, role, endpoint):
        if endpoint not in {'fcp', 'http'}:
            fail('endpoint-not-approved')
        self.remaining()
        self.observe(role)
        value, connected = self.control.request('connect-' + endpoint, self.handles[role])
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
        self.remaining()
        value = self.control.request('start', self.handles[role])
        if (value.get('handle') != self.handles[role] or value.get('state') != 'running'
                or not re.fullmatch('[a-f0-9]{64}', str(value.get('generation')))
                or not re.fullmatch('[a-f0-9]{32}', str(value.get('managerInvocation')))
                or not re.fullmatch('[a-f0-9-]{36}', str(value.get('bootId')))):
            fail('start-identity-invalid')
        self.nodes[role] = value
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
        self.emit('node-start', role=role, node_epoch=runtime.canonical_digest({key: value[key] for key in EPOCH})[7:39])
        self._journal_started_roles.add(role)
        return value

    def connect(self):
        for role in runtime.ROLES[:-1]:
            with runtime.absolute_deadline(self.remaining(180)), self.client(role) as client, self.client('relay-no-apps') as peer:
                relay, node = self.nodes['relay-no-apps']['reference'], self.nodes[role]['reference']
                runtime.interop.add_peer(client, 'peer-add', relay)
                runtime.interop.add_peer(peer, 'peer-add', node)
                runtime.interop.wait_for_peer_connection(client, peer, node['identity'], relay['identity'], 150)

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
            if len(selected_apps) != 1 or selected_apps[0]['appId'] != 'mail-prototype' or role == 'relay-no-apps':
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
        if role in self._journal_started_roles:
            self.emit('node-stop', role=role)
            self._journal_started_roles.remove(role)
        return value

    def restart(self, role):
        """New manager epoch over retained role data, without extending approved runtime."""
        before = dict(self.nodes[role])
        self.stop(role)
        after = self.start(role)
        if (before['generation'] == after['generation']
                or before['managerInvocation'] == after['managerInvocation']
                or before['bootId'] != after['bootId']):
            fail('restart-epoch-invalid')
        app = self.apps.get((role, 'mail-prototype'))
        if app is not None:
            app.host_bootstrap()
            status, value = app.request('GET', '/api/v1/apps')
            if status != 200 or [entry.get('appId') for entry in value.get('apps', [])] != ['mail-prototype']:
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
        return after

    def cleanup(self):
        complete = True
        for role in reversed(runtime.ROLES):
            try:
                self.stop(role)
            except (runtime.RuntimeFailure, OSError):
                complete = False
        self.emit('cleanup', outcome='pass' if complete else 'fail')
        return 'complete' if complete else 'reconciliation-required'

    def run_positive(self):
        """Exercise normal four-role transports and real app startup; always stop owned roles."""
        try:
            for role in runtime.ROLES:
                self.start(role)
            self.connect()
            self.provision_apps()
            runtime.Supervisor.content(self, 'candidate-sender', 'candidate-recipient')
            before = dict(self.nodes['candidate-sender'])
            after = self.restart('candidate-sender')
            new_epoch = (before['generation'] != after['generation']
                         and before['managerInvocation'] != after['managerInvocation']
                         and before['bootId'] == after['bootId'])
            runtime.Supervisor.content(self, 'candidate-sender', 'candidate-recipient')
            return {'profile': PROFILE, 'classification': 'synthetic-source-build-not-original-authority',
                    'topologyRoles': len(self.nodes), 'signedAppWorkers': len(self.apps),
                    'newEpoch': new_epoch,
                    'contentRetrieval': self.outcomes.get('network-chk')}
        finally:
            if self.cleanup() != 'complete':
                fail('terminal-reconciliation-required')

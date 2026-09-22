#!/usr/bin/python3
"""Tokenless fixed role controller. This service has no original-provider credentials.

Only the observer UID can use the private socket. Each request names an already retained
role handle and one fixed method. Service death stops bound role units through systemd.
"""
import array
from contextlib import contextmanager
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
import sys
import time
import urllib.parse

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
import restricted_workload as workload

SOCKET = Path('/run/cryptad-workload/control.sock')
METHODS = frozenset({'start', 'observe', 'stop', 'connect-fcp', 'connect-http', 'bootstrap-mail'})


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


def bootstrap(handle):
    """Resolve dynamic app origin only from this role's current daemon launch proof."""
    with workload.locked(), deadline():
        campaign, role, record = workload.retained(handle)
        workload.admit(campaign)
        workload.exact(role, record, workload.manager(role, 'show'))
        from restricted_workload_storage import verify_installed_app
        launch = workload.read(workload.ROOT / 'roles' / role / 'launch.json')
        verify_installed_app(workload.ROOT / 'state' / role / 'data/node/apps/installed/mail-prototype',
            launch['mailIdentity'], workload.ROOT / 'authority' / (role + '-app-snapshot'),
            min(time.monotonic() + 5, campaign['deadlineMonotonicNs'] / 1e9))
        from restricted_workload_network import connect, _connect_port, HTTP_PORT
        status, headers, _body = _http(connect(role, 'http'),
            '/apps/mail-prototype/?cryptadIsolatedLaunch', {'Accept': 'text/html'})
        if status not in (301, 302, 303, 307, 308):
            workload.reject('app-launch-unavailable')
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
        from restricted_workload_app import require_app_listener
        runtime_status, _headers, runtime_body = _http(connect(role, 'http'),
            '/api/v1/apps/mail-prototype/runtime', {'Accept': 'application/json'})
        if runtime_status != 200:
            workload.reject('app-runtime-unavailable')
        binding = require_app_listener(role, runtime_object(runtime_body), selected.port)
        origin = 'http://127.0.0.1:' + str(selected.port)
        status, _headers, body = _http(_connect_port(role, selected.port),
            '/.well-known/cryptad-bootstrap.json', {'Accept': 'application/json', 'Origin': origin,
                'X-Crypta-App-Bootstrap-Nonce': fragment['cryptadBootstrapNonce'][0]})
        value = json.loads(body)
        if (status != 200 or not isinstance(value, dict) or value.get('uiOrigin') != origin
                or not isinstance(value.get('browserSessionToken'), str)
                or not 1 <= len(value['browserSessionToken']) <= 4096):
            workload.reject('app-bootstrap-invalid')
        workload.current(campaign)
        workload.exact(role, record, workload.manager(role, 'show'))
        runtime_status, _headers, runtime_body = _http(connect(role, 'http'),
            '/api/v1/apps/mail-prototype/runtime', {'Accept': 'application/json'})
        if (runtime_status != 200 or require_app_listener(role, runtime_object(runtime_body),
                                                        selected.port) != binding):
            workload.reject('app-worker-changed')
        # A private response; never inserted into an acceptance/public result.
        return {key: value.get(key) for key in ('uiOrigin', 'browserSessionToken', 'browserSessionExpiresAt')}


def serve(connection, expected_uid):
    credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
    _pid, uid, _gid = struct.unpack('3i', credentials)
    if uid != expected_uid:
        workload.reject('peer-denied')
    connection.settimeout(5)
    raw = bytearray()
    while b'\n' not in raw:
        block = connection.recv(257 - len(raw))
        if not block:
            workload.reject('request-incomplete')
        raw.extend(block)
        if len(raw) > 256:
            workload.reject('request-limit')
    if raw[-1:] != b'\n' or raw.count(b'\n') != 1:
        workload.reject('request-framing-invalid')
    selected = request(bytes(raw[:-1]))
    method, handle = selected['method'], selected['handle']
    if method.startswith('connect-'):
        with workload.connect(handle, method.removeprefix('connect-')) as stream:
            rights = array.array('i', [stream.fileno()])
            connection.sendmsg([b'{"status":"connected"}\n'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
    else:
        operation = {'start': workload.start, 'stop': workload.stop, 'observe': workload.observe,
                     'bootstrap-mail': bootstrap}[method]
        result = operation(handle)
        raw = json.dumps(result, separators=(',', ':'), allow_nan=False).encode() + b'\n'
        if len(raw) > 1024 * 1024:
            workload.reject('response-limit')
        connection.sendall(raw)
    return method


def handle_request(connection, observer_uid):
    """Contain adversarial protocol errors to this request, preserving owned siblings."""
    try:
        with deadline(45):
            serve(connection, observer_uid)
        return True
    except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
        try:
            connection.sendall(b'{"error":"restricted-workload-request-failed"}\n')
        except OSError:
            pass
        return False


def main():
    if len(sys.argv) != 1 or not sys.flags.isolated or not sys.flags.no_site or os.geteuid() != 0:
        workload.reject('fixed-entry-required')
    os.environ.clear()
    os.umask(0o077)
    workload.secured(Path(__file__))
    # Verify the same immutable installed code/dependency closure as the existing resolver.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'restricted'))
    import installation
    installation.verify_execution()
    observer = pwd.getpwnam('cryptad-soak')
    if (workload.ROOT / 'campaign.json').exists():
        workload.reconcile()
    if SOCKET.exists() or SOCKET.is_symlink():
        workload.reject('socket-reconciliation-required')
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(SOCKET))
    SOCKET.chmod(0o600)
    os.chown(SOCKET, observer.pw_uid, observer.pw_gid)
    server.listen(8)
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
        workload.reconcile()
        SOCKET.unlink()


if __name__ == '__main__':
    try:
        result = main()
    except Exception:
        result = 1
    raise SystemExit(result)

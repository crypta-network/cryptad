#!/usr/bin/python3
"""Closed four-role network fabric, called only by the installed workload controller.

The caller holds its exclusive workload lease for setup, connections and teardown. It must
establish whole-role cgroup quiescence before teardown; namespace PID checks below are an
additional check, not a replacement. Partial setup is retained and never automatically adopted.
This module grants no external RPC and does not authenticate original workload authorization.
"""
import array
import json
import os
from pathlib import Path
import select
import signal
import socket
import stat
import subprocess

ROLES = ('candidate-sender', 'candidate-recipient', 'previous', 'relay-no-apps')
# Only this controller authority directory is private. Its workload-layout parent may be
# traversable so fixed role UIDs can reach their own separately protected input/state roots.
ROOT = Path('/var/lib/cryptad-restricted-workload/authority')
NETNS_ROOT = Path('/run/netns')
IP = '/usr/sbin/ip'
NFT = '/usr/sbin/nft'
SWITCH = 'cryptad-role-switch'
FNP_PORT, FCP_PORT, HTTP_PORT = 19400, 19401, 19402
ENDPOINTS = {'fcp': FCP_PORT, 'http': HTTP_PORT}
MAX_STATE_BYTES = 8192


class NetworkBoundaryError(ValueError):
    """Fixed diagnostics that never disclose candidate output or private topology."""


def _reject():
    raise NetworkBoundaryError('restricted-workload-network-rejected')


def namespace(role):
    if role not in ROLES:
        _reject()
    return 'cryptad-role-' + role


def address(role):
    if role not in ROLES:
        _reject()
    return '10.231.0.' + str(ROLES.index(role) + 1)


def _peers(role):
    return ROLES[:-1] if role == ROLES[-1] else (ROLES[-1],)


def _secure_directory(path):
    for item in (path, *path.parents):
        info = item.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            _reject()


def _guard():
    if os.geteuid() != 0:
        _reject()
    _secure_directory(ROOT)
    if ROOT.stat().st_mode & 0o077:
        _reject()


def _boot():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def _run(arguments, script=None):
    """Run only internal fixed commands, retaining bounded failure details privately.

    The existing helper owns its process-group cleanup and pipe budgets. Diagnostics never
    enter the exception message or controller protocol; only administrator evidence readers
    may inspect ``private_diagnostics``. The nft script payload is deliberately not retained.
    """
    from bounded_process import run

    captured = {}
    def retain(_stdout, stderr):
        captured['stderr'] = stderr.decode('utf-8', errors='replace')[:2048]
    try:
        return run(arguments, payload=script.encode('utf-8') if script is not None else None,
                   timeout=15, output_limit=8192, diagnostic_sink=retain,
                   environment={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'})
    except (OSError, ValueError, subprocess.SubprocessError) as cause:
        selected, remaining = [], 2048
        for argument in arguments[:32]:
            part = argument[:remaining]
            selected.append(part)
            remaining -= len(part)
            if not remaining:
                break
        known = {'bounded_process_input_exceeded', 'bounded_process_deadline_exceeded',
                 'bounded_process_output_exceeded', 'bounded_process_failed',
                 'bounded_process_diagnostics_failed'}
        error = NetworkBoundaryError('restricted-workload-network-command-failed')
        error.private_diagnostics = {'arguments': selected, 'stderr': captured.get('stderr', ''),
            'failureClass': str(cause) if str(cause) in known else type(cause).__name__[:128]}
        raise error from None


def _save(state, initial=False):
    _guard()
    target = ROOT / ('network.json' if initial else 'network.new')
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(state, stream, sort_keys=True, separators=(',', ':'))
        stream.flush()
        os.fsync(stream.fileno())
    if not initial:
        os.replace(target, ROOT / 'network.json')
    descriptor = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _load():
    _guard()
    descriptor = os.open(ROOT / 'network.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor) as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077
                or info.st_nlink != 1 or info.st_size > MAX_STATE_BYTES):
            _reject()
        state = json.loads(stream.read(MAX_STATE_BYTES + 1))
    if (set(state) != {'version', 'bootId', 'phase', 'pending', 'namespaces'}
            or state['version'] != 1 or state['bootId'] != _boot()
            or state['phase'] not in {'preparing', 'ready', 'stopping', 'retained'}
            or not isinstance(state['namespaces'], dict)
            or set(state['namespaces']) - {SWITCH, *(namespace(role) for role in ROLES)}):
        _reject()
    return state


def _namespace_identity(name):
    _secure_directory(NETNS_ROOT)
    descriptor = os.open(NETNS_ROOT / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if info.st_uid != 0:
            _reject()
        return [info.st_dev, info.st_ino]
    finally:
        os.close(descriptor)


def role_rules(role):
    """Own loopback plus the exact UDP peer matrix; no established-connection bypass."""
    peers = ', '.join(address(peer) for peer in _peers(role))
    own = address(role)
    return ('table inet cryptad_role {\n'
            ' chain input { type filter hook input priority 0; policy drop;\n'
            '  iifname "lo" accept\n'
            f'  iifname "data0" ip saddr {{ {peers} }} ip daddr {own} '
            f'udp sport {FNP_PORT} udp dport {FNP_PORT} accept\n }}\n'
            ' chain output { type filter hook output priority 0; policy drop;\n'
            '  oifname "lo" accept\n'
            f'  oifname "data0" ip saddr {own} ip daddr {{ {peers} }} '
            f'udp sport {FNP_PORT} udp dport {FNP_PORT} accept\n }}\n'
            ' chain forward { type filter hook forward priority 0; policy drop; }\n}\n')


def switch_rules():
    lines = ['table bridge cryptad_switch {',
             ' chain input { type filter hook input priority 0; policy drop; }',
             ' chain output { type filter hook output priority 0; policy drop; }',
             ' chain forward { type filter hook forward priority 0; policy drop;']
    for index, role in enumerate(ROLES[:-1]):
        for source, target, src_role, dst_role in ((index, 3, role, ROLES[-1]),
                                                 (3, index, ROLES[-1], role)):
            prefix = f'  iifname "sw{source}" oifname "sw{target}" '
            lines.append(prefix + 'ether type arp accept')
            lines.append(prefix + f'ether type ip ip saddr {address(src_role)} '
                         f'ip daddr {address(dst_role)} ip protocol udp '
                         f'udp sport {FNP_PORT} udp dport {FNP_PORT} accept')
    return '\n'.join([*lines, ' }', '}', ''])


def setup():
    """Create the one fixed fabric, retaining intent before each namespace mutation.

    No role service may start until this returns. Existing names or retained state reject
    setup before mutation; on failure the controller must retain reconciliation state.
    """
    _guard()
    names = (SWITCH, *(namespace(role) for role in ROLES))
    if (ROOT / 'network.json').exists() or any(os.path.lexists(NETNS_ROOT / name) for name in names):
        _reject()
    state = {'version': 1, 'bootId': _boot(), 'phase': 'preparing',
             'pending': None, 'namespaces': {}}
    _save(state, initial=True)
    for name in names:
        state['pending'] = name
        _save(state)
        _run([IP, 'netns', 'add', name])
        state['namespaces'][name] = _namespace_identity(name)
        state['pending'] = None
        _save(state)
    _run([IP, '-n', SWITCH, 'link', 'add', 'br0', 'type', 'bridge'])
    _run([IP, 'netns', 'exec', SWITCH, NFT, '-f', '-'], switch_rules())
    for index, role in enumerate(ROLES):
        name = namespace(role)
        # Both ends are born in task namespaces: no transient host-side interface exists.
        _run([IP, '-n', SWITCH, 'link', 'add', f'sw{index}', 'type', 'veth',
              'peer', 'name', 'data0', 'netns', name])
        _run([IP, '-n', SWITCH, 'link', 'set', f'sw{index}', 'master', 'br0'])
        _run([IP, 'netns', 'exec', name, NFT, '-f', '-'], role_rules(role))
        _run([IP, '-n', name, 'address', 'add', address(role) + '/32', 'dev', 'data0'])
        _run([IP, '-n', name, 'link', 'set', 'lo', 'up'])
        _run([IP, '-n', name, 'link', 'set', 'data0', 'up'])
        _run([IP, '-n', SWITCH, 'link', 'set', f'sw{index}', 'up'])
        # Linux requires the route's output device to be administratively up.
        # Both namespace filters already exist; the switch bridge remains down.
        for peer in _peers(role):
            _run([IP, '-n', name, 'route', 'add', address(peer) + '/32', 'dev', 'data0'])
    _run([IP, '-n', SWITCH, 'link', 'set', 'br0', 'up'])
    state['phase'] = 'ready'
    _save(state)


def teardown():
    """Remove only recorded, unchanged, empty namespaces; keep the terminal record.

    Caller first verifies all owned role cgroups empty. A lost namespace-add response or
    changed mount identity requires explicit controller reconciliation, never blind deletion.
    """
    state = _load()
    if state['pending'] is not None:
        _reject()
    for name, identity in state['namespaces'].items():
        if _namespace_identity(name) != identity:
            _reject()
        # Avoid unbounded stdout capture: any byte means a live member, regardless of PID count.
        with subprocess.Popen([IP, 'netns', 'pids', name], stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL,
                              env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'}) as process:
            try:
                if not select.select([process.stdout], [], [], 15)[0]:
                    process.kill()
                    _reject()
                occupied = bool(process.stdout.read(1))
                if occupied:
                    process.kill()
                code = process.wait(timeout=15)
                if occupied or code != 0:
                    _reject()
            except BaseException:
                process.kill()
                process.wait()
                raise
    state['phase'] = 'stopping'
    _save(state)
    for name in list(reversed(state['namespaces'])):
        if _namespace_identity(name) != state['namespaces'][name]:
            _reject()
        state['pending'] = name
        _save(state)
        _run([IP, 'netns', 'delete', name])
        del state['namespaces'][name]
        state['pending'] = None
        _save(state)
    state['phase'] = 'retained'
    _save(state)


def connect(role, endpoint):
    """Return a TCP socket for fixed FCP/HTTP in a current retained role namespace.

    Fork confines setns to a short-lived privileged child. Neither a namespace path, PID,
    address nor dynamic port can enter through this API. Original authority and the retained
    manager invocation are checked by the owning controller before and after this operation.
    """
    if endpoint not in ENDPOINTS:
        _reject()
    return _connect_port(role, ENDPOINTS[endpoint])


def _connect_port(role, port):
    """Internal transport for controller-resolved app bootstrap, never an RPC selector.

    Only the fixed semantic bootstrap operation may select a dynamic port after validating
    the current role's launch response, nonce and origin. The socket remains in that role's
    network namespace; candidate redirects cannot select host or sibling management sockets.
    """
    name = namespace(role)
    if type(port) is not int or not 1 <= port <= 65535:
        _reject()
    state = _load()
    if state['phase'] != 'ready' or state['pending'] is not None:
        _reject()
    expected = state['namespaces'].get(name)
    if expected is None or _namespace_identity(name) != expected:
        _reject()
    descriptor = os.open(NETNS_ROOT / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    info = os.fstat(descriptor)
    if [info.st_dev, info.st_ino] != expected:
        os.close(descriptor)
        _reject()
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    pid = None
    transferred = []
    try:
        parent.settimeout(12)
        pid = os.fork()
        if pid == 0:
            try:
                parent.close()
                signal.alarm(10)
                os.setns(descriptor, 0x40000000)  # CLONE_NEWNET only.
                with socket.create_connection(('127.0.0.1', port), timeout=8) as connected:
                    child.sendmsg([b'1'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                           array.array('i', [connected.fileno()]))])
                os._exit(0)
            except BaseException:
                os._exit(1)
        child.close()
        body, controls, flags, _ = parent.recvmsg(1, socket.CMSG_SPACE(array.array('i').itemsize),
                                                 socket.MSG_CMSG_CLOEXEC)
        for level, kind, raw in controls:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                _reject()
            values = array.array('i')
            values.frombytes(raw)
            transferred.extend(values)
        _, status = os.waitpid(pid, 0)
        pid = None
        if body != b'1' or flags & socket.MSG_CTRUNC or len(transferred) != 1 or status != 0:
            _reject()
        if _namespace_identity(name) != expected:
            _reject()
        result = socket.socket(fileno=transferred.pop())
        result.settimeout(8)
        return result
    except (OSError, ValueError):
        raise NetworkBoundaryError('restricted-workload-connect-failed') from None
    finally:
        if pid is not None and pid > 0:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)
        for received in transferred:
            os.close(received)
        parent.close()
        child.close()
        os.close(descriptor)

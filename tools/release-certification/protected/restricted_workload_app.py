"""Bind fixed Mail or budget workers and UI listeners to one owned role kernel scope.

The installed controller calls this while holding the workload lease and an absolute
request deadline, before and after its semantic bootstrap exchange. Candidate runtime JSON
is only a hint. This projection proves process/namespace/ancestry and socket ownership;
it does not authenticate application classes or make candidate telemetry truthful.
"""
import os
from pathlib import Path
import re
import time
from pr320_budget_contract import PROSPECTIVE_EXECUTION_CLASSES as COMPLETE_STORAGE_CLASSES

import restricted_workload as workload

PROC = Path('/proc')
MAX_TASKS = 512
MAX_FDS = 1024
MAX_TCP_BYTES = 512 * 1024
MAX_SECONDS = 5
IDENTITY_FIELDS = ('hostPid', 'hostParentPid', 'startTicks', 'pidNamespace', 'namespacePids',
                   'executableDigest', 'noNewPrivileges', 'effectiveCapabilities')


def _reject():
    workload.reject('app-kernel-binding-unavailable')


def _time(deadline):
    if time.monotonic() >= deadline:
        _reject()


def _read(path, maximum, deadline):
    """Only internally derived cgroup/proc files enter this bounded reader."""
    _time(deadline)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        pieces, remaining = [], maximum + 1
        while remaining:
            _time(deadline)
            block = os.read(descriptor, min(65536, remaining))
            if not block:
                break
            pieces.append(block)
            remaining -= len(block)
        if remaining == 0:
            _reject()
        return b''.join(pieces).decode('ascii')
    finally:
        os.close(descriptor)


def _members(role, deadline):
    root = workload.group(role)
    # Delegation is forbidden. Nested membership would require a separately reviewed profile.
    with os.scandir(root) as entries:
        for count, entry in enumerate(entries, 1):
            _time(deadline)
            if count > 256 or entry.is_dir(follow_symlinks=False):
                _reject()
    values = _read(root / 'cgroup.procs', 8192, deadline).split()
    if (not values or len(values) > MAX_TASKS
            or any(re.fullmatch('[1-9][0-9]{0,9}', value) is None for value in values)):
        _reject()
    return sorted(set(map(int, values)))


def _epoch(process):
    return {name: process[name] for name in IDENTITY_FIELDS}


def _descendant(pid, ancestor, processes):
    seen = set()
    for _ in range(64):
        if pid == ancestor:
            return True
        if pid in seen or pid not in processes:
            return False
        seen.add(pid)
        pid = processes[pid]['hostParentPid']
    return False


def _budget_cwd(pid, app_id, deadline):
    """Bind the identical fixture executable to its fixed AppHost-installed bundle root."""
    path = PROC / str(pid) / 'cwd'
    expected = '/node/data/node/apps/installed/' + app_id
    _time(deadline)
    before = path.stat()
    if os.readlink(path) != expected:
        _reject()
    _time(deadline)
    after = path.stat()
    if ((before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or os.readlink(path) != expected):
        _reject()
    return [before.st_dev, before.st_ino]


def _listener(daemon, port, deadline):
    """Resolve only the daemon's own loopback listener, never an arbitrary candidate path."""
    path = PROC / str(daemon['hostPid'])
    selected = []
    # The reference JDK uses an IPv4-mapped AF_INET6 socket even for an explicit
    # InetAddress(127.0.0.1). It therefore appears in tcp6, while the logical endpoint
    # and namespace-confined connector remain IPv4 loopback. No :: or wildcard binds pass.
    for table, loopback in (('tcp', '0100007F'),
                            ('tcp6', '0000000000000000FFFF00000100007F')):
        try:
            rows = _read(path / 'net' / table, MAX_TCP_BYTES, deadline).splitlines()
        except FileNotFoundError:
            if table == 'tcp6':
                continue
            raise
        wanted = loopback + ':' + format(port, '04X')
        if not rows or len(rows) > 4097:
            _reject()
        for row in rows[1:]:
            fields = row.split()
            if len(fields) < 10:
                _reject()
            if fields[1].upper() == wanted and fields[3] == '0A':
                if re.fullmatch('[1-9][0-9]{0,19}', fields[9]) is None:
                    _reject()
                selected.append(int(fields[9]))
    # Ambiguous SO_REUSEPORT listeners do not satisfy this fixed binding.
    if len(selected) != 1:
        _reject()
    inode, found = selected[0], False
    with os.scandir(path / 'fd') as entries:
        for count, entry in enumerate(entries, 1):
            _time(deadline)
            if count > MAX_FDS or not entry.name.isdecimal():
                _reject()
            try:
                target = os.readlink(path / 'fd' / entry.name)
            except FileNotFoundError:
                continue
            if target == 'socket:[' + str(inode) + ']':
                found = True
    if not found:
        _reject()
    return inode


def _projection(process):
    return {name: process[name] for name in ('hostPid', 'startTicks', 'pidNamespace')}


def require_app_listener(role, runtime_dict, port):
    """Return a private, fixed binding for current Mail JVM, daemon and UI listener.

    ``runtime_dict`` is the untrusted ``runtime`` member from the fixed Mail runtime API;
    its PID is interpreted in the outer daemon namespace, never as a host PID selector.
    The caller supplies the dynamic port only after validating the fixed launch redirect.
    No returned process identifiers belong in public acceptance output.
    """
    deadline = time.monotonic() + MAX_SECONDS
    if (role not in workload.ROLES or type(port) is not int or not 1024 <= port <= 65535
            or not isinstance(runtime_dict, dict) or runtime_dict.get('running') is not True
            or type(runtime_dict.get('pid')) is not int
            or not 1 <= runtime_dict['pid'] <= 2147483647):
        _reject()
    sandbox = runtime_dict.get('sandbox')
    if (not isinstance(sandbox, dict) or sandbox.get('provider') != 'bubblewrap'
            or sandbox.get('active') is not True):
        _reject()
    try:
        launch = workload.read(workload.ROOT / 'roles' / role / 'launch.json')
        java_digest = launch.get('javaDigest')
        if not isinstance(java_digest, str) or re.fullmatch('sha256:[0-9a-f]{64}', java_digest) is None:
            _reject()
        uid = workload.account(role).pw_uid
        processes = {}
        for pid in _members(role, deadline):
            _time(deadline)
            try:
                processes[pid] = workload._process(pid, role, uid)
            except (FileNotFoundError, ProcessLookupError):
                continue
        daemons = [value for value in processes.values()
                   if value['executableDigest'] == java_digest and len(value['namespacePids']) == 2]
        if len(daemons) != 1:
            _reject()
        daemon = daemons[0]
        workers = [value for value in processes.values()
                   if len(value['namespacePids']) >= 2 and value['namespacePids'][1] == runtime_dict['pid']]
        if len(workers) != 1:
            _reject()
        worker = workers[0]
        # AppHost may report its outer launcher or an interpreter-managed descendant.
        # Both hints use the daemon-visible PID (NSpid[1]), including nested processes.
        outer_worker = len(worker['namespacePids']) == 2
        if (worker['hostPid'] == daemon['hostPid']
                or (worker['pidNamespace'] == daemon['pidNamespace']) != outer_worker
                or not _descendant(worker['hostPid'], daemon['hostPid'], processes)):
            _reject()
        app_jvms = [value for value in processes.values()
                    if value['executableDigest'] == java_digest
                    and len(value['namespacePids']) >= 3
                    and value['pidNamespace'] != daemon['pidNamespace']
                    and _descendant(value['hostPid'], worker['hostPid'], processes)]
        if len(app_jvms) != 1:
            _reject()
        app = app_jvms[0]
        if any(value['noNewPrivileges'] is not True or value['effectiveCapabilities'] != 0
               for value in (daemon, worker, app)):
            _reject()
        inode = _listener(daemon, port, deadline)
        # Recheck each scoped ancestor as well as leaf identities; a reparent or PID reuse
        # invalidates the relation. Cgroup membership is independently rechecked by _process.
        required = set()
        for origin in (worker['hostPid'], app['hostPid']):
            cursor = origin
            for _ in range(64):
                required.add(cursor)
                if cursor == daemon['hostPid']:
                    break
                cursor = processes[cursor]['hostParentPid']
            else:
                _reject()
        for pid in sorted(required):
            _time(deadline)
            if _epoch(workload._process(pid, role, uid)) != _epoch(processes[pid]):
                _reject()
        if _listener(daemon, port, deadline) != inode:
            _reject()
        _time(deadline)
        return {'daemon': _projection(daemon), 'worker': _projection(worker),
                'appJvm': _projection(app), 'listenerInode': inode}
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        _reject()


def require_budget_listener(role, app_id, runtime_dict, port):
    """Bind one selected non-Java budget fixture without reusing Mail JVM semantics.

    The app id is accepted only to index the controller-created launch record.  The caller
    obtains it from the retained PR-317 roster, never from request bytes.  AppHost's reported
    daemon-namespace PID is treated as a hint; the actual signed fixture executable, ancestry,
    nested namespace, cgroup, daemon and listener epochs are independently observed here.
    """
    deadline = time.monotonic() + MAX_SECONDS
    if (role != 'candidate-sender'
            or app_id not in ('feed-reader', 'budget-importer',
                              'budget-no-trust', 'budget-no-fetch')
            or type(port) is not int or not 1024 <= port <= 65535
            or not isinstance(runtime_dict, dict) or runtime_dict.get('running') is not True
            or type(runtime_dict.get('pid')) is not int
            or not 1 <= runtime_dict['pid'] <= 2147483647):
        _reject()
    sandbox = runtime_dict.get('sandbox')
    if (not isinstance(sandbox, dict) or sandbox.get('provider') != 'bubblewrap'
            or sandbox.get('active') is not True):
        _reject()
    try:
        launch = workload.read(workload.ROOT / 'roles' / role / 'launch.json')
        if (launch.get('executionClass') not in ('pr317-namespace-bound-composed-budget-v1',
                'pr318-fixed-window-partial-store-v1', 'pr319-composed-budget-restart-diagnostics-v1', *COMPLETE_STORAGE_CLASSES)
                or set(launch.get('budgetAppIdentities', {})) != {
                    'feed-reader', 'budget-importer', 'budget-no-trust', 'budget-no-fetch'}):
            _reject()
        java_digest = launch.get('javaDigest')
        executable_digest = (launch.get('budgetExecutableDigests', {}).get(app_id)
            if launch.get('executionClass') in COMPLETE_STORAGE_CLASSES else launch.get('budgetExecutableDigest'))
        bundle = launch['budgetAppIdentities'][app_id]
        if (re.fullmatch('sha256:[0-9a-f]{64}', str(java_digest)) is None
                or re.fullmatch('sha256:[0-9a-f]{64}', str(executable_digest)) is None
                or not isinstance(bundle, dict)
                or set(bundle) != {'digest', 'fileCount', 'sizeBytes'}
                or re.fullmatch('sha256:[0-9a-f]{64}', str(bundle.get('digest'))) is None):
            _reject()
        uid = workload.account(role).pw_uid
        processes = {}
        for pid in _members(role, deadline):
            _time(deadline)
            try:
                processes[pid] = workload._process(pid, role, uid)
            except (FileNotFoundError, ProcessLookupError):
                continue
        daemons = [value for value in processes.values()
                   if value['executableDigest'] == java_digest
                   and len(value['namespacePids']) == 2]
        if len(daemons) != 1:
            _reject()
        daemon = daemons[0]
        leaders = [value for value in processes.values()
                   if len(value['namespacePids']) >= 2
                   and value['namespacePids'][1] == runtime_dict['pid']]
        if len(leaders) != 1:
            _reject()
        leader = leaders[0]
        outer_leader = len(leader['namespacePids']) == 2
        if (leader['hostPid'] == daemon['hostPid']
                or (leader['pidNamespace'] == daemon['pidNamespace']) != outer_leader
                or not _descendant(leader['hostPid'], daemon['hostPid'], processes)):
            _reject()
        fixtures = [value for value in processes.values()
                    if value['executableDigest'] == executable_digest
                    and len(value['namespacePids']) >= 3
                    and value['pidNamespace'] != daemon['pidNamespace']
                    and _descendant(value['hostPid'], leader['hostPid'], processes)]
        if len(fixtures) != 1:
            _reject()
        fixture = fixtures[0]
        if launch.get('executionClass') in COMPLETE_STORAGE_CLASSES and app_id in ('feed-reader', 'budget-importer'):
            if _read(PROC / str(fixture['hostPid']) / 'cmdline', 4096, deadline).split(b'\0') != [
                    b'/usr/bin/python3', b'-I', b'-S', b'-B', b'lib/pr320-budget-process-client.py', b'']:
                _reject()
        bundle_cwd = _budget_cwd(fixture['hostPid'], app_id, deadline)
        if (leader['mountNamespaceIdentity'] != fixture['mountNamespaceIdentity']
                or leader['userNamespaceIdentity'] != fixture['userNamespaceIdentity']):
            _reject()
        if any(value['noNewPrivileges'] is not True
               or value['effectiveCapabilities'] != 0
               for value in (daemon, leader, fixture)):
            _reject()
        inode = _listener(daemon, port, deadline)
        required = set()
        for origin in (leader['hostPid'], fixture['hostPid']):
            cursor = origin
            for _ in range(64):
                required.add(cursor)
                if cursor == daemon['hostPid']:
                    break
                cursor = processes[cursor]['hostParentPid']
            else:
                _reject()
        for pid in sorted(required):
            _time(deadline)
            if _epoch(workload._process(pid, role, uid)) != _epoch(processes[pid]):
                _reject()
        if _listener(daemon, port, deadline) != inode:
            _reject()
        _time(deadline)
        return {'daemon': _projection(daemon),
                'worker': {'appHostLeader': _projection(leader),
                           'fixtureProcess': _projection(fixture),
                           'listenerInode': inode,
                           'bundleCwdIdentity': bundle_cwd,
                           'bundleDigest': bundle['digest'],
                           'executableDigest': executable_digest}}
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        _reject()

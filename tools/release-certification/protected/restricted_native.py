"""Host-UID separation for the two fixed private maintenance native invocations.

The installed owner supplies authority in process, never through request JSON or environment.
Only a copied per-invocation input set reaches the native account. Native output is untrusted.
"""
from contextlib import contextmanager
from contextvars import ContextVar
import os
from pathlib import Path
import stat
import tempfile
import sys
import hashlib
import json
import itertools
import re
import secrets
import shutil
import time

if sys.platform == 'linux':
    import fcntl
    import grp
    import pwd

from bounded_process import run as bounded_run

ROOT = Path('/var/lib/cryptad-restricted-native')
UNIT = 'cryptad-restricted-native.service'
CGROUP = '/system.slice/' + UNIT
_ACTIVE = ContextVar('restricted_native_owner', default=False)


class NativeBoundaryError(ValueError):
    """Closed diagnostics; child output and local paths are never public."""


def _reject():
    raise NativeBoundaryError('restricted-native-boundary-rejected')


def _secured(path, directory=False):
    path = Path(path)
    for parent in (path, *path.parents):
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            _reject()
    if directory and not path.is_dir():
        _reject()


@contextmanager
def owning_boundary(context=None, check=None):
    """Enter only from the installed, authenticated fixed-operation owner."""
    if sys.platform != 'linux' or os.geteuid() != 0:
        _reject()
    _secured(ROOT, directory=True)
    inherited = _ACTIVE.get()
    token = _ACTIVE.set((context, check) if context is not None else inherited or (None, None))
    try:
        yield
    finally:
        _ACTIVE.reset(token)


def _native_identity():
    if sys.platform != 'linux':
        _reject()
    user = pwd.getpwnam('cryptad-native')
    group = grp.getgrnam('cryptad-native')
    if (user.pw_uid == 0 or group.gr_gid == 0 or user.pw_gid != group.gr_gid
            or user.pw_shell not in ('/usr/sbin/nologin', '/sbin/nologin', '/bin/false')
            or any(row.gr_mem and user.pw_name in row.gr_mem for row in grp.getgrall())):
        _reject()
    return user.pw_uid, group.gr_gid


def _copy_identity(info):
    return tuple(getattr(info, field) for field in (
        'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def _copy_owner(info, *, ancestor=False):
    # A root-owned sticky ancestor protects a root-owned, nonwritable selected child.
    # The source root and every copied member have no sticky-directory exception.
    if info.st_uid != 0 or (info.st_mode & 0o022 and not (
            ancestor and stat.S_ISDIR(info.st_mode) and info.st_mode & stat.S_ISVTX)):
        _reject()


def _copy(source, target, uid, gid, budget, depth=0, *, deadline=None, trusted_source=False):
    """Copy through pinned descriptors; reject changed bindings before accepting a tree."""
    def check():
        if deadline is not None and time.monotonic() >= deadline:
            raise NativeBoundaryError('restricted-native-deadline-exceeded')

    def unchanged(parent, name, descriptor, before):
        check()
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (_copy_identity(before) != _copy_identity(os.fstat(descriptor))
                or _copy_identity(before) != _copy_identity(current)):
            _reject()

    def member(parent, name, destination, level):
        check()
        budget[1] += 1
        if level > 32 or budget[1] > 65536:
            _reject()
        pinned = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            before = os.fstat(pinned)
            if trusted_source:
                _copy_owner(before)
            if stat.S_ISDIR(before.st_mode):
                descriptor = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                     | os.O_CLOEXEC, dir_fd=pinned)
                try:
                    with os.scandir(descriptor) as entries:
                        names = [entry.name for entry in itertools.islice(entries, 65537 - budget[1])]
                    if len(names) + budget[1] > 65536:
                        _reject()
                    destination.mkdir(mode=0o700)
                    os.chown(destination, uid, gid)
                    for child in sorted(names):
                        member(descriptor, child, destination / child, level + 1)
                    unchanged(parent, name, pinned, before)
                finally:
                    os.close(descriptor)
            elif stat.S_ISREG(before.st_mode) and before.st_nlink == 1:
                # Reserve the actual pinned inode's bytes before opening it for any read.
                budget[0] += before.st_size
                if budget[0] > 4 * 1024**3:
                    _reject()
                descriptor = os.open('/proc/self/fd/' + str(pinned),
                                     os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
                try:
                    if _copy_identity(os.fstat(descriptor)) != _copy_identity(before):
                        _reject()
                    with destination.open('xb') as output:
                        remaining = before.st_size
                        while remaining:
                            check()
                            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
                            if not chunk:
                                _reject()
                            output.write(chunk)
                            remaining -= len(chunk)
                        if os.read(descriptor, 1):
                            _reject()
                    unchanged(parent, name, pinned, before)
                finally:
                    os.close(descriptor)
                destination.chmod(0o500 if before.st_mode & 0o111 else 0o400)
                os.chown(destination, uid, gid)
            else:
                _reject()
        finally:
            os.close(pinned)

    source = Path(os.path.abspath(source))
    descriptors = []
    anchors = []
    try:
        parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        descriptors.append(parent)
        if trusted_source:
            _copy_owner(os.fstat(parent), ancestor=True)
        for name in source.parts[1:-1]:
            check()
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                            | os.O_CLOEXEC, dir_fd=parent)
            descriptors.append(child)
            info = os.fstat(child)
            if trusted_source:
                _copy_owner(info, ancestor=True)
                if os.fstat(parent).st_mode & 0o022:
                    _copy_owner(info)
            anchors.append((parent, name, child, info))
            parent = child
        member(parent, source.name, Path(target), depth)
        for parent, name, descriptor, before in reversed(anchors):
            # Ancestors can have unrelated children added; binding and ownership must persist.
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid')
            if any(getattr(before, field) != getattr(current, field)
                   or getattr(before, field) != getattr(os.fstat(descriptor), field)
                   for field in fields):
                _reject()
        check()
    except OSError as exc:
        raise NativeBoundaryError('restricted-native-boundary-rejected') from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _collect(source, target, *, deadline=None):
    raw = _read_output(source, 32768, deadline=deadline)
    # The destination is chosen by the owning projection implementation, never native output.
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                _reject()
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def _write(path, value, mode=0o400, gid=None):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    os.fchmod(descriptor, mode)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if gid is not None:
        os.chown(path, 0, gid)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _spec(arguments, operation):
    """Decode only the two existing owner-built commands; never relay a command list."""
    from restricted_native_launcher import validate_spec
    if operation not in ('package-api', 'app-projection'):
        _reject()
    command = list(arguments)
    prefix = ['/usr/bin/prlimit', '--cpu=' + ('60' if operation == 'package-api' else '180'),
              '--fsize=8388608', '--nofile=128']
    if operation == 'app-projection':
        prefix += ['--as=4294967296']
    prefix += ['--', '/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session']
    if command[:len(prefix)] != prefix:
        _reject()
    command = command[len(prefix):]
    fixed = ['--ro-bind', '/usr', '/usr']
    if operation == 'app-projection':
        fixed += ['--symlink', 'usr/bin', '/bin']
    fixed += ['--ro-bind', '/lib', '/lib', '--ro-bind', '/lib64', '/lib64', '--proc', '/proc',
              '--dev', '/dev', '--size', '16777216', '--tmpfs', '/tmp']
    if command[:len(fixed)] != fixed:
        _reject()
    command = command[len(fixed):]
    bindings = {}
    while command and command[0] in ('--bind', '--ro-bind'):
        mode, source, destination, *command = command
        if (destination not in ('/jdk', '/tools', '/inputs', '/work') or destination[1:] in bindings
                or mode != ('--bind' if operation == 'app-projection' and destination == '/work' else '--ro-bind')):
            _reject()
        bindings[destination[1:]] = Path(source)
    if command[:2] != ['--chdir', '/work']:
        _reject()
    command = command[2:]
    # Historical package tools are appended after --chdir by the existing owner.
    if command[:1] == ['--ro-bind']:
        if operation != 'package-api' or len(command) < 3 or command[2] != '/tools':
            _reject()
        bindings['tools'] = Path(command[1])
        command = command[3:]
    if command[:1] != ['--']:
        _reject()
    command = command[1:]
    if operation == 'package-api':
        if 'tools' not in bindings:
            if command != ['/jdk/bin/java', '-Xmx128m', '-cp', '/work/cryptad.jar',
                           'network.crypta.platform.api.PackagedApiExport']:
                _reject()
            spec = {'operation': operation, 'historicalJars': []}
        else:
            if (len(command) != 6 or command[:3] != ['/jdk/bin/java', '-Xmx128m', '-cp']
                    or command[4:] != ['network.crypta.platform.devtools.HistoricalPackagedApiExport', '/work/cryptad.jar']):
                _reject()
            jars = command[3].split(':')
            if any(not name.startswith('/tools/lib/') for name in jars):
                _reject()
            spec = {'operation': operation, 'historicalJars': [name[len('/tools/lib/'):] for name in jars]}
        if set(bindings) != {'jdk', 'work'} | ({'tools'} if spec['historicalJars'] else set()):
            _reject()
    else:
        if len(command) < 2 or command[1] != 'subject-projection':
            _reject()
        options = {}
        tail = command[2:]
        if len(tail) % 2:
            _reject()
        for option, value in zip(tail[::2], tail[1::2]):
            if option in options:
                _reject()
            options[option] = value
        if options.pop('--private-root', None) != '/work' or options.pop('--output', None) != '/work/projection.json':
            _reject()
        spec = {'operation': operation, 'exporter': command[0], 'options': options}
        if set(bindings) != {'jdk', 'tools', 'inputs', 'work'}:
            _reject()
    validate_spec(spec)
    return spec, bindings


def _readonly_tree(path, gid, *, deadline=None):
    for directory, directories, files in os.walk(path):
        if deadline is not None and time.monotonic() >= deadline:
            _reject()
        os.chown(directory, 0, gid)
        os.chmod(directory, 0o550)
        for name in files:
            if deadline is not None and time.monotonic() >= deadline:
                _reject()
            selected = Path(directory) / name
            executable = selected.stat().st_mode & 0o111
            os.chown(selected, 0, gid)
            selected.chmod(0o550 if executable else 0o440)


def _manager(action, *, timeout=10):
    arguments = ['/usr/bin/systemctl', action, UNIT]
    if action == 'show':
        arguments += ['--property=InvocationID,ControlGroup,ActiveState,SubState,ExecMainStatus,Result']
    output = bounded_run(arguments, environment={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'},
                         timeout=timeout, output_limit=16384)
    if action != 'show':
        return None
    rows = dict(line.split('=', 1) for line in output.decode().splitlines() if '=' in line)
    if set(rows) != {'InvocationID', 'ControlGroup', 'ActiveState', 'SubState', 'ExecMainStatus', 'Result'}:
        _reject()
    return rows


def _quiesce():
    """Stop the fixed manager-owned cgroup, including escaped process groups, before reuse."""
    _manager('stop', timeout=20)
    state = _manager('show')
    if state['ActiveState'] not in ('inactive', 'failed') or state['ControlGroup'] not in ('', CGROUP):
        _reject()
    group = Path('/sys/fs/cgroup' + CGROUP)
    try:
        rows = dict(line.split() for line in (group / 'cgroup.events').read_text().splitlines())
        if rows.get('populated') != '0':
            _reject()
    except FileNotFoundError:
        if group.exists():
            _reject()


def _installation_identity():
    approval = Path('/etc/cryptad-certification/restricted-installation.json')
    _secured(approval)
    return 'sha256:' + hashlib.sha256(_read_output(approval, 1024 * 1024)).hexdigest()


def _execute(spec, bindings, *, timeout, output_limit):
    from restricted_native_launcher import tree_identity, validate_spec
    validate_spec(spec)
    context, check = _ACTIVE.get()
    if (not isinstance(context, dict) or set(context) != {'operationId', 'registrationDigest', 'bundleIdentity', 'deadlineMonotonic'}
            or re.fullmatch('[0-9a-f]{64}', str(context['operationId'])) is None
            or re.fullmatch('[0-9a-f]{64}', str(context['bundleIdentity'])) is None
            or re.fullmatch('sha256:[0-9a-f]{64}', str(context['registrationDigest'])) is None
            or type(context['deadlineMonotonic']) not in (float, int)):
        _reject()
    uid, gid = _native_identity()
    _secured(ROOT, directory=True)
    lock = os.open(ROOT / '.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    stage = None
    launched = False
    quiescent = False
    collected = False
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        history = list(itertools.islice(ROOT.iterdir(), 67))
        if len(history) >= 66 or sum(re.fullmatch('[0-9a-f]{64}', path.name) is not None
                                     for path in history) >= 64:
            _reject()
        retained_bytes = 0
        for previous in history:
            if re.fullmatch('[0-9a-f]{64}', previous.name) and previous.is_dir():
                manifest = previous / 'invocation.json'
                if not manifest.exists():
                    # Interrupted staging has no trusted size record: reserve the full budget.
                    retained_bytes += 4 * 1024**3
                elif not (previous / 'complete.json').exists():
                    if manifest.stat().st_size > 65536:
                        _reject()
                    retained = _json(manifest.read_bytes())
                    retained_bytes += sum(row['sizeBytes'] for row in retained['inputs'].values())
        if retained_bytes > 4 * 1024**3:
            _reject()
        if (ROOT / 'active.json').exists():
            raise NativeBoundaryError('restricted-native-reconciliation-required')
        if _manager('show')['ActiveState'] not in ('inactive', 'failed'):
            _reject()
        if check is not None:
            check()
        deadline = min(time.monotonic() + timeout, context['deadlineMonotonic'])
        if deadline <= time.monotonic():
            _reject()
        invocation = secrets.token_hex(32)
        stage = ROOT / invocation
        stage.mkdir(mode=0o750)
        stage.chmod(0o750)
        os.chown(stage, 0, gid)
        _write(stage / 'staging.json', {'schemaVersion': 1, 'invocation': invocation,
            'owner': context, 'spec': spec, 'deadlineMonotonic': deadline, 'status': 'staging'})
        budget = [0, 0]
        identities = {}
        for role, source in sorted(bindings.items()):
            _copy(source, stage / role, 0, gid, budget, deadline=deadline, trusted_source=True)
            _readonly_tree(stage / role, gid, deadline=deadline)
            identities[role] = tree_identity(stage / role, deadline=deadline)
        output = stage / 'output'
        output.mkdir(mode=0o700)
        os.chown(output, uid, gid)
        diagnostics = stage / 'diagnostics'
        diagnostics.mkdir(mode=0o700)
        os.chown(diagnostics, uid, gid)
        record = {'schemaVersion': 1, 'invocation': invocation, 'owner': context,
                  'spec': spec, 'inputs': identities, 'deadlineMonotonic': deadline,
                  'outputLimit': output_limit, 'profile': 'keyless-native-v1',
                  'installationDigest': _installation_identity()}
        _write(stage / 'invocation.json', record, mode=0o440, gid=gid)
        _write(ROOT / 'active.json', {'invocation': invocation}, mode=0o440, gid=gid)
        if check is not None:
            check()
        launched = True  # Lost manager response still requires unconditional owned stop.
        _manager('start', timeout=min(10, max(.1, deadline - time.monotonic())))
        state = _manager('show')
        identity = state['InvocationID']
        if (re.fullmatch('[0-9a-f]{32}', identity) is None
                or state['ControlGroup'] != CGROUP and not (state['ControlGroup'] == ''
                    and state['ActiveState'] == 'active' and state['SubState'] == 'exited')):
            _reject()
        _write(stage / 'manager.json', {'invocationId': identity, 'controlGroup': CGROUP})
        while True:
            if check is not None:
                check()
            if time.monotonic() >= deadline:
                raise NativeBoundaryError('restricted-native-deadline-exceeded')
            state = _manager('show', timeout=min(5, max(.1, deadline - time.monotonic())))
            if state['InvocationID'] != identity or state['ControlGroup'] not in ('', CGROUP):
                _reject()
            if state['SubState'] == 'exited' and state['ActiveState'] == 'active':
                if state['ExecMainStatus'] != '0' or state['Result'] != 'success':
                    _reject()
                break
            if state['ActiveState'] in ('inactive', 'failed'):
                _reject()
            time.sleep(.05)
        _quiesce()
        quiescent = True
        if check is not None:
            check()
        # No native process survives this point. All returned bytes remain untrusted.
        if set(path.name for path in output.iterdir()) != ({'stdout', 'complete.json', 'projection.json'}
                if spec['operation'] == 'app-projection' else {'stdout', 'complete.json'}):
            _reject()
        completion = _json(_read_output(output / 'complete.json', 4096, deadline=deadline))
        if completion != {'invocation': invocation, 'status': 'complete'}:
            _reject()
        result = _read_output(output / 'stdout', output_limit, allow_empty=True, deadline=deadline)
        if spec['operation'] == 'app-projection':
            _collect(output / 'projection.json', bindings['work'] / 'projection.json', deadline=deadline)
        _write(stage / 'complete.json', {'status': 'collected', 'invocationId': identity})
        collected = True
        return result
    except (OSError, ValueError, KeyError, TypeError):
        if stage is not None:
            try:
                _write(stage / 'failure.json', {'status': 'reconciliation-required'})
            except (OSError, ValueError):
                pass
        raise NativeBoundaryError('restricted-native-execution-failed') from None
    finally:
        try:
            if not launched and stage is not None:
                stage.chmod(0o700)
            if launched and not quiescent:
                _quiesce()
                quiescent = True
            if quiescent:
                if stage is not None:
                    stage.chmod(0o700)
                    if collected:
                        # Successful input copies are disposable only after proven quiescence.
                        # Immutable intent/input identities and bounded outputs remain retained.
                        for role in bindings:
                            shutil.rmtree(stage / role)
                (ROOT / 'active.json').unlink()
        except (OSError, ValueError):
            if stage is not None:
                try:
                    _write(stage / 'cleanup-failure.json',
                           {'status': 'reconciliation-required', 'stage': 'cleanup'})
                except (OSError, ValueError):
                    pass
            raise NativeBoundaryError('restricted-native-cleanup-failed') from None
        finally:
            os.close(lock)


def _read_output(source, maximum, *, allow_empty=False, deadline=None):
    """Descriptor-based single-member read with anchored ancestors and complete race checks."""
    deadline = time.monotonic() + 5 if deadline is None else deadline
    parents = []
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in Path(source).absolute().parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            parents.append((descriptor, part, os.fstat(child)))
            descriptor = child
        pinned = os.open(Path(source).name, os.O_PATH | os.O_NOFOLLOW, dir_fd=descriptor)
        fd = None
        try:
            before = os.fstat(pinned)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or not (0 if allow_empty else 1) <= before.st_size <= maximum):
                _reject()
            fd = os.open('/proc/self/fd/' + str(pinned), os.O_RDONLY | os.O_NONBLOCK)
            if (os.fstat(fd).st_dev, os.fstat(fd).st_ino) != (before.st_dev, before.st_ino):
                _reject()
            result = bytearray()
            while len(result) <= maximum:
                if time.monotonic() >= deadline:
                    _reject()
                block = os.read(fd, min(65536, maximum + 1 - len(result)))
                if not block:
                    break
                result.extend(block)
            current = os.stat(Path(source).name, dir_fd=descriptor, follow_symlinks=False)
            after = os.fstat(fd)
            fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            if len(result) != before.st_size or any(getattr(before, key) != getattr(after, key)
                    or getattr(before, key) != getattr(current, key) for key in fields):
                _reject()
            for parent, name, expected in parents:
                current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if (current.st_dev, current.st_ino, current.st_mode) != (expected.st_dev, expected.st_ino, expected.st_mode):
                    _reject()
            return bytes(result)
        finally:
            if fd is not None:
                os.close(fd)
            os.close(pinned)
    finally:
        os.close(descriptor)
        for parent, _, _ in reversed(parents):
            os.close(parent)


def run(arguments, *, environment, timeout=180, output_limit=32768, operation=None):
    """Run only fixed finite owner operations through the manager-started keyless unit."""
    if not _ACTIVE.get():
        if Path(__file__).resolve().is_relative_to('/opt'):
            _reject()
        return bounded_run(arguments, environment=environment, timeout=timeout, output_limit=output_limit)
    expected_environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': '/tmp', 'TMPDIR': '/tmp'}
    if operation == 'app-projection':
        expected_environment.update({'PATH': '/jdk/bin:/usr/bin:/bin', 'JAVA_HOME': '/jdk',
            'JAVA_OPTS': '-Xmx256m -XX:CompressedClassSpaceSize=64m -XX:ReservedCodeCacheSize=64m'})
    if environment != expected_environment:
        _reject()
    spec, bindings = _spec(arguments, operation)
    return _execute(spec, bindings, timeout=timeout, output_limit=output_limit)


def probe(*, bundle_identity=None):
    """Fixed internal harmless setup probe; never admitted through the runner protocol."""
    if bundle_identity is not None:
        context = {'operationId': secrets.token_hex(32), 'registrationDigest': 'sha256:' + '0' * 64,
                   'bundleIdentity': bundle_identity, 'deadlineMonotonic': time.monotonic() + 20}
        with owning_boundary(context=context):
            return _execute({'operation': 'probe'}, {}, timeout=20, output_limit=4096)
    if not _ACTIVE.get():
        _reject()
    return _execute({'operation': 'probe'}, {}, timeout=20, output_limit=4096)

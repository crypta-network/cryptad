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

if sys.platform == 'linux':
    import fcntl
    import grp
    import pwd

from bounded_process import run as bounded_run

ROOT = Path('/var/lib/cryptad-restricted/native')
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
def owning_boundary():
    """Enter only from the installed, authenticated fixed-operation owner."""
    if sys.platform != 'linux' or os.geteuid() != 0:
        _reject()
    _secured(ROOT, directory=True)
    token = _ACTIVE.set(True)
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


def _copy(source, target, uid, gid, budget, depth=0):
    """Copy a bounded regular tree without following links or retaining writable aliases."""
    budget[1] += 1
    if depth > 32 or budget[1] > 65536:
        _reject()
    if depth == 0 and any(parent.is_symlink() for parent in source.parents):
        _reject()
    info = source.lstat()
    if stat.S_ISDIR(info.st_mode):
        target.mkdir(mode=0o700)
        os.chown(target, uid, gid)
        for child in sorted(source.iterdir()):
            _copy(child, target / child.name, uid, gid, budget, depth + 1)
    elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
        budget[0] += info.st_size
        if budget[0] > 4 * 1024**3 or budget[1] > 65536:
            _reject()
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(descriptor)
            with os.fdopen(descriptor, 'rb', closefd=False) as stream, target.open('xb') as output:
                remaining = before.st_size
                while remaining:
                    chunk = stream.read(min(remaining, 1024 * 1024))
                    if not chunk:
                        _reject()
                    output.write(chunk)
                    remaining -= len(chunk)
                if stream.read(1):
                    _reject()
            after = os.fstat(descriptor)
            current = source.lstat()
            if any(getattr(before, field) != getattr(after, field)
                   or getattr(before, field) != getattr(current, field)
                   or getattr(before, field) != getattr(info, field)
                   for field in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
                _reject()
        finally:
            os.close(descriptor)
        target.chmod(0o500 if info.st_mode & 0o111 else 0o400)
        os.chown(target, uid, gid)
    else:
        _reject()


def _collect(source, target):
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 1 <= info.st_size <= 32768:
            _reject()
        raw = os.read(descriptor, 32769)
        if len(raw) != info.st_size:
            _reject()
    finally:
        os.close(descriptor)
    # The destination is chosen by the owning projection implementation, never native output.
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)


def run(arguments, *, environment, timeout=180, output_limit=32768):
    """Run existing finite bwrap commands after dropping the host UID, groups and capabilities.

    Offline repository fixtures retain their existing bwrap execution. Installed /opt code must
    have entered the owning boundary; neither a job flag nor an environment variable enables it.
    """
    if not _ACTIVE.get():
        if Path(__file__).resolve().is_relative_to('/opt'):
            _reject()
        return bounded_run(arguments, environment=environment, timeout=timeout, output_limit=output_limit)
    if sys.platform != 'linux' or os.geteuid() != 0 or not arguments or arguments[0] != '/usr/bin/prlimit':
        _reject()
    uid, gid = _native_identity()
    _secured('/usr/bin/setpriv')
    _secured('/usr/bin/bwrap')
    _secured(ROOT, directory=True)
    lock = os.open(ROOT / '.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with tempfile.TemporaryDirectory(prefix='invocation-', dir=ROOT) as temporary:
            stage = Path(temporary)
            stage.chmod(0o700)
            os.chown(stage, uid, gid)
            command = list(arguments)
            writable = None
            index = command.index('/usr/bin/bwrap') + 1
            budget = [0, 0]
            while index < len(command):
                if command[index] == '--':
                    break
                option = command[index]
                if option in ('--ro-bind', '--bind'):
                    source, destination = Path(command[index + 1]), command[index + 2]
                    if destination in ('/usr', '/lib', '/lib64'):
                        if option != '--ro-bind' or str(source) != destination:
                            _reject()
                    else:
                        if destination not in ('/jdk', '/tools', '/work', '/inputs'):
                            _reject()
                        copied = stage / destination[1:]
                        _copy(source, copied, uid, gid, budget)
                        command[index + 1] = str(copied)
                        if option == '--bind':
                            if destination != '/work' or writable is not None:
                                _reject()
                            writable = (copied / 'projection.json', source / 'projection.json')
                    index += 3
                else:
                    index += 1
            # setpriv changes the actual host identity before bwrap establishes user/mount/PID
            # namespaces. close_fds in the bounded launcher leaves only the three pipes.
            command = ['/usr/bin/setpriv', '--reuid=' + str(uid), '--regid=' + str(gid),
                       '--clear-groups', '--no-new-privs', '--bounding-set=-all',
                       '--inh-caps=-all', '--ambient-caps=-all', '--', *command]
            output = bounded_run(command, environment=environment, timeout=timeout, output_limit=output_limit)
            if writable is not None:
                _collect(*writable)
            return output
    except (OSError, ValueError, KeyError):
        raise NativeBoundaryError('restricted-native-execution-failed') from None
    finally:
        os.close(lock)

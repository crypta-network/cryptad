#!/usr/bin/python3
"""Fixed keyless service entry point. It accepts no command-line or request transport.

Only controller-owned records select one of two finite verification commands (or the fixed
bootstrap probe). This module imports no private owner, provider, CMS or test implementation.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

ROOT = Path('/var/lib/cryptad-restricted-native')
OPTIONS = {
    '--catalog': '/work/catalog', '--catalog-signature': '/work/catalogSignature',
    '--bundle': '/work/bundle', '--submission-file': '/work/submission',
    '--catalog-keys': '/inputs/catalog-keys', '--publisher-keys': '/inputs/publisher-keys',
    '--reviewer-keys': '/inputs/reviewer-keys', '--contract': '/inputs/contract',
    '--baseline-registry': '/inputs/baseline-registry',
}
REQUIRED = {'--catalog', '--catalog-signature', '--bundle', '--catalog-keys',
            '--publisher-keys', '--catalog-key-id', '--app-id'}


def reject():
    raise ValueError('restricted-native-launch-rejected')


def validate_spec(spec):
    if not isinstance(spec, dict):
        reject()
    operation = spec.get('operation')
    if operation == 'probe':
        if set(spec) != {'operation'}:
            reject()
    elif operation == 'package-api':
        if set(spec) != {'operation', 'historicalJars'} or not isinstance(spec['historicalJars'], list):
            reject()
        jars = spec['historicalJars']
        if (len(jars) > 128 or jars != sorted(set(jars))
                or any(not isinstance(name, str) or re.fullmatch('[A-Za-z0-9_.+-]+\\.jar', name) is None for name in jars)):
            reject()
    elif operation == 'app-projection':
        if set(spec) != {'operation', 'exporter', 'options'} or spec['exporter'] != '/tools/bin/crypta-app':
            reject()
        options = spec['options']
        if (not isinstance(options, dict) or not REQUIRED <= set(options)
                or not set(options) <= set(OPTIONS) | {'--catalog-key-id', '--app-id', '--federation-selection', '--federation-generation'}):
            reject()
        for key, value in options.items():
            if not isinstance(value, str) or len(value) > 256:
                reject()
            if key in OPTIONS and value != OPTIONS[key]:
                reject()
            if key in ('--catalog-key-id', '--app-id') and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', value) is None:
                reject()
            if key == '--federation-generation' and re.fullmatch('[1-9][0-9]{0,15}', value) is None:
                reject()
            if key == '--federation-selection':
                path = Path(value)
                if (not value.startswith('/work/federation/') or '..' in path.parts
                        or path.as_posix() != value or '\\' in value):
                    reject()
        for pair in ({'--contract', '--baseline-registry'}, {'--federation-selection', '--federation-generation'}):
            if set(options) & pair and not pair <= set(options):
                reject()
    else:
        reject()


def tree_identity(root, *, deadline=None):
    """Bounded complete regular-file roster including modes; no writable aliases."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        reject()
    result = hashlib.sha256()
    count, total, directory_count = 0, 0, 0
    for directory, directories, files in os.walk(root, followlinks=False):
        if deadline is not None and time.monotonic() >= deadline:
            reject()
        path = Path(directory)
        directory_count += 1
        directories.sort()
        if len(path.relative_to(root).parts) > 32 or directory_count > 65536:
            reject()
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            reject()
        result.update(('d:' + path.relative_to(root).as_posix() + '\n').encode())
        for name in directories:
            if (path / name).is_symlink():
                reject()
        for name in sorted(files):
            count += 1
            selected = path / name
            fd = os.open(selected, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                before = os.fstat(fd)
                total += before.st_size
                if (count > 65536 or total > 4 * 1024**3 or not stat.S_ISREG(before.st_mode)
                        or before.st_nlink != 1):
                    reject()
                digest = hashlib.sha256()
                size = 0
                while True:
                    if deadline is not None and time.monotonic() >= deadline:
                        reject()
                    block = os.read(fd, 1024 * 1024)
                    if not block:
                        break
                    size += len(block)
                    if size > before.st_size:
                        reject()
                    digest.update(block)
                after, current = os.fstat(fd), selected.lstat()
                fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
                if size != before.st_size or any(getattr(before, key) != getattr(after, key)
                        or getattr(before, key) != getattr(current, key) for key in fields):
                    reject()
                result.update(json.dumps([selected.relative_to(root).as_posix(), size,
                              bool(before.st_mode & 0o111), digest.hexdigest()], separators=(',', ':')).encode())
            finally:
                os.close(fd)
    return {'digest': 'sha256:' + result.hexdigest(), 'fileCount': count, 'sizeBytes': total}


def _trusted_read(path):
    for entry in (path, *path.parents):
        info = entry.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            reject()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 1 <= info.st_size <= 65536:
            reject()
        raw = os.read(fd, 65537)
        if len(raw) != info.st_size:
            reject()
    finally:
        os.close(fd)
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                reject()
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def command(record, stage):
    spec = record['spec']
    validate_spec(spec)
    operation = spec['operation']
    # No resolver mounts, host proc, management sockets, home or configuration enter this tree.
    sandbox = ['/usr/bin/bwrap', '--unshare-all', '--unshare-user', '--disable-userns',
        '--assert-userns-disabled', '--die-with-parent', '--new-session',
        '--cap-drop', 'ALL', '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
        '--ro-bind', '/lib', '/lib', '--ro-bind', '/lib64', '/lib64',
        '--proc', '/proc', '--dev', '/dev', '--bind', '/tmp/native-tmp', '/tmp']
    for role in sorted(record['inputs']):
        sandbox += ['--ro-bind', str(stage / role), '/' + role]
    sandbox += ['--bind', '/run/native-output', '/output',
                '--bind', '/tmp/native-scratch', '/scratch']
    environment = {'PATH': '/jdk/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': '/tmp', 'TMPDIR': '/tmp'}
    if operation == 'probe':
        child = ['/usr/bin/true']
    elif operation == 'package-api':
        sandbox += ['--chdir', '/work']
        jars = spec['historicalJars']
        child = ['/jdk/bin/java', '-Xmx128m', '-cp', ':'.join('/tools/lib/' + name for name in jars)
                 if jars else '/work/cryptad.jar', 'network.crypta.platform.devtools.HistoricalPackagedApiExport'
                 if jars else 'network.crypta.platform.api.PackagedApiExport']
        if jars:
            child += ['/work/cryptad.jar']
    else:
        sandbox += ['--chdir', '/work']
        environment.update({'JAVA_HOME': '/jdk',
            'JAVA_OPTS': '-Xmx256m -XX:CompressedClassSpaceSize=64m -XX:ReservedCodeCacheSize=64m'})
        child = [spec['exporter'], 'subject-projection']
        for key, value in sorted(spec['options'].items()):
            child += [key, value]
        child += ['--private-root', '/scratch', '--output', '/output/projection.json']
    # Generated tmpfs roots otherwise remain writable outside the quota-controlled mounts.
    # Nonrecursive remounts preserve the explicit /tmp, /scratch and /output bind mounts,
    # and fixed character-device binds still provide /dev/null and randomness.
    sandbox += ['--remount-ro', '/dev/pts', '--remount-ro', '/dev', '--remount-ro', '/']
    limits = ['/usr/bin/prlimit', '--cpu=' + ('60' if operation == 'package-api' else '180'),
              '--fsize=8388608', '--nofile=128']
    if operation == 'app-projection':
        limits += ['--as=4294967296']
    return limits + ['--', *sandbox, '--', *child], environment


def main():
    import pwd
    account = pwd.getpwnam('cryptad-native')
    if (len(sys.argv) != 1 or not sys.flags.isolated or not sys.flags.no_site
            or os.getuid() != account.pw_uid or os.geteuid() != account.pw_uid
            or os.getgid() != account.pw_gid or os.getegid() != account.pw_gid
            or any(group != account.pw_gid for group in os.getgroups())):
        reject()
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    if (any(int(status[key].strip(), 16) for key in ('CapEff', 'CapPrm', 'CapInh', 'CapAmb', 'CapBnd'))
            or status['NoNewPrivs'].strip() != '1'):
        reject()
    if not any(line.endswith(':/system.slice/cryptad-restricted-native.service')
               for line in Path('/proc/self/cgroup').read_text().splitlines()):
        reject()
    os.environ.clear()
    os.umask(0o077)
    os.chdir('/')
    # systemd supplies no activation descriptors to this unit; close anything except stdio.
    for name in os.listdir('/proc/self/fd'):
        if name.isdecimal() and int(name) > 2:
            try:
                os.close(int(name))
            except OSError:
                pass
    active = _trusted_read(ROOT / 'active.json')
    if set(active) != {'invocation'} or re.fullmatch('[0-9a-f]{64}', str(active['invocation'])) is None:
        reject()
    stage = ROOT / active['invocation']
    record = _trusted_read(stage / 'invocation.json')
    if (set(record) != {'schemaVersion', 'invocation', 'owner', 'spec', 'inputs', 'deadlineMonotonic', 'outputLimit', 'profile', 'installationDigest'}
            or record['schemaVersion'] != 1 or record['invocation'] != active['invocation']
            or record['profile'] != 'keyless-native-v1'
            or re.fullmatch('sha256:[0-9a-f]{64}', str(record['installationDigest'])) is None
            or not isinstance(record['inputs'], dict)
            or not set(record['inputs']) <= {'jdk', 'tools', 'work', 'inputs'}
            or type(record['outputLimit']) is not int or not 1 <= record['outputLimit'] <= 4 * 1024 * 1024):
        reject()
    for role, expected in record['inputs'].items():
        if tree_identity(stage / role, deadline=record['deadlineMonotonic']) != expected:
            reject()
    remaining = record['deadlineMonotonic'] - time.monotonic()
    if not 0 < remaining <= 180:
        reject()
    native_output = Path('/run/native-output')
    native_output.mkdir(mode=0o700)
    Path('/tmp/native-tmp').mkdir(mode=0o700)
    Path('/tmp/native-scratch').mkdir(mode=0o700)
    arguments, environment = command(record, stage)
    # The selected immutable installed module supplies concurrent bounded drains, not a provider.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from bounded_process import run
    def retain_diagnostics(stdout, stderr):
        # Never mounted into the candidate sandbox or collected into the public result.
        for name, raw in (('stdout', stdout), ('stderr', stderr)):
            fd = os.open(stage / 'diagnostics' / name,
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
    try:
        output = run(arguments, environment=environment, timeout=max(.01, remaining - .25),
                     output_limit=record['outputLimit'], diagnostic_sink=retain_diagnostics)
    except ValueError as failure:
        category = {'bounded_process_deadline_exceeded': 'deadline',
                    'bounded_process_output_exceeded': 'output-limit'}.get(str(failure), 'native-failed')
        fd = os.open(stage / 'output' / 'failure.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(json.dumps({'invocation': active['invocation'], 'stage': category}, separators=(',', ':')).encode())
            stream.flush()
            os.fsync(stream.fileno())
        raise
    # Candidate PID namespace termination is checked against the complete owned cgroup.
    # A wrapper that exits with a setsid descendant cannot reach output collection.
    group = Path('/sys/fs/cgroup/system.slice/cryptad-restricted-native.service/cgroup.procs')
    if set(group.read_text().split()) != {str(os.getpid())}:
        reject()
    expected = {'projection.json'} if record['spec']['operation'] == 'app-projection' else set()
    if set(path.name for path in native_output.iterdir()) != expected:
        reject()
    if expected:
        # This collector imports only the keyless adapter and never an owning verifier.
        from restricted_native import _read_output
        raw = _read_output(native_output / 'projection.json', 32768, deadline=record['deadlineMonotonic'])
        fd = os.open(stage / 'output' / 'projection.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    for name, raw in (('stdout', output), ('complete.json', json.dumps({
            'invocation': active['invocation'], 'status': 'complete'}, separators=(',', ':')).encode())):
        fd = os.open(stage / 'output' / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        # No exception, input excerpt or path reaches the journal.
        raise SystemExit(1) from None

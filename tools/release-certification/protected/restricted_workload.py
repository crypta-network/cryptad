"""Closed, controller-owned four-role workload lifecycle.

The API is internal to installed trusted code. It never accepts executable paths, unit
properties, PIDs or namespace names from an observer. Provisioning requires a root-owned
selection prepared by the owning authority; possession of this API is not original approval.
The restricted provider channel remains closed pending both installed acceptance contracts.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import select
import stat
import subprocess
import time

from restricted_native_launcher import tree_identity, _trusted_read

ROOT = Path('/var/lib/cryptad-restricted-workload')
ROLES = ('candidate-sender', 'candidate-recipient', 'previous', 'relay-no-apps')
PROFILE = 'debian13-systemd257-workload-v1'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}
MAX_SECONDS = 3600


class WorkloadError(ValueError):
    """A fixed diagnostic, never candidate output."""


class ProcessExitedDuringSample(ProcessLookupError):
    """Pidfd-confirmed exit: skip in rosters, reject when a required binding is lost."""


def reject(code='boundary-rejected'):
    raise WorkloadError('restricted-workload-' + code)


def secured(path, *, directory=False):
    path = Path(path)
    for entry in (path, *path.parents):
        info = entry.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            reject('untrusted-authority')
    if directory and not path.is_dir():
        reject('untrusted-authority')
    return path


def read(path):
    return _trusted_read(secured(path))


def execution_record_digest():
    path = secured(Path('/opt/cryptad-cross-version/restricted-execution.json'))
    checksum, size = hashlib.sha256(), 0
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 1 <= info.st_size <= 32 * 1024**2:
            reject('execution-record-invalid')
        while True:
            block = os.read(descriptor, 65536)
            if not block:
                break
            size += len(block)
            if size > info.st_size:
                reject('execution-record-changed')
            checksum.update(block)
        after = path.stat()
        if size != info.st_size or any(getattr(info, field) != getattr(after, field)
                for field in ('st_dev', 'st_ino', 'st_mtime_ns', 'st_ctime_ns')):
            reject('execution-record-changed')
        return checksum.hexdigest()
    finally:
        os.close(descriptor)


def write(path, value, *, create=False, mode=0o600):
    """Root-only durable replacement; a partial intent is never erased on failure."""
    secured(path.parent, directory=True)
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    if len(raw) > 65536:
        reject('record-limit')
    temporary = path.with_name('.' + path.name + '-' + secrets.token_hex(16))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'wb') as stream:
            # Publication permissions are part of the record contract, not the
            # administrator's umask (role launch records must remain readable).
            os.fchmod(stream.fileno(), mode)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if create:
            os.link(temporary, path, follow_symlinks=False)
            temporary.unlink()
        else:
            os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if temporary.exists():
            temporary.unlink()


def unit(role):
    if role not in ROLES:
        reject('role-invalid')
    return 'cryptad-workload@' + role + '.service'


def account(role):
    unit(role)
    row = pwd.getpwnam('cryptad-role-' + role)
    if row.pw_uid == 0 or row.pw_gid == 0 or row.pw_shell != '/usr/sbin/nologin':
        reject('role-account-invalid')
    return row


def boot():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


@contextmanager
def locked():
    if os.geteuid() != 0:
        reject('root-controller-required')
    secured(ROOT, directory=True)
    fd = os.open(ROOT / 'lease', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0:
            reject('lease-invalid')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def manager(role, operation):
    if operation not in {'start', 'stop', 'show'}:
        reject('manager-operation-invalid')
    command = ['/usr/bin/systemctl', operation, unit(role)]
    if operation == 'show':
        command += ['--property=InvocationID,ActiveState,SubState,ControlGroup,MainPID,Result', '--no-pager']
    result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                            env=ENV, timeout=35, check=True)
    if len(result.stdout) > 8192 or len(result.stderr) > 8192:
        reject('manager-output-limit')
    if operation == 'show':
        value = dict(line.split('=', 1) for line in result.stdout.decode().splitlines() if '=' in line)
        if set(value) != {'InvocationID', 'ActiveState', 'SubState', 'ControlGroup', 'MainPID', 'Result'}:
            reject('manager-observation-invalid')
        return value


def group(role):
    # The explicit Slice in the fixed template avoids systemd's default template slice.
    return Path('/sys/fs/cgroup/system.slice') / unit(role)


def quiescent(role):
    path = group(role)
    if not path.exists():
        return True
    values = dict(line.split() for line in (path / 'cgroup.events').read_text().splitlines())
    return values.get('populated') == '0'


def retained(handle):
    if not isinstance(handle, str) or re.fullmatch('[a-f0-9]{64}', handle) is None:
        reject('handle-invalid')
    campaign = read(ROOT / 'campaign.json')
    matches = [role for role in ROLES if campaign['handles'].get(role) == handle]
    if len(matches) != 1:
        reject('handle-unavailable')
    role = matches[0]
    record = read(ROOT / 'authority' / (role + '.json'))
    if record['handle'] != handle or record['campaign'] != campaign['generation']:
        reject('record-substituted')
    return campaign, role, record


def current(campaign):
    if campaign.get('state') != 'prepared':
        reject('preparation-incomplete')
    if campaign['bootId'] != boot():
        reject('boot-changed-reconciliation-required')
    if os.path.lexists(ROOT / 'revoked') or time.monotonic_ns() >= campaign['deadlineMonotonicNs']:
        reject('authority-expired-or-revoked')
    if execution_record_digest() != campaign['executionRecordDigest']:
        reject('installed-implementation-changed')
    selection = read(ROOT / 'selection.json')
    if hashlib.sha256(json.dumps(selection, sort_keys=True, separators=(',', ':')).encode()).hexdigest() != campaign['selectionDigest']:
        reject('selection-changed')


def admit(campaign):
    current(campaign)
    consumed = campaign.get('usedOperations', 0)
    if type(consumed) is not int or consumed >= campaign['maxOperations']:
        reject('operation-budget-exhausted')
    campaign['usedOperations'] = consumed + 1
    write(ROOT / 'campaign.json', campaign)


def launched(role, record, state):
    """Reconcile the manager's privileged ExecStartPre receipt after a lost response."""
    marker = read(ROOT / 'authority' / (role + '-start.json'))
    if (marker['generation'] != record['generation'] or marker['bootId'] != record['bootId']
            or marker['managerInvocation'] != state['InvocationID']):
        reject('launch-reconciliation-required')
    record.update(managerInvocation=marker['managerInvocation'], cgroupIdentity=marker['cgroupIdentity'])
    exact(role, record, state)
    return record


def exact(role, record, state):
    if (record['bootId'] != boot() or not record.get('managerInvocation')
            or state['InvocationID'] != record['managerInvocation']
            or state['ControlGroup'] != '/system.slice/' + unit(role)):
        reject('invocation-changed-reconciliation-required')
    info = group(role).stat()
    if [info.st_dev, info.st_ino] != record.get('cgroupIdentity'):
        reject('cgroup-changed-reconciliation-required')


def start(handle):
    """Return retained invocation promptly; never hold provider credentials for the soak."""
    with locked():
        campaign, role, record = retained(handle)
        admit(campaign)
        state = manager(role, 'show')
        if record['state'] == 'launching':
            launched(role, record, state)
            record['state'] = 'running'
            write(ROOT / 'authority' / (role + '.json'), record)
        if record['state'] == 'running':
            exact(role, record, state)
            if state['ActiveState'] == 'active':
                return summary(role, record)
            reject('running-service-lost')
        if record['state'] not in {'prepared', 'quiescent'}:
            reject('reconciliation-required')
        if state['ActiveState'] not in {'inactive', 'failed'} or not quiescent(role):
            reject('role-slot-busy')
        inputs = ROOT / 'roles' / role
        expected = read(inputs / 'launch.json')
        for name, identity in expected['inputs'].items():
            if tree_identity(inputs / name, deadline=campaign['deadlineMonotonicNs'] / 1e9) != identity:
                reject('input-substituted')
        current(campaign)
        record.update(state='launching', generation=secrets.token_hex(32), managerInvocation=None,
                      cgroupIdentity=None, stopReason=None)
        write(ROOT / 'authority' / (role + '.json'), record)
        # If this call/response is lost, intent remains launching. A retry cannot duplicate it.
        manager(role, 'start')
        state = manager(role, 'show')
        if (state['ActiveState'] != 'active' or re.fullmatch('[0-9a-f]{32}', state['InvocationID']) is None
                or state['ControlGroup'] != '/system.slice/' + unit(role)):
            reject('launch-reconciliation-required')
        launched(role, record, state)
        record.update(state='running')
        write(ROOT / 'authority' / (role + '.json'), record)
        try:
            current(campaign)
        except WorkloadError:
            _stop(role, record, 'authority-changed')
            raise
        return summary(role, record)


def summary(role, record):
    """Private observer handoff only; never uploaded as a public report."""
    return {key: record[key] for key in ('handle', 'state', 'generation', 'managerInvocation', 'bootId')}


def _stop(role, record, reason):
    state = manager(role, 'show')
    if state['ActiveState'] in {'inactive', 'failed'} and quiescent(role):
        record.update(state='quiescent', stopReason=reason)
        write(ROOT / 'authority' / (role + '.json'), record)
        return summary(role, record)
    if record['state'] == 'launching':
        launched(role, record, state)
    exact(role, record, state)
    record.update(state='stopping', stopReason=reason)
    write(ROOT / 'authority' / (role + '.json'), record)
    manager(role, 'stop')
    after = manager(role, 'show')
    if after['ActiveState'] not in {'inactive', 'failed'} or not quiescent(role):
        record['state'] = 'reconciliation-required'
        write(ROOT / 'authority' / (role + '.json'), record)
        reject('descendants-not-quiescent')
    record['state'] = 'quiescent'
    write(ROOT / 'authority' / (role + '.json'), record)
    return summary(role, record)


def stop(handle):
    """Ownership-only cleanup: deliberately independent of current execution approval."""
    with locked():
        _campaign, role, record = retained(handle)
        return _stop(role, record, 'requested')


def reconcile():
    """Stop observed owned invocations after controller/observer loss; retain uncertainty."""
    with locked():
        campaign = read(ROOT / 'campaign.json')
        failures = []
        for role in ROLES:
            try:
                _campaign, _role, record = retained(campaign['handles'][role])
                _stop(role, record, 'controller-reconciliation')
            except (OSError, ValueError, subprocess.SubprocessError):
                failures.append(role)
        if failures:
            reject('reconciliation-required')


def _process(pid, role, expected_uid):
    descriptor = os.pidfd_open(pid)
    try:
        result = _process_sample(pid, role, expected_uid)
        if select.select([descriptor], [], [], 0)[0]:
            raise ProcessExitedDuringSample('process-exited-during-sample')
        return result
    finally:
        os.close(descriptor)


def _process_sample(pid, role, expected_uid):
    """A fixed kernel-only projection. No cmdline, environment or caller-selected PID."""
    path = Path('/proc') / str(pid)
    before = (path / 'stat').read_text().rsplit(')', 1)[1].split()
    status = dict(line.split(':', 1) for line in (path / 'status').read_text().splitlines() if ':' in line)
    if (set(map(int, status['Uid'].split())) != {expected_uid}
            or (path / 'cgroup').read_text().strip() != '0::/system.slice/' + unit(role)):
        reject('process-scope-changed')
    executable = path / 'exe'
    digest = hashlib.sha256()
    with executable.open('rb') as source:
        executable_identity = os.fstat(source.fileno())
        size = 0
        for block in iter(lambda: source.read(1024 * 1024), b''):
            size += len(block)
            if size > 64 * 1024 * 1024:
                reject('executable-sample-limit')
            digest.update(block)
        after_executable = executable.stat()
        if ((executable_identity.st_dev, executable_identity.st_ino, executable_identity.st_size,
             executable_identity.st_mtime_ns, executable_identity.st_ctime_ns)
                != (after_executable.st_dev, after_executable.st_ino, after_executable.st_size,
                    after_executable.st_mtime_ns, after_executable.st_ctime_ns)):
            reject('process-executable-changed')
    after = (path / 'stat').read_text().rsplit(')', 1)[1].split()
    if before[19] != after[19]:
        reject('process-epoch-changed')
    return {'hostPid': pid, 'hostParentPid': int(before[1]),
            'pidNamespace': os.readlink(path / 'ns/pid'),
            'namespacePids': list(map(int, status['NSpid'].split())),
            'startTicks': int(before[19]), 'executableDigest': 'sha256:' + digest.hexdigest(),
            'rssBytes': int(status['VmRSS'].split()[0]) * 1024 if 'VmRSS' in status else None,
            'processThreads': int(status['Threads']), 'noNewPrivileges': status['NoNewPrivs'].strip() == '1',
            'effectiveCapabilities': int(status['CapEff'].strip(), 16)}


def observe(handle):
    with locked():
        campaign, role, record = retained(handle)
        admit(campaign)
        before = manager(role, 'show')
        exact(role, record, before)
        root = group(role)
        # No cgroup delegation is permitted. A nested group is a profile violation.
        if any(path.is_dir() for path in root.iterdir()):
            reject('unexpected-descendant-cgroup')
        pids = (root / 'cgroup.procs').read_text().split()
        if len(pids) > 512:
            reject('task-limit')
        processes, exited = [], 0
        for pid in sorted(set(map(int, pids))):
            try:
                processes.append(_process(pid, role, account(role).pw_uid))
            except (FileNotFoundError, ProcessLookupError):
                exited += 1
        exact(role, record, manager(role, 'show'))
        return {**summary(role, record), 'provenance': 'controller-kernel-sample',
                'processes': processes, 'exitedDuringSample': exited,
                'cgroupMemoryBytes': int((root / 'memory.current').read_text()),
                'cgroupTasks': int((root / 'pids.current').read_text())}


def connect(handle, endpoint):
    with locked():
        campaign, role, record = retained(handle)
        admit(campaign)
        exact(role, record, manager(role, 'show'))
        from restricted_workload_network import connect as connection
        result = connection(role, endpoint)
        try:
            current(campaign)
            exact(role, record, manager(role, 'show'))
            return result
        except BaseException:
            result.close()
            raise

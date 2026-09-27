#!/usr/bin/python3
"""Fixed unprivileged entry point for one of four installed role services."""
import os
from pathlib import Path
import pwd
import re
import hashlib
import json
import stat
import subprocess
import sys
import time

ROOT = Path('/var/lib/cryptad-restricted-workload')
ROLES = ('candidate-sender', 'candidate-recipient', 'previous', 'relay-no-apps')
PROBE_REQUEST = ROOT / 'probe-requests/candidate-sender.json'
PROBE_SOURCE = ROOT / 'probe-source/pr315_role_probe.py'
LIFECYCLE_PROBE_SOURCE = ROOT / 'probe-source/pr315_lifecycle_role_probe.py'
PARTIAL_LAUNCH_REQUEST = ROOT / 'probe-requests/previous.json'
PARTIAL_LAUNCH_RECORD = ROOT / 'state/previous/tmp/pr315-partial-launch-fault.json'
PARTIAL_LAUNCH_RELEASE = ROOT / 'state/previous/tmp/pr315-partial-launch-release.json'


def launcher_policy():
    """Closed prospective policy, included in every role's configuration identity.

    The historical product initializes its wrapper backend after crypto providers.
    The candidate sender also exhausted the 30-second wrapper handshake twice
    under TCG before its JVM could signal startup, while its role had no OOM or
    HotSpot fatal. Give only these two roles the measured startup allowance;
    daemon readiness and the retained campaign deadline do not change.
    """
    return {'revision': 'workload-launcher-policy-v35',
            'candidateRoleProbe': 'fixed-role-file-claims-network-resolver-output-origin-v16',
            'observerEndpointProbe': 'fixed-recipient-fcp-selector-v1',
            'networkDenialCounters': 'fixed-sibling-fcp-http-app-host-drop-v3',
            'hostNetworkCanary': 'fixed-guest-host-namespace-address-listener-v2',
            'resolverAuthorityProbe': 'fixed-installed-resolver-canary-v1',
            'hostileOriginProbe': 'fixed-candidate-browser-session-origin-denial-v1',
            'providerAuthorityProbe': 'fixed-installed-worker-synthetic-provider-credential-v2',
            'siblingAppProbe': 'fixed-signed-apphost-source-port-drop-v1',
            'resourceExhaustionProbe': 'fixed-signed-apphost-pids-admin-child-epochs-v2',
            'partialLaunchFault': 'fixed-previous-after-start-marker-before-daemon-v1',
            'stuckOutputProbe': 'fixed-role-fifo-held-writer-bounded-collector-v1',
            'lateChildProbe': 'fixed-role-child-after-root-stop-intent-v1',
            'retiredAuthorityProbe': 'sealed-stopped-guest-observer-good-bad-good-v1',
            'stalePidUidProbe': 'fixed-sender-restart-two-observer-epochs-v1',
            'cleanupRaceProbe': 'fixed-manager-replacement-stop-barrier-v1',
            'outputCollectorProbe': 'fixed-role-symlink-fifo-hardlink-flood-replacement-v5',
            'groupPreparation': 'four-role-ready-with-group-selected-apps-v2',
            'privateVolatileMaxBytes': 128 * 1024,
            'wrapperStartupTimeoutSeconds': {
                role: 60 if role in ('candidate-sender', 'previous') else 30
                for role in ROLES}}


def _trusted_probe_request(spec):
    """Read one root-only fixed request; no client supplies a program or target."""
    if not PROBE_REQUEST.exists():
        return None
    info = PROBE_REQUEST.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o222 or info.st_nlink != 1
            or not 0 < info.st_size <= 4096):
        raise ValueError('workload-role-probe-request-invalid')
    descriptor = os.open(PROBE_REQUEST, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        if os.fstat(descriptor).st_ino != info.st_ino:
            raise ValueError('workload-role-probe-request-changed')
        request = json.loads(os.read(descriptor, 4097))
    finally:
        os.close(descriptor)
    if (not isinstance(request, dict) or set(request) != {
            'schemaVersion', 'caseId', 'nonce', 'bootId', 'javaDigest', 'sourceDigest'}
            or request['schemaVersion'] != 1
            or request['caseId'] not in ('observer-private-read', 'role-boundary',
                                         'authority', 'network-app',
                                         'setsid-double-fork',
                                         'output-symlink',
                                         'output-fifo', 'output-hardlink', 'output-flood',
                                         'output-replacement', 'stuck-output',
                                         'late-child')
            or request['bootId'] != spec['bootId'] or request['javaDigest'] != spec['javaDigest']
            or re.fullmatch('[0-9a-f]{64}', str(request['nonce'])) is None):
        raise ValueError('workload-role-probe-request-mismatch')
    selected = LIFECYCLE_PROBE_SOURCE if request['caseId'] == 'late-child' else PROBE_SOURCE
    source = selected.lstat()
    maximum = 8192 if request['caseId'] == 'late-child' else 32768
    if (not stat.S_ISREG(source.st_mode) or source.st_uid != 0
            or source.st_mode & 0o222 or source.st_nlink != 1
            or not 0 < source.st_size <= maximum
            or request['sourceDigest'] != hashlib.sha256(selected.read_bytes()).hexdigest()):
        raise ValueError('workload-role-probe-source-invalid')
    return request


def _start_probe(role, spec):
    request = _trusted_probe_request(spec)
    if request is None:
        return None
    arguments, environment = command(role)
    separator = arguments.index('--')
    if arguments[separator - 2:separator] != ['--remount-ro', '/']:
        raise ValueError('workload-role-probe-sandbox-changed')
    selected = LIFECYCLE_PROBE_SOURCE if request['caseId'] == 'late-child' else PROBE_SOURCE
    probe = [*arguments[:separator - 2], '--ro-bind', str(selected), '/probe.py',
             *arguments[separator - 2:separator], '--', '/usr/bin/python3', '-I', '-S', '-B',
             '/probe.py', request['nonce'], request['caseId']]
    return subprocess.Popen(probe, env=environment, stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            close_fds=True)


def _partial_launch_request(role, spec):
    """Read one root-owned previous-role failure selection, without a command."""
    if role != 'previous' or not os.path.lexists(PARTIAL_LAUNCH_REQUEST):
        return None
    info = PARTIAL_LAUNCH_REQUEST.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o222 or info.st_nlink != 1
            or not 0 < info.st_size <= 512):
        raise ValueError('workload-partial-launch-request-invalid')
    descriptor = os.open(PARTIAL_LAUNCH_REQUEST,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        current = os.fstat(descriptor)
        if (current.st_dev, current.st_ino, current.st_size) != (
                info.st_dev, info.st_ino, info.st_size):
            raise ValueError('workload-partial-launch-request-changed')
        value = json.loads(os.read(descriptor, 513))
    finally:
        os.close(descriptor)
    nonce = value.get('nonce') if isinstance(value, dict) else None
    if (not isinstance(value, dict) or set(value) != {
            'schemaVersion', 'caseId', 'nonce', 'bootId', 'javaDigest',
            'sourceDigest'}
            or value['schemaVersion'] != 1 or value['caseId'] != 'partial-launch'
            or not isinstance(nonce, str)
            or re.fullmatch('[0-9a-f]{64}', nonce) is None
            or value['bootId'] != spec['bootId']
            or value['javaDigest'] != spec['javaDigest']
            or value['sourceDigest'] != hashlib.sha256(Path(__file__).read_bytes()).hexdigest()):
        raise ValueError('workload-partial-launch-request-mismatch')
    return nonce


def _publish_partial_launch_fault(nonce, expected_uid):
    """Publish this actual ExecStart process epoch before any daemon fork."""
    directory = PARTIAL_LAUNCH_RECORD.parent
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid
            or info.st_mode & 0o077):
        raise ValueError('workload-partial-launch-output-root-invalid')
    fields = Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()
    if len(fields) <= 19 or not fields[19].isdecimal():
        raise ValueError('workload-partial-launch-process-epoch-invalid')
    record = {'schemaVersion': 1, 'kind': 'pr315-previous-launch-fault',
        'caseId': 'partial-launch', 'nonce': nonce, 'pid': os.getpid(),
        'uid': os.getuid(), 'startTicks': int(fields[19]),
        'sourceDigest': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'observedMonotonicNs': time.monotonic_ns()}
    pending = directory / '.pr315-partial-launch-fault.pending'
    descriptor = os.open(pending,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600)
    try:
        raw = json.dumps(record, sort_keys=True, separators=(',', ':')).encode()
        if os.write(descriptor, raw) != len(raw):
            raise ValueError('workload-partial-launch-short-write')
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.link(pending, PARTIAL_LAUNCH_RECORD, follow_symlinks=False)
    pending.unlink()


def _wait_partial_launch_release(nonce, deadline_ns):
    """Hold the real launcher only until root samples its live cgroup epoch."""
    until = min(time.monotonic() + 10, deadline_ns / 1e9)
    while not os.path.lexists(PARTIAL_LAUNCH_RELEASE):
        if time.monotonic() >= until:
            raise ValueError('workload-partial-launch-release-timeout')
        time.sleep(.01)
    descriptor = os.open(PARTIAL_LAUNCH_RELEASE,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1
                or not 0 < info.st_size <= 512):
            raise ValueError('workload-partial-launch-release-invalid')
        raw = os.read(descriptor, 513)
        if len(raw) != info.st_size or os.fstat(descriptor).st_size != info.st_size:
            raise ValueError('workload-partial-launch-release-changed')
    finally:
        os.close(descriptor)
    if json.loads(raw) != {'schemaVersion': 1,
            'kind': 'pr315-partial-launch-release', 'nonce': nonce}:
        raise ValueError('workload-partial-launch-release-mismatch')


def verify_wrapper_options(package):
    """Reserve one fixed JVM option without overwriting a selected product's options."""
    with (Path(package) / 'conf/wrapper.conf').open('rb') as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError('workload-wrapper-options-unsupported')
    indexes = set()
    for line in raw.decode('utf-8').splitlines():
        line = line.strip()
        if line.startswith('#include') or line.endswith('\\'):
            raise ValueError('workload-wrapper-options-unsupported')
        if not line.startswith('wrapper.java.additional.'):
            continue
        match = re.fullmatch(r'wrapper\.java\.additional\.([1-9][0-9]*)=.*', line)
        if match is None or int(match[1]) in indexes:
            raise ValueError('workload-wrapper-options-unsupported')
        indexes.add(int(match[1]))
    if indexes != set(range(1, 10)):
        raise ValueError('workload-wrapper-options-unsupported')


def command(role):
    if role not in ROLES:
        raise ValueError('workload-role-invalid')
    inputs, state = ROOT / 'roles' / role, ROOT / 'state' / role
    arguments = ['/usr/bin/bwrap', '--unshare-user', '--unshare-pid', '--unshare-ipc',
        '--unshare-uts', '--die-with-parent', '--new-session', '--cap-drop', 'ALL',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
        '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
        '--proc', '/proc', '--dev', '/dev', '--ro-bind', str(inputs / 'package'), '/package',
        '--ro-bind', str(inputs / 'jdk'), '/jdk', '--ro-bind', str(inputs / 'apps'), '/inputs/apps',
        '--ro-bind', str(inputs / 'public'), '/inputs/public', '--bind', str(state), '/node',
        '--bind', str(state / 'tmp'), '/tmp', '--chdir', '/node',
        '--remount-ro', '/dev/pts', '--remount-ro', '/dev', '--remount-ro', '/']
    # Use the packaged wrapper's existing bounded rotation inside this role's tmpfs.
    # The administrator snapshots only a small safe tail after owned quiescence.
    child = ['/package/bin/cryptad', 'wrapper.java.maxmemory=256',
             'wrapper.startup.timeout=' + str(launcher_policy()['wrapperStartupTimeoutSeconds'][role]),
             'wrapper.logfile=/node/logs/wrapper.log',
             'wrapper.logfile.maxsize=2M', 'wrapper.logfile.maxfiles=3',
             'wrapper.java.additional.10=-Dcrypta.log.dir=/node/logs']
    values = ['--config-file', '/node/config/cryptad.ini']
    for name in ('config', 'data', 'cache', 'run', 'logs'):
        values += ['--' + name + '-dir', '/node/' + name]
    child += ['wrapper.app.parameter.' + str(i) + '=' + value for i, value in enumerate(values, 1)]
    environment = {'PATH': '/jdk/bin:/usr/bin:/bin', 'JAVA_HOME': '/jdk', 'HOME': '/node',
        'LANG': 'C.UTF-8', 'TMPDIR': '/tmp', 'CRYPTAD_APPHOST_SANDBOX_PROVIDER': 'bubblewrap',
        'CRYPTAD_APPHOST_TRUSTED_KEYS_FILE': '/inputs/public/trusted-app-keys.properties'}
    return arguments + ['--', *child], environment


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ROLES or not sys.flags.isolated or not sys.flags.no_site:
        raise ValueError('workload-fixed-entry-required')
    role = sys.argv[1]
    user = pwd.getpwnam('cryptad-wl-' + role)
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    if (os.getuid() != user.pw_uid or os.geteuid() != user.pw_uid or os.getgid() != user.pw_gid
            or os.getegid() != user.pw_gid or set(os.getgroups()) - {user.pw_gid}
            or status['NoNewPrivs'].strip() != '1'
            or any(int(status[key].strip(), 16) for key in ('CapEff', 'CapPrm', 'CapInh', 'CapAmb', 'CapBnd'))):
        raise ValueError('workload-identity-invalid')
    if Path('/proc/self/cgroup').read_text().strip() != '0::/system.slice/cryptad-workload@' + role + '.service':
        raise ValueError('workload-cgroup-invalid')
    os.environ.clear()
    os.umask(0o077)
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from restricted_native_launcher import _trusted_read, tree_identity
    spec = _trusted_read(ROOT / 'roles' / role / 'launch.json')
    remaining = spec['deadlineMonotonicNs'] / 1e9 - time.monotonic()
    if (spec['role'] != role or spec['bootId'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            or not 0 < remaining <= 3600):
        raise ValueError('workload-expired')
    for name, expected in spec['inputs'].items():
        if name not in {'package', 'jdk', 'apps', 'public'} or tree_identity(
                ROOT / 'roles' / role / name, deadline=spec['deadlineMonotonicNs'] / 1e9) != expected:
            raise ValueError('workload-input-changed')
    for name in os.listdir('/proc/self/fd'):
        if name.isdecimal() and int(name) > 2:
            try:
                os.close(int(name))
            except OSError:
                pass
    arguments, environment = command(role)
    if spec['deadlineMonotonicNs'] <= time.monotonic_ns():
        raise ValueError('workload-expired')
    fault_nonce = _partial_launch_request(role, spec)
    if fault_nonce is not None:
        _publish_partial_launch_fault(fault_nonce, user.pw_uid)
        _wait_partial_launch_release(fault_nonce, spec['deadlineMonotonicNs'])
        return 73
    # A main-process exit causes systemd to terminate the entire nondelegated role cgroup.
    # Candidate stdout/stderr are discarded, avoiding a privileged candidate-file collector.
    process = subprocess.Popen(arguments, env=environment, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
    probe = None
    while True:
        remaining = spec['deadlineMonotonicNs'] / 1e9 - time.monotonic()
        if remaining <= 0:
            raise ValueError('workload-expired')
        try:
            return process.wait(timeout=min(.25, remaining))
        except subprocess.TimeoutExpired:
            if role == 'candidate-sender' and 'probeIdentity' in spec and probe is None:
                probe = _start_probe(role, spec)
            if probe is not None and probe.poll() is not None:
                raise ValueError('workload-role-probe-exited')


if __name__ == '__main__':
    try:
        result = main()
    except Exception:
        result = 1
    raise SystemExit(result)

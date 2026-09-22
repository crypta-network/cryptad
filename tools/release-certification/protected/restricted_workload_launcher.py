#!/usr/bin/python3
"""Fixed unprivileged entry point for one of four installed role services."""
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import time

ROOT = Path('/var/lib/cryptad-restricted-workload')
ROLES = ('candidate-sender', 'candidate-recipient', 'previous', 'relay-no-apps')


def launcher_policy():
    """Closed prospective policy, included in every role's configuration identity.

    The historical product initializes its wrapper backend after crypto providers.
    Its initial handshake needs a separate fixed allowance on the selected TCG guest;
    candidate watchdogs, daemon readiness and the retained campaign deadline do not change.
    """
    return {'revision': 'workload-launcher-policy-v2',
            'wrapperStartupTimeoutSeconds': {
                role: 60 if role == 'previous' else 30 for role in ROLES}}


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
    # A main-process exit causes systemd to terminate the entire nondelegated role cgroup.
    # Candidate stdout/stderr are discarded, avoiding a privileged candidate-file collector.
    process = subprocess.Popen(arguments, env=environment, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
    remaining = spec['deadlineMonotonicNs'] / 1e9 - time.monotonic()
    return process.wait(timeout=max(.001, remaining))


if __name__ == '__main__':
    try:
        result = main()
    except Exception:
        result = 1
    raise SystemExit(result)

#!/usr/bin/python3
"""Administrator test-kit entry for the real installed four-role positive sequence.

Run only in the copied, explicitly disposable PR-313 reference after base installation.
The fixed private selection is prepared with two distinct source-built products and a
normally signed Mail bundle. This driver never manufactures original release authority.
Its positive result alone cannot satisfy the separate complete workload fault contract.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import select
import signal
import socket
import subprocess
import struct
import stat
import sys
import time

sys.dont_write_bytecode = True

INSTALLED = Path('/opt/cryptad-cross-version/current')
TEST_KIT = Path('/opt/cryptad-restricted-test-kit')
SELECTION = Path('/root/pr314-workload-selection.json')
REPORT = Path('/root/pr314-workload-observation.private.json')
VOLATILE = Path('/root/pr315-workload-volatile.private.json')
VOLATILE_MAX = 128 * 1024
DIAGNOSTICS = Path('/root/pr315-workload-memory.private.json')
READINESS_JCMD = Path('/root/pr315-readiness-jcmd.private.json')
CGROUP_ROOT = Path('/sys/fs/cgroup/system.slice')
ROLE_NAMES = ('candidate-sender', 'candidate-recipient', 'previous', 'relay-no-apps')
LIFECYCLE_SCENARIOS = ('cancellation', 'controller-restart', 'none')
STARTUP_MEASUREMENT_SECONDS = 120
# Prospective administrator observation budget after the installed startup measurement.
# Production limits and the retained campaign deadline remain unchanged.
READINESS_SECONDS = 90
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}
SIBLING_CANARY = 'pr315-sibling-data-canary'
SIBLING_PROBE_PATH = '/var/lib/cryptad-restricted-workload/state/candidate-recipient/pr315-sibling-data-canary'
PACKAGE_PROBE_PATH = '/package/lib/cryptad.jar'
CGROUP_PROBE_PATH = '/sys/fs/cgroup/system.slice/cryptad-workload@candidate-recipient.service/cgroup.procs'
RESOLVER_PROBE_PATH = '/var/lib/cryptad-restricted/resolver/pr315-workload-canary'
OUTPUT_CANARY = 'pr315-output-target-canary'
OUTPUT_SYMLINK = 'pr315-output-symlink-artifact'
OUTPUT_SYMLINK_READY = 'pr315-output-symlink-ready.json'
OUTPUT_SYMLINK_TRIGGER = 'pr315-output-symlink-trigger.json'
OUTPUT_SYMLINK_RESULT = 'pr315-output-symlink-result.json'
ROLE_PROBE_CODES = frozenset(('workload-role-probe-campaign-expired',
    'workload-observer-private-control-failed', 'workload-observer-private-control-mismatch',
    'workload-role-probe-ready-timeout', 'workload-role-probe-ready-invalid',
    'workload-role-probe-file-invalid', 'workload-role-probe-file-changed',
    'workload-role-probe-actor-unavailable', 'workload-role-probe-pid-unbound',
    'workload-role-probe-target-changed', 'workload-role-probe-result-timeout',
    'workload-role-probe-actor-changed', 'workload-role-probe-invocation-changed',
    'workload-role-probe-result-unbound', 'workload-role-probe-outcome-mismatch',
    'workload-role-probe-timeline-invalid', 'workload-role-probe-write-result-invalid',
    'workload-role-probe-write-outcome-mismatch', 'workload-role-probe-write-timeline-invalid',
    'workload-role-probe-identity-claim-invalid', 'workload-role-probe-counter-claim-invalid',
    'workload-role-probe-counter-target-unavailable',
    'workload-role-probe-claim-timeline-invalid',
    'workload-sibling-data-control-failed', 'workload-sibling-data-target-changed',
    'workload-package-target-changed', 'workload-cgroup-target-changed',
    'workload-role-probe-sibling-data-invalid',
    'workload-role-probe-package-expectation-invalid',
    'workload-role-probe-cgroup-migration-invalid',
    'workload-role-probe-fixed-access-timeline-invalid',
    'workload-resolver-target-invalid', 'workload-resolver-probe-invalid',
    'workload-output-symlink-ready-timeout', 'workload-output-symlink-result-timeout',
    'workload-output-symlink-actor-invalid', 'workload-output-symlink-target-invalid',
    'workload-output-symlink-collector-invalid',
    'workload-sibling-network-deadline', 'workload-sibling-network-target-inactive',
    'workload-sibling-network-before-window-invalid',
    'workload-sibling-network-result-timeout', 'workload-sibling-network-probe-invalid',
    'workload-sibling-network-case-invalid',
    'workload-sibling-network-counter-context-invalid',
    'workload-sibling-network-counter-invalid',
    'workload-sibling-network-counter-epoch-invalid',
    'workload-sibling-network-drop-not-attributed',
    'workload-sibling-network-other-case-changed'))


class RoleProbeDiagnosticError(ValueError):
    """Fixed private classification; never include a candidate message in text."""

    def __init__(self, code, observed_outcome=None):
        super().__init__(code)
        self.observed_outcome = observed_outcome


def _private_role_probe_code(error):
    code = str(error)
    return code if code in ROLE_PROBE_CODES else None


def prerequisites():
    reasons = []
    if os.geteuid() != 0:
        reasons.append('administrator-required')
    if 'VERSION_ID="13"' not in Path('/etc/os-release').read_text():
        reasons.append('debian13-required')
    if Path('/proc/1/comm').read_text().strip() != 'systemd':
        reasons.append('systemd-pid1-required')
    result = subprocess.run(['/usr/bin/systemd-detect-virt', '--vm'], capture_output=True, env=ENV, timeout=10)
    if result.returncode:
        reasons.append('dedicated-disposable-vm-required')
    if not (INSTALLED / '.restricted-manifest.json').is_file():
        reasons.append('fixed-installed-source-required')
    if not (TEST_KIT / '.test-kit.json').is_file():
        reasons.append('separate-measured-test-kit-required')
    return reasons


def stage_role_probe(workload, kit):
    """Copy only the measured fixed test-kit actor into root-owned probe storage."""
    import installation
    relative = 'tools/release-certification/restricted/pr315_role_probe.py'
    source = TEST_KIT / relative
    raw = installation.secured(source).read_bytes()
    if (not 0 < len(raw) <= 32768
            or kit['files'].get(relative) != hashlib.sha256(raw).hexdigest()):
        raise ValueError('workload-role-probe-test-kit-mismatch')
    directory = workload.ROOT / 'probe-source'
    requests = workload.ROOT / 'probe-requests'
    directory.mkdir(mode=0o755)
    requests.mkdir(mode=0o755)
    directory.chmod(0o755)
    requests.chmod(0o755)
    target = directory / 'pr315_role_probe.py'
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    try:
        with os.fdopen(descriptor, 'wb', closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.fchmod(descriptor, 0o444)
    finally:
        os.close(descriptor)
    return hashlib.sha256(raw).hexdigest()


def prepare_sibling_canary(workload):
    """Place one recipient-owned 32-byte target in its real mounted role tmpfs."""
    user = workload.account('candidate-recipient')
    path = workload.ROOT / 'state/candidate-recipient' / SIBLING_CANARY
    raw = secrets.token_bytes(32)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchown(descriptor, user.pw_uid, user.pw_gid)
        if os.write(descriptor, raw) != len(raw):
            raise ValueError('workload-sibling-canary-short-write')
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return hashlib.sha256(raw).hexdigest()


def _resolver_target_control(expected_digest):
    """Bind the fixed private canary to one active installed resolver instance."""
    unit = 'cryptad-restricted.service'
    selected = subprocess.run(['/usr/bin/systemctl', 'show', unit,
        '--property=ActiveState,SubState,Result,MainPID,InvocationID,ControlGroup',
        '--no-pager'], stdin=subprocess.DEVNULL, capture_output=True,
        env=ENV, timeout=15, check=True)
    values = dict(line.split('=', 1) for line in selected.stdout.decode('ascii').splitlines()
                  if '=' in line)
    if (set(values) != {'ActiveState', 'SubState', 'Result', 'MainPID',
                        'InvocationID', 'ControlGroup'}
            or values['ActiveState'] != 'active' or values['SubState'] != 'running'
            or values['Result'] != 'success'
            or not values['MainPID'].isdecimal() or int(values['MainPID']) <= 1
            or re.fullmatch('[0-9a-f]{32}', values['InvocationID']) is None
            or values['ControlGroup'] != '/system.slice/' + unit):
        raise ValueError('workload-resolver-target-invalid')
    pid = int(values['MainPID'])
    process = Path('/proc') / str(pid)
    status = (process / 'status').read_text()
    uid = next((line.split()[1] for line in status.splitlines()
                if line.startswith('Uid:')), None)
    raw_stat = (process / 'stat').read_text().rsplit(')', 1)[1].split()
    cgroup = (process / 'cgroup').read_text().strip()
    group = CGROUP_ROOT / unit
    identity = group.stat()
    path = Path(RESOLVER_PROBE_PATH)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        raw = os.read(descriptor, 33)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (uid != '0' or len(raw_stat) <= 19 or not raw_stat[19].isdecimal()
            or cgroup != '0::/system.slice/' + unit
            or not stat.S_ISREG(before.st_mode) or before.st_uid != 0
            or before.st_nlink != 1 or before.st_mode & 0o077
            or before.st_size != 32 or len(raw) != 32
            or any(getattr(before, key) != getattr(after, key)
                   for key in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))
            or hashlib.sha256(raw).hexdigest() != expected_digest):
        raise ValueError('workload-resolver-target-invalid')
    return {'role': None, 'managerInvocation': values['InvocationID'],
            'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'cgroupIdentity': [identity.st_dev, identity.st_ino],
            'mainPid': pid, 'mainStartTicks': int(raw_stat[19]),
            'canaryIdentity': [before.st_dev, before.st_ino],
            'observedMonotonicNs': time.monotonic_ns(),
            'controlDigest': expected_digest}


def prepare_resolver_canary():
    """Start the installed resolver and create one root-only synthetic subject."""
    subprocess.run(['/usr/bin/systemctl', 'start', 'cryptad-restricted.service'],
                   check=True, stdin=subprocess.DEVNULL, timeout=190, env=ENV)
    parent = Path(RESOLVER_PROBE_PATH).parent
    info = parent.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o077):
        raise ValueError('workload-resolver-target-invalid')
    raw = secrets.token_bytes(32)
    descriptor = os.open(RESOLVER_PROBE_PATH,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        if os.write(descriptor, raw) != len(raw):
            raise ValueError('workload-resolver-target-invalid')
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    digest = hashlib.sha256(raw).hexdigest()
    _resolver_target_control(digest)
    return digest


def _candidate_probe_file(path, uid):
    """Read a bounded role-owned file without following a candidate link."""
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1
            or info.st_mode & 0o077 or not 0 < info.st_size <= 4096):
        raise ValueError('workload-role-probe-file-invalid')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        current = os.fstat(descriptor)
        if (info.st_dev, info.st_ino, info.st_size) != (
                current.st_dev, current.st_ino, current.st_size):
            raise ValueError('workload-role-probe-file-changed')
        return json.loads(os.read(descriptor, 4097))
    finally:
        os.close(descriptor)


def _observer_canary_control(path, user, failure_code='workload-observer-private-control-failed'):
    """Demonstrate that the selected target owner can read the current bytes."""
    if failure_code not in ('workload-observer-private-control-failed',
                            'workload-sibling-data-control-failed'):
        raise ValueError('workload-canary-control-selection-invalid')
    def drop():
        os.setgroups([])
        os.setgid(user.pw_gid)
        os.setuid(user.pw_uid)
    selected = subprocess.run(['/usr/bin/python3', '-I', '-S', '-B', '-c',
        'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read(64)).hexdigest())',
        str(path)], stdin=subprocess.DEVNULL, capture_output=True, env=ENV,
        preexec_fn=drop, timeout=5)
    if (selected.returncode != 0 or selected.stderr or len(selected.stdout) != 65
            or re.fullmatch(rb'[0-9a-f]{64}\n', selected.stdout) is None):
        raise ValueError(failure_code)
    return selected.stdout[:64].decode()


def _staged_package_digest(workload):
    path = workload.ROOT / 'roles/candidate-sender/package/lib/cryptad.jar'
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
            or before.st_mode & 0o022 or not 0 < before.st_size <= 512 * 1024**2):
        raise ValueError('workload-package-target-changed')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        current = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after = path.lstat()
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
    if any(getattr(before, key) != getattr(after, key)
           or getattr(before, key) != getattr(current, key) for key in fields):
        raise ValueError('workload-package-target-changed')
    return digest


def _role_probe_actor(observation, nonce, case_id='observer-private-read'):
    """Select the one measured Python actor in the active candidate service."""
    found = []
    for process in observation['processes']:
        pid = process['hostPid']
        try:
            command = (Path('/proc') / str(pid) / 'cmdline').read_bytes().split(b'\0')
        except OSError:
            continue
        if command[:7] == [b'/usr/bin/python3', b'-I', b'-S', b'-B',
                            b'/probe.py', nonce.encode(), case_id.encode()]:
            found.append(process)
    if (len(found) != 1 or found[0]['noNewPrivileges'] is not True
            or found[0]['effectiveCapabilities'] != 0):
        raise ValueError('workload-role-probe-actor-unavailable')
    return found[0]


def _safe_role_probe_outcome(value):
    if (not isinstance(value, dict) or set(value) != {'opened', 'errno'}
            or type(value['opened']) is not bool
            or value['errno'] not in ('ENOENT', 'EACCES', 'EPERM', 'EROFS', 'UNKNOWN', None)):
        return None
    return {'opened': value['opened'], 'errno': value['errno']}


def _validate_role_probe_result(ready, before, actor_before, after, actor_after,
                                result, expected, target_after, nonce, trigger_ns):
    """Bind the final role action with separately named failure conditions."""
    stable = ('hostPid', 'startTicks', 'namespacePids', 'networkNamespaceIdentity',
              'mountNamespaceIdentity', 'userNamespaceIdentity', 'executableDigest',
              'noNewPrivileges', 'effectiveCapabilities')
    if any(actor_before[key] != actor_after[key] for key in stable):
        raise RoleProbeDiagnosticError('workload-role-probe-actor-changed')
    if before['managerInvocation'] != after['managerInvocation']:
        raise RoleProbeDiagnosticError('workload-role-probe-invocation-changed')
    if target_after != expected:
        raise RoleProbeDiagnosticError('workload-role-probe-target-changed')
    if (not isinstance(result, dict) or result.get('nonce') != nonce
            or result.get('caseId') != 'observer-private-read'
            or result.get('pid') != actor_before['namespacePids'][-1]):
        raise RoleProbeDiagnosticError('workload-role-probe-result-unbound')
    if result.get('outcome') != {'opened': False, 'errno': 'ENOENT'}:
        raise RoleProbeDiagnosticError('workload-role-probe-outcome-mismatch',
                                       _safe_role_probe_outcome(result.get('outcome')))
    times = (ready.get('startedMonotonicNs'), trigger_ns,
             result.get('startedMonotonicNs'), result.get('finishedMonotonicNs'),
             after.get('observedMonotonicNs'))
    if (any(type(value) is not int or value <= 0 for value in times)
            or list(times) != sorted(times) or len(set(times)) != len(times)):
        raise RoleProbeDiagnosticError('workload-role-probe-timeline-invalid')


def _validate_role_probe_write(result, after):
    write = result.get('writeAttempt')
    if (not isinstance(write, dict) or set(write) != {
            'operation', 'startedMonotonicNs', 'finishedMonotonicNs',
            'writtenBytes', 'outcome'}
            or write['operation'] != 'observer-private-write'
            or type(write['writtenBytes']) is not int or not 0 <= write['writtenBytes'] <= 6):
        raise RoleProbeDiagnosticError('workload-role-probe-write-result-invalid')
    if write['outcome'] != {'opened': False, 'errno': 'ENOENT'} or write['writtenBytes'] != 0:
        raise RoleProbeDiagnosticError('workload-role-probe-write-outcome-mismatch',
                                       _safe_role_probe_outcome(write['outcome']))
    times = (result.get('finishedMonotonicNs'), write.get('startedMonotonicNs'),
             write.get('finishedMonotonicNs'), after.get('observedMonotonicNs'))
    if (any(type(value) is not int or value <= 0 for value in times)
            or list(times) != sorted(times) or len(set(times)) != len(times)):
        raise RoleProbeDiagnosticError('workload-role-probe-write-timeline-invalid')
    return write


def _validate_false_role_claims(result, before, after, actor, uid):
    identity, counters = result.get('identityClaim'), result.get('counterClaim')
    if (not isinstance(identity, dict) or set(identity) != {
            'claimedHostPid', 'claimedHostUid', 'startedMonotonicNs', 'finishedMonotonicNs'}
            or type(identity['claimedHostPid']) is not int or identity['claimedHostPid'] != 1
            or type(identity['claimedHostUid']) is not int or identity['claimedHostUid'] != 0
            or actor['hostPid'] <= 1 or uid <= 0):
        raise RoleProbeDiagnosticError('workload-role-probe-identity-claim-invalid')
    if (not isinstance(counters, dict) or set(counters) != {
            'claimedMemoryCurrentBytes', 'claimedTasksCurrent',
            'startedMonotonicNs', 'finishedMonotonicNs'}
            or type(counters['claimedMemoryCurrentBytes']) is not int
            or counters['claimedMemoryCurrentBytes'] != 0
            or type(counters['claimedTasksCurrent']) is not int
            or counters['claimedTasksCurrent'] != 0):
        raise RoleProbeDiagnosticError('workload-role-probe-counter-claim-invalid')
    if (before['cgroupIdentity'] != after['cgroupIdentity']
            or any(type(observed[key]) is not int or observed[key] <= 0
                   for observed in (before, after)
                   for key in ('cgroupMemoryBytes', 'cgroupTasks'))):
        raise RoleProbeDiagnosticError('workload-role-probe-counter-target-unavailable')
    times = (result['writeAttempt']['finishedMonotonicNs'],
             identity.get('startedMonotonicNs'), identity.get('finishedMonotonicNs'),
             counters.get('startedMonotonicNs'), counters.get('finishedMonotonicNs'),
             after['observedMonotonicNs'])
    if (any(type(value) is not int or value <= 0 for value in times)
            or list(times) != sorted(times) or len(set(times)) != len(times)):
        raise RoleProbeDiagnosticError('workload-role-probe-claim-timeline-invalid')
    return identity, counters


def _validate_fixed_role_accesses(result, after):
    selected = (
        ('siblingRead', 'sibling-data', SIBLING_PROBE_PATH, ('ENOENT',)),
        ('packageWrite', 'package-expectation', PACKAGE_PROBE_PATH,
         ('EACCES', 'EPERM', 'EROFS')),
        ('cgroupMigration', 'cgroup-migration', CGROUP_PROBE_PATH, ('ENOENT',)))
    previous = result['counterClaim']['finishedMonotonicNs']
    found = {}
    for name, case_id, target, allowed in selected:
        row = result.get(name)
        if (not isinstance(row, dict) or set(row) != {
                'operation', 'startedMonotonicNs', 'finishedMonotonicNs',
                'writtenBytes', 'outcome', 'targetPathDigest'}
                or row['operation'] != case_id or type(row['writtenBytes']) is not int
                or row['writtenBytes'] != 0
                or row['targetPathDigest'] != hashlib.sha256(target.encode()).hexdigest()):
            raise RoleProbeDiagnosticError('workload-role-probe-' + case_id + '-invalid')
        if (not isinstance(row['outcome'], dict)
                or row['outcome'].get('opened') is not False
                or row['outcome'].get('errno') not in allowed
                or set(row['outcome']) != {'opened', 'errno'}):
            raise RoleProbeDiagnosticError('workload-role-probe-' + case_id + '-invalid',
                                           _safe_role_probe_outcome(row['outcome']))
        times = (previous, row['startedMonotonicNs'], row['finishedMonotonicNs'],
                 after['observedMonotonicNs'])
        if (any(type(value) is not int or value <= 0 for value in times)
                or list(times) != sorted(times) or len(set(times)) != len(times)):
            raise RoleProbeDiagnosticError('workload-role-probe-fixed-access-timeline-invalid')
        previous = row['finishedMonotonicNs']
        found[case_id] = row
    return found


def _cgroup_control_digest(observation):
    raw = json.dumps({'role': 'candidate-recipient',
        'managerInvocation': observation['managerInvocation'],
        'cgroupIdentity': observation['cgroupIdentity']},
        sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(raw).hexdigest()


def _fixed_role_target(role, observation, digest):
    if (role not in ('candidate-sender', 'candidate-recipient')
            or re.fullmatch('[0-9a-f]{64}', digest) is None):
        raise ValueError('workload-fixed-role-target-invalid')
    return {'role': role, 'managerInvocation': observation['managerInvocation'],
            'cgroupIdentity': observation['cgroupIdentity'],
            'observedMonotonicNs': observation['observedMonotonicNs'],
            'controlDigest': digest}


def _validate_resolver_read(result, before, after, target_before, target_after):
    """Require a bounded denied syscall while the same root resolver serves."""
    row = result.get('resolverRead')
    stable = ('role', 'managerInvocation', 'bootId', 'cgroupIdentity', 'mainPid',
              'mainStartTicks', 'canaryIdentity', 'controlDigest')
    if (not isinstance(row, dict) or set(row) != {
            'operation', 'startedMonotonicNs', 'finishedMonotonicNs',
            'writtenBytes', 'outcome', 'targetPathDigest'}
            or row['operation'] != 'resolver-authority'
            or row['targetPathDigest'] != hashlib.sha256(
                RESOLVER_PROBE_PATH.encode()).hexdigest()
            or row['writtenBytes'] != 0
            or row['outcome'] not in ({'opened': False, 'errno': 'ENOENT'},
                                     {'opened': False, 'errno': 'EACCES'},
                                     {'opened': False, 'errno': 'EPERM'})
            or any(target_before[key] != target_after[key] for key in stable)
            or not before['observedMonotonicNs'] < target_before['observedMonotonicNs']
                < row['startedMonotonicNs'] < row['finishedMonotonicNs']
                < target_after['observedMonotonicNs'] < after['observedMonotonicNs']):
        raise RoleProbeDiagnosticError('workload-resolver-probe-invalid',
                                       _safe_role_probe_outcome(row.get('outcome')
                                           if isinstance(row, dict) else None))
    return row


def _sibling_counter_pair(case_id, before, after, sender_namespace):
    """Bind one denied sender SYN to its own named nft DROP counter."""
    from restricted_workload_network import SIBLING_DROP_COUNTERS, role_rules
    if case_id not in SIBLING_DROP_COUNTERS:
        raise ValueError('workload-sibling-network-case-invalid')
    expected = hashlib.sha256(role_rules('candidate-sender').encode()).hexdigest()
    names = set(SIBLING_DROP_COUNTERS.values())
    for row in (before, after):
        if (not isinstance(row, dict) or row.get('schemaVersion') != 1
                or row.get('kind') != 'pr315-fixed-sibling-drop-counters'
                or row.get('policyDigest') != expected
                or row.get('roleNamespaceIdentity') != sender_namespace
                or not isinstance(row.get('counters'), dict)
                or set(row['counters']) != names):
            raise ValueError('workload-sibling-network-counter-context-invalid')
        for counter in row['counters'].values():
            if (not isinstance(counter, dict) or set(counter) != {'packets', 'bytes'}
                    or any(type(counter[key]) is not int or counter[key] < 0
                           for key in ('packets', 'bytes'))):
                raise ValueError('workload-sibling-network-counter-invalid')
    if (before['bootId'] != after['bootId']
            or not before['observedMonotonicNs'] < after['observedMonotonicNs']):
        raise ValueError('workload-sibling-network-counter-epoch-invalid')
    selected = SIBLING_DROP_COUNTERS[case_id]
    for name in names:
        old, new = before['counters'][name], after['counters'][name]
        packets, size = new['packets'] - old['packets'], new['bytes'] - old['bytes']
        if name == selected:
            if not 1 <= packets <= 8 or not 1 <= size <= 8192:
                raise ValueError('workload-sibling-network-drop-not-attributed')
        elif packets != 0 or size != 0:
            raise ValueError('workload-sibling-network-other-case-changed')


def _sibling_target_control(case_id, handle):
    """Keep FCP and HTTP active-target checks on their approved recipient namespace."""
    from restricted_workload_controller import _recipient_fcp_control, _recipient_http_control
    if case_id == 'sibling-fcp':
        observed, controlled_ns, digest = _recipient_fcp_control(handle)
    elif case_id == 'sibling-http':
        observed, controlled_ns, digest = _recipient_http_control(handle)
    else:
        raise ValueError('workload-sibling-network-case-invalid')
    if (observed.get('state') != 'running'
            or observed.get('provenance') != 'controller-kernel-sample'
            or re.fullmatch('[0-9a-f]{64}', digest) is None):
        raise ValueError('workload-sibling-network-target-inactive')
    fields = ('managerInvocation', 'bootId', 'cgroupIdentity',
              'observedMonotonicNs')
    return {'role': 'candidate-recipient',
            **{key: observed[key] for key in fields},
            'controlObservedNs': controlled_ns, 'controlDigest': digest}


def probe_sibling_network(workload, handoff, nonce, source_digest, campaign_deadline_ns):
    """Trigger two finite role-origin TCP attempts with separate root filter controls."""
    import pr315_role_probe as role_probe
    from restricted_workload_network import read_sibling_drop_counters, SIBLING_DROP_COUNTERS
    sender_handle = handoff['handles']['candidate-sender']
    recipient_handle = handoff['handles']['candidate-recipient']
    sender_uid = workload.account('candidate-sender').pw_uid
    root = workload.ROOT / 'state/candidate-sender/tmp'
    audits = {}
    for case_id, (port, prefix) in role_probe.NETWORK_CASES.items():
        if time.monotonic_ns() >= campaign_deadline_ns:
            raise ValueError('workload-sibling-network-deadline')
        sender_before = workload.observe(sender_handle)
        actor_before = _role_probe_actor(sender_before, nonce)
        target_before = _sibling_target_control(case_id, recipient_handle)
        counters_before = read_sibling_drop_counters()
        if (target_before['observedMonotonicNs'] >= target_before['controlObservedNs']
                or target_before['controlObservedNs'] >= counters_before['observedMonotonicNs']
                or counters_before['roleNamespaceIdentity'] !=
                   sender_before['networkNamespaceIdentity']):
            raise ValueError('workload-sibling-network-before-window-invalid')
        trigger_ns = time.monotonic_ns()
        trigger = root / (prefix + '-trigger.json')
        descriptor = os.open(trigger, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o444)
        try:
            with os.fdopen(descriptor, 'w', closefd=False) as stream:
                json.dump({'caseId': case_id, 'nonce': nonce}, stream,
                          sort_keys=True, separators=(',', ':'))
                stream.flush()
                os.fsync(stream.fileno())
            os.fchmod(descriptor, 0o444)
        finally:
            os.close(descriptor)
        result_path = root / (prefix + '-result.json')
        until = min(time.monotonic() + 10, campaign_deadline_ns / 1e9)
        while time.monotonic() < until and not result_path.exists():
            time.sleep(.05)
        if not result_path.exists():
            raise ValueError('workload-sibling-network-result-timeout')
        result = _candidate_probe_file(result_path, sender_uid)
        counters_after = read_sibling_drop_counters()
        sender_after = workload.observe(sender_handle)
        actor_after = _role_probe_actor(sender_after, nonce)
        target_after = _sibling_target_control(case_id, recipient_handle)
        stable_actor = ('hostPid', 'hostParentPid', 'startTicks', 'namespacePids',
                        'networkNamespaceIdentity', 'mountNamespaceIdentity',
                        'userNamespaceIdentity', 'executableDigest',
                        'noNewPrivileges', 'effectiveCapabilities')
        stable_target = ('role', 'managerInvocation', 'bootId', 'cgroupIdentity')
        if (not isinstance(result, dict) or set(result) != {
                'schemaVersion', 'kind', 'caseId', 'nonce', 'pid', 'uid', 'gid',
                'startedMonotonicNs', 'finishedMonotonicNs', 'targetEndpointDigest',
                'outcome'}
                or result['schemaVersion'] != 1
                or result['kind'] != 'pr315-candidate-network-probe'
                or result['caseId'] != case_id or result['nonce'] != nonce
                or result['pid'] != actor_before['namespacePids'][-1]
                or result['uid'] != sender_uid
                or result['targetEndpointDigest'] != hashlib.sha256(
                    f'{role_probe.SIBLING_ADDRESS}:{port}'.encode()).hexdigest()
                or result['outcome'] not in ({'connected': False, 'errno': 'ETIMEDOUT'},
                    {'connected': False, 'errno': 'EHOSTUNREACH'},
                    {'connected': False, 'errno': 'ENETUNREACH'},
                    {'connected': False, 'errno': 'EACCES'})
                or any(actor_before[key] != actor_after[key] for key in stable_actor)
                or sender_before['managerInvocation'] != sender_after['managerInvocation']
                or sender_before['cgroupIdentity'] != sender_after['cgroupIdentity']
                or re.fullmatch('[0-9a-f]{64}', str(sender_before['stateDigest'])) is None
                or sender_before['stateDigest'] != sender_after['stateDigest']
                or any(target_before[key] != target_after[key] for key in stable_target)
                or target_before['controlObservedNs'] >= counters_before['observedMonotonicNs']
                or not counters_before['observedMonotonicNs'] < trigger_ns
                    < result['startedMonotonicNs'] < result['finishedMonotonicNs']
                    < counters_after['observedMonotonicNs']
                    < target_after['observedMonotonicNs']
                    < target_after['controlObservedNs']):
            raise ValueError('workload-sibling-network-probe-invalid')
        _sibling_counter_pair(case_id, counters_before, counters_after,
                              sender_before['networkNamespaceIdentity'])
        audit = {'schemaVersion': 1, 'kind': 'pr315-administrator-sibling-network-denial',
                 'caseId': case_id, 'sourceDigest': source_digest,
                 'nonceDigest': hashlib.sha256(nonce.encode()).hexdigest(),
                 'actorUid': sender_uid, 'actorBefore': actor_before,
                 'actorAfter': actor_after,
                 'senderInvocationBefore': sender_before['managerInvocation'],
                 'senderInvocationAfter': sender_after['managerInvocation'],
                 'senderCgroupBefore': sender_before['cgroupIdentity'],
                 'senderCgroupAfter': sender_after['cgroupIdentity'],
                 'senderStateBefore': sender_before['stateDigest'],
                 'senderStateAfter': sender_after['stateDigest'],
                 'targetBefore': target_before, 'targetAfter': target_after,
                 'counterBefore': counters_before, 'counterAfter': counters_after,
                 'triggerMonotonicNs': trigger_ns,
                 'attackStartedNs': result['startedMonotonicNs'],
                 'attackFinishedNs': result['finishedMonotonicNs'],
                 'targetEndpointDigest': result['targetEndpointDigest'],
                 'kernelConnectResult': result['outcome'],
                 'counterName': SIBLING_DROP_COUNTERS[case_id]}
        workload.write(workload.ROOT / 'authority' / (case_id + '-denial.json'),
                       audit, create=True)
        audits[case_id] = hashlib.sha256(json.dumps(audit,
            sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return audits


def _administrator_collector_epoch():
    """Measure the real test-kit descriptor reader process, not an asserted PID."""
    import cross_version_runtime as runtime
    pid = os.getpid()
    proc = Path('/proc/self')
    fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
    cgroup = (proc / 'cgroup').read_text().strip()
    if (os.geteuid() != 0 or len(fields) <= 19 or not fields[19].isdecimal()
            or not cgroup.startswith('0::/') or '..' in cgroup.split('/')):
        raise ValueError('workload-output-symlink-collector-invalid')
    group = (Path('/sys/fs/cgroup') / cgroup[4:].lstrip('/')).stat()
    identity = [group.st_dev, group.st_ino]
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    start = int(fields[19])
    source = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    invocation = hashlib.sha256(json.dumps({'bootId': boot, 'pid': pid,
        'startTicks': start, 'cgroupIdentity': identity, 'sourceDigest': source},
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()[:32]
    return {'pid': pid, 'uid': 0, 'startTicks': start, 'bootId': boot,
            'cgroupIdentity': identity,
            'cgroupDigest': runtime.canonical_digest({
                'role': 'output-collector', 'identity': identity})[7:],
            'invocationId': invocation, 'sourceDigest': source,
            'observedMonotonicNs': time.monotonic_ns()}


def _output_canary_control(root, uid, expected):
    import runtime_snapshot as snapshot
    path = root / OUTPUT_CANARY
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
            or info.st_nlink != 1 or info.st_size != 32 or info.st_mode & 0o077):
        raise ValueError('workload-output-symlink-target-invalid')
    raw = snapshot.read_file(root, OUTPUT_CANARY, maximum=32, timeout=2)
    digest = hashlib.sha256(raw).hexdigest()
    if len(raw) != 32 or digest != expected:
        raise ValueError('workload-output-symlink-target-invalid')
    return {'controlDigest': digest, 'fileIdentity': [info.st_dev, info.st_ino,
        info.st_size, info.st_mtime_ns, info.st_ctime_ns],
            'observedMonotonicNs': time.monotonic_ns()}


def probe_output_symlink(workload, handoff, source_digest, campaign_deadline_ns):
    """Trigger one real role symlink and the installed safe descriptor reader."""
    import runtime_snapshot as snapshot
    role = 'candidate-sender'
    uid = workload.account(role).pw_uid
    gid = workload.account(role).pw_gid
    root = workload.ROOT / 'state/candidate-sender/tmp'
    canary = root / OUTPUT_CANARY
    raw = secrets.token_bytes(32)
    fd = os.open(canary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchown(fd, uid, gid)
        if os.write(fd, raw) != len(raw):
            raise ValueError('workload-output-symlink-target-invalid')
        os.fsync(fd)
    finally:
        os.close(fd)
    digest = hashlib.sha256(raw).hexdigest()
    nonce = secrets.token_hex(32)
    launch = workload.read(workload.ROOT / 'roles/candidate-sender/launch.json')
    workload.write(workload.ROOT / 'probe-requests/candidate-sender.json',
        {'schemaVersion': 1, 'caseId': 'output-symlink', 'nonce': nonce,
         'bootId': workload.boot(), 'javaDigest': launch['javaDigest'],
         'sourceDigest': source_digest}, create=True, mode=0o444)
    ready_path = root / OUTPUT_SYMLINK_READY
    until = min(time.monotonic() + 25, campaign_deadline_ns / 1e9)
    while time.monotonic() < until and not ready_path.exists():
        time.sleep(.05)
    if not ready_path.exists():
        raise ValueError('workload-output-symlink-ready-timeout')
    ready = _candidate_probe_file(ready_path, uid)
    if (not isinstance(ready, dict) or set(ready) != {
            'schemaVersion', 'kind', 'caseId', 'nonce', 'pid', 'startedMonotonicNs'}
            or ready['schemaVersion'] != 1
            or ready['kind'] != 'pr315-candidate-role-probe-ready'
            or ready['caseId'] != 'output-symlink' or ready['nonce'] != nonce):
        raise ValueError('workload-output-symlink-actor-invalid')
    handle = handoff['handles'][role]
    before = workload.observe(handle)
    actor_before = _role_probe_actor(before, nonce, 'output-symlink')
    if ready['pid'] != actor_before['namespacePids'][-1]:
        raise ValueError('workload-output-symlink-actor-invalid')
    target_before = _output_canary_control(root, uid, digest)
    collector_before = _administrator_collector_epoch()
    trigger_ns = time.monotonic_ns()
    trigger = root / OUTPUT_SYMLINK_TRIGGER
    fd = os.open(trigger, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    try:
        with os.fdopen(fd, 'w', closefd=False) as stream:
            json.dump({'caseId': 'output-symlink', 'nonce': nonce}, stream,
                      sort_keys=True, separators=(',', ':'))
            stream.flush()
            os.fsync(stream.fileno())
        os.fchmod(fd, 0o444)
    finally:
        os.close(fd)
    result_path = root / OUTPUT_SYMLINK_RESULT
    while time.monotonic() < until and not result_path.exists():
        time.sleep(.05)
    if not result_path.exists():
        raise ValueError('workload-output-symlink-result-timeout')
    result = _candidate_probe_file(result_path, uid)
    artifact = root / OUTPUT_SYMLINK
    info = artifact.lstat()
    if (not stat.S_ISLNK(info.st_mode) or info.st_uid != uid
            or info.st_nlink != 1
            or os.readlink(artifact) != '/node/tmp/' + OUTPUT_CANARY):
        raise ValueError('workload-output-symlink-target-invalid')
    started = time.monotonic_ns()
    try:
        snapshot.read_file(root, OUTPUT_SYMLINK, maximum=64, timeout=2)
    except snapshot.SnapshotError as error:
        denial = str(error)
    else:
        raise ValueError('workload-output-symlink-collector-invalid')
    finished = time.monotonic_ns()
    target_after = _output_canary_control(root, uid, digest)
    collector_after = _administrator_collector_epoch()
    after = workload.observe(handle)
    actor_after = _role_probe_actor(after, nonce, 'output-symlink')
    stable_actor = ('hostPid', 'hostParentPid', 'startTicks', 'namespacePids',
                    'pidNamespace', 'networkNamespaceIdentity',
                    'mountNamespaceIdentity', 'userNamespaceIdentity',
                    'executableDigest', 'noNewPrivileges', 'effectiveCapabilities')
    stable_collector = ('pid', 'uid', 'startTicks', 'bootId', 'cgroupIdentity',
                        'cgroupDigest', 'invocationId', 'sourceDigest')
    if (not isinstance(result, dict) or set(result) != {
            'schemaVersion', 'kind', 'caseId', 'nonce', 'pid', 'uid', 'gid',
            'startedMonotonicNs', 'finishedMonotonicNs',
            'artifactPathDigest', 'targetPathDigest'}
            or result['schemaVersion'] != 1
            or result['kind'] != 'pr315-candidate-output-symlink'
            or result['caseId'] != 'output-symlink' or result['nonce'] != nonce
            or result['pid'] != actor_before['namespacePids'][-1]
            or result['uid'] != uid or result['gid'] != gid
            or result['artifactPathDigest'] != hashlib.sha256(
                b'/node/tmp/pr315-output-symlink-artifact').hexdigest()
            or result['targetPathDigest'] != hashlib.sha256(
                b'/node/tmp/pr315-output-target-canary').hexdigest()
            or denial != 'workload-snapshot-file-invalid'
            or any(actor_before[key] != actor_after[key] for key in stable_actor)
            or any(collector_before[key] != collector_after[key]
                   for key in stable_collector)
            or before['managerInvocation'] != after['managerInvocation']
            or before['cgroupIdentity'] != after['cgroupIdentity']
            or re.fullmatch('[0-9a-f]{64}', str(before['stateDigest'])) is None
            or before['stateDigest'] != after['stateDigest']
            or target_before['controlDigest'] != target_after['controlDigest']
            or target_before['fileIdentity'] != target_after['fileIdentity']
            or not before['observedMonotonicNs'] < target_before['observedMonotonicNs']
                < collector_before['observedMonotonicNs'] < trigger_ns
                < result['startedMonotonicNs'] < result['finishedMonotonicNs']
                < started < finished < target_after['observedMonotonicNs']
                < collector_after['observedMonotonicNs'] < after['observedMonotonicNs']):
        raise ValueError('workload-output-symlink-collector-invalid')
    audit = {'schemaVersion': 1,
        'kind': 'pr315-administrator-output-symlink-denial',
        'caseId': 'output-symlink', 'sourceDigest': source_digest,
        'nonceDigest': hashlib.sha256(nonce.encode()).hexdigest(),
        'actorUid': uid, 'actorBefore': actor_before, 'actorAfter': actor_after,
        'actorInvocationBefore': before['managerInvocation'],
        'actorInvocationAfter': after['managerInvocation'],
        'actorCgroupBefore': before['cgroupIdentity'],
        'actorCgroupAfter': after['cgroupIdentity'],
        'senderStateBefore': before['stateDigest'],
        'senderStateAfter': after['stateDigest'],
        'collectorBefore': collector_before, 'collectorAfter': collector_after,
        'collectorStartedNs': started, 'collectorFinishedNs': finished,
        'collectorDenial': denial, 'targetBefore': target_before,
        'targetAfter': target_after,
        'artifactIdentity': [info.st_dev, info.st_ino],
        'artifactOwnerUid': uid,
        'linkTargetDigest': hashlib.sha256(
            b'/node/tmp/pr315-output-target-canary').hexdigest(),
        'triggerMonotonicNs': trigger_ns,
        'attackStartedNs': result['startedMonotonicNs'],
        'attackFinishedNs': result['finishedMonotonicNs']}
    workload.write(workload.ROOT / 'authority/output-symlink-denial.json',
                   audit, create=True)
    return hashlib.sha256(json.dumps(audit, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()


def probe_observer_private_read(workload, handoff, observer, source_digest,
                                sibling_digest, resolver_digest,
                                campaign_deadline_ns):
    """Measure a real role child opening an active observer-owned canary."""
    if time.monotonic_ns() >= campaign_deadline_ns:
        raise ValueError('workload-role-probe-campaign-expired')
    canary = Path('/var/lib/cryptad-cross-version/experiments/pr315-installed-workload/observer-private-canary')
    data = secrets.token_bytes(32)
    descriptor = os.open(canary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
        os.fchown(descriptor, observer.pw_uid, observer.pw_gid)
    finally:
        os.close(descriptor)
    expected = hashlib.sha256(data).hexdigest()
    if _observer_canary_control(canary, observer) != expected:
        raise ValueError('workload-observer-private-control-mismatch')
    nonce = secrets.token_hex(32)
    launch = workload.read(workload.ROOT / 'roles/candidate-sender/launch.json')
    request = {'schemaVersion': 1, 'caseId': 'observer-private-read', 'nonce': nonce,
               'bootId': workload.boot(), 'javaDigest': launch['javaDigest'],
               'sourceDigest': source_digest}
    workload.write(workload.ROOT / 'probe-requests/candidate-sender.json',
                   request, create=True, mode=0o444)
    role = 'candidate-sender'
    uid = workload.account(role).pw_uid
    probe_root = workload.ROOT / 'state/candidate-sender/tmp'
    ready_path = probe_root / 'pr315-observer-private-read-ready.json'
    result_path = probe_root / 'pr315-observer-private-read.json'
    until = min(time.monotonic() + 25, campaign_deadline_ns / 1e9)
    while time.monotonic() < until and not ready_path.exists():
        time.sleep(.05)
    if not ready_path.exists():
        raise ValueError('workload-role-probe-ready-timeout')
    ready = _candidate_probe_file(ready_path, uid)
    if (not isinstance(ready, dict) or set(ready) != {
            'schemaVersion', 'kind', 'caseId', 'nonce', 'pid', 'startedMonotonicNs'}
            or ready['schemaVersion'] != 1 or ready['kind'] != 'pr315-candidate-role-probe-ready'
            or ready['caseId'] != 'observer-private-read' or ready['nonce'] != nonce):
        raise ValueError('workload-role-probe-ready-invalid')
    before = workload.observe(handoff['handles'][role])
    actor_before = _role_probe_actor(before, nonce)
    if ready['pid'] != actor_before['namespacePids'][-1]:
        raise ValueError('workload-role-probe-pid-unbound')
    target_before = _observer_canary_control(canary, observer)
    if target_before != expected:
        raise ValueError('workload-role-probe-target-changed')
    sibling_path = workload.ROOT / 'state/candidate-recipient' / SIBLING_CANARY
    recipient_user = workload.account('candidate-recipient')
    recipient_before = workload.observe(handoff['handles']['candidate-recipient'])
    sibling_before = _observer_canary_control(
        sibling_path, recipient_user, 'workload-sibling-data-control-failed')
    package_before = _staged_package_digest(workload)
    resolver_before = _resolver_target_control(resolver_digest)
    if sibling_before != sibling_digest:
        raise ValueError('workload-sibling-data-target-changed')
    trigger_ns = time.monotonic_ns()
    trigger = probe_root / 'pr315-observer-private-read-trigger.json'
    descriptor = os.open(trigger, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    try:
        with os.fdopen(descriptor, 'w', closefd=False) as stream:
            json.dump({'caseId': 'observer-private-read', 'nonce': nonce}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.fchmod(descriptor, 0o444)
    finally:
        os.close(descriptor)
    while time.monotonic() < until and not result_path.exists():
        time.sleep(.05)
    if not result_path.exists():
        raise ValueError('workload-role-probe-result-timeout')
    result = _candidate_probe_file(result_path, uid)
    resolver_after = _resolver_target_control(resolver_digest)
    after = workload.observe(handoff['handles'][role])
    actor_after = _role_probe_actor(after, nonce)
    target_after = _observer_canary_control(canary, observer)
    recipient_after = workload.observe(handoff['handles']['candidate-recipient'])
    sibling_after = _observer_canary_control(
        sibling_path, recipient_user, 'workload-sibling-data-control-failed')
    package_after = _staged_package_digest(workload)
    _validate_role_probe_result(ready, before, actor_before, after, actor_after,
                                result, expected, target_after, nonce, trigger_ns)
    audit = {'schemaVersion': 1, 'kind': 'pr315-administrator-observer-private-read',
             'caseId': 'observer-private-read', 'sourceDigest': source_digest,
             'nonceDigest': hashlib.sha256(nonce.encode()).hexdigest(),
             'actorUid': uid,
             'actorBefore': actor_before, 'actorAfter': actor_after,
             'roleInvocationBefore': before['managerInvocation'],
             'roleInvocationAfter': after['managerInvocation'],
             'targetDigestBefore': target_before, 'targetDigestAfter': target_after,
             'triggerMonotonicNs': trigger_ns,
             'attackStartedNs': result['startedMonotonicNs'],
             'attackFinishedNs': result['finishedMonotonicNs'],
             'kernelOpenResult': result['outcome'],
             'controllerObservedBeforeNs': before['observedMonotonicNs'],
             'controllerObservedAfterNs': after['observedMonotonicNs']}
    workload.write(workload.ROOT / 'authority/observer-private-read-denial.json', audit, create=True)
    write = _validate_role_probe_write(result, after)
    write_audit = {**audit, 'kind': 'pr315-administrator-observer-private-write',
                   'caseId': 'observer-private-write',
                   'attackStartedNs': write['startedMonotonicNs'],
                   'attackFinishedNs': write['finishedMonotonicNs'],
                   'kernelOpenResult': write['outcome']}
    workload.write(workload.ROOT / 'authority/observer-private-write-denial.json',
                   write_audit, create=True)
    identity, counters = _validate_false_role_claims(result, before, after,
                                                     actor_before, uid)
    claim_base = {'schemaVersion': 1, 'sourceDigest': source_digest,
                  'nonceDigest': audit['nonceDigest'], 'actorUid': uid,
                  'actorBefore': actor_before, 'actorAfter': actor_after,
                  'roleInvocationBefore': before['managerInvocation'],
                  'roleInvocationAfter': after['managerInvocation'],
                  'cgroupIdentityBefore': before['cgroupIdentity'],
                  'cgroupIdentityAfter': after['cgroupIdentity'],
                  'targetActiveBeforeNs': before['observedMonotonicNs'],
                  'targetActiveAfterNs': after['observedMonotonicNs'],
                  'denial': 'kernel-mismatch-observed'}
    identity_audit = {**claim_base,
        'kind': 'pr315-administrator-forged-runtime-identity',
        'caseId': 'forged-runtime-identity',
        'attackStartedNs': identity['startedMonotonicNs'],
        'attackFinishedNs': identity['finishedMonotonicNs'],
        'claimedHostPid': identity['claimedHostPid'],
        'claimedHostUid': identity['claimedHostUid'],
        'actualHostPid': actor_before['hostPid'], 'actualHostUid': uid}
    workload.write(workload.ROOT / 'authority/forged-runtime-identity-denial.json',
                   identity_audit, create=True)
    counter_audit = {**claim_base, 'kind': 'pr315-administrator-forged-counters',
        'caseId': 'forged-counters',
        'attackStartedNs': counters['startedMonotonicNs'],
        'attackFinishedNs': counters['finishedMonotonicNs'],
        'claimedMemoryCurrentBytes': counters['claimedMemoryCurrentBytes'],
        'claimedTasksCurrent': counters['claimedTasksCurrent'],
        'actualMemoryBefore': before['cgroupMemoryBytes'],
        'actualTasksBefore': before['cgroupTasks'],
        'actualMemoryAfter': after['cgroupMemoryBytes'],
        'actualTasksAfter': after['cgroupTasks']}
    workload.write(workload.ROOT / 'authority/forged-counters-denial.json',
                   counter_audit, create=True)
    if (recipient_before['managerInvocation'] != recipient_after['managerInvocation']
            or recipient_before['cgroupIdentity'] != recipient_after['cgroupIdentity']
            or sibling_before != sibling_digest or sibling_after != sibling_digest):
        raise ValueError('workload-sibling-data-target-changed')
    if package_before != package_after:
        raise ValueError('workload-package-target-changed')
    if before['cgroupIdentity'] != after['cgroupIdentity']:
        raise ValueError('workload-cgroup-target-changed')
    accesses = _validate_fixed_role_accesses(result, after)
    resolver_read = _validate_resolver_read(
        result, before, after, resolver_before, resolver_after)
    fixed_audits = {}
    target_map = {
        'sibling-data': ('candidate-recipient', recipient_before, recipient_after,
                         sibling_before, sibling_after),
        'package-expectation': ('candidate-sender', before, after,
                                package_before, package_after),
        'cgroup-migration': ('candidate-recipient', recipient_before, recipient_after,
                             _cgroup_control_digest(recipient_before),
                             _cgroup_control_digest(recipient_after))}
    for case_id, row in accesses.items():
        target_role, first, last, control_before, control_after = target_map[case_id]
        target_first = _fixed_role_target(target_role, first, control_before)
        target_last = _fixed_role_target(target_role, last, control_after)
        if target_first['controlDigest'] != target_last['controlDigest']:
            raise ValueError('workload-' + case_id + '-target-changed')
        fixed_audit = {'schemaVersion': 1,
            'kind': 'pr315-administrator-fixed-role-access-denial', 'caseId': case_id,
            'sourceDigest': source_digest, 'nonceDigest': audit['nonceDigest'],
            'actorUid': uid, 'actorBefore': actor_before, 'actorAfter': actor_after,
            'actorInvocationBefore': before['managerInvocation'],
            'actorInvocationAfter': after['managerInvocation'],
            'actorCgroupBefore': before['cgroupIdentity'],
            'actorCgroupAfter': after['cgroupIdentity'],
            'targetBefore': target_first, 'targetAfter': target_last,
            'attackStartedNs': row['startedMonotonicNs'],
            'attackFinishedNs': row['finishedMonotonicNs'],
            'kernelOpenResult': row['outcome'], 'writtenBytes': row['writtenBytes']}
        workload.write(workload.ROOT / 'authority' / (case_id + '-denial.json'),
                       fixed_audit, create=True)
        fixed_audits[case_id] = hashlib.sha256(json.dumps(fixed_audit,
            sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    resolver_audit = {'schemaVersion': 1,
        'kind': 'pr315-administrator-resolver-authority-denial',
        'caseId': 'resolver-authority', 'sourceDigest': source_digest,
        'nonceDigest': audit['nonceDigest'], 'actorUid': uid,
        'actorBefore': actor_before, 'actorAfter': actor_after,
        'actorInvocationBefore': before['managerInvocation'],
        'actorInvocationAfter': after['managerInvocation'],
        'actorCgroupBefore': before['cgroupIdentity'],
        'actorCgroupAfter': after['cgroupIdentity'],
        'actorStateBefore': before['stateDigest'],
        'actorStateAfter': after['stateDigest'],
        'targetBefore': resolver_before, 'targetAfter': resolver_after,
        'targetPathDigest': resolver_read['targetPathDigest'],
        'attackStartedNs': resolver_read['startedMonotonicNs'],
        'attackFinishedNs': resolver_read['finishedMonotonicNs'],
        'kernelOpenResult': resolver_read['outcome']}
    workload.write(workload.ROOT / 'authority/resolver-authority-denial.json',
                   resolver_audit, create=True)
    resolver_audit_digest = hashlib.sha256(json.dumps(resolver_audit,
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    network_audits = probe_sibling_network(
        workload, handoff, nonce, source_digest, campaign_deadline_ns)
    return {'status': 'captured', 'caseId': 'observer-private-read',
            'auditDigest': hashlib.sha256(json.dumps(audit, sort_keys=True,
                separators=(',', ':')).encode()).hexdigest(),
            'writeStatus': 'captured',
            'writeAuditDigest': hashlib.sha256(json.dumps(write_audit, sort_keys=True,
                separators=(',', ':')).encode()).hexdigest(),
            'identityStatus': 'captured',
            'identityAuditDigest': hashlib.sha256(json.dumps(identity_audit, sort_keys=True,
                separators=(',', ':')).encode()).hexdigest(),
            'counterStatus': 'captured',
            'counterAuditDigest': hashlib.sha256(json.dumps(counter_audit, sort_keys=True,
                separators=(',', ':')).encode()).hexdigest(),
            'fixedAccessAudits': fixed_audits,
            'resolverAuditDigest': resolver_audit_digest,
            'networkAudits': network_audits}


def _readiness_java_process(workload, handoff):
    """Select one current role JVM from trusted service and kernel observations."""
    for role in reversed(ROLE_NAMES):
        state = workload.manager(role, 'show')
        if state['ActiveState'] != 'active' or state['SubState'] != 'running':
            continue
        observed = workload.observe(handoff['handles'][role])
        expected = handoff['expectedJdkDigests'][role]
        processes = [row for row in observed['processes']
                     if row['executableDigest'] == expected]
        if len(processes) != 1:
            raise ValueError('workload-readiness-jvm-ambiguous-or-absent')
        return role, observed['managerInvocation'], processes[0]
    raise ValueError('workload-readiness-no-active-role')


def capture_readiness_jcmd(workload, handoff):
    """Collect two bounded JVM diagnostics before a failed role is stopped."""
    from bounded_process import run
    path = READINESS_JCMD
    try:
        role, invocation, process = _readiness_java_process(workload, handoff)
        java = workload.ROOT / 'roles' / role / 'jdk/bin/jcmd'
        if not java.is_file():
            raise ValueError('workload-readiness-jcmd-unavailable')
        record = {'schemaVersion': 1, 'kind': 'pr315-private-readiness-jcmd',
                  'classification': 'private-diagnostic-not-acceptance',
                  'role': role, 'managerInvocation': invocation,
                  'hostPid': process['hostPid'], 'startTicks': process['startTicks'],
                  'executableDigest': process['executableDigest'], 'commands': {}}
        for name, limit, timeout in (('VM.command_line', 4096, 5),
                                     ('Thread.print -l', 131072, 8)):
            captured = {'stdout': b'', 'stderr': b''}
            def retain(stdout, stderr):
                captured.update(stdout=stdout, stderr=stderr)
            try:
                run([str(java), str(process['hostPid']), *name.split()],
                    environment={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'},
                    timeout=timeout, output_limit=limit, diagnostic_sink=retain)
                status = 'completed'
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                status = (str(error) if str(error) in {
                    'bounded_process_failed', 'bounded_process_deadline_exceeded',
                    'bounded_process_output_exceeded'} else type(error).__name__)
            record['commands'][name] = {'status': status,
                'stdoutBase64': base64.b64encode(captured['stdout']).decode(),
                'stderrBase64': base64.b64encode(captured['stderr'][:2048]).decode()}
        raw = json.dumps(record, sort_keys=True, separators=(',', ':')).encode()
        if len(raw) > 262144:
            raise ValueError('workload-readiness-jcmd-record-too-large')
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        return {'status': 'retained', 'role': role,
                'commandStatuses': {key: row['status'] for key, row in record['commands'].items()},
                'privateDigest': hashlib.sha256(raw).hexdigest()}
    except (OSError, ValueError, KeyError, TypeError, IndexError,
            subprocess.SubprocessError) as error:
        return {'status': 'unavailable-or-unsafe', 'exceptionType': type(error).__name__[:128]}


def cleanup(workload):
    """Fence launch before terminal owner shutdown, within the existing stop budget."""
    deadline = time.monotonic() + 110
    fence_deadline = time.monotonic() + 35
    try:
        while True:
            try:
                workload.fence_campaign()
                break
            except BlockingIOError:
                if time.monotonic() >= fence_deadline:
                    raise ValueError('workload-terminal-fence-timeout') from None
                time.sleep(.05)
    finally:
        # A failed fence must still attempt exact installed owner shutdown. It must
        # not fall through to network deletion or a successful terminal record.
        subprocess.run(['/usr/bin/systemctl', 'stop', 'cryptad-workload-controller.service'],
                       check=True, timeout=max(.001, deadline - time.monotonic()), env=ENV)
    workload.reconcile()
    with workload.locked():
        if not all(workload.quiescent(role) for role in workload.ROLES):
            raise ValueError('workload-terminal-cgroups-not-empty')
        from restricted_workload_network import teardown
        teardown()
    # Role tmpfs state and records remain explicitly retained for private diagnostics.


def begin_cancellation(workload, handoff, result):
    """Observe four current, populated role cgroups before administrator-owned stop."""
    from cross_version_runtime import canonical_digest
    principals = result.get('roleKernelRoster') if isinstance(result, dict) else None
    if (not isinstance(principals, dict) or not isinstance(principals.get('roles'), list)
            or len(principals['roles']) != len(ROLE_NAMES)):
        raise ValueError('workload-cancellation-roster-unavailable')
    expected = {row['role']: row for row in principals['roles']}
    if set(expected) != set(ROLE_NAMES):
        raise ValueError('workload-cancellation-roster-invalid')
    rows = []
    with workload.locked():
        campaign = workload.read(workload.ROOT / 'campaign.json')
        workload.current(campaign)
        for role in ROLE_NAMES:
            _campaign, actual_role, record = workload.retained(handoff['handles'][role])
            state = workload.manager(role, 'show')
            if actual_role != role or state['ActiveState'] != 'active' or state['SubState'] != 'running':
                raise ValueError('workload-cancellation-role-not-active')
            workload.exact(role, record, state)
            if not state['MainPID'].isdecimal() or int(state['MainPID']) <= 0:
                raise ValueError('workload-cancellation-role-main-pid-invalid')
            events = (workload.group(role) / 'cgroup.events').read_text().splitlines()
            if 'populated 1' not in events:
                raise ValueError('workload-cancellation-role-not-populated')
            row = expected[role]
            digest = canonical_digest({'role': role, 'identity': record['cgroupIdentity']})[7:]
            if (row['invocationId'] != record['managerInvocation']
                    or row['bootId'] != record['bootId'].replace('-', '').lower()
                    or row['cgroupDigest'] != digest):
                raise ValueError('workload-cancellation-roster-mismatch')
            rows.append({'role': role, 'managerInvocation': record['managerInvocation'],
                         'bootId': record['bootId'], 'cgroupIdentity': record['cgroupIdentity'],
                         'mainPid': int(state['MainPID'])})
        started = time.monotonic_ns()
        if started >= campaign['deadlineMonotonicNs']:
            raise ValueError('workload-cancellation-deadline')
        event = {'kind': 'cancellation', 'roles': rows,
                 'campaignDeadlineNs': campaign['deadlineMonotonicNs']}
        return {'schemaVersion': 1, 'kind': 'pr315-administrator-cancellation',
                'triggerStartedNs': started, 'triggerEventDigest': canonical_digest(event)[7:],
                'campaignDeadlineNs': campaign['deadlineMonotonicNs'], 'preRoles': rows}


def complete_cancellation(workload, context):
    """Bind the administrator stop to exact retained receipts and empty owned cgroups."""
    with workload.locked():
        for row in context['preRoles']:
            role = row['role']
            state = workload.manager(role, 'show')
            receipt = workload.read(workload.ROOT / 'authority' / (role + '-stop.json'))
            if (state['ActiveState'] not in {'inactive', 'failed'}
                    or state['SubState'] not in {'dead', 'failed'} or state['MainPID'] != '0'
                    or not workload.quiescent(role)
                    or any(receipt[key] != row[key] for key in
                           ('role', 'managerInvocation', 'bootId', 'cgroupIdentity'))):
                raise ValueError('workload-cancellation-terminal-mismatch')
        finished = time.monotonic_ns()
    if finished <= context['triggerStartedNs']:
        raise ValueError('workload-cancellation-clock-invalid')
    return {**context, 'terminalObservedNs': finished,
            'populatedCgroups': [], 'remainingDescendants': 0, 'retention': 'retained'}


def controller_unit_state():
    """Project the fixed installed controller's actual systemd invocation."""
    command = ['/usr/bin/systemctl', 'show', 'cryptad-workload-controller.service',
               '--property=InvocationID,ActiveState,SubState,MainPID,Result', '--no-pager']
    process = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                             env=ENV, timeout=35, check=True)
    if len(process.stdout) > 8192 or len(process.stderr) > 8192:
        raise ValueError('workload-controller-state-output-limit')
    state = dict(line.split('=', 1) for line in process.stdout.decode().splitlines() if '=' in line)
    if (set(state) != {'InvocationID', 'ActiveState', 'SubState', 'MainPID', 'Result'}
            or len(state['InvocationID']) != 32
            or any(character not in '0123456789abcdef' for character in state['InvocationID'])
            or not state['MainPID'].isdecimal()):
        raise ValueError('workload-controller-state-invalid')
    return state


def begin_controller_restart(workload, handoff, result):
    """Bind a fixed restart trigger to four independently observed active role cgroups."""
    from cross_version_runtime import canonical_digest
    active = begin_cancellation(workload, handoff, result)
    before = controller_unit_state()
    if (before['ActiveState'] != 'active' or before['SubState'] != 'running'
            or int(before['MainPID']) <= 0):
        raise ValueError('workload-controller-restart-not-active')
    event = {'kind': 'controller-restart', 'roles': active['preRoles'],
             'campaignDeadlineNs': active['campaignDeadlineNs'],
             'oldControllerInvocation': before['InvocationID']}
    started = time.monotonic_ns()
    if started >= active['campaignDeadlineNs']:
        raise ValueError('workload-controller-restart-deadline')
    return {'schemaVersion': 1, 'kind': 'pr315-administrator-controller-restart',
            'triggerStartedNs': started,
            'triggerEventDigest': canonical_digest(event)[7:],
            'campaignDeadlineNs': active['campaignDeadlineNs'],
            'preRoles': active['preRoles'], 'beforeController': before}


def wait_bound_roles_stopped(workload, context):
    """Observe BindsTo termination before starting a new controller invocation."""
    until = min(time.monotonic() + 35, context['campaignDeadlineNs'] / 10**9)
    while time.monotonic() < until:
        try:
            stopped = []
            for row in context['preRoles']:
                role = row['role']
                state = workload.manager(role, 'show')
                record = workload.read(workload.ROOT / 'authority' / (role + '.json'))
                receipt = workload.stop_receipt(role, record)
                if (state['ActiveState'] not in {'inactive', 'failed'}
                        or state['SubState'] not in {'dead', 'failed'} or state['MainPID'] != '0'
                        or not workload.quiescent(role)
                        or any(record[key] != row[key] for key in
                               ('managerInvocation', 'bootId', 'cgroupIdentity'))):
                    raise ValueError('workload-bound-role-still-active')
                stopped.append({'role': role, 'activeState': state['ActiveState'],
                                'subState': state['SubState'], 'mainPid': 0,
                                'receiptObservedMonotonicNs': receipt['observedMonotonicNs']})
            return stopped
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            time.sleep(min(.05, max(0, until - time.monotonic())))
    raise ValueError('workload-bound-role-stop-timeout')


def trigger_controller_restart(workload, context):
    """Kill the old main process, prove BindsTo stop, then start one new controller."""
    killed = subprocess.run(['/usr/bin/systemctl', 'kill', '--kill-who=main',
                             '--signal=SIGKILL', 'cryptad-workload-controller.service'],
                            stdin=subprocess.DEVNULL, capture_output=True,
                            env=ENV, timeout=20, check=True)
    bound_roles = wait_bound_roles_stopped(workload, context)
    requested = time.monotonic_ns()
    started = subprocess.run(['/usr/bin/systemctl', 'start',
                              'cryptad-workload-controller.service'],
                             stdin=subprocess.DEVNULL, capture_output=True,
                             env=ENV, timeout=100, check=False)
    after = controller_unit_state()
    if after['InvocationID'] == context['beforeController']['InvocationID']:
        raise ValueError('workload-controller-restart-invocation-unchanged')
    return {**context, 'killReturnCode': killed.returncode,
            'preStartBoundRoles': bound_roles,
            'newControllerStartRequestedNs': requested,
            'startReturnCode': started.returncode,
            'afterController': after}


def complete_controller_restart(workload, context):
    """Confirm BindsTo termination and retained reconciliation after the new invocation."""
    with workload.locked():
        for row in context['preRoles']:
            role = row['role']
            state = workload.manager(role, 'show')
            receipt = workload.read(workload.ROOT / 'authority' / (role + '-stop.json'))
            record = workload.read(workload.ROOT / 'authority' / (role + '.json'))
            if (state['ActiveState'] not in {'inactive', 'failed'}
                    or state['SubState'] not in {'dead', 'failed'} or state['MainPID'] != '0'
                    or not workload.quiescent(role)
                    or record['stopReason'] != 'controller-reconciliation'
                    or any(receipt[key] != row[key] for key in
                           ('role', 'managerInvocation', 'bootId', 'cgroupIdentity'))):
                raise ValueError('workload-controller-restart-terminal-mismatch')
        finished = time.monotonic_ns()
    if finished <= context['triggerStartedNs']:
        raise ValueError('workload-controller-restart-clock-invalid')
    return {**context, 'terminalObservedNs': finished,
            'populatedCgroups': [], 'remainingDescendants': 0, 'retention': 'retained'}


def wait_child(pid, deadline):
    """Reap only our unreaped child, including the interval after its output reaches EOF."""
    while True:
        observed, status = os.waitpid(pid, os.WNOHANG)
        if observed == pid:
            return status
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('workload-observer-exit-timeout')
        time.sleep(min(.02, remaining))


def stop_child(pid):
    """Bound termination; an unreaped child remains owned and cannot have its PID reused."""
    observed, _status = os.waitpid(pid, os.WNOHANG)
    if observed == pid:
        return
    os.kill(pid, signal.SIGKILL)
    wait_child(pid, time.monotonic() + 5)


class AdministratorFnpSampler:
    """Fixed administrator observations over this attempt's inherited private socket."""

    def __init__(self, workload, recipient_handle, diagnostics, sender_handle=None,
                 probe_digest=None, sender_jdk_digest=None):
        self.workload = workload
        self.recipient_handle = recipient_handle
        self.diagnostics = diagnostics
        self.phase = 'initial'
        self.sender_handle = sender_handle
        self.probe_digest = probe_digest
        self.sender_jdk_digest = sender_jdk_digest

    def probe(self):
        """Bind one live signed probe process, immutable app bytes and its first result."""
        import runtime_snapshot as snapshot
        from restricted_workload_storage import verify_installed_app
        from cross_version_runtime import digest_file
        workload = self.workload
        if (self.sender_handle is None or not isinstance(self.probe_digest, str)
                or not isinstance(self.sender_jdk_digest, str)):
            raise ValueError('workload-admin-probe-not-selected')
        first = workload.observe(self.sender_handle)
        if first.get('state') != 'running' or first.get('provenance') != 'controller-kernel-sample':
            raise ValueError('workload-admin-probe-target-inactive')
        with workload.locked():
            campaign, role, retained = workload.retained(self.sender_handle)
            if role != 'candidate-sender':
                raise ValueError('workload-admin-probe-role-invalid')
            workload.admit(campaign)
            workload.exact(role, retained, workload.manager(role, 'show'))
            launch = workload.read(workload.ROOT / 'roles/candidate-sender/launch.json')
            expected_tree = launch.get('probeIdentity')
            if not isinstance(expected_tree, dict):
                raise ValueError('workload-admin-probe-tree-unselected')
            verified_tree = verify_installed_app(
                workload.ROOT / 'state/candidate-sender/data/node/apps/installed/pr315-probe',
                expected_tree, workload.ROOT / 'authority/candidate-sender-probe-app-snapshot',
                min(time.monotonic() + 5, campaign['deadlineMonotonicNs'] / 1e9))
        raw = snapshot.read_file(
            workload.ROOT / 'state/candidate-sender/data/node/apps/data/pr315-probe',
            'pr315-probe-result-first.json', maximum=2048, timeout=2)
        result = json.loads(raw)
        if (not isinstance(result, dict) or not isinstance(result.get('mountEscape'), dict)
                or not isinstance(result.get('namespaceInodes'), dict)):
            raise ValueError('workload-admin-probe-result-invalid')
        namespaces = result['namespaceInodes']
        second = workload.observe(self.sender_handle)
        if (second.get('state') != 'running' or second.get('managerInvocation') != first['managerInvocation']
                or second.get('cgroupIdentity') != first['cgroupIdentity']
                or first.get('stateDigest') != second.get('stateDigest')
                or not isinstance(first.get('stateDigest'), str)):
            raise ValueError('workload-admin-probe-target-changed')
        processes = second.get('processes')
        if not isinstance(processes, list):
            raise ValueError('workload-admin-probe-processes-invalid')
        workers = [row for row in processes if isinstance(row, dict)
                   and isinstance(row.get('namespacePids'), list)
                   and len(row['namespacePids']) >= 3
                   and row['namespacePids'][-1] == result.get('pid')
                   and row.get('pidNamespace') == 'pid:[' + str(namespaces.get('pid')) + ']'
                   and isinstance(row.get('mountNamespaceIdentity'), list)
                   and len(row['mountNamespaceIdentity']) == 2
                   and row['mountNamespaceIdentity'][-1] == namespaces.get('mnt')]
        outers = [row for row in processes if isinstance(row, dict)
                  and row.get('executableDigest') == self.sender_jdk_digest
                  and isinstance(row.get('namespacePids'), list)
                  and len(row['namespacePids']) == 2]
        if len(workers) != 1 or len(outers) != 1:
            raise ValueError('workload-admin-probe-actor-ambiguous')
        worker, outer = workers[0], outers[0]
        leaders = [row for row in processes if isinstance(row, dict)
                   and row.get('hostPid') == worker.get('hostParentPid')
                   and isinstance(row.get('namespacePids'), list)
                   and len(row['namespacePids']) == 3
                   and row['namespacePids'][-1] == 1
                   and all(row.get(key) == worker.get(key) for key in
                           ('pidNamespace', 'mountNamespaceIdentity',
                            'userNamespaceIdentity', 'networkNamespaceIdentity'))]
        if len(leaders) != 1:
            raise ValueError('workload-admin-probe-leader-ambiguous')
        leader = leaders[0]
        account = workload.account('candidate-sender')
        ns = result.get('namespaceInodes')
        if (result.get('uid') != account.pw_uid or result.get('gid') != account.pw_gid
                or not isinstance(ns, dict)
                or worker.get('noNewPrivileges') is not True
                or worker.get('effectiveCapabilities') != 0
                or leader.get('noNewPrivileges') is not True
                or leader.get('effectiveCapabilities') != 0
                or type(leader.get('startTicks')) is not int
                or worker.get('startTicks', 0) < leader['startTicks']
                or worker.get('executableDigest') != digest_file('/usr/bin/python3')
                or worker.get('mountNamespaceIdentity', [None, None])[-1] != ns.get('mnt')
                or worker.get('userNamespaceIdentity', [None, None])[-1] != ns.get('user')
                or worker.get('networkNamespaceIdentity', [None, None])[-1] != ns.get('net')
                or worker.get('networkNamespaceIdentity') != second['networkNamespaceIdentity']
                or worker.get('pidNamespace') != 'pid:[' + str(ns.get('pid')) + ']'
                or worker.get('mountNamespaceIdentity') == outer.get('mountNamespaceIdentity')
                or result.get('mountEscape', {}).get('operation') != 'unshare-mount'
                or result['mountEscape'].get('returnCode') != -1
                or result['mountEscape'].get('errno') != 'EPERM'
                or not first['observedMonotonicNs'] < second['observedMonotonicNs']):
            raise ValueError('workload-admin-probe-boundary-invalid')
        record = {'schemaVersion': 1, 'kind': 'pr315-administrator-probe-process',
                  'caseId': 'namespace-mount-escape', 'role': 'candidate-sender',
                  'bundleDigest': self.probe_digest, 'verifiedTree': verified_tree,
                  'firstResultDigest': hashlib.sha256(raw).hexdigest(),
                  'senderUid': account.pw_uid, 'senderGid': account.pw_gid,
                  'managerInvocation': first['managerInvocation'], 'bootId': first['bootId'],
                  'cgroupIdentity': first['cgroupIdentity'],
                  'stateBefore': first['stateDigest'], 'stateAfter': second['stateDigest'],
                  'activeBeforeNs': first['observedMonotonicNs'],
                  'activeAfterNs': second['observedMonotonicNs'],
                  'worker': worker, 'sandboxLeader': leader, 'outer': outer}
        workload.write(workload.ROOT / 'authority/pr315-probe-process.json', record, create=True)
        return {'phase': 'probe', 'recordDigest': hashlib.sha256(json.dumps(
            record, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}

    def sample(self, phase):
        if (phase, self.phase) not in {('before', 'initial'), ('after', 'before')}:
            raise ValueError('workload-admin-fnp-phase-invalid')
        from restricted_workload_network import read_fnp_counters
        workload = self.workload
        with workload.locked():
            campaign, role, record = workload.retained(self.recipient_handle)
            if role != 'candidate-recipient':
                raise ValueError('workload-admin-fnp-recipient-invalid')
            workload.admit(campaign)
            workload.exact(role, record, workload.manager(role, 'show'))
            snapshot = read_fnp_counters()
            workload.exact(role, record, workload.manager(role, 'show'))
            workload.current(campaign)
            path = workload.ROOT / 'authority/fnp-content-probe.json'
            if phase == 'before':
                if os.path.lexists(path):
                    raise ValueError('workload-admin-fnp-pair-exists')
                pair = {'schemaVersion': 1, 'kind': 'pr315-administrator-fnp-counter-pair',
                        'caseId': 'fnp-content-retrieval', 'role': role,
                        'managerInvocation': record['managerInvocation'],
                        'before': snapshot, 'after': None}
                workload.write(path, pair, create=True)
            else:
                pair = workload.read(path)
                before = pair.get('before') if isinstance(pair, dict) else None
                if (not isinstance(pair, dict)
                        or set(pair) != {'schemaVersion', 'kind', 'caseId', 'role',
                                         'managerInvocation', 'before', 'after'}
                        or pair['schemaVersion'] != 1
                        or pair['kind'] != 'pr315-administrator-fnp-counter-pair'
                        or pair['caseId'] != 'fnp-content-retrieval' or pair['role'] != role
                        or pair['managerInvocation'] != record['managerInvocation']
                        or pair['after'] is not None or not isinstance(before, dict)
                        or any(before.get(key) != snapshot.get(key) for key in
                               ('policyDigest', 'bootId', 'switchNamespaceIdentity'))
                        or type(before.get('observedMonotonicNs')) is not int
                        or before['observedMonotonicNs'] >= snapshot['observedMonotonicNs']):
                    raise ValueError('workload-admin-fnp-pair-invalid')
                pair['after'] = snapshot
                workload.write(path, pair)
        self.phase = phase
        return {'phase': phase, 'managerInvocation': record['managerInvocation'],
                'snapshot': snapshot}

    def serve(self, channel):
        message, _ancillary, flags, _address = channel.recvmsg(2)
        if not message:
            return False
        try:
            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or message not in (b'B', b'A', b'P'):
                raise ValueError('workload-admin-fnp-request-invalid')
            result = (self.probe() if message == b'P' else
                      self.sample('before' if message == b'B' else 'after'))
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            private = getattr(error, 'private_diagnostics', None)
            if message == b'P':
                self.diagnostics['probeAdminFailure'] = {
                    'phase': 'probe', 'exceptionType': type(error).__name__[:128]}
                result = {'error': 'pr315-admin-probe-sample-failed'}
            else:
                self.diagnostics['fnpAdminFailure'] = {
                    'phase': self.phase, 'exceptionType': type(error).__name__[:128],
                    'networkFailureClass': (private.get('failureClass')
                        if isinstance(private, dict) and isinstance(private.get('failureClass'), str)
                        else None)}
                result = {'error': 'pr315-admin-fnp-sample-failed'}
        raw = json.dumps(result, sort_keys=True, separators=(',', ':')).encode() + b'\n'
        if len(raw) > 8192:
            raise ValueError('workload-admin-fnp-response-limit')
        channel.sendall(raw)
        return True


def request_administrator_fnp(channel, phase, campaign_deadline):
    """One fixed phase request; the administrator owns namespace access and durable pair."""
    from cross_version_runtime import RuntimeFailure
    if phase not in ('before', 'after', 'probe'):
        raise RuntimeFailure('workload-admin-fnp-phase-invalid')
    remaining = campaign_deadline / 10**9 - time.monotonic()
    if remaining <= 0:
        raise RuntimeFailure('workload-admin-fnp-deadline')
    channel.settimeout(min(90, remaining))
    try:
        channel.sendall({'before': b'B', 'after': b'A', 'probe': b'P'}[phase])
        raw = channel.recv(8193)
        if not 1 <= len(raw) <= 8192 or not raw.endswith(b'\n') or raw.count(b'\n') != 1:
            raise RuntimeFailure('workload-admin-fnp-response-invalid')
        value = json.loads(raw)
        if not isinstance(value, dict) or 'error' in value:
            raise RuntimeFailure('workload-admin-' +
                                 ('probe' if phase == 'probe' else 'fnp') + '-sample-failed')
        return value
    except RuntimeFailure:
        raise
    except (OSError, ValueError):
        raise RuntimeFailure('workload-admin-fnp-transport-failed') from None


def collect_child(parent, pid, deadline, sample=None, *, admin_channel=None, admin_sampler=None):
    raw = bytearray()
    next_sample = 0
    while time.monotonic() < deadline:
        if sample is not None and time.monotonic() >= next_sample:
            sample()
            next_sample = time.monotonic() + 5
        watched = [parent] if admin_channel is None else [parent, admin_channel]
        ready, _, _ = select.select(watched, [], [], min(1, max(.001, deadline - time.monotonic())))
        if admin_channel is not None and admin_channel in ready:
            if not admin_sampler.serve(admin_channel):
                admin_channel = None
        if parent in ready:
            block = parent.recv(65537 - len(raw))
            if not block:
                return bytes(raw), wait_child(pid, deadline)
            raw.extend(block)
            if len(raw) > 65536:
                raise ValueError('workload-observer-output-limit')
    raise ValueError('workload-observer-timeout')


def controller_ready(deadline):
    """Observe a root peer process serving the closed protocol, as the observer UID.

    The deliberately empty request must receive the fixed rejection. This is a readiness
    exchange, never an accepted workload operation or an acceptance case witness.
    """
    expected = b'{"error":"restricted-workload-request-failed"}\n'
    while time.monotonic() < deadline:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
                channel.settimeout(min(1, max(.001, deadline - time.monotonic())))
                channel.connect('/run/cryptad-workload/control.sock')
                _pid, uid, _gid = struct.unpack('3i', channel.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
                if uid != 0:
                    raise ValueError('workload-controller-peer-not-root')
                channel.sendall(b'{}\n')
                received = bytearray()
                while len(received) <= len(expected) and not received.endswith(b'\n'):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('readiness-deadline')
                    channel.settimeout(min(1, remaining))
                    chunk = channel.recv(len(expected) + 1 - len(received))
                    if not chunk:
                        break
                    received.extend(chunk)
                if received != expected:
                    raise ValueError('workload-controller-readiness-response-invalid')
                return
        except (FileNotFoundError, ConnectionRefusedError, TimeoutError):
            pass
        time.sleep(min(.05, max(0, deadline - time.monotonic())))
    raise ValueError('workload-controller-readiness-timeout')


def _kernel_read(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError('kernel-metric-not-regular')
        value = os.read(descriptor, 65537)
        if len(value) > 65536:
            raise ValueError('kernel-metric-too-large')
        return value.decode('ascii')
    finally:
        os.close(descriptor)


def controller_startup_snapshot(workload):
    """Capture the fixed root-private startup diagnostic before systemd removes it.

    This latest runtime checkpoint is neither an acceptance witness nor retained lifecycle
    authority. Its absence does not establish whether the controller ran or stopped.
    """
    try:
        value = workload.read(Path('/run/cryptad-workload/startup.json'))
        return {'status': 'captured', 'record': value,
                'observedMonotonicNs': time.monotonic_ns(),
                'classification': 'private-startup-diagnostic-not-acceptance'}
    except (OSError, ValueError):
        return {'status': 'unavailable-not-quiescence-proof'}


def readiness_deadline(campaign_deadline_ns, started, startup_measurement=False):
    """Prospective diagnostic observation never extends the retained execution deadline."""
    seconds = STARTUP_MEASUREMENT_SECONDS if startup_measurement else READINESS_SECONDS
    return min(campaign_deadline_ns / 10**9, started + seconds)


def observer_sequence(selected, root, handoff, campaign_deadline, startup_begin,
                      startup_measurement=False, *, admin_channel=None):
    """The diagnostic stops at the actual served readiness response, before any role start."""
    controller_ready(readiness_deadline(campaign_deadline, startup_begin, startup_measurement))
    if startup_measurement:
        return {'classification': 'startup-measurement-not-workload-acceptance',
                'controllerReadiness': 'observed-root-peer-response',
                'startupElapsedSeconds': time.monotonic() - startup_begin,
                'observationCeilingSeconds': STARTUP_MEASUREMENT_SECONDS,
                'installedPositiveExecuted': False}
    from cross_version_workload import InstalledWorkloadAdapter
    from cryptad_certification.cross_version_evidence import Journal
    with Journal(root, selected['plan']) as journal:
        journal.append('start')
        adapter = InstalledWorkloadAdapter(selected['plan'], selected['private'],
            selected['authorization'], journal, handoff,
            counter_sampler=(lambda phase: request_administrator_fnp(
                admin_channel, phase, campaign_deadline)) if admin_channel is not None else None)
        result = adapter.run_positive(leave_running_for_administrator=True)
        journal.checkpoint('partial')
    return result


def memory_snapshot():
    """Fixed private kernel metrics; absent cgroups never establish owned quiescence."""
    snapshot = {'observedMonotonicNs': time.monotonic_ns(), 'guest': {}, 'services': {}}
    try:
        snapshot['bootId'] = _kernel_read(Path('/proc/sys/kernel/random/boot_id')).strip()
        values = dict(line.split(':', 1) for line in _kernel_read(Path('/proc/meminfo')).splitlines())
        selected = {}
        for key in ('MemTotal', 'MemAvailable', 'SwapTotal', 'SwapFree', 'Shmem'):
            value, unit = values[key].split()
            if unit != 'kB' or not value.isdecimal():
                raise ValueError('guest-memory-invalid')
            selected[key + 'Bytes'] = int(value) * 1024
        snapshot['guest'] = {'status': 'observed', **selected}
    except (OSError, ValueError, KeyError):
        snapshot['guest'] = {'status': 'unavailable'}
    units = ['cryptad-workload-controller.service', *(
        'cryptad-workload@' + role + '.service' for role in ROLE_NAMES)]
    for unit in units:
        path = CGROUP_ROOT / unit
        try:
            before = path.stat(follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                raise ValueError('cgroup-not-directory')
            metrics = {}
            for name in ('memory.current', 'memory.max', 'memory.swap.max', 'pids.current', 'pids.max'):
                raw = _kernel_read(path / name).strip()
                if raw != 'max' and not raw.isdecimal():
                    raise ValueError('cgroup-metric-invalid')
                metrics[name] = raw if raw == 'max' else int(raw)
            for name in ('memory.events', 'cgroup.events', 'cpu.stat'):
                rows = [line.split() for line in _kernel_read(path / name).splitlines()]
                if any(len(row) != 2 or not row[1].isdecimal() for row in rows):
                    raise ValueError('cgroup-events-invalid')
                metrics[name] = {key: int(value) for key, value in rows}
            quota, period = _kernel_read(path / 'cpu.max').split()
            if (quota != 'max' and not quota.isdecimal()) or not period.isdecimal() or int(period) <= 0:
                raise ValueError('cgroup-cpu-limit-invalid')
            metrics['cpu.max'] = {'quota': quota if quota == 'max' else int(quota), 'period': int(period)}
            after = path.stat(follow_symlinks=False)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise ValueError('cgroup-replaced')
            snapshot['services'][unit] = {'status': 'observed',
                'cgroupIdentity': [before.st_dev, before.st_ino], **metrics}
        except FileNotFoundError:
            snapshot['services'][unit] = {'status': 'absent-or-removed-not-quiescence-proof'}
        except (OSError, ValueError):
            snapshot['services'][unit] = {'status': 'unavailable'}
    snapshot['finishedMonotonicNs'] = time.monotonic_ns()
    return snapshot


def sample_memory(diagnostics):
    """Keep constant-size sampled peaks, explicitly neither continuous nor OOM attribution."""
    snapshot = memory_snapshot()
    live = diagnostics.setdefault('during', {'sampleCount': 0, 'services': {},
        'classification': 'five-second-sampled-not-continuous'})
    live['sampleCount'] += 1
    live['last'] = snapshot
    guest = snapshot['guest']
    if guest['status'] == 'observed':
        available = guest['MemAvailableBytes']
        live['minimumObservedGuestAvailableBytes'] = min(
            live.get('minimumObservedGuestAvailableBytes', available), available)
    for unit, metrics in snapshot['services'].items():
        if metrics['status'] != 'observed':
            continue
        peak = live['services'].setdefault(unit, {'sampleCount': 0,
            'maximumObservedMemoryBytes': 0, 'maximumObservedTasks': 0})
        peak['sampleCount'] += 1
        peak['maximumObservedMemoryBytes'] = max(peak['maximumObservedMemoryBytes'], metrics['memory.current'])
        peak['maximumObservedTasks'] = max(peak['maximumObservedTasks'], metrics['pids.current'])
        peak['lastObserved'] = metrics
        peak['lastObservedWindow'] = {'startedMonotonicNs': snapshot['observedMonotonicNs'],
                                      'finishedMonotonicNs': snapshot['finishedMonotonicNs']}


def observer_failure(error):
    """Keep a bounded immediate propagation cause in the existing private child response."""
    from pr315_workload_guest import _bounded_text
    result = {'observerFailure': _bounded_text(type(error).__name__, 128),
              'privateDetail': _bounded_text(str(error), 1024)}
    cause = error.__cause__
    if cause is not None and cause is not error:
        result['immediateCause'] = {'exceptionType': _bounded_text(type(cause).__name__, 128),
            'privateDetail': _bounded_text(str(cause), 512),
            'meaning': 'python-explicit-cause-not-acceptance'}
    # A shared deadline exception alone cannot locate the expired operation. Retain
    # bounded code locations, never frame locals, source lines or absolute paths.
    components = {'cross_version_workload.py', 'cross_version_runtime.py',
                  'interop_smoke.py', 'pr314_workload_driver.py'}
    frames = []
    current = error.__traceback__
    for _ in range(64):
        if current is None:
            break
        code = current.tb_frame.f_code
        component = Path(code.co_filename).name
        if (component in components and code.co_name.isascii()
                and code.co_name.isidentifier() and len(code.co_name) <= 64):
            frames.append(component + ':' + code.co_name + ':' + str(current.tb_lineno))
        current = current.tb_next
    if frames:
        result['privateCodeLocations'] = frames[-8:]
    return result


def controller_unit_identity(workload):
    """Measure the active installed controller unit from the administrator process."""
    unit = 'cryptad-workload-controller.service'
    selected = subprocess.run(['/usr/bin/systemctl', 'show', unit,
        '--property=InvocationID,ActiveState,SubState,MainPID,ControlGroup', '--no-pager'],
        stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=5, env=ENV)
    if len(selected.stdout) > 8192 or selected.stderr:
        raise ValueError('runner-control-target-unavailable')
    state = dict(line.split('=', 1) for line in selected.stdout.decode().splitlines() if '=' in line)
    group = '/system.slice/' + unit
    if (set(state) != {'InvocationID', 'ActiveState', 'SubState', 'MainPID', 'ControlGroup'}
            or re.fullmatch('[0-9a-f]{32}', state['InvocationID']) is None
            or state['ActiveState'] != 'active' or state['SubState'] != 'running'
            or not state['MainPID'].isdecimal() or int(state['MainPID']) <= 1
            or state['ControlGroup'] != group):
        raise ValueError('runner-control-target-inactive')
    pid = int(state['MainPID'])
    process = Path('/proc') / str(pid)
    if process.joinpath('cgroup').read_text().strip() != '0::' + group:
        raise ValueError('runner-control-target-cgroup-changed')
    start_ticks = int(process.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19])
    identity = (Path('/sys/fs/cgroup') / group.removeprefix('/')).stat()
    return {'invocationId': state['InvocationID'],
            'cgroupIdentity': [identity.st_dev, identity.st_ino],
            'bootId': workload.boot(), 'mainPid': pid, 'mainStartTicks': start_ticks,
            'observedMonotonicNs': time.monotonic_ns()}


def bounded_runner_control_output(process):
    """Collect at most 2 KiB from the exact systemctl child within 15 seconds."""
    streams = (process.stdout, process.stderr)
    data = [bytearray(), bytearray()]
    pending = {stream.fileno(): index for index, stream in enumerate(streams)}
    deadline = time.monotonic() + 15
    try:
        for descriptor in pending:
            os.set_blocking(descriptor, False)
        while pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('runner-control-request-timeout')
            readable, _, _ = select.select(tuple(pending), [], [], remaining)
            if not readable:
                raise ValueError('runner-control-request-timeout')
            for descriptor in readable:
                count = sum(map(len, data))
                chunk = os.read(descriptor, max(1, 2049 - count))
                if chunk:
                    data[pending[descriptor]].extend(chunk)
                    if sum(map(len, data)) > 2048:
                        raise ValueError('runner-control-output-limit')
                else:
                    del pending[descriptor]
        process.wait(timeout=max(.001, deadline - time.monotonic()))
        return bytes(data[0]), bytes(data[1])
    except (ValueError, subprocess.TimeoutExpired):
        if process.poll() is None:
            process.kill()
        process.wait(timeout=2)
        raise
    finally:
        for stream in streams:
            stream.close()


def probe_runner_control(workload, handoff, result):
    """Bind a vmadmin systemd denial to the active controller and sender epochs."""
    roster = result['roleKernelRoster']
    window = result['roleKernelRosterWindow']
    runner = pwd.getpwnam('vmadmin')
    if (runner.pw_uid <= 0 or runner.pw_uid != roster['runnerUid']
            or not isinstance(window, dict)):
        raise ValueError('runner-control-actor-invalid')
    handle = handoff['handles']['candidate-sender']
    before = controller_unit_identity(workload)
    sender_before = workload.observe(handle)
    if sender_before.get('state') != 'running' or sender_before.get('stateDigest') is None:
        raise ValueError('runner-control-sender-inactive')
    arguments = ['/usr/bin/systemctl', '--no-ask-password', 'stop',
                 'cryptad-workload-controller.service']
    request_raw = json.dumps(arguments, separators=(',', ':')).encode()

    def become_runner():
        os.setgroups([])
        os.setgid(runner.pw_gid)
        os.setuid(runner.pw_uid)

    started = time.monotonic_ns()
    process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, cwd='/', env=ENV, preexec_fn=become_runner,
                               start_new_session=True)
    actor_path = Path('/proc') / str(process.pid)
    try:
        status = dict(line.split(':', 1) for line in actor_path.joinpath('status').read_text().splitlines()
                      if ':' in line)
        if set(map(int, status['Uid'].split())) != {runner.pw_uid}:
            raise ValueError('runner-control-actor-uid-changed')
        actor_start = int(actor_path.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19])
        stdout, stderr = bounded_runner_control_output(process)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)
    responded = time.monotonic_ns()
    if process.returncode == 0:
        raise RuntimeError('runner-control-forbidden-unit-stop-admitted')
    if (stdout or not 1 <= len(stderr) <= 2048
            or not any(marker in stderr for marker in
                       (b'Interactive authentication required', b'Access denied'))):
        raise ValueError('runner-control-policy-denial-unobserved')
    sender_after = workload.observe(handle)
    after = controller_unit_identity(workload)
    if (not window['finishedMonotonicNs'] < before['observedMonotonicNs'] < started
            < responded < after['observedMonotonicNs']
            or any(before[key] != after[key] for key in
                   ('invocationId', 'cgroupIdentity', 'bootId', 'mainPid', 'mainStartTicks'))
            or any(sender_before[key] != sender_after[key] for key in
                   ('managerInvocation', 'cgroupIdentity', 'bootId', 'stateDigest'))
            or sender_after.get('state') != 'running'):
        raise RuntimeError('runner-control-target-changed')
    audit = {'schemaVersion': 1, 'kind': 'pr315-administrator-runner-control-denial',
             'caseId': 'runner-control', 'actor': {'pid': process.pid,
                 'uid': runner.pw_uid, 'startTicks': actor_start},
             'roleKernelRoster': roster, 'roleKernelRosterWindow': window,
             'targetBefore': before, 'targetAfter': after,
             'senderManagerInvocation': sender_before['managerInvocation'],
             'senderCgroupIdentity': sender_before['cgroupIdentity'],
             'senderStateBefore': sender_before['stateDigest'],
             'senderStateAfter': sender_after['stateDigest'],
             'requestStartedNs': started, 'responseObservedNs': responded,
             'requestDigest': hashlib.sha256(request_raw).hexdigest(),
             'responseDigest': hashlib.sha256(stderr).hexdigest(),
             'responseBase64': base64.b64encode(stderr).decode('ascii'),
             'exitCode': process.returncode, 'stdoutBytes': len(stdout)}
    workload.write(workload.ROOT / 'authority/runner-control-denial.json', audit, create=True)
    return {'status': 'captured'}


def _write_volatile_bytes(path, raw):
    """Link one fully synced private file without replacing prior evidence."""
    temporary = path.with_name('.pr315-volatile-' + secrets.token_hex(16))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            if stream.write(raw) != len(raw):
                raise ValueError('workload-volatile-short-write')
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        temporary.unlink(missing_ok=True)


def retain_volatile(workload, value):
    """Publish only the fixed bounded private snapshot above the generic record cap.

    The controller's ordinary authority writer remains capped at 64 KiB. The
    administrator test kit alone owns this fixed root-only diagnostic path;
    no control-socket caller can choose a destination or a new size limit.
    """
    if os.geteuid() != 0 or VOLATILE != Path('/root/pr315-workload-volatile.private.json'):
        raise ValueError('workload-volatile-owner-or-path-invalid')
    workload.secured(VOLATILE.parent, directory=True)
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    if not 0 < len(raw) <= VOLATILE_MAX:
        raise ValueError('workload-volatile-output-limit')
    _write_volatile_bytes(VOLATILE, raw)


def execute(*, startup_measurement=False, lifecycle_scenario='cancellation',
            workload_group=None):
    if lifecycle_scenario not in LIFECYCLE_SCENARIOS:
        raise ValueError('workload-lifecycle-scenario-invalid')
    if workload_group not in (None, 'output-symlink') or (startup_measurement and workload_group):
        raise ValueError('workload-group-invalid')
    if (workload_group == 'output-symlink') != (lifecycle_scenario == 'none'):
        raise ValueError('workload-group-lifecycle-invalid')
    if prerequisites():
        raise ValueError('workload-reference-prerequisites-unavailable')
    sys.path.insert(0, str(INSTALLED / 'tools/release-certification/restricted'))
    sys.path.insert(0, str(INSTALLED / 'tools/release-certification/protected'))
    sys.path.insert(0, str(INSTALLED / 'tools/release-certification'))
    sys.path.insert(0, str(INSTALLED / 'tools/interop'))
    sys.path.insert(0, str(TEST_KIT / 'tools/release-certification/restricted'))
    import installation
    import workload_installation
    import restricted_workload as workload
    from restricted_workload_prepare import prepare
    from restricted_workload_launcher import launcher_policy
    import pr315_workload_evidence as evidence
    if (evidence.MAX_OUTPUT != VOLATILE_MAX
            or launcher_policy().get('privateVolatileMaxBytes') != VOLATILE_MAX):
        raise ValueError('workload-volatile-policy-mismatch')
    identity = installation.verify_execution()
    kit = installation.read_json(installation.secured(TEST_KIT / '.test-kit.json'))
    relative = 'tools/release-certification/restricted/pr314_workload_driver.py'
    import hashlib
    if (kit['sourceCommit'] != identity['sourceCommit']
            or Path(__file__).resolve() != TEST_KIT / relative
            or hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != kit['files'].get(relative)):
        raise ValueError('workload-test-kit-source-mismatch')
    selected = workload.read(SELECTION)
    if set(selected) != {'plan', 'private', 'authorization'}:
        raise ValueError('workload-test-selection-invalid')
    observer = pwd.getpwnam('cryptad-soak')
    root = Path(selected['private']['root'])
    if (root.parent != Path('/var/lib/cryptad-cross-version/experiments') or root.exists()
            or root.is_symlink()):
        raise ValueError('workload-observer-root-not-new')
    workload_installation.install()
    resolver_digest = (prepare_resolver_canary()
                       if not startup_measurement and workload_group is None else None)
    parent = child = admin_parent = admin_child = None
    pid = None
    status = None
    result = None
    diagnostics = {'classification': 'private-kernel-diagnostics-not-acceptance',
                   'before': memory_snapshot(), 'cleanup': 'not-completed'}
    sentinel = None
    cancellation = None
    controller_restart = None
    try:
        handoff = prepare(selected['plan'], selected['private'], selected['authorization'])
        role_probe_digest = stage_role_probe(workload, kit)
        sibling_digest = prepare_sibling_canary(workload)
        campaign_deadline = workload.read(workload.ROOT / 'campaign.json')['deadlineMonotonicNs']
        if type(campaign_deadline) is not int or campaign_deadline <= time.monotonic_ns():
            raise ValueError('workload-preparation-consumed-deadline')
        if (type(handoff.get('deadlineMonotonicNs')) is not int
                or handoff['deadlineMonotonicNs'] != campaign_deadline):
            raise ValueError('workload-handoff-deadline-mismatch')
        sentinel = evidence.prepare_sentinel(workload)
        root.mkdir(mode=0o700)
        os.chown(root, observer.pw_uid, observer.pw_gid)
        startup_begin = time.monotonic()
        subprocess.run(['/usr/bin/systemctl', 'start', 'cryptad-workload-controller.service'],
                       check=True, timeout=30, env=ENV)
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        admin_parent, admin_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        pid = os.fork()
        if pid == 0:
            parent.close()
            admin_parent.close()
            try:
                os.setgroups([])
                os.setgid(observer.pw_gid)
                os.setuid(observer.pw_uid)
                os.environ.clear()
                os.environ.update(ENV)
                os.umask(0o077)
                result = observer_sequence(selected, root, handoff, campaign_deadline,
                                           startup_begin, startup_measurement,
                                           admin_channel=admin_child)
                child.sendall(json.dumps(result, separators=(',', ':')).encode())
                child.close()
                admin_child.close()
                os._exit(0)
            except BaseException as error:
                try:
                    child.sendall(json.dumps(observer_failure(error)).encode())
                except OSError:
                    pass
                child.close()
                admin_child.close()
                os._exit(1)
        child.close()
        admin_child.close()
        # Preparation already started the campaign clock. Observation gets only the
        # original deadline plus bounded teardown grace, never a new execution budget.
        deadline = campaign_deadline / 10**9 + 100
        selected_apps = selected['private'].get('nodes', {}).get('candidate-sender', {}).get('apps', [])
        probe_digest = (selected_apps[1]['bundleDigest'] if len(selected_apps) == 2
                        and selected_apps[1]['appId'] == 'pr315-probe' else None)
        sampler = AdministratorFnpSampler(workload,
            handoff['handles']['candidate-recipient'], diagnostics,
            sender_handle=handoff['handles'].get('candidate-sender') if probe_digest else None,
            probe_digest=probe_digest,
            sender_jdk_digest=handoff.get('expectedJdkDigests', {}).get('candidate-sender'))
        raw, status = collect_child(parent, pid, deadline,
            lambda: sample_memory(diagnostics), admin_channel=admin_parent,
            admin_sampler=sampler)
        if status != 0:
            diagnostics['observerFailure'] = {'exitStatus': status,
                'privateTranscript': raw[:4096].decode('utf-8', errors='replace')}
            try:
                failure = json.loads(raw)
                if (failure.get('observerFailure') == 'RuntimeFailure'
                        and failure.get('privateDetail') == 'workload-daemon-readiness-timeout'):
                    diagnostics['readinessJcmd'] = capture_readiness_jcmd(workload, handoff)
            except (UnicodeError, ValueError, TypeError, AttributeError):
                diagnostics['readinessJcmd'] = {'status': 'failure-transcript-invalid'}
            raise ValueError('workload-positive-sequence-failed')
        result = json.loads(raw)
        if not startup_measurement and (result.get('contentRetrieval') != 'observed' or result.get('newEpoch') is not True):
            raise ValueError('workload-positive-observation-incomplete')
        result.update(identity=identity, runtimePolicy=launcher_policy(),
                      finiteNativeAcceptance='not-executed-by-this-driver',
                      campaignDeadlineMonotonicNs=campaign_deadline,
                      workloadAcceptance=('not-executed-startup-measurement' if startup_measurement
                          else 'incomplete-hostile-contract-not-executed'), protectedExecutionEnabled=False)
        if not startup_measurement and workload_group is None:
            try:
                diagnostics['runnerControl'] = probe_runner_control(workload, handoff, result)
            except (OSError, ValueError, KeyError, TypeError, IndexError,
                    subprocess.SubprocessError) as error:
                diagnostics['runnerControl'] = {'status': 'unavailable-or-unsafe',
                                                'exceptionType': type(error).__name__[:128]}
            try:
                private_probe = probe_observer_private_read(
                    workload, handoff, observer, role_probe_digest, sibling_digest,
                    resolver_digest,
                    campaign_deadline)
                diagnostics['observerPrivateRead'] = {key: private_probe[key]
                    for key in ('status', 'caseId', 'auditDigest')}
                diagnostics['observerPrivateWrite'] = {'status': private_probe['writeStatus'],
                    'caseId': 'observer-private-write',
                    'auditDigest': private_probe['writeAuditDigest']}
                diagnostics['forgedRuntimeIdentity'] = {
                    'status': private_probe['identityStatus'],
                    'caseId': 'forged-runtime-identity',
                    'auditDigest': private_probe['identityAuditDigest']}
                diagnostics['forgedCounters'] = {'status': private_probe['counterStatus'],
                    'caseId': 'forged-counters',
                    'auditDigest': private_probe['counterAuditDigest']}
                for case_id, field in (('sibling-data', 'siblingData'),
                                       ('package-expectation', 'packageExpectation'),
                                       ('cgroup-migration', 'cgroupMigration')):
                    diagnostics[field] = {'status': 'captured', 'caseId': case_id,
                                          'auditDigest': private_probe['fixedAccessAudits'][case_id]}
                for case_id, field in (('sibling-fcp', 'siblingFcp'),
                                       ('sibling-http', 'siblingHttp')):
                    diagnostics[field] = {'status': 'captured', 'caseId': case_id,
                                          'auditDigest': private_probe['networkAudits'][case_id]}
                diagnostics['resolverAuthority'] = {'status': 'captured',
                    'caseId': 'resolver-authority',
                    'auditDigest': private_probe['resolverAuditDigest']}
            except (OSError, ValueError, KeyError, TypeError, AttributeError,
                    subprocess.SubprocessError) as error:
                diagnostic = {'status': 'unavailable-or-unsafe',
                              'exceptionType': type(error).__name__[:128]}
                code = _private_role_probe_code(error)
                if code is not None:
                    diagnostic['code'] = code
                if isinstance(error, RoleProbeDiagnosticError):
                    diagnostic['observedOutcome'] = error.observed_outcome
                diagnostics['observerPrivateRead'] = diagnostic
                diagnostics['observerPrivateWrite'] = diagnostic
                diagnostics['forgedRuntimeIdentity'] = diagnostic
                diagnostics['forgedCounters'] = diagnostic
                for field in ('siblingData', 'packageExpectation', 'cgroupMigration'):
                    diagnostics[field] = diagnostic
                for field in ('siblingFcp', 'siblingHttp'):
                    diagnostics[field] = diagnostic
                diagnostics['resolverAuthority'] = diagnostic
        if not startup_measurement and workload_group == 'output-symlink':
            try:
                digest = probe_output_symlink(
                    workload, handoff, role_probe_digest, campaign_deadline)
                diagnostics['outputSymlink'] = {'status': 'captured',
                    'caseId': 'output-symlink', 'auditDigest': digest}
            except (OSError, ValueError, KeyError, TypeError, AttributeError,
                    subprocess.SubprocessError) as error:
                diagnostics['outputSymlink'] = {'status': 'unavailable-or-unsafe',
                    'exceptionType': type(error).__name__[:128],
                    'code': _private_role_probe_code(error)}
        if not startup_measurement and workload_group is None and lifecycle_scenario == 'cancellation':
            try:
                cancellation = begin_cancellation(workload, handoff, result)
                diagnostics['cancellation'] = cancellation
            except (OSError, ValueError, KeyError, TypeError, AttributeError,
                    subprocess.SubprocessError) as error:
                diagnostics['cancellation'] = {'status': 'unavailable-or-unsafe',
                                               'exceptionType': type(error).__name__[:128]}
        if not startup_measurement and workload_group is None and lifecycle_scenario == 'controller-restart':
            try:
                active = begin_controller_restart(workload, handoff, result)
                controller_restart = trigger_controller_restart(workload, active)
                diagnostics['controllerRestart'] = controller_restart
            except (OSError, ValueError, KeyError, TypeError, AttributeError,
                    subprocess.SubprocessError) as error:
                diagnostics['controllerRestart'] = {'status': 'unavailable-or-unsafe',
                                                    'exceptionType': type(error).__name__[:128]}
    finally:
        try:
            if parent is not None:
                parent.close()
            if child is not None:
                child.close()
            if admin_parent is not None:
                admin_parent.close()
            if admin_child is not None:
                admin_child.close()
            if pid is not None and pid > 0 and status is None:
                stop_child(pid)
        finally:
            try:
                diagnostics['controllerStartup'] = controller_startup_snapshot(workload)
                cleanup(workload)
                diagnostics['cleanup'] = 'completed'
                if cancellation is not None:
                    try:
                        diagnostics['cancellation'] = complete_cancellation(workload, cancellation)
                    except (OSError, ValueError, KeyError, TypeError, AttributeError,
                            subprocess.SubprocessError) as error:
                        diagnostics['cancellation'] = {'status': 'unavailable-or-unsafe',
                                                       'exceptionType': type(error).__name__[:128]}
                if controller_restart is not None:
                    try:
                        diagnostics['controllerRestart'] = complete_controller_restart(
                            workload, controller_restart)
                    except (OSError, ValueError, KeyError, TypeError, AttributeError,
                            subprocess.SubprocessError) as error:
                        diagnostics['controllerRestart'] = {'status': 'unavailable-or-unsafe',
                                                            'exceptionType': type(error).__name__[:128]}
            finally:
                diagnostics['after'] = memory_snapshot()
                workload.write(DIAGNOSTICS, diagnostics, create=True)
                volatile = evidence.capture(workload, sentinel, diagnostics['cleanup'] == 'completed',
                                            observer_root=root)
                retain_volatile(workload, volatile)
                if (sentinel is not None and diagnostics['cleanup'] == 'completed'
                        and volatile['sentinel']['status'] != 'matched'):
                    raise ValueError('workload-retained-sentinel-not-established')
    # No terminal result can exist before owned controller/role/network cleanup succeeds.
    workload.write(REPORT, result, create=True)
    return {'status': 'startup-measurement-executed' if startup_measurement else 'positive-sequence-executed',
            'workloadAcceptance': 'incomplete',
            'protectedExecutionEnabled': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--lifecycle-scenario', choices=LIFECYCLE_SCENARIOS,
                        default='cancellation')
    parser.add_argument('--workload-group', choices=('output-symlink',))
    args = parser.parse_args()
    reasons = prerequisites()
    if reasons:
        print(json.dumps({'status': 'not-executed', 'reasons': reasons, 'protectedExecutionEnabled': False}))
        return 78
    if not args.execute:
        print(json.dumps({'status': 'prerequisites-present-not-executed', 'protectedExecutionEnabled': False}))
        return 0
    print(json.dumps(execute(lifecycle_scenario=args.lifecycle_scenario,
                             workload_group=args.workload_group), sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        result = main()
    except Exception:
        print('{"status":"failed-private-reconciliation-required","protectedExecutionEnabled":false}')
        result = 1
    raise SystemExit(result)

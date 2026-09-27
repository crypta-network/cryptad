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
RETIRED_AUTHORITY = Path('/root/pr315-retired-authority.private.json')
RETIRED_AUTHORITY_SOURCE = Path('/root/pr315-retired-authority-source.private.json')
RESOURCE_CHILDREN = Path('/root/pr315-resource-children.private.json')
VOLATILE_MAX = 128 * 1024
DIAGNOSTICS = Path('/root/pr315-workload-memory.private.json')
READINESS_JCMD = Path('/root/pr315-readiness-jcmd.private.json')
REVOCATION_CONTROL_SOCKET = '/run/cryptad-workload/control.sock'
OBSERVER_DEATH_CONTROL_SOCKET = '/run/cryptad-workload/control.sock'
CGROUP_ROOT = Path('/sys/fs/cgroup/system.slice')
ROLE_NAMES = ('candidate-sender', 'candidate-recipient', 'previous', 'relay-no-apps')
READINESS_STAGES = ('start-request', 'fcp-get-node', 'daemon-epoch', 'journal-node-start')
LIFECYCLE_SCENARIOS = ('cancellation', 'controller-restart', 'deadline',
                       'revocation-running', 'setsid-double-fork',
                       'observer-death', 'none')
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
PROVIDER_PROBE_PATH = '/var/lib/cryptad-restricted/pr315-provider/pr315-provider-canary'
PROVIDER_CREDENTIAL_PATH = '/etc/cryptad-certification/restricted-provider.json'
PROVIDER_CONTEXT_ROOT = Path('/etc/cryptad-certification')
OUTPUT_CANARY = 'pr315-output-target-canary'
OUTPUT_SYMLINK = 'pr315-output-symlink-artifact'
OUTPUT_SYMLINK_READY = 'pr315-output-symlink-ready.json'
OUTPUT_SYMLINK_TRIGGER = 'pr315-output-symlink-trigger.json'
OUTPUT_SYMLINK_RESULT = 'pr315-output-symlink-result.json'
OUTPUT_FIFO = 'pr315-output-fifo-artifact'
OUTPUT_FIFO_READY = 'pr315-output-fifo-ready.json'
OUTPUT_FIFO_TRIGGER = 'pr315-output-fifo-trigger.json'
OUTPUT_FIFO_RESULT = 'pr315-output-fifo-result.json'
OUTPUT_HARDLINK = 'pr315-output-hardlink-artifact'
OUTPUT_HARDLINK_READY = 'pr315-output-hardlink-ready.json'
OUTPUT_HARDLINK_TRIGGER = 'pr315-output-hardlink-trigger.json'
OUTPUT_HARDLINK_RESULT = 'pr315-output-hardlink-result.json'
OUTPUT_FLOOD = 'pr315-output-flood-artifact'
OUTPUT_FLOOD_READY = 'pr315-output-flood-ready.json'
OUTPUT_FLOOD_TRIGGER = 'pr315-output-flood-trigger.json'
OUTPUT_FLOOD_RESULT = 'pr315-output-flood-result.json'
OUTPUT_FLOOD_BYTES = 65537
OUTPUT_REPLACEMENT = 'pr315-output-replacement-artifact'
OUTPUT_REPLACEMENT_READY = 'pr315-output-replacement-ready.json'
OUTPUT_REPLACEMENT_TRIGGER = 'pr315-output-replacement-trigger.json'
OUTPUT_REPLACEMENT_RESULT = 'pr315-output-replacement-result.json'
OUTPUT_REPLACEMENT_SWAP_TRIGGER = 'pr315-output-replacement-swap-trigger.json'
OUTPUT_REPLACEMENT_SWAP_RESULT = 'pr315-output-replacement-swap-result.json'
OUTPUT_ARTIFACTS = {
    'output-symlink': (OUTPUT_SYMLINK, OUTPUT_SYMLINK_READY,
                       OUTPUT_SYMLINK_TRIGGER, OUTPUT_SYMLINK_RESULT),
    'output-fifo': (OUTPUT_FIFO, OUTPUT_FIFO_READY,
                    OUTPUT_FIFO_TRIGGER, OUTPUT_FIFO_RESULT),
    'output-hardlink': (OUTPUT_HARDLINK, OUTPUT_HARDLINK_READY,
                        OUTPUT_HARDLINK_TRIGGER, OUTPUT_HARDLINK_RESULT),
    'output-flood': (OUTPUT_FLOOD, OUTPUT_FLOOD_READY,
                     OUTPUT_FLOOD_TRIGGER, OUTPUT_FLOOD_RESULT),
    'output-replacement': (OUTPUT_REPLACEMENT, OUTPUT_REPLACEMENT_READY,
                           OUTPUT_REPLACEMENT_TRIGGER, OUTPUT_REPLACEMENT_RESULT),
}
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
    'workload-output-fifo-ready-timeout', 'workload-output-fifo-result-timeout',
    'workload-output-fifo-actor-invalid', 'workload-output-fifo-target-invalid',
    'workload-output-fifo-collector-invalid',
    'workload-output-hardlink-ready-timeout', 'workload-output-hardlink-result-timeout',
    'workload-output-hardlink-actor-invalid', 'workload-output-hardlink-target-invalid',
    'workload-output-hardlink-collector-invalid',
    'workload-output-flood-ready-timeout', 'workload-output-flood-result-timeout',
    'workload-output-flood-actor-invalid', 'workload-output-flood-target-invalid',
    'workload-output-flood-collector-invalid',
    'workload-output-replacement-ready-timeout',
    'workload-output-replacement-result-timeout',
    'workload-output-replacement-actor-invalid',
    'workload-output-replacement-target-invalid',
    'workload-output-replacement-collector-invalid',
    'workload-output-replacement-swap-timeout',
    'workload-authority-actor-or-window-invalid',
    'workload-authority-operation-order-invalid',
    'workload-setsid-ready-invalid', 'workload-setsid-child-invalid',
    'workload-setsid-stop-invalid', 'workload-setsid-descendant-retained',
    'workload-sibling-network-deadline', 'workload-sibling-network-target-inactive',
    'workload-sibling-network-before-window-invalid',
    'workload-sibling-network-result-timeout', 'workload-sibling-network-probe-invalid',
    'workload-sibling-network-case-invalid',
    'workload-sibling-network-counter-context-invalid',
    'workload-sibling-network-counter-invalid',
    'workload-sibling-network-counter-epoch-invalid',
    'workload-sibling-network-drop-not-attributed',
    'workload-sibling-network-actor-changed',
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


def stage_lifecycle_probe(workload, kit):
    """Stage only the second measured fixed role actor for lifecycle barriers."""
    import installation
    relative = 'tools/release-certification/restricted/pr315_lifecycle_role_probe.py'
    source = TEST_KIT / relative
    raw = installation.secured(source).read_bytes()
    if (not 0 < len(raw) <= 8192
            or kit['files'].get(relative) != hashlib.sha256(raw).hexdigest()):
        raise ValueError('workload-lifecycle-probe-test-kit-mismatch')
    directory = workload.ROOT / 'probe-source'
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o022):
        raise ValueError('workload-lifecycle-probe-root-invalid')
    target = directory / 'pr315_lifecycle_role_probe.py'
    descriptor = os.open(target,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    try:
        os.fchmod(descriptor, 0o444)
        if os.write(descriptor, raw) != len(raw):
            raise ValueError('workload-lifecycle-probe-short-write')
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if target.read_bytes() != raw:
        raise ValueError('workload-lifecycle-probe-changed')
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


def _provider_target_control(provider_digest, resolver_digest,
                             credential_digest=None):
    """Bind one private synthetic provider subject to the live root service."""
    service = _resolver_target_control(resolver_digest)
    descriptor = os.open(PROVIDER_PROBE_PATH,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        raw = os.read(descriptor, 33)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
            or before.st_nlink != 1 or before.st_mode & 0o077
            or before.st_size != 32 or len(raw) != 32
            or any(getattr(before, key) != getattr(after, key)
                   for key in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))
            or hashlib.sha256(raw).hexdigest() != provider_digest):
        raise ValueError('workload-provider-target-invalid')
    credential = None
    if credential_digest is not None:
        descriptor = os.open(PROVIDER_CREDENTIAL_PATH,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            first = os.fstat(descriptor)
            encoded = os.read(descriptor, 32769)
            last = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if (not stat.S_ISREG(first.st_mode) or first.st_uid != 0
                or first.st_nlink != 1 or first.st_mode & 0o077
                or not 0 < first.st_size <= 32768
                or len(encoded) != first.st_size
                or any(getattr(first, key) != getattr(last, key)
                       for key in ('st_dev', 'st_ino', 'st_size',
                                   'st_mtime_ns', 'st_ctime_ns'))
                or hashlib.sha256(encoded).hexdigest() != credential_digest):
            raise ValueError('workload-provider-credential-target-invalid')
        credential = {'credentialIdentity': [first.st_dev, first.st_ino],
                      'credentialDigest': credential_digest}
    return {key: service[key] for key in ('role', 'managerInvocation',
            'bootId', 'cgroupIdentity', 'mainPid', 'mainStartTicks') } | {
        'resolverCanaryIdentity': service['canaryIdentity'],
        'resolverControlDigest': resolver_digest,
        'providerCanaryIdentity': [before.st_dev, before.st_ino],
        'observedMonotonicNs': time.monotonic_ns(),
        'controlDigest': provider_digest} | (credential or {})


def prepare_provider_canary():
    """Create only synthetic root inputs, including the installed Worker credential."""
    resolver_digest = prepare_resolver_canary()
    parent = Path(PROVIDER_PROBE_PATH).parent
    outer = parent.parent.lstat()
    if (not stat.S_ISDIR(outer.st_mode) or outer.st_uid != 0
            or outer.st_mode & 0o022):
        raise ValueError('workload-provider-root-invalid')
    parent.mkdir(mode=0o700, exist_ok=False)
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError('workload-provider-target-invalid')
    raw = secrets.token_bytes(32)
    descriptor = os.open(PROVIDER_PROBE_PATH,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        if os.write(descriptor, raw) != len(raw):
            raise ValueError('workload-provider-target-short-write')
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    provider_digest = hashlib.sha256(raw).hexdigest()
    _provider_target_control(provider_digest, resolver_digest)
    if Path(PROVIDER_CREDENTIAL_PATH).exists():
        raise ValueError('workload-provider-credential-already-present')
    from datetime import datetime, timedelta, timezone
    credential = {'token': 'pr315-synthetic-' + secrets.token_hex(32),
        'expiresAt': (datetime.now(timezone.utc) + timedelta(minutes=55)).isoformat()}
    encoded = json.dumps(credential, sort_keys=True,
        separators=(',', ':')).encode()
    descriptor = os.open(PROVIDER_CREDENTIAL_PATH,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600)
    try:
        if os.write(descriptor, encoded) != len(encoded):
            raise ValueError('workload-provider-credential-short-write')
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    credential_digest = hashlib.sha256(encoded).hexdigest()
    _provider_target_control(provider_digest, resolver_digest,
                             credential_digest)
    return {'providerDigest': provider_digest,
            'resolverDigest': resolver_digest,
            'credentialDigest': credential_digest}


def _installed_provider_worker_control(credential_digest, ordinal):
    """Exercise the installed Worker with a registered synthetic provider input.

    Only external GitHub I/O and owner dispatch are fixed no-I/O stubs in this
    administrator test process. Registration, job policy authentication,
    credential ingress, input checks, intent and result persistence are real.
    """
    if ordinal not in (1, 2):
        raise ValueError('workload-provider-control-ordinal-invalid')
    from datetime import datetime, timedelta, timezone
    sys.path.insert(0, str(INSTALLED / 'tools/release-certification/protected'))
    import restricted_registration as registration
    import restricted_worker as worker
    import original_artifact_authentication as original_provider
    if (Path(registration.__file__).resolve() != INSTALLED /
            'tools/release-certification/protected/restricted_registration.py'
            or Path(worker.__file__).resolve() != INSTALLED /
            'tools/release-certification/protected/restricted_worker.py'
            or worker.CREDENTIAL != Path(PROVIDER_CREDENTIAL_PATH)):
        raise ValueError('workload-provider-installed-worker-required')
    registration.installed_verifier()
    raw_credential = worker.read(worker.CREDENTIAL, 32768)
    if hashlib.sha256(raw_credential).hexdigest() != credential_digest:
        raise ValueError('workload-provider-credential-changed')
    selected_credential = worker.decode(raw_credential, 32768)
    if (not isinstance(selected_credential, dict)
            or set(selected_credential) != {'token', 'expiresAt'}
            or not selected_credential['token'].startswith('pr315-synthetic-')):
        raise ValueError('workload-provider-synthetic-credential-invalid')
    base = PROVIDER_CONTEXT_ROOT
    inputs = base / 'pr315-provider-inputs'
    inputs.mkdir(mode=0o700, exist_ok=True)
    if (inputs.stat().st_uid != 0 or inputs.stat().st_mode & 0o077
            or any(inputs.iterdir())):
        raise ValueError('workload-provider-input-root-invalid')
    now = datetime.now(timezone.utc)
    context = {'method': 'maintenance-prepare',
        'context': {'sourceCommit': '0' * 40, 'runId': 1,
                    'runAttempt': 1, 'jobId': 1},
        'notBefore': (now - timedelta(minutes=1)).isoformat(),
        'expiresAt': (now + timedelta(minutes=10)).isoformat(),
        'collectUntil': (now + timedelta(days=1)).isoformat(),
        'configurationFiles': []}
    context_path = base / ('pr315-provider-context-' + str(ordinal) + '.json')
    encoded = worker.encode(context)
    descriptor = os.open(context_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600)
    try:
        if os.write(descriptor, encoded) != len(encoded):
            raise ValueError('workload-provider-context-short-write')
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    selected = registration.register(context_path, inputs)
    handle = selected['handle']
    operation = worker.OPERATIONS / handle
    record_raw = worker.read(operation / 'registration.json')
    record = worker.validate_record(worker.decode(record_raw, worker.MAX_RECORD))
    expected = {'schemaVersion': 1,
        'kind': 'pr315-synthetic-provider-no-network', 'status': 'complete'}
    calls = []
    workflow, _job = worker.POLICIES[record['method']]
    run_path = (f'repos/{original_provider.REPOSITORY}/actions/runs/'
                f'{record["context"]["runId"]}')
    responses = {
        run_path: {'run_attempt': 1},
        run_path + '/attempts/1': {'id': 1, 'run_attempt': 1,
            'path': workflow, 'head_sha': record['context']['sourceCommit'],
            'event': 'workflow_dispatch',
            'repository': {'full_name': original_provider.REPOSITORY},
            'actor': {'login': 'leumor'},
            'triggering_actor': {'login': 'leumor'}},
        f'repos/{original_provider.REPOSITORY}/actions/jobs/1': {
            'id': 1, 'run_id': 1, 'run_attempt': 1,
            'name': worker.JOB_NAMES[record['method']],
            'head_sha': record['context']['sourceCommit'],
            'status': 'in_progress',
            'started_at': record['notBefore']}}

    def provider_io(arguments, environment):
        if (arguments[:1] != ['api'] or len(arguments) != 2
                or arguments[1] not in responses
                or environment.get('GH_TOKEN') !=
                    selected_credential['token']):
            raise ValueError('workload-provider-worker-ingress-invalid')
        calls.append(arguments[1])
        return responses[arguments[1]]

    def dispatch(actual, root):
        if actual != record or root != operation:
            raise ValueError('workload-provider-worker-dispatch-invalid')
        calls.append('fixed-no-network-dispatch')
        return expected

    original_io, original_dispatch = (
        original_provider._gh, worker.dispatch)
    original_provider._gh, worker.dispatch = provider_io, dispatch
    started = time.monotonic_ns()
    try:
        response = worker.Worker(record['bundleIdentity']).process(
            {'method': record['method'], 'handle': handle},
            record['callerUid'])
    finally:
        original_provider._gh, worker.dispatch = (
            original_io, original_dispatch)
    finished = time.monotonic_ns()
    result_raw = worker.read(operation / 'result.json')
    persisted = worker.decode(result_raw, worker.MAX_RESULT)
    if (calls != [run_path, run_path + '/attempts/1',
                  f'repos/{original_provider.REPOSITORY}/actions/jobs/1',
                  'fixed-no-network-dispatch']
            or response.get('status') != 'complete'
            or response.get('result') != expected
            or persisted.get('result') != expected
            or persisted.get('receipt') != response.get('receipt')
            or persisted.get('registrationDigest') !=
                worker.digest(record_raw)):
        raise ValueError('workload-provider-worker-control-invalid')
    return {'kind': 'pr315-installed-worker-synthetic-provider-control-v2',
        'ordinal': ordinal,
        'workerSourceDigest': hashlib.sha256(
            Path(worker.__file__).read_bytes()).hexdigest(),
        'jobAuthentication': 'installed-policy-fixed-no-network-provider-stub',
        'credentialDigest': credential_digest,
        'registrationDigest': hashlib.sha256(record_raw).hexdigest(),
        'resultDigest': hashlib.sha256(result_raw).hexdigest(),
        'handleDigest': hashlib.sha256(handle.encode()).hexdigest(),
        'bundleIdentity': record['bundleIdentity'],
        'callerUid': record['callerUid'],
        'startedMonotonicNs': started,
        'finishedMonotonicNs': finished}


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


def _wait_output_record(path, uid, until, timeout_code):
    """Wait only for the atomic publisher's transient second link to disappear."""
    while time.monotonic() < until:
        if path.exists():
            try:
                return _candidate_probe_file(path, uid)
            except ValueError:
                if path.lstat().st_nlink != 2:
                    raise
        time.sleep(.01)
    raise ValueError(timeout_code)


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


def _validate_false_role_claims(result, before, after, actor, uid, *, authority_only=False):
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
    prior = (result['startedMonotonicNs'] if authority_only else
             result['writeAttempt']['finishedMonotonicNs'])
    times = (prior,
             identity.get('startedMonotonicNs'), identity.get('finishedMonotonicNs'),
             counters.get('startedMonotonicNs'), counters.get('finishedMonotonicNs'),
             after['observedMonotonicNs'])
    if (any(type(value) is not int or value <= 0 for value in times)
            or list(times) != sorted(times) or len(set(times)) != len(times)):
        raise RoleProbeDiagnosticError('workload-role-probe-claim-timeline-invalid')
    return identity, counters


def _validate_fixed_role_accesses(result, after, *, role_boundary=False):
    selected = (
        ('siblingRead', 'sibling-data', SIBLING_PROBE_PATH, ('ENOENT',)),
        ('packageWrite', 'package-expectation', PACKAGE_PROBE_PATH,
         ('EACCES', 'EPERM', 'EROFS')),
        ('cgroupMigration', 'cgroup-migration', CGROUP_PROBE_PATH, ('ENOENT',)))
    previous = (result['writeAttempt']['finishedMonotonicNs'] if role_boundary
                else result['counterClaim']['finishedMonotonicNs'])
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


def probe_sibling_network(workload, handoff, nonce, source_digest,
                          campaign_deadline_ns, actor_case='observer-private-read'):
    """Trigger two finite role-origin TCP attempts with separate root filter controls."""
    if actor_case not in ('observer-private-read', 'network-app'):
        raise ValueError('workload-sibling-network-actor-selection-invalid')
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
        actor_before = _role_probe_actor(sender_before, nonce, actor_case)
        target_before = _sibling_target_control(case_id, recipient_handle)
        counters_before = read_sibling_drop_counters()
        if (target_before['observedMonotonicNs'] >= target_before['controlObservedNs']
                or target_before['controlObservedNs'] >= counters_before['observedMonotonicNs']
                or counters_before['roleNamespaceIdentity'] !=
                   sender_before['networkNamespaceIdentity']):
            raise ValueError('workload-sibling-network-before-window-invalid')
        trigger_ns = time.monotonic_ns()
        _publish_output_trigger(root, prefix + '-trigger.json', case_id, nonce)
        result_path = root / (prefix + '-result.json')
        until = min(time.monotonic() + 10, campaign_deadline_ns / 1e9)
        result = _wait_output_record(result_path, sender_uid, until,
                                     'workload-sibling-network-result-timeout')
        counters_after = read_sibling_drop_counters()
        sender_after = workload.observe(sender_handle)
        actor_after = _role_probe_actor(sender_after, nonce, actor_case)
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


def _host_canary_epoch(workload):
    """Bind the guest host-namespace canary to this root test-kit process."""
    from restricted_workload_network import HOST_CANARY_ADDRESS, IP
    pid = os.getpid()
    stat_fields = (Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split())
    start = int(stat_fields[19])
    group = Path('/proc/self/cgroup').read_text().strip()
    if not group.startswith('0::/') or start <= 0 or os.geteuid() != 0:
        raise ValueError('workload-host-canary-owner-invalid')
    cgroup = Path('/sys/fs/cgroup') / group[4:]
    info = cgroup.stat()
    source = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    boot = workload.boot()
    network = os.stat('/proc/self/ns/net').st_ino
    init_network = os.stat('/proc/1/ns/net').st_ino
    if network != init_network:
        raise ValueError('workload-host-canary-not-in-guest-host-namespace')
    addresses = subprocess.run([IP, '-j', '-4', 'address', 'show', 'to',
        HOST_CANARY_ADDRESS + '/32'], capture_output=True, check=True,
        timeout=5, env=ENV)
    if len(addresses.stdout) > 16384:
        raise ValueError('workload-host-canary-address-observation-limit')
    interfaces = json.loads(addresses.stdout)
    bound = [(row['ifindex'], row['ifname'], entry['local'])
        for row in interfaces for entry in row['addr_info']
        if entry.get('family') == 'inet'
        and entry.get('local') == HOST_CANARY_ADDRESS]
    if (len(bound) != 1 or type(bound[0][0]) is not int
            or bound[0][0] <= 0
            or not isinstance(bound[0][1], str)
            or re.fullmatch('[a-zA-Z0-9_.-]{1,15}', bound[0][1]) is None):
        raise ValueError('workload-host-canary-address-not-assigned')
    identity = [info.st_dev, info.st_ino]
    invocation = hashlib.sha256(json.dumps({'bootId': boot, 'pid': pid,
        'startTicks': start, 'cgroupIdentity': identity,
        'sourceDigest': source}, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()[:32]
    return {'pid': pid, 'uid': 0, 'startTicks': start, 'bootId': boot,
        'cgroupIdentity': identity, 'networkNamespace': network,
        'initNetworkNamespace': init_network,
        'addressBinding': {'ifindex': bound[0][0],
                           'ifname': bound[0][1], 'address': bound[0][2]},
        'sourceDigest': source, 'invocationId': invocation}


def _host_canary_control(listener, workload):
    """Connect to the live guest host socket and retain only its fixed echo digest."""
    from restricted_workload_network import HOST_CANARY_ADDRESS, HOST_CANARY_PORT
    def receive_exact(channel, count):
        body = bytearray()
        while len(body) < count:
            block = channel.recv(count - len(body))
            if not block:
                raise ValueError('workload-host-canary-truncated')
            body.extend(block)
        return bytes(body)

    before = _host_canary_epoch(workload)
    if listener.getsockname() != (HOST_CANARY_ADDRESS, HOST_CANARY_PORT):
        raise ValueError('workload-host-canary-listener-address-changed')
    with socket.create_connection((HOST_CANARY_ADDRESS, HOST_CANARY_PORT),
                                  timeout=2) as client:
        listener.settimeout(2)
        accepted, address = listener.accept()
        with accepted:
            if address[0] != HOST_CANARY_ADDRESS:
                raise ValueError('workload-host-canary-peer-invalid')
            client.sendall(b'pr315-host-probe')
            if receive_exact(accepted, len(b'pr315-host-probe')) != b'pr315-host-probe':
                raise ValueError('workload-host-canary-request-invalid')
            accepted.sendall(b'pr315-host-ready')
            if receive_exact(client, len(b'pr315-host-ready')) != b'pr315-host-ready':
                raise ValueError('workload-host-canary-response-invalid')
    after = _host_canary_epoch(workload)
    if before != after:
        raise ValueError('workload-host-canary-owner-changed')
    return {**before, 'controlDigest': hashlib.sha256(
        b'pr315-host-probe\0pr315-host-ready').hexdigest(),
        'observedMonotonicNs': time.monotonic_ns()}


def probe_host_network(workload, handoff, nonce, source_digest,
                       campaign_deadline_ns):
    """Prove a role SYN hit its own DROP rule while host canary stayed live."""
    import pr315_role_probe as role_probe
    from restricted_workload_network import (HOST_CANARY_ADDRESS,
        HOST_CANARY_PORT, SIBLING_DROP_COUNTERS, read_sibling_drop_counters)
    if time.monotonic_ns() >= campaign_deadline_ns:
        raise ValueError('workload-host-network-deadline')
    case_id, address, port, prefix = role_probe.HOST_CASE
    if (case_id != 'host-network' or address != HOST_CANARY_ADDRESS
            or port != HOST_CANARY_PORT):
        raise ValueError('workload-host-network-policy-changed')
    handle = handoff['handles']['candidate-sender']
    uid = workload.account('candidate-sender').pw_uid
    root = workload.ROOT / 'state/candidate-sender/tmp'
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        listener.bind((address, port))
        listener.listen(2)
        target_before = _host_canary_control(listener, workload)
        sender_before = workload.observe(handle)
        actor_before = _role_probe_actor(sender_before, nonce, 'network-app')
        counters_before = read_sibling_drop_counters()
        if (not target_before['observedMonotonicNs']
                < sender_before['observedMonotonicNs']
                < counters_before['observedMonotonicNs']
                or counters_before['roleNamespaceIdentity'] !=
                   sender_before['networkNamespaceIdentity']):
            raise ValueError('workload-host-network-before-invalid')
        trigger_ns = time.monotonic_ns()
        _publish_output_trigger(root, prefix + '-trigger.json', case_id, nonce)
        result = _wait_output_record(root / (prefix + '-result.json'), uid,
            min(time.monotonic() + 10, campaign_deadline_ns / 1e9),
            'workload-host-network-result-timeout')
        counters_after = read_sibling_drop_counters()
        sender_after = workload.observe(handle)
        actor_after = _role_probe_actor(sender_after, nonce, 'network-app')
        target_after = _host_canary_control(listener, workload)
    stable_actor = ('hostPid', 'hostParentPid', 'startTicks', 'namespacePids',
        'networkNamespaceIdentity', 'mountNamespaceIdentity',
        'userNamespaceIdentity', 'executableDigest',
        'noNewPrivileges', 'effectiveCapabilities')
    stable_target = ('pid', 'uid', 'startTicks', 'bootId', 'cgroupIdentity',
        'networkNamespace', 'initNetworkNamespace', 'addressBinding',
        'sourceDigest', 'invocationId', 'controlDigest')
    if (not isinstance(result, dict) or set(result) != {
            'schemaVersion', 'kind', 'caseId', 'nonce', 'pid', 'uid', 'gid',
            'startedMonotonicNs', 'finishedMonotonicNs',
            'targetEndpointDigest', 'outcome'}
            or result['schemaVersion'] != 1
            or result['kind'] != 'pr315-candidate-network-probe'
            or result['caseId'] != case_id or result['nonce'] != nonce
            or result['pid'] != actor_before['namespacePids'][-1]
            or result['uid'] != uid
            or result['targetEndpointDigest'] != hashlib.sha256(
                f'{address}:{port}'.encode()).hexdigest()
            or result['outcome'] not in (
                {'connected': False, 'errno': 'ETIMEDOUT'},
                {'connected': False, 'errno': 'EHOSTUNREACH'},
                {'connected': False, 'errno': 'ENETUNREACH'},
                {'connected': False, 'errno': 'EACCES'})
            or any(actor_before[key] != actor_after[key] for key in stable_actor)
            or any(target_before[key] != target_after[key] for key in stable_target)
            or sender_before['managerInvocation'] != sender_after['managerInvocation']
            or sender_before['cgroupIdentity'] != sender_after['cgroupIdentity']
            or sender_before['stateDigest'] != sender_after['stateDigest']
            or not counters_before['observedMonotonicNs']
                < trigger_ns < result['startedMonotonicNs']
                < result['finishedMonotonicNs']
                < counters_after['observedMonotonicNs']
                < sender_after['observedMonotonicNs']
                < target_after['observedMonotonicNs']):
        raise ValueError('workload-host-network-observation-invalid')
    _sibling_counter_pair(case_id, counters_before, counters_after,
                          sender_before['networkNamespaceIdentity'])
    audit = {'schemaVersion': 1, 'kind': 'pr315-administrator-host-network-denial',
        'caseId': case_id, 'sourceDigest': source_digest,
        'nonceDigest': hashlib.sha256(nonce.encode()).hexdigest(),
        'actorUid': uid, 'actorBefore': actor_before,
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
    workload.write(workload.ROOT / 'authority/host-network-denial.json',
                   audit, create=True)
    return hashlib.sha256(json.dumps(audit, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()


def probe_network_app_roles(workload, handoff, source_digest, campaign_deadline_ns):
    """Start one fixed candidate actor for the two real sibling network denials."""
    if time.monotonic_ns() >= campaign_deadline_ns:
        raise ValueError('workload-sibling-network-deadline')
    case_id = 'network-app'
    nonce = secrets.token_hex(32)
    launch = workload.read(workload.ROOT / 'roles/candidate-sender/launch.json')
    workload.write(workload.ROOT / 'probe-requests/candidate-sender.json',
        {'schemaVersion': 1, 'caseId': case_id, 'nonce': nonce,
         'bootId': workload.boot(), 'javaDigest': launch['javaDigest'],
         'sourceDigest': source_digest}, create=True, mode=0o444)
    uid = workload.account('candidate-sender').pw_uid
    root = workload.ROOT / 'state/candidate-sender/tmp'
    until = min(time.monotonic() + 25, campaign_deadline_ns / 1e9)
    ready = _wait_output_record(root / 'pr315-network-app-ready.json', uid, until,
                                'workload-role-probe-ready-timeout')
    if (not isinstance(ready, dict) or set(ready) != {
            'schemaVersion', 'kind', 'caseId', 'nonce', 'pid', 'startedMonotonicNs'}
            or ready['schemaVersion'] != 1
            or ready['kind'] != 'pr315-candidate-role-probe-ready'
            or ready['caseId'] != case_id or ready['nonce'] != nonce):
        raise ValueError('workload-role-probe-ready-invalid')
    handle = handoff['handles']['candidate-sender']
    before = workload.observe(handle)
    actor_before = _role_probe_actor(before, nonce, case_id)
    if (ready['pid'] != actor_before['namespacePids'][-1]
            or ready['startedMonotonicNs'] >= before['observedMonotonicNs']):
        raise ValueError('workload-role-probe-pid-unbound')
    audits = probe_sibling_network(workload, handoff, nonce, source_digest,
                                   campaign_deadline_ns, actor_case=case_id)
    audits['host-network'] = probe_host_network(
        workload, handoff, nonce, source_digest, campaign_deadline_ns)
    after = workload.observe(handle)
    actor_after = _role_probe_actor(after, nonce, case_id)
    if (before['managerInvocation'] != after['managerInvocation']
            or before['cgroupIdentity'] != after['cgroupIdentity']
            or actor_before['hostPid'] != actor_after['hostPid']
            or actor_before['startTicks'] != actor_after['startTicks']):
        raise ValueError('workload-sibling-network-actor-changed')
    return audits


def _provider_app_actor(workload, handoff, expected_worker):
    """Resolve the actual signed probe AppHost child in the current role cgroup."""
    from cross_version_workload import bind_probe_worker
    role = 'candidate-sender'
    if (not isinstance(expected_worker, dict)
            or type(expected_worker.get('namespacePid')) is not int
            or expected_worker['namespacePid'] <= 1):
        raise ValueError('workload-provider-app-worker-invalid')
    observed = workload.observe(handoff['handles'][role])
    bound = bind_probe_worker(observed, expected_worker['namespacePid'],
                              handoff['expectedJdkDigests'][role])
    stable = ('hostPid', 'namespacePid', 'startTicks',
              'managerInvocation', 'cgroupIdentity', 'sandboxLeader')
    if any(bound[key] != expected_worker[key] for key in stable):
        raise ValueError('workload-provider-app-worker-changed')
    return bound


def probe_provider_authority(workload, handoff, provider_setup,
                             resolver_digest, bundle_digest, expected_worker,
                             campaign_deadline_ns):
    """Bracket a signed AppHost denial with two real installed Worker reads."""
    if time.monotonic_ns() >= campaign_deadline_ns:
        raise ValueError('workload-provider-campaign-expired')
    role = 'candidate-sender'
    account = workload.account(role)
    root = workload.ROOT / 'state/candidate-sender/data/node/apps/data/pr315-probe'
    provider_digest = provider_setup['providerDigest']
    credential_digest = provider_setup['credentialDigest']
    worker_before = _installed_provider_worker_control(credential_digest, 1)
    target_before = _provider_target_control(provider_digest, resolver_digest,
                                             credential_digest)
    actor_before = _provider_app_actor(workload, handoff, expected_worker)
    nonce = secrets.token_hex(32)
    trigger = root / 'pr315-provider-trigger.json'
    request = {'schemaVersion': 1, 'kind': 'pr315-provider-trigger', 'nonce': nonce}
    encoded = json.dumps(request, sort_keys=True, separators=(',', ':')).encode()
    descriptor = os.open(trigger,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600)
    try:
        os.fchown(descriptor, account.pw_uid, account.pw_gid)
        if os.write(descriptor, encoded) != len(encoded):
            raise ValueError('workload-provider-trigger-short-write')
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    trigger_ns = time.monotonic_ns()
    until = min(time.monotonic() + 25, campaign_deadline_ns / 1e9)
    try:
        result = _wait_output_record(root / 'pr315-provider-result.json',
            account.pw_uid, until, 'workload-provider-result-timeout')
    finally:
        trigger.unlink(missing_ok=True)
    actor_after = _provider_app_actor(workload, handoff, expected_worker)
    target_after = _provider_target_control(provider_digest, resolver_digest,
                                            credential_digest)
    worker_after = _installed_provider_worker_control(credential_digest, 2)
    stable_actor = ('hostPid', 'namespacePid', 'startTicks',
                    'managerInvocation', 'cgroupIdentity',
                    'sandboxLeader')
    stable_target = ('role', 'managerInvocation', 'bootId', 'cgroupIdentity',
                     'mainPid', 'mainStartTicks', 'resolverCanaryIdentity',
                     'resolverControlDigest', 'providerCanaryIdentity',
                     'controlDigest', 'credentialIdentity',
                     'credentialDigest')
    if (not isinstance(result, dict) or set(result) != {
            'schemaVersion', 'kind', 'caseId', 'nonce', 'pid', 'uid', 'gid',
            'startedMonotonicNs', 'finishedMonotonicNs',
            'targetPathDigest', 'outcome'}
            or result['schemaVersion'] != 1
            or result['kind'] != 'pr315-signed-provider-authority-probe'
            or result['caseId'] != 'provider-authority' or result['nonce'] != nonce
            or result['pid'] != actor_before['namespacePids'][-1]
            or result['uid'] != account.pw_uid or result['gid'] != account.pw_gid
            or result['targetPathDigest'] != hashlib.sha256(
                PROVIDER_CREDENTIAL_PATH.encode()).hexdigest()
            or result['outcome'] not in (
                {'opened': False, 'errno': 'ENOENT'},
                {'opened': False, 'errno': 'EACCES'},
                {'opened': False, 'errno': 'EPERM'})
            or any(actor_before[key] != actor_after[key] for key in stable_actor)
            or any(target_before[key] != target_after[key] for key in stable_target)
            or worker_before['credentialDigest'] != credential_digest
            or worker_after['credentialDigest'] != credential_digest
            or worker_before['handleDigest'] == worker_after['handleDigest']
            or worker_before['finishedMonotonicNs'] >=
                target_before['observedMonotonicNs']
            or worker_after['startedMonotonicNs'] <=
                target_after['observedMonotonicNs']
            or actor_before['stateDigest'] != actor_after['stateDigest']
            or not target_before['observedMonotonicNs']
                < actor_before['observedMonotonicNs'] < trigger_ns
                < result['startedMonotonicNs'] < result['finishedMonotonicNs']
                < actor_after['observedMonotonicNs']
                < target_after['observedMonotonicNs']):
        raise ValueError('workload-provider-actor-target-or-denial-invalid')
    audit = {'schemaVersion': 2,
        'kind': 'pr315-administrator-provider-authority-denial',
        'caseId': 'provider-authority', 'bundleDigest': bundle_digest,
        'nonceDigest': hashlib.sha256(nonce.encode()).hexdigest(),
        'actorUid': account.pw_uid,
        'actorBefore': actor_before, 'actorAfter': actor_after,
        'senderStateBefore': actor_before['stateDigest'],
        'senderStateAfter': actor_after['stateDigest'],
        'targetBefore': target_before, 'targetAfter': target_after,
        'workerControlBefore': worker_before,
        'workerControlAfter': worker_after,
        'targetPathDigest': result['targetPathDigest'],
        'attackStartedNs': result['startedMonotonicNs'],
        'attackFinishedNs': result['finishedMonotonicNs'],
        'kernelOpenResult': result['outcome'],
        'appResultDigest': hashlib.sha256(json.dumps(result,
            sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
    workload.write(workload.ROOT / 'authority/provider-authority-denial.json',
                   audit, create=True)
    return hashlib.sha256(json.dumps(audit,
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _sibling_app_target_control(workload, handoff, expected_worker):
    """Bind the active recipient Mail child to its real role HTTP control."""
    from cross_version_workload import bind_worker
    from restricted_workload_controller import bootstrap
    role = 'candidate-recipient'
    handle = handoff['handles'][role]
    if (not isinstance(expected_worker, dict)
            or type(expected_worker.get('namespacePid')) is not int
            or expected_worker['namespacePid'] <= 1):
        raise ValueError('workload-sibling-app-worker-invalid')
    before = workload.observe(handle)
    worker_before = bind_worker(before, expected_worker['namespacePid'],
                                handoff['expectedJdkDigests'][role])
    stable = ('hostPid', 'namespacePid', 'startTicks', 'javaHostPid',
              'javaStartTicks', 'managerInvocation', 'cgroupIdentity')
    if any(worker_before[key] != expected_worker[key] for key in stable):
        raise ValueError('workload-sibling-app-worker-changed')
    selected = bootstrap(handle)
    origin = selected.get('uiOrigin') if isinstance(selected, dict) else None
    if (not isinstance(origin, str)
            or re.fullmatch(r'http://127\.0\.0\.1:[1-9][0-9]{3,4}', origin) is None):
        raise ValueError('workload-sibling-app-origin-unavailable')
    http = _sibling_target_control('sibling-http', handle)
    after = workload.observe(handle)
    worker_after = bind_worker(after, expected_worker['namespacePid'],
                               handoff['expectedJdkDigests'][role])
    if (any(worker_before[key] != worker_after[key] for key in stable)
            or before['managerInvocation'] != http['managerInvocation']
            or after['managerInvocation'] != http['managerInvocation']
            or before['cgroupIdentity'] != http['cgroupIdentity']
            or after['cgroupIdentity'] != http['cgroupIdentity']
            or before['stateDigest'] != after['stateDigest']
            or not before['observedMonotonicNs'] < http['controlObservedNs']
                < after['observedMonotonicNs']):
        raise ValueError('workload-sibling-app-target-changed')
    return {'role': role, 'managerInvocation': after['managerInvocation'],
            'bootId': after['bootId'],
            'cgroupIdentity': after['cgroupIdentity'],
            'workerHostPid': worker_after['hostPid'],
            'workerStartTicks': worker_after['startTicks'],
            'javaHostPid': worker_after['javaHostPid'],
            'javaStartTicks': worker_after['javaStartTicks'],
            'observedMonotonicNs': after['observedMonotonicNs'],
            'controlObservedNs': http['controlObservedNs'],
            'controlDigest': http['controlDigest'],
            'appUiOriginDigest': hashlib.sha256(origin.encode()).hexdigest()}


def probe_sibling_app(workload, handoff, bundle_digest,
                      expected_sender_worker, expected_recipient_worker,
                      campaign_deadline_ns):
    """Require the signed sender AppHost SYN and its own named DROP witness."""
    from restricted_workload_network import (SIBLING_APP_SOURCE_PORT,
        SIBLING_DROP_COUNTERS, read_sibling_drop_counters)
    if time.monotonic_ns() >= campaign_deadline_ns:
        raise ValueError('workload-sibling-app-campaign-expired')
    account = workload.account('candidate-sender')
    root = workload.ROOT / 'state/candidate-sender/data/node/apps/data/pr315-probe'
    actor_before = _provider_app_actor(workload, handoff, expected_sender_worker)
    target_before = _sibling_app_target_control(workload, handoff,
                                                 expected_recipient_worker)
    counters_before = read_sibling_drop_counters()
    if counters_before['roleNamespaceIdentity'] != actor_before['networkNamespaceIdentity']:
        raise ValueError('workload-sibling-app-filter-owner-invalid')
    nonce = secrets.token_hex(32)
    trigger = root / 'pr315-sibling-app-trigger.json'
    encoded = json.dumps({'schemaVersion': 1,
        'kind': 'pr315-sibling-app-trigger', 'nonce': nonce},
        sort_keys=True, separators=(',', ':')).encode()
    descriptor = os.open(trigger,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600)
    try:
        os.fchown(descriptor, account.pw_uid, account.pw_gid)
        if os.write(descriptor, encoded) != len(encoded):
            raise ValueError('workload-sibling-app-trigger-short-write')
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    trigger_ns = time.monotonic_ns()
    until = min(time.monotonic() + 25, campaign_deadline_ns / 1e9)
    try:
        result = _wait_output_record(root / 'pr315-sibling-app-result.json',
            account.pw_uid, until, 'workload-sibling-app-result-timeout')
    finally:
        trigger.unlink(missing_ok=True)
    counters_after = read_sibling_drop_counters()
    actor_after = _provider_app_actor(workload, handoff, expected_sender_worker)
    target_after = _sibling_app_target_control(workload, handoff,
                                                expected_recipient_worker)
    stable_actor = ('hostPid', 'namespacePid', 'namespacePids', 'startTicks',
                    'managerInvocation', 'cgroupIdentity', 'sandboxLeader',
                    'networkNamespaceIdentity')
    stable_target = ('role', 'managerInvocation', 'bootId', 'cgroupIdentity',
                     'workerHostPid', 'workerStartTicks', 'javaHostPid',
                     'javaStartTicks', 'appUiOriginDigest')
    endpoint_digest = hashlib.sha256(b'10.231.0.2:19402').hexdigest()
    if (not isinstance(result, dict) or set(result) != {
            'schemaVersion', 'kind', 'caseId', 'nonce', 'pid', 'uid', 'gid',
            'startedMonotonicNs', 'finishedMonotonicNs', 'sourcePort',
            'targetEndpointDigest', 'outcome'}
            or result['schemaVersion'] != 1
            or result['kind'] != 'pr315-signed-sibling-app-probe'
            or result['caseId'] != 'sibling-app' or result['nonce'] != nonce
            or result['pid'] != actor_before['namespacePids'][-1]
            or result['uid'] != account.pw_uid or result['gid'] != account.pw_gid
            or result['sourcePort'] != SIBLING_APP_SOURCE_PORT
            or result['targetEndpointDigest'] != endpoint_digest
            or result['outcome'] not in (
                {'connected': False, 'phase': 'connect', 'errno': 'ETIMEDOUT'},
                {'connected': False, 'phase': 'connect', 'errno': 'EHOSTUNREACH'},
                {'connected': False, 'phase': 'connect', 'errno': 'ENETUNREACH'},
                {'connected': False, 'phase': 'connect', 'errno': 'EACCES'})
            or any(actor_before[key] != actor_after[key] for key in stable_actor)
            or any(target_before[key] != target_after[key] for key in stable_target)
            or actor_before['stateDigest'] != actor_after['stateDigest']
            or counters_before['policyDigest'] != counters_after['policyDigest']
            or counters_before['roleNamespaceIdentity'] !=
                counters_after['roleNamespaceIdentity']
            or not actor_before['observedMonotonicNs']
                < target_before['observedMonotonicNs']
                < counters_before['observedMonotonicNs'] < trigger_ns
                < result['startedMonotonicNs'] < result['finishedMonotonicNs']
                < counters_after['observedMonotonicNs']
                < actor_after['observedMonotonicNs']
                < target_after['observedMonotonicNs']):
        raise ValueError('workload-sibling-app-actor-target-or-window-invalid')
    _sibling_counter_pair('sibling-app', counters_before, counters_after,
                          actor_before['networkNamespaceIdentity'])
    audit = {'schemaVersion': 1,
        'kind': 'pr315-administrator-sibling-app-denial',
        'caseId': 'sibling-app', 'bundleDigest': bundle_digest,
        'nonceDigest': hashlib.sha256(nonce.encode()).hexdigest(),
        'actorUid': account.pw_uid,
        'actorBefore': actor_before, 'actorAfter': actor_after,
        'senderStateBefore': actor_before['stateDigest'],
        'senderStateAfter': actor_after['stateDigest'],
        'targetBefore': target_before, 'targetAfter': target_after,
        'counterBefore': counters_before, 'counterAfter': counters_after,
        'counterName': SIBLING_DROP_COUNTERS['sibling-app'],
        'sourcePort': result['sourcePort'],
        'targetEndpointDigest': endpoint_digest,
        'triggerMonotonicNs': trigger_ns,
        'attackStartedNs': result['startedMonotonicNs'],
        'attackFinishedNs': result['finishedMonotonicNs'],
        'kernelConnectResult': result['outcome'],
        'appResultDigest': hashlib.sha256(json.dumps(result,
            sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
    workload.write(workload.ROOT / 'authority/sibling-app-denial.json',
                   audit, create=True)
    return hashlib.sha256(json.dumps(audit,
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _resource_cgroup_control(workload, handoff):
    """Read the current owned sender cgroup and its real pids.max event count."""
    role = 'candidate-sender'
    with workload.locked():
        campaign, actual_role, record = workload.retained(handoff['handles'][role])
        state = workload.manager(role, 'show')
        if (actual_role != role or state['ActiveState'] != 'active'
                or state['SubState'] != 'running'):
            raise ValueError('workload-resource-role-inactive')
        workload.exact(role, record, state)
        workload.current(campaign)
        root = workload.group(role)
        info = root.stat()
        if [info.st_dev, info.st_ino] != record['cgroupIdentity']:
            raise ValueError('workload-resource-cgroup-replaced')
        lines = [line.split() for line in (root / 'pids.events').read_text().splitlines()]
        if (not 1 <= len(lines) <= 4
                or any(len(line) != 2 or not line[1].isdecimal() for line in lines)
                or len({line[0] for line in lines}) != len(lines)):
            raise ValueError('workload-resource-pids-events-invalid')
        events = {key: int(value) for key, value in lines}
        pids_max = (root / 'pids.max').read_text().strip()
        pids_current = (root / 'pids.current').read_text().strip()
        memory_max = (root / 'memory.max').read_text().strip()
        swap_max = (root / 'memory.swap.max').read_text().strip()
        memory_events = dict(line.split() for line in
            (root / 'memory.events').read_text().splitlines())
        if (pids_max != '512' or not pids_current.isdecimal()
                or not 0 < int(pids_current) <= 512
                or memory_max != str(1024**3) or swap_max != '0'
                or 'max' not in events
                or 'oom_kill' not in memory_events
                or not memory_events['oom_kill'].isdecimal()):
            raise ValueError('workload-resource-limits-unavailable')
        return {'role': role, 'managerInvocation': record['managerInvocation'],
            'bootId': record['bootId'],
            'cgroupIdentity': record['cgroupIdentity'],
            'pidsMax': 512, 'pidsCurrent': int(pids_current),
            'pidsMaxEvents': events['max'],
            'memoryMaxBytes': 1024**3,
            'memoryOomKills': int(memory_events['oom_kill']),
            'observedMonotonicNs': time.monotonic_ns()}


def _resource_sibling_controls(workload, handoff):
    """Require a real FCP response from every separate sibling role."""
    from restricted_workload_controller import _recipient_fcp_control
    rows = []
    for role in ('candidate-recipient', 'previous', 'relay-no-apps'):
        observed, controlled_ns, digest = _recipient_fcp_control(
            handoff['handles'][role])
        if (observed.get('state') != 'running'
                or observed.get('provenance') != 'controller-kernel-sample'
                or re.fullmatch('[0-9a-f]{64}', digest) is None
                or not observed['observedMonotonicNs'] < controlled_ns):
            raise ValueError('workload-resource-sibling-inactive')
        rows.append({'role': role,
            'managerInvocation': observed['managerInvocation'],
            'bootId': observed['bootId'],
            'cgroupIdentity': observed['cgroupIdentity'],
            'stateDigest': observed['stateDigest'],
            'observedMonotonicNs': observed['observedMonotonicNs'],
            'controlObservedNs': controlled_ns,
            'controlDigest': digest})
    return rows


def _resource_child_epochs(workload, actor, uid):
    """Sample the held AppHost children from the owned role cgroup, not app JSON."""
    root = workload.group('candidate-sender')
    raw = (root / 'cgroup.procs').read_text()
    if len(raw) > 4096 or any(not pid.isdecimal() for pid in raw.split()):
        raise ValueError('workload-resource-child-cgroup-list-invalid')
    rows = []
    for pid in sorted(set(map(int, raw.split()))):
        if pid <= 1:
            raise ValueError('workload-resource-child-pid-invalid')
        proc = Path('/proc') / str(pid)
        try:
            before = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
        except FileNotFoundError:
            continue  # Other role tasks may exit between cgroup and proc reads.
        if len(before) <= 19 or not before[1].isdecimal():
            raise ValueError('workload-resource-child-stat-invalid')
        if int(before[1]) != actor['hostPid']:
            continue
        status = dict(line.split(':', 1) for line in
            (proc / 'status').read_text().splitlines() if ':' in line)
        namespace_pids = list(map(int, status['NSpid'].split()))
        namespace = (proc / 'ns/pid').stat().st_ino
        after = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
        if (before[19] != after[19] or int(before[19]) <= 0
                or set(map(int, status['Uid'].split())) != {uid}
                or len(namespace_pids) != 3 or namespace_pids[0] != pid
                or namespace_pids[-1] <= actor['namespacePids'][-1]
                or namespace != actor['pidNamespaceIdentity']
                or (proc / 'cgroup').read_text().strip() !=
                    '0::' + str(root).removeprefix('/sys/fs/cgroup')):
            raise ValueError('workload-resource-child-ownership-invalid')
        rows.append({'pid': pid, 'parentPid': actor['hostPid'],
            'startTicks': int(before[19]), 'uid': uid,
            'namespacePid': namespace_pids[-1],
            'pidNamespace': namespace})
    if not 1 <= len(rows) <= 600:
        raise ValueError('workload-resource-child-count-invalid')
    return rows, time.monotonic_ns()


def _resource_children_exited(children):
    """Reject any retained child epoch after the app's reported reap."""
    for row in children:
        try:
            current = (Path('/proc') / str(row['pid']) / 'stat').read_text()
        except FileNotFoundError:
            continue
        fields = current.rsplit(')', 1)[1].split()
        if len(fields) <= 19 or not fields[19].isdecimal():
            raise ValueError('workload-resource-child-exit-unverifiable')
        if int(fields[19]) == row['startTicks']:
            raise ValueError('workload-resource-child-still-running')
    return time.monotonic_ns()


def probe_resource_exhaustion(*args, **kwargs):
    """Run the same fixed test-kit fault through its measured module."""
    from pr315_workload_fault_probes import probe_resource_exhaustion as emit
    return emit(*args, **kwargs)


def _partial_role_projection(workload, handle):
    observed = workload.observe(handle)
    if (observed.get('state') != 'running'
            or observed.get('provenance') != 'controller-kernel-sample'):
        raise ValueError('workload-partial-launch-sibling-inactive')
    return {key: observed[key] for key in ('state', 'managerInvocation',
        'bootId', 'cgroupIdentity', 'stateDigest', 'observedMonotonicNs')}


def probe_partial_launch(*args, **kwargs):
    """Run the same fixed test-kit fault through its measured module."""
    from pr315_workload_fault_probes import probe_partial_launch as emit
    return emit(*args, **kwargs)


def _stuck_collector_epoch(pid):
    """Bind only the child just started by the installed bounded collector."""
    proc = Path('/proc') / str(pid)
    status = dict(line.split(':', 1) for line in
                  (proc / 'status').read_text().splitlines() if ':' in line)
    first = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
    executable = (proc / 'exe').open('rb')
    try:
        digest = hashlib.sha256()
        count = 0
        for block in iter(lambda: executable.read(1024 * 1024), b''):
            count += len(block)
            if count > 64 * 1024 * 1024:
                raise ValueError('workload-stuck-collector-executable-limit')
            digest.update(block)
    finally:
        executable.close()
    after = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
    if (set(map(int, status['Uid'].split())) != {0}
            or first[19] != after[19] or int(first[19]) <= 0
            or os.getsid(pid) != pid):
        raise ValueError('workload-stuck-collector-epoch-invalid')
    group = (proc / 'cgroup').read_text().strip()
    if not group.startswith('0::/') or '..' in group.split('/'):
        raise ValueError('workload-stuck-collector-cgroup-invalid')
    info = (Path('/sys/fs/cgroup') / group[4:].lstrip('/')).stat()
    return {'pid': pid, 'uid': 0, 'startTicks': int(first[19]),
        'session': pid, 'cgroupIdentity': [info.st_dev, info.st_ino],
        'executableDigest': digest.hexdigest(),
        'observedMonotonicNs': time.monotonic_ns()}


def _begin_installed_observer_stop(handle, expected_uid, deadline_ns):
    """Start one exact observer stop while root prepares a fixed race witness."""
    from cross_version_workload import WorkloadClient
    observer = pwd.getpwnam('cryptad-soak')
    if observer.pw_uid != expected_uid or expected_uid <= 0:
        raise ValueError('workload-stuck-output-observer-invalid')
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        pid = os.fork()
    except BaseException:
        parent.close()
        child.close()
        raise
    if pid == 0:
        parent.close()
        try:
            os.setgroups([])
            os.setgid(observer.pw_gid)
            os.setuid(observer.pw_uid)
            os.environ.clear()
            os.environ.update(ENV)
            result = WorkloadClient().request('stop', handle)
            child.sendall(json.dumps({key: result[key] for key in
                ('state', 'generation', 'managerInvocation', 'bootId')},
                sort_keys=True, separators=(',', ':')).encode())
            os._exit(0)
        except BaseException:
            os._exit(1)
    child.close()
    try:
        epoch = _positive_observer_epoch(pid, expected_uid, deadline_ns)
    except BaseException:
        try:
            stop_child(pid)
        except ChildProcessError:
            pass
        parent.close()
        raise
    return parent, pid, epoch


def _finish_installed_observer_stop(started, deadline_ns):
    """Read the fixed controller response and reap the exact observer."""
    parent, pid, epoch = started
    try:
        raw, status = collect_child(parent, pid,
            min(time.monotonic() + 50, deadline_ns / 1e9 + 100))
    except BaseException:
        try:
            stop_child(pid)
        except ChildProcessError:
            pass
        raise
    finally:
        parent.close()
    if status != 0 or not 0 < len(raw) <= 512:
        raise ValueError('workload-stuck-output-controller-stop-invalid')
    selected = json.loads(raw)
    if (not isinstance(selected, dict) or set(selected) != {
            'state', 'generation', 'managerInvocation', 'bootId'}
            or selected['state'] != 'quiescent'):
        raise ValueError('workload-stuck-output-controller-stop-invalid')
    return selected, epoch


def _installed_observer_stop(handle, expected_uid, deadline_ns):
    return _finish_installed_observer_stop(
        _begin_installed_observer_stop(handle, expected_uid, deadline_ns),
        deadline_ns)


def _stale_handle_controller_epoch(workload):
    """Bind the installed root socket owner to its active systemd invocation."""
    unit = 'cryptad-workload-controller.service'
    selected = subprocess.run(['/usr/bin/systemctl', 'show', unit,
        '--property=InvocationID,ActiveState,SubState,MainPID,ControlGroup',
        '--no-pager'], stdin=subprocess.DEVNULL, capture_output=True,
        env=ENV, timeout=5, check=True)
    if len(selected.stdout) > 8192 or selected.stderr:
        raise ValueError('workload-stale-handle-controller-unavailable')
    state = dict(line.split('=', 1) for line in
                 selected.stdout.decode().splitlines() if '=' in line)
    path = '/system.slice/' + unit
    if (set(state) != {'InvocationID', 'ActiveState', 'SubState',
                      'MainPID', 'ControlGroup'}
            or re.fullmatch('[0-9a-f]{32}', state['InvocationID']) is None
            or state['ActiveState'] != 'active'
            or state['SubState'] != 'running'
            or not state['MainPID'].isdecimal()
            or int(state['MainPID']) <= 1
            or state['ControlGroup'] != path):
        raise ValueError('workload-stale-handle-controller-state-invalid')
    pid = int(state['MainPID'])
    proc = Path('/proc') / str(pid)
    first = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
    status = dict(line.split(':', 1) for line in
        (proc / 'status').read_text().splitlines() if ':' in line)
    second = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
    group = (Path('/sys/fs/cgroup') / path.lstrip('/')).stat()
    if (len(first) <= 19 or first[19] != second[19]
            or not first[19].isdecimal() or int(first[19]) <= 0
            or set(map(int, status['Uid'].split())) != {0}
            or (proc / 'cgroup').read_text().strip() != '0::' + path):
        raise ValueError('workload-stale-handle-controller-epoch-invalid')
    return {'pid': pid, 'uid': 0, 'startTicks': int(first[19]),
        'bootId': workload.boot(),
        'invocationId': state['InvocationID'],
        'cgroupIdentity': [group.st_dev, group.st_ino],
        'observedMonotonicNs': time.monotonic_ns()}


def probe_stale_handle(*args, **kwargs):
    """Run the same fixed test-kit fault through its measured module."""
    from pr315_workload_fault_probes import probe_stale_handle as emit
    return emit(*args, **kwargs)


def _stale_pid_observer_reply(channel, maximum=4096):
    """Receive one bounded line while the child remains behind its barrier."""
    raw = bytearray()
    while b'\n' not in raw and len(raw) <= maximum:
        block = channel.recv(min(1024, maximum + 1 - len(raw)))
        if not block:
            raise ValueError('workload-stale-pid-observer-disconnected')
        raw.extend(block)
    if len(raw) > maximum or raw.count(b'\n') != 1 or not raw.endswith(b'\n'):
        raise ValueError('workload-stale-pid-observer-framing-invalid')
    return json.loads(raw)


def _stale_pid_observer_process(handle, expected_jdk, old, observer):
    """Run the installed adapter epoch check as the actual soak account."""
    from cross_version_workload import (WorkloadClient, InstalledWorkloadAdapter,
                                        bind_daemon)
    from cross_version_runtime import RuntimeFailure
    role = 'candidate-sender'
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        pid = os.fork()
    except BaseException:
        parent.close()
        child.close()
        raise
    if pid == 0:
        parent.close()
        try:
            os.setgroups([])
            os.setgid(observer.pw_gid)
            os.setuid(observer.pw_uid)
            os.environ.clear()
            os.environ.update(ENV)
            child.sendall(b'R')
            if child.recv(1) != b'G':
                raise ValueError('workload-stale-pid-start-invalid')
            client = WorkloadClient()
            started = time.monotonic_ns()
            observed = client.request('observe', handle)
            adapter = object.__new__(InstalledWorkloadAdapter)
            adapter.handles = {role: handle}
            adapter.nodes = {role: observed}
            adapter._bound(role, observed)
            daemon = bind_daemon(observed, expected_jdk)
            first = {'target': {key: observed[key] for key in
                ('state', 'generation', 'managerInvocation',
                 'bootId', 'cgroupIdentity', 'stateDigest')},
                'daemon': daemon, 'exchange': client.last_exchange,
                'startedMonotonicNs': started,
                'finishedMonotonicNs': time.monotonic_ns()}
            if old:
                child.sendall(json.dumps(first, sort_keys=True,
                    separators=(',', ':')).encode() + b'\n')
                if child.recv(1) != b'G':
                    raise ValueError('workload-stale-pid-release-invalid')
                started = time.monotonic_ns()
                changed = client.request('observe', handle)
                try:
                    adapter._bound(role, changed)
                except RuntimeFailure as error:
                    if str(error) != 'workload-role-invocation-changed':
                        raise
                else:
                    raise ValueError('workload-stale-pid-old-observer-accepted')
                first['rejected'] = {'reason': 'workload-role-invocation-changed',
                    'target': {key: changed[key] for key in
                        ('state', 'generation', 'managerInvocation',
                         'bootId', 'cgroupIdentity', 'stateDigest')},
                    'exchange': client.last_exchange,
                    'startedMonotonicNs': started,
                    'finishedMonotonicNs': time.monotonic_ns()}
                payload = first['rejected']
            else:
                payload = first
            child.sendall(json.dumps(payload, sort_keys=True,
                separators=(',', ':')).encode())
            child.close()
            os._exit(0)
        except BaseException:
            os._exit(1)
    child.close()
    return parent, pid


def probe_stale_pid_uid(*args, **kwargs):
    """Run the same fixed test-kit fault through its measured module."""
    from pr315_workload_fault_probes import probe_stale_pid_uid as emit
    return emit(*args, **kwargs)


def probe_stuck_output(*args, **kwargs):
    """Run the same fixed test-kit fault through its measured module."""
    from pr315_workload_fault_probes import probe_stuck_output as emit
    return emit(*args, **kwargs)


def probe_late_child(*args, **kwargs):
    """Run the same fixed test-kit fault through its measured module."""
    from pr315_workload_fault_probes import probe_late_child as emit
    return emit(*args, **kwargs)


def _begin_cleanup_race_stop(handle, observer, campaign_deadline_ns):
    """Start an actual observer stop; the fixed root barrier holds its response."""
    from cross_version_workload import WorkloadClient
    from cross_version_runtime import RuntimeFailure
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        pid = os.fork()
    except BaseException:
        parent.close()
        child.close()
        raise
    if pid == 0:
        parent.close()
        try:
            os.setgroups([])
            os.setgid(observer.pw_gid)
            os.setuid(observer.pw_uid)
            os.environ.clear()
            os.environ.update(ENV)
            client = WorkloadClient()
            started = time.monotonic_ns()
            try:
                client.request('stop', handle)
            except RuntimeFailure as error:
                if str(error) != 'workload-controller-request-rejected':
                    raise
            else:
                raise ValueError('workload-cleanup-race-old-stop-accepted')
            child.sendall(json.dumps({'status': 'rejected',
                'reason': 'workload-controller-request-rejected',
                'exchange': client.last_exchange,
                'startedMonotonicNs': started,
                'finishedMonotonicNs': time.monotonic_ns()},
                sort_keys=True, separators=(',', ':')).encode())
            child.close()
            os._exit(0)
        except BaseException:
            os._exit(1)
    child.close()
    try:
        actor = _positive_observer_epoch(pid, observer.pw_uid,
                                         campaign_deadline_ns)
    except BaseException:
        try:
            stop_child(pid)
        except ChildProcessError:
            pass
        parent.close()
        raise
    return parent, pid, actor


def probe_cleanup_race(*args, **kwargs):
    """Run the same fixed test-kit fault through its measured module."""
    from pr315_workload_fault_probes import probe_cleanup_race as emit
    return emit(*args, **kwargs)


def _setsid_process_epoch(pid):
    fields = (Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()
    if (len(fields) <= 19 or not fields[3].isdecimal()
            or not fields[19].isdecimal()):
        raise ValueError('workload-setsid-child-invalid')
    return {'session': int(fields[3]), 'startTicks': int(fields[19])}


def probe_setsid_double_fork(*args, **kwargs):
    """Run the same fixed test-kit fault through its measured module."""
    from pr315_workload_fault_probes import probe_setsid_double_fork as emit
    return emit(*args, **kwargs)


def _administrator_collector_epoch(case_id):
    """Measure this fixed root test-kit process, never an asserted PID."""
    import cross_version_runtime as runtime
    pid = os.getpid()
    proc = Path('/proc/self')
    fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
    cgroup = (proc / 'cgroup').read_text().strip()
    if (os.geteuid() != 0 or len(fields) <= 19 or not fields[19].isdecimal()
            or not cgroup.startswith('0::/') or '..' in cgroup.split('/')):
        raise ValueError('workload-' + case_id + '-collector-invalid')
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
                'role': ('positive-administrator' if case_id == 'positive'
                         else 'lifecycle-administrator' if case_id in
                         ('cancellation', 'controller-restart', 'deadline',
                          'revocation-running', 'setsid-double-fork',
                          'observer-death', 'lost-start-response',
                          'partial-launch', 'stuck-output',
                          'late-child', 'cleanup-race')
                         else 'output-collector'), 'identity': identity})[7:],
            'invocationId': invocation, 'sourceDigest': source,
            'observedMonotonicNs': time.monotonic_ns()}


def _positive_observer_epoch(pid, expected_uid, deadline_ns,
                             kind='installed-observer-process'):
    """Bind a fixed unprivileged test actor through a pidfd."""
    import cross_version_runtime as runtime
    if (type(pid) is not int or pid <= 1 or type(expected_uid) is not int
            or expected_uid <= 0 or type(deadline_ns) is not int
            or kind not in ('installed-observer-process',
                            'installed-runner-process')):
        raise ValueError('workload-positive-observer-selection-invalid')
    descriptor = os.pidfd_open(pid)
    try:
        until = min(time.monotonic_ns() + 2 * 10**9, deadline_ns)
        proc = Path('/proc') / str(pid)
        while time.monotonic_ns() < until:
            if select.select([descriptor], [], [], 0)[0]:
                raise ValueError('workload-positive-observer-exited')
            status = dict(line.split(':', 1) for line in
                          (proc / 'status').read_text().splitlines() if ':' in line)
            if set(map(int, status['Uid'].split())) == {expected_uid}:
                break
            time.sleep(.01)
        else:
            raise ValueError('workload-positive-observer-uid-unavailable')
        first = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
        cgroup = (proc / 'cgroup').read_text().strip()
        if (len(first) <= 19 or not first[19].isdecimal()
                or not cgroup.startswith('0::/')
                or '..' in cgroup.split('/') or status['NoNewPrivs'].strip() not in ('0', '1')):
            raise ValueError('workload-positive-observer-epoch-invalid')
        group = (Path('/sys/fs/cgroup') / cgroup[4:].lstrip('/')).stat()
        cgroup_identity = [group.st_dev, group.st_ino]
        namespaces = {name: os.stat(proc / 'ns' / name).st_ino
                      for name in ('pid', 'net', 'mnt', 'user')}
        second = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
        if (first[19] != second[19]
                or select.select([descriptor], [], [], 0)[0]):
            raise ValueError('workload-positive-observer-epoch-changed')
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        source = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        return {'kind': kind, 'pid': pid,
            'uid': expected_uid, 'startTicks': int(first[19]), 'bootId': boot,
            'cgroupIdentity': cgroup_identity,
            'cgroupDigest': runtime.canonical_digest({
                'role': 'positive-observer',
                'identity': cgroup_identity})[7:],
            'namespaces': namespaces, 'sourceDigest': source,
            'observedMonotonicNs': time.monotonic_ns()}
    finally:
        os.close(descriptor)


def _output_canary_control(root, uid, expected, case_id, expected_links=1):
    import runtime_snapshot as snapshot
    path = root / OUTPUT_CANARY
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
            or info.st_nlink != expected_links or info.st_size != 32
            or info.st_mode & 0o777 != 0o600):
        raise ValueError('workload-' + case_id + '-target-invalid')
    if case_id == 'output-hardlink' and expected_links == 2:
        with snapshot._directory(root) as parent:
            descriptor = os.open(OUTPUT_CANARY,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=parent)
            try:
                opened = os.fstat(descriptor)
                if ((opened.st_dev, opened.st_ino, opened.st_size,
                     opened.st_mtime_ns, opened.st_ctime_ns, opened.st_nlink)
                        != (info.st_dev, info.st_ino, info.st_size,
                            info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)):
                    raise ValueError('workload-output-hardlink-target-changed')
                raw = os.read(descriptor, 33)
                closed = os.fstat(descriptor)
                if ((closed.st_dev, closed.st_ino, closed.st_size,
                     closed.st_mtime_ns, closed.st_ctime_ns, closed.st_nlink)
                        != (info.st_dev, info.st_ino, info.st_size,
                            info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)):
                    raise ValueError('workload-output-hardlink-target-changed')
            finally:
                os.close(descriptor)
    else:
        raw = snapshot.read_file(root, OUTPUT_CANARY, maximum=32, timeout=2)
    digest = hashlib.sha256(raw).hexdigest()
    if len(raw) != 32 or digest != expected:
        raise ValueError('workload-' + case_id + '-target-invalid')
    result = {'controlDigest': digest, 'fileIdentity': [info.st_dev, info.st_ino,
        info.st_size, info.st_mtime_ns, info.st_ctime_ns],
            'observedMonotonicNs': time.monotonic_ns()}
    if case_id == 'output-hardlink':
        result['linkCount'] = info.st_nlink
    return result


def _publish_output_trigger(root, name, case_id, nonce):
    """Publish one complete root-owned barrier only after its final read mode is set."""
    pending = root / (name + '.pending')
    descriptor = os.open(pending,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, 'w', closefd=False) as stream:
            json.dump({'caseId': case_id, 'nonce': nonce}, stream,
                      sort_keys=True, separators=(',', ':'))
            stream.flush()
            os.fsync(stream.fileno())
        os.fchmod(descriptor, 0o444)
    finally:
        os.close(descriptor)
    os.link(pending, root / name, follow_symlinks=False)
    pending.unlink()


def _probe_output_artifact(*args, **kwargs):
    """Run the same fixed test-kit fault through its measured module."""
    from pr315_workload_fault_probes import _probe_output_artifact as emit
    return emit(*args, **kwargs)


def probe_output_symlink(workload, handoff, source_digest, campaign_deadline_ns):
    return _probe_output_artifact(workload, handoff, source_digest,
                                  campaign_deadline_ns, 'output-symlink')


def probe_output_fifo(workload, handoff, source_digest, campaign_deadline_ns):
    return _probe_output_artifact(workload, handoff, source_digest,
                                  campaign_deadline_ns, 'output-fifo')


def probe_output_hardlink(workload, handoff, source_digest, campaign_deadline_ns):
    return _probe_output_artifact(workload, handoff, source_digest,
                                  campaign_deadline_ns, 'output-hardlink')


def probe_output_flood(workload, handoff, source_digest, campaign_deadline_ns):
    return _probe_output_artifact(workload, handoff, source_digest,
                                  campaign_deadline_ns, 'output-flood')


def probe_output_replacement(workload, handoff, source_digest, campaign_deadline_ns):
    return _probe_output_artifact(workload, handoff, source_digest,
                                  campaign_deadline_ns, 'output-replacement')


def _mail_browser_control(workload, handoff, session, origin, expected_worker):
    """Prove a valid Mail browser session and current AppHost child through fixed HTTP."""
    from cross_version_workload import bind_worker
    from restricted_workload_controller import _http
    role = 'candidate-sender'
    handle = handoff['handles'][role]
    jdk = handoff['expectedJdkDigests'][role]
    if (not isinstance(expected_worker, dict)
            or type(expected_worker.get('namespacePid')) is not int
            or expected_worker['namespacePid'] <= 1):
        raise ValueError('workload-hostile-origin-app-worker-invalid')
    before = workload.observe(handle)
    worker_before = bind_worker(before, expected_worker['namespacePid'], jdk)
    stable_worker = ('hostPid', 'namespacePid', 'startTicks', 'javaHostPid',
                     'javaStartTicks', 'managerInvocation', 'cgroupIdentity')
    if any(worker_before[key] != expected_worker[key] for key in stable_worker):
        raise ValueError('workload-hostile-origin-app-worker-changed')
    with workload.connect(handle, 'http') as channel:
        status, _headers, body = _http(channel, '/api/v1/app-data/status', {
            'Accept': 'application/json', 'Origin': origin,
            'X-Crypta-App-Session': session})
    response = json.loads(body)
    app_status = response.get('status') if isinstance(response, dict) else None
    if (status != 200 or not isinstance(app_status, dict)
            or app_status.get('appId') != 'mail-prototype'
            or app_status.get('storeAvailable') is not True):
        raise ValueError('workload-hostile-origin-valid-target-unavailable')
    after = workload.observe(handle)
    worker_after = bind_worker(after, expected_worker['namespacePid'], jdk)
    if (any(worker_before[key] != worker_after[key] for key in stable_worker)
            or before['stateDigest'] != after['stateDigest']):
        raise ValueError('workload-hostile-origin-app-worker-changed')
    return {'role': role, 'managerInvocation': after['managerInvocation'],
            'bootId': after['bootId'], 'cgroupIdentity': after['cgroupIdentity'],
            'workerHostPid': worker_after['hostPid'],
            'workerStartTicks': worker_after['startTicks'],
            'javaHostPid': worker_after['javaHostPid'],
            'javaStartTicks': worker_after['javaStartTicks'],
            'observedMonotonicNs': after['observedMonotonicNs'],
            'controlResponseDigest': hashlib.sha256(body).hexdigest()}


def _validate_hostile_origin(value, secret, before, after, trigger_ns):
    """Require the candidate's good/bad/good exchange against one active app."""
    import pr315_role_probe as role_probe
    if (not isinstance(value, dict) or set(value) != {
            'caseId', 'endpointDigest', 'sessionDigest',
            'expectedOriginDigest', 'hostileOriginDigest',
            'before', 'attack', 'after'}
            or value['caseId'] != 'hostile-app-origin'
            or value['endpointDigest'] != hashlib.sha256(
                role_probe.HOSTILE_ORIGIN_ENDPOINT.encode()).hexdigest()
            or value['sessionDigest'] != hashlib.sha256(
                secret['session'].encode()).hexdigest()
            or value['expectedOriginDigest'] != hashlib.sha256(
                secret['expectedOrigin'].encode()).hexdigest()
            or value['hostileOriginDigest'] != hashlib.sha256(
                role_probe.HOSTILE_ORIGIN.encode()).hexdigest()):
        raise ValueError('workload-hostile-origin-probe-invalid')
    fields = {'status', 'errorCode', 'responseDigest',
              'startedMonotonicNs', 'finishedMonotonicNs'}
    for name in ('before', 'attack', 'after'):
        sample = value[name]
        if (not isinstance(sample, dict) or set(sample) != fields
                or type(sample['status']) is not int
                or re.fullmatch('[0-9a-f]{64}', str(sample['responseDigest'])) is None
                or type(sample['startedMonotonicNs']) is not int
                or type(sample['finishedMonotonicNs']) is not int
                or sample['startedMonotonicNs'] >= sample['finishedMonotonicNs']):
            raise ValueError('workload-hostile-origin-exchange-invalid')
    good_before, attack, good_after = (value[key]
        for key in ('before', 'attack', 'after'))
    stable = ('role', 'managerInvocation', 'bootId', 'cgroupIdentity',
              'workerHostPid', 'workerStartTicks', 'javaHostPid',
              'javaStartTicks')
    if (good_before['status'] != 200 or good_before['errorCode'] is not None
            or attack['status'] != 403 or attack['errorCode'] != 'origin_mismatch'
            or good_after['status'] != 200 or good_after['errorCode'] is not None
            or any(before[key] != after[key] for key in stable)
            or not before['observedMonotonicNs'] < trigger_ns
                < good_before['startedMonotonicNs'] < good_before['finishedMonotonicNs']
                < attack['startedMonotonicNs'] < attack['finishedMonotonicNs']
                < good_after['startedMonotonicNs'] < good_after['finishedMonotonicNs']
                < after['observedMonotonicNs']):
        raise ValueError('workload-hostile-origin-denial-or-target-invalid')
    return value


def probe_authority_claims(*args, **kwargs):
    """Run the same fixed test-kit fault through its measured module."""
    from pr315_workload_fault_probes import probe_authority_claims as emit
    return emit(*args, **kwargs)


def probe_observer_private_read(*args, **kwargs):
    """Run the same fixed test-kit fault through its measured module."""
    from pr315_workload_fault_probes import probe_observer_private_read as emit
    return emit(*args, **kwargs)


def _readiness_java_process(workload, handoff, selected_role=None):
    """Select one current role JVM from trusted service and kernel observations."""
    if selected_role is not None and selected_role not in ROLE_NAMES:
        raise ValueError('workload-readiness-role-invalid')
    for role in ((selected_role,) if selected_role is not None else reversed(ROLE_NAMES)):
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


def capture_readiness_jcmd(workload, handoff, role=None):
    """Collect two bounded JVM diagnostics before a failed role is stopped."""
    from bounded_process import run
    path = READINESS_JCMD
    try:
        role, invocation, process = _readiness_java_process_retry(workload, handoff, role)
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
        return {'status': 'retained', 'role': role, 'hostPid': process['hostPid'],
                'startTicks': process['startTicks'], 'managerInvocation': invocation,
                'commandStatuses': {key: row['status'] for key, row in record['commands'].items()},
                'privateDigest': hashlib.sha256(raw).hexdigest()}
    except (OSError, ValueError, KeyError, TypeError, IndexError,
            subprocess.SubprocessError) as error:
        return {'status': 'unavailable-or-unsafe', 'exceptionType': type(error).__name__[:128]}


def _readiness_java_process_retry(workload, handoff, role=None):
    """Retry only a busy authority lease within the original campaign deadline."""
    deadline_ns = handoff.get('deadlineMonotonicNs')
    now_ns = time.monotonic_ns()
    if type(deadline_ns) is not int or deadline_ns <= now_ns:
        raise ValueError('workload-readiness-jcmd-deadline-unavailable')
    until_ns = min(deadline_ns, now_ns + 2_000_000_000)
    while True:
        try:
            return _readiness_java_process(workload, handoff, role)
        except BlockingIOError:
            remaining_ns = until_ns - time.monotonic_ns()
            if remaining_ns <= 0:
                raise
            time.sleep(min(.05, remaining_ns / 1e9))


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


def complete_lost_start_before_cleanup(workload, handoff, result, diagnostics):
    """Bind the observer retry to the launch independently seen before its reply."""
    from cross_version_runtime import canonical_digest
    context = diagnostics.get('lostStartIntent')
    first = context.get('first') if isinstance(context, dict) else None
    observed = result.get('lostStartResponse') if isinstance(result, dict) else None
    if (not isinstance(context, dict) or not isinstance(first, dict)
            or not isinstance(observed, dict) or set(observed) != {
                'administratorBefore', 'droppedRequest', 'administratorBarrier'}
            or context.get('kind') != 'pr315-administrator-lost-start-intent'
            or context.get('schemaVersion') != 1
            or context.get('before') != diagnostics.get('lostStartBefore')
            or context['before'].get('role') != 'candidate-sender'
            or context['requestDigest'] != observed['droppedRequest'].get('requestDigest')
            or diagnostics.get('probeStart', {}).get('caseId') != 'lost-start-response'):
        raise ValueError('workload-lost-start-observer-binding-invalid')
    before, dropped, barrier = (observed[key] for key in
        ('administratorBefore', 'droppedRequest', 'administratorBarrier'))
    marker_ns = diagnostics['probeStart']['startedMonotonicNs']
    window = result.get('roleKernelRosterWindow')
    if (before != {'phase': 'lost-start-before', 'role': 'candidate-sender',
                   'observedMonotonicNs': marker_ns}
            or barrier != {'phase': 'lost-start-intent', 'role': 'candidate-sender',
                           'generation': first['generation'],
                           'managerInvocation': first['managerInvocation'],
                           'observedMonotonicNs': first['observedMonotonicNs']}
            or type(window) is not dict
            or not context['before']['observedMonotonicNs'] < marker_ns
                < dropped['sendStartedNs'] < dropped['sendFinishedNs']
                < first['observedMonotonicNs'] < window['startedMonotonicNs']
                < window['finishedMonotonicNs']):
        raise ValueError('workload-lost-start-window-invalid')
    role = 'candidate-sender'
    with workload.locked():
        campaign, selected, record = workload.retained(handoff['handles'][role])
        state = workload.manager(role, 'show')
        if (selected != role or record.get('state') != 'running'
                or state['ActiveState'] != 'active'):
            raise ValueError('workload-lost-start-retry-target-inactive')
        workload.exact(role, record, state)
        workload.current(campaign)
        marker = workload.read(workload.ROOT / 'authority' / (role + '-start.json'))
        if (any(record.get(key) != first[key] for key in
                ('generation', 'managerInvocation', 'bootId', 'cgroupIdentity'))
                or any(marker.get(key) != first[key] for key in
                       ('generation', 'managerInvocation', 'bootId', 'cgroupIdentity'))
                or state['MainPID'] != str(first['mainPid'])):
            raise ValueError('workload-lost-start-duplicate-invocation')
        roster = result.get('roleKernelRoster', {}).get('roles')
        if not isinstance(roster, list):
            raise ValueError('workload-lost-start-roster-unavailable')
        sender = next((row for row in roster if row.get('role') == role), None)
        if (not isinstance(sender, dict)
                or sender.get('invocationId') != first['managerInvocation']
                or sender.get('bootId') != first['bootId'].replace('-', '').lower()
                or sender.get('cgroupDigest') != canonical_digest({
                    'role': role, 'identity': first['cgroupIdentity']})[7:]):
            raise ValueError('workload-lost-start-roster-mismatch')
        finished = time.monotonic_ns()
    if finished <= window['finishedMonotonicNs']:
        raise ValueError('workload-lost-start-final-clock-invalid')
    return {**context, 'droppedRequest': dropped,
            'retry': {'role': role, 'generation': record['generation'],
                      'managerInvocation': record['managerInvocation'],
                      'bootId': record['bootId'],
                      'cgroupIdentity': record['cgroupIdentity'],
                      'mainPid': int(state['MainPID']),
                      'observedMonotonicNs': finished}}


def _verify_hostile_origin_handoff(result, group, sampler, diagnostics):
    """Bind a root-memory browser credential to digest-only observer output."""
    if not isinstance(result, dict):
        raise ValueError('workload-observer-result-invalid')
    injected = result.pop('hostileOriginSecret', None)
    secret = sampler.hostile_origin_secret
    if injected is not None:
        raise ValueError('workload-hostile-origin-secret-in-result')
    if group != 'authority':
        if secret is not None:
            raise ValueError('workload-hostile-origin-session-unselected')
        return None
    if (not isinstance(secret, dict)
            or set(secret) != {'session', 'expectedOrigin'}
            or not isinstance(secret['session'], str)
            or not 1 <= len(secret['session']) <= 4096
            or not secret['session'].isascii()
            or any(ord(character) < 33 or ord(character) > 126
                   for character in secret['session'])
            or not isinstance(secret['expectedOrigin'], str)
            or re.fullmatch(r'http://127\.0\.0\.1:[1-9][0-9]{3,4}',
                            secret['expectedOrigin']) is None):
        raise ValueError('workload-hostile-origin-session-invalid')
    session_digest = hashlib.sha256(secret['session'].encode()).hexdigest()
    origin_digest = hashlib.sha256(secret['expectedOrigin'].encode()).hexdigest()
    if (result.get('hostileOriginSessionDigest') != session_digest
            or result.get('mailUiOriginDigest') != origin_digest):
        raise ValueError('workload-hostile-origin-handoff-mismatch')
    diagnostics['hostileOriginSessionDigest'] = session_digest
    return secret


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


def begin_deadline(workload, handoff, result):
    """Arm the original campaign expiry only after all four roles are active."""
    from cross_version_runtime import canonical_digest
    active = begin_cancellation(workload, handoff, result)
    event = {'kind': 'deadline', 'roles': active['preRoles'],
             'campaignDeadlineNs': active['campaignDeadlineNs']}
    return {'schemaVersion': 1, 'kind': 'pr315-administrator-deadline',
            'armedMonotonicNs': active['triggerStartedNs'],
            'triggerEventDigest': canonical_digest(event)[7:],
            'campaignDeadlineNs': active['campaignDeadlineNs'],
            'preRoles': active['preRoles']}


def complete_deadline(workload, context):
    """Wait the retained deadline and observe each service stop before root cleanup."""
    deadline_ns = context['campaignDeadlineNs']
    if type(deadline_ns) is not int or context['armedMonotonicNs'] >= deadline_ns:
        raise ValueError('workload-deadline-selection-invalid')
    while time.monotonic_ns() < deadline_ns:
        time.sleep(min(.2, max(0, (deadline_ns - time.monotonic_ns()) / 1e9)))
    until = time.monotonic() + 40
    while time.monotonic() < until:
        observed = []
        for row in context['preRoles']:
            role = row['role']
            state = workload.manager(role, 'show')
            if (state['ActiveState'] not in {'inactive', 'failed'}
                    or state['SubState'] not in {'dead', 'failed'}
                    or state['MainPID'] != '0' or not workload.quiescent(role)):
                break
            try:
                receipt = workload.read(workload.ROOT / 'authority' /
                                        (role + '-stop.json'))
            except FileNotFoundError:
                break
            if (any(receipt[key] != row[key] for key in
                    ('role', 'managerInvocation', 'bootId', 'cgroupIdentity'))
                    or receipt['membership'] != 'only-stop-helper'
                    or receipt['descendantCgroups'] != 0
                    or receipt['startedMonotonicNs'] < deadline_ns
                    or receipt['observedMonotonicNs'] < receipt['startedMonotonicNs']):
                raise ValueError('workload-deadline-receipt-invalid')
            observed.append({'role': role,
                'managerInvocation': row['managerInvocation'],
                'receiptStartedNs': receipt['startedMonotonicNs'],
                'receiptObservedNs': receipt['observedMonotonicNs']})
        if len(observed) == len(ROLE_NAMES):
            finished = time.monotonic_ns()
            if finished <= deadline_ns:
                raise ValueError('workload-deadline-clock-invalid')
            return {**context, 'terminalObservedNs': finished,
                    'roleStops': observed, 'populatedCgroups': [],
                    'remainingDescendants': 0, 'retention': 'retained'}
        time.sleep(.05)
    raise ValueError('workload-deadline-service-stop-unobserved')


def _revocation_request(observer, handle, controller_pid):
    """Use one exact observer UID and fixed controller method after root revocation."""
    if (observer.pw_uid <= 0 or observer.pw_gid <= 0
            or re.fullmatch('[0-9a-f]{64}', handle) is None
            or type(controller_pid) is not int or controller_pid <= 1):
        raise ValueError('workload-revocation-observer-selection-invalid')
    request = (b'{"method":"start","handle":"' + handle.encode() + b'"}\n')
    response = b'{"error":"restricted-workload-request-failed"}\n'
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    pid = os.fork()
    if pid == 0:
        parent.close()
        try:
            allowed = {0, 1, 2, child.fileno()}
            for name in os.listdir('/proc/self/fd'):
                if name.isdecimal() and int(name) not in allowed:
                    try:
                        os.close(int(name))
                    except OSError:
                        pass
            os.setgroups([])
            os.setgid(observer.pw_gid)
            os.setuid(observer.pw_uid)
            os.environ.clear()
            os.environ.update(ENV)
            child.sendall(b'R')
            child.settimeout(5)
            if child.recv(1) != b'G':
                raise ValueError('workload-revocation-barrier-invalid')
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
                channel.settimeout(5)
                channel.connect(REVOCATION_CONTROL_SOCKET)
                peer, uid, _gid = struct.unpack('3i', channel.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
                if peer != controller_pid or uid != 0:
                    raise ValueError('workload-revocation-controller-peer-invalid')
                channel.sendall(request)
                raw = bytearray()
                while len(raw) <= len(response) and not raw.endswith(b'\n'):
                    block = channel.recv(len(response) + 1 - len(raw))
                    if not block:
                        break
                    raw.extend(block)
                if bytes(raw) != response:
                    raise ValueError('workload-revocation-denial-not-observed')
            child.sendall(b'1')
            os._exit(0)
        except BaseException:
            try:
                child.sendall(b'0')
            except OSError:
                pass
            os._exit(1)
    child.close()
    reaped = False
    try:
        parent.settimeout(5)
        if parent.recv(1) != b'R':
            raise ValueError('workload-revocation-observer-not-ready')
        proc = Path('/proc') / str(pid)
        status = next(line for line in proc.joinpath('status').read_text().splitlines()
                      if line.startswith('Uid:'))
        if set(map(int, status.split()[1:])) != {observer.pw_uid}:
            raise ValueError('workload-revocation-observer-uid-invalid')
        start_ticks = int(proc.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19])
        started = time.monotonic_ns()
        parent.sendall(b'G')
        observed = parent.recv(1)
        finished = time.monotonic_ns()
        status = wait_child(pid, time.monotonic() + 5)
        reaped = True
        if observed != b'1' or status != 0 or start_ticks <= 0 or finished <= started:
            raise ValueError('workload-revocation-denial-not-observed')
        return {'actor': {'pid': pid, 'uid': observer.pw_uid,
                          'startTicks': start_ticks},
                'requestDigest': hashlib.sha256(request).hexdigest(),
                'responseDigest': hashlib.sha256(response).hexdigest(),
                'requestStartedNs': started, 'responseObservedNs': finished}
    finally:
        parent.close()
        if not reaped:
            stop_child(pid)


def _observer_death_request(observer, handle, controller_pid, invocation):
    """Kill the exact observer after one successful installed controller request."""
    if (observer.pw_uid <= 0 or observer.pw_gid <= 0
            or re.fullmatch('[0-9a-f]{64}', handle) is None
            or type(controller_pid) is not int or controller_pid <= 1
            or re.fullmatch('[0-9a-f]{32}', invocation) is None
            or not hasattr(os, 'pidfd_open')
            or not hasattr(signal, 'pidfd_send_signal')):
        raise ValueError('workload-observer-death-selection-invalid')
    request = (b'{"method":"observe","handle":"' + handle.encode() + b'"}\n')
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    pid = os.fork()
    if pid == 0:
        parent.close()
        try:
            allowed = {0, 1, 2, child.fileno()}
            for name in os.listdir('/proc/self/fd'):
                if name.isdecimal() and int(name) not in allowed:
                    try:
                        os.close(int(name))
                    except OSError:
                        pass
            os.setgroups([])
            os.setgid(observer.pw_gid)
            os.setuid(observer.pw_uid)
            os.environ.clear()
            os.environ.update(ENV)
            child.sendall(b'R')
            child.settimeout(40)
            if child.recv(1) != b'G':
                raise ValueError('workload-observer-death-barrier-invalid')
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
                channel.settimeout(40)
                channel.connect(OBSERVER_DEATH_CONTROL_SOCKET)
                peer, uid, _gid = struct.unpack('3i', channel.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
                if peer != controller_pid or uid != 0:
                    raise ValueError('workload-observer-death-controller-peer-invalid')
                channel.sendall(request)
                raw = bytearray()
                while len(raw) <= 1024 * 1024 and not raw.endswith(b'\n'):
                    block = channel.recv(min(65536, 1024 * 1024 + 1 - len(raw)))
                    if not block:
                        break
                    raw.extend(block)
                if not 0 < len(raw) <= 1024 * 1024 or not raw.endswith(b'\n'):
                    raise ValueError('workload-observer-death-response-invalid')
                value = json.loads(raw)
                if (not isinstance(value, dict) or value.get('handle') != handle
                        or value.get('state') != 'running'
                        or value.get('managerInvocation') != invocation
                        or value.get('provenance') != 'controller-kernel-sample'):
                    raise ValueError('workload-observer-death-response-invalid')
            child.sendall(b'1' + hashlib.sha256(raw).hexdigest().encode())
            child.settimeout(None)
            while child.recv(1):
                pass
            os._exit(1)
        except BaseException:
            try:
                child.sendall(b'0')
            except OSError:
                pass
            os._exit(1)
    child.close()
    reaped = False
    pidfd = None
    try:
        parent.settimeout(5)
        if parent.recv(1) != b'R':
            raise ValueError('workload-observer-death-child-not-ready')
        proc = Path('/proc') / str(pid)
        status = next(line for line in proc.joinpath('status').read_text().splitlines()
                      if line.startswith('Uid:'))
        if set(map(int, status.split()[1:])) != {observer.pw_uid}:
            raise ValueError('workload-observer-death-child-uid-invalid')
        start_ticks = int(proc.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19])
        started = time.monotonic_ns()
        parent.sendall(b'G')
        parent.settimeout(40)
        response = parent.recv(65)
        finished = time.monotonic_ns()
        if (len(response) != 65 or response[:1] != b'1'
                or re.fullmatch(b'[0-9a-f]{64}', response[1:]) is None
                or start_ticks <= 0 or finished <= started):
            raise ValueError('workload-observer-death-activity-unobserved')
        pidfd = os.pidfd_open(pid)
        if int(proc.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19]) != start_ticks:
            raise ValueError('workload-observer-death-child-replaced')
        kill_started = time.monotonic_ns()
        signal.pidfd_send_signal(pidfd, signal.SIGTERM)
        status = wait_child(pid, time.monotonic() + 5)
        reaped = True
        kill_finished = time.monotonic_ns()
        if (not os.WIFSIGNALED(status) or os.WTERMSIG(status) != signal.SIGTERM
                or kill_finished <= kill_started):
            raise ValueError('workload-observer-death-child-not-killed')
        return {'actor': {'pid': pid, 'uid': observer.pw_uid,
                          'startTicks': start_ticks},
                'requestDigest': hashlib.sha256(request).hexdigest(),
                'responseDigest': response[1:].decode(),
                'requestStartedNs': started, 'responseObservedNs': finished,
                'killStartedNs': kill_started, 'killFinishedNs': kill_finished,
                'pidfdUsed': True}
    finally:
        if pidfd is not None:
            os.close(pidfd)
        parent.close()
        if not reaped:
            stop_child(pid)


def begin_revocation_running(workload, handoff, result, observer):
    """Revoke one live campaign and observe the installed controller refuse work."""
    from cross_version_runtime import canonical_digest
    import runtime_snapshot as snapshot
    active = begin_cancellation(workload, handoff, result)
    before = controller_unit_identity(workload)
    marker = workload.ROOT / 'revoked'
    raw = secrets.token_bytes(32)
    descriptor = os.open(marker,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(descriptor, raw) != len(raw):
            raise ValueError('workload-revocation-marker-short-write')
        os.fsync(descriptor)
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_nlink != 1 or info.st_mode & 0o077):
            raise ValueError('workload-revocation-marker-invalid')
    finally:
        os.close(descriptor)
    trigger = time.monotonic_ns()
    digest = hashlib.sha256(raw).hexdigest()
    denial = _revocation_request(observer,
        handoff['handles']['candidate-sender'], before['mainPid'])
    after = controller_unit_identity(workload)
    stable = ('invocationId', 'cgroupIdentity', 'bootId', 'mainPid',
              'mainStartTicks')
    if (any(before[key] != after[key] for key in stable)
            or not before['observedMonotonicNs'] < trigger
                < denial['requestStartedNs'] < denial['responseObservedNs']
                < after['observedMonotonicNs']
            or snapshot.read_file(workload.ROOT, 'revoked', maximum=32,
                                  timeout=2) != raw):
        raise ValueError('workload-revocation-target-changed')
    marker_after = marker.lstat()
    if ((marker_after.st_dev, marker_after.st_ino, marker_after.st_size)
            != (info.st_dev, info.st_ino, info.st_size)):
        raise ValueError('workload-revocation-marker-changed')
    for row in active['preRoles']:
        state = workload.manager(row['role'], 'show')
        if (state['ActiveState'] != 'active' or state['SubState'] != 'running'
                or state['MainPID'] != str(row['mainPid'])
                or state['InvocationID'] != row['managerInvocation']):
            raise ValueError('workload-revocation-sibling-changed')
    event = {'kind': 'revocation-running', 'roles': active['preRoles'],
             'campaignDeadlineNs': active['campaignDeadlineNs'],
             'markerDigest': digest}
    return {'schemaVersion': 1, 'kind': 'pr315-administrator-revocation-running',
        'triggerStartedNs': trigger,
        'triggerEventDigest': canonical_digest(event)[7:],
        'campaignDeadlineNs': active['campaignDeadlineNs'],
        'preRoles': active['preRoles'],
        'markerIdentity': [info.st_dev, info.st_ino, info.st_size],
        'markerDigest': digest, 'controllerBefore': before,
        'controllerAfter': after, **denial}


def complete_revocation_running(workload, context):
    """Bind the refusal to exact owned termination and unchanged revocation."""
    import runtime_snapshot as snapshot
    marker = workload.ROOT / 'revoked'
    info = marker.lstat()
    if ([info.st_dev, info.st_ino, info.st_size] != context['markerIdentity']
            or hashlib.sha256(snapshot.read_file(workload.ROOT, 'revoked',
                maximum=32, timeout=2)).hexdigest() != context['markerDigest']):
        raise ValueError('workload-revocation-marker-changed')
    for row in context['preRoles']:
        role = row['role']
        state = workload.manager(role, 'show')
        receipt = workload.read(workload.ROOT / 'authority' / (role + '-stop.json'))
        if (state['ActiveState'] not in {'inactive', 'failed'}
                or state['SubState'] not in {'dead', 'failed'}
                or state['MainPID'] != '0' or not workload.quiescent(role)
                or any(receipt[key] != row[key] for key in
                       ('role', 'managerInvocation', 'bootId', 'cgroupIdentity'))
                or receipt['membership'] != 'only-stop-helper'
                or receipt['descendantCgroups'] != 0
                or receipt['startedMonotonicNs'] <= context['responseObservedNs']):
            raise ValueError('workload-revocation-terminal-mismatch')
    finished = time.monotonic_ns()
    return {**context, 'terminalObservedNs': finished,
            'populatedCgroups': [], 'remainingDescendants': 0,
            'retention': 'retained'}


def _observer_death_controller_state():
    selected = subprocess.run(['/usr/bin/systemctl', 'show',
        'cryptad-workload-controller.service',
        '--property=InvocationID,ActiveState,SubState,MainPID', '--no-pager'],
        stdin=subprocess.DEVNULL, capture_output=True, check=True,
        timeout=5, env=ENV)
    if len(selected.stdout) > 8192 or selected.stderr:
        raise ValueError('workload-observer-death-controller-state-invalid')
    state = dict(line.split('=', 1) for line in selected.stdout.decode().splitlines()
                 if '=' in line)
    if set(state) != {'InvocationID', 'ActiveState', 'SubState', 'MainPID'}:
        raise ValueError('workload-observer-death-controller-state-invalid')
    return {'invocationId': state['InvocationID'],
            'activeState': state['ActiveState'],
            'subState': state['SubState'], 'mainPid': state['MainPID'],
            'observedMonotonicNs': time.monotonic_ns()}


def probe_observer_death(workload, handoff, result, observer):
    """Observe real 240-second controller inactivity after exact observer death."""
    from cross_version_runtime import canonical_digest
    active = begin_cancellation(workload, handoff, result)
    if active['campaignDeadlineNs'] - time.monotonic_ns() <= 300 * 10**9:
        raise ValueError('workload-observer-death-budget-insufficient')
    sender = next(row for row in active['preRoles']
                  if row['role'] == 'candidate-sender')
    controller_before = controller_unit_identity(workload)
    activity = _observer_death_request(observer,
        handoff['handles']['candidate-sender'], controller_before['mainPid'],
        sender['managerInvocation'])
    controller_active = controller_unit_identity(workload)
    stable = ('invocationId', 'cgroupIdentity', 'bootId', 'mainPid',
              'mainStartTicks')
    if (any(controller_before[key] != controller_active[key] for key in stable)
            or not controller_before['observedMonotonicNs']
                < activity['requestStartedNs'] < activity['responseObservedNs']
                < activity['killStartedNs'] < activity['killFinishedNs']
                < controller_active['observedMonotonicNs']):
        raise ValueError('workload-observer-death-controller-changed')
    target_ns = activity['responseObservedNs'] + 240 * 10**9
    if active['campaignDeadlineNs'] <= target_ns + 40 * 10**9:
        raise ValueError('workload-observer-death-budget-insufficient')
    until_ns = min(target_ns + 40 * 10**9, active['campaignDeadlineNs'])
    final_state = None
    stops = []
    while time.monotonic_ns() < until_ns:
        current = _observer_death_controller_state()
        if (current['activeState'] in {'inactive', 'failed'}
                and current['subState'] in {'dead', 'failed'}
                and current['mainPid'] == '0'):
            observed = []
            for row in active['preRoles']:
                role = row['role']
                state = workload.manager(role, 'show')
                if (state['ActiveState'] not in {'inactive', 'failed'}
                        or state['SubState'] not in {'dead', 'failed'}
                        or state['MainPID'] != '0' or not workload.quiescent(role)):
                    break
                try:
                    receipt = workload.read(workload.ROOT / 'authority' /
                                            (role + '-stop.json'))
                except FileNotFoundError:
                    break
                if (any(receipt[key] != row[key] for key in
                        ('role', 'managerInvocation', 'bootId', 'cgroupIdentity'))
                        or receipt['membership'] != 'only-stop-helper'
                        or receipt['descendantCgroups'] != 0
                        or receipt['startedMonotonicNs'] < target_ns):
                    raise ValueError('workload-observer-death-receipt-invalid')
                observed.append({'role': role,
                    'managerInvocation': row['managerInvocation'],
                    'receiptStartedNs': receipt['startedMonotonicNs'],
                    'receiptObservedNs': receipt['observedMonotonicNs']})
            if len(observed) == len(ROLE_NAMES):
                final_state = current
                stops = observed
                break
        time.sleep(1)
    if final_state is None:
        raise ValueError('workload-observer-death-owner-stop-unobserved')
    terminal_ns = time.monotonic_ns()
    if terminal_ns < target_ns:
        raise ValueError('workload-observer-death-premature-stop')
    event = {'kind': 'observer-death', 'roles': active['preRoles'],
             'observerPid': activity['actor']['pid'],
             'observerStartTicks': activity['actor']['startTicks'],
             'campaignDeadlineNs': active['campaignDeadlineNs'],
             'policySeconds': 240}
    return {'schemaVersion': 1, 'kind': 'pr315-administrator-observer-death',
        'triggerStartedNs': activity['killStartedNs'],
        'triggerEventDigest': canonical_digest(event)[7:],
        'campaignDeadlineNs': active['campaignDeadlineNs'],
        'preRoles': active['preRoles'],
        'controllerBefore': controller_before,
        'controllerActiveAfterRequest': controller_active,
        'controllerAfter': final_state,
        'policySeconds': 240, 'policyThresholdNs': target_ns,
        'stopObservations': stops,
        'terminalObservedNs': terminal_ns,
        'populatedCgroups': [], 'remainingDescendants': 0,
        'retention': 'retained', **activity}


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
                 probe_digest=None, sender_jdk_digest=None, handoff=None, observer_root=None,
                 lost_start_before=None, hostile_origin_selected=False):
        self.workload = workload
        self.recipient_handle = recipient_handle
        self.diagnostics = diagnostics
        self.phase = 'initial'
        self.sender_handle = sender_handle
        self.probe_digest = probe_digest
        self.sender_jdk_digest = sender_jdk_digest
        self.handoff = handoff
        self.observer_root = observer_root
        self.lost_start_before = lost_start_before
        self.hostile_origin_selected = hostile_origin_selected
        self.hostile_origin_secret = None

    def hostile_origin_handoff(self, payload):
        """Keep one selected browser credential in administrator memory only."""
        if (self.hostile_origin_selected is not True
                or self.hostile_origin_secret is not None
                or not 0 < len(payload) <= 8192):
            raise ValueError('workload-hostile-origin-handoff-unselected')
        secret = json.loads(payload)
        if (not isinstance(secret, dict)
                or set(secret) != {'session', 'expectedOrigin'}
                or not isinstance(secret['session'], str)
                or not 1 <= len(secret['session']) <= 4096
                or not secret['session'].isascii()
                or any(ord(character) < 33 or ord(character) > 126
                       for character in secret['session'])
                or not isinstance(secret['expectedOrigin'], str)
                or re.fullmatch(r'http://127\.0\.0\.1:[1-9][0-9]{3,4}',
                                secret['expectedOrigin']) is None):
            raise ValueError('workload-hostile-origin-handoff-invalid')
        self.hostile_origin_secret = secret
        return {'phase': 'hostile-origin-handoff',
                'sessionDigest': hashlib.sha256(secret['session'].encode()).hexdigest(),
                'originDigest': hashlib.sha256(
                    secret['expectedOrigin'].encode()).hexdigest()}

    def lost_start_prepare(self):
        """Mark the exact transition from four-role preparation to the fault probe."""
        before = self.lost_start_before
        workload = self.workload
        if (not isinstance(before, dict) or self.handoff is None
                or 'probeStart' in self.diagnostics):
            raise ValueError('workload-lost-start-probe-already-started')
        with workload.locked():
            campaign, role, record = workload.retained(self.sender_handle)
            state = workload.manager(role, 'show')
            if (role != 'candidate-sender' or record.get('state') != 'prepared'
                    or any(record.get(key) != before.get(key) for key in
                           ('generation', 'managerInvocation', 'cgroupIdentity', 'bootId'))
                    or state['ActiveState'] != 'inactive' or state['MainPID'] != '0'
                    or os.path.lexists(workload.ROOT / 'authority' /
                                      (role + '-start.json'))):
                raise ValueError('workload-lost-start-prepared-epoch-changed')
            workload.admit(campaign)
            self.diagnostics['lifecycleActorBefore'] = _administrator_collector_epoch(
                'lost-start-response')
            observed = time.monotonic_ns()
            if observed <= before['observedMonotonicNs']:
                raise ValueError('workload-lost-start-before-clock-invalid')
            self.diagnostics['probeStart'] = {'schemaVersion': 1,
                'kind': 'pr315-workload-probe-start',
                'caseId': 'lost-start-response', 'startedMonotonicNs': observed}
        return {'phase': 'lost-start-before', 'role': 'candidate-sender',
                'observedMonotonicNs': observed}

    def lost_start_intent(self):
        """Observe the first fixed sender launch before allowing an observer retry."""
        workload = self.workload
        before = self.lost_start_before
        if (not isinstance(before, dict) or self.handoff is None
                or self.sender_handle != self.handoff.get('handles', {}).get('candidate-sender')
                or before.get('state') != 'prepared'
                or before.get('managerInvocation') is not None
                or type(before.get('observedMonotonicNs')) is not int
                or self.diagnostics.get('probeStart', {}).get('caseId') !=
                    'lost-start-response'):
            raise ValueError('workload-lost-start-before-unavailable')
        deadline_ns = self.handoff.get('deadlineMonotonicNs')
        if type(deadline_ns) is not int or deadline_ns <= time.monotonic_ns():
            raise ValueError('workload-lost-start-deadline-unavailable')
        until = min(time.monotonic() + 45, deadline_ns / 1e9)
        while time.monotonic() < until:
            try:
                with workload.locked():
                    campaign, role, record = workload.retained(self.sender_handle)
                    state = workload.manager(role, 'show')
                    if (role == 'candidate-sender' and record.get('state') == 'running'
                            and state.get('ActiveState') == 'active'):
                        workload.exact(role, record, state)
                        workload.current(campaign)
                        marker = workload.read(workload.ROOT / 'authority' /
                                               (role + '-start.json'))
                        if (record.get('generation') == before.get('generation')
                                or record.get('bootId') != before.get('bootId')
                                or record.get('previousStopGeneration') is not None
                                or any(marker.get(key) != record.get(key) for key in
                                       ('generation', 'bootId', 'managerInvocation',
                                        'cgroupIdentity'))):
                            raise ValueError('workload-lost-start-first-invocation-invalid')
                        observed = time.monotonic_ns()
                        if observed <= before['observedMonotonicNs']:
                            raise ValueError('workload-lost-start-clock-invalid')
                        request = (b'{"method":"start","handle":"'
                                   + self.sender_handle.encode('ascii') + b'"}\n')
                        reply = {'phase': 'lost-start-intent', 'role': role,
                                 'generation': record['generation'],
                                 'managerInvocation': record['managerInvocation'],
                                 'observedMonotonicNs': observed}
                        self.diagnostics['lostStartIntent'] = {
                            'schemaVersion': 1,
                            'kind': 'pr315-administrator-lost-start-intent',
                            'before': before, 'requestDigest': hashlib.sha256(request).hexdigest(),
                            'first': {'role': role, 'generation': record['generation'],
                                      'managerInvocation': record['managerInvocation'],
                                      'bootId': record['bootId'],
                                      'cgroupIdentity': record['cgroupIdentity'],
                                      'mainPid': int(state['MainPID']),
                                      'observedMonotonicNs': observed}}
                        return reply
            except (BlockingIOError, FileNotFoundError):
                pass
            time.sleep(.05)
        raise ValueError('workload-lost-start-first-invocation-unobserved')

    def readiness(self, role, stage):
        """Capture one fixed failed role while the observer still owns its cleanup."""
        if (role not in ROLE_NAMES or stage not in READINESS_STAGES
                or self.handoff is None or self.observer_root is None):
            raise ValueError('workload-admin-readiness-selection-invalid')
        try:
            memory = memory_snapshot()
        except (OSError, ValueError, KeyError, TypeError):
            memory = {'status': 'unavailable'}
        record = {'role': role, 'stage': stage,
                  'observedMonotonicNs': time.monotonic_ns(),
                  'memory': memory,
                  'jcmd': capture_readiness_jcmd(self.workload, self.handoff, role)}
        log = self.observer_root / ('fcp-' + role + '.log')
        try:
            descriptor = os.open(log, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                info = os.fstat(descriptor)
                owner = pwd.getpwnam('cryptad-soak').pw_uid
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner
                        or info.st_nlink != 1 or info.st_mode & 0o077
                        or info.st_size > 16 * 1024 * 1024):
                    raise ValueError('workload-readiness-fcp-log-unsafe')
                os.lseek(descriptor, max(0, info.st_size - 8192), os.SEEK_SET)
                tail = os.read(descriptor, 8192)
                if os.fstat(descriptor).st_size != info.st_size:
                    raise ValueError('workload-readiness-fcp-log-changed')
                record['fcpLog'] = {'status': 'captured', 'sizeBytes': info.st_size,
                    'tailBase64': base64.b64encode(tail).decode('ascii')}
            finally:
                os.close(descriptor)
        except (OSError, ValueError, KeyError):
            record['fcpLog'] = {'status': 'unavailable-or-unsafe'}
        self.diagnostics['readinessAtFailure'] = record
        return {'phase': 'readiness', 'role': role, 'stage': stage,
                'status': 'captured'}

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
        message, _ancillary, flags, _address = channel.recvmsg(8193)
        if not message:
            return False
        try:
            readiness_role = (ROLE_NAMES[int(message[1:2])] if len(message) == 3
                              and message[:1] == b'J' and message[1:2] in (b'0', b'1', b'2', b'3')
                              else None)
            readiness_stage = ({b'S': 'start-request', b'F': 'fcp-get-node',
                                b'E': 'daemon-epoch', b'J': 'journal-node-start'}.get(message[2:3])
                               if readiness_role is not None else None)
            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or (
                    message not in (b'B', b'A', b'P', b'Q', b'L')
                    and not message.startswith(b'H') and readiness_stage is None):
                raise ValueError('workload-admin-fnp-request-invalid')
            result = (self.readiness(readiness_role, readiness_stage)
                      if readiness_stage is not None else
                      self.hostile_origin_handoff(message[1:])
                      if message.startswith(b'H') else
                      self.lost_start_prepare() if message == b'Q' else
                      self.lost_start_intent() if message == b'L' else
                      self.probe() if message == b'P' else
                      self.sample('before' if message == b'B' else 'after'))
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            private = getattr(error, 'private_diagnostics', None)
            if readiness_role is not None:
                self.diagnostics['readinessAdminFailure'] = {
                    'role': readiness_role, 'exceptionType': type(error).__name__[:128]}
                result = {'error': 'pr315-admin-readiness-capture-failed'}
            elif message == b'P':
                self.diagnostics['probeAdminFailure'] = {
                    'phase': 'probe', 'exceptionType': type(error).__name__[:128]}
                result = {'error': 'pr315-admin-probe-sample-failed'}
            elif message.startswith(b'H'):
                self.diagnostics['hostileOriginAdminFailure'] = {
                    'phase': 'hostile-origin-handoff',
                    'exceptionType': type(error).__name__[:128]}
                result = {'error': 'pr315-admin-hostile-origin-handoff-failed'}
            elif message in (b'Q', b'L'):
                self.diagnostics['lostStartAdminFailure'] = {
                    'phase': 'lost-start-before' if message == b'Q' else 'lost-start-intent',
                    'exceptionType': type(error).__name__[:128]}
                result = {'error': 'pr315-admin-lost-start-sample-failed'}
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


def request_administrator_readiness(channel, role, stage):
    """Ask for one fixed private diagnostic after a failed start, before cleanup."""
    if role not in ROLE_NAMES or stage not in READINESS_STAGES:
        raise ValueError('workload-admin-readiness-role-invalid')
    channel.settimeout(18)
    channel.sendall(b'J' + str(ROLE_NAMES.index(role)).encode('ascii') + {
        'start-request': b'S', 'fcp-get-node': b'F', 'daemon-epoch': b'E',
        'journal-node-start': b'J'}[stage])
    raw = channel.recv(8193)
    if not 1 <= len(raw) <= 8192 or not raw.endswith(b'\n') or raw.count(b'\n') != 1:
        raise ValueError('workload-admin-readiness-response-invalid')
    value = json.loads(raw)
    if value != {'phase': 'readiness', 'role': role, 'stage': stage,
                 'status': 'captured'}:
        raise ValueError('workload-admin-readiness-capture-failed')
    return value


def request_administrator_lost_start(channel, phase, campaign_deadline):
    """Use only fixed pre-send and first-invocation administrator barriers."""
    if phase not in ('before', 'intent'):
        raise ValueError('workload-admin-lost-start-phase-invalid')
    remaining = campaign_deadline / 1e9 - time.monotonic()
    if remaining <= 0:
        raise ValueError('workload-admin-lost-start-deadline')
    channel.settimeout(min(50, remaining))
    channel.sendall(b'Q' if phase == 'before' else b'L')
    raw = channel.recv(8193)
    if not 1 <= len(raw) <= 8192 or not raw.endswith(b'\n') or raw.count(b'\n') != 1:
        raise ValueError('workload-admin-lost-start-response-invalid')
    value = json.loads(raw)
    expected = {'phase', 'role', 'observedMonotonicNs'}
    if phase == 'intent':
        expected.update(('generation', 'managerInvocation'))
    if (not isinstance(value, dict) or set(value) != expected
            or value['phase'] != 'lost-start-' + phase
            or value['role'] != 'candidate-sender'
            or type(value['observedMonotonicNs']) is not int
            or value['observedMonotonicNs'] <= 0
            or phase == 'intent' and (
                re.fullmatch('[0-9a-f]{64}', str(value['generation'])) is None
                or re.fullmatch('[0-9a-f]{32}', str(value['managerInvocation'])) is None)):
        raise ValueError('workload-admin-lost-start-sample-failed')
    return value


def request_administrator_hostile_origin(channel, session, origin,
                                         campaign_deadline):
    """Send one selected browser credential over the inherited private packet socket."""
    if (not isinstance(session, str) or not 1 <= len(session) <= 4096
            or not isinstance(origin, str)
            or re.fullmatch(r'http://127\.0\.0\.1:[1-9][0-9]{3,4}', origin) is None):
        raise ValueError('workload-admin-hostile-origin-selection-invalid')
    payload = json.dumps({'session': session, 'expectedOrigin': origin},
                         sort_keys=True, separators=(',', ':')).encode()
    if len(payload) > 8192:
        raise ValueError('workload-admin-hostile-origin-packet-limit')
    remaining = campaign_deadline / 1e9 - time.monotonic()
    if remaining <= 0:
        raise ValueError('workload-admin-hostile-origin-deadline')
    channel.settimeout(min(8, remaining))
    channel.sendall(b'H' + payload)
    raw = channel.recv(513)
    if not 1 <= len(raw) <= 512 or not raw.endswith(b'\n') or raw.count(b'\n') != 1:
        raise ValueError('workload-admin-hostile-origin-response-invalid')
    value = json.loads(raw)
    expected = {'phase': 'hostile-origin-handoff',
                'sessionDigest': hashlib.sha256(session.encode()).hexdigest(),
                'originDigest': hashlib.sha256(origin.encode()).hexdigest()}
    if value != expected:
        raise ValueError('workload-admin-hostile-origin-unverified')
    return value


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


def controller_bootstrap_failure_snapshot(workload):
    """Copy only a closed root-private bootstrap phase before service teardown."""
    path = Path('/run/cryptad-workload/bootstrap-failure.private.json')
    try:
        value = workload.read(path)
    except FileNotFoundError:
        return {'status': 'not-observed'}
    except (OSError, ValueError):
        return {'status': 'unavailable-or-unsafe'}
    stages = {'authority', 'installed-app', 'launch-redirect',
              'origin-parse', 'app-runtime', 'session-bootstrap', 'recheck'}
    try:
        if (not isinstance(value, dict) or set(value) != {
                'schemaVersion', 'kind', 'stage', 'role', 'exceptionType',
                'errorCode', 'controllerPid', 'bootId',
                'startedMonotonicNs', 'observedMonotonicNs'}
                or value['schemaVersion'] != 1
                or value['kind'] != 'pr315-controller-bootstrap-failure-phase'
                or value['stage'] not in stages
                or value['role'] not in (*ROLE_NAMES, 'unknown')
                or re.fullmatch(r'[A-Za-z][A-Za-z0-9]{0,127}',
                    value['exceptionType']) is None
                or re.fullmatch(r'[a-z][a-z0-9-]{1,100}',
                    value['errorCode']) is None
                or value['bootId'] != workload.boot()
                or type(value['controllerPid']) is not int
                or value['controllerPid'] <= 1
                or type(value['startedMonotonicNs']) is not int
                or type(value['observedMonotonicNs']) is not int
                or not 0 < value['startedMonotonicNs'] <
                    value['observedMonotonicNs'] <= time.monotonic_ns()):
            raise ValueError('workload-bootstrap-diagnostic-invalid')
        return {'status': 'captured', 'record': value,
                'classification': 'private-bootstrap-diagnostic-not-acceptance'}
    except (KeyError, TypeError, ValueError):
        return {'status': 'unavailable-or-unsafe'}


def readiness_deadline(campaign_deadline_ns, started, startup_measurement=False):
    """Prospective diagnostic observation never extends the retained execution deadline."""
    seconds = STARTUP_MEASUREMENT_SECONDS if startup_measurement else READINESS_SECONDS
    return min(campaign_deadline_ns / 10**9, started + seconds)


def observer_sequence(selected, root, handoff, campaign_deadline, startup_begin,
                      startup_measurement=False, *, admin_channel=None, workload_group=None):
    """Observe controller readiness, then run the selected finite installed path."""
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
                admin_channel, phase, campaign_deadline)) if admin_channel is not None else None,
            lost_start_sampler=(lambda phase: request_administrator_lost_start(
                admin_channel, phase, campaign_deadline))
                if admin_channel is not None and workload_group == 'lost-start-response' else None,
            origin_handoff=(lambda session, origin: request_administrator_hostile_origin(
                admin_channel, session, origin, campaign_deadline))
                if admin_channel is not None and workload_group == 'authority' else None)
        diagnostic = ((lambda role, stage: request_administrator_readiness(
            admin_channel, role, stage))
                      if admin_channel is not None else None)
        if workload_group in ('lost-start-response', 'partial-launch',
                              'stuck-output', 'late-child', 'cleanup-race',
                              'resource-exhaustion',
                              'output-symlink', 'output-fifo', 'output-hardlink',
                              'output-flood', 'output-replacement',
                              'role-readiness-diagnostic', 'role-boundary',
                              'authority', 'network-app', 'cancellation',
                              'controller-restart', 'deadline', 'revocation-running',
                              'setsid-double-fork', 'observer-death'):
            result = adapter.run_group_preparation(workload_group,
                leave_running_for_administrator=True, on_start_failure=diagnostic)
        else:
            result = adapter.run_positive(leave_running_for_administrator=True,
                on_start_failure=diagnostic)
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
        actor_epoch = _positive_observer_epoch(process.pid, runner.pw_uid,
            time.monotonic_ns() + 2 * 10**9, kind='installed-runner-process')
        if actor_epoch['startTicks'] != actor_start:
            raise ValueError('runner-control-actor-epoch-changed')
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
    return {'status': 'captured', 'actorEpoch': actor_epoch}


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
            workload_group=None, retired_authority_preparation=False):
    if lifecycle_scenario not in LIFECYCLE_SCENARIOS:
        raise ValueError('workload-lifecycle-scenario-invalid')
    if workload_group not in (None, 'positive', 'lost-start-response',
                             'partial-launch', 'stuck-output', 'late-child',
                             'cleanup-race',
                             'resource-exhaustion',
                             'output-symlink', 'output-fifo',
                             'output-hardlink', 'output-flood', 'output-replacement',
                             'role-readiness-diagnostic', 'role-boundary',
                             'authority', 'network-app', 'cancellation',
                             'controller-restart', 'deadline', 'revocation-running',
                             'setsid-double-fork', 'observer-death') or (
            startup_measurement and workload_group or
            retired_authority_preparation and
            (workload_group != 'role-readiness-diagnostic'
             or lifecycle_scenario != 'none')):
        raise ValueError('workload-group-invalid')
    if (workload_group in ('cancellation', 'controller-restart', 'deadline',
                           'revocation-running', 'setsid-double-fork',
                           'observer-death') and
            lifecycle_scenario != workload_group or
            workload_group not in (None, 'cancellation', 'controller-restart',
                                   'deadline', 'revocation-running',
                                   'setsid-double-fork', 'observer-death')
            and lifecycle_scenario != 'none' or
            workload_group is None and lifecycle_scenario == 'none'):
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
                       if not startup_measurement and workload_group in (None, 'authority')
                       else None)
    provider_setup = (prepare_provider_canary()
                      if not startup_measurement and workload_group == 'network-app'
                      else None)
    if provider_setup is not None:
        resolver_digest = provider_setup['resolverDigest']
    parent = child = admin_parent = admin_child = None
    pid = None
    status = None
    result = None
    diagnostics = {'classification': 'private-kernel-diagnostics-not-acceptance',
                   'before': memory_snapshot(), 'cleanup': 'not-completed'}
    sentinel = None
    lost_start_before = None
    cancellation = None
    controller_restart = None
    revocation = None
    try:
        handoff = prepare(selected['plan'], selected['private'], selected['authorization'])
        role_probe_digest = stage_role_probe(workload, kit)
        lifecycle_probe_digest = stage_lifecycle_probe(workload, kit)
        sibling_digest = prepare_sibling_canary(workload)
        campaign_deadline = workload.read(workload.ROOT / 'campaign.json')['deadlineMonotonicNs']
        if type(campaign_deadline) is not int or campaign_deadline <= time.monotonic_ns():
            raise ValueError('workload-preparation-consumed-deadline')
        if (type(handoff.get('deadlineMonotonicNs')) is not int
                or handoff['deadlineMonotonicNs'] != campaign_deadline):
            raise ValueError('workload-handoff-deadline-mismatch')
        sentinel = evidence.prepare_sentinel(workload)
        if not startup_measurement and workload_group in (None, 'positive'):
            diagnostics['positiveAdministratorBefore'] = (
                _administrator_collector_epoch('positive'))
        if workload_group == 'lost-start-response':
            role = 'candidate-sender'
            prepared = workload.read(workload.ROOT / 'authority' / (role + '.json'))
            state = workload.manager(role, 'show')
            if (prepared.get('handle') != handoff['handles'][role]
                    or prepared.get('state') != 'prepared'
                    or any(prepared.get(key) is not None for key in
                           ('generation', 'managerInvocation', 'cgroupIdentity'))
                    or state['ActiveState'] != 'inactive' or state['MainPID'] != '0'
                    or os.path.lexists(workload.ROOT / 'authority' /
                                      (role + '-start.json'))):
                raise ValueError('workload-lost-start-role-not-prepared')
            lost_start_before = {'role': role, 'state': 'prepared',
                'generation': None, 'managerInvocation': None,
                'cgroupIdentity': None, 'bootId': prepared['bootId'],
                'mainPid': 0, 'observedMonotonicNs': time.monotonic_ns()}
            diagnostics['lostStartBefore'] = lost_start_before
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
                                           admin_channel=admin_child,
                                           workload_group=workload_group)
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
        if not startup_measurement and workload_group in (None, 'positive'):
            diagnostics['positiveObserverEpoch'] = _positive_observer_epoch(
                pid, observer.pw_uid, campaign_deadline)
        if not startup_measurement and workload_group == 'authority':
            diagnostics['authorityObserverEpoch'] = _positive_observer_epoch(
                pid, observer.pw_uid, campaign_deadline)
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
            sender_jdk_digest=handoff.get('expectedJdkDigests', {}).get('candidate-sender'),
            handoff=handoff, observer_root=root,
            lost_start_before=lost_start_before,
            hostile_origin_selected=workload_group == 'authority')
        raw, status = collect_child(parent, pid, deadline,
            lambda: sample_memory(diagnostics), admin_channel=admin_parent,
            admin_sampler=sampler)
        if status != 0:
            diagnostics['observerFailure'] = {'exitStatus': status,
                'privateTranscript': raw[:4096].decode('utf-8', errors='replace')}
            try:
                failure = json.loads(raw)
                if (failure.get('observerFailure') == 'RuntimeFailure'
                        and failure.get('privateDetail') == 'workload-daemon-readiness-timeout'
                        and 'readinessAtFailure' not in diagnostics):
                    diagnostics['readinessJcmd'] = capture_readiness_jcmd(workload, handoff)
            except (UnicodeError, ValueError, TypeError, AttributeError):
                diagnostics['readinessJcmd'] = {'status': 'failure-transcript-invalid'}
            raise ValueError('workload-positive-sequence-failed')
        result = json.loads(raw)
        hostile_secret = _verify_hostile_origin_handoff(
            result, workload_group, sampler, diagnostics)
        if (not startup_measurement and workload_group in (None, 'positive')
                and (result.get('contentRetrieval') != 'observed' or result.get('newEpoch') is not True)):
            raise ValueError('workload-positive-observation-incomplete')
        if (workload_group in ('lost-start-response', 'partial-launch',
                              'stuck-output', 'late-child', 'cleanup-race',
                              'resource-exhaustion',
                              'output-symlink', 'output-fifo', 'output-hardlink',
                              'output-flood', 'output-replacement',
                              'role-readiness-diagnostic', 'role-boundary',
                              'authority', 'network-app', 'cancellation',
                              'controller-restart', 'deadline',
                              'revocation-running', 'setsid-double-fork',
                              'observer-death') and
                (result.get('groupPreparation') != workload_group
                 or result.get('contentRetrieval') != 'not-executed-group'
                 or result.get('newEpoch') is not False)):
            raise ValueError('workload-group-preparation-incomplete')
        result.update(identity=identity, runtimePolicy=launcher_policy(),
                      finiteNativeAcceptance='not-executed-by-this-driver',
                      campaignDeadlineMonotonicNs=campaign_deadline,
                      workloadAcceptance=('not-executed-startup-measurement' if startup_measurement
                          else 'not-executed-role-readiness-measurement'
                          if workload_group == 'role-readiness-diagnostic'
                          else 'incomplete-hostile-contract-not-executed'), protectedExecutionEnabled=False)
        if not startup_measurement and workload_group == 'lost-start-response':
            try:
                diagnostics['lostStartResponse'] = complete_lost_start_before_cleanup(
                    workload, handoff, result, diagnostics)
            except (OSError, ValueError, KeyError, TypeError, AttributeError,
                    StopIteration) as error:
                diagnostics['lostStartResponse'] = {'status': 'unavailable-or-unsafe',
                    'exceptionType': type(error).__name__[:128]}
                raise ValueError('workload-lost-start-verification-failed') from None
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
        if not startup_measurement and workload_group == 'role-boundary':
            diagnostics['probeStart'] = {'schemaVersion': 1,
                'kind': 'pr315-workload-probe-start', 'caseId': workload_group,
                'startedMonotonicNs': time.monotonic_ns()}
            try:
                private_probe = probe_observer_private_read(
                    workload, handoff, observer, role_probe_digest, sibling_digest,
                    None, campaign_deadline, case_group='role-boundary')
                diagnostics['observerPrivateRead'] = {key: private_probe[key]
                    for key in ('status', 'caseId', 'auditDigest')}
                diagnostics['observerPrivateWrite'] = {'status': private_probe['writeStatus'],
                    'caseId': 'observer-private-write',
                    'auditDigest': private_probe['writeAuditDigest']}
                for selected_case, field in (
                        ('sibling-data', 'siblingData'),
                        ('package-expectation', 'packageExpectation'),
                        ('cgroup-migration', 'cgroupMigration')):
                    diagnostics[field] = {'status': 'captured', 'caseId': selected_case,
                        'auditDigest': private_probe['fixedAccessAudits'][selected_case]}
            except (OSError, ValueError, KeyError, TypeError, AttributeError,
                    subprocess.SubprocessError) as error:
                diagnostic = {'status': 'unavailable-or-unsafe',
                              'exceptionType': type(error).__name__[:128]}
                code = _private_role_probe_code(error)
                if code is not None:
                    diagnostic['code'] = code
                for field in ('observerPrivateRead', 'observerPrivateWrite',
                              'siblingData', 'packageExpectation', 'cgroupMigration'):
                    diagnostics[field] = diagnostic
        if not startup_measurement and workload_group == 'authority':
            diagnostics['probeStart'] = {'schemaVersion': 1,
                'kind': 'pr315-workload-probe-start', 'caseId': workload_group,
                'startedMonotonicNs': time.monotonic_ns()}
            try:
                diagnostics['runnerControl'] = probe_runner_control(
                    workload, handoff, result)
            except (OSError, ValueError, KeyError, TypeError, IndexError,
                    subprocess.SubprocessError) as error:
                diagnostics['runnerControl'] = {'status': 'unavailable-or-unsafe',
                                                'exceptionType': type(error).__name__[:128]}
            try:
                claims = probe_authority_claims(
                    workload, handoff, role_probe_digest, resolver_digest,
                    campaign_deadline, hostile_secret,
                    result['mailAppKernelProcess'])
                for field, case_id, digest_key in (
                        ('forgedRuntimeIdentity', 'forged-runtime-identity',
                         'identityAuditDigest'),
                        ('forgedCounters', 'forged-counters', 'counterAuditDigest'),
                        ('resolverAuthority', 'resolver-authority',
                         'resolverAuditDigest'),
                        ('hostileAppOrigin', 'hostile-app-origin',
                         'hostileOriginAuditDigest')):
                    diagnostics[field] = {'status': 'captured', 'caseId': case_id,
                                          'auditDigest': claims[digest_key]}
            except (OSError, ValueError, KeyError, TypeError, AttributeError,
                    subprocess.SubprocessError) as error:
                diagnostic = {'status': 'unavailable-or-unsafe',
                              'exceptionType': type(error).__name__[:128]}
                code = _private_role_probe_code(error)
                if code is not None:
                    diagnostic['code'] = code
                for field in ('forgedRuntimeIdentity', 'forgedCounters',
                              'resolverAuthority', 'hostileAppOrigin'):
                    diagnostics[field] = diagnostic
            if RETIRED_AUTHORITY_SOURCE.exists():
                try:
                    retired = workload.read(RETIRED_AUTHORITY_SOURCE)
                    digest = probe_stale_handle(workload, handoff,
                        retired, result, campaign_deadline)
                    diagnostics['staleHandle'] = {'status': 'captured',
                        'caseId': 'stale-handle', 'auditDigest': digest}
                except Exception as error:
                    diagnostics['staleHandle'] = {
                        'status': 'unavailable-or-unsafe',
                        'exceptionType': type(error).__name__[:128]}
            try:
                digest = probe_stale_pid_uid(workload, handoff, result,
                    campaign_deadline)
                diagnostics['stalePidUid'] = {'status': 'captured',
                    'caseId': 'stale-pid-uid', 'auditDigest': digest}
            except Exception as error:
                diagnostics['stalePidUid'] = {'status': 'unavailable-or-unsafe',
                    'exceptionType': type(error).__name__[:128]}
        if not startup_measurement and workload_group == 'network-app':
            diagnostics['probeStart'] = {'schemaVersion': 1,
                'kind': 'pr315-workload-probe-start', 'caseId': workload_group,
                'startedMonotonicNs': time.monotonic_ns()}
            try:
                digest = probe_provider_authority(workload, handoff,
                    provider_setup, resolver_digest,
                    probe_digest, result['probeAppKernelProcess'],
                    campaign_deadline)
                diagnostics['providerAuthority'] = {'status': 'captured',
                    'caseId': 'provider-authority', 'auditDigest': digest}
            except (OSError, ValueError, KeyError, TypeError, AttributeError,
                    subprocess.SubprocessError) as error:
                diagnostics['providerAuthority'] = {
                    'status': 'unavailable-or-unsafe',
                    'exceptionType': type(error).__name__[:128]}
            try:
                digest = probe_sibling_app(workload, handoff,
                    probe_digest, result['probeAppKernelProcess'],
                    result['recipientMailAppKernelProcess'],
                    campaign_deadline)
                diagnostics['siblingApp'] = {'status': 'captured',
                    'caseId': 'sibling-app', 'auditDigest': digest}
            except (OSError, ValueError, KeyError, TypeError, AttributeError,
                    subprocess.SubprocessError) as error:
                diagnostics['siblingApp'] = {'status': 'unavailable-or-unsafe',
                    'exceptionType': type(error).__name__[:128]}
            try:
                audits = probe_network_app_roles(workload, handoff,
                    role_probe_digest, campaign_deadline)
                for selected_case, field in (('sibling-fcp', 'siblingFcp'),
                                             ('sibling-http', 'siblingHttp'),
                                             ('host-network', 'hostNetwork')):
                    diagnostics[field] = {'status': 'captured',
                        'caseId': selected_case, 'auditDigest': audits[selected_case]}
            except (OSError, ValueError, KeyError, TypeError, AttributeError,
                    subprocess.SubprocessError) as error:
                diagnostic = {'status': 'unavailable-or-unsafe',
                              'exceptionType': type(error).__name__[:128]}
                code = _private_role_probe_code(error)
                if code is not None:
                    diagnostic['code'] = code
                for field in ('siblingFcp', 'siblingHttp', 'hostNetwork'):
                    diagnostics[field] = diagnostic
        if not startup_measurement and workload_group == 'resource-exhaustion':
            diagnostics['probeStart'] = {'schemaVersion': 1,
                'kind': 'pr315-workload-probe-start', 'caseId': workload_group,
                'startedMonotonicNs': time.monotonic_ns()}
            try:
                digest = probe_resource_exhaustion(workload, handoff,
                    probe_digest, result['probeAppKernelProcess'],
                    campaign_deadline)
                diagnostics['resourceExhaustion'] = {'status': 'captured',
                    'caseId': 'resource-exhaustion', 'auditDigest': digest}
            except (OSError, ValueError, KeyError, TypeError, AttributeError,
                    subprocess.SubprocessError) as error:
                diagnostics['resourceExhaustion'] = {
                    'status': 'unavailable-or-unsafe',
                    'exceptionType': type(error).__name__[:128]}
        if not startup_measurement and workload_group == 'partial-launch':
            diagnostics['probeStart'] = {'schemaVersion': 1,
                'kind': 'pr315-workload-probe-start', 'caseId': workload_group,
                'startedMonotonicNs': time.monotonic_ns()}
            try:
                digest = probe_partial_launch(workload, handoff, result,
                    observer.pw_uid, campaign_deadline)
                diagnostics['partialLaunch'] = {'status': 'captured',
                    'caseId': 'partial-launch', 'auditDigest': digest}
            except (OSError, ValueError, KeyError, TypeError, AttributeError,
                    subprocess.SubprocessError) as error:
                diagnostics['partialLaunch'] = {
                    'status': 'unavailable-or-unsafe',
                    'exceptionType': type(error).__name__[:128]}
        if not startup_measurement and workload_group == 'stuck-output':
            diagnostics['probeStart'] = {'schemaVersion': 1,
                'kind': 'pr315-workload-probe-start', 'caseId': workload_group,
                'startedMonotonicNs': time.monotonic_ns()}
            try:
                digest = probe_stuck_output(workload, handoff, result,
                    role_probe_digest, campaign_deadline)
                diagnostics['stuckOutput'] = {'status': 'captured',
                    'caseId': 'stuck-output', 'auditDigest': digest}
            except (OSError, ValueError, KeyError, TypeError, AttributeError,
                    subprocess.SubprocessError) as error:
                diagnostics['stuckOutput'] = {'status': 'unavailable-or-unsafe',
                    'exceptionType': type(error).__name__[:128]}
        if not startup_measurement and workload_group == 'late-child':
            diagnostics['probeStart'] = {'schemaVersion': 1,
                'kind': 'pr315-workload-probe-start', 'caseId': workload_group,
                'startedMonotonicNs': time.monotonic_ns()}
            try:
                digest = probe_late_child(workload, handoff, result,
                    lifecycle_probe_digest, campaign_deadline)
                diagnostics['lateChild'] = {'status': 'captured',
                    'caseId': 'late-child', 'auditDigest': digest}
            except (OSError, ValueError, KeyError, TypeError, AttributeError,
                    subprocess.SubprocessError) as error:
                diagnostics['lateChild'] = {'status': 'unavailable-or-unsafe',
                    'exceptionType': type(error).__name__[:128]}
        if not startup_measurement and workload_group == 'cleanup-race':
            diagnostics['probeStart'] = {'schemaVersion': 1,
                'kind': 'pr315-workload-probe-start', 'caseId': workload_group,
                'startedMonotonicNs': time.monotonic_ns()}
            try:
                digest = probe_cleanup_race(workload, handoff, result,
                    campaign_deadline)
                diagnostics['cleanupRace'] = {'status': 'captured',
                    'caseId': 'cleanup-race', 'auditDigest': digest}
            except (OSError, ValueError, KeyError, TypeError, AttributeError,
                    subprocess.SubprocessError) as error:
                diagnostics['cleanupRace'] = {'status': 'unavailable-or-unsafe',
                    'exceptionType': type(error).__name__[:128]}
        if not startup_measurement and workload_group in (
                'output-symlink', 'output-fifo', 'output-hardlink',
                'output-flood', 'output-replacement'):
            diagnostics['probeStart'] = {'schemaVersion': 1,
                'kind': 'pr315-workload-probe-start', 'caseId': workload_group,
                'startedMonotonicNs': time.monotonic_ns()}
            try:
                probe = {'output-symlink': probe_output_symlink,
                         'output-fifo': probe_output_fifo,
                         'output-hardlink': probe_output_hardlink,
                         'output-flood': probe_output_flood,
                         'output-replacement': probe_output_replacement}[workload_group]
                digest = probe(workload, handoff, role_probe_digest, campaign_deadline)
                field = {'output-symlink': 'outputSymlink', 'output-fifo': 'outputFifo',
                         'output-hardlink': 'outputHardlink',
                         'output-flood': 'outputFlood',
                         'output-replacement': 'outputReplacement'}[workload_group]
                diagnostics[field] = {'status': 'captured',
                    'caseId': workload_group, 'auditDigest': digest}
            except (OSError, ValueError, KeyError, TypeError, AttributeError,
                    subprocess.SubprocessError) as error:
                field = {'output-symlink': 'outputSymlink', 'output-fifo': 'outputFifo',
                         'output-hardlink': 'outputHardlink',
                         'output-flood': 'outputFlood',
                         'output-replacement': 'outputReplacement'}[workload_group]
                diagnostics[field] = {'status': 'unavailable-or-unsafe',
                    'exceptionType': type(error).__name__[:128],
                    'code': _private_role_probe_code(error)}
        if not startup_measurement and workload_group in ('cancellation',
                'controller-restart', 'deadline', 'revocation-running',
                'setsid-double-fork', 'observer-death'):
            diagnostics['probeStart'] = {'schemaVersion': 1,
                'kind': 'pr315-workload-probe-start', 'caseId': workload_group,
                'startedMonotonicNs': time.monotonic_ns()}
            diagnostics['lifecycleActorBefore'] = _administrator_collector_epoch(
                workload_group)
        if (not startup_measurement and workload_group in (None, 'cancellation')
                and lifecycle_scenario == 'cancellation'):
            try:
                cancellation = begin_cancellation(workload, handoff, result)
                diagnostics['cancellation'] = cancellation
            except (OSError, ValueError, KeyError, TypeError, AttributeError,
                    subprocess.SubprocessError) as error:
                diagnostics['cancellation'] = {'status': 'unavailable-or-unsafe',
                                               'exceptionType': type(error).__name__[:128]}
        if (not startup_measurement and workload_group in (None, 'controller-restart')
                and lifecycle_scenario == 'controller-restart'):
            try:
                active = begin_controller_restart(workload, handoff, result)
                controller_restart = trigger_controller_restart(workload, active)
                diagnostics['controllerRestart'] = controller_restart
            except (OSError, ValueError, KeyError, TypeError, AttributeError,
                    subprocess.SubprocessError) as error:
                diagnostics['controllerRestart'] = {'status': 'unavailable-or-unsafe',
                                                    'exceptionType': type(error).__name__[:128]}
        if not startup_measurement and workload_group == 'deadline':
            try:
                diagnostics['deadline'] = complete_deadline(
                    workload, begin_deadline(workload, handoff, result))
            except (OSError, ValueError, KeyError, TypeError, AttributeError,
                    subprocess.SubprocessError) as error:
                diagnostics['deadline'] = {'status': 'unavailable-or-unsafe',
                                           'exceptionType': type(error).__name__[:128]}
        if not startup_measurement and workload_group == 'revocation-running':
            try:
                revocation = begin_revocation_running(workload, handoff, result, observer)
                diagnostics['revocationRunning'] = revocation
            except (OSError, ValueError, KeyError, TypeError, AttributeError,
                    subprocess.SubprocessError) as error:
                diagnostics['revocationRunning'] = {'status': 'unavailable-or-unsafe',
                                                    'exceptionType': type(error).__name__[:128]}
        if not startup_measurement and workload_group == 'setsid-double-fork':
            try:
                diagnostics['setsidDoubleFork'] = {'status': 'captured',
                    'record': probe_setsid_double_fork(workload, handoff,
                        role_probe_digest, campaign_deadline)}
            except (OSError, ValueError, KeyError, TypeError, AttributeError,
                    subprocess.SubprocessError) as error:
                diagnostics['setsidDoubleFork'] = {'status': 'unavailable-or-unsafe',
                                                    'exceptionType': type(error).__name__[:128]}
        if not startup_measurement and workload_group == 'observer-death':
            try:
                diagnostics['observerDeath'] = probe_observer_death(
                    workload, handoff, result, observer)
            except (OSError, ValueError, KeyError, TypeError, AttributeError,
                    subprocess.SubprocessError) as error:
                diagnostics['observerDeath'] = {'status': 'unavailable-or-unsafe',
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
                diagnostics['controllerBootstrapFailure'] = (
                    controller_bootstrap_failure_snapshot(workload))
                cleanup(workload)
                diagnostics['cleanup'] = 'completed'
                diagnostics['cleanupFinishedNs'] = time.monotonic_ns()
                if not startup_measurement and workload_group in (None, 'positive'):
                    diagnostics['positiveAdministratorAfter'] = (
                        _administrator_collector_epoch('positive'))
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
                if revocation is not None:
                    try:
                        diagnostics['revocationRunning'] = complete_revocation_running(
                            workload, revocation)
                    except (OSError, ValueError, KeyError, TypeError, AttributeError,
                            subprocess.SubprocessError) as error:
                        diagnostics['revocationRunning'] = {
                            'status': 'unavailable-or-unsafe',
                            'exceptionType': type(error).__name__[:128]}
                if workload_group in ('lost-start-response', 'cancellation',
                                      'controller-restart', 'deadline',
                                      'revocation-running', 'setsid-double-fork',
                                      'observer-death'):
                    try:
                        diagnostics['lifecycleActorAfter'] = _administrator_collector_epoch(
                            workload_group)
                    except (OSError, ValueError, KeyError, TypeError):
                        diagnostics['lifecycleActorAfter'] = {'status': 'unavailable-or-unsafe'}
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
    if retired_authority_preparation:
        if (diagnostics['cleanup'] != 'completed'
                or result.get('groupPreparation') != 'role-readiness-diagnostic'
                or not isinstance(result.get('roleKernelRoster'), dict)):
            raise ValueError('workload-retired-authority-preparation-incomplete')
        sender = next(row for row in result['roleKernelRoster']['roles']
                      if row['role'] == 'candidate-sender')
        campaign, actual_role, authority = workload.retained(
            handoff['handles']['candidate-sender'])
        if (actual_role != 'candidate-sender'
                or authority['managerInvocation'] != sender['invocationId']
                or authority['bootId'] != campaign['bootId']):
            raise ValueError('workload-retired-authority-record-changed')
        receipts = {}
        for row in result['roleKernelRoster']['roles']:
            entry = volatile['stopReceipts'][row['role']]['current']
            if (entry['status'] != 'captured'
                    or entry['record']['managerInvocation'] != row['invocationId']
                    or entry['record']['membership'] != 'only-stop-helper'
                    or entry['record']['descendantCgroups'] != 0):
                raise ValueError('workload-retired-authority-stop-incomplete')
            receipts[row['role']] = hashlib.sha256(json.dumps(entry['record'],
                sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        workload.write(RETIRED_AUTHORITY, {'schemaVersion': 1,
            'kind': 'pr315-retired-authority-input',
            'sourceCommit': identity['sourceCommit'],
            'campaignGeneration': campaign['generation'],
            'bootId': campaign['bootId'],
            'senderHandle': handoff['handles']['candidate-sender'],
            'senderUid': sender['uid'],
            'senderInvocation': sender['invocationId'],
            'senderProcessEpoch': sender['processEpoch'],
            'stopReceiptDigests': receipts}, create=True)
    workload.write(REPORT, result, create=True)
    return {'status': ('startup-measurement-executed' if startup_measurement else
                       'role-readiness-measurement-executed'
                       if workload_group == 'role-readiness-diagnostic' else
                       'group-sequence-executed' if workload_group not in (None, 'positive') else
                       'positive-sequence-executed'),
            'workloadAcceptance': ('not-executed' if workload_group == 'role-readiness-diagnostic'
                                   else 'incomplete'),
            'protectedExecutionEnabled': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--lifecycle-scenario', choices=LIFECYCLE_SCENARIOS,
                        default='cancellation')
    parser.add_argument('--workload-group', choices=('positive', 'lost-start-response',
                                                    'partial-launch', 'stuck-output', 'late-child',
                                                    'cleanup-race',
                                                    'resource-exhaustion',
                                                    'output-symlink', 'output-fifo',
                                                    'output-hardlink', 'output-flood',
                                                    'output-replacement',
                                                    'role-readiness-diagnostic',
                                                    'role-boundary', 'authority',
                                                    'network-app', 'cancellation',
                                                    'controller-restart', 'deadline',
                                                    'revocation-running',
                                                    'setsid-double-fork',
                                                    'observer-death'))
    parser.add_argument('--retired-authority-preparation', action='store_true')
    args = parser.parse_args()
    reasons = prerequisites()
    if reasons:
        print(json.dumps({'status': 'not-executed', 'reasons': reasons, 'protectedExecutionEnabled': False}))
        return 78
    if not args.execute:
        print(json.dumps({'status': 'prerequisites-present-not-executed', 'protectedExecutionEnabled': False}))
        return 0
    print(json.dumps(execute(lifecycle_scenario=args.lifecycle_scenario,
                             workload_group=args.workload_group,
                             retired_authority_preparation=
                                 args.retired_authority_preparation), sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        result = main()
    except Exception:
        print('{"status":"failed-private-reconciliation-required","protectedExecutionEnabled":false}')
        result = 1
    raise SystemExit(result)

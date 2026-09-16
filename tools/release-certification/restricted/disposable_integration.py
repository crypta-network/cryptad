#!/usr/bin/python3
"""Destructive test provisioning ONLY in an explicitly disposable Debian 13 systemd VM.

Default --probe is read-only. Exit 78 means the mandatory VM lane was not executed. This harness
never installs on a container, developer host, existing worker, or already provisioned VM.
External provider/selection transport seams remain synthetic; maintenance CMS and native tools
are real. A successful local dimension is neither production authority nor Phase 12 completion.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import datetime as dt
import grp
import hashlib
import secrets
import signal
import socket
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import time

ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': '/root'}
INSTALLED = Path('/opt/cryptad-cross-version/current')
STATE = Path('/var/lib/cryptad-restricted')
TEST_KIT = Path('/opt/cryptad-restricted-test-kit')


class BoundedPrivateLog:
    """A test-owner diagnostic stream; private bytes never become a socket/public result."""
    def __init__(self, stream, maximum=65536):
        self.stream = stream
        self.remaining = maximum

    def write(self, value):
        raw = value.encode('utf-8', errors='replace')[:self.remaining]
        self.stream.write(raw)
        self.remaining -= len(raw)
        return len(value)

    def flush(self):
        self.stream.flush()


def call(arguments, *, expected=0, environment=None, timeout=120):
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True,
                            env=environment or ENV, timeout=timeout)
    if result.returncode != expected:
        raise ValueError('disposable-command-failed')
    return result.stdout


def source_commit(value):
    """Validate a test-only source selection; product authentication still verifies package bytes."""
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{40}', value) is None:
        raise argparse.ArgumentTypeError('expected an exact 40-character source commit')
    return value


def failure_code(failure):
    """Keep fixed local error identifiers and discard exception paths or input excerpts."""
    value = str(failure)
    return value if re.fullmatch('restricted-[a-z-]{1,120}', value) else 'restricted-disposable-stage-failed'


def test_source_identities(source, product_commit=None):
    """Keep installed helper provenance distinct from the selected packaged product provenance."""
    helper = source_commit(call(['/usr/bin/git', '-C', str(source), 'rev-parse', '--verify',
                                 'HEAD^{commit}']).decode().strip())
    return {'helperSourceCommit': helper,
            'productSourceCommit': helper if product_commit is None else source_commit(product_commit)}


def prerequisites(source):
    reasons = []
    if 'VERSION_ID="13"' not in Path('/etc/os-release').read_text():
        reasons.append('debian-13-required')
    if Path('/proc/1/comm').read_text().strip() != 'systemd':
        reasons.append('systemd-pid1-required')
    virtualization = subprocess.run(['/usr/bin/systemd-detect-virt', '--vm'], capture_output=True,
                                    env=ENV, timeout=10)
    if virtualization.returncode != 0:
        reasons.append('dedicated-disposable-vm-required')
    for name in ('python3.13', 'openssl', 'bwrap', 'setpriv', 'gh', 'git', 'sudo', 'javac'):
        if shutil.which(name) is None:
            reasons.append(name + '-required')
    for name in ('build/cryptad-dist/lib/cryptad.jar',
                 'platform-devtools/build/install/crypta-app/bin/crypta-app'):
        if not (source / name).is_file():
            reasons.append('native-distribution-build-required')
    if shutil.which('javac'):
        version = subprocess.run(['javac', '-version'], capture_output=True, timeout=10)
        if not (version.stdout + version.stderr).startswith(b'javac 25'):
            reasons.append('jdk-25-reference-required')
    return sorted(set(reasons))


def load_installation(source):
    path = source / 'tools/release-certification/restricted/installation.py'
    spec = importlib.util.spec_from_file_location('installation', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules['installation'] = module
    spec.loader.exec_module(module)
    return module


def install_test_kit(source):
    """Materialize only committed test seams outside the immutable production installation."""
    import installation
    if TEST_KIT.exists() or TEST_KIT.is_symlink():
        raise ValueError('disposable-test-kit-must-be-new')
    environment = {**ENV, 'GIT_NO_REPLACE_OBJECTS': '1'}
    prefix = ['/usr/bin/git', '-C', str(source)]
    if call([*prefix, 'status', '--porcelain', '--untracked-files=normal'], environment=environment):
        raise ValueError('disposable-test-kit-clean-source-required')
    revision = call([*prefix, 'rev-parse', '--verify', 'HEAD^{commit}'], environment=environment).decode().strip()
    manifest = installation.read_json(INSTALLED / installation.MANIFEST)
    if revision != manifest['sourceCommit']:
        raise ValueError('disposable-test-kit-source-mismatch')
    entries = call([*prefix, 'ls-tree', '-r', '-z', '-l', '--full-tree', revision],
                   environment=environment).split(b'\0')
    TEST_KIT.mkdir(mode=0o755)
    records = {}
    for entry in entries:
        if not entry:
            continue
        metadata, name = entry.split(b'\t', 1)
        mode, kind, oid, size = metadata.split()
        relative = Path(os.fsdecode(name))
        if installation.production_member(relative):
            continue
        if (mode not in {b'100644', b'100755'} or kind != b'blob' or not size.isdigit()
                or int(size) > installation.MAX_FILE or relative.is_absolute() or '..' in relative.parts):
            raise ValueError('disposable-test-kit-entry-invalid')
        raw = call([*prefix, 'cat-file', 'blob', oid.decode('ascii')], environment=environment)
        checksum = hashlib.new('sha1' if len(oid) == 40 else 'sha256')
        checksum.update(b'blob ' + str(len(raw)).encode() + b'\0' + raw)
        if len(raw) != int(size) or checksum.hexdigest().encode() != oid:
            raise ValueError('disposable-test-kit-blob-mismatch')
        target = TEST_KIT / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        target.chmod(0o555 if mode == b'100755' else 0o444)
        records[relative.as_posix()] = hashlib.sha256(raw).hexdigest()
    # Fixture ROOT calculations stay within this test-only tree. These fixed references expose
    # immutable installed products/source resources, never test code in the production tree.
    for name in ('build', 'platform-devtools', 'platform-api', 'platform-appcatalog'):
        (TEST_KIT / name).symlink_to(INSTALLED / name, target_is_directory=True)
    identity = TEST_KIT / '.test-kit.json'
    identity.write_text(json.dumps({'schemaVersion': 1, 'kind': 'synthetic-disposable-test-kit',
        'sourceCommit': revision, 'productionEligible': False, 'files': records}, sort_keys=True))
    identity.chmod(0o444)
    for directory, _names, _files in os.walk(TEST_KIT, followlinks=False):
        Path(directory).chmod(0o755)


def provision(source, stage, event=None):
    import installation
    event = event or (lambda _stage, _status: None)
    bundle = stage / 'bundle'
    event('installation-export', 'running')
    installation.plan(source, bundle)
    # Test native dependencies are explicitly included BEFORE approval and immutable installation.
    # No evaluated job may augment an installed helper this way.
    for relative in ('build/cryptad-dist', 'platform-devtools/build/install/crypta-app', 'platform-api/build/libs'):
        destination = bundle / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source / relative, destination, symlinks=False)
    manifest = installation.read_json(bundle / installation.MANIFEST)
    manifest['files'] = installation.inventory(bundle)
    (bundle / installation.MANIFEST).write_bytes(installation.encode(manifest))
    identity = installation.digest(installation.encode(manifest))
    event('installation-export', 'complete')
    event('dependency-profile-measurement', 'running')
    approval = installation.host_plan(identity)
    installation.APPROVAL.parent.mkdir(mode=0o700, parents=True, exist_ok=False)
    installation.APPROVAL.write_bytes(installation.encode(approval))
    installation.APPROVAL.chmod(0o600)
    event('dependency-profile-measurement', 'complete')
    event('installation-publication', 'running')
    installation.install(bundle)
    event('installation-publication', 'complete')
    event('installed-profile-verification', 'running')
    installation.verify()
    event('installed-profile-verification', 'complete')
    event('production-test-kit-separation', 'running')
    install_test_kit(source)
    event('production-test-kit-separation', 'complete')
    as_role('cryptad-soak', """import json,pathlib,sys
record = pathlib.Path(sys.argv[1])
assert json.loads(record.read_bytes())['schemaVersion'] == 1
for path, mode in ((record, 'wb'), (pathlib.Path(sys.argv[2]), 'rb')):
    try:
        path.open(mode)
    except PermissionError:
        pass
    else:
        raise AssertionError('observer access boundary failed')
""", arguments=(str(installation.EXECUTION), str(installation.APPROVAL)))
    event('socket-listening', 'running')
    call(['/usr/bin/systemctl', 'start', 'cryptad-restricted.socket'])
    event('socket-listening', 'complete')
    return identity


def as_role(name, script, *, arguments=(), timeout=120, expected=0):
    user = pwd.getpwnam(name)
    # The root bootstrap is outside the principal under test. The process below is the actual
    # role UID/GID, with the provisioned group list and no capability or sudo inheritance.
    command = ['/usr/bin/setpriv', '--reuid=' + str(user.pw_uid), '--regid=' + str(user.pw_gid),
               '--init-groups', '--no-new-privs', '--bounding-set=-all', '--inh-caps=-all',
               '--ambient-caps=-all', '--', '/usr/bin/python3', '-I', '-S', '-c', script, *arguments]
    return call(command, expected=expected, timeout=timeout)


def denial_probes():
    private = STATE / 'resolver/test-key'
    private.write_bytes(b'SYNTHETIC-PRIVATE-KEY-CANARY')
    private.chmod(0o600)
    source = INSTALLED / 'tools/release-certification/protected/restricted_native.py'
    script = r'''
import os, pathlib, subprocess, sys
key, code = map(pathlib.Path, sys.argv[1:])
assert os.geteuid() != 0
for path, mode in ((key, 'rb'), (code, 'ab')):
    try:
        with path.open(mode): pass
    except PermissionError: pass
    else: raise SystemExit(71)
status = pathlib.Path('/proc/self/status').read_text()
for field in ('CapEff', 'CapPrm', 'CapAmb', 'CapInh', 'CapBnd'):
    assert int(next(line.split(':')[1].strip() for line in status.splitlines() if line.startswith(field + ':')), 16) == 0
assert subprocess.run(['/usr/bin/sudo','-n','/usr/bin/true'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0
for path in ('/var/run/docker.sock','/run/containerd/containerd.sock','/var/lib/cryptad-restricted/operations'):
    assert not os.access(path, os.R_OK | os.W_OK)
'''
    for name in ('cryptad-runner', 'cryptad-native', 'cryptad-workload', 'cryptad-soak'):
        as_role(name, script, arguments=(str(private), str(source)))
    # Real peer identity and installed socket activation; a caller cannot invent an operation.
    client = str(INSTALLED / 'tools/release-certification/protected/restricted_client.py')
    socket_script = r'''
import subprocess, sys
p = subprocess.run(['/usr/bin/python3','-I','-S',sys.argv[1],'collect','0'*64], capture_output=True, timeout=900)
assert p.returncode == 2
assert p.stdout == b''
assert p.stderr == b'restricted-operation-unavailable\n'
'''
    as_role('cryptad-runner', socket_script, arguments=(client,), timeout=950)
    return ['actual-role-dac-denials', 'actual-role-capability-denials', 'actual-socket-unknown-handle-denied']


def bootstrap_readiness():
    """Wait for the installed main process's manager-authenticated notification."""
    call(['/usr/bin/systemctl', 'start', 'cryptad-restricted.service'], timeout=190)
    raw = call(['/usr/bin/systemctl', 'show', 'cryptad-restricted.service',
                '--property=Type,NotifyAccess,ActiveState,SubState,MainPID'], timeout=15)
    properties = dict(line.split('=', 1) for line in raw.decode('ascii').splitlines())
    if (properties.get('Type') != 'notify' or properties.get('NotifyAccess') != 'main'
            or properties.get('ActiveState') != 'active' or properties.get('SubState') != 'running'
            or not properties.get('MainPID', '').isdigit() or int(properties['MainPID']) <= 1):
        raise ValueError('disposable-installed-bootstrap-not-ready')
    return ['installed-production-bootstrap-notify-ready']


def wrong_socket_uid():
    """The actual excluded native UID must fail admission at the socket filesystem boundary."""
    as_role('cryptad-native', r'''
import socket
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.settimeout(5)
    try:
        client.connect('/run/cryptad-restricted/control.sock')
    except PermissionError:
        pass
    else:
        raise AssertionError('excluded native UID reached control socket')
''', timeout=10)
    return ['actual-socket-wrong-uid-denied']


def controller_unit_probe(entrypoint):
    """Run one fixed test entrypoint with the actual controller's capability/filesystem settings."""
    if entrypoint not in {'baseline_workspace_probe.py', 'native_cleanup_probe.py'}:
        raise ValueError('disposable-controller-probe-not-fixed')
    import installation
    unit = 'cryptad-restricted.service'
    override = Path('/run/systemd/system/cryptad-restricted.service.d')
    call(['/usr/bin/systemctl', 'stop', 'cryptad-restricted.socket', unit, 'cryptad-cross-version-soak.service'])
    # This also exercises upgrade's shutdown precondition against real systemctl property output.
    installation.require_stopped_units(ENV)
    override.mkdir(mode=0o755, parents=True, exist_ok=False)
    selected = override / 'workspace-test.conf'
    try:
        selected.write_text('[Service]\nType=oneshot\nExecStart=\n'
            'ExecStart=/usr/bin/python3 -I -S /opt/cryptad-restricted-test-kit/'
            'tools/release-certification/restricted/' + entrypoint + '\n')
        call(['/usr/bin/systemctl', 'daemon-reload'])
        call(['/usr/bin/systemctl', 'start', unit])
        observed = call(['/usr/bin/systemctl', 'show', unit,
                         '--property=Result,ExecMainStatus', '--no-pager'])
        fields = dict(line.split('=', 1) for line in observed.decode().splitlines() if '=' in line)
        if fields != {'Result': 'success', 'ExecMainStatus': '0'}:
            raise ValueError('controller-unit-probe-failed')
    finally:
        call(['/usr/bin/systemctl', 'stop', unit, 'cryptad-restricted.socket'])
        selected.unlink(missing_ok=True)
        override.rmdir()
        call(['/usr/bin/systemctl', 'daemon-reload'])
        call(['/usr/bin/systemctl', 'start', 'cryptad-restricted.socket'])


def baseline_workspace_unit_probe():
    controller_unit_probe('baseline_workspace_probe.py')
    return ['baseline-owner-workspaces-under-controller-unit', 'real-unit-upgrade-shutdown-precondition']


def native_cleanup_unit_probe():
    controller_unit_probe('native_cleanup_probe.py')
    return ['native-timeout-owned-group-reaped', 'native-output-limit-owned-group-reaped',
            'native-failure-controller-cgroup-quiescent']


def hostile_native():
    sys.path.insert(0, str(INSTALLED / 'tools/release-certification/protected'))
    import app_subject_projection as projection
    import restricted_native as native
    private = STATE / 'resolver'
    with tempfile.TemporaryDirectory(prefix='hostile-', dir=private) as temporary:
        root = Path(temporary)
        work, tools, jdk = (root / name for name in ('work', 'tools', 'jdk'))
        for path in (work, tools, jdk):
            path.mkdir(mode=0o700)
        executable = tools / 'native'
        executable.write_text('#!/bin/sh\n'
            'test "$(id -u)" != 0 || exit 81\n'
            'test ! -e /etc/cryptad-certification || exit 82\n'
            'test ! -e /var/lib/cryptad-restricted/resolver || exit 83\n'
            'test ! -e /run/cryptad-restricted/control.sock || exit 84\n'
            'test -z "$GH_TOKEN$GITHUB_TOKEN$LD_PRELOAD$PYTHONPATH" || exit 85\n'
            'test "$(ls /proc/self/fd | wc -l)" -le 5 || exit 86\n'
            'printf \'{"untrusted":"SYNTHETIC-CHILD-CANARY"}\' > /work/projection.json\n'
            'printf SYNTHETIC-STDOUT-CANARY\n')
        executable.chmod(0o700)
        with native.owning_boundary():
            raw = projection._run_maintenance_native([str(executable), 'subject-projection',
                '--output', str(work / 'projection.json')], work, executable, tools, jdk)
        assert raw == b'SYNTHETIC-STDOUT-CANARY'
        # These are private untrusted bytes. The collector is never given this file or stdout.
        assert (work / 'projection.json').read_bytes() == b'{"untrusted":"SYNTHETIC-CHILD-CANARY"}'
    return ['actual-keyless-host-uid-native-dispatch']


def preparation_provider(context, timestamp, upstream):
    """Synthetic upstream transport shared by the VM fixture and its offline contract test."""
    import restricted_worker as worker
    def provider(arguments, environment, **options):
        prefix = 'repos/crypta-network/cryptad/actions/'
        if arguments == ['api', prefix + 'runs/310']:
            return {'run_attempt': 1}
        if arguments == ['api', prefix + 'runs/310/attempts/1']:
            return {'id': 310, 'run_attempt': 1,
                'path': worker.POLICIES['maintenance-prepare'][0], 'head_sha': context['sourceCommit'],
                'event': 'workflow_dispatch', 'repository': {'full_name': 'crypta-network/cryptad'},
                'actor': {'login': 'leumor'}, 'triggering_actor': {'login': 'leumor'}}
        if arguments == ['api', prefix + 'jobs/31001']:
            return {'id': 31001, 'run_id': 310, 'run_attempt': 1,
                'name': worker.JOB_NAMES['maintenance-prepare'], 'head_sha': context['sourceCommit'],
                'status': 'in_progress', 'started_at': timestamp.isoformat()}
        return upstream(arguments, environment, **options)
    return provider


class PreparationChild:
    """Own only the direct synthetic controller child, with bounded reap and escalation."""

    def __init__(self):
        self.pid = None

    def start(self, entrypoint):
        if self.pid is not None:
            raise ValueError('disposable-child-already-owned')
        pid = os.fork()
        if pid == 0:
            try:
                entrypoint()
            except BaseException:
                os._exit(2)
            os._exit(0)
        self.pid = pid

    def stop(self):
        if self.pid is None:
            return
        # An unreaped child retains its PID. Clear ownership as soon as waitpid reaps it;
        # never signal a saved PID after a successful wait or failed replacement fork.
        for signum in (signal.SIGTERM, signal.SIGKILL):
            try:
                waited, _status = os.waitpid(self.pid, os.WNOHANG)
            except ChildProcessError:
                self.pid = None
                raise ValueError('disposable-child-ownership-lost') from None
            if waited == self.pid:
                self.pid = None
                return
            try:
                os.kill(self.pid, signum)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                waited, _status = os.waitpid(self.pid, os.WNOHANG)
                if waited == self.pid:
                    self.pid = None
                    return
                time.sleep(0.05)
        raise ValueError('disposable-child-reconciliation-required')


@contextmanager
def preparation_socket():
    """Restore socket activation after setup failure; retain it stopped if reap fails."""
    call(['/usr/bin/systemctl', 'stop', 'cryptad-restricted.service', 'cryptad-restricted.socket'])
    endpoint = Path('/run/cryptad-restricted/control.sock')
    listener = None
    bound = False
    child = PreparationChild()
    try:
        if endpoint.exists():
            raise ValueError('disposable-existing-socket')
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(endpoint))
        bound = True
        os.chown(endpoint, 0, grp.getgrnam('cryptad-control').gr_gid)
        endpoint.chmod(0o660)
        listener.listen(16)
        yield listener, child
    finally:
        try:
            child.stop()
        finally:
            if listener is not None:
                listener.close()
        # Do not replace a socket while its controller might remain live. Keep unknown
        # endpoints intact; only this context's successful bind owns unlink permission.
        if child.pid is None:
            if bound:
                endpoint.unlink(missing_ok=True)
            call(['/usr/bin/systemctl', 'start', 'cryptad-restricted.socket'])


def activate_test_listener(listener):
    """Match the installed socket activation FD contract in the synthetic controller child."""
    descriptor = listener.detach()
    if descriptor != 3:
        os.dup2(descriptor, 3, inheritable=False)
        os.close(descriptor)
    # A listener already on descriptor 3 may have been made inheritable by its caller.
    os.set_inheritable(3, False)
    for name in os.listdir('/proc/self/fd'):
        if int(name) > 3:
            try:
                os.close(int(name))
            except OSError:
                pass
    os.environ['LISTEN_PID'] = str(os.getpid())
    os.environ['LISTEN_FDS'] = '1'


def socket_preparation(real_seal, real_read, freeze, package, runtime_root, *, projection_origin, private_root, observe=None, bind_context=None):
    """Run real preparation through the installed Worker with synthetic original provider I/O.

    Only this root-owned test harness substitutes upstream transport. Production bootstrap has
    no flag, hook or import permitting these substitutions. Local peer/DAC/state/crypto/native
    admission and original job comparison are their real implementations.
    """
    import installation
    import maintenance_runtime_companion as companion
    import maintenance_runtime_metadata as metadata
    import original_artifact_authentication as original
    import restricted_worker as worker
    handle = secrets.token_hex(32)
    root = worker.OPERATIONS / handle
    root.mkdir(mode=0o700)
    inputs = root / 'inputs'
    inputs.mkdir(mode=0o700)
    for name, raw in (('freeze.json', metadata.canonical_bytes(freeze)),
                      ('projection-origin.json', metadata.canonical_bytes(projection_origin)),
                      ('package.tar.gz', package.read_bytes())):
        (inputs / name).write_bytes(raw)
        (inputs / name).chmod(0o400)
    timestamp = dt.datetime.now(dt.timezone.utc)
    identity = installation.configuration()['bundleIdentity']
    context = {'sourceCommit': installation.read_json(INSTALLED / installation.MANIFEST)['sourceCommit'],
               'runId': 310, 'runAttempt': 1, 'jobId': 31001}
    record = {'schemaVersion': 1, 'method': 'maintenance-prepare', 'handle': handle,
        'bundleIdentity': identity, 'callerUid': pwd.getpwnam('cryptad-runner').pw_uid,
        'context': context, 'notBefore': (timestamp - dt.timedelta(minutes=1)).isoformat(),
        'expiresAt': (timestamp + dt.timedelta(hours=1)).isoformat(),
        'collectUntil': (timestamp + dt.timedelta(days=1)).isoformat(),
        'configurationFiles': {},
        'inputFiles': {p.name: {'digest': worker.digest(p.read_bytes()), 'size': p.stat().st_size}
                       for p in inputs.iterdir()}}
    worker.validate_record(record)
    worker.persist(root / 'registration.json', record)
    if not (STATE / 'revocations.json').exists():
        worker.persist(STATE / 'revocations.json', [])
    worker.CREDENTIAL.write_bytes(worker.encode({'token': 'SYNTHETIC-PROVIDER-CANARY',
        'expiresAt': (timestamp + dt.timedelta(minutes=30)).isoformat()}))
    worker.CREDENTIAL.chmod(0o600)
    provider = preparation_provider(context, timestamp, original._gh)
    read_counter = root / 'test-read-count.private'
    read_counter.write_text('0')
    def counted_read(*args, **kwargs):
        read_counter.write_text(str(int(read_counter.read_text()) + 1))
        return real_read(*args, **kwargs)
    def serve(listener):
        metadata.seal_private_freeze = real_seal
        companion._read = counted_read  # Count real reads, preserving the installed owner.
        original._gh = provider
        try:
            activate_test_listener(listener)
            worker.main(bundle_identity=identity)
        except Exception as failure:
            # Fixed classifications only; retain no exception text, credential or fixture bytes.
            category = ('socket-activation-rejected' if isinstance(failure, worker.BoundaryError)
                        and str(failure) == 'restricted-socket-activation-required' else 'controller-failed')
            diagnostic = root / 'controller-failure.private.json'
            try:
                descriptor = os.open(diagnostic, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(descriptor, 'w') as stream:
                    json.dump({'phase': 'synthetic-worker-main', 'category': category}, stream, sort_keys=True)
            except OSError:
                pass
            raise
    client = str(INSTALLED / 'tools/release-certification/protected/restricted_client.py')
    script = "import subprocess,sys; p=subprocess.run(['/usr/bin/python3','-I','-S',sys.argv[1],sys.argv[2],sys.argv[3]],capture_output=True,timeout=900); assert p.returncode==0; assert not p.stderr; sys.stdout.buffer.write(p.stdout)"
    native_window = None
    if observe is not None or bind_context is not None:
        from pr313_observations import InvocationWindow
        native_window = InvocationWindow()
    with preparation_socket() as (listener, child):
        child.start(lambda: serve(listener))
        public = as_role('cryptad-runner', script, arguments=(client, 'maintenance-prepare', handle), timeout=950)
        binding = None
        if native_window is not None:
            binding = native_window.finish('package-api', owner_operation=handle)
            if bind_context is not None:
                bind_context(binding)
        ciphertext = {p.name: p.read_bytes() for p in (root / 'runtime').iterdir()}
        retained = (root / 'result.json').read_bytes()
        import restricted_native as native
        native_before = set(native.ROOT.iterdir())
        reads_before = int(read_counter.read_text())
        child.stop()
        child.start(lambda: serve(listener))
        retried = as_role('cryptad-runner', script, arguments=(client, 'maintenance-prepare', handle), timeout=950)
        assert retried == public
        child.stop()
        child.start(lambda: serve(listener))
        collected = as_role('cryptad-runner', script, arguments=(client, 'collect', handle), timeout=950)
        assert collected == public
        assert retained == (root / 'result.json').read_bytes()
        assert ciphertext == {p.name: p.read_bytes() for p in (root / 'runtime').iterdir()}
        assert set(json.loads(public)) == {'schemaVersion', 'kind', 'operation', 'status', 'freezeDigest', 'descriptor', 'ciphertext'}
        assert b'SYNTHETIC-PROVIDER-CANARY' not in public
        assert native_before == set(native.ROOT.iterdir())
        assert reads_before == int(read_counter.read_text())
        if observe is not None:
            from pr313_observations import quiescent
            observe({'caseId': 'retained-exact-retry', 'phase': 'completed-retry', 'outcome': 'exact-retry',
                'managerInvocationId': binding['managerInvocationId'],
                'quiescent': quiescent(), 'attackWitness': {
                    'retainedDigest': hashlib.sha256(public).hexdigest(),
                    'responseDigest': hashlib.sha256(retried).hexdigest(),
                    'nativeLaunchCountBefore': len(native_before), 'nativeLaunchCountAfter': len(native_before),
                    'decryptCountBefore': reads_before, 'decryptCountAfter': int(read_counter.read_text()),
                    'durablePhase': 'completed-retry'}})
        # Transfer only exact retained ciphertext to the rest of the native consumer fixture.
        # The fixture's later owning consumer reauthenticates/decrypts it; JSON is not authority.
        shutil.copytree(root / 'runtime', runtime_root)
        return json.loads((root / 'freeze.json').read_bytes())


def native_package_api(jdk, identity, source, *, root=Path('/root/pr312-package-api')):
    """Observe the exact installed product before unrelated signed-fixture preparation.

    This synthetic archive/test owner creates no original release authority or frozen receipt.
    The installed native adapter, package verifier and schemas execute unchanged.
    """
    import gzip
    import io
    import tarfile
    import restricted_native as native
    import maintenance_runtime_metadata as metadata
    from pr312_native_faults import _fixture_jdk
    selected = Path(source).resolve(strict=True) / 'build/cryptad-dist/lib/cryptad.jar'
    product_digest = hashlib.sha256(metadata._regular(selected, 256 * 1024 * 1024)).hexdigest()
    product = INSTALLED.resolve(strict=True) / 'build/cryptad-dist/lib/cryptad.jar'
    raw = metadata._regular(product, 256 * 1024 * 1024)
    if hashlib.sha256(raw).hexdigest() != product_digest:
        raise ValueError('disposable-package-product-substituted')
    root.mkdir(mode=0o700, exist_ok=False)
    java = _fixture_jdk(jdk, root)
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode='w') as archive:
        member = tarfile.TarInfo('lib/cryptad.jar')
        member.mode, member.size = 0o644, len(raw)
        member.uname = member.gname = 'root'
        archive.addfile(member, io.BytesIO(raw))
    package = root / 'synthetic-selected-product.tar.gz'
    package.write_bytes(gzip.compress(archive_bytes.getvalue(), mtime=0))
    context = {'operationId': secrets.token_hex(32),
        'registrationDigest': 'sha256:' + hashlib.sha256(b'pr312-package-test-owner').hexdigest(),
        'bundleIdentity': identity, 'deadlineMonotonic': time.monotonic() + 900}
    with native.owning_boundary(context=context):
        snapshot, registry, executable = metadata.observe_package(package, java, root)
    metadata.verify_package_identity(package, {
        'portable': metadata.identity(package, 1024 * 1024 * 1024), 'executable': executable})
    if (executable['digest'] != 'sha256:' + product_digest
            or metadata.validate_schema(metadata.read_json(snapshot),
                'platform-api-contract-snapshot-envelope-v1.schema.json')
            or metadata.validate_schema(metadata.read_json(registry),
                'platform-api-1.x-baseline-registry-v1.schema.json')):
        raise ValueError('disposable-package-owner-validation-failed')
    (root / 'snapshot.json').write_bytes(snapshot)
    (root / 'registry.json').write_bytes(registry)
    (root / 'observation.json').write_text(json.dumps({
        'kind': 'synthetic-installed-package-owner-observation', 'productionEligible': False,
        'operationId': context['operationId'], 'productDigest': product_digest,
        'packageDigest': hashlib.sha256(package.read_bytes()).hexdigest(),
        'executable': executable}, sort_keys=True))
    return ['installed-real-package-api-export-owner-validated']


def installed_fixture_resources(fixture_module):
    """Use canonical installed resources; Python fixtures remain in the separate test kit."""
    resources = INSTALLED.resolve(strict=True)
    if not resources.is_dir() or any(path.is_symlink() for path in (resources, *resources.parents)):
        raise ValueError('disposable-installed-resource-root-invalid')
    fixture_module.ROOT = resources


def private_fixture_failure(stream, error):
    """Write setup diagnostics only to the disposable administrator's bounded private stream."""
    import traceback
    stream.write(''.join(traceback.format_exception(type(error), error, error.__traceback__)))
    if isinstance(error, subprocess.CalledProcessError):
        for name in ('stdout', 'stderr'):
            value = getattr(error, name, None)
            if isinstance(value, bytes):
                value = value[:65536].decode('utf-8', errors='replace')
            if isinstance(value, str):
                stream.write(name + ': ' + value[:65536] + '\n')
    stream.flush()


def cms_native_integration(source, product_source_commit, prepared_inputs=None, worker_case=None, observe=None):
    import unittest
    import restricted_native as native
    import maintenance_runtime_metadata as metadata
    import maintenance_runtime_companion as companion
    from unittest.mock import patch
    sys.path.insert(0, str(INSTALLED / 'tools/release-certification'))
    sys.path.append(str(TEST_KIT / 'tools/release-certification/protected'))
    import cryptad_certification
    cryptad_certification.__path__.append(str(TEST_KIT / 'tools/release-certification/cryptad_certification'))
    from cryptad_certification.tests import test_pr304_product_consumer_integration as legacy
    from cryptad_certification.tests import test_pr307_product_consumer_integration as integration
    # The exporter/JDK owner correctly rejects symlink ancestors. The test kit's convenience
    # links and installation's "current" selector must not become native resource identities.
    # This changes only the excluded fixture's data root, never its Python import authority.
    installed_fixture_resources(legacy)
    legacy.ProductConsumerIntegrationTest.prepared_inputs = prepared_inputs
    # The actual disposable root creates every synthetic key/policy. Remove inherited local
    # ownership test shims: real filesystem ownership checks run unchanged here.
    legacy.SelectedRootPolicy = Path
    integration.fixtures._SyntheticRootOwnedPath = Path
    os.environ['GIT_DIR'] = str(source / '.git')  # fixture package source identity only
    suite = unittest.defaultTestLoader.loadTestsFromModule(integration)
    for case in suite:
        for selected in case:
            selected.product_source_commit = source_commit(product_source_commit)
    windows, cms_binding = {}, {}
    if observe is not None:
        from pr313_observations import InvocationWindow, owner
        def begin(case):
            if case not in ('wrong-app', 'wrong-product') or case in windows:
                raise ValueError('disposable-owner-observation-interval-invalid')
            windows[case] = InvocationWindow()
            return windows[case].started
        def owned_observation(row):
            operation = row['attackWitness']['operation']
            if operation == 'maintenance-prepare':
                if not cms_binding:
                    raise ValueError('disposable-cms-native-context-unobserved')
                binding = cms_binding
            else:
                binding = windows.pop(row['caseId']).finish(operation,
                    owner_operation=native_context['operationId'])
            # Closing the exact invocation window is part of observing this assertion.
            row = {**row, 'attackWitness': {**row['attackWitness'],
                'finishedMonotonicNs': time.monotonic_ns()}}
            observe(owner(row, binding))
        integration.EncryptedProductConsumerIntegrationTest.acceptance_begin = staticmethod(begin)
        integration.EncryptedProductConsumerIntegrationTest.acceptance_observer = staticmethod(owned_observation)
    real_seal, real_read = metadata.seal_private_freeze, companion._read
    def through_socket(*args, **kwargs):
        companion._read = real_read
        if worker_case is not None:
            from pr313_worker_faults import run
            observed = run(worker_case, real_seal, real_read, *args, **kwargs)
            Path('/root/pr313-observation.private.json').write_text(json.dumps(observed, sort_keys=True))
            raise ValueError('disposable-selected-worker-case-complete')
        return socket_preparation(real_seal, real_read, *args, **kwargs, observe=observe,
            bind_context=cms_binding.update if observe is not None else None)
    import installation
    # This root-owned disposable driver is a synthetic test owner, not the production controller.
    # Only original provider transport is substituted; the installed launch adapter is unchanged.
    native_context = {'operationId': secrets.token_hex(32),
        'registrationDigest': 'sha256:' + hashlib.sha256(b'pr312-synthetic-test-owner').hexdigest(),
        'bundleIdentity': installation.configuration()['bundleIdentity'],
        'deadlineMonotonic': time.monotonic() + 900}
    descriptor = os.open('/root/pr312-native-consumer.private.log',
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as private_log, native.owning_boundary(context=native_context), \
            patch.object(metadata, 'seal_private_freeze', side_effect=through_socket):
        bounded_log = BoundedPrivateLog(private_log)
        import bounded_process
        original_bounded_run = bounded_process.run
        from pr313_fixtures import PrivateCommandDiagnostics
        command_diagnostics = PrivateCommandDiagnostics(Path('/root/pr313-fixture-commands.private.json'))
        diagnostic_pid = os.getpid()
        def fixture_run(*arguments, **options):
            # This excluded synthetic owner observes direct fixture-tool failures only. The
            # real call retains its exact command, environment, deadline and output bounds.
            if os.getpid() != diagnostic_pid:
                return original_bounded_run(*arguments, **options)
            started = time.monotonic()
            captured = []
            supplied_sink = options.pop('diagnostic_sink', None)
            def capture(stdout, stderr):
                captured[:] = [stdout, stderr]
                if supplied_sink is not None:
                    supplied_sink(stdout, stderr)
            try:
                return original_bounded_run(*arguments, **options, diagnostic_sink=capture)
            except Exception:
                # Preserve command identity before unittest teardown removes the temporary JDK.
                command_diagnostics.failed(arguments[0], options, legacy.ProductConsumerIntegrationTest,
                    getattr(selected, '_stage', 'fixture-setup'), started, captured)
                if captured:
                    for label, raw in zip(('fixture-stdout', 'fixture-stderr'), captured):
                        bounded_log.write(label + ': ' + raw[:65536].decode('utf-8', errors='replace') + '\n')
                    bounded_log.flush()
                raise
        with patch.object(integration.EncryptedProductConsumerIntegrationTest,
                          'private_diagnostic_sink',
                          staticmethod(lambda error: private_fixture_failure(bounded_log, error)),
                          create=True), patch.object(bounded_process, 'run', side_effect=fixture_run):
            result = unittest.TextTestRunner(stream=bounded_log).run(suite)
    if worker_case is not None:
        observed = Path('/root/pr313-observation.private.json')
        if not observed.is_file() or json.loads(observed.read_bytes()).get('caseId') != worker_case:
            raise ValueError('disposable-worker-case-unobserved')
        return []
    if result.testsRun != 1 or not result.wasSuccessful() or result.skipped:
        raise ValueError('disposable-real-cms-native-consumer-failed')
    return ['real-maintenance-cms-signed-native-owning-consumer-with-synthetic-provider',
            'installed-worker-socket-preparation-and-restart-exact-retry-with-synthetic-provider']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument('--probe', action='store_true')
    parser.add_argument('--disposable-vm', action='store_true')
    lane = parser.add_mutually_exclusive_group()
    lane.add_argument('--bootstrap-only', action='store_true',
                      help='Observe production readiness and actual socket denials only.')
    lane.add_argument('--native-slice', action='store_true',
                      help='Observe the finite installed native/CMS slice; workload acceptance stays false.')
    parser.add_argument('--product-source-commit', type=source_commit,
                        help='Test-only exact packaged source revision; defaults to helper source HEAD.')
    from pr313_faults import CASES as NATIVE_CASES
    from pr313_worker_faults import CASES as WORKER_CASES
    from pr313_public_faults import CASES as PUBLIC_CASES
    CASES = NATIVE_CASES + WORKER_CASES + PUBLIC_CASES
    parser.add_argument('--case-group', choices=('positive', 'native-hostile', 'output-hostile', 'fault', 'worker', 'public'))
    parser.add_argument('--fault-case', choices=CASES)
    parser.add_argument('--prepared-fixtures', type=Path)
    parser.add_argument('--fixture-manifest-digest')
    args = parser.parse_args()
    if ((args.case_group in ('fault', 'worker', 'public')) != bool(args.fault_case)
            or (args.case_group == 'fault' and args.fault_case not in NATIVE_CASES)
            or (args.case_group == 'worker' and args.fault_case not in WORKER_CASES)
            or (args.case_group == 'public' and args.fault_case not in PUBLIC_CASES)
            or (args.case_group is not None and not args.native_slice)
            or (args.prepared_fixtures is None) != (args.fixture_manifest_digest is None)):
        parser.error('invalid fixed case or fixture selection')
    source = args.source.resolve()
    missing = prerequisites(source)
    if missing or args.probe or not args.disposable_vm:
        print(json.dumps({'schemaVersion': 2, 'kind': 'restricted-disposable-isolation',
            'executed': False, 'status': 'unexecuted', 'prerequisites': missing,
            'provisioningRequested': False, 'mandatoryIsolationTestSatisfied': False,
            'installedKeylessNativeAcceptanceSatisfied': False}, sort_keys=True))
        return 78
    if os.geteuid() != 0:
        raise ValueError('disposable-administrator-required')
    # Fail before creating users/services on any existing installation/security domain.
    if any(path.exists() or path.is_symlink()
           for path in (INSTALLED.parent, STATE, TEST_KIT, Path('/etc/cryptad-certification'))):
        raise ValueError('disposable-fresh-vm-required')
    identities = test_source_identities(source, args.product_source_commit)
    prepared_inputs = None
    if args.prepared_fixtures is not None:
        # Keep fixture-source imports out of the process that will load installed owners.
        script = ('import sys; from pathlib import Path; '
                  'sys.path.insert(0, sys.argv[1]); from pr313_fixtures import verify; '
                  'verify(Path(sys.argv[2]),sys.argv[3],Path(sys.argv[4]),sys.argv[5])')
        call(['/usr/bin/python3', '-I', '-S', '-c', script,
              str(source / 'tools/release-certification/restricted'), str(args.prepared_fixtures),
              args.fixture_manifest_digest, str(source), identities['productSourceCommit']], timeout=120)
        prepared_inputs = args.prepared_fixtures
    javac = Path(shutil.which('javac')).resolve()
    os.environ.clear()
    os.environ.update(ENV, PATH=str(javac.parent) + ':/usr/bin:/bin',
                      PYTHONDONTWRITEBYTECODE='1')
    sys.dont_write_bytecode = True
    load_installation(source)
    dimensions = []
    observations = []
    def observe(row):
        # A repeated owner check is not new coverage; keep the first witnessed case in this guest.
        if row['caseId'] not in {item['caseId'] for item in observations}:
            observations.append(row)
            Path('/root/pr313-observation.private.json').write_text(json.dumps(observations, sort_keys=True))
    identity = None
    stage = 'installation'
    def installation_event(name, status):
        nonlocal stage
        stage = name
        if status == 'complete':
            dimensions.append(name)
    try:
        with tempfile.TemporaryDirectory(prefix='cryptad-disposable-', dir='/root') as temporary:
            identity = provision(source, Path(temporary), event=installation_event)
            dimensions.append('installed-bundle-and-effective-profile-verified')
            stage = 'production-bootstrap-readiness'
            dimensions.extend(bootstrap_readiness())
            from pr313_observations import InvocationWindow, baseline, completed
            raw_state = call(['/usr/bin/systemctl', 'show', 'cryptad-restricted.service',
                '--property=Type,NotifyAccess,ActiveState,SubState,MainPID'], timeout=15)
            state = dict(line.split('=', 1) for line in raw_state.decode('ascii').splitlines())
            state['MainPID'] = int(state['MainPID'])
            if args.case_group in (None, 'positive'):
                observe(baseline('bootstrap-ready', state))
            stage = 'socket-admission'
            dimensions.extend(wrong_socket_uid())
            dimensions.extend(denial_probes())
            if args.case_group in (None, 'positive'):
                for case, peer in (('socket-wrong-uid', 'wrong-uid'), ('socket-unknown-handle', 'runner')):
                    observe(baseline(case, {'peerClass': peer, 'exitCode': 0 if peer == 'wrong-uid' else 2, 'stdoutBytes': 0,
                        'stderrClassification': 'dac-permission-denied' if peer == 'wrong-uid' else 'restricted-operation-unavailable'}))
            if not args.bootstrap_only:
                if not args.native_slice:
                    stage = 'legacy-probes-unavailable'
                    raise ValueError('disposable-legacy-probes-unavailable')
                else:
                    stage = 'installed-keyless-sandbox-probe'
                    sys.path.insert(0, str(INSTALLED / 'tools/release-certification/protected'))
                    import restricted_native
                    if not Path(restricted_native.__file__).resolve().is_relative_to(INSTALLED.resolve()):
                        raise ValueError('disposable-native-source-not-installed')
                    if args.case_group != 'fault':
                        probe_window = InvocationWindow()
                        restricted_native.probe(bundle_identity=identity)
                        if args.case_group in (None, 'positive'):
                            observe(completed('construction-probe', 'bootstrap-probe', 'accepted', probe_window.finish('probe')))
                        dimensions.append('installed-keyless-fixed-native-probe')
                if args.case_group in (None, 'positive'):
                    stage = 'installed-package-api-owner-validation'
                    package_window = InvocationWindow()
                    dimensions.extend(native_package_api(javac.parent.parent, identity, source))
                    observe(completed('package-api', 'package-api', 'owner-validated',
                        package_window.finish('package-api')))
                    stage = 'installed-app-projection-owner-validation'
                    from pr312_app_projection import run as app_projection
                    app_started = time.monotonic_ns()
                    dimensions.extend(app_projection(Path('/root/pr312-app-projection'),
                        INSTALLED.resolve(strict=True), identity, Path('/root/pr312-package-api/jdk'),
                        prepared_inputs=prepared_inputs, observe=observe))
                    stage = 'native-cms-owning-consumer'
                    dimensions.extend(cms_native_integration(source, identities['productSourceCommit'],
                                                             prepared_inputs=prepared_inputs, observe=observe))
                if args.case_group in (None, 'native-hostile'):
                    stage = 'installed-native-hostile-fixtures'
                    from pr312_native_faults import run as native_faults
                    dimensions.extend(native_faults(javac.parent.parent,
                        Path('/root/pr312-native-faults'), identity, observe=observe))
                if args.case_group in (None, 'output-hostile'):
                    stage = 'installed-projection-output-hostile-fixtures'
                    from pr312_output_faults import run as output_faults
                    dimensions.extend(output_faults(Path('/root/pr312-output-faults'), identity, observe=observe))
                if args.case_group == 'public':
                    stage = 'installed-pr313-public-fault'
                    from pr313_public_faults import run as public_fault
                    observe(public_fault(args.fault_case, Path('/root/pr313-public'), identity))
                if args.case_group == 'worker':
                    stage = 'installed-pr313-worker-fault'
                    cms_native_integration(source, identities['productSourceCommit'],
                        prepared_inputs=prepared_inputs, worker_case=args.fault_case)
                if args.case_group == 'fault':
                    stage = 'installed-pr313-fault'
                    from pr313_faults import run as fault
                    observation = fault(args.fault_case, Path('/root/pr313-fault'), identity)
                    Path('/root/pr313-observation.private.json').write_text(json.dumps(observation, sort_keys=True))
                if args.case_group in (None, 'positive'):
                    stage = 'production-restart-readiness'
                    call(['/usr/bin/systemctl', 'restart', 'cryptad-restricted.service'], timeout=190)
                    dimensions.extend(bootstrap_readiness())
                    if args.case_group in (None, 'positive'):
                        raw_state = call(['/usr/bin/systemctl', 'show', 'cryptad-restricted.service',
                            '--property=Type,NotifyAccess,ActiveState,SubState,MainPID'], timeout=15)
                        state = dict(line.split('=', 1) for line in raw_state.decode('ascii').splitlines())
                        state['MainPID'] = int(state['MainPID'])
                        observe(baseline('restart-ready', state))
                    dimensions.extend(denial_probes())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as failure:
        # Only the closed fixed identifier is retained; raw errors, paths and excerpts are dropped.
        code = failure_code(failure)
        diagnostic = Path('/root/pr312-installation-failure.json')
        fd = os.open(diagnostic, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump({'stage': stage, 'code': code}, stream, sort_keys=True)
        print(json.dumps({'schemaVersion': 2, 'kind': 'restricted-disposable-isolation',
            'executed': True, 'status': 'failed', 'failedStage': stage, 'bundleIdentity': identity,
            **identities, 'dimensions': sorted(set(dimensions)),
            'productionAuthorityObserved': False, 'mandatoryIsolationTestSatisfied': False,
            'installedKeylessNativeAcceptanceSatisfied': False}, sort_keys=True))
        return 2
    print(json.dumps({'schemaVersion': 2, 'kind': 'restricted-disposable-isolation',
        'executed': True, 'status': 'local-dimensions-executed', 'bundleIdentity': identity, **identities,
        'dimensions': sorted(set(dimensions)), 'productionAuthorityObserved': False,
        'mandatoryIsolationTestSatisfied': False,
        'installedKeylessNativeAcceptanceSatisfied': False,
        'installedNativePositiveExecuted': not args.bootstrap_only,
        'remainingMandatoryTests': ['installed-controller-owned-workload-positive',
            'primary-catalog-scheduler-app-budget-role-confinement',
            'sibling-admin-plane-and-storage-denials',
            'workload-cgroup-restart-cancellation-terminal-reconciliation',
            'production-bootstrap-maintenance-socket-positive',
            'baseline-approval-and-stopped-supervisor-through-socket',
            'fault-injection-and-full-adversarial-matrix']}, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print('{"schemaVersion":2,"kind":"restricted-disposable-isolation","status":"failed",'
              '"mandatoryIsolationTestSatisfied":false,"installedKeylessNativeAcceptanceSatisfied":false}')
        raise SystemExit(2) from None

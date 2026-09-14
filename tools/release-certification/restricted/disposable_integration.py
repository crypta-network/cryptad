#!/usr/bin/python3
"""Destructive test provisioning ONLY in an explicitly disposable Debian 13 systemd VM.

Default --probe is read-only. Exit 78 means the mandatory VM lane was not executed. This harness
never installs on a container, developer host, existing worker, or already provisioned VM.
External provider/selection transport seams remain synthetic; maintenance CMS and native tools
are real. A successful local dimension is neither production authority nor Phase 12 completion.
"""
from __future__ import annotations

import argparse
import datetime as dt
import grp
import secrets
import signal
import socket
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import tempfile

ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': '/root'}
INSTALLED = Path('/opt/cryptad-cross-version/current')
STATE = Path('/var/lib/cryptad-restricted')


def call(arguments, *, expected=0, environment=None, timeout=120):
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True,
                            env=environment or ENV, timeout=timeout)
    if result.returncode != expected:
        raise ValueError('disposable-command-failed')
    return result.stdout


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


def provision(source, stage):
    import installation
    bundle = stage / 'bundle'
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
    approval = installation.host_plan(identity)
    installation.APPROVAL.parent.mkdir(mode=0o700, parents=True, exist_ok=False)
    installation.APPROVAL.write_bytes(installation.encode(approval))
    installation.APPROVAL.chmod(0o600)
    installation.install(bundle)
    installation.verify()
    call(['/usr/bin/systemctl', 'start', 'cryptad-restricted.socket'])
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
            'ExecStart=/usr/bin/python3 -I -S /opt/cryptad-cross-version/current/'
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


def socket_preparation(real_seal, real_read, freeze, package, runtime_root, *, projection_origin, private_root):
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
    context = {'sourceCommit': freeze['source']['commit'], 'runId': 310, 'runAttempt': 1, 'jobId': 31001}
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
    upstream = original._gh
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
                'name': worker.JOB_NAMES['freeze-and-validate'], 'head_sha': context['sourceCommit'],
                'status': 'in_progress', 'started_at': timestamp.isoformat()}
        return upstream(arguments, environment, **options)
    call(['/usr/bin/systemctl', 'stop', 'cryptad-restricted.service', 'cryptad-restricted.socket'])
    endpoint = Path('/run/cryptad-restricted/control.sock')
    if endpoint.exists():
        raise ValueError('disposable-existing-socket')
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(endpoint))
    os.chown(endpoint, 0, grp.getgrnam('cryptad-control').gr_gid)
    endpoint.chmod(0o660)
    listener.listen(16)
    child = None
    def start():
        pid = os.fork()
        if pid == 0:
            try:
                metadata.seal_private_freeze = real_seal
                companion._read = real_read  # no inherited ownership-relaxation fixture shim
                original._gh = provider
                descriptor = listener.detach()
                if descriptor != 3:
                    os.dup2(descriptor, 3)
                    os.close(descriptor)
                for name in os.listdir('/proc/self/fd'):
                    if int(name) > 3:
                        try: os.close(int(name))
                        except OSError: pass
                os.environ['LISTEN_PID'] = str(os.getpid())
                os.environ['LISTEN_FDS'] = '1'
                worker.main(bundle_identity=identity)
            except BaseException:
                os._exit(2)
        return pid
    client = str(INSTALLED / 'tools/release-certification/protected/restricted_client.py')
    script = "import subprocess,sys; p=subprocess.run(['/usr/bin/python3','-I','-S',sys.argv[1],sys.argv[2],sys.argv[3]],capture_output=True,timeout=900); assert p.returncode==0; assert not p.stderr; sys.stdout.buffer.write(p.stdout)"
    try:
        child = start()
        public = as_role('cryptad-runner', script, arguments=(client, 'maintenance-prepare', handle), timeout=950)
        ciphertext = {p.name: p.read_bytes() for p in (root / 'runtime').iterdir()}
        retained = (root / 'result.json').read_bytes()
        os.kill(child, signal.SIGTERM)
        os.waitpid(child, 0)
        child = start()
        retried = as_role('cryptad-runner', script, arguments=(client, 'maintenance-prepare', handle), timeout=950)
        assert retried == public
        os.kill(child, signal.SIGTERM)
        os.waitpid(child, 0)
        child = start()
        collected = as_role('cryptad-runner', script, arguments=(client, 'collect', handle), timeout=950)
        assert collected == public
        assert retained == (root / 'result.json').read_bytes()
        assert ciphertext == {p.name: p.read_bytes() for p in (root / 'runtime').iterdir()}
        assert set(json.loads(public)) == {'schemaVersion', 'kind', 'operation', 'status', 'freezeDigest', 'descriptor', 'ciphertext'}
        assert b'SYNTHETIC-PROVIDER-CANARY' not in public
        # Transfer only exact retained ciphertext to the rest of the native consumer fixture.
        # The fixture's later owning consumer reauthenticates/decrypts it; JSON is not authority.
        shutil.copytree(root / 'runtime', runtime_root)
        return json.loads((root / 'freeze.json').read_bytes())
    finally:
        if child is not None:
            try: os.kill(child, signal.SIGTERM)
            except ProcessLookupError: pass
            os.waitpid(child, 0)
        listener.close()
        endpoint.unlink(missing_ok=True)
        call(['/usr/bin/systemctl', 'start', 'cryptad-restricted.socket'])


def cms_native_integration(source):
    import unittest
    import restricted_native as native
    import maintenance_runtime_metadata as metadata
    import maintenance_runtime_companion as companion
    from unittest.mock import patch
    sys.path.insert(0, str(INSTALLED / 'tools/release-certification'))
    from cryptad_certification.tests import test_pr304_product_consumer_integration as legacy
    from cryptad_certification.tests import test_pr307_product_consumer_integration as integration
    # The actual disposable root creates every synthetic key/policy. Remove inherited local
    # ownership test shims: real filesystem ownership checks run unchanged here.
    legacy.SelectedRootPolicy = Path
    integration.fixtures._SyntheticRootOwnedPath = Path
    os.environ['GIT_DIR'] = str(source / '.git')  # fixture package source identity only
    suite = unittest.defaultTestLoader.loadTestsFromModule(integration)
    real_seal, real_read = metadata.seal_private_freeze, companion._read
    def through_socket(*args, **kwargs):
        companion._read = real_read
        return socket_preparation(real_seal, real_read, *args, **kwargs)
    with open(os.devnull, 'w') as sink, native.owning_boundary(), \
            patch.object(metadata, 'seal_private_freeze', side_effect=through_socket):
        result = unittest.TextTestRunner(stream=sink).run(suite)
    if result.testsRun != 1 or not result.wasSuccessful() or result.skipped:
        raise ValueError('disposable-real-cms-native-consumer-failed')
    return ['real-maintenance-cms-signed-native-owning-consumer-with-synthetic-provider',
            'installed-worker-socket-preparation-and-restart-exact-retry-with-synthetic-provider']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument('--probe', action='store_true')
    parser.add_argument('--disposable-vm', action='store_true')
    args = parser.parse_args()
    source = args.source.resolve()
    missing = prerequisites(source)
    if missing or args.probe or not args.disposable_vm:
        print(json.dumps({'schemaVersion': 1, 'kind': 'restricted-disposable-isolation',
            'executed': False, 'status': 'unexecuted', 'prerequisites': missing,
            'provisioningRequested': False, 'mandatoryIsolationTestSatisfied': False}, sort_keys=True))
        return 78
    if os.geteuid() != 0:
        raise ValueError('disposable-administrator-required')
    # Fail before creating users/services on any existing installation/security domain.
    if any(path.exists() for path in (INSTALLED.parent, STATE, Path('/etc/cryptad-certification'))):
        raise ValueError('disposable-fresh-vm-required')
    javac = Path(shutil.which('javac')).resolve()
    os.environ.clear()
    os.environ.update(ENV, PATH=str(javac.parent) + ':/usr/bin:/bin',
                      PYTHONDONTWRITEBYTECODE='1')
    sys.dont_write_bytecode = True
    load_installation(source)
    dimensions = []
    with tempfile.TemporaryDirectory(prefix='cryptad-disposable-', dir='/root') as temporary:
        identity = provision(source, Path(temporary))
        dimensions.append('installed-bundle-and-effective-profile-verified')
        dimensions.extend(denial_probes())
        dimensions.extend(baseline_workspace_unit_probe())
        dimensions.extend(native_cleanup_unit_probe())
        dimensions.extend(hostile_native())
        dimensions.extend(cms_native_integration(source))
        call(['/usr/bin/systemctl', 'restart', 'cryptad-restricted.service'])
        dimensions.extend(denial_probes())
    print(json.dumps({'schemaVersion': 1, 'kind': 'restricted-disposable-isolation',
        'executed': True, 'status': 'local-dimensions-executed', 'bundleIdentity': identity,
        'dimensions': sorted(set(dimensions)), 'productionAuthorityObserved': False,
        'mandatoryIsolationTestSatisfied': False,
        'remainingMandatoryTests': ['production-bootstrap-maintenance-socket-positive',
            'baseline-approval-and-stopped-supervisor-through-socket',
            'fault-injection-and-full-adversarial-matrix']}, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print('{"kind":"restricted-disposable-isolation","status":"failed","mandatoryIsolationTestSatisfied":false}')
        raise SystemExit(2) from None

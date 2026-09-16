"""Fixed administrator-only installed races; one selected case per fresh disposable guest.

Instrumentation lives only in the separate test kit. A forked external observer mutates an
actual acquired file at a pipe rendezvous. The installed copier, collector and manager run
unchanged. These observations are synthetic tests, never original provider authority.
"""
import json
import hashlib
import os
from pathlib import Path
import select
import socket
import pwd
import signal
import subprocess
import time
from unittest.mock import patch

MUTATIONS = ('inode', 'ancestor', 'symlink', 'hardlink', 'truncation', 'growth')
RACE_CASES = tuple(prefix + '-' + mutation for prefix in ('input', 'output') for mutation in MUTATIONS)
LIFECYCLE_CASES = ('owner-revocation-running', 'death-active', 'death-running', 'death-output')
CASES = RACE_CASES + ('sibling-control-canary',) + LIFECYCLE_CASES
ENVIRONMENT = {'PATH': '/jdk/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': '/tmp',
               'TMPDIR': '/tmp', 'JAVA_HOME': '/jdk',
               'JAVA_OPTS': '-Xmx256m -XX:CompressedClassSpaceSize=64m -XX:ReservedCodeCacheSize=64m'}
EXPORTER = '''#!/usr/bin/python3
from pathlib import Path
Path('/output/projection.json').write_bytes(b'{"syntheticCollectorControl":true,"authority":"none"}\\n')
print('pr313-output-ready', flush=True)
'''


def mutation(path, kind):
    """Apply one real mutation; return bounded identity facts, never fixture contents."""
    path = Path(path)
    before = path.parent.lstat() if kind == 'ancestor' else path.stat()
    if kind == 'inode':
        replacement = path.with_name('replacement')
        replacement.write_bytes(path.read_bytes())
        os.replace(replacement, path)
    elif kind == 'ancestor':
        parent = path.parent
        relocated = parent.with_name(parent.name + '-relocated')
        parent.rename(relocated)
        parent.symlink_to(relocated, target_is_directory=True)
    elif kind == 'symlink':
        replacement = path.with_name('replacement')
        replacement.write_bytes(b'synthetic-private-substitution')
        path.unlink()
        path.symlink_to(replacement.name)
    elif kind == 'hardlink':
        os.link(path, path.with_name('alias'))
    elif kind == 'truncation':
        os.truncate(path, 1)
    elif kind == 'growth':
        with path.open('ab') as stream:
            stream.write(b'x' * 65536)
    else:
        raise ValueError('unknown-fixed-mutation')
    after = path.parent.lstat() if kind == 'ancestor' else path.stat()
    return {'mutation': kind, 'beforeInode': before.st_ino, 'afterInode': after.st_ino,
            'beforeSize': before.st_size, 'afterSize': after.st_size,
            'afterLinks': after.st_nlink,
            'before': {key: getattr(before, 'st_' + key) for key in ('dev', 'ino', 'size', 'nlink')},
            'after': {key: getattr(after, 'st_' + key) for key in ('dev', 'ino', 'size', 'nlink')}}


class Rendezvous:
    """External mutation after the controller acquired a matching descriptor."""
    def __init__(self, root, kind):
        self.root, self.kind = Path(root), kind
        self.fired = False
        self.real_read = os.read
        self.request_read, self.request_write = os.pipe()
        self.answer_read, self.answer_write = os.pipe()
        self.pid = os.fork()
        if self.pid == 0:
            try:
                os.close(self.request_write)
                os.close(self.answer_read)
                if not select.select([self.request_read], [], [], 60)[0]:
                    os._exit(2)
                raw = os.read(self.request_read, 4096)
                path = Path(os.fsdecode(raw))
                if not path.is_absolute() or not path.is_relative_to(self.root):
                    os._exit(3)
                witness = mutation(path, kind)
                (self.root / 'mutation.json').write_text(json.dumps(witness, sort_keys=True))
                os.write(self.answer_write, b'done')
                os._exit(0)
            except BaseException:
                os._exit(4)
        os.close(self.request_read)
        os.close(self.answer_write)

    def read(self, descriptor, maximum):
        raw = self.real_read(descriptor, maximum)
        if not self.fired and raw:
            try:
                path = Path(os.readlink('/proc/self/fd/' + str(descriptor)))
            except OSError:
                return raw
            if path == self.selected():
                self.fired = True
                os.write(self.request_write, os.fsencode(path))
                if not select.select([self.answer_read], [], [], 10)[0]:
                    raise ValueError('mutation-rendezvous-timeout')
                if self.real_read(self.answer_read, 4) != b'done':
                    raise ValueError('mutation-rendezvous-failed')
        return raw

    def close(self):
        os.close(self.request_write)
        os.close(self.answer_read)
        if not self.fired:
            os.kill(self.pid, signal.SIGKILL)
        _, status = os.waitpid(self.pid, 0)
        if self.fired and status != 0:
            raise ValueError('mutation-observer-failed')


def run(case, root, identity):
    """Execute one fixed real installed acquisition attack and retain all private state."""
    import restricted_native as native
    from pr312_output_faults import _command, _quiescent
    if case in LIFECYCLE_CASES:
        return lifecycle(case, root, identity)
    if case == 'sibling-control-canary':
        return sibling_canary(root, identity)
    if case not in RACE_CASES:
        raise ValueError('unknown-fixed-case')
    if (os.geteuid() != 0 or not Path(native.__file__).resolve().is_relative_to('/opt')
            or not Path('/opt/cryptad-restricted-test-kit/.test-kit.json').is_file()):
        raise ValueError('installed-disposable-test-kit-required')
    detected = subprocess.run(['/usr/bin/systemd-detect-virt', '--vm'], capture_output=True,
                              check=True, timeout=5, env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
    if detected.stdout != b'qemu\n':
        raise ValueError('reference-guest-required')
    # Refuse a nonfresh native history. Destructive races cannot reclaim retained state.
    for path in native.ROOT.iterdir():
        if path.is_dir() and (not (path / 'complete.json').is_file()
                or json.loads((path / 'invocation.json').read_bytes())['spec']['operation'] != 'probe'):
            raise ValueError('fresh-native-case-state-required')
    root = Path(root)
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    jdk, tools, inputs, work = (root / name for name in ('jdk', 'tools', 'inputs', 'work'))
    for path in (jdk, tools, inputs, work):
        path.mkdir(mode=0o700)
    (jdk / 'fixture').write_bytes(b'unused-synthetic-jdk')
    (tools / 'bin').mkdir()
    executable = tools / 'bin/crypta-app'
    executable.write_text(EXPORTER)
    executable.chmod(0o500)
    for name in ('catalog-keys', 'publisher-keys'):
        (inputs / name).write_bytes(b'public-synthetic-input')
    for name in ('catalog', 'catalogSignature', 'bundle'):
        (work / name).write_bytes(b'public-synthetic-input')
    phase, kind = case.split('-', 1)
    # Output stages are outside fixture root; authorize only the owned fixed native root.
    observer_root = root if phase == 'input' else native.ROOT
    rendezvous = Rendezvous(observer_root, kind)
    def selected():
        if phase == 'input':
            return work / 'catalog'
        stages = [p for p in native.ROOT.iterdir() if p.is_dir() and not (p / 'complete.json').exists()]
        return stages[0] / 'output/projection.json' if len(stages) == 1 else None
    rendezvous.selected = selected
    context = {'operationId': '3' * 64, 'registrationDigest': 'sha256:' + '0' * 64,
               'bundleIdentity': identity, 'deadlineMonotonic': time.monotonic() + 60}
    rejected = False
    try:
        with patch.object(native.os, 'read', side_effect=rendezvous.read), native.owning_boundary(context=context):
            native.run(_command(jdk, tools, work, inputs), environment=ENVIRONMENT,
                       timeout=45, output_limit=8192, operation='app-projection')
    except native.NativeBoundaryError:
        rejected = True
    finally:
        rendezvous.close()
    if not rendezvous.fired or not rejected or (work / 'projection.json').exists():
        raise ValueError('attack-not-observed-or-substitution-accepted')
    _quiescent(native)
    stages = [p for p in native.ROOT.iterdir() if p.is_dir() and not (p / 'complete.json').exists()]
    if len(stages) != 1 or (stages[0] / 'complete.json').exists():
        raise ValueError('unexpected-native-retention')
    manager = stages[0] / 'manager.json'
    if phase == 'output' and not manager.is_file():
        raise ValueError('collector-not-launched')
    result = {'caseId': case, 'phase': 'staging-read' if phase == 'input' else 'quiescent-collection-read',
              'attackWitness': json.loads((observer_root / 'mutation.json').read_bytes()),
              'outcome': 'rejected', 'quiescent': {
                  'activeState': native._manager('show')['ActiveState'],
                  'cgroupPopulated': False, 'activeRecordPresent': False},
              'managerInvocationId': json.loads(manager.read_bytes())['invocationId'] if manager.exists() else None}
    result['attackWitness'] = {key: result['attackWitness'][key] for key in ('mutation', 'before', 'after')}
    result['attackWitness']['barrier'] = 'source-opened' if phase == 'input' else 'output-opened'
    (root / 'observation.json').write_text(json.dumps(result, sort_keys=True))
    return result


def sibling_canary(root, identity):
    """Prove a real distinct-UID listener is reachable before native network denial."""
    import restricted_native as native
    from pr312_output_faults import _command, _quiescent
    if (os.geteuid() != 0 or not Path(native.__file__).resolve().is_relative_to('/opt')
            or not Path('/opt/cryptad-restricted-test-kit/.test-kit.json').is_file()):
        raise ValueError('installed-disposable-test-kit-required')
    detected = subprocess.run(['/usr/bin/systemd-detect-virt', '--vm'], capture_output=True,
                              check=True, timeout=5, env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
    if detected.stdout != b'qemu\n':
        raise ValueError('reference-guest-required')
    root = Path(root)
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    jdk, tools, inputs, work = (root / name for name in ('jdk', 'tools', 'inputs', 'work'))
    for path in (jdk, tools, inputs, work):
        path.mkdir(mode=0o700)
    (jdk / 'fixture').write_bytes(b'unused-synthetic-jdk')
    (tools / 'bin').mkdir()
    for name in ('catalog-keys', 'publisher-keys'):
        (inputs / name).write_bytes(b'public-synthetic-input')
    for name in ('catalog', 'catalogSignature', 'bundle'):
        (work / name).write_bytes(b'public-synthetic-input')
    server = socket.socket()
    server.bind(('127.0.0.1', 0))
    server.listen(4)
    port = server.getsockname()[1]
    canary = os.urandom(32)
    counts_read, counts_write = os.pipe()
    account = pwd.getpwnam('nobody')
    if account.pw_uid in (0, native._native_identity()[0]):
        raise ValueError('distinct-sibling-identity-required')
    pid = os.fork()
    if pid == 0:
        try:
            os.close(counts_read)
            os.setgroups([])
            os.setgid(account.pw_gid)
            os.setuid(account.pw_uid)
            server.settimeout(55)
            while True:
                connection, _ = server.accept()
                with connection:
                    connection.sendall(canary)
                os.write(counts_write, b'x')
        except BaseException:
            os._exit(0)
    server_start = int(Path('/proc/' + str(pid) + '/stat').read_text().rsplit(')', 1)[1].split()[19])
    server.close()
    os.close(counts_write)
    executable = tools / 'bin/crypta-app'
    executable.write_text("#!/usr/bin/python3\nimport socket\nfrom pathlib import Path\n"
        + "s=socket.socket(); s.settimeout(2)\ntry:\n s.connect(('127.0.0.1', " + str(port) + "))\n"
        + "except OSError:\n print('pr313-active-sibling-denied', flush=True)\n"
        + "else:\n raise RuntimeError('sibling-reachable')\n"
        + "finally:\n s.close()\nPath('/output/projection.json').write_bytes(b'{}')\n")
    executable.chmod(0o500)
    context = {'operationId': '4' * 64, 'registrationDigest': 'sha256:' + '0' * 64,
               'bundleIdentity': identity, 'deadlineMonotonic': time.monotonic() + 45}
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=5) as connection:
            received = b''
            while len(received) < len(canary):
                block = connection.recv(32)
                if not block:
                    break
                received += block
            if received != canary:
                raise ValueError('authorized-canary-control-failed')
        if not select.select([counts_read], [], [], 5)[0] or os.read(counts_read, 1) != b'x':
            raise ValueError('authorized-canary-listener-unwitnessed')
        before = set(native.ROOT.iterdir())
        with native.owning_boundary(context=context):
            output = native.run(_command(jdk, tools, work, inputs), environment=ENVIRONMENT,
                                timeout=35, output_limit=8192, operation='app-projection')
        if output != b'pr313-active-sibling-denied\n':
            raise ValueError('native-sibling-attempt-unwitnessed')
        _quiescent(native)
        if select.select([counts_read], [], [], 0)[0]:
            raise ValueError('unexpected-sibling-retrieval')
        # Prove the listener survived the native attempt, rather than crediting an absent server.
        with socket.create_connection(('127.0.0.1', port), timeout=5) as connection:
            if connection.recv(32) != canary:
                raise ValueError('post-native-sibling-control-failed')
        stages = [p for p in set(native.ROOT.iterdir()) - before if p.is_dir()]
        if len(stages) != 1:
            raise ValueError('ambiguous-native-invocation')
        result = {'caseId': 'sibling-control-canary', 'phase': 'native-network-connect',
                  'attackWitness': {'controlBefore': 'retrieved', 'controlAfter': 'retrieved',
                                    'nativeRetrievals': 0, 'distinctServerUid': account.pw_uid,
                                    'marker': 'pr313-active-sibling-denied',
                                    'serverPidStartTime': server_start,
                                    'controlResponseDigest': 'sha256:' + hashlib.sha256(received).hexdigest(),
                                    'expectedCanaryDigest': 'sha256:' + hashlib.sha256(canary).hexdigest()},
                  'outcome': 'denied', 'managerInvocationId': json.loads(
                      (stages[0] / 'manager.json').read_bytes())['invocationId'],
                  'quiescent': {'activeState': native._manager('show')['ActiveState'],
                                'cgroupPopulated': False, 'activeRecordPresent': False}}
        (root / 'observation.json').write_text(json.dumps(result, sort_keys=True))
        return result
    finally:
        # This unreaped direct child cannot be replaced through PID reuse.
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        os.close(counts_read)


def _lifecycle_fixture(root):
    jdk, tools, inputs, work = (root / name for name in ('jdk', 'tools', 'inputs', 'work'))
    for path in (jdk, tools, inputs, work):
        path.mkdir(mode=0o700)
    (jdk / 'fixture').write_bytes(b'unused-synthetic-jdk')
    (tools / 'bin').mkdir()
    for name in ('catalog-keys', 'publisher-keys'):
        (inputs / name).write_bytes(b'public-synthetic-input')
    for name in ('catalog', 'catalogSignature', 'bundle'):
        (work / name).write_bytes(b'public-synthetic-input')
    executable = tools / 'bin/crypta-app'
    executable.write_text(EXPORTER)
    executable.chmod(0o500)
    return jdk, tools, inputs, work


def lifecycle(case, root, identity):
    """Native-owner revocation and abrupt native-controller death, without Worker substitution.

    These cases explicitly do not establish Worker durable-result or original admission coverage.
    The native owner uses the unchanged Worker's real revocation reader against a synthetic
    registration. The marker and native processes are real; no mocked revocation verdict exists.
    """
    import restricted_native as native
    import restricted_worker as worker
    from pr312_output_faults import _command, _quiescent
    if (os.geteuid() != 0 or not Path(native.__file__).resolve().is_relative_to('/opt')
            or not Path('/opt/cryptad-restricted-test-kit/.test-kit.json').is_file()):
        raise ValueError('installed-disposable-test-kit-required')
    detected = subprocess.run(['/usr/bin/systemd-detect-virt', '--vm'], capture_output=True,
                              check=True, timeout=5, env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
    if detected.stdout != b'qemu\n':
        raise ValueError('reference-guest-required')
    for path in native.ROOT.iterdir():
        if path.is_dir() and (not (path / 'complete.json').is_file()
                or json.loads((path / 'invocation.json').read_bytes())['spec']['operation'] != 'probe'):
            raise ValueError('fresh-native-case-state-required')
    root = Path(root)
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    jdk, tools, inputs, work = _lifecycle_fixture(root)
    context = {'operationId': '5' * 64, 'registrationDigest': 'sha256:' + '0' * 64,
               'bundleIdentity': identity, 'deadlineMonotonic': time.monotonic() + 60}
    command = _command(jdk, tools, work, inputs)
    if case == 'owner-revocation-running':
        executable = tools / 'bin/crypta-app'
        executable.write_text("#!/usr/bin/python3\nfrom pathlib import Path\nimport time\n"
                              "Path('/output/started').write_bytes(b'candidate-started')\ntime.sleep(120)\n")
        record = {'bundleIdentity': identity}
        worker.persist(root / 'registration.json', record)
        if not (worker.STATE / 'revocations.json').exists():
            worker.persist(worker.STATE / 'revocations.json', [])
        actor = os.fork()
        if actor == 0:
            try:
                deadline = time.monotonic() + 40
                while time.monotonic() < deadline:
                    stages = [p for p in native.ROOT.iterdir() if p.is_dir() and not (p / 'complete.json').exists()]
                    if len(stages) == 1 and (stages[0] / 'output/started').is_file() and (stages[0] / 'manager.json').is_file():
                        manager = json.loads((stages[0] / 'manager.json').read_bytes())
                        state = native._manager('show')
                        if (state['InvocationID'] == manager['invocationId'] and
                                state['ControlGroup'] == native.CGROUP and state['SubState'] == 'running'):
                            worker.persist(root / 'revoked.json', {'reason': 'synthetic-fixed-case'})
                            (root / 'revocation-witness.json').write_text(json.dumps(manager))
                            os._exit(0)
                    time.sleep(.02)
                os._exit(2)
            except BaseException:
                os._exit(3)
        rejected = False
        try:
            with native.owning_boundary(context=context, check=lambda: worker.require_not_revoked(root, record)):
                native.run(command, environment=ENVIRONMENT, timeout=50, output_limit=8192, operation='app-projection')
        except native.NativeBoundaryError:
            rejected = True
        finally:
            # Unreaped direct child identity is pinned even if it already exited.
            _, status = os.waitpid(actor, 0)
        if not rejected or status != 0 or not (root / 'revocation-witness.json').is_file():
            raise ValueError('real-owner-revocation-unwitnessed')
        try:
            worker.require_not_revoked(root, record)
        except worker.BoundaryError as failure:
            if str(failure) != 'restricted-operation-revoked':
                raise
        else:
            raise ValueError('current-owner-revocation-not-enforced')
        _quiescent(native)
        stages = [p for p in native.ROOT.iterdir() if p.is_dir() and not (p / 'complete.json').exists()]
        if len(stages) != 1 or (stages[0] / 'complete.json').exists():
            raise ValueError('revoked-result-retained')
        result = {'caseId': case, 'phase': 'native-running', 'outcome': 'rejected',
                  'managerInvocationId': json.loads((root / 'revocation-witness.json').read_bytes())['invocationId'],
                  'attackWitness': {'revocationObserved': 'restricted-operation-revoked',
                                    'candidateMarker': 'candidate-started',
                                    'registrationDigest': worker.digest((root / 'registration.json').read_bytes()),
                                    'revokedDigest': worker.digest((root / 'revoked.json').read_bytes())},
                  'quiescent': {'activeState': native._manager('show')['ActiveState'],
                                'cgroupPopulated': False, 'activeRecordPresent': False}}
    else:
        if case == 'death-running':
            executable = tools / 'bin/crypta-app'
            executable.write_text("#!/usr/bin/python3\nimport time\ntime.sleep(120)\n")
        result = _death(case, root, native, command, context)
    (root / 'observation.json').write_text(json.dumps(result, sort_keys=True))
    return result


def _death(case, root, native, command, context):
    ready_read, ready_write = os.pipe()
    release_read, release_write = os.pipe()
    controller = os.fork()
    if controller == 0:
        try:
            os.close(ready_read)
            os.close(release_write)
            fired = False
            def barrier():
                nonlocal fired
                if fired:
                    return
                fired = True
                os.write(ready_write, b'ready')
                # Only the parent can release; acceptance deliberately kills this controller.
                if not select.select([release_read], [], [], 55)[0]:
                    os._exit(3)
                os.read(release_read, 1)
                os._exit(4)
            real_write, real_quiesce = native._write, native._quiesce
            def write(path, value, **kwargs):
                real_write(path, value, **kwargs)
                if ((case == 'death-active' and Path(path).name == 'active.json')
                        or (case == 'death-running' and Path(path).name == 'manager.json')):
                    barrier()
            def quiesce():
                real_quiesce()
                if case == 'death-output':
                    barrier()
            with patch.object(native, '_write', side_effect=write), patch.object(native, '_quiesce', side_effect=quiesce), native.owning_boundary(context=context):
                native.run(command, environment=ENVIRONMENT, timeout=45, output_limit=8192, operation='app-projection')
            os._exit(5)
        except BaseException:
            os._exit(6)
    os.close(ready_write)
    os.close(release_read)
    try:
        if not select.select([ready_read], [], [], 55)[0] or os.read(ready_read, 5) != b'ready':
            raise ValueError('durable-death-boundary-unwitnessed')
        stages = [p for p in native.ROOT.iterdir() if p.is_dir() and not (p / 'complete.json').exists()]
        if len(stages) != 1 or not (native.ROOT / 'active.json').is_file():
            raise ValueError('active-native-intent-unwitnessed')
        manager = stages[0] / 'manager.json'
        manager_id = json.loads(manager.read_bytes())['invocationId'] if manager.exists() else None
        if case == 'death-output':
            require_output_ready(native, stages[0])
        if case == 'death-running':
            state = native._manager('show')
            if state['InvocationID'] != manager_id or state['SubState'] != 'running':
                raise ValueError('running-native-boundary-unwitnessed')
        start_time = int(Path('/proc/' + str(controller) + '/stat').read_text().rsplit(')', 1)[1].split()[19])
        active_before = 'sha256:' + hashlib.sha256((native.ROOT / 'active.json').read_bytes()).hexdigest()
        os.kill(controller, signal.SIGKILL)
        _, status = os.waitpid(controller, 0)
        controller = None
        if not os.WIFSIGNALED(status) or os.WTERMSIG(status) != signal.SIGKILL:
            raise ValueError('controller-death-not-observed')
        native._quiesce()  # Fixed owned service only; active state is intentionally retained.
        before = set(native.ROOT.iterdir())
        try:
            with native.owning_boundary(context=context):
                native.run(command, environment=ENVIRONMENT, timeout=10, output_limit=8192, operation='app-projection')
        except native.NativeBoundaryError as failure:
            retry_error = str(failure)
        else:
            raise ValueError('uncertain-invocation-replayed')
        if set(native.ROOT.iterdir()) != before or not (native.ROOT / 'active.json').is_file():
            raise ValueError('uncertain-native-state-not-retained')
        return {'caseId': case, 'phase': {'death-active': 'intent-written', 'death-running': 'native-running', 'death-output': 'output-ready'}[case],
                'outcome': 'reconciliation-required', 'managerInvocationId': manager_id,
                'attackWitness': {'signal': 'SIGKILL', 'pidStartTime': start_time,
                                  'durablePhase': {'death-active': 'intent-written', 'death-running': 'native-running', 'death-output': 'output-ready'}[case],
                                  'retryError': retry_error,
                                  'activeRecordDigestBefore': active_before,
                                  'activeRecordDigestAfter': 'sha256:' + hashlib.sha256((native.ROOT / 'active.json').read_bytes()).hexdigest(),
                                  'nativeLaunchCount': int(manager_id is not None)},
                'quiescent': {'activeState': native._manager('show')['ActiveState'],
                              'cgroupPopulated': False, 'activeRecordPresent': True}}
    finally:
        if controller is not None:
            os.kill(controller, signal.SIGKILL)
            os.waitpid(controller, 0)
            native._quiesce()
        os.close(ready_read)
        os.close(release_write)


def require_output_ready(native, stage):
    """A cleanup quiescence callback is not evidence that native output completed."""
    from pr312_output_faults import CONTROL_BYTES
    stage = Path(stage)
    output = stage / 'output'
    if ((stage / 'failure.json').exists() or (output / 'failure.json').exists()
            or set(path.name for path in output.iterdir()) != {'stdout', 'complete.json', 'projection.json'}
            or json.loads(native._read_output(output / 'complete.json', 4096)) != {
                'invocation': stage.name, 'status': 'complete'}
            or native._read_output(output / 'stdout', 8192) != b'pr313-output-ready\n'
            or native._read_output(output / 'projection.json', 32768) != CONTROL_BYTES):
        raise ValueError('native-successful-output-not-ready')

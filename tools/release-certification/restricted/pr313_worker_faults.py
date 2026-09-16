"""Durable Worker death using the existing real CMS socket preparation fixture.

Call from the signed fixture's seal callback, passing the same arguments as socket_preparation.
Only original-provider transport is synthetic. The unchanged installed Worker, CMS owner and
native service execute. An external forked observer kills the exact test controller at a durable
persist boundary. Each selected case requires an independent fresh disposable guest.
"""
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import time
from unittest.mock import patch

CASES = ('worker-death-intent', 'worker-death-result', 'worker-revocation-running', 'completed-revocation-retry', 'public-adversarial-output')


def _digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def run(case, real_seal, real_read, freeze, package, runtime_root, *, projection_origin, private_root):
    import disposable_integration as integration
    import restricted_worker as worker
    import restricted_native as native
    from pr312_output_faults import _quiescent
    if case not in CASES:
        raise ValueError('unknown-fixed-worker-case')
    if (os.geteuid() != 0 or not Path(worker.__file__).resolve().is_relative_to('/opt')
            or not Path('/opt/cryptad-restricted-test-kit/.test-kit.json').is_file()):
        raise ValueError('installed-disposable-test-kit-required')
    import subprocess
    detected = subprocess.run(['/usr/bin/systemd-detect-virt', '--vm'], capture_output=True,
                              check=True, timeout=5, env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
    if detected.stdout != b'qemu\n':
        raise ValueError('reference-guest-required')
    if case == 'public-adversarial-output':
        return public_adversary(real_seal, real_read, freeze, package, runtime_root,
                                projection_origin=projection_origin, private_root=private_root)
    selected = {'worker-death-intent': 'intent.json', 'worker-death-result': 'result.json',
                'worker-revocation-running': 'manager.json',
                'completed-revocation-retry': 'result.json'}[case]
    evidence = Path('/root') / ('pr313-' + case)
    evidence.mkdir(mode=0o700, exist_ok=False)
    rendezvous = evidence / 'rendezvous'
    os.mkfifo(rendezvous, 0o600)
    request_read = os.open(rendezvous, os.O_RDONLY | os.O_NONBLOCK)
    before = set(worker.OPERATIONS.iterdir())
    observer = os.fork()
    if observer == 0:
        try:
            if not select.select([request_read], [], [], 900)[0]:
                os._exit(2)
            request = json.loads(os.read(request_read, 4096))
            controller, start = request['pid'], request['start']
            # pidfd pins the actual target; validate its birth time before delivering SIGKILL.
            descriptor = os.pidfd_open(controller)
            current = int(Path('/proc/' + str(controller) + '/stat').read_text().rsplit(')', 1)[1].split()[19])
            if current != start or request['phase'] != selected:
                os._exit(3)
            if case == 'worker-revocation-running':
                deadline = time.monotonic() + 30
                processes = Path('/sys/fs/cgroup' + native.CGROUP) / 'cgroup.procs'
                while time.monotonic() < deadline:
                    try:
                        observed = any((Path('/proc') / pid / 'comm').read_text().strip() == 'java'
                                       for pid in processes.read_text().split())
                    except FileNotFoundError:
                        observed = False
                    if observed:
                        operation = worker.OPERATIONS / request['handle']
                        record = worker.decode(worker.read(operation / 'registration.json'), worker.MAX_RECORD)
                        if record['handle'] != request['handle']:
                            os._exit(5)
                        worker.persist(operation / 'revoked.json', {'reason': 'synthetic-fixed-case'})
                        break
                    time.sleep(.02)
                else:
                    os._exit(6)
                (evidence / 'death.json').write_text(json.dumps(request, sort_keys=True))
            else:
                (evidence / 'death.json').write_text(json.dumps(request, sort_keys=True))
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            os.close(descriptor)
            os._exit(0)
        except BaseException:
            os._exit(4)
    os.close(request_read)
    real_persist, real_native_write = worker.persist, native._write
    def barrier(path):
        path = Path(path)
        handle = path.parent.name
        if case == 'worker-revocation-running':
            invocation = json.loads((path.parent / 'invocation.json').read_bytes())
            handle = invocation['owner']['operationId']
        pid = os.getpid()
        start = int(Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19])
        raw = path.read_bytes()
        descriptor = os.open(rendezvous, os.O_WRONLY | os.O_NONBLOCK)
        try:
            os.write(descriptor, json.dumps({'pid': pid, 'start': start, 'phase': selected,
                        'handle': handle, 'durableDigest': _digest(raw)}).encode())
        finally:
            os.close(descriptor)
        if case == 'worker-revocation-running':
            deadline = time.monotonic() + 35
            while time.monotonic() < deadline:
                if (evidence / 'death.json').exists():
                    return
                time.sleep(.02)
            raise ValueError('worker-revocation-not-observed')
        select.select([], [], [], 900)
        raise ValueError('worker-death-observer-unexpected-release')
    def persist(path, value):
        real_persist(path, value)
        if Path(path).name == selected and Path(path).parent.is_relative_to(worker.OPERATIONS):
            barrier(path)
    def native_write(path, value, **kwargs):
        real_native_write(path, value, **kwargs)
        if case == 'worker-revocation-running' and Path(path).name == 'manager.json':
            barrier(path)
    failed = False
    try:
        with patch.object(worker, 'persist', side_effect=persist), patch.object(native, '_write', side_effect=native_write):
            try:
                integration.socket_preparation(real_seal, real_read, freeze, package, runtime_root,
                    projection_origin=projection_origin, private_root=private_root)
            except (AssertionError, OSError, ValueError):
                failed = True
    finally:
        if not (evidence / 'death.json').exists():
            os.kill(observer, signal.SIGKILL)
        _, status = os.waitpid(observer, 0)
    if not failed or status != 0 or not (evidence / 'death.json').is_file():
        raise ValueError('worker-durable-death-not-executed')
    witness = json.loads((evidence / 'death.json').read_bytes())
    roots = [p for p in set(worker.OPERATIONS.iterdir()) - before if p.is_dir()]
    if len(roots) != 1 or roots[0].name != witness['handle']:
        raise ValueError('worker-operation-identity-mismatch')
    root = roots[0]
    record = worker.decode(worker.read(root / 'registration.json'), worker.MAX_RECORD)
    selected_request = {'method': record['method'], 'handle': record['handle']}
    owner = worker.Worker(record['bundleIdentity'])
    native_before = set(native.ROOT.iterdir())
    if case == 'worker-revocation-running':
        if (root / 'result.json').exists():
            raise ValueError('revoked-worker-result-retained')
        require_revoked_retry(owner, record)
        _quiescent(native)
        stages = [p for p in native.ROOT.iterdir() if p.is_dir()
                  and (p / 'invocation.json').is_file()
                  and json.loads((p / 'invocation.json').read_bytes())['owner']['operationId'] == record['handle']]
        if len(stages) != 1:
            raise ValueError('worker-native-invocation-ambiguous')
        manager = json.loads((stages[0] / 'manager.json').read_bytes())
        result = {'caseId': case, 'phase': 'native-running', 'outcome': 'rejected',
                  'managerInvocationId': manager['invocationId'],
                  'attackWitness': {'registrationDigest': _digest((root / 'registration.json').read_bytes()),
                                    'revokedDigest': _digest((root / 'revoked.json').read_bytes()),
                                    'revocationObserved': 'restricted-operation-revoked',
                                    'nativeProcess': 'java', 'retryAndCollect': 'revoked'},
                  'quiescent': {'activeState': native._manager('show')['ActiveState'],
                                'cgroupPopulated': False, 'activeRecordPresent': False}}
        (evidence / 'observation.json').write_text(json.dumps(result, sort_keys=True))
        return result
    durable_before = (root / selected).read_bytes()
    if _digest(durable_before) != witness['durableDigest']:
        raise ValueError('durable-state-changed-after-death')
    if case == 'worker-death-intent':
        try:
            owner.process(selected_request, record['callerUid'])
        except worker.BoundaryError as failure:
            if str(failure) != 'restricted-reconciliation-required':
                raise
        else:
            raise ValueError('worker-uncertain-intent-replayed')
        outcome = 'reconciliation-required'
    else:
        retained = worker.decode(worker.read(root / 'result.json'), worker.MAX_RESULT)
        # Retained retry executes no owner dispatch: make any accidental dispatch a hard failure.
        with patch.object(worker, 'dispatch', side_effect=AssertionError('retained-dispatch-reran')):
            retried = owner.process(selected_request, record['callerUid'])
            collected = owner.process({'method': 'collect', 'handle': record['handle']}, record['callerUid'])
        expected = {'status': 'complete', 'receipt': retained['receipt'], 'result': retained['result']}
        if retried != expected or collected != expected:
            raise ValueError('worker-exact-retained-retry-failed')
        outcome = 'exact-retained-result'
        if case == 'completed-revocation-retry':
            worker.persist(root / 'revoked.json', {'reason': 'synthetic-after-completion'})
            require_revoked_retry(owner, record)
            outcome = 'revoked'
    if durable_before != (root / selected).read_bytes() or native_before != set(native.ROOT.iterdir()):
        raise ValueError('worker-retry-modified-retained-state')
    _quiescent(native)
    result = {'caseId': case, 'phase': selected, 'outcome': outcome,
              'attackWitness': {'controllerStartTime': witness['start'], 'signal': 'SIGKILL',
                                'durableDigestBefore': witness['durableDigest'],
                                'durableDigestAfter': _digest((root / selected).read_bytes()),
                                'nativeRetryLaunches': 0},
              'managerInvocationId': None,
              'quiescent': {'activeState': native._manager('show')['ActiveState'],
                            'cgroupPopulated': False, 'activeRecordPresent': False}}
    if case == 'completed-revocation-retry':
        result['attackWitness'].update(
            registrationDigest=_digest((root / 'registration.json').read_bytes()),
            revokedDigest=_digest((root / 'revoked.json').read_bytes()), retryAndCollect='revoked')
    (evidence / 'observation.json').write_text(json.dumps(result, sort_keys=True))
    return result


def require_revoked_retry(owner, record):
    """Credit revocation only when real retry and collection return its exact boundary error."""
    import restricted_worker as worker
    for method in (record['method'], 'collect'):
        try:
            owner.process({'method': method, 'handle': record['handle']}, record['callerUid'])
        except worker.BoundaryError as failure:
            if str(failure) != 'restricted-operation-revoked':
                raise
        else:
            raise ValueError('current-worker-revocation-not-enforced')


def public_adversary(real_seal, real_read, freeze, package, runtime_root, *, projection_origin, private_root):
    """Actual malicious Java package export through unchanged Worker/CMS semantic ownership."""
    import copy
    import io
    import secrets
    import subprocess
    import tarfile
    import app_subject_projection as projection
    import maintenance_runtime_metadata as metadata
    import restricted_worker as worker
    import restricted_native as native
    import disposable_integration as integration
    from pr312_output_faults import _quiescent
    evidence = Path('/root/pr313-public-adversarial-output')
    evidence.mkdir(mode=0o700, exist_ok=False)
    cohort = projection._cohort()
    jdk = Path(cohort['javaHome'])
    canary = 'synthetic-private-prose-' + secrets.token_hex(16)
    payload = json.dumps({'accepted': True, 'message': 'Ordinary private narrative ' + canary,
                          'privateState': canary}, sort_keys=True)
    source = evidence / 'PackagedApiExport.java'
    source.write_text('package network.crypta.platform.api; public final class PackagedApiExport {'
                      'public static void main(String[] args) {System.out.println('
                      + json.dumps(payload) + ');}}\n')
    classes = evidence / 'classes'
    classes.mkdir(mode=0o700)
    jar = evidence / 'adversarial.jar'
    environment = {'PATH': str(jdk / 'bin') + ':/usr/bin:/bin', 'LANG': 'C.UTF-8',
                   'JAVA_HOME': str(jdk), 'HOME': str(evidence), 'TMPDIR': str(evidence)}
    with (evidence / 'compile.private').open('xb') as log:
        subprocess.run([str(jdk / 'bin/javac'), '-d', str(classes), str(source)],
                       env=environment, stdout=log, stderr=log, check=True, timeout=120)
        subprocess.run([str(jdk / 'bin/jar'), '--create', '--file', str(jar), '-C', str(classes), '.'],
                       env=environment, stdout=log, stderr=log, check=True, timeout=60)
    selected_package = evidence / Path(package).name
    with tarfile.open(selected_package, 'w:gz') as archive:
        raw = jar.read_bytes()
        member = tarfile.TarInfo('lib/cryptad.jar')
        member.size, member.mode, member.mtime = len(raw), 0o644, 0
        archive.addfile(member, io.BytesIO(raw))
    selected_freeze = copy.deepcopy(freeze)
    products = [row for row in selected_freeze['assets'] if row['role'] == 'product']
    if len(products) != 1:
        raise ValueError('synthetic-public-product-selection-invalid')
    products[0].update(digest=_digest(selected_package.read_bytes()), sizeBytes=selected_package.stat().st_size,
                       fileName=selected_package.name)
    selected_freeze['assets'].sort(key=lambda row: row['fileName'])
    checksums = ''.join(row['digest'][7:] + '  ' + row['fileName'] + '\n' for row in selected_freeze['assets']).encode()
    selected_freeze['checksumsDigest'] = _digest(checksums)
    selected_freeze['assetSetDigest'] = metadata.semantic_digest(selected_freeze['assets'])
    (evidence / 'fixture-identity.private.json').write_text(json.dumps({
        'provenance': 'synthetic-selected-malicious-package-not-release',
        'sourceDigest': _digest(source.read_bytes()), 'jarDigest': _digest(raw),
        'jdkTreeDigest': cohort['javaTreeDigest'], 'packageDigest': _digest(selected_package.read_bytes())}, sort_keys=True))
    native_before, operations_before = set(native.ROOT.iterdir()), set(worker.OPERATIONS.iterdir())
    client_response = []
    real_as_role = integration.as_role
    # This test client reads the actual socket response; it does not alter the installed server.
    script = ("import json,socket,sys; sys.path.insert(0,str(__import__('pathlib').Path(sys.argv[1]).parent)); "
              "from restricted_protocol import send,receive,encode,MAX_REQUEST,MAX_RESULT; "
              "s=socket.socket(socket.AF_UNIX); s.settimeout(900); s.connect('/run/cryptad-restricted/control.sock'); "
              "send(s,{'method':sys.argv[2],'handle':sys.argv[3]},MAX_REQUEST); "
              "sys.stdout.buffer.write(receive(s,MAX_RESULT,timeout=900)); s.close()")
    def observe_client(name, ignored_script, *, arguments=(), timeout=120, expected=0):
        if name != 'cryptad-runner' or len(arguments) != 3 or arguments[1] != 'maintenance-prepare':
            raise ValueError('unexpected-public-test-client-operation')
        raw = real_as_role(name, script, arguments=arguments, timeout=timeout, expected=expected)
        client_response.append(raw)
        raise ValueError('synthetic-public-response-captured')
    try:
        with patch.object(integration, 'as_role', side_effect=observe_client):
            integration.socket_preparation(real_seal, real_read, selected_freeze, selected_package,
                runtime_root, projection_origin=projection_origin, private_root=private_root)
    except ValueError as failure:
        if str(failure) != 'synthetic-public-response-captured':
            raise
    if len(client_response) != 1 or worker.decode(client_response[0], worker.MAX_RESULT) != {'status': 'unavailable'}:
        raise ValueError('worker-public-response-not-closed-denial')
    roots = [p for p in set(worker.OPERATIONS.iterdir()) - operations_before if p.is_dir()]
    stages = [p for p in set(native.ROOT.iterdir()) - native_before if p.is_dir()]
    if len(roots) != 1 or len(stages) != 1:
        raise ValueError('worker-public-native-execution-unwitnessed')
    root, stage = roots[0], stages[0]
    if (root / 'result.json').exists() or not (root / 'intent.json').is_file() or not (stage / 'complete.json').is_file():
        raise ValueError('worker-public-semantic-rejection-unwitnessed')
    output = native._read_output(stage / 'output/stdout', 32768)
    if output != (payload + '\n').encode():
        raise ValueError('worker-public-candidate-output-unwitnessed')
    _quiescent(native)
    # All publicly eligible bytes for this bounded test are constructed and inspected here.
    # Failed collection artifacts and candidate diagnostics remain outside this exact roster.
    public = evidence / 'public'
    public.mkdir(mode=0o700)
    artifacts = public_artifacts(client_response[0], canary, payload)
    for name, content in artifacts.items():
        (public / name).write_bytes(content)
    if set(p.name for p in public.iterdir()) != set(artifacts):
        raise ValueError('worker-public-artifact-roster-invalid')
    return {'caseId': 'public-adversarial-output', 'phase': 'public-export', 'outcome': 'rejected',
            'managerInvocationId': json.loads((stage / 'manager.json').read_bytes())['invocationId'],
            'attackWitness': {'candidateOutputDigest': _digest(output),
                              'clientResponseDigest': _digest(client_response[0]),
                              'semanticOwner': 'rejected', 'workerResultPresent': False,
                              'publicArtifactNames': sorted(artifacts), 'privateCanary': 'absent',
                              'failedArtifacts': 'private-only'},
            'quiescent': {'activeState': native._manager('show')['ActiveState'],
                          'cgroupPopulated': False, 'activeRecordPresent': False}}


def public_artifacts(response, canary, payload):
    """Construct the fixed eligible artifact roster only for the actual closed socket denial."""
    import restricted_worker as worker
    if worker.decode(response, worker.MAX_RESULT) != {'status': 'unavailable'}:
        raise ValueError('worker-public-response-not-closed-denial')
    report = {'caseId': 'public-adversarial-output', 'status': 'rejected', 'productionAuthorityObserved': False}
    artifacts = {'report.json': json.dumps(report, sort_keys=True).encode(),
                 'summary.md': b'Synthetic malicious native output rejected by the installed Worker.\n',
                 'client.log': response}
    for content in artifacts.values():
        if canary.encode() in content or payload.encode() in content or b'accepted' in content:
            raise ValueError('worker-public-canary-exposed')
    return artifacts

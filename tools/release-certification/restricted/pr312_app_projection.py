"""Disposable signed-app observation with synthetic originals and unchanged installed validators.

Fixture construction is trusted administrator work in the selected guest. This module is excluded
from production imports; its observations cannot constitute original-provider proof or receipts.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import time
import zipfile


def _artifact(original, fixture):
    names = {'catalog': 'external.properties', 'catalogSignature': 'external.signature',
             'bundle': 'external-app.zip', 'submission': 'submission.zip'}
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        for role, name in sorted(names.items()):
            raw = (fixture / name).read_bytes()
            if len(raw) > 8 * 1024 * 1024:
                raise ValueError('app-fixture-input-overflow')
            archive.writestr(role, raw)
    raw = output.getvalue()
    coordinates = {'repository': 'crypta-network/cryptad', 'sourceFamily': 'third-party-pilot',
        'sourceCommit': 'a' * 40, 'runId': 1, 'runAttempt': 1, 'jobId': 1,
        'jobName': original.PRODUCERS['third-party-pilot'][2], 'artifactId': 1,
        'artifactName': 'synthetic-pr312-signed-app',
        'artifactDigest': 'sha256:' + hashlib.sha256(raw).hexdigest(), 'artifactSize': len(raw)}
    original.validate_coordinates(coordinates)
    return original.OriginalArtifact(raw, coordinates), {role: role for role in names}


def _quiescent(native):
    state = native._manager('show')
    if (state['ActiveState'] not in ('inactive', 'failed')
            or state['ControlGroup'] not in ('', native.CGROUP)
            or (native.ROOT / 'active.json').exists()):
        raise ValueError('app-fixture-quiescence-unavailable')
    events = Path('/sys/fs/cgroup' + native.CGROUP) / 'cgroup.events'
    if events.exists() and 'populated 0' not in events.read_text().splitlines():
        raise ValueError('app-fixture-quiescence-unavailable')


def _validate_result(result):
    if (result['declaration']['appId'] != 'external-app'
            or result['producerAttestation'] != 'not-observed'
            or result['releaseEligibility'] != 'blocked'):
        raise ValueError('app-fixture-owner-validation-failed')


def _installed_module(native, installed_root):
    expected = installed_root / 'tools/release-certification/protected/restricted_native.py'
    return (installed_root.is_relative_to('/opt/cryptad-cross-version')
            and Path(native.__file__) == expected
            and all(not path.is_symlink() for path in (installed_root, *installed_root.parents)))


def run(root, installed_root, identity, java_home, prepared_inputs=None, observe=None):
    import restricted_native as native
    import app_subject_projection as projection
    import original_artifact_authentication as original
    from bounded_process import run as bounded_run
    installed_root, java_home, root = map(Path, (installed_root, java_home, root))
    if (os.geteuid() != 0 or not _installed_module(native, installed_root)
            or len(identity) != 64 or any(c not in '0123456789abcdef' for c in identity)
            or not Path('/opt/cryptad-restricted-test-kit/.test-kit.json').is_file()):
        raise ValueError('app-fixture-requires-installed-guest')
    for selected in (installed_root, java_home):
        native._secured(selected, directory=True)
    if bounded_run(['/usr/bin/systemd-detect-virt', '--vm'],
            environment={'PATH': '/usr/bin:/bin', 'LANG': 'C'}, timeout=5, output_limit=1024) != b'qemu\n':
        raise ValueError('app-fixture-reference-guest-required')
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    fixture, classes, work = (root / name for name in ('signed', 'classes', 'work'))
    for directory in (fixture, classes, work):
        directory.mkdir(mode=0o700)
    tools = installed_root / 'platform-devtools/build/install/crypta-app'
    source = installed_root / 'platform-devtools/src/test/java/network/crypta/platform/devtools/fixtures/Pr304SignedFixture.java'
    environment = {'PATH': str(java_home / 'bin') + ':/usr/bin:/bin', 'LANG': 'C.UTF-8',
                   'JAVA_HOME': str(java_home), 'HOME': str(root), 'TMPDIR': str(root)}
    def diagnostics(name):
        def retain(stdout, stderr):
            for channel, raw in (('stdout', stdout), ('stderr', stderr)):
                path = root / (name + '-' + channel + '.private')
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(descriptor, 'wb') as stream:
                    stream.write(raw[:65536])
        return retain
    classpath = str(tools / 'lib/*')
    if prepared_inputs is None:
        bounded_run([str(java_home / 'bin/javac'), '-cp', classpath, '-d', str(classes), str(source)],
                    environment=environment, timeout=60, output_limit=65536, diagnostic_sink=diagnostics('compile'))
        bounded_run([str(java_home / 'bin/java'), '-cp', str(classes) + os.pathsep + classpath,
                    'network.crypta.platform.devtools.fixtures.Pr304SignedFixture', str(fixture)],
                    environment=environment, timeout=60, output_limit=65536, diagnostic_sink=diagnostics('generate'))
    else:
        import shutil
        shutil.copytree(prepared_inputs / 'signed', fixture, dirs_exist_ok=True)
    artifact, names = _artifact(original, fixture)
    exporter = tools / 'bin/crypta-app'
    options = dict(exporter=exporter, exporter_digest='sha256:' + hashlib.sha256(exporter.read_bytes()).hexdigest(),
        catalog_key_id='catalog', catalog_keys=fixture / 'catalog-keys.properties',
        publisher_keys=fixture / 'publisher-keys.properties', reviewer_keys=fixture / 'reviewer-keys.properties',
        private_root=work, java_home=java_home, maintenance_tool_root=tools)
    operations = []
    for app in ('external-app', 'wrong-app'):
        context = {'operationId': secrets.token_hex(32), 'registrationDigest': 'sha256:' + '0' * 64,
                   'bundleIdentity': identity, 'deadlineMonotonic': time.monotonic() + 180}
        started_ns = time.monotonic_ns()
        before = set(native.ROOT.iterdir())
        rejected = False
        with native.owning_boundary(context):
            try:
                result = projection.produce(artifact, names, app_id=app, **options)
            except projection.ProjectionFailure:
                rejected = True
        _quiescent(native)
        stages = [path for path in set(native.ROOT.iterdir()) - before if path.is_dir()]
        if len(stages) != 1:
            raise ValueError('app-fixture-installed-invocation-unobserved')
        manager = json.loads((stages[0] / 'manager.json').read_bytes())
        if (manager['controlGroup'] != native.CGROUP or len(manager['invocationId']) != 32
                or any(c not in '0123456789abcdef' for c in manager['invocationId'])):
            raise ValueError('app-fixture-manager-identity-unobserved')
        record = json.loads((stages[0] / 'invocation.json').read_bytes())
        if record['spec']['options']['--app-id'] != app or record['owner'] != context:
            raise ValueError('app-fixture-invocation-substituted')
        if app == 'external-app':
            if rejected:
                raise ValueError('app-fixture-positive-rejected')
            _validate_result(result)
        else:
            if not rejected:
                raise ValueError('app-fixture-wrong-subject-accepted')
            failure = json.loads((stages[0] / 'output/failure.json').read_bytes())
            if failure != {'invocation': stages[0].name, 'stage': 'native-failed'}:
                raise ValueError('app-fixture-negative-native-unobserved')
        if observe is not None:
            from pr313_observations import quiescent
            case = 'signed-app' if app == 'external-app' else 'wrong-app'
            outcome = 'owner-validated' if app == 'external-app' else 'rejected'
            observe({'caseId': case, 'phase': 'native-complete', 'outcome': outcome,
                'managerInvocationId': manager['invocationId'], 'quiescent': quiescent(),
                'attackWitness': {'operation': 'app-projection', 'operationMarker': case,
                    'ownerOutcome': outcome, 'stdoutDigest': hashlib.sha256(
                        (stages[0] / 'invocation.json').read_bytes()).hexdigest(),
                    'startedMonotonicNs': started_ns, 'finishedMonotonicNs': time.monotonic_ns()}})
        operations.append(context['operationId'])
    (root / 'observation.json').write_text(json.dumps({'kind': 'synthetic-installed-signed-app-observation',
        'productionEligible': False, 'originalProviderProof': 'synthetic', 'bundleIdentity': identity,
        'originalDigest': artifact.coordinates['artifactDigest'], 'operationIds': operations}, sort_keys=True))
    return ['installed-signed-app-projection-owner-validated', 'installed-signed-app-wrong-subject-rejected']

"""Malicious synthetic exporter bytes through the real native collector and projection owner.

No Java signature claim is made: this is a selected test exporter adversary. The real signed
Java positive and negative ladder remains mandatory independently. Public rows are constructed
from closed fixed fields; raw stdout, output and private state stay in the disposable guest.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

CASES = ('public-malformed', 'public-claimed-accepted', 'public-private-fields', 'public-wrong-subject')


def run(case, root, identity):
    import restricted_native as native
    import app_subject_projection as projection
    import original_artifact_authentication as original
    from pr312_app_projection import _artifact, _quiescent
    from pr313_faults import _lifecycle_fixture
    if case not in CASES:
        raise ValueError('unknown-fixed-public-case')
    if (os.geteuid() != 0 or not Path(native.__file__).resolve().is_relative_to('/opt')
            or not Path('/opt/cryptad-restricted-test-kit/.test-kit.json').is_file()):
        raise ValueError('installed-disposable-test-kit-required')
    detected = subprocess.run(['/usr/bin/systemd-detect-virt', '--vm'], capture_output=True,
                              check=True, timeout=5, env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
    if detected.stdout != b'qemu\n':
        raise ValueError('reference-guest-required')
    root = Path(root)
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    jdk, tools, inputs, work = _lifecycle_fixture(root)
    fixture = root / 'fixture'
    fixture.mkdir(mode=0o700)
    for name in ('external.properties', 'external.signature', 'external-app.zip', 'submission.zip'):
        (fixture / name).write_bytes(b'public-synthetic-selected-input')
    artifact, names = _artifact(original, fixture)
    canary = 'synthetic-private-' + secrets.token_hex(16)
    payload = adversarial_payload(case, projection, canary)
    exporter = tools / 'bin/crypta-app'
    exporter.write_text('#!/usr/bin/python3\nfrom pathlib import Path\n'
        + 'Path("/output/projection.json").write_bytes(' + repr(payload) + ')\n'
        + 'print(' + repr(canary) + ', flush=True)\n')
    exporter.chmod(0o500)
    context = {'operationId': secrets.token_hex(32), 'registrationDigest': 'sha256:' + '0' * 64,
               'bundleIdentity': identity, 'deadlineMonotonic': time.monotonic() + 60}
    before = set(native.ROOT.iterdir())
    rejected = False
    with native.owning_boundary(context=context):
        try:
            projection.produce(artifact, names, exporter=exporter,
                exporter_digest='sha256:' + hashlib.sha256(exporter.read_bytes()).hexdigest(),
                app_id='expected-app', catalog_key_id='synthetic',
                catalog_keys=inputs / 'catalog-keys', publisher_keys=inputs / 'publisher-keys',
                reviewer_keys=None, private_root=work, java_home=jdk, maintenance_tool_root=tools)
        except projection.ProjectionFailure:
            rejected = True
    _quiescent(native)
    stages = [p for p in set(native.ROOT.iterdir()) - before if p.is_dir()]
    if not rejected or len(stages) != 1 or not (stages[0] / 'complete.json').is_file():
        raise ValueError('public-semantic-attack-not-collected-and-rejected')
    stage = stages[0]
    if (native._read_output(stage / 'output/stdout', 8192) != (canary + '\n').encode()
            or native._read_output(stage / 'output/projection.json', 32768) != payload):
        raise ValueError('public-adversary-output-not-observed')
    result = {'caseId': case, 'phase': 'owner-semantic-validation', 'outcome': 'rejected',
              'managerInvocationId': json.loads((stage / 'manager.json').read_bytes())['invocationId'],
              'attackWitness': {'candidateOutput': 'collected', 'semanticOwner': 'rejected',
                                'publicFields': 'closed', 'privateCanary': 'absent',
                                'candidateOutputDigest': 'sha256:' + hashlib.sha256(payload).hexdigest(),
                                'stdoutDigest': 'sha256:' + hashlib.sha256((canary + '\n').encode()).hexdigest()},
              'quiescent': {'activeState': native._manager('show')['ActiveState'],
                            'cgroupPopulated': False, 'activeRecordPresent': False}}
    public = json.dumps(result, sort_keys=True).encode()
    if canary.encode() in public or payload in public:
        raise ValueError('public-projection-canary-exposed')
    descriptor = os.open(root / 'observation.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(public)
    return result


def adversarial_payload(case, projection, canary):
    if case == 'public-malformed':
        payload = ('{invalid:' + canary).encode()
    elif case == 'public-claimed-accepted':
        payload = json.dumps({'accepted': True, 'authority': 'production', 'detail': canary}).encode()
    elif case == 'public-private-fields':
        payload = json.dumps({'privateState': canary, 'message': 'ordinary private prose ' + canary}).encode()
    else:
        declaration = {key: None for key in projection.DECLARATION_FIELDS}
        for key in ('bundleDigest', 'manifestDigest', 'signedContentDigest', 'signatureDigest',
                    'publisherFingerprint', 'catalogDigest', 'catalogSignatureDigest'):
            declaration[key] = 'sha256:' + '0' * 64
        declaration.update(schemaVersion=1, kind='signed-app-subject-projection', appId='wrong-app',
            appVersion='1', publisherId='synthetic', catalogId='synthetic', catalogKeyId='synthetic',
            bundleSize=1, targetStability='stable', experimentalCapabilitiesAccepted=False,
            requiredCapabilities=[], optionalCapabilities=[])
        projection.validate_declaration(declaration)
        payload = json.dumps(declaration).encode()
    return payload

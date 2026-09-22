#!/usr/bin/python3
"""Run one fresh synthetic reference guest; never provision the development host.

The administrator supplies an already prepared Debian image, extracted QEMU distribution and
ephemeral SSH key. Every invocation creates a new overlay and retains private diagnostics. This
driver does not download packages, access production providers, or publish evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

import pr313_boot_inputs as boot


PRODUCTS = ('build/cryptad-dist', 'platform-devtools/build/install/crypta-app',
            'platform-api/build/libs')
# Prospective candidate VM environment after a trusted fixture SIGILL under TCG/max.
# The finite max/qemu64 short diagnostics both passed, but a later qemu64 cohort reproduced
# SIGILL. This narrower advertised ISA is not a fix and changes neither JVM options nor either
# installed service's security profile. A single-thread TCG cohort exceeded its fixed deadline.
CPU_MODEL = 'qemu64'
ACCELERATOR = 'tcg,thread=multi'
PROFILES = {'tcg-multi': 'tcg,thread=multi', 'tcg-single': 'tcg,thread=single'}
GUEST_STAGES = frozenset(('installation', 'installation-export',
    'dependency-profile-measurement', 'installation-publication', 'installed-profile-verification',
    'production-test-kit-separation', 'socket-listening', 'production-bootstrap-readiness',
    'socket-admission', 'legacy-probes-unavailable', 'installed-keyless-sandbox-probe',
    'installed-package-api-owner-validation', 'installed-app-projection-owner-validation',
    'native-cms-owning-consumer', 'installed-native-hostile-fixtures',
    'installed-projection-output-hostile-fixtures', 'production-restart-readiness'))
GUEST_DIMENSIONS = (GUEST_STAGES & frozenset(('installation-export',
    'dependency-profile-measurement', 'installation-publication', 'installed-profile-verification',
    'production-test-kit-separation', 'socket-listening'))) | frozenset((
    'installed-bundle-and-effective-profile-verified', 'actual-role-dac-denials',
    'actual-role-capability-denials', 'actual-socket-unknown-handle-denied',
    'actual-socket-wrong-uid-denied', 'installed-production-bootstrap-notify-ready',
    'installed-keyless-fixed-native-probe', 'installed-real-package-api-export-owner-validated',
    'installed-signed-app-projection-owner-validated', 'installed-signed-app-wrong-subject-rejected',
    'real-maintenance-cms-signed-native-owning-consumer-with-synthetic-provider',
    'installed-worker-socket-preparation-and-restart-exact-retry-with-synthetic-provider',
    'installed-synthetic-native-setid-stripped', 'installed-synthetic-native-filecap-no-gain',
    'installed-synthetic-native-openat2-safe-and-hostile',
    'installed-synthetic-output-device-creation-denied')) | frozenset(
    'installed-synthetic-native-' + mode for mode in ('positive', 'cross-operation',
    'synthetic-revocation', 'lost-start-response', 'overflow', 'timeout', 'descendant',
    'unexpected-output')) | frozenset('installed-synthetic-output-' + mode for mode in
    ('control', 'symlink', 'hardlink-roster', 'fifo', 'socket', 'oversize',
     'race-timeout', 'open-output-timeout'))


def guest_summary(value):
    """Translate untrusted guest output through closed enums and an exact digest shape."""
    if not isinstance(value, dict):
        return {}
    result = {}
    stage = value.get('failedStage')
    if isinstance(stage, str) and stage in GUEST_STAGES:
        result['guestFailedStage'] = stage
    identity = value.get('bundleIdentity')
    if isinstance(identity, str) and re.fullmatch('[0-9a-f]{64}', identity):
        result['installedBundleIdentity'] = identity
    dimensions = value.get('dimensions')
    if isinstance(dimensions, list) and len(dimensions) <= 128:
        result['completedDimensions'] = sorted({entry for entry in dimensions
            if isinstance(entry, str) and entry in GUEST_DIMENSIONS})
    return result
BASELINE = r'''
import json, os, pathlib, subprocess, sys, tempfile
source = pathlib.Path('/root/cryptad')
sys.path.insert(0, str(source / 'tools/release-certification/restricted'))
import disposable_integration as h
h.load_installation(source)
os.environ.update(PYTHONDONTWRITEBYTECODE='1')
sys.dont_write_bytecode = True
result = {'schemaVersion': 1, 'kind': 'pr312-installed-baseline', 'executed': True,
          'productionAuthorityObserved': False, 'mandatoryIsolationTestSatisfied': False,
          'bootstrapReady': False, 'stage': 'installation', 'status': 'failed'}
try:
    with tempfile.TemporaryDirectory(dir='/root') as temporary:
        result['bundleIdentity'] = h.provision(source, pathlib.Path(temporary))
        result['stage'] = 'socket-listening'
        h.call(['/usr/bin/systemctl', 'start', 'cryptad-restricted.service'], timeout=180)
        result['stage'] = 'bounded-unknown-handle-request'
        client = str(h.INSTALLED / 'tools/release-certification/protected/restricted_client.py')
        script = "import subprocess,sys; p=subprocess.run(['/usr/bin/python3','-I','-S',sys.argv[1],'collect','0'*64],capture_output=True,timeout=60); assert p.returncode==2 and p.stdout==b'' and p.stderr==b'restricted-operation-unavailable\\n'"
        h.as_role('cryptad-runner', script, arguments=(client,), timeout=70)
        result['status'] = 'unknown-handle-denied-readiness-not-instrumented'
except Exception:
    pass
finally:
    print(json.dumps(result, sort_keys=True))
'''


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def command(arguments, *, timeout=120, **options):
    options.setdefault("env", boot.ENVIRONMENT)
    return subprocess.run(boot.invocation(arguments, options.get("env", {})), check=True, stdin=subprocess.DEVNULL,
                          timeout=timeout, **options)


def require_standalone_image(image, qemu_img, environment):
    """A file digest binds guest storage only when QCOW2 has no external dependencies."""
    result = command([str(qemu_img), 'info', '--output=json', '-f', 'qcow2', str(image)],
                     env=environment, capture_output=True)
    metadata = json.loads(result.stdout)
    specific = metadata.get('format-specific', {})
    data = specific.get('data', {})
    if (metadata.get('format') != 'qcow2'
            or any(key in metadata for key in ('backing-filename', 'full-backing-filename',
                                               'backing-filename-format', 'data-file'))
            or 'data-file' in data):
        raise ValueError('prepared-image-not-standalone')


def verified_image_copy(source, destination, expected_digest, qemu_img, environment):
    """Boot from the private verified copy, never a subsequently replaced caller path."""
    with Path(source).open('rb') as incoming, Path(destination).open('xb') as outgoing:
        shutil.copyfileobj(incoming, outgoing)
    if sha256(destination) != expected_digest:
        raise ValueError('prepared-image-identity-mismatch')
    require_standalone_image(destination, qemu_img, environment)
    return destination


def snapshot_file(source, destination, algorithm='sha256'):
    """Copy one opened source inode and identify the private bytes actually consumed."""
    with Path(source).open('rb') as incoming, Path(destination).open('xb') as outgoing:
        shutil.copyfileobj(incoming, outgoing)
    with Path(destination).open('rb') as retained:
        return hashlib.file_digest(retained, algorithm).hexdigest()


def snapshot_products(source, clone):
    """Record the product bytes in the private tree that will enter the guest archive."""
    for relative in PRODUCTS:
        destination = clone / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source / relative, destination, symlinks=False)
    return sha256(clone / 'build/cryptad-dist/lib/cryptad.jar')


def verify_product_source(source, clone, commit, expected_digest):
    """Check local Git and the copied package marker; this is not build/release attestation."""
    if not isinstance(commit, str) or re.fullmatch('[0-9a-f]{40}', commit) is None:
        raise ValueError('reference-product-source-invalid')
    resolved = command(['git', '-C', str(source), 'rev-parse', '--verify', commit + '^{commit}'],
                       capture_output=True).stdout.decode().strip()
    if resolved != commit:
        raise ValueError('reference-product-source-mismatch')
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'interop'))
    try:
        import cross_version_runtime as runtime
        try:
            observed = runtime.packaged_daemon_identity(clone / 'build/cryptad-dist', resolved)
        except runtime.RuntimeFailure:
            raise ValueError('reference-product-source-mismatch') from None
    finally:
        sys.path.pop(0)
    if observed != 'sha256:' + expected_digest:
        raise ValueError('reference-product-digest-mismatch')
    return resolved


def snapshot_executables(sources, output):
    directory = output / 'tools'
    directory.mkdir(mode=0o700)
    result = {}
    for name, source in sources.items():
        destination = directory / name
        snapshot_file(source, destination)
        destination.chmod(0o500)
        result[name] = destination
    return result


def qemu_arguments(root, attempt, prepared, seed, port):
    """Fixed guest hardware/network; callers cannot supply units, mounts, or candidate commands."""
    return [str(root / 'usr/bin/qemu-system-x86_64'), '-name', 'pr312-disposable',
            '-machine', 'pc,smm=off', '-accel', ACCELERATOR, '-cpu', CPU_MODEL,
            '-smp', '4', '-m', '5632', '-L', str(root / 'usr/share/qemu'),
            '-bios', str(root / 'usr/share/seabios/bios-256k.bin'),
            '-drive', f'file={attempt / "guest.qcow2"},if=virtio,format=qcow2',
            '-drive', f'file={seed},media=cdrom,format=raw,readonly=on',
            '-netdev', f'user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:{port}-:22',
            '-device', 'virtio-net-pci,netdev=net0,romfile=', '-vga', 'none',
            '-display', 'none', '-serial', f'file:{attempt / "serial.private.log"}',
            '-monitor', 'none', '-no-user-config']


def fixture_summary(value):
    """Export only fixed diagnostic classifications, never private command identities."""
    if not isinstance(value, dict) or not isinstance(value.get('commands'), list):
        return []
    allowed = {'fatalSignal': {'SIGILL', 'SIGSEGV', 'unclassified'},
               'failureClass': {'jvm-sigill', 'jvm-sigsegv', 'producer-command-failed'},
               'fatalFrame': {'split-constant-pool-entry', 'regex-branch-match',
                              'long-rotate-right', 'unclassified'}}
    rows = []
    for record in value['commands'][:128]:
        if not isinstance(record, dict):
            continue
        row = {key: record[key] for key, choices in allowed.items()
               if isinstance(record.get(key), str) and record[key] in choices}
        if len(row) == len(allowed) and row not in rows:
            rows.append(row)
    return rows


def public_report(report):
    """Construct a closed export; never forward guest JSON, exceptions or console output."""
    if report.get('mode') == 'workload-positive':
        # Workload selections and all correlatable private identities remain private.
        return {'schemaVersion': 1, 'kind': 'pr315-workload-reference-attempt',
                'executed': report.get('executed') is True,
                'status': 'transport-completed' if report.get('status') == 'guest-report-retained'
                          else 'setup-or-execution-failed',
                'guestStopped': report.get('guestStopped') is True,
                'installedWorkloadAcceptanceSatisfied': False,
                'protectedExecutionEnabled': False, 'phaseComplete': False}
    fields = ('schemaVersion', 'kind', 'executed', 'status', 'stage', 'helperSourceCommit',
              'helperSourceTree', 'productSourceCommit', 'productSourceVerification',
              'productDigest', 'sourceArchiveDigest',
              'preparedImageDigest', 'qemuSha256', 'qemuImgSha256',
              'guestExitCode', 'guestStopped', 'mode', 'developmentSnapshot',
              'sshHostKeyPinOrigin', 'cpuModel', 'accelerator')
    output = {key: report[key] for key in fields if key in report}
    output.update(guest_summary(report.get('guestSummary')))
    output['trustedFixtureDiagnostics'] = fixture_summary(report.get('fixtureDiagnostics'))
    output.update(productionAuthorityObserved=False, mandatoryIsolationTestSatisfied=False,
                  installedKeylessNativeAcceptanceSatisfied=False,
                  cpuModel=CPU_MODEL, accelerator=ACCELERATOR)
    return output


def expected_installation(source, output, commit):
    """Independently derive source/product export and separate test-kit bytes on the host."""
    import installation
    bundle = output / 'expected-bundle'
    installation.plan(source, bundle)
    for relative in PRODUCTS:
        destination = bundle / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source / relative, destination, symlinks=False)
    manifest = installation.read_json(bundle / installation.MANIFEST)
    manifest['files'] = installation.inventory(bundle)
    expected_bundle = installation.digest(installation.encode(manifest))
    records = {}
    entries = command(['git', '-C', str(source), 'ls-tree', '-r', '-z', '--name-only', commit],
                      capture_output=True).stdout.split(b'\0')
    for raw in entries:
        if raw:
            name = os.fsdecode(raw)
            if not installation.production_member(Path(name)):
                records[name] = sha256(source / name)
    kit = {'schemaVersion': 1, 'kind': 'synthetic-disposable-test-kit', 'sourceCommit': commit,
           'productionEligible': False, 'files': records}
    return expected_bundle, hashlib.sha256(json.dumps(kit, sort_keys=True).encode()).hexdigest()


def verified_attempt_identity(report, attempt, expected_bundle, expected_kit):
    """Pinned SSH transports installed verification; local bytes bind the helper and kit."""
    import installation
    execution = installation.read_json(attempt / 'execution.private.json')
    kit_path = attempt / 'test-kit.private.json'
    verified = installation.read_json(attempt / 'installed-verification.private.json')
    if (execution['sourceCommit'] != report['helperSourceCommit']
            or execution['bundleIdentity'] != expected_bundle
            or sha256(kit_path) != expected_kit
            or verified != {'bundleIdentity': expected_bundle, 'sourceCommit': report['helperSourceCommit'],
                'executionClosureDigest': 'sha256:' + installation.digest(installation.encode(execution['dependencies']))}):
        raise ValueError('installed-identity-substituted')
    boot_record = installation.read_json(attempt / 'boot-inputs.private.json')
    closure = {'files': boot_record['files'],
               'privateInputs': {key: boot_record['bootInputs'][key] for key in
                   ('seedDigest', 'sshHostKeyPinDigest', 'sshKeyDigest')}, 'machine': 'pc,smm=off', 'cpu': CPU_MODEL,
               'accelerator': ACCELERATOR, 'vcpus': 4, 'memoryMiB': 5632}
    return {key: report[key] for key in ('helperSourceCommit', 'helperSourceTree', 'productSourceCommit',
        'productDigest', 'preparedImageDigest', 'fixtureManifestDigest')} | {
        'bundleIdentity': expected_bundle, 'testKitDigest': expected_kit,
        'profileDigest': installation.digest(installation.encode(execution['dependencies'])),
        'bootClosureDigest': installation.digest(installation.encode(closure))}


def identity_observations(identity):
    from pr313_acceptance import CASES
    rows = []
    for name, witness in (
        ('reference-identity', {'storageFormat': 'qcow2', 'backingFiles': [], 'externalDataFiles': [],
            'snapshotVerified': 'exact-private-copy', **{key: identity[key] for key in
                ('bootClosureDigest', 'preparedImageDigest')}}),
        ('installed-identity', {'testKitLocation': 'separate-administrator-owned',
            **{key: identity[key] for key in ('bundleIdentity', 'testKitDigest', 'profileDigest')}})):
        case = CASES[name]
        rows.append({'caseId': name, 'phase': case.phase, 'outcome': case.outcome,
            'managerInvocationId': None, 'attackWitness': witness,
            'quiescent': {'activeState': 'inactive', 'cgroupPopulated': False, 'activeRecordPresent': False}})
    return rows


def run(args):
    global ACCELERATOR
    selected_profile = getattr(args, 'profile', 'tcg-multi')
    if selected_profile not in PROFILES:
        raise ValueError('reference-profile-invalid')
    ACCELERATOR = PROFILES[selected_profile]
    if getattr(os, 'geteuid', lambda: 0)() == 0:
        raise ValueError('reference-unprivileged-host-required')
    attempt = args.attempt.absolute()
    if any(character in str(attempt) for character in (',', '\n', '\r', '\x00')):
        raise ValueError('reference-output-path-invalid')
    attempt.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.umask(0o077)
    report = {'schemaVersion': 7, 'kind': 'pr312-reference-vm-attempt', 'executed': False,
              'status': 'failed', 'stage': 'preparation', 'guestStopped': True, 'mode': args.mode,
              'developmentSnapshot': args.development_snapshot, 'cpuModel': CPU_MODEL,
              'accelerator': ACCELERATOR}
    process = None
    log = (attempt / 'driver.private.log').open('xb')
    try:
        source = args.source.resolve(strict=True)
        def git(*arguments):
            return command(['git', '-C', str(source), *arguments], capture_output=True).stdout.decode().strip()
        if git('status', '--porcelain', '--untracked-files=normal'):
            raise ValueError('exact-clean-source-required')
        report.update(helperSourceCommit=git('rev-parse', 'HEAD'),
                      helperSourceTree=git('rev-parse', 'HEAD^{tree}'))
        report['stage'] = 'prepared-image-identity'
        root = args.qemu_root.resolve(strict=True)
        env = {**boot.ENVIRONMENT, 'LD_LIBRARY_PATH': str(root / 'usr/lib/x86_64-linux-gnu'),
               'QEMU_MODULE_DIR': str(root / 'usr/lib/x86_64-linux-gnu/qemu')}
        executables = snapshot_executables({name: root / 'usr/bin' / name
            for name in ('qemu-img', 'qemu-system-x86_64')}, attempt)
        qemu_img = executables['qemu-img']
        qemu = executables['qemu-system-x86_64']
        report.update(qemuSha256=sha256(qemu), qemuImgSha256=sha256(qemu_img))
        report['stage'] = 'boot-runtime-snapshot'
        root, env = boot.snapshot_runtime(root, attempt, executables)
        report['stage'] = 'prepared-image-identity'
        prepared = verified_image_copy(args.prepared_image, attempt / 'prepared.qcow2',
            args.prepared_image_digest, qemu_img, env)
        report['preparedImageDigest'] = args.prepared_image_digest
        report['sshHostKeyPinDigest'] = snapshot_file(args.known_hosts, attempt / 'known_hosts')
        report['sshHostKeyPinOrigin'] = args.host_key_pin_origin
        report['stage'] = 'seed-snapshot'
        seed = attempt / 'seed.iso'
        report['seedDigest'] = snapshot_file(args.seed, seed)
        key = attempt / 'guest-key'
        key_digest = snapshot_file(args.ssh_key, key)
        boot.record_private_inputs(attempt, preparedImageDigest=args.prepared_image_digest,
            seedDigest=report['seedDigest'], sshHostKeyPinDigest=report['sshHostKeyPinDigest'],
            sshKeyDigest=key_digest, cpuModel=CPU_MODEL, accelerator=ACCELERATOR,
            machine='pc,smm=off', vcpus=4, memoryMiB=5632)
        helper_names = ['pr312_reference_vm.py', 'pr313_boot_inputs.py', 'pr313_fixtures.py', 'installation.py']
        if args.mode == 'workload-positive':
            helper_names.extend(('pr315_workload_fixtures.py', 'pr315_workload_guest.py'))
        for name in helper_names:
            if sha256(Path(__file__).resolve().parent / name) != sha256(source / 'tools/release-certification/restricted' / name):
                raise ValueError('executing-reference-source-mismatch')
        clone = attempt / 'cryptad'
        report['stage'] = 'source-clone'
        command(['git', 'clone', '--no-hardlinks', '--no-checkout', str(source), str(clone)],
                stdout=log, stderr=log)
        command(['git', '-C', str(clone), 'checkout', '--detach', report['helperSourceCommit']],
                stdout=log, stderr=log)
        report['productDigest'] = snapshot_products(source, clone)
        report['stage'] = 'product-source-verification'
        report['productSourceCommit'] = verify_product_source(source, clone,
            args.product_source_commit, report['productDigest'])
        report['productSourceVerification'] = 'local-git-and-embedded-marker-v1'
        if args.prepared_fixtures is not None:
            if args.mode == 'workload-positive':
                import pr315_workload_fixtures as fixture_module
                fixtures = clone / 'build/pr315-inputs'
            else:
                import pr313_fixtures as fixture_module
                fixtures = clone / 'build/pr313-inputs'
            fixtures.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(args.prepared_fixtures, fixtures, symlinks=True)
            fixture_module.verify(fixtures, args.fixture_manifest_digest, clone,
                                  args.product_source_commit)
            report['fixtureManifestDigest'] = args.fixture_manifest_digest
        expected_bundle, expected_kit = expected_installation(clone, attempt, report['helperSourceCommit'])
        archive = attempt / 'source.tar.gz'
        report['stage'] = 'source-archive'
        command(['tar', '-czf', str(archive), '-C', str(attempt), 'cryptad'], stdout=log, stderr=log)
        report['sourceArchiveDigest'] = sha256(archive)
        report['stage'] = 'guest-overlay'
        command([str(qemu_img), 'create', '-f', 'qcow2', '-F', 'qcow2',
                 '-b', str(prepared), str(attempt / 'guest.qcow2')],
                env=env, stdout=log, stderr=log)
        arguments = qemu_arguments(root, attempt, prepared, seed, args.port)
        arguments[0] = str(qemu)
        boot.record_private_inputs(attempt, emulatorArguments=arguments)
        process = subprocess.Popen(boot.invocation(arguments, env),
                                   env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        report.update(executed=True, guestStopped=False, stage='guest-boot')
        ssh = ['ssh', '-F', '/dev/null', '-i', str(key), '-p', str(args.port),
               '-o', 'IdentitiesOnly=yes', '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes',
               '-o', 'StrictHostKeyChecking=yes',
               '-o', 'UserKnownHostsFile=' + str(attempt / 'known_hosts'),
               '-o', 'ConnectTimeout=5', '-o', 'BatchMode=yes', 'vmadmin@127.0.0.1']
        deadline = time.monotonic() + 180
        while True:
            probe = subprocess.run([*ssh, 'true'], stdin=subprocess.DEVNULL,
                                   stdout=log, stderr=log, timeout=10, env=boot.ENVIRONMENT)
            if probe.returncode == 0:
                if process.poll() is not None:
                    raise ValueError('owned-guest-unavailable')
                break
            if process.poll() is not None or time.monotonic() >= deadline:
                raise ValueError('guest-boot-unavailable')
            time.sleep(2)
        report['stage'] = 'source-transfer'
        with archive.open('rb') as stream:
            subprocess.run([*ssh, 'cat > /home/vmadmin/source.tar.gz'], stdin=stream,
                           stdout=log, stderr=log, check=True, timeout=180, env=boot.ENVIRONMENT)
        script = 'set -eu\numask 022\nsudo systemctl start dbus.service polkit.service\n'
        script += 'test "$(sha256sum /home/vmadmin/source.tar.gz | cut -d " " -f 1)" = ' + report['sourceArchiveDigest'] + '\n'
        script += 'sudo test ! -e /root/cryptad\nsudo tar --no-same-owner -xzf /home/vmadmin/source.tar.gz -C /root\n'
        script += ('install -m 0600 /dev/null /home/vmadmin/report.json\n'
                   'install -m 0600 /dev/null /home/vmadmin/driver.private.log\n')
        if args.mode == 'baseline':
            script += "sudo /usr/bin/python3 - <<'PR312_DRIVER' > /home/vmadmin/report.json 2>/home/vmadmin/driver.private.log\n" + BASELINE + '\nPR312_DRIVER\n'
        elif args.mode == 'workload-positive':
            script += ('sudo /usr/bin/python3 /root/cryptad/tools/release-certification/restricted/'
                       'pr315_workload_guest.py --fixture-manifest-digest '
                       + args.fixture_manifest_digest + ' --product-source-commit '
                       + args.product_source_commit
                       + ' > /home/vmadmin/report.json 2>/home/vmadmin/driver.private.log\n')
        else:
            script += ('sudo /usr/bin/python3 /root/cryptad/tools/release-certification/restricted/disposable_integration.py '
                       '--disposable-vm --source /root/cryptad --product-source-commit '
                       + args.product_source_commit + ' --' + args.mode
                       + (' --case-group ' + args.case_group if args.case_group else '')
                       + (' --fault-case ' + args.fault_case if args.fault_case else '')
                       + (' --prepared-fixtures /root/cryptad/build/pr313-inputs --fixture-manifest-digest '
                          + args.fixture_manifest_digest if args.prepared_fixtures is not None else '')
                       + ' > /home/vmadmin/report.json 2>/home/vmadmin/driver.private.log\n')
        report['stage'] = 'installed-' + args.mode
        result = subprocess.run([*ssh, 'bash -s'], input=script.encode(), stdout=log, stderr=log,
                                timeout=args.timeout, env=boot.ENVIRONMENT)
        report['guestExitCode'] = result.returncode
        with (attempt / 'guest-report.private.json').open('xb') as stream:
            command([*ssh, 'cat /home/vmadmin/report.json'], stdout=stream, stderr=log)
        guest_path = attempt / 'guest-report.private.json'
        if guest_path.stat().st_size <= 65536:
            try:
                report['guestSummary'] = json.loads(guest_path.read_bytes())
            except (ValueError, UnicodeError):
                pass
        with (attempt / 'guest-profile.private.txt').open('xb') as stream:
            command([*ssh, 'sudo systemctl show cryptad-restricted.service '
                '--property=Type,NotifyAccess,ActiveState,SubState,MainPID,Result,ExecMainStatus; '
                'uname -r; /usr/lib/systemd/systemd --version | head -n 1; '
                '/usr/bin/python3 --version; /usr/bin/bwrap --version; /usr/local/bin/java -version'],
                stdout=stream, stderr=log)
        diagnostics = """import json,pathlib
root=pathlib.Path('/var/lib/cryptad-restricted/bootstrap')
records=[]
if root.is_dir():
 for path in sorted(root.glob('*.jsonl'))[:16]:
  if path.is_symlink() or path.stat().st_size>16384: continue
  for line in path.read_bytes().splitlines()[:32]:
   try: value=json.loads(line)
   except (ValueError,UnicodeError): continue
   records.append({k:value[k] for k in ('stage','status') if k in value})
print(json.dumps(records))
"""
        with (attempt / 'bootstrap-stages.private.json').open('xb') as stream:
            subprocess.run([*ssh, "sudo /usr/bin/python3 -I -S -"], input=diagnostics.encode(),
                           stdout=stream, stderr=log, check=True, timeout=15, env=boot.ENVIRONMENT)
        with (attempt / 'installation-failure.private.json').open('xb') as stream:
            command([*ssh, 'sudo test ! -f /root/pr312-installation-failure.json || '
                     'sudo head -c 1024 /root/pr312-installation-failure.json'],
                    stdout=stream, stderr=log, timeout=15)
        for label, remote, maximum in (
                ('fixture-commands.private.json', '/root/pr313-fixture-commands.private.json', 262144),
                ('pr313-observation.private.json', '/root/pr313-observation.private.json', 65536),
                ('pr314-workload-observation.private.json', '/root/pr314-workload-observation.private.json', 65536),
                ('pr315-workload-memory.private.json', '/root/pr315-workload-memory.private.json', 65536),
                ('pr315-workload-volatile.private.json', '/root/pr315-workload-volatile.private.json', 262144),
                ('test-kit.private.json', '/opt/cryptad-restricted-test-kit/.test-kit.json', 1048576),
                ('execution.private.json', '/opt/cryptad-cross-version/restricted-execution.json', 8388608),
                ('native-consumer.private.log', '/root/pr312-native-consumer.private.log', 65536),
                ('guest-driver.private.log', '/home/vmadmin/driver.private.log', 65536),
                ('package-observation.private.json', '/root/pr312-package-api/observation.json', 16384),
                ('app-observation.private.json', '/root/pr312-app-projection/observation.json', 16384),
                ('app-compile-stdout.private', '/root/pr312-app-projection/compile-stdout.private', 65536),
                ('app-compile-stderr.private', '/root/pr312-app-projection/compile-stderr.private', 65536),
                ('app-generate-stdout.private', '/root/pr312-app-projection/generate-stdout.private', 65536),
                ('app-generate-stderr.private', '/root/pr312-app-projection/generate-stderr.private', 65536)):
            with (attempt / label).open('xb') as stream:
                command([*ssh, 'sudo test ! -f ' + remote + ' || sudo head -c ' + str(maximum) + ' ' + remote],
                        stdout=stream, stderr=log, timeout=15)
        verification_script = ("import sys,json; from pathlib import Path; "
            "sys.path.insert(0,str(Path('/opt/cryptad-cross-version/current').resolve()/'tools/release-certification/restricted')); "
            "import installation; print(json.dumps(installation.verify_execution(),sort_keys=True))")
        diagnostic_path = attempt / 'fixture-commands.private.json'
        if diagnostic_path.stat().st_size:
            import installation
            report['fixtureDiagnostics'] = installation.read_json(diagnostic_path)
        with (attempt / 'installed-verification.private.json').open('xb') as stream:
            subprocess.run([*ssh, 'sudo /usr/bin/python3 -I -S -B -'], input=verification_script.encode(),
                           stdout=stream, stderr=log, check=True, timeout=120, env=boot.ENVIRONMENT)
        if args.prepared_fixtures is not None:
            report['hostVerifiedIdentity'] = verified_attempt_identity(report, attempt, expected_bundle, expected_kit)
            if args.mode != 'workload-positive' and getattr(args, 'case_group', None) == 'positive':
                evidence_path = attempt / 'pr313-observation.private.json'
                rows = json.loads(evidence_path.read_bytes())
                if not isinstance(rows, list):
                    raise ValueError('invalid-case-observations')
                rows = identity_observations(report['hostVerifiedIdentity']) + rows
                evidence_path.write_text(json.dumps(rows, sort_keys=True) + '\n')
        native_diagnostics = """import base64,json,os,pathlib,stat
root=pathlib.Path('/var/lib/cryptad-restricted-native'); result=[]; remaining=1048576
if root.is_dir():
 for stage in sorted(root.iterdir())[:65]:
  if not stage.is_dir() or stage.is_symlink(): continue
  row={}
  for name in ('stdout','stderr'):
   try:
    fd=os.open(stage/'diagnostics'/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
   except OSError: continue
   try:
    info=os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1: continue
    raw=os.read(fd,min(65536,remaining)); remaining-=len(raw)
    row[name]=base64.b64encode(raw).decode('ascii')
   finally: os.close(fd)
  if row: result.append(row)
  if remaining<=0: break
print(json.dumps(result))
"""
        with (attempt / 'native-diagnostics.private.json').open('xb') as stream:
            subprocess.run([*ssh, 'sudo /usr/bin/python3 -I -S -'], input=native_diagnostics.encode(),
                           stdout=stream, stderr=log, check=True, timeout=15, env=boot.ENVIRONMENT)
        controller_diagnostics = """import json,os,pathlib,stat
root=pathlib.Path('/var/lib/cryptad-restricted/operations'); rows=[]
if root.is_dir():
 for path in sorted(root.iterdir())[:65]:
  if path.is_symlink() or not path.is_dir(): continue
  try: fd=os.open(path/'controller-failure.private.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  except FileNotFoundError: continue
  try:
   info=os.fstat(fd)
   if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>1024: continue
   value=json.loads(os.read(fd,1024))
   if value.get('phase')!='synthetic-worker-main': continue
   if value.get('category') not in ('socket-activation-rejected','controller-failed'): continue
   rows.append({'operationId':path.name,'phase':'synthetic-worker-main','category':value['category']})
  finally: os.close(fd)
print(json.dumps(rows))
"""
        with (attempt / 'controller-failures.private.json').open('xb') as stream:
            subprocess.run([*ssh, 'sudo /usr/bin/python3 -I -S -B -'], input=controller_diagnostics.encode(),
                           stdout=stream, stderr=log, check=True, timeout=15, env=boot.ENVIRONMENT)
        # Completion of transport is separate from bootstrap/native acceptance in the guest report.
        report['status'] = 'guest-report-retained' if result.returncode == 0 else 'guest-operation-failed'
        subprocess.run([*ssh, 'sudo poweroff'], stdin=subprocess.DEVNULL, stdout=log, stderr=log, timeout=20, env=boot.ENVIRONMENT)
    except (OSError, ValueError, subprocess.SubprocessError):
        report['status'] = 'failed'
    finally:
        if process is not None:
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
            report['guestStopped'] = process.poll() is not None
        log.close()
        (attempt / 'attempt.private.json').write_text(json.dumps(report, sort_keys=True) + '\n')
        (attempt / 'stage-report.json').write_text(json.dumps(public_report(report), indent=2) + '\n')
    print(json.dumps(public_report(report), sort_keys=True))
    return 0 if report['status'] == 'guest-report-retained' else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'attempt', 'prepared-image', 'qemu-root', 'seed', 'ssh-key', 'known-hosts'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--product-source-commit', required=True)
    from pr313_faults import CASES as NATIVE_CASES
    from pr313_worker_faults import CASES as WORKER_CASES
    from pr313_public_faults import CASES as PUBLIC_CASES
    CASES = NATIVE_CASES + WORKER_CASES + PUBLIC_CASES
    parser.add_argument('--case-group', choices=('positive', 'native-hostile', 'output-hostile', 'fault', 'worker', 'public'))
    parser.add_argument('--fault-case', choices=CASES)
    parser.add_argument('--prepared-fixtures', type=Path)
    parser.add_argument('--fixture-manifest-digest')
    parser.add_argument('--prepared-image-digest', required=True,
                        help='Expected SHA-256 of the standalone administrator-prepared QCOW2 image.')
    parser.add_argument('--mode', choices=('baseline', 'bootstrap-only', 'native-slice'), required=True)
    parser.add_argument('--profile', choices=tuple(PROFILES), default='tcg-multi',
                        help='Explicit fixed TCG profile; no automatic fallback or JVM overrides.')
    parser.add_argument('--port', type=int, default=23112)
    parser.add_argument('--timeout', type=int, default=1800)
    parser.add_argument('--development-snapshot', action='store_true',
                        help='Label an isolated local helper commit as development observation only.')
    parser.add_argument('--host-key-pin-origin', choices=('preselected-host-key', 'administrator-preparation-tofu'),
                        required=True, help='Record the actual origin of the supplied SSH host-key pin.')
    args = parser.parse_args()
    if ((args.case_group in ('fault', 'worker', 'public')) != bool(args.fault_case)
            or (args.case_group == 'fault' and args.fault_case not in NATIVE_CASES)
            or (args.case_group == 'worker' and args.fault_case not in WORKER_CASES)
            or (args.case_group == 'public' and args.fault_case not in PUBLIC_CASES)
            or (args.case_group is not None and args.mode != 'native-slice')
            or (args.prepared_fixtures is None) != (args.fixture_manifest_digest is None)
            or (args.mode == 'workload-positive' and args.prepared_fixtures is None)
            or (args.fixture_manifest_digest is not None
                and re.fullmatch('[0-9a-f]{64}', args.fixture_manifest_digest) is None)):
        parser.error('invalid fixed case or fixture selection')
    if (re.fullmatch('[0-9a-f]{40}', args.product_source_commit) is None
            or re.fullmatch('[0-9a-f]{64}', args.prepared_image_digest) is None
            or not 1024 <= args.port <= 65535):
        parser.error('invalid source identity or local port')
    if not 60 <= args.timeout <= 3600:
        parser.error('timeout must be finite, from 60 through 3600 seconds')
    return run(args)


if __name__ == '__main__':
    raise SystemExit(main())

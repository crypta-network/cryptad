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
import time


PRODUCTS = ('build/cryptad-dist', 'platform-devtools/build/install/crypta-app',
            'platform-api/build/libs')
# Prospective candidate VM environment after a trusted fixture SIGILL under TCG/max.
# The finite max/qemu64 short diagnostics both passed, but a later qemu64 cohort reproduced
# SIGILL. This narrower advertised ISA is not a fix and changes neither JVM options nor either
# installed service's security profile. A single-thread TCG cohort exceeded its fixed deadline.
CPU_MODEL = 'qemu64'
ACCELERATOR = 'tcg,thread=multi'
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
    return subprocess.run(arguments, check=True, stdin=subprocess.DEVNULL,
                          timeout=timeout, **options)


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
            '-monitor', 'none']


def public_report(report):
    """Construct a closed export; never forward guest JSON, exceptions or console output."""
    fields = ('schemaVersion', 'kind', 'executed', 'status', 'stage', 'helperSourceCommit',
              'helperSourceTree', 'productSourceCommit', 'productDigest', 'sourceArchiveDigest',
              'preparedImageDigest', 'guestExitCode', 'guestStopped', 'mode', 'developmentSnapshot',
              'sshHostKeyPinDigest', 'sshHostKeyPinOrigin', 'cpuModel', 'accelerator')
    output = {key: report[key] for key in fields if key in report}
    output.update(guest_summary(report.get('guestSummary')))
    output.update(productionAuthorityObserved=False, mandatoryIsolationTestSatisfied=False,
                  installedKeylessNativeAcceptanceSatisfied=False,
                  cpuModel=CPU_MODEL, accelerator=ACCELERATOR)
    return output


def run(args):
    attempt = args.attempt.absolute()
    attempt.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.umask(0o077)
    report = {'schemaVersion': 2, 'kind': 'pr312-reference-vm-attempt', 'executed': False,
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
                      helperSourceTree=git('rev-parse', 'HEAD^{tree}'),
                      productSourceCommit=args.product_source_commit,
                      productDigest=sha256(source / 'build/cryptad-dist/lib/cryptad.jar'))
        report['stage'] = 'prepared-image-identity'
        report['preparedImageDigest'] = sha256(args.prepared_image)
        if report['preparedImageDigest'] != args.prepared_image_digest:
            raise ValueError('prepared-image-identity-mismatch')
        report['sshHostKeyPinDigest'] = sha256(args.known_hosts)
        report['sshHostKeyPinOrigin'] = args.host_key_pin_origin
        shutil.copyfile(args.known_hosts, attempt / 'known_hosts')
        clone = attempt / 'cryptad'
        report['stage'] = 'source-clone'
        command(['git', 'clone', '--no-hardlinks', '--no-checkout', str(source), str(clone)],
                stdout=log, stderr=log)
        command(['git', '-C', str(clone), 'checkout', '--detach', report['helperSourceCommit']],
                stdout=log, stderr=log)
        for relative in PRODUCTS:
            destination = clone / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(source / relative, destination, symlinks=False)
        archive = attempt / 'source.tar.gz'
        report['stage'] = 'source-archive'
        command(['tar', '-czf', str(archive), '-C', str(attempt), 'cryptad'], stdout=log, stderr=log)
        report['sourceArchiveDigest'] = sha256(archive)
        root = args.qemu_root.resolve(strict=True)
        env = {**os.environ, 'LD_LIBRARY_PATH': str(root / 'usr/lib/x86_64-linux-gnu'),
               'QEMU_MODULE_DIR': str(root / 'usr/lib/x86_64-linux-gnu/qemu')}
        report['stage'] = 'guest-overlay'
        command([str(root / 'usr/bin/qemu-img'), 'create', '-f', 'qcow2', '-F', 'qcow2',
                 '-b', str(args.prepared_image.resolve(strict=True)), str(attempt / 'guest.qcow2')],
                env=env, stdout=log, stderr=log)
        process = subprocess.Popen(qemu_arguments(root, attempt, args.prepared_image,
                                                  args.seed.resolve(strict=True), args.port),
                                   env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        report.update(executed=True, guestStopped=False, stage='guest-boot')
        ssh = ['ssh', '-F', '/dev/null', '-i', str(args.ssh_key.resolve(strict=True)), '-p', str(args.port),
               '-o', 'IdentitiesOnly=yes', '-o', 'ForwardAgent=no', '-o', 'StrictHostKeyChecking=yes',
               '-o', 'UserKnownHostsFile=' + str(attempt / 'known_hosts'),
               '-o', 'ConnectTimeout=5', '-o', 'BatchMode=yes', 'vmadmin@127.0.0.1']
        deadline = time.monotonic() + 180
        while True:
            probe = subprocess.run([*ssh, 'true'], stdin=subprocess.DEVNULL,
                                   stdout=log, stderr=log, timeout=10)
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
                           stdout=log, stderr=log, check=True, timeout=180)
        script = 'set -eu\numask 022\nsudo systemctl start dbus.service polkit.service\n'
        script += 'test "$(sha256sum /home/vmadmin/source.tar.gz | cut -d " " -f 1)" = ' + report['sourceArchiveDigest'] + '\n'
        script += 'sudo test ! -e /root/cryptad\nsudo tar --no-same-owner -xzf /home/vmadmin/source.tar.gz -C /root\n'
        script += ('install -m 0600 /dev/null /home/vmadmin/report.json\n'
                   'install -m 0600 /dev/null /home/vmadmin/driver.private.log\n')
        if args.mode == 'baseline':
            script += "sudo /usr/bin/python3 - <<'PR312_DRIVER' > /home/vmadmin/report.json 2>/home/vmadmin/driver.private.log\n" + BASELINE + '\nPR312_DRIVER\n'
        else:
            script += ('sudo /usr/bin/python3 /root/cryptad/tools/release-certification/restricted/disposable_integration.py '
                       '--disposable-vm --source /root/cryptad --product-source-commit '
                       + args.product_source_commit + ' --' + args.mode
                       + ' > /home/vmadmin/report.json 2>/home/vmadmin/driver.private.log\n')
        report['stage'] = 'installed-' + args.mode
        result = subprocess.run([*ssh, 'bash -s'], input=script.encode(), stdout=log, stderr=log,
                                timeout=args.timeout)
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
                           stdout=stream, stderr=log, check=True, timeout=15)
        with (attempt / 'installation-failure.private.json').open('xb') as stream:
            command([*ssh, 'sudo test ! -f /root/pr312-installation-failure.json || '
                     'sudo head -c 1024 /root/pr312-installation-failure.json'],
                    stdout=stream, stderr=log, timeout=15)
        for label, remote, maximum in (
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
                           stdout=stream, stderr=log, check=True, timeout=15)
        # Completion of transport is separate from bootstrap/native acceptance in the guest report.
        report['status'] = 'guest-report-retained' if result.returncode == 0 else 'guest-operation-failed'
        subprocess.run([*ssh, 'sudo poweroff'], stdin=subprocess.DEVNULL, stdout=log, stderr=log, timeout=20)
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
        (attempt / 'stage-report.json').write_text(json.dumps(public_report(report), indent=2) + '\n')
    print(json.dumps(public_report(report), sort_keys=True))
    return 0 if report['status'] == 'guest-report-retained' else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'attempt', 'prepared-image', 'qemu-root', 'seed', 'ssh-key', 'known-hosts'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--product-source-commit', required=True)
    parser.add_argument('--prepared-image-digest', required=True,
                        help='Expected SHA-256 of the exact administrator-prepared image.')
    parser.add_argument('--mode', choices=('baseline', 'bootstrap-only', 'native-slice'), required=True)
    parser.add_argument('--port', type=int, default=23112)
    parser.add_argument('--timeout', type=int, default=1800)
    parser.add_argument('--development-snapshot', action='store_true',
                        help='Label an isolated local helper commit as development observation only.')
    parser.add_argument('--host-key-pin-origin', choices=('preselected-host-key', 'administrator-preparation-tofu'),
                        required=True, help='Record the actual origin of the supplied SSH host-key pin.')
    args = parser.parse_args()
    if (re.fullmatch('[0-9a-f]{40}', args.product_source_commit) is None
            or re.fullmatch('[0-9a-f]{64}', args.prepared_image_digest) is None
            or not 1024 <= args.port <= 65535):
        parser.error('invalid source identity or local port')
    if not 60 <= args.timeout <= 3600:
        parser.error('timeout must be finite, from 60 through 3600 seconds')
    return run(args)


if __name__ == '__main__':
    raise SystemExit(main())

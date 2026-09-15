"""Disposable installed collector attacks using one fixed synthetic Python exporter.

This is not Java app validation, original authentication, or production authority. The separately
identified test owner stages a tiny unused synthetic JDK tree because the malicious exporter
runs Python. The real installed adapter, sandbox, native UID and output collector run unchanged.
All failed invocation histories remain retained; no test deletes them to reclaim capacity.
"""
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

MODES = ('control', 'symlink', 'hardlink-roster', 'fifo', 'socket', 'oversize',
         'race-timeout', 'open-output-timeout')
ENVIRONMENT = {'PATH': '/jdk/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': '/tmp', 'TMPDIR': '/tmp',
    'JAVA_HOME': '/jdk', 'JAVA_OPTS': '-Xmx256m -XX:CompressedClassSpaceSize=64m -XX:ReservedCodeCacheSize=64m'}
CONTROL_BYTES = b'{"syntheticCollectorControl":true,"authority":"none"}\n'
CONTROL_STDOUT = b'fixture-device-creation-denied\nfixture-output-ready:control\n'
EXPORTER = r'''#!/usr/bin/python3
import errno, json, os, pathlib, socket, stat, sys, time
root = pathlib.Path('/work')
mode = (root / 'mode').read_text()
uid = int((root / 'uid').read_text())
assert uid > 0 and os.getuid() == uid and os.geteuid() == uid
status = dict(line.split(':', 1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
assert status['NoNewPrivs'].strip() == '1'
assert all(int(status[key].strip(), 16) == 0 for key in ('CapEff', 'CapPrm', 'CapInh', 'CapAmb', 'CapBnd'))
assert sys.argv[1] == 'subject-projection' and len(sys.argv[2:]) % 2 == 0
options = dict(zip(sys.argv[2::2], sys.argv[3::2]))
assert options['--output'] == '/output/projection.json' and options['--private-root'] == '/scratch'
output = pathlib.Path('/output/projection.json')
if mode == 'control':
    device = pathlib.Path('/scratch/character-device')
    try:
        os.mknod(device, stat.S_IFCHR | 0o600, os.makedev(1, 3))
    except OSError as failure:
        assert failure.errno == errno.EPERM
    else:
        raise RuntimeError('fixture-device-creation-succeeded')
    assert not os.path.lexists(device)
    print('fixture-device-creation-denied', flush=True)
    output.write_bytes(b'{"syntheticCollectorControl":true,"authority":"none"}\n')
elif mode == 'symlink':
    output.symlink_to('/work/catalog')
    assert stat.S_ISLNK(output.lstat().st_mode)
elif mode == 'hardlink-roster':
    alias = pathlib.Path('/output/alias')
    alias.write_bytes(b'{"synthetic":true}')
    os.link(alias, output)
    assert output.stat().st_nlink == 2
elif mode == 'fifo':
    os.mkfifo(output, 0o600)
    assert stat.S_ISFIFO(output.lstat().st_mode)
elif mode == 'socket':
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(output))
    assert stat.S_ISSOCK(output.lstat().st_mode)
elif mode == 'oversize':
    output.write_bytes(b'x' * 32769)
elif mode in ('race-timeout', 'open-output-timeout'):
    output.write_bytes(b'{"synthetic":true}')
    child = os.fork()
    if child == 0:
        os.setsid()
        if mode == 'open-output-timeout':
            with output.open('ab') as retained:
                print('fixture-child-active', flush=True)
                time.sleep(120)
        else:
            for index in range(12000):
                temporary = pathlib.Path('/output/replacement')
                if index % 2:
                    temporary.symlink_to('/work/catalog')
                else:
                    temporary.write_bytes(b'{"replacement":true}')
                os.replace(temporary, output)
                if index == 0:
                    print('fixture-race-active', flush=True)
                time.sleep(.01)
        os._exit(0)
    print('fixture-output-ready:' + mode, flush=True)
    time.sleep(120)
    raise RuntimeError('fixture-timeout-not-enforced')
else:
    raise RuntimeError('fixture-mode-invalid')
print('fixture-output-ready:' + mode, flush=True)
'''


def _command(jdk, tools, work, inputs):
    return ['/usr/bin/prlimit', '--cpu=180', '--fsize=8388608', '--nofile=128', '--as=4294967296', '--',
        '/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--ro-bind', '/lib', '/lib',
        '--ro-bind', '/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev',
        '--size', '16777216', '--tmpfs', '/tmp', '--ro-bind', str(jdk), '/jdk',
        '--ro-bind', str(tools), '/tools', '--ro-bind', str(inputs), '/inputs',
        '--bind', str(work), '/work', '--chdir', '/work', '--', '/tools/bin/crypta-app',
        'subject-projection', '--catalog', '/work/catalog', '--catalog-signature', '/work/catalogSignature',
        '--bundle', '/work/bundle', '--catalog-keys', '/inputs/catalog-keys',
        '--publisher-keys', '/inputs/publisher-keys', '--catalog-key-id', 'synthetic-collector',
        '--app-id', 'synthetic-collector', '--private-root', '/work', '--output', '/work/projection.json']


def _quiescent(native):
    state = native._manager('show')
    if (state['ActiveState'] not in ('inactive', 'failed')
            or state['ControlGroup'] not in ('', native.CGROUP)
            or (native.ROOT / 'active.json').exists()):
        raise ValueError('output-fixture-not-quiescent')
    group = Path('/sys/fs/cgroup' + native.CGROUP)
    if group.exists() and 'populated 0' not in (group / 'cgroup.events').read_text().splitlines():
        raise ValueError('output-fixture-not-quiescent')


def _validate_observation(native, mode, stage, work, rejected, result):
    # These files are root-retained after actual manager/cgroup quiescence. Native stdout is
    # only a test-stage marker, never app subject evidence or an authentication capability.
    raw = native._read_output(stage / 'diagnostics/stdout', 8192, allow_empty=True)
    if ('fixture-output-ready:' + mode + '\n').encode() not in raw:
        raise ValueError('output-fixture-attack-not-observed')
    if mode in ('race-timeout', 'open-output-timeout'):
        marker = b'fixture-race-active\n' if mode == 'race-timeout' else b'fixture-child-active\n'
        if marker not in raw:
            raise ValueError('output-fixture-child-not-observed')
        failure = json.loads(native._read_output(stage / 'output/failure.json', 4096))
        if failure != {'invocation': stage.name, 'stage': 'deadline'}:
            raise ValueError('output-fixture-timeout-not-observed')
    if mode == 'control':
        if (rejected or result != CONTROL_STDOUT or b'fixture-device-creation-denied\n' not in raw
                or native._read_output(work / 'projection.json', 32768) != CONTROL_BYTES):
            raise ValueError('output-fixture-control-unavailable')
    elif not rejected or (work / 'projection.json').exists():
        raise ValueError('output-fixture-hostile-output-accepted')


def run(root, identity):
    """Return fixed coverage names only after every executed case and quiescence check passes."""
    import restricted_native as native
    if (os.geteuid() != 0 or not Path(native.__file__).resolve().is_relative_to('/opt')
            or len(identity) != 64 or any(character not in '0123456789abcdef' for character in identity)):
        raise ValueError('output-fixture-requires-installed-guest')
    if not Path('/opt/cryptad-restricted-test-kit/.test-kit.json').is_file():
        raise ValueError('output-fixture-test-kit-required')
    detected = subprocess.run(['/usr/bin/systemd-detect-virt', '--vm'], check=True,
        capture_output=True, timeout=5, env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
    if detected.stdout != b'qemu\n':
        raise ValueError('output-fixture-reference-guest-required')
    root = Path(root)
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    jdk, tools, inputs = (root / name for name in ('synthetic-unused-jdk', 'synthetic-tools', 'public-inputs'))
    for directory in (jdk, tools, inputs):
        directory.mkdir(mode=0o700)
    (jdk / 'fixture-only.txt').write_text('Unused synthetic JDK input; this fixture executes Python, not Java.\n')
    (tools / 'bin').mkdir(mode=0o700)
    exporter = tools / 'bin/crypta-app'
    exporter.write_text(EXPORTER)
    exporter.chmod(0o500)
    for name in ('catalog-keys', 'publisher-keys'):
        (inputs / name).write_bytes(b'synthetic-collector-public-input\n')
    dimensions = []
    for mode in MODES:
        work = root / mode
        work.mkdir(mode=0o700)
        for name in ('catalog', 'catalogSignature', 'bundle'):
            (work / name).write_bytes(b'synthetic-collector-input\n')
        (work / 'mode').write_text(mode)
        (work / 'uid').write_text(str(native._native_identity()[0]))
        before = set(native.ROOT.iterdir())
        context = {'operationId': secrets.token_hex(32), 'registrationDigest': 'sha256:' + '0' * 64,
                   'bundleIdentity': identity, 'deadlineMonotonic': time.monotonic() + 60}
        rejected, result = False, b''
        started = time.monotonic()
        try:
            with native.owning_boundary(context=context):
                result = native.run(_command(jdk, tools, work, inputs), environment=ENVIRONMENT,
                    timeout=20 if mode.endswith('-timeout') else 45, output_limit=8192,
                    operation='app-projection')
        except native.NativeBoundaryError:
            rejected = True
        _quiescent(native)
        stages = [path for path in set(native.ROOT.iterdir()) - before if path.is_dir()]
        if len(stages) != 1 or not (stages[0] / 'manager.json').exists():
            raise ValueError('output-fixture-not-launched')
        _validate_observation(native, mode, stages[0], work, rejected, result)
        (work / 'observation.json').write_text(json.dumps({'mode': mode, 'rejected': rejected,
            'quiescent': True, 'elapsedSeconds': time.monotonic() - started,
            'javaAppValidation': False, 'productionAuthority': False}, sort_keys=True))
        dimensions.append('installed-synthetic-output-' + mode)
        if mode == 'control':
            dimensions.append('installed-synthetic-output-device-creation-denied')
    return dimensions

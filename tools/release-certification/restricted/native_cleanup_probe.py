"""Disposable controller-unit probe for termination of real different-UID native children.

The harness alone selects this test ExecStart. Process creation and signaling are real; wrappers
only retain the Popen handle and inspect private test readiness immediately before the real kill.
"""
import json
import os
from pathlib import Path
import pwd
import signal
import sys
import tempfile
import time
from unittest.mock import patch

ROOT = Path('/opt/cryptad-cross-version/current')
TEST_KIT = Path('/opt/cryptad-restricted-test-kit')
CGROUP = Path('/sys/fs/cgroup/system.slice/cryptad-restricted.service/cgroup.procs')

HELPER = r'''
import json, os, pathlib, sys, time
status = dict(line.split(':', 1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
fields = ('CapEff', 'CapPrm', 'CapInh', 'CapAmb', 'CapBnd')
assert os.getuid() != 0
assert all(int(status[field].strip(), 16) == 0 for field in fields)
assert status['NoNewPrivs'].strip() == '1'
pathlib.Path('/work/ready.json').write_text(json.dumps({'uid': os.getuid(), 'capabilities': [int(status[k].strip(),16) for k in fields]}))
if sys.argv[1] == 'output':
    while True:
        os.write(1, b'x' * 8192)
else:
    time.sleep(120)
'''


def members():
    return set(CGROUP.read_text().split())


def exercise(mode):
    import bounded_process
    import restricted_native as native
    expected_uid = pwd.getpwnam('cryptad-native').pw_uid
    before = members()
    processes, signals, readiness = [], [], []
    popen, killpg = bounded_process.subprocess.Popen, bounded_process.os.killpg
    def start(*args, **kwargs):
        child = popen(*args, **kwargs)
        processes.append(child)
        return child
    def terminate(pgid, sig):
        signals.append((pgid, sig))
        # The child file supplies test observations only, never a PID or termination target.
        try:
            for path in native.ROOT.glob('invocation-*/work/ready.json'):
                if path.stat().st_size <= 4096:
                    readiness.append(json.loads(path.read_bytes()))
        finally:
            killpg(pgid, sig)
    with tempfile.TemporaryDirectory(prefix='cleanup-probe-', dir='/var/lib/cryptad-restricted/resolver') as directory:
        work = Path(directory)
        (work / 'helper.py').write_text(HELPER)
        command = ['/usr/bin/prlimit', '--nofile=128', '--', '/usr/bin/bwrap',
            '--unshare-all', '--die-with-parent', '--new-session',
            '--ro-bind', '/usr', '/usr', '--ro-bind', '/lib', '/lib', '--ro-bind', '/lib64', '/lib64',
            '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--bind', str(work), '/work',
            '--chdir', '/work', '--', '/usr/bin/python3', '-I', '-S', '/work/helper.py', mode]
        with native.owning_boundary(), patch.object(bounded_process.subprocess, 'Popen', side_effect=start), \
                patch.object(bounded_process.os, 'killpg', side_effect=terminate):
            try:
                native.run(command, environment={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'},
                           timeout=3 if mode == 'timeout' else 15, output_limit=1024)
            except native.NativeBoundaryError:
                pass
            else:
                raise ValueError('native-cleanup-probe-expected-failure')
        if (len(processes) != 1 or processes[0].returncode is None
                or signals != [(processes[0].pid, signal.SIGKILL)]
                or readiness != [{'uid': expected_uid, 'capabilities': [0, 0, 0, 0, 0]}]):
            raise ValueError('native-cleanup-probe-not-reaped-or-not-keyless')
        # A reaped wrapper alone is insufficient: require the owned unit to contain only its
        # original processes. systemd stopping this probe later cannot make this check pass.
        deadline = time.monotonic() + 5
        while members() != before:
            if time.monotonic() >= deadline:
                raise ValueError('native-cleanup-probe-descendants-remain')
            time.sleep(.05)


def main():
    if (os.geteuid() != 0 or Path(__file__) != TEST_KIT / 'tools/release-certification/restricted/native_cleanup_probe.py'
            or not any(line.endswith(':/system.slice/cryptad-restricted.service')
                       for line in Path('/proc/self/cgroup').read_text().splitlines())):
        raise ValueError('native-cleanup-probe-controller-unit-required')
    sys.path.insert(0, str(ROOT / 'tools/release-certification/protected'))
    for mode in ('timeout', 'output'):
        exercise(mode)


if __name__ == '__main__':
    main()

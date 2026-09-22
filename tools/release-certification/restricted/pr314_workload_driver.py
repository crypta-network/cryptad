#!/usr/bin/python3
"""Administrator test-kit entry for the real installed four-role positive sequence.

Run only in the copied, explicitly disposable PR-313 reference after base installation.
The fixed private selection is prepared with two distinct source-built products and a
normally signed Mail bundle. This driver never manufactures original release authority.
Its positive result alone cannot satisfy the separate complete workload fault contract.
"""
import argparse
import json
import os
from pathlib import Path
import pwd
import select
import signal
import socket
import subprocess
import sys
import time

INSTALLED = Path('/opt/cryptad-cross-version/current')
TEST_KIT = Path('/opt/cryptad-restricted-test-kit')
SELECTION = Path('/root/pr314-workload-selection.json')
REPORT = Path('/root/pr314-workload-observation.private.json')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}


def prerequisites():
    reasons = []
    if os.geteuid() != 0:
        reasons.append('administrator-required')
    if 'VERSION_ID="13"' not in Path('/etc/os-release').read_text():
        reasons.append('debian13-required')
    if Path('/proc/1/comm').read_text().strip() != 'systemd':
        reasons.append('systemd-pid1-required')
    result = subprocess.run(['/usr/bin/systemd-detect-virt', '--vm'], capture_output=True, env=ENV, timeout=10)
    if result.returncode:
        reasons.append('dedicated-disposable-vm-required')
    if not (INSTALLED / '.restricted-manifest.json').is_file():
        reasons.append('fixed-installed-source-required')
    if not (TEST_KIT / '.test-kit.json').is_file():
        reasons.append('separate-measured-test-kit-required')
    return reasons


def execute():
    if prerequisites():
        raise ValueError('workload-reference-prerequisites-unavailable')
    sys.path.insert(0, str(INSTALLED / 'tools/release-certification/restricted'))
    sys.path.insert(0, str(INSTALLED / 'tools/release-certification/protected'))
    sys.path.insert(0, str(INSTALLED / 'tools/release-certification'))
    sys.path.insert(0, str(INSTALLED / 'tools/interop'))
    import installation
    import workload_installation
    import restricted_workload as workload
    from restricted_workload_prepare import prepare
    from cross_version_workload import InstalledWorkloadAdapter
    from cryptad_certification.cross_version_evidence import Journal
    identity = installation.verify_execution()
    kit = installation.read_json(installation.secured(TEST_KIT / '.test-kit.json'))
    relative = 'tools/release-certification/restricted/pr314_workload_driver.py'
    import hashlib
    if (kit['sourceCommit'] != identity['sourceCommit']
            or Path(__file__).resolve() != TEST_KIT / relative
            or hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != kit['files'].get(relative)):
        raise ValueError('workload-test-kit-source-mismatch')
    selected = workload.read(SELECTION)
    if set(selected) != {'plan', 'private', 'authorization'}:
        raise ValueError('workload-test-selection-invalid')
    observer = pwd.getpwnam('cryptad-soak')
    root = Path(selected['private']['root'])
    if (root.parent != Path('/var/lib/cryptad-cross-version/experiments') or root.exists()
            or root.is_symlink()):
        raise ValueError('workload-observer-root-not-new')
    workload_installation.install()
    handoff = prepare(selected['plan'], selected['private'], selected['authorization'])
    root.mkdir(mode=0o700)
    os.chown(root, observer.pw_uid, observer.pw_gid)
    subprocess.run(['/usr/bin/systemctl', 'start', 'cryptad-workload-controller.service'],
                   check=True, timeout=30, env=ENV)
    until = time.monotonic() + 30
    while not Path('/run/cryptad-workload/control.sock').exists():
        if time.monotonic() >= until:
            raise ValueError('workload-controller-readiness-timeout')
        time.sleep(.05)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    pid = os.fork()
    if pid == 0:
        parent.close()
        try:
            os.setgroups([])
            os.setgid(observer.pw_gid)
            os.setuid(observer.pw_uid)
            os.environ.clear()
            os.environ.update(ENV)
            os.umask(0o077)
            with Journal(root, selected['plan']) as journal:
                journal.append('start')
                adapter = InstalledWorkloadAdapter(selected['plan'], selected['private'],
                                                   selected['authorization'], journal, handoff)
                result = adapter.run_positive()
                # All other required scenarios retain their original missing status.
                journal.checkpoint('partial')
            child.sendall(json.dumps(result, separators=(',', ':')).encode())
            child.close()
            os._exit(0)
        except BaseException:
            child.close()
            os._exit(1)
    child.close()
    deadline = time.monotonic() + selected['authorization']['maxSeconds'] + 100
    raw = bytearray()
    status = None
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([parent], [], [], min(1, max(.01, deadline - time.monotonic())))
            if ready:
                block = parent.recv(65537 - len(raw))
                if not block:
                    break
                raw.extend(block)
                if len(raw) > 65536:
                    raise ValueError('workload-observer-output-limit')
        else:
            raise ValueError('workload-observer-timeout')
        _pid, status = os.waitpid(pid, 0)
        if status != 0:
            raise ValueError('workload-positive-sequence-failed')
        result = json.loads(raw)
        if result.get('contentRetrieval') != 'observed' or result.get('newEpoch') is not True:
            raise ValueError('workload-positive-observation-incomplete')
        result.update(identity=identity, finiteNativeAcceptance='not-executed-by-this-driver',
                      workloadAcceptance='incomplete-hostile-contract-not-executed', protectedExecutionEnabled=False)
        workload.write(REPORT, result, create=True)
        return {'status': 'positive-sequence-executed', 'workloadAcceptance': 'incomplete',
                'protectedExecutionEnabled': False}
    finally:
        parent.close()
        if status is None:
            # This is the exact unreaped fork child; it cannot have been PID-reused.
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        workload.reconcile()
        subprocess.run(['/usr/bin/systemctl', 'stop', 'cryptad-workload-controller.service'],
                       check=True, timeout=110, env=ENV)
        with workload.locked():
            if not all(workload.quiescent(role) for role in workload.ROLES):
                raise ValueError('workload-terminal-cgroups-not-empty')
            from restricted_workload_network import teardown
            teardown()
        # Role tmpfs state and records remain explicitly retained for private diagnostics.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    reasons = prerequisites()
    if reasons:
        print(json.dumps({'status': 'not-executed', 'reasons': reasons, 'protectedExecutionEnabled': False}))
        return 78
    if not args.execute:
        print(json.dumps({'status': 'prerequisites-present-not-executed', 'protectedExecutionEnabled': False}))
        return 0
    print(json.dumps(execute(), sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        result = main()
    except Exception:
        print('{"status":"failed-private-reconciliation-required","protectedExecutionEnabled":false}')
        result = 1
    raise SystemExit(result)

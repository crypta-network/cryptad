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
import struct
import stat
import sys
import time

sys.dont_write_bytecode = True

INSTALLED = Path('/opt/cryptad-cross-version/current')
TEST_KIT = Path('/opt/cryptad-restricted-test-kit')
SELECTION = Path('/root/pr314-workload-selection.json')
REPORT = Path('/root/pr314-workload-observation.private.json')
VOLATILE = Path('/root/pr315-workload-volatile.private.json')
DIAGNOSTICS = Path('/root/pr315-workload-memory.private.json')
CGROUP_ROOT = Path('/sys/fs/cgroup/system.slice')
ROLE_NAMES = ('candidate-sender', 'candidate-recipient', 'previous', 'relay-no-apps')
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


def cleanup(workload):
    """Stop the lease owner before acquiring its nonblocking reconciliation lease."""
    subprocess.run(['/usr/bin/systemctl', 'stop', 'cryptad-workload-controller.service'],
                   check=True, timeout=110, env=ENV)
    workload.reconcile()
    with workload.locked():
        if not all(workload.quiescent(role) for role in workload.ROLES):
            raise ValueError('workload-terminal-cgroups-not-empty')
        from restricted_workload_network import teardown
        teardown()
    # Role tmpfs state and records remain explicitly retained for private diagnostics.


def wait_child(pid, deadline):
    """Reap only our unreaped child, including the interval after its output reaches EOF."""
    while True:
        observed, status = os.waitpid(pid, os.WNOHANG)
        if observed == pid:
            return status
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('workload-observer-exit-timeout')
        time.sleep(min(.02, remaining))


def stop_child(pid):
    """Bound termination; an unreaped child remains owned and cannot have its PID reused."""
    observed, _status = os.waitpid(pid, os.WNOHANG)
    if observed == pid:
        return
    os.kill(pid, signal.SIGKILL)
    wait_child(pid, time.monotonic() + 5)


def collect_child(parent, pid, deadline, sample=None):
    raw = bytearray()
    next_sample = 0
    while time.monotonic() < deadline:
        if sample is not None and time.monotonic() >= next_sample:
            sample()
            next_sample = time.monotonic() + 5
        ready, _, _ = select.select([parent], [], [], min(1, max(.001, deadline - time.monotonic())))
        if ready:
            block = parent.recv(65537 - len(raw))
            if not block:
                return bytes(raw), wait_child(pid, deadline)
            raw.extend(block)
            if len(raw) > 65536:
                raise ValueError('workload-observer-output-limit')
    raise ValueError('workload-observer-timeout')


def controller_ready(deadline):
    """Observe a root peer process serving the closed protocol, as the observer UID.

    The deliberately empty request must receive the fixed rejection. This is a readiness
    exchange, never an accepted workload operation or an acceptance case witness.
    """
    expected = b'{"error":"restricted-workload-request-failed"}\n'
    while time.monotonic() < deadline:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
                channel.settimeout(min(1, max(.001, deadline - time.monotonic())))
                channel.connect('/run/cryptad-workload/control.sock')
                _pid, uid, _gid = struct.unpack('3i', channel.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
                if uid != 0:
                    raise ValueError('workload-controller-peer-not-root')
                channel.sendall(b'{}\n')
                received = bytearray()
                while len(received) <= len(expected) and not received.endswith(b'\n'):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('readiness-deadline')
                    channel.settimeout(min(1, remaining))
                    chunk = channel.recv(len(expected) + 1 - len(received))
                    if not chunk:
                        break
                    received.extend(chunk)
                if received != expected:
                    raise ValueError('workload-controller-readiness-response-invalid')
                return
        except (FileNotFoundError, ConnectionRefusedError, TimeoutError):
            pass
        time.sleep(min(.05, max(0, deadline - time.monotonic())))
    raise ValueError('workload-controller-readiness-timeout')


def _kernel_read(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError('kernel-metric-not-regular')
        value = os.read(descriptor, 65537)
        if len(value) > 65536:
            raise ValueError('kernel-metric-too-large')
        return value.decode('ascii')
    finally:
        os.close(descriptor)


def controller_startup_snapshot(workload):
    """Capture the fixed root-private startup diagnostic before systemd removes it.

    This latest runtime checkpoint is neither an acceptance witness nor retained lifecycle
    authority. Its absence does not establish whether the controller ran or stopped.
    """
    try:
        value = workload.read(Path('/run/cryptad-workload/startup.json'))
        return {'status': 'captured', 'record': value,
                'observedMonotonicNs': time.monotonic_ns(),
                'classification': 'private-startup-diagnostic-not-acceptance'}
    except (OSError, ValueError):
        return {'status': 'unavailable-not-quiescence-proof'}


def memory_snapshot():
    """Fixed private kernel metrics; absent cgroups never establish owned quiescence."""
    snapshot = {'observedMonotonicNs': time.monotonic_ns(), 'guest': {}, 'services': {}}
    try:
        snapshot['bootId'] = _kernel_read(Path('/proc/sys/kernel/random/boot_id')).strip()
        values = dict(line.split(':', 1) for line in _kernel_read(Path('/proc/meminfo')).splitlines())
        selected = {}
        for key in ('MemTotal', 'MemAvailable', 'SwapTotal', 'SwapFree', 'Shmem'):
            value, unit = values[key].split()
            if unit != 'kB' or not value.isdecimal():
                raise ValueError('guest-memory-invalid')
            selected[key + 'Bytes'] = int(value) * 1024
        snapshot['guest'] = {'status': 'observed', **selected}
    except (OSError, ValueError, KeyError):
        snapshot['guest'] = {'status': 'unavailable'}
    units = ['cryptad-workload-controller.service', *(
        'cryptad-workload@' + role + '.service' for role in ROLE_NAMES)]
    for unit in units:
        path = CGROUP_ROOT / unit
        try:
            before = path.stat(follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                raise ValueError('cgroup-not-directory')
            metrics = {}
            for name in ('memory.current', 'memory.max', 'memory.swap.max', 'pids.current', 'pids.max'):
                raw = _kernel_read(path / name).strip()
                if raw != 'max' and not raw.isdecimal():
                    raise ValueError('cgroup-metric-invalid')
                metrics[name] = raw if raw == 'max' else int(raw)
            for name in ('memory.events', 'cgroup.events'):
                rows = [line.split() for line in _kernel_read(path / name).splitlines()]
                if any(len(row) != 2 or not row[1].isdecimal() for row in rows):
                    raise ValueError('cgroup-events-invalid')
                metrics[name] = {key: int(value) for key, value in rows}
            after = path.stat(follow_symlinks=False)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise ValueError('cgroup-replaced')
            snapshot['services'][unit] = {'status': 'observed',
                'cgroupIdentity': [before.st_dev, before.st_ino], **metrics}
        except FileNotFoundError:
            snapshot['services'][unit] = {'status': 'absent-or-removed-not-quiescence-proof'}
        except (OSError, ValueError):
            snapshot['services'][unit] = {'status': 'unavailable'}
    return snapshot


def sample_memory(diagnostics):
    """Keep constant-size sampled peaks, explicitly neither continuous nor OOM attribution."""
    snapshot = memory_snapshot()
    live = diagnostics.setdefault('during', {'sampleCount': 0, 'services': {},
        'classification': 'five-second-sampled-not-continuous'})
    live['sampleCount'] += 1
    live['last'] = snapshot
    guest = snapshot['guest']
    if guest['status'] == 'observed':
        available = guest['MemAvailableBytes']
        live['minimumObservedGuestAvailableBytes'] = min(
            live.get('minimumObservedGuestAvailableBytes', available), available)
    for unit, metrics in snapshot['services'].items():
        if metrics['status'] != 'observed':
            continue
        peak = live['services'].setdefault(unit, {'sampleCount': 0,
            'maximumObservedMemoryBytes': 0, 'maximumObservedTasks': 0})
        peak['sampleCount'] += 1
        peak['maximumObservedMemoryBytes'] = max(peak['maximumObservedMemoryBytes'], metrics['memory.current'])
        peak['maximumObservedTasks'] = max(peak['maximumObservedTasks'], metrics['pids.current'])
        peak['lastObserved'] = metrics


def execute():
    if prerequisites():
        raise ValueError('workload-reference-prerequisites-unavailable')
    sys.path.insert(0, str(INSTALLED / 'tools/release-certification/restricted'))
    sys.path.insert(0, str(INSTALLED / 'tools/release-certification/protected'))
    sys.path.insert(0, str(INSTALLED / 'tools/release-certification'))
    sys.path.insert(0, str(INSTALLED / 'tools/interop'))
    sys.path.insert(0, str(TEST_KIT / 'tools/release-certification/restricted'))
    import installation
    import workload_installation
    import restricted_workload as workload
    from restricted_workload_prepare import prepare
    import pr315_workload_evidence as evidence
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
    parent = child = None
    pid = None
    status = None
    result = None
    diagnostics = {'classification': 'private-kernel-diagnostics-not-acceptance',
                   'before': memory_snapshot(), 'cleanup': 'not-completed'}
    sentinel = None
    try:
        handoff = prepare(selected['plan'], selected['private'], selected['authorization'])
        campaign_deadline = workload.read(workload.ROOT / 'campaign.json')['deadlineMonotonicNs']
        if type(campaign_deadline) is not int or campaign_deadline <= time.monotonic_ns():
            raise ValueError('workload-preparation-consumed-deadline')
        sentinel = evidence.prepare_sentinel(workload)
        root.mkdir(mode=0o700)
        os.chown(root, observer.pw_uid, observer.pw_gid)
        subprocess.run(['/usr/bin/systemctl', 'start', 'cryptad-workload-controller.service'],
                       check=True, timeout=30, env=ENV)
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
                controller_ready(time.monotonic() + 30)
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
            except BaseException as error:
                try:
                    child.sendall(json.dumps({'observerFailure': type(error).__name__,
                                             'privateDetail': str(error)[:1024]}).encode())
                except OSError:
                    pass
                child.close()
                os._exit(1)
        child.close()
        # Preparation already started the campaign clock. Observation gets only the
        # original deadline plus bounded teardown grace, never a new execution budget.
        deadline = campaign_deadline / 10**9 + 100
        raw, status = collect_child(parent, pid, deadline, lambda: sample_memory(diagnostics))
        if status != 0:
            diagnostics['observerFailure'] = {'exitStatus': status,
                'privateTranscript': raw[:4096].decode('utf-8', errors='replace')}
            raise ValueError('workload-positive-sequence-failed')
        result = json.loads(raw)
        if result.get('contentRetrieval') != 'observed' or result.get('newEpoch') is not True:
            raise ValueError('workload-positive-observation-incomplete')
        result.update(identity=identity, finiteNativeAcceptance='not-executed-by-this-driver',
                      campaignDeadlineMonotonicNs=campaign_deadline,
                      workloadAcceptance='incomplete-hostile-contract-not-executed', protectedExecutionEnabled=False)
    finally:
        try:
            if parent is not None:
                parent.close()
            if child is not None:
                child.close()
            if pid is not None and pid > 0 and status is None:
                stop_child(pid)
        finally:
            try:
                diagnostics['controllerStartup'] = controller_startup_snapshot(workload)
                cleanup(workload)
                diagnostics['cleanup'] = 'completed'
            finally:
                diagnostics['after'] = memory_snapshot()
                workload.write(DIAGNOSTICS, diagnostics, create=True)
                volatile = evidence.capture(workload, sentinel, diagnostics['cleanup'] == 'completed')
                workload.write(VOLATILE, volatile, create=True)
                if (sentinel is not None and diagnostics['cleanup'] == 'completed'
                        and volatile['sentinel']['status'] != 'matched'):
                    raise ValueError('workload-retained-sentinel-not-established')
    # No terminal result can exist before owned controller/role/network cleanup succeeds.
    workload.write(REPORT, result, create=True)
    return {'status': 'positive-sequence-executed', 'workloadAcceptance': 'incomplete',
            'protectedExecutionEnabled': False}


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

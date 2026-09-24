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
LIFECYCLE_SCENARIOS = ('cancellation', 'controller-restart')
STARTUP_MEASUREMENT_SECONDS = 120
# Prospective administrator observation budget after the installed startup measurement.
# Production limits and the retained campaign deadline remain unchanged.
READINESS_SECONDS = 90
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
    """Fence launch before terminal owner shutdown, within the existing stop budget."""
    deadline = time.monotonic() + 110
    fence_deadline = time.monotonic() + 35
    try:
        while True:
            try:
                workload.fence_campaign()
                break
            except BlockingIOError:
                if time.monotonic() >= fence_deadline:
                    raise ValueError('workload-terminal-fence-timeout') from None
                time.sleep(.05)
    finally:
        # A failed fence must still attempt exact installed owner shutdown. It must
        # not fall through to network deletion or a successful terminal record.
        subprocess.run(['/usr/bin/systemctl', 'stop', 'cryptad-workload-controller.service'],
                       check=True, timeout=max(.001, deadline - time.monotonic()), env=ENV)
    workload.reconcile()
    with workload.locked():
        if not all(workload.quiescent(role) for role in workload.ROLES):
            raise ValueError('workload-terminal-cgroups-not-empty')
        from restricted_workload_network import teardown
        teardown()
    # Role tmpfs state and records remain explicitly retained for private diagnostics.


def begin_cancellation(workload, handoff, result):
    """Observe four current, populated role cgroups before administrator-owned stop."""
    from cross_version_runtime import canonical_digest
    principals = result.get('roleKernelRoster') if isinstance(result, dict) else None
    if (not isinstance(principals, dict) or not isinstance(principals.get('roles'), list)
            or len(principals['roles']) != len(ROLE_NAMES)):
        raise ValueError('workload-cancellation-roster-unavailable')
    expected = {row['role']: row for row in principals['roles']}
    if set(expected) != set(ROLE_NAMES):
        raise ValueError('workload-cancellation-roster-invalid')
    rows = []
    with workload.locked():
        campaign = workload.read(workload.ROOT / 'campaign.json')
        workload.current(campaign)
        for role in ROLE_NAMES:
            _campaign, actual_role, record = workload.retained(handoff['handles'][role])
            state = workload.manager(role, 'show')
            if actual_role != role or state['ActiveState'] != 'active' or state['SubState'] != 'running':
                raise ValueError('workload-cancellation-role-not-active')
            workload.exact(role, record, state)
            if not state['MainPID'].isdecimal() or int(state['MainPID']) <= 0:
                raise ValueError('workload-cancellation-role-main-pid-invalid')
            events = (workload.group(role) / 'cgroup.events').read_text().splitlines()
            if 'populated 1' not in events:
                raise ValueError('workload-cancellation-role-not-populated')
            row = expected[role]
            digest = canonical_digest({'role': role, 'identity': record['cgroupIdentity']})[7:]
            if (row['invocationId'] != record['managerInvocation']
                    or row['bootId'] != record['bootId'].replace('-', '').lower()
                    or row['cgroupDigest'] != digest):
                raise ValueError('workload-cancellation-roster-mismatch')
            rows.append({'role': role, 'managerInvocation': record['managerInvocation'],
                         'bootId': record['bootId'], 'cgroupIdentity': record['cgroupIdentity'],
                         'mainPid': int(state['MainPID'])})
        started = time.monotonic_ns()
        if started >= campaign['deadlineMonotonicNs']:
            raise ValueError('workload-cancellation-deadline')
        event = {'kind': 'cancellation', 'roles': rows,
                 'campaignDeadlineNs': campaign['deadlineMonotonicNs']}
        return {'schemaVersion': 1, 'kind': 'pr315-administrator-cancellation',
                'triggerStartedNs': started, 'triggerEventDigest': canonical_digest(event)[7:],
                'campaignDeadlineNs': campaign['deadlineMonotonicNs'], 'preRoles': rows}


def complete_cancellation(workload, context):
    """Bind the administrator stop to exact retained receipts and empty owned cgroups."""
    with workload.locked():
        for row in context['preRoles']:
            role = row['role']
            state = workload.manager(role, 'show')
            receipt = workload.read(workload.ROOT / 'authority' / (role + '-stop.json'))
            if (state['ActiveState'] not in {'inactive', 'failed'}
                    or state['SubState'] not in {'dead', 'failed'} or state['MainPID'] != '0'
                    or not workload.quiescent(role)
                    or any(receipt[key] != row[key] for key in
                           ('role', 'managerInvocation', 'bootId', 'cgroupIdentity'))):
                raise ValueError('workload-cancellation-terminal-mismatch')
        finished = time.monotonic_ns()
    if finished <= context['triggerStartedNs']:
        raise ValueError('workload-cancellation-clock-invalid')
    return {**context, 'terminalObservedNs': finished,
            'populatedCgroups': [], 'remainingDescendants': 0, 'retention': 'retained'}


def controller_unit_state():
    """Project the fixed installed controller's actual systemd invocation."""
    command = ['/usr/bin/systemctl', 'show', 'cryptad-workload-controller.service',
               '--property=InvocationID,ActiveState,SubState,MainPID,Result', '--no-pager']
    process = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                             env=ENV, timeout=35, check=True)
    if len(process.stdout) > 8192 or len(process.stderr) > 8192:
        raise ValueError('workload-controller-state-output-limit')
    state = dict(line.split('=', 1) for line in process.stdout.decode().splitlines() if '=' in line)
    if (set(state) != {'InvocationID', 'ActiveState', 'SubState', 'MainPID', 'Result'}
            or len(state['InvocationID']) != 32
            or any(character not in '0123456789abcdef' for character in state['InvocationID'])
            or not state['MainPID'].isdecimal()):
        raise ValueError('workload-controller-state-invalid')
    return state


def begin_controller_restart(workload, handoff, result):
    """Bind a fixed restart trigger to four independently observed active role cgroups."""
    from cross_version_runtime import canonical_digest
    active = begin_cancellation(workload, handoff, result)
    before = controller_unit_state()
    if (before['ActiveState'] != 'active' or before['SubState'] != 'running'
            or int(before['MainPID']) <= 0):
        raise ValueError('workload-controller-restart-not-active')
    event = {'kind': 'controller-restart', 'roles': active['preRoles'],
             'campaignDeadlineNs': active['campaignDeadlineNs'],
             'oldControllerInvocation': before['InvocationID']}
    started = time.monotonic_ns()
    if started >= active['campaignDeadlineNs']:
        raise ValueError('workload-controller-restart-deadline')
    return {'schemaVersion': 1, 'kind': 'pr315-administrator-controller-restart',
            'triggerStartedNs': started,
            'triggerEventDigest': canonical_digest(event)[7:],
            'campaignDeadlineNs': active['campaignDeadlineNs'],
            'preRoles': active['preRoles'], 'beforeController': before}


def wait_bound_roles_stopped(workload, context):
    """Observe BindsTo termination before starting a new controller invocation."""
    until = min(time.monotonic() + 35, context['campaignDeadlineNs'] / 10**9)
    while time.monotonic() < until:
        try:
            stopped = []
            for row in context['preRoles']:
                role = row['role']
                state = workload.manager(role, 'show')
                record = workload.read(workload.ROOT / 'authority' / (role + '.json'))
                receipt = workload.stop_receipt(role, record)
                if (state['ActiveState'] not in {'inactive', 'failed'}
                        or state['SubState'] not in {'dead', 'failed'} or state['MainPID'] != '0'
                        or not workload.quiescent(role)
                        or any(record[key] != row[key] for key in
                               ('managerInvocation', 'bootId', 'cgroupIdentity'))):
                    raise ValueError('workload-bound-role-still-active')
                stopped.append({'role': role, 'activeState': state['ActiveState'],
                                'subState': state['SubState'], 'mainPid': 0,
                                'receiptObservedMonotonicNs': receipt['observedMonotonicNs']})
            return stopped
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            time.sleep(min(.05, max(0, until - time.monotonic())))
    raise ValueError('workload-bound-role-stop-timeout')


def trigger_controller_restart(workload, context):
    """Kill the old main process, prove BindsTo stop, then start one new controller."""
    killed = subprocess.run(['/usr/bin/systemctl', 'kill', '--kill-who=main',
                             '--signal=SIGKILL', 'cryptad-workload-controller.service'],
                            stdin=subprocess.DEVNULL, capture_output=True,
                            env=ENV, timeout=20, check=True)
    bound_roles = wait_bound_roles_stopped(workload, context)
    requested = time.monotonic_ns()
    started = subprocess.run(['/usr/bin/systemctl', 'start',
                              'cryptad-workload-controller.service'],
                             stdin=subprocess.DEVNULL, capture_output=True,
                             env=ENV, timeout=100, check=False)
    after = controller_unit_state()
    if after['InvocationID'] == context['beforeController']['InvocationID']:
        raise ValueError('workload-controller-restart-invocation-unchanged')
    return {**context, 'killReturnCode': killed.returncode,
            'preStartBoundRoles': bound_roles,
            'newControllerStartRequestedNs': requested,
            'startReturnCode': started.returncode,
            'afterController': after}


def complete_controller_restart(workload, context):
    """Confirm BindsTo termination and retained reconciliation after the new invocation."""
    with workload.locked():
        for row in context['preRoles']:
            role = row['role']
            state = workload.manager(role, 'show')
            receipt = workload.read(workload.ROOT / 'authority' / (role + '-stop.json'))
            record = workload.read(workload.ROOT / 'authority' / (role + '.json'))
            if (state['ActiveState'] not in {'inactive', 'failed'}
                    or state['SubState'] not in {'dead', 'failed'} or state['MainPID'] != '0'
                    or not workload.quiescent(role)
                    or record['stopReason'] != 'controller-reconciliation'
                    or any(receipt[key] != row[key] for key in
                           ('role', 'managerInvocation', 'bootId', 'cgroupIdentity'))):
                raise ValueError('workload-controller-restart-terminal-mismatch')
        finished = time.monotonic_ns()
    if finished <= context['triggerStartedNs']:
        raise ValueError('workload-controller-restart-clock-invalid')
    return {**context, 'terminalObservedNs': finished,
            'populatedCgroups': [], 'remainingDescendants': 0, 'retention': 'retained'}


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


class AdministratorFnpSampler:
    """Two fixed administrator counter reads over this attempt's inherited private socket."""

    def __init__(self, workload, recipient_handle, diagnostics):
        self.workload = workload
        self.recipient_handle = recipient_handle
        self.diagnostics = diagnostics
        self.phase = 'initial'

    def sample(self, phase):
        if (phase, self.phase) not in {('before', 'initial'), ('after', 'before')}:
            raise ValueError('workload-admin-fnp-phase-invalid')
        from restricted_workload_network import read_fnp_counters
        workload = self.workload
        with workload.locked():
            campaign, role, record = workload.retained(self.recipient_handle)
            if role != 'candidate-recipient':
                raise ValueError('workload-admin-fnp-recipient-invalid')
            workload.admit(campaign)
            workload.exact(role, record, workload.manager(role, 'show'))
            snapshot = read_fnp_counters()
            workload.exact(role, record, workload.manager(role, 'show'))
            workload.current(campaign)
            path = workload.ROOT / 'authority/fnp-content-probe.json'
            if phase == 'before':
                if os.path.lexists(path):
                    raise ValueError('workload-admin-fnp-pair-exists')
                pair = {'schemaVersion': 1, 'kind': 'pr315-administrator-fnp-counter-pair',
                        'caseId': 'fnp-content-retrieval', 'role': role,
                        'managerInvocation': record['managerInvocation'],
                        'before': snapshot, 'after': None}
                workload.write(path, pair, create=True)
            else:
                pair = workload.read(path)
                before = pair.get('before') if isinstance(pair, dict) else None
                if (not isinstance(pair, dict)
                        or set(pair) != {'schemaVersion', 'kind', 'caseId', 'role',
                                         'managerInvocation', 'before', 'after'}
                        or pair['schemaVersion'] != 1
                        or pair['kind'] != 'pr315-administrator-fnp-counter-pair'
                        or pair['caseId'] != 'fnp-content-retrieval' or pair['role'] != role
                        or pair['managerInvocation'] != record['managerInvocation']
                        or pair['after'] is not None or not isinstance(before, dict)
                        or any(before.get(key) != snapshot.get(key) for key in
                               ('policyDigest', 'bootId', 'switchNamespaceIdentity'))
                        or type(before.get('observedMonotonicNs')) is not int
                        or before['observedMonotonicNs'] >= snapshot['observedMonotonicNs']):
                    raise ValueError('workload-admin-fnp-pair-invalid')
                pair['after'] = snapshot
                workload.write(path, pair)
        self.phase = phase
        return {'phase': phase, 'managerInvocation': record['managerInvocation'],
                'snapshot': snapshot}

    def serve(self, channel):
        message, _ancillary, flags, _address = channel.recvmsg(2)
        if not message:
            return False
        try:
            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or message not in (b'B', b'A'):
                raise ValueError('workload-admin-fnp-request-invalid')
            result = self.sample('before' if message == b'B' else 'after')
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            private = getattr(error, 'private_diagnostics', None)
            self.diagnostics['fnpAdminFailure'] = {
                'phase': self.phase, 'exceptionType': type(error).__name__[:128],
                'networkFailureClass': (private.get('failureClass')
                    if isinstance(private, dict) and isinstance(private.get('failureClass'), str)
                    else None)}
            result = {'error': 'pr315-admin-fnp-sample-failed'}
        raw = json.dumps(result, sort_keys=True, separators=(',', ':')).encode() + b'\n'
        if len(raw) > 8192:
            raise ValueError('workload-admin-fnp-response-limit')
        channel.sendall(raw)
        return True


def request_administrator_fnp(channel, phase, campaign_deadline):
    """One fixed phase request; the administrator owns namespace access and durable pair."""
    from cross_version_runtime import RuntimeFailure
    if phase not in ('before', 'after'):
        raise RuntimeFailure('workload-admin-fnp-phase-invalid')
    remaining = campaign_deadline / 10**9 - time.monotonic()
    if remaining <= 0:
        raise RuntimeFailure('workload-admin-fnp-deadline')
    channel.settimeout(min(90, remaining))
    try:
        channel.sendall(b'B' if phase == 'before' else b'A')
        raw = channel.recv(8193)
        if not 1 <= len(raw) <= 8192 or not raw.endswith(b'\n') or raw.count(b'\n') != 1:
            raise RuntimeFailure('workload-admin-fnp-response-invalid')
        value = json.loads(raw)
        if not isinstance(value, dict) or 'error' in value:
            raise RuntimeFailure('workload-admin-fnp-sample-failed')
        return value
    except RuntimeFailure:
        raise
    except (OSError, ValueError):
        raise RuntimeFailure('workload-admin-fnp-transport-failed') from None


def collect_child(parent, pid, deadline, sample=None, *, admin_channel=None, admin_sampler=None):
    raw = bytearray()
    next_sample = 0
    while time.monotonic() < deadline:
        if sample is not None and time.monotonic() >= next_sample:
            sample()
            next_sample = time.monotonic() + 5
        watched = [parent] if admin_channel is None else [parent, admin_channel]
        ready, _, _ = select.select(watched, [], [], min(1, max(.001, deadline - time.monotonic())))
        if admin_channel is not None and admin_channel in ready:
            if not admin_sampler.serve(admin_channel):
                admin_channel = None
        if parent in ready:
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


def readiness_deadline(campaign_deadline_ns, started, startup_measurement=False):
    """Prospective diagnostic observation never extends the retained execution deadline."""
    seconds = STARTUP_MEASUREMENT_SECONDS if startup_measurement else READINESS_SECONDS
    return min(campaign_deadline_ns / 10**9, started + seconds)


def observer_sequence(selected, root, handoff, campaign_deadline, startup_begin,
                      startup_measurement=False, *, admin_channel=None):
    """The diagnostic stops at the actual served readiness response, before any role start."""
    controller_ready(readiness_deadline(campaign_deadline, startup_begin, startup_measurement))
    if startup_measurement:
        return {'classification': 'startup-measurement-not-workload-acceptance',
                'controllerReadiness': 'observed-root-peer-response',
                'startupElapsedSeconds': time.monotonic() - startup_begin,
                'observationCeilingSeconds': STARTUP_MEASUREMENT_SECONDS,
                'installedPositiveExecuted': False}
    from cross_version_workload import InstalledWorkloadAdapter
    from cryptad_certification.cross_version_evidence import Journal
    with Journal(root, selected['plan']) as journal:
        journal.append('start')
        adapter = InstalledWorkloadAdapter(selected['plan'], selected['private'],
            selected['authorization'], journal, handoff,
            counter_sampler=(lambda phase: request_administrator_fnp(
                admin_channel, phase, campaign_deadline)) if admin_channel is not None else None)
        result = adapter.run_positive(leave_running_for_administrator=True)
        journal.checkpoint('partial')
    return result


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
            for name in ('memory.events', 'cgroup.events', 'cpu.stat'):
                rows = [line.split() for line in _kernel_read(path / name).splitlines()]
                if any(len(row) != 2 or not row[1].isdecimal() for row in rows):
                    raise ValueError('cgroup-events-invalid')
                metrics[name] = {key: int(value) for key, value in rows}
            quota, period = _kernel_read(path / 'cpu.max').split()
            if (quota != 'max' and not quota.isdecimal()) or not period.isdecimal() or int(period) <= 0:
                raise ValueError('cgroup-cpu-limit-invalid')
            metrics['cpu.max'] = {'quota': quota if quota == 'max' else int(quota), 'period': int(period)}
            after = path.stat(follow_symlinks=False)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise ValueError('cgroup-replaced')
            snapshot['services'][unit] = {'status': 'observed',
                'cgroupIdentity': [before.st_dev, before.st_ino], **metrics}
        except FileNotFoundError:
            snapshot['services'][unit] = {'status': 'absent-or-removed-not-quiescence-proof'}
        except (OSError, ValueError):
            snapshot['services'][unit] = {'status': 'unavailable'}
    snapshot['finishedMonotonicNs'] = time.monotonic_ns()
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
        peak['lastObservedWindow'] = {'startedMonotonicNs': snapshot['observedMonotonicNs'],
                                      'finishedMonotonicNs': snapshot['finishedMonotonicNs']}


def observer_failure(error):
    """Keep a bounded immediate propagation cause in the existing private child response."""
    from pr315_workload_guest import _bounded_text
    result = {'observerFailure': _bounded_text(type(error).__name__, 128),
              'privateDetail': _bounded_text(str(error), 1024)}
    cause = error.__cause__
    if cause is not None and cause is not error:
        result['immediateCause'] = {'exceptionType': _bounded_text(type(cause).__name__, 128),
            'privateDetail': _bounded_text(str(cause), 512),
            'meaning': 'python-explicit-cause-not-acceptance'}
    # A shared deadline exception alone cannot locate the expired operation. Retain
    # bounded code locations, never frame locals, source lines or absolute paths.
    components = {'cross_version_workload.py', 'cross_version_runtime.py',
                  'interop_smoke.py', 'pr314_workload_driver.py'}
    frames = []
    current = error.__traceback__
    for _ in range(64):
        if current is None:
            break
        code = current.tb_frame.f_code
        component = Path(code.co_filename).name
        if (component in components and code.co_name.isascii()
                and code.co_name.isidentifier() and len(code.co_name) <= 64):
            frames.append(component + ':' + code.co_name + ':' + str(current.tb_lineno))
        current = current.tb_next
    if frames:
        result['privateCodeLocations'] = frames[-8:]
    return result


def execute(*, startup_measurement=False, lifecycle_scenario='cancellation'):
    if lifecycle_scenario not in LIFECYCLE_SCENARIOS:
        raise ValueError('workload-lifecycle-scenario-invalid')
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
    from restricted_workload_launcher import launcher_policy
    import pr315_workload_evidence as evidence
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
    parent = child = admin_parent = admin_child = None
    pid = None
    status = None
    result = None
    diagnostics = {'classification': 'private-kernel-diagnostics-not-acceptance',
                   'before': memory_snapshot(), 'cleanup': 'not-completed'}
    sentinel = None
    cancellation = None
    controller_restart = None
    try:
        handoff = prepare(selected['plan'], selected['private'], selected['authorization'])
        campaign_deadline = workload.read(workload.ROOT / 'campaign.json')['deadlineMonotonicNs']
        if type(campaign_deadline) is not int or campaign_deadline <= time.monotonic_ns():
            raise ValueError('workload-preparation-consumed-deadline')
        if (type(handoff.get('deadlineMonotonicNs')) is not int
                or handoff['deadlineMonotonicNs'] != campaign_deadline):
            raise ValueError('workload-handoff-deadline-mismatch')
        sentinel = evidence.prepare_sentinel(workload)
        root.mkdir(mode=0o700)
        os.chown(root, observer.pw_uid, observer.pw_gid)
        startup_begin = time.monotonic()
        subprocess.run(['/usr/bin/systemctl', 'start', 'cryptad-workload-controller.service'],
                       check=True, timeout=30, env=ENV)
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        admin_parent, admin_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        pid = os.fork()
        if pid == 0:
            parent.close()
            admin_parent.close()
            try:
                os.setgroups([])
                os.setgid(observer.pw_gid)
                os.setuid(observer.pw_uid)
                os.environ.clear()
                os.environ.update(ENV)
                os.umask(0o077)
                result = observer_sequence(selected, root, handoff, campaign_deadline,
                                           startup_begin, startup_measurement,
                                           admin_channel=admin_child)
                child.sendall(json.dumps(result, separators=(',', ':')).encode())
                child.close()
                admin_child.close()
                os._exit(0)
            except BaseException as error:
                try:
                    child.sendall(json.dumps(observer_failure(error)).encode())
                except OSError:
                    pass
                child.close()
                admin_child.close()
                os._exit(1)
        child.close()
        admin_child.close()
        # Preparation already started the campaign clock. Observation gets only the
        # original deadline plus bounded teardown grace, never a new execution budget.
        deadline = campaign_deadline / 10**9 + 100
        sampler = AdministratorFnpSampler(workload,
            handoff['handles']['candidate-recipient'], diagnostics)
        raw, status = collect_child(parent, pid, deadline,
            lambda: sample_memory(diagnostics), admin_channel=admin_parent,
            admin_sampler=sampler)
        if status != 0:
            diagnostics['observerFailure'] = {'exitStatus': status,
                'privateTranscript': raw[:4096].decode('utf-8', errors='replace')}
            raise ValueError('workload-positive-sequence-failed')
        result = json.loads(raw)
        if not startup_measurement and (result.get('contentRetrieval') != 'observed' or result.get('newEpoch') is not True):
            raise ValueError('workload-positive-observation-incomplete')
        result.update(identity=identity, runtimePolicy=launcher_policy(),
                      finiteNativeAcceptance='not-executed-by-this-driver',
                      campaignDeadlineMonotonicNs=campaign_deadline,
                      workloadAcceptance=('not-executed-startup-measurement' if startup_measurement
                          else 'incomplete-hostile-contract-not-executed'), protectedExecutionEnabled=False)
        if not startup_measurement and lifecycle_scenario == 'cancellation':
            try:
                cancellation = begin_cancellation(workload, handoff, result)
                diagnostics['cancellation'] = cancellation
            except (OSError, ValueError, KeyError, TypeError, AttributeError,
                    subprocess.SubprocessError) as error:
                diagnostics['cancellation'] = {'status': 'unavailable-or-unsafe',
                                               'exceptionType': type(error).__name__[:128]}
        if not startup_measurement and lifecycle_scenario == 'controller-restart':
            try:
                active = begin_controller_restart(workload, handoff, result)
                controller_restart = trigger_controller_restart(workload, active)
                diagnostics['controllerRestart'] = controller_restart
            except (OSError, ValueError, KeyError, TypeError, AttributeError,
                    subprocess.SubprocessError) as error:
                diagnostics['controllerRestart'] = {'status': 'unavailable-or-unsafe',
                                                    'exceptionType': type(error).__name__[:128]}
    finally:
        try:
            if parent is not None:
                parent.close()
            if child is not None:
                child.close()
            if admin_parent is not None:
                admin_parent.close()
            if admin_child is not None:
                admin_child.close()
            if pid is not None and pid > 0 and status is None:
                stop_child(pid)
        finally:
            try:
                diagnostics['controllerStartup'] = controller_startup_snapshot(workload)
                cleanup(workload)
                diagnostics['cleanup'] = 'completed'
                if cancellation is not None:
                    try:
                        diagnostics['cancellation'] = complete_cancellation(workload, cancellation)
                    except (OSError, ValueError, KeyError, TypeError, AttributeError,
                            subprocess.SubprocessError) as error:
                        diagnostics['cancellation'] = {'status': 'unavailable-or-unsafe',
                                                       'exceptionType': type(error).__name__[:128]}
                if controller_restart is not None:
                    try:
                        diagnostics['controllerRestart'] = complete_controller_restart(
                            workload, controller_restart)
                    except (OSError, ValueError, KeyError, TypeError, AttributeError,
                            subprocess.SubprocessError) as error:
                        diagnostics['controllerRestart'] = {'status': 'unavailable-or-unsafe',
                                                            'exceptionType': type(error).__name__[:128]}
            finally:
                diagnostics['after'] = memory_snapshot()
                workload.write(DIAGNOSTICS, diagnostics, create=True)
                volatile = evidence.capture(workload, sentinel, diagnostics['cleanup'] == 'completed',
                                            observer_root=root)
                workload.write(VOLATILE, volatile, create=True)
                if (sentinel is not None and diagnostics['cleanup'] == 'completed'
                        and volatile['sentinel']['status'] != 'matched'):
                    raise ValueError('workload-retained-sentinel-not-established')
    # No terminal result can exist before owned controller/role/network cleanup succeeds.
    workload.write(REPORT, result, create=True)
    return {'status': 'startup-measurement-executed' if startup_measurement else 'positive-sequence-executed',
            'workloadAcceptance': 'incomplete',
            'protectedExecutionEnabled': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--lifecycle-scenario', choices=LIFECYCLE_SCENARIOS,
                        default='cancellation')
    args = parser.parse_args()
    reasons = prerequisites()
    if reasons:
        print(json.dumps({'status': 'not-executed', 'reasons': reasons, 'protectedExecutionEnabled': False}))
        return 78
    if not args.execute:
        print(json.dumps({'status': 'prerequisites-present-not-executed', 'protectedExecutionEnabled': False}))
        return 0
    print(json.dumps(execute(lifecycle_scenario=args.lifecycle_scenario), sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        result = main()
    except Exception:
        print('{"status":"failed-private-reconciliation-required","protectedExecutionEnabled":false}')
        result = 1
    raise SystemExit(result)

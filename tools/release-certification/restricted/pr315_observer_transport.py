#!/usr/bin/python3
"""Fixed observer transport for the measured administrator test kit.

The caller supplies its actual driver module explicitly. Kernel, clock and
process hooks therefore retain the same installed or offline execution epoch;
this helper adds no controller methods, caller-selected paths or authority.
"""

def revocation_request(driver, observer, handle, controller_pid, *, prepare_peer=None, publish=None):
    """Use one exact observer UID and fixed controller method after root revocation."""
    if (observer.pw_uid <= 0 or observer.pw_gid <= 0
            or driver.re.fullmatch('[0-9a-f]{64}', handle) is None
            or type(controller_pid) is not int or controller_pid <= 1
            or (prepare_peer is None) != (publish is None)):
        raise ValueError('workload-revocation-observer-selection-invalid')
    request = (b'{"method":"start","handle":"' + handle.encode() + b'"}\n')
    response = b'{"error":"restricted-workload-request-failed"}\n'
    parent, child = driver.socket.socketpair(driver.socket.AF_UNIX, driver.socket.SOCK_SEQPACKET)
    pid = driver.os.fork()
    if pid == 0:
        parent.close()
        try:
            allowed = {0, 1, 2, child.fileno()}
            for name in driver.os.listdir('/proc/self/fd'):
                if name.isdecimal() and int(name) not in allowed:
                    try:
                        driver.os.close(int(name))
                    except OSError:
                        pass
            driver.os.setgroups([])
            driver.os.setgid(observer.pw_gid)
            driver.os.setuid(observer.pw_uid)
            driver.os.environ.clear()
            driver.os.environ.update(driver.ENV)
            child.sendall(b'R')
            child.settimeout(5)
            if child.recv(1) != b'G':
                raise ValueError('workload-revocation-barrier-invalid')
            with driver.socket.socket(driver.socket.AF_UNIX, driver.socket.SOCK_STREAM) as channel:
                channel.settimeout(5)
                channel.connect(driver.REVOCATION_CONTROL_SOCKET)
                peer, uid, _gid = driver.struct.unpack('3i', channel.getsockopt(
                    driver.socket.SOL_SOCKET, driver.socket.SO_PEERCRED, driver.struct.calcsize('3i')))
                if peer != controller_pid or uid != 0:
                    raise ValueError('workload-revocation-controller-peer-invalid')
                if prepare_peer is not None:
                    channel.sendall(b'P')
                    if channel.recv(1) != b'R':
                        raise ValueError('workload-revocation-controller-not-accepted')
                    child.sendall(b'A')
                    if child.recv(1) != b'G':
                        raise ValueError('workload-revocation-barrier-invalid')
                channel.sendall(request)
                raw = bytearray()
                while len(raw) <= len(response) and not raw.endswith(b'\n'):
                    block = channel.recv(len(response) + 1 - len(raw))
                    if not block:
                        break
                    raw.extend(block)
                if bytes(raw) != response:
                    raise ValueError('workload-revocation-denial-not-observed')
            child.sendall(b'1')
            driver.os._exit(0)
        except BaseException:
            try:
                child.sendall(b'0')
            except OSError:
                pass
            driver.os._exit(1)
    child.close()
    reaped = False
    try:
        parent.settimeout(5)
        if parent.recv(1) != b'R':
            raise ValueError('workload-revocation-observer-not-ready')
        proc = driver.Path('/proc') / str(pid)
        status = next(line for line in proc.joinpath('status').read_text().splitlines()
                      if line.startswith('Uid:'))
        if set(map(int, status.split()[1:])) != {observer.pw_uid}:
            raise ValueError('workload-revocation-observer-uid-invalid')
        start_ticks = int(proc.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19])
        actor = {'pid': pid, 'uid': observer.pw_uid, 'startTicks': start_ticks}
        if prepare_peer is not None:
            prepare_peer(actor)
        started = driver.time.monotonic_ns()
        parent.sendall(b'G')
        if publish is not None:
            if parent.recv(1) != b'A':
                raise ValueError('workload-revocation-controller-not-accepted')
            publish()
            started = driver.time.monotonic_ns()
            parent.sendall(b'G')
        observed = parent.recv(1)
        finished = driver.time.monotonic_ns()
        status = driver.wait_child(pid, driver.time.monotonic() + 5)
        reaped = True
        if observed != b'1' or status != 0 or start_ticks <= 0 or finished <= started:
            raise ValueError('workload-revocation-denial-not-observed')
        return {'actor': actor,
                'requestDigest': driver.hashlib.sha256(request).hexdigest(),
                'responseDigest': driver.hashlib.sha256(response).hexdigest(),
                'requestStartedNs': started, 'responseObservedNs': finished}
    finally:
        parent.close()
        if not reaped:
            driver.stop_child(pid)



def observer_request(driver, observer, handle, controller_pid, invocation, *,
                            normal_exit=False, deadline_ns=None):
    """Complete one fixed real observer request, then prove death or normal exit."""
    if (type(normal_exit) is not bool or normal_exit and
            (type(deadline_ns) is not int or deadline_ns <= driver.time.monotonic_ns())):
        raise ValueError('workload-deadline-observer-budget-invalid')
    if (observer.pw_uid <= 0 or observer.pw_gid <= 0
            or driver.re.fullmatch('[0-9a-f]{64}', handle) is None
            or type(controller_pid) is not int or controller_pid <= 1
            or driver.re.fullmatch('[0-9a-f]{32}', invocation) is None
            or not hasattr(driver.os, 'pidfd_open')
            or not hasattr(driver.signal, 'pidfd_send_signal')):
        raise ValueError('workload-observer-death-selection-invalid')
    request = (b'{"method":"observe","handle":"' + handle.encode() + b'"}\n')
    parent, child = driver.socket.socketpair(driver.socket.AF_UNIX, driver.socket.SOCK_SEQPACKET)
    pid = driver.os.fork()
    if pid == 0:
        parent.close()
        try:
            allowed = {0, 1, 2, child.fileno()}
            for name in driver.os.listdir('/proc/self/fd'):
                if name.isdecimal() and int(name) not in allowed:
                    try:
                        driver.os.close(int(name))
                    except OSError:
                        pass
            driver.os.setgroups([])
            driver.os.setgid(observer.pw_gid)
            driver.os.setuid(observer.pw_uid)
            driver.os.environ.clear()
            driver.os.environ.update(driver.ENV)
            child.sendall(b'R')
            child.settimeout(40)
            if child.recv(1) != b'G':
                raise ValueError('workload-observer-death-barrier-invalid')
            with driver.socket.socket(driver.socket.AF_UNIX, driver.socket.SOCK_STREAM) as channel:
                channel.settimeout(40)
                channel.connect(driver.OBSERVER_DEATH_CONTROL_SOCKET)
                peer, uid, _gid = driver.struct.unpack('3i', channel.getsockopt(
                    driver.socket.SOL_SOCKET, driver.socket.SO_PEERCRED, driver.struct.calcsize('3i')))
                if peer != controller_pid or uid != 0:
                    raise ValueError('workload-observer-death-controller-peer-invalid')
                channel.sendall(request)
                raw = bytearray()
                while len(raw) <= 1024 * 1024 and not raw.endswith(b'\n'):
                    block = channel.recv(min(65536, 1024 * 1024 + 1 - len(raw)))
                    if not block:
                        break
                    raw.extend(block)
                if not 0 < len(raw) <= 1024 * 1024 or not raw.endswith(b'\n'):
                    raise ValueError('workload-observer-death-response-invalid')
                value = driver.json.loads(raw)
                if (not isinstance(value, dict) or value.get('handle') != handle
                        or value.get('state') != 'running'
                        or value.get('managerInvocation') != invocation
                        or value.get('provenance') != 'controller-kernel-sample'):
                    raise ValueError('workload-observer-death-response-invalid')
            child.sendall(b'1' + driver.hashlib.sha256(raw).hexdigest().encode())
            child.settimeout(None)
            if normal_exit:
                driver.os._exit(0 if child.recv(1) == b'E' else 1)
            while child.recv(1):
                pass
            driver.os._exit(1)
        except BaseException:
            try:
                child.sendall(b'0')
            except OSError:
                pass
            driver.os._exit(1)
    child.close()
    reaped = False
    pidfd = None
    try:
        parent.settimeout(5)
        if parent.recv(1) != b'R':
            raise ValueError('workload-observer-death-child-not-ready')
        proc = driver.Path('/proc') / str(pid)
        status = next(line for line in proc.joinpath('status').read_text().splitlines()
                      if line.startswith('Uid:'))
        if set(map(int, status.split()[1:])) != {observer.pw_uid}:
            raise ValueError('workload-observer-death-child-uid-invalid')
        start_ticks = int(proc.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19])
        epoch = (driver._positive_observer_epoch(pid, observer.pw_uid, deadline_ns)
                 if normal_exit else None)
        started = driver.time.monotonic_ns()
        parent.sendall(b'G')
        parent.settimeout(40)
        response = parent.recv(65)
        finished = driver.time.monotonic_ns()
        if (len(response) != 65 or response[:1] != b'1'
                or driver.re.fullmatch(b'[0-9a-f]{64}', response[1:]) is None
                or start_ticks <= 0 or finished <= started):
            raise ValueError('workload-observer-death-activity-unobserved')
        pidfd = driver.os.pidfd_open(pid)
        if int(proc.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19]) != start_ticks:
            raise ValueError('workload-observer-death-child-replaced')
        if normal_exit:
            exit_started = driver.time.monotonic_ns()
            parent.sendall(b'E')
            status = driver.wait_child(pid, min(driver.time.monotonic() + 5, deadline_ns / 1e9 + 5))
            reaped = True
            exit_finished = driver.time.monotonic_ns()
            if status != 0 or exit_finished <= exit_started:
                raise ValueError('workload-deadline-observer-exit-invalid')
            return {'actor': epoch, 'requestDigest': driver.hashlib.sha256(request).hexdigest(),
                'responseDigest': response[1:].decode(),
                'requestStartedNs': started, 'responseObservedNs': finished,
                'exitStartedNs': exit_started, 'exitObservedNs': exit_finished,
                'pidfdUsed': True, 'exitStatus': 0}
        kill_started = driver.time.monotonic_ns()
        driver.signal.pidfd_send_signal(pidfd, driver.signal.SIGTERM)
        status = driver.wait_child(pid, driver.time.monotonic() + 5)
        reaped = True
        kill_finished = driver.time.monotonic_ns()
        if (not driver.os.WIFSIGNALED(status) or driver.os.WTERMSIG(status) != driver.signal.SIGTERM
                or kill_finished <= kill_started):
            raise ValueError('workload-observer-death-child-not-killed')
        return {'actor': {'pid': pid, 'uid': observer.pw_uid,
                          'startTicks': start_ticks},
                'requestDigest': driver.hashlib.sha256(request).hexdigest(),
                'responseDigest': response[1:].decode(),
                'requestStartedNs': started, 'responseObservedNs': finished,
                'killStartedNs': kill_started, 'killFinishedNs': kill_finished,
                'pidfdUsed': True}
    finally:
        if pidfd is not None:
            driver.os.close(pidfd)
        parent.close()
        if not reaped:
            driver.stop_child(pid)



def deadline_activity(driver, workload, context):
    """Perform one fixed real observer request while preserving the original expiry."""
    campaign = workload.read(workload.ROOT / 'campaign.json')
    if (campaign['deadlineMonotonicNs'] != context['campaignDeadlineNs']
            or driver.time.monotonic_ns() >= context['campaignDeadlineNs']):
        raise ValueError('workload-deadline-heartbeat-expired')
    sender = next(row for row in context['preRoles'] if row['role'] == 'candidate-sender')
    controller = driver.controller_unit_identity(workload)
    result = driver._observer_death_request(driver.pwd.getpwnam('cryptad-soak'),
        campaign['handles']['candidate-sender'], controller['mainPid'],
        sender['managerInvocation'], normal_exit=True,
        deadline_ns=context['campaignDeadlineNs'])
    return {**result, 'controllerInvocation': controller['invocationId'],
            'controllerPid': controller['mainPid'],
            'controllerStartTicks': controller['mainStartTicks']}

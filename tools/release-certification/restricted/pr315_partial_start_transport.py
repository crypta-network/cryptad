#!/usr/bin/python3
"""Fixed installed previous-role start, with a live observer through sampling."""
import json

POLICY = 'pr315-partial-launch-start-response-v2'


def start(driver, observer, handle, deadline_ns):
    """Use the existing start RPC, then keep its real observer alive for root."""
    from cross_version_workload import WorkloadClient, runtime
    if (observer.pw_uid <= 0 or observer.pw_gid <= 0
            or driver.re.fullmatch('[0-9a-f]{64}', handle) is None):
        raise ValueError('workload-partial-launch-observer-invalid')
    parent, child = driver.socket.socketpair(driver.socket.AF_UNIX, driver.socket.SOCK_STREAM)
    started_ns = driver.time.monotonic_ns()
    try:
        pid = driver.os.fork()
    except BaseException:
        parent.close()
        child.close()
        raise
    if pid == 0:
        parent.close()
        try:
            driver.os.setgroups([])
            driver.os.setgid(observer.pw_gid)
            driver.os.setuid(observer.pw_uid)
            driver.os.environ.clear()
            driver.os.environ.update(driver.ENV)
            try:
                response = WorkloadClient().request('start', handle)
                classification = ('transient-start-response' if response.get('state') == 'running'
                                  else 'unexpected-start-response')
            except runtime.RuntimeFailure:
                classification = 'controller-rejected-launch'
            child.sendall(json.dumps({'classification': classification},
                separators=(',', ':')).encode() + b'\n')
            remaining = (deadline_ns-driver.time.monotonic_ns())/1e9
            if remaining <= 0:
                driver.os._exit(1)
            child.settimeout(min(45, remaining))
            if child.recv(1) != b'G':
                driver.os._exit(1)
            driver.os._exit(0)
        except BaseException:
            driver.os._exit(1)
    child.close()
    try:
        # This is the existing 45-second collection allowance, before sampling.
        until_ns = min(driver.time.monotonic_ns()+45*10**9, deadline_ns)
        raw = bytearray()
        while not raw.endswith(b'\n'):
            remaining = (until_ns-driver.time.monotonic_ns())/1e9
            if remaining <= 0:
                raise ValueError('workload-partial-launch-start-response-timeout')
            parent.settimeout(remaining)
            block = parent.recv(513-len(raw))
            if not block or len(raw)+len(block)>512:
                raise ValueError('workload-partial-launch-start-response-invalid')
            raw.extend(block)
        value = json.loads(raw)
        if (set(value) != {'classification'} or value['classification'] not in (
                'controller-rejected-launch', 'transient-start-response')):
            raise ValueError('workload-partial-launch-start-response-invalid')
        observed_ns = driver.time.monotonic_ns()
        parent.settimeout(None)
        return parent, pid, value, started_ns, observed_ns
    except BaseException:
        parent.close()
        driver.stop_child(pid)
        raise


def finish(driver, parent, pid, deadline_ns):
    """Release only the observer child just started, then prove its normal exit."""
    try:
        parent.sendall(b'G')
        raw, status = driver.collect_child(parent, pid,
            min(driver.time.monotonic()+45, deadline_ns/1e9))
        if raw or status != 0:
            raise ValueError('workload-partial-launch-start-response-invalid')
    except BaseException:
        try:
            driver.stop_child(pid)
        except ChildProcessError:
            pass
        raise
    finally:
        parent.close()

#!/usr/bin/python3
"""Trusted -I -S bootstrap; the ENTIRE externally measured Python runtime is initial TCB.

All stdlib imports below already execute trusted code, before any local verification.
The offline measure_runtime_image.py procedure must precede starting this image.
Verify the installed application verifier itself before importing it. Its complete source/dependency checks
then precede imports of credential-using owners. No checkout or caller environment supplies code.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import socket
import sys

ROOT = Path('/opt/cryptad-cross-version/current')
APPROVAL = Path('/etc/cryptad-certification/restricted-installation.json')
DIAGNOSTICS = Path('/var/lib/cryptad-restricted/bootstrap')
NOTIFY_SOCKET = '/run/systemd/notify'
MAX_BOOTSTRAP_ATTEMPTS = 128


def trusted(path):
    for entry in (path, *path.parents):
        value = entry.lstat()
        if stat.S_ISLNK(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022:
            raise ValueError('restricted-bootstrap-untrusted-file')
    return path


class Stages:
    """Private append-only bounded attempt history; exhaustion requires operator reconciliation."""
    def __init__(self):
        DIAGNOSTICS.mkdir(mode=0o700, exist_ok=True)
        trusted(DIAGNOSTICS)
        if DIAGNOSTICS.stat().st_mode & 0o077:
            raise ValueError('restricted-bootstrap-private-diagnostics-required')
        with os.scandir(DIAGNOSTICS) as entries:
            for count, _entry in enumerate(entries, 1):
                if count >= MAX_BOOTSTRAP_ATTEMPTS:
                    raise ValueError('restricted-bootstrap-attempt-capacity')
        self.fd = os.open(DIAGNOSTICS / (os.urandom(16).hex() + '.jsonl'),
                          os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.fchmod(self.fd, 0o600)
        self.stage = 'source-verification'
        try:
            self.record(self.stage)
            directory = os.open(DIAGNOSTICS, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except BaseException:
            self.close()
            raise

    def record(self, stage, status='entered'):
        if stage not in {'source-verification', 'kernel-verification', 'installation-verification',
                         'request-loop-initialization', 'bootstrap-ready'} or status not in {'entered', 'failed'}:
            raise ValueError('restricted-bootstrap-stage-invalid')
        if os.fstat(self.fd).st_size > 1024:
            raise ValueError('restricted-bootstrap-diagnostic-capacity')
        self.stage = stage
        raw = (json.dumps({'stage': stage, 'status': status}, sort_keys=True) + '\n').encode('ascii')
        if os.write(self.fd, raw) != len(raw):
            raise OSError('restricted-bootstrap-diagnostic-write-failed')
        os.fsync(self.fd)

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def notification_channel():
    """Only the fixed, manager-owned channel is retained, never its environment variable."""
    if os.environ.get('NOTIFY_SOCKET') != NOTIFY_SOCKET:
        raise ValueError('restricted-bootstrap-notification-required')
    path = Path(NOTIFY_SOCKET)
    trusted(path.parent)
    value = path.lstat()
    if not stat.S_ISSOCK(value.st_mode) or value.st_uid != 0:
        raise ValueError('restricted-bootstrap-notification-untrusted')
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC)
    try:
        channel.settimeout(5)
        channel.connect(NOTIFY_SOCKET)
    except BaseException:
        channel.close()
        raise
    return channel


def main():
    if os.geteuid() != 0 or not sys.flags.isolated or not sys.flags.no_site:
        raise ValueError('restricted-bootstrap-isolated-root-required')
    stages = Stages()
    try:
        initialize(stages)
    except BaseException:
        if stages.fd >= 0:
            stages.record(stages.stage, 'failed')
        raise
    finally:
        stages.close()


def initialize(stages):
    if os.geteuid() != 0 or not sys.flags.isolated or not sys.flags.no_site:
        raise ValueError('restricted-bootstrap-isolated-root-required')
    if APPROVAL.stat().st_mode & 0o077:
        raise ValueError('restricted-bootstrap-private-approval-required')
    approval = json.loads(trusted(APPROVAL).read_bytes())
    manifest_bytes = trusted(ROOT / '.restricted-manifest.json').read_bytes()
    if hashlib.sha256(manifest_bytes).hexdigest() != approval['bundleIdentity']:
        raise ValueError('restricted-bootstrap-manifest-mismatch')
    manifest = json.loads(manifest_bytes)
    relative = 'tools/release-certification/restricted/installation.py'
    verifier = trusted(ROOT / relative)
    if hashlib.sha256(verifier.read_bytes()).hexdigest() != manifest['files'][relative]['sha256']:
        raise ValueError('restricted-bootstrap-verifier-mismatch')
    # Only activation and the fixed manager notification channel survive initialization.
    if os.environ.get('LISTEN_PID') != str(os.getpid()) or os.environ.get('LISTEN_FDS') != '1':
        raise ValueError('restricted-bootstrap-socket-activation-required')
    channel = notification_channel()
    try:
        initialize_verified(verifier, stages, channel)
    finally:
        channel.close()


def initialize_verified(verifier, stages, channel):
    for name in os.listdir('/proc/self/fd'):
        number = int(name)
        if number > 3 and number not in {channel.fileno(), stages.fd}:
            try:
                os.close(number)
            except OSError:
                pass
    os.set_inheritable(3, False)
    os.environ.clear()
    os.environ.update(PATH='/usr/bin:/bin', LANG='C.UTF-8', HOME='/var/empty',
                      PYTHONDONTWRITEBYTECODE='1', LISTEN_PID=str(os.getpid()), LISTEN_FDS='1')
    os.chdir(ROOT)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(verifier.parent))
    import installation
    stages.record('kernel-verification')
    installation.verify_controller_process()
    stages.record('installation-verification')
    result = installation.verify()
    sys.path.insert(0, str(ROOT / 'tools/release-certification/protected'))
    import restricted_worker
    stages.record('request-loop-initialization')
    main_pid = os.getpid()
    notified = False
    def ready():
        nonlocal notified
        if notified or os.getpid() != main_pid:
            raise ValueError('restricted-bootstrap-notification-invalid')
        # This durable stage means checks passed; only the manager authenticates signal receipt.
        stages.record('bootstrap-ready')
        if channel.send(b'READY=1') != len(b'READY=1'):
            raise OSError('restricted-bootstrap-notification-failed')
        notified = True
        channel.close()
        stages.close()
    restricted_worker.main(bundle_identity=result['bundleIdentity'], ready=ready)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Bootstrap failures expose only this fixed verdict, including import/probe failures.
        raise SystemExit('restricted-bootstrap-rejected') from None

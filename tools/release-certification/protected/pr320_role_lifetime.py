"""Set only the fixed role pool's source-owned runtime ceiling before any launch."""
import os
from pathlib import Path
import stat
import subprocess

from pr320_budget_contract import PRIVACY_EXECUTION_CLASS, ROLES

SYSTEM = Path('/run/systemd/system')
NAME = '20-cryptad-workload-runtime.conf'
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
CONTENTS = {seconds: ('[Service]\nRuntimeMaxSec=' + str(seconds) + '\n').encode()
            for seconds in (3600, 7200)}


def _need(condition):
    if not condition:
        raise ValueError('pr320-role-runtime-invalid')


def _trusted(path):
    for entry in (path, *path.parents):
        observed = entry.lstat()
        _need(observed.st_uid == 0 and not observed.st_mode & 0o022
              and not stat.S_ISLNK(observed.st_mode))


def _retain(directory, raw):
    target = directory / NAME
    if target.exists() or target.is_symlink():
        _trusted(target)
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            _need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                  and 0 < before.st_size <= 128)
            previous = os.read(fd, 129)
            after = os.fstat(fd)
            _need(previous in CONTENTS.values() and all(getattr(before, field) == getattr(after, field)
                  for field in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')))
        finally:
            os.close(fd)
        if previous == raw:
            return
    temporary = directory / (NAME + '.pending')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, 'wb') as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, target)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def configure(execution_class):
    """Require the stopped pool before entry; retain only the reviewed 1h/2h override.

    The root preparer invokes this after admitting its selection and verifying every role
    is stopped. PID1 loads the override before launch; the hardened controller never gains
    a unit-file writer or an arbitrary property setter. Later profiles explicitly restore 1h.
    """
    _need(os.geteuid() == 0)
    seconds = 7200 if execution_class == PRIVACY_EXECUTION_CLASS else 3600
    _trusted(SYSTEM.parent)
    SYSTEM.mkdir(mode=0o755, exist_ok=True)
    _trusted(SYSTEM)
    for role in ROLES:
        directory = SYSTEM / ('cryptad-workload@' + role + '.service.d')
        directory.mkdir(mode=0o755, exist_ok=True)
        _trusted(directory)
        _retain(directory, CONTENTS[seconds])
    subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=True, timeout=30,
                   env=ENV, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for role in ROLES:
        observed = subprocess.run(['/usr/bin/systemctl', 'show',
            'cryptad-workload@' + role + '.service', '--property=RuntimeMaxUSec', '--value'],
            check=True, timeout=10, env=ENV, stdin=subprocess.DEVNULL, capture_output=True)
        # systemctl formats this microsecond-valued property as a timespan.
        _need(len(observed.stdout) <= 128 and not observed.stderr
              and observed.stdout.strip() in ({b'2h', b'7200s'} if seconds == 7200 else {b'1h', b'3600s'}))

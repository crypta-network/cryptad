#!/usr/bin/python3
"""Explicit administrator installation of the closed workload extension.

Installing reviewed units is not installed acceptance and does not enable protected work.
The base restricted installation and its immutable dependency closure must already verify.
"""
import os
from pathlib import Path
import pwd
import subprocess
import sys

import installation

ROLES = ('candidate-sender', 'candidate-recipient', 'previous', 'relay-no-apps')
SOURCE = installation.PREFIX / 'current/tools/release-certification/restricted/systemd'
ASSETS = {
    'cryptad-workload-controller.service': Path('/etc/systemd/system/cryptad-workload-controller.service'),
    'cryptad-workload@.service': Path('/etc/systemd/system/cryptad-workload@.service'),
    'cryptad-workload.conf': Path('/usr/lib/sysusers.d/cryptad-workload.conf'),
}
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'}


def verify():
    identity = installation.verify_execution()
    users = [pwd.getpwnam('cryptad-wl-' + role) for role in ROLES]
    existing = [pwd.getpwnam('cryptad-' + name) for name in ('runner', 'native', 'workload', 'soak')]
    if (len({user.pw_uid for user in users + existing}) != 8
            or len({user.pw_gid for user in users + existing}) != 8
            or any(user.pw_uid == 0 or user.pw_gid == 0 or user.pw_shell != '/usr/sbin/nologin' for user in users)):
        raise ValueError('workload-account-policy-invalid')
    import grp
    if any(user.pw_name in group.gr_mem for user in users for group in grp.getgrall()):
        raise ValueError('workload-supplementary-group-invalid')
    if any(grp.getgrgid(user.pw_gid).gr_name != user.pw_name for user in users):
        raise ValueError('workload-primary-group-invalid')
    for user in (*users, pwd.getpwnam('cryptad-soak')):
        probe = subprocess.run(['/usr/bin/sudo', '-n', '-l', '-U', user.pw_name],
                               capture_output=True, env=ENV, timeout=15)
        installation.verify_sudo_denial(probe, user=user.pw_name)
    for name, target in ASSETS.items():
        if installation.secured(target).read_bytes() != installation.secured(SOURCE / name).read_bytes():
            raise ValueError('workload-installed-unit-changed')
    for unit in ('cryptad-workload-controller.service', *(f'cryptad-workload@{role}.service' for role in ROLES)):
        for root in ('/etc/systemd/system', '/run/systemd/system', '/usr/lib/systemd/system',
                     '/etc/systemd/system.control', '/run/systemd/system.control'):
            for name in (unit + '.d', 'cryptad-workload@.service.d', 'cryptad-workload-.service.d'):
                if (Path(root) / name).exists():
                    raise ValueError('workload-unit-dropin-unreviewed')
        shown = subprocess.run(['/usr/bin/systemctl', 'show', unit, '--property=FragmentPath,DropInPaths', '--no-pager'],
                               capture_output=True, env=ENV, timeout=15, check=True)
        result = dict(line.split('=', 1) for line in shown.stdout.decode().splitlines() if '=' in line)
        template = 'cryptad-workload@.service' if '@' in unit else unit
        if result != {'FragmentPath': str(ASSETS[template]), 'DropInPaths': ''}:
            raise ValueError('workload-unit-load-path-invalid')
    return {**identity, 'profile': 'debian13-systemd257-workload-v1',
            'status': 'installed-unaccepted', 'protectedExecutionEnabled': False}


def install():
    if os.geteuid() != 0:
        raise ValueError('workload-administrator-required')
    installation.verify_execution()
    root = Path('/var/lib/cryptad-restricted-workload')
    if root.exists() or any(path.exists() or path.is_symlink() for path in ASSETS.values()):
        raise ValueError('workload-existing-installation-requires-reconciliation')
    for name, target in ASSETS.items():
        installation.secured(target.parent)
        with target.open('xb') as output:
            output.write(installation.secured(SOURCE / name).read_bytes())
            output.flush()
            os.fsync(output.fileno())
        target.chmod(0o644)
    subprocess.run(['/usr/bin/systemd-sysusers', str(ASSETS['cryptad-workload.conf'])], check=True, env=ENV, timeout=30)
    root.mkdir(mode=0o711)
    root.chmod(0o711)
    subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=True, env=ENV, timeout=30)
    return verify()


if __name__ == '__main__':
    if sys.argv[1:] not in (['install'], ['verify']):
        raise SystemExit('workload-fixed-install-operation-required')
    try:
        result = install() if sys.argv[1] == 'install' else verify()
        print(installation.encode(result).decode())
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SystemExit('workload-installation-rejected') from None

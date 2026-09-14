#!/usr/bin/python3
"""Trusted -I -S bootstrap; the administrator-provisioned interpreter/loader is initial TCB.

Verify the installed verifier itself before importing it. Its complete source/dependency checks
then precede imports of credential-using owners. No checkout or caller environment supplies code.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path('/opt/cryptad-cross-version/current')
APPROVAL = Path('/etc/cryptad-certification/restricted-installation.json')


def trusted(path):
    for entry in (path, *path.parents):
        value = entry.lstat()
        if stat.S_ISLNK(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022:
            raise ValueError('restricted-bootstrap-untrusted-file')
    return path


def main():
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
    # Only the socket-activation descriptors survive into the daemon. All children close them.
    if os.environ.get('LISTEN_PID') != str(os.getpid()) or os.environ.get('LISTEN_FDS') != '1':
        raise ValueError('restricted-bootstrap-socket-activation-required')
    for name in os.listdir('/proc/self/fd'):
        number = int(name)
        if number > 3:
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
    result = installation.verify()
    sys.path.insert(0, str(ROOT / 'tools/release-certification/protected'))
    import restricted_worker
    restricted_worker.main(bundle_identity=result['bundleIdentity'])


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError):
        raise SystemExit('restricted-bootstrap-rejected') from None

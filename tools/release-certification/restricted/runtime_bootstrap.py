#!/usr/bin/python3
"""Fixed tokenless observer bootstrap; the entire Python runtime is initial trusted code.

Offline image measurement must precede startup; these imports cannot verify themselves.
Verify the installed application closure before owner imports.

This entrypoint grants no workload isolation or operation authority. The existing root activation,
original evidence and service cgroup checks still admit the selected observer execution.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import stat
import sys

ROOT = Path('/opt/cryptad-cross-version/current')
STATE = Path('/var/lib/cryptad-cross-version')


def protected_file(path):
    for entry in (path, *path.parents):
        value = entry.lstat()
        if stat.S_ISLNK(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022:
            raise ValueError('restricted-runtime-untrusted-installation')
    if not path.is_file() or path.stat().st_nlink != 1:
        raise ValueError('restricted-runtime-untrusted-installation')
    return path


def main():
    if (sys.argv[1:] not in (['service'], ['runtime']) or not sys.flags.isolated
            or not sys.flags.no_site or os.geteuid() != pwd.getpwnam('cryptad-soak').pw_uid
            or os.geteuid() == 0):
        raise ValueError('restricted-runtime-fixed-tokenless-entry-required')
    operation = sys.argv[1]
    manifest_path = protected_file(ROOT / '.restricted-manifest.json')
    if manifest_path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError('restricted-runtime-manifest-too-large')
    manifest = json.loads(manifest_path.read_bytes())
    relative = 'tools/release-certification/restricted/installation.py'
    verifier = protected_file(ROOT / relative)
    if hashlib.sha256(verifier.read_bytes()).hexdigest() != manifest['files'][relative]['sha256']:
        raise ValueError('restricted-runtime-verifier-mismatch')
    os.environ.clear()
    os.environ.update(PATH='/usr/bin:/bin', LANG='C.UTF-8', HOME=str(STATE),
                      PYTHONDONTWRITEBYTECODE='1', PYTHONUNBUFFERED='1')
    os.chdir(ROOT)
    sys.dont_write_bytecode = True
    os.umask(0o077)
    for name in os.listdir('/proc/self/fd'):
        if int(name) > 2:
            try:
                os.close(int(name))
            except OSError:
                pass
    spec = importlib.util.spec_from_file_location('cryptad_runtime_installation', verifier)
    installation = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installation)
    installation.verify_execution()
    sys.path.insert(0, str(ROOT / 'tools/interop'))
    import cross_version_service as service
    if operation == 'service':
        sys.argv = [str(ROOT / 'tools/interop/cross_version_service.py')]
        return service.main()
    selected, root, output, _maximum = service.load_selection(ROOT, STATE)
    sys.path.insert(0, str(ROOT / 'tools/release-certification'))
    from cryptad_certification.cli import main as certify
    sys.argv = [str(ROOT / 'tools/release-certification/certify.py'),
                'cross-version-soak', 'run', '--execute', '--plan', str(selected / 'plan.json'),
                '--private-config', str(selected / 'private-config.json'),
                '--authorization', str(selected / 'authorization.json'), '--journal-root', str(root),
                '--out-dir', str(output)]
    return certify()


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError):
        raise SystemExit('restricted-runtime-bootstrap-rejected') from None

#!/usr/bin/python3
"""Measure an OFFLINE image from a separate trusted administrator/rescue environment.

Never run this with the target image's Python or libraries. This is not a boot attestation,
activation token or replacement for keeping the measured image immutable until execution.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

PYTHON_ROOT = '/usr/lib/python3.13'
ZIP = '/usr/lib/python313.zip'


def image_path(root, name):
    """Resolve image symlinks within the image, never against the measuring host's root."""
    if not name.startswith('/') or '..' in Path(name).parts:
        raise ValueError('runtime-image-path-invalid')
    pending = list(Path(name).parts[1:])
    resolved = []
    links = 0
    while pending:
        part = pending.pop(0)
        if part in ('', '.'):
            continue
        if part == '..':
            if not resolved:
                raise ValueError('runtime-image-link-escape')
            resolved.pop()
            continue
        path = root.joinpath(*resolved, part)
        # Leave the final component unresolved: its link identity is measured separately.
        if pending and path.is_symlink():
            links += 1
            if links > 40:
                raise ValueError('runtime-image-link-loop')
            target = Path(os.readlink(path))
            if target.is_absolute():
                resolved = []
                pending = list(target.parts[1:]) + pending
            else:
                pending = list(target.parts) + pending
        else:
            resolved.append(part)
    return root.joinpath(*resolved)


def measure(root, records):
    """Compare approved dependency bytes using only the measuring environment's runtime."""
    required = {PYTHON_ROOT, ZIP, '/usr/bin/python3', '/usr/bin/python3.13'}
    if (not isinstance(records, dict) or not required <= records.keys()
            or records[PYTHON_ROOT] != {'directory': True}):
        raise ValueError('runtime-image-inventory-incomplete')
    for name, expected in records.items():
        path = image_path(root, name)
        try:
            info = path.lstat()
        except FileNotFoundError:
            if expected == {'absent': True}:
                continue
            raise ValueError('runtime-image-missing-file') from None
        if info.st_uid != 0 or (not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022):
            raise ValueError('runtime-image-untrusted-owner-mode')
        if 'link' in expected:
            if not stat.S_ISLNK(info.st_mode) or os.readlink(path) != expected['link']:
                raise ValueError('runtime-image-link-mismatch')
        elif expected == {'directory': True}:
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError('runtime-image-directory-mismatch')
        elif 'sha256' in expected:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as stream:
                actual = os.fstat(stream.fileno())
                if (not stat.S_ISREG(actual.st_mode) or actual.st_size != expected['size']
                        or bool(actual.st_mode & 0o111) != expected['executable']
                        or hashlib.file_digest(stream, 'sha256').hexdigest() != expected['sha256']):
                    raise ValueError('runtime-image-file-mismatch')
        else:
            raise ValueError('runtime-image-record-mismatch')
    # Additional importable files must fail, even if every previously recorded hash matches.
    python = image_path(root, PYTHON_ROOT)
    actual = {PYTHON_ROOT}
    for directory, dirs, files in os.walk(python, followlinks=False):
        for name in dirs + files:
            actual.add('/' + (Path(directory) / name).relative_to(root).as_posix())
    expected = {name for name in records if name == PYTHON_ROOT or name.startswith(PYTHON_ROOT + '/')}
    if actual != expected:
        raise ValueError('runtime-image-python-roster-mismatch')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--approved-inventory', type=Path, required=True)
    args = parser.parse_args()
    root = args.image_root.resolve(strict=True)
    if root == Path('/') or any(path.resolve().is_relative_to(root) for path in
            (Path(sys.executable), Path(__file__), args.approved_inventory)):
        raise ValueError('runtime-image-separate-measuring-environment-required')
    # Require a separately mounted read-only offline image, with no writable submounts.
    result = subprocess.run(['/usr/bin/findmnt', '--json', '--submounts', '--mountpoint', str(root),
        '--output', 'TARGET,VFS-OPTIONS'], check=True, capture_output=True, timeout=10,
        env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
    mounts = json.loads(result.stdout)['filesystems']
    def readonly(rows):
        return bool(rows) and all('ro' in row['vfs-options'].split(',') and
            (not row.get('children') or readonly(row['children'])) for row in rows)
    if len(mounts) != 1 or mounts[0]['target'] != str(root) or not readonly(mounts):
        raise ValueError('runtime-image-read-only-mount-required')
    approval = args.approved_inventory.read_bytes()
    measure(root, json.loads(approval)['dependencies'])
    print(json.dumps({'status': 'offline-image-matched',
                      'approvalSha256': hashlib.sha256(approval).hexdigest(),
                      'bootAttested': False}))


if __name__ == '__main__':
    main()

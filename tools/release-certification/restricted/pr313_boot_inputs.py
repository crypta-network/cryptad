"""Private bounded boot snapshots for the fixed disposable reference profile.

These inventories identify local bytes, not their supply-chain authenticity. They never belong
in public reports: seed and SSH trust commitments are intentionally private.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

ENVIRONMENT = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
MAX_FILES = 8192
MAX_BYTES = 1024 * 1024 * 1024
TREES = ('usr/lib/x86_64-linux-gnu', 'usr/share/qemu', 'usr/share/seabios')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def snapshot_runtime(source, output, executables):
    """Materialize firmware/modules and all resolved ELF dependencies before any guest starts."""
    root = output / 'boot-runtime'
    root.mkdir(mode=0o700)
    count = total = 0
    def copy(incoming, destination):
        nonlocal count, total
        with incoming.open('rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ValueError('reference-boot-input-not-regular')
            count += 1
            total += info.st_size
            if count > MAX_FILES or total > MAX_BYTES:
                raise ValueError('reference-boot-input-bound-exceeded')
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open('xb') as retained:
                remaining = info.st_size
                while remaining:
                    data = stream.read(min(1024 * 1024, remaining))
                    if not data:
                        raise ValueError('reference-boot-input-changed')
                    retained.write(data)
                    remaining -= len(data)
                if stream.read(1):
                    raise ValueError('reference-boot-input-changed')
            destination.chmod(0o500 if info.st_mode & 0o111 else 0o400)
    for relative in TREES:
        selected = source / relative
        if not selected.is_dir():
            raise ValueError('reference-boot-tree-unavailable')
        for parent, directories, files in os.walk(selected, followlinks=False):
            if any((Path(parent) / name).is_symlink() for name in directories):
                raise ValueError('reference-boot-directory-link-unavailable')
            for name in sorted(files):
                incoming = Path(parent) / name
                copy(incoming, root / relative / incoming.relative_to(selected))
    libraries = root / 'usr/lib/x86_64-linux-gnu'
    # Inspect trusted ELF copies only. ldd is a host preparation dependency, never guest input.
    targets = list(executables.values()) + [p for p in libraries.rglob('*') if p.is_file()]
    loader = None
    for target in targets:
        if target.name.startswith('ld-linux-x86-64.so.'):
            loader = libraries / target.name
            continue
        with target.open('rb') as stream:
            if stream.read(4) != b'\x7fELF':
                continue
        result = subprocess.run(['/usr/bin/ldd', str(target)], env={**ENVIRONMENT,
            'LD_LIBRARY_PATH': str(libraries)}, capture_output=True, timeout=15, check=False)
        text = result.stdout.decode('utf-8', errors='strict')
        if result.returncode or 'not found' in text:
            raise ValueError('reference-boot-dependency-unresolved')
        for line in text.splitlines():
            match = re.search(r'(?:=>\s+)?(/[^\s]+)\s+\(0x[0-9a-f]+\)', line)
            if match is None:
                if line.strip().startswith('linux-vdso.so.') or line.strip() == 'statically linked':
                    continue
                raise ValueError('reference-boot-dependency-unrecognized')
            dependency = Path(match.group(1))
            destination = libraries / dependency.name
            if dependency.resolve() != destination.resolve():
                if destination.exists():
                    if digest(destination) != digest(dependency):
                        raise ValueError('reference-boot-library-collision')
                else:
                    copy(dependency, destination)
            if dependency.name.startswith('ld-linux-x86-64.so.'):
                if loader is not None and loader != destination:
                    raise ValueError('reference-boot-loader-conflict')
                loader = destination
    if loader is None:
        raise ValueError('reference-boot-loader-unavailable')
    inventory = {p.relative_to(output).as_posix(): digest(p)
        for p in sorted(root.rglob('*')) if p.is_file()}
    inventory.update({p.relative_to(output).as_posix(): digest(p) for p in executables.values()})
    (output / 'boot-inputs.private.json').write_text(json.dumps({'schemaVersion': 1,
        'kind': 'local-boot-byte-inventory', 'files': inventory}, sort_keys=True) + '\n')
    environment = {**ENVIRONMENT, 'LD_LIBRARY_PATH': str(libraries),
        'QEMU_MODULE_DIR': str(libraries / 'qemu'), 'PR313_PRIVATE_LOADER': str(loader)}
    return root, environment


def invocation(arguments, environment):
    """Run snapshotted ELF tools with the copied loader and no ambient loader cache."""
    loader = environment.get('PR313_PRIVATE_LOADER')
    if loader and Path(arguments[0]).is_absolute():
        return [loader, '--inhibit-cache', '--library-path', environment['LD_LIBRARY_PATH'], *arguments]
    return arguments


def record_private_inputs(output, **inputs):
    path = output / 'boot-inputs.private.json'
    record = json.loads(path.read_bytes())
    record.setdefault('bootInputs', {}).update(inputs)
    path.write_text(json.dumps(record, sort_keys=True) + '\n')

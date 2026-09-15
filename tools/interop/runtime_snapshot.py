"""Bounded observations of untrusted workload files through pinned directory descriptors.

The returned bytes and digests remain observations, never expected product identities or
authorization. No candidate tree is copied, changed, or traversed through a link. This helper
detects changes during acquisition; it does not make a writable filesystem an atomic snapshot.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import stat
import time


class SnapshotError(ValueError):
    """Closed diagnostic; candidate paths and error text stay out of public output."""


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _unchanged(before, after):
    if _identity(before) != _identity(after):
        raise SnapshotError('workload-snapshot-changed')


@contextmanager
def _directory(path):
    """Pin every ancestor from /; verify replacements before accepting an observation."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or len(path.parts) > 64:
        raise SnapshotError('workload-snapshot-root-invalid')
    descriptors = []
    try:
        descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(descriptor)
        links = []
        for name in path.parts[1:]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=descriptor)
            descriptors.append(child)
            links.append((descriptor, name, os.fstat(child)))
            descriptor = child
        yield descriptor
        # Ancestor content changes unrelated to this root are harmless; replacing the actual
        # directory reached by a selected name is not. Pin its object identity, not its mtime.
        for parent, name, expected in links:
            actual = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (actual.st_dev, actual.st_ino, actual.st_mode) != (
                    expected.st_dev, expected.st_ino, expected.st_mode):
                raise SnapshotError('workload-snapshot-root-changed')
    except OSError:
        raise SnapshotError('workload-snapshot-unavailable') from None
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _file(parent, name, maximum, deadline, *, content=False):
    if not hasattr(os, 'O_PATH'):
        raise SnapshotError('workload-snapshot-linux-required')
    # O_PATH pins a leaf without invoking a device's open method. Reopening our own pinned
    # descriptor only follows this procfs reference after the regular-file check, never a
    # candidate symlink. The reference profile provides genuine procfs at /proc.
    pinned = os.open(name, os.O_PATH | os.O_NOFOLLOW, dir_fd=parent)
    descriptor = None
    try:
        before = os.fstat(pinned)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or not 0 <= before.st_size <= maximum):
            raise SnapshotError('workload-snapshot-file-invalid')
        descriptor = os.open('/proc/self/fd/' + str(pinned), os.O_RDONLY | os.O_NONBLOCK)
        _unchanged(before, os.fstat(descriptor))
        checksum = hashlib.sha256()
        result = bytearray() if content else None
        size = 0
        while True:
            if time.monotonic() >= deadline:
                raise SnapshotError('workload-snapshot-deadline')
            block = os.read(descriptor, min(65536, maximum - size + 1))
            if not block:
                break
            size += len(block)
            if size > maximum:
                raise SnapshotError('workload-snapshot-size-limit')
            checksum.update(block)
            if content:
                result.extend(block)
        _unchanged(before, os.fstat(descriptor))
        _unchanged(before, os.stat(name, dir_fd=parent, follow_symlinks=False))
        if size != before.st_size:
            raise SnapshotError('workload-snapshot-changed')
        return (bytes(result) if content else 'sha256:' + checksum.hexdigest()), size, _identity(before)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(pinned)


def read_file(root, name, *, maximum=65536, timeout=5):
    """Read one fixed leaf from its separately selected parent; reject special/multi-link files."""
    if (not isinstance(name, str) or name in {'', '.', '..'} or '/' in name or '\\' in name
            or type(maximum) is not int or not 0 <= maximum <= 16 * 1024 * 1024
            or not 0 < timeout <= 30):
        raise SnapshotError('workload-snapshot-selection-invalid')
    with _directory(root) as parent:
        value, _, _identity_read = _file(parent, name, maximum, time.monotonic() + timeout, content=True)
    return value


def content_tree(root, *, maximum_entries=4096, maximum_bytes=256 * 1024 * 1024,
                 maximum_file_bytes=64 * 1024 * 1024, timeout=30):
    """Return sorted [relative-name, SHA-256] rows under finite entry/depth/byte/time limits.

    Directory metadata and child rosters are checked before accepting the complete observation.
    Partial observations are discarded on every failure. Call only over the selected app tree;
    this function does not authenticate the caller's choice of root.
    """
    if (type(maximum_entries) is not int or not 1 <= maximum_entries <= 16384
            or type(maximum_bytes) is not int or not 0 <= maximum_bytes <= 1024**3
            or type(maximum_file_bytes) is not int or not 0 <= maximum_file_bytes <= maximum_bytes
            or not 0 < timeout <= 60):
        raise SnapshotError('workload-snapshot-limits-invalid')
    deadline = time.monotonic() + timeout
    rows, count, total = [], 0, 0
    identities = {}

    def visit(descriptor, prefix, depth, *, verify=False):
        nonlocal count, total
        if depth > 32 or time.monotonic() >= deadline:
            raise SnapshotError('workload-snapshot-limit')
        before = os.fstat(descriptor)
        if verify:
            if identities.get(prefix) != _identity(before):
                raise SnapshotError('workload-snapshot-changed')
        else:
            identities[prefix] = _identity(before)
        names = []
        with os.scandir(descriptor) as entries:
            for entry in entries:
                count += 1
                if count > maximum_entries or time.monotonic() >= deadline:
                    raise SnapshotError('workload-snapshot-limit')
                names.append(entry.name)
        for name in sorted(names):
            relative = prefix + name
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=descriptor)
                try:
                    _unchanged(info, os.fstat(child))
                    visit(child, relative + '/', depth + 1, verify=verify)
                    _unchanged(info, os.stat(name, dir_fd=descriptor, follow_symlinks=False))
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                if verify:
                    if identities.get(relative) != _identity(info):
                        raise SnapshotError('workload-snapshot-changed')
                else:
                    value, size, observed = _file(descriptor, name,
                                                 min(maximum_file_bytes, maximum_bytes - total), deadline)
                    total += size
                    identities[relative] = observed
                    rows.append([relative, value])
            else:
                raise SnapshotError('workload-snapshot-special-file')
        _unchanged(before, os.fstat(descriptor))

    with _directory(root) as descriptor:
        visit(descriptor, '', 0)
        count = 0
        visit(descriptor, '', 0, verify=True)
    return sorted(rows)

"""Root-only, bounded immutable input copies for installed workload roles.

Paths are controller selections, never request parameters. A failed copy retains its
exclusive destination for reconciliation; callers must not retry over those bytes.
This module does not authenticate product provenance or candidate-generated output.
"""
from __future__ import annotations

from contextlib import contextmanager
import math
import os
from pathlib import Path
import stat
import time

ROOT = Path('/var/lib/cryptad-restricted-workload')
ROLES = ('candidate-sender', 'candidate-recipient', 'previous', 'relay-no-apps')
MAX_BYTES = 8 * 1024**3
MAX_FILES = 30000
MAX_DEPTH = 32


class StorageError(ValueError):
    """Closed diagnostic; no selected private paths or contents."""


def _check_deadline(deadline):
    if time.monotonic() >= deadline:
        raise StorageError('workload-storage-deadline')


def _metadata(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _trusted_directory(info):
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise StorageError('workload-storage-directory-not-trusted')


@contextmanager
def _directory(path):
    """Pin and revalidate every ancestor; reject traversing writable or linked roots."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise StorageError('workload-storage-path-invalid')
    descriptors, links = [], []
    try:
        descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(descriptor)
        _trusted_directory(os.fstat(descriptor))
        for name in path.parts[1:]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=descriptor)
            descriptors.append(child)
            info = os.fstat(child)
            _trusted_directory(info)
            links.append((descriptor, name, child, info.st_dev, info.st_ino))
            descriptor = child
        yield descriptor
        for parent, name, child, device, inode in links:
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            _trusted_directory(info)
            _trusted_directory(os.fstat(child))
            if (info.st_dev, info.st_ino) != (device, inode):
                raise StorageError('workload-storage-ancestor-replaced')
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def copy_tree(source, destination, deadline, *, max_bytes=MAX_BYTES, max_files=MAX_FILES):
    """Copy a trusted tree to an exclusive immutable directory, retaining any failure.

    ``deadline`` is an absolute monotonic time. Source and destination-parent ancestors
    must be root-owned and not writable by group/other. All entries, including directories,
    consume ``max_files``; every source regular file must have exactly one hard link.
    Returned byte/entry counts are copy accounting, not artifact-authentication evidence.
    The caller owns admission, role-path mapping, mount policy and failed-copy retention.
    """
    if os.geteuid() != 0:
        raise StorageError('workload-storage-root-required')
    if (isinstance(deadline, bool) or not isinstance(deadline, (int, float))
            or not math.isfinite(deadline) or type(max_bytes) is not int
            or not 1 <= max_bytes <= MAX_BYTES or type(max_files) is not int
            or not 1 <= max_files <= MAX_FILES):
        raise StorageError('workload-storage-budget-invalid')
    source, destination = Path(source), Path(destination)
    if (not source.is_absolute() or not destination.is_absolute()
            or '..' in source.parts or '..' in destination.parts or destination == Path('/')
            or destination == source or destination.is_relative_to(source)):
        raise StorageError('workload-storage-path-invalid')
    counts = {'bytes': 0, 'entries': 0}
    try:
        _check_deadline(deadline)
        with _directory(source) as src, _directory(destination.parent) as parent:
            os.mkdir(destination.name, 0o700, dir_fd=parent)
            dst = os.open(destination.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                          dir_fd=parent)
            try:
                _copy_directory(src, dst, deadline, max_bytes, max_files, counts, 0)
                os.fchmod(dst, 0o755)
                os.fsync(dst)
                retained = os.stat(destination.name, dir_fd=parent, follow_symlinks=False)
                if _metadata(retained) != _metadata(os.fstat(dst)):
                    raise StorageError('workload-storage-destination-replaced')
                os.fsync(parent)
            finally:
                os.close(dst)
        return counts
    except OSError:
        raise StorageError('workload-storage-copy-failed-retained') from None


def _copy_directory(src, dst, deadline, max_bytes, max_files, counts, depth):
    _check_deadline(deadline)
    if depth > MAX_DEPTH:
        raise StorageError('workload-storage-depth-exceeded')
    before = os.fstat(src)
    _trusted_directory(before)
    with os.scandir(src) as entries:
        for entry in entries:
            _check_deadline(deadline)
            counts['entries'] += 1
            if counts['entries'] > max_files:
                raise StorageError('workload-storage-entry-budget-exceeded')
            pinned = os.open(entry.name, os.O_PATH | os.O_NOFOLLOW, dir_fd=src)
            try:
                info = os.fstat(pinned)
                if info.st_uid != 0 or info.st_mode & 0o022:
                    raise StorageError('workload-storage-input-not-trusted')
                if stat.S_ISDIR(info.st_mode):
                    os.mkdir(entry.name, 0o700, dir_fd=dst)
                    child_src = os.open('/proc/self/fd/' + str(pinned), os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        child_dst = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dst)
                        try:
                            _copy_directory(child_src, child_dst, deadline, max_bytes, max_files, counts, depth + 1)
                            os.fchmod(child_dst, 0o755)
                            os.fsync(child_dst)
                        finally:
                            os.close(child_dst)
                    finally:
                        os.close(child_src)
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    if counts['bytes'] + info.st_size > max_bytes:
                        raise StorageError('workload-storage-byte-budget-exceeded')
                    _copy_file(pinned, dst, entry.name, info, deadline, max_bytes, counts)
                else:
                    raise StorageError('workload-storage-special-or-linked-input')
                retained = os.stat(entry.name, dir_fd=src, follow_symlinks=False)
                if _metadata(info) != _metadata(os.fstat(pinned)) or _metadata(info) != _metadata(retained):
                    raise StorageError('workload-storage-input-replaced')
            finally:
                os.close(pinned)
    if _metadata(before) != _metadata(os.fstat(src)):
        raise StorageError('workload-storage-directory-changed')


def _copy_file(pinned, dst, name, info, deadline, max_bytes, counts):
    reader = os.open('/proc/self/fd/' + str(pinned), os.O_RDONLY | os.O_NONBLOCK)
    try:
        writer = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dst)
        try:
            copied = 0
            while True:
                _check_deadline(deadline)
                chunk = os.read(reader, min(1024 * 1024, max_bytes - counts['bytes'] + 1))
                if not chunk:
                    break
                counts['bytes'] += len(chunk)
                copied += len(chunk)
                if counts['bytes'] > max_bytes or copied > info.st_size:
                    raise StorageError('workload-storage-byte-budget-exceeded')
                pending = memoryview(chunk)
                while pending:
                    _check_deadline(deadline)
                    written = os.write(writer, pending)
                    if written <= 0:
                        raise StorageError('workload-storage-write-failed')
                    pending = pending[written:]
            if copied != info.st_size or _metadata(info) != _metadata(os.fstat(reader)):
                raise StorageError('workload-storage-input-changed')
            os.fchmod(writer, 0o555 if info.st_mode & 0o111 else 0o444)
            os.fsync(writer)
        finally:
            os.close(writer)
    finally:
        os.close(reader)


APP_MAX_BYTES = 64 * 1024**2
APP_MAX_ENTRIES = 4096


def verify_installed_app(source, expected_tree, scratch, deadline):
    """Compare a bounded, untrusted installed app snapshot to its admitted immutable tree.

    The controller supplies the fixed role path, expected native tree identity and fixed
    private scratch path. Candidate bytes never become authority merely by being copied.
    An exclusive scratch directory is created before source inspection and retained on
    any failure, preventing silent repeated attempts. Only an exactly matching root-owned
    snapshot is removed. Source files and directories are never modified or deleted.
    """
    import re
    import shutil
    from restricted_native import _copy
    from restricted_native_launcher import tree_identity

    if os.geteuid() != 0:
        raise StorageError('workload-app-verification-root-required')
    if (isinstance(deadline, bool) or not isinstance(deadline, (int, float))
            or not math.isfinite(deadline)
            or not isinstance(expected_tree, dict)
            or set(expected_tree) != {'digest', 'fileCount', 'sizeBytes'}
            or not isinstance(expected_tree['digest'], str)
            or re.fullmatch('sha256:[0-9a-f]{64}', expected_tree['digest']) is None
            or type(expected_tree['sizeBytes']) is not int
            or not 1 <= expected_tree['sizeBytes'] <= APP_MAX_BYTES
            or type(expected_tree['fileCount']) is not int
            or not 1 <= expected_tree['fileCount'] < APP_MAX_ENTRIES):
        raise StorageError('workload-app-verification-selection-invalid')
    source, scratch = Path(source), Path(scratch)
    if (not source.is_absolute() or not scratch.is_absolute()
            or '..' in source.parts or '..' in scratch.parts
            or source == Path('/') or scratch == Path('/')
            or source == scratch or source.is_relative_to(scratch) or scratch.is_relative_to(source)):
        raise StorageError('workload-app-verification-path-invalid')
    try:
        _check_deadline(deadline)
        with _directory(scratch.parent) as parent:
            # This reservation survives even a failure opening the candidate source root.
            os.mkdir(scratch.name, 0o700, dir_fd=parent)
            fd = os.open(scratch.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                before = os.fstat(fd)
                os.fsync(parent)
                copied = Path('/proc/self/fd/' + str(fd)) / 'tree'
                # Reuse the existing native copier's global budget accounting. Reserving
                # the unused capacity produces this smaller fixed app verification limit.
                budget = [4 * 1024**3 - APP_MAX_BYTES, 65536 - APP_MAX_ENTRIES]
                _copy(source, copied, 0, 0, budget, deadline=deadline, trusted_source=False)
                actual = tree_identity(copied, deadline=deadline)
                if actual != expected_tree:
                    raise StorageError('workload-installed-app-identity-mismatch')
                _check_deadline(deadline)
                retained = os.stat(scratch.name, dir_fd=parent, follow_symlinks=False)
                if (retained.st_dev, retained.st_ino, retained.st_uid, retained.st_mode) != (
                        before.st_dev, before.st_ino, before.st_uid, before.st_mode):
                    raise StorageError('workload-app-verification-scratch-replaced')
                # Only the root-created private copy is eligible. Python's fd-based rmtree
                # rejects symlink substitution; no deletion walks the candidate source.
                if not shutil.rmtree.avoids_symlink_attacks:
                    raise StorageError('workload-app-verification-cleanup-unavailable')
                shutil.rmtree('tree', dir_fd=fd)
                os.fsync(fd)
                os.rmdir(scratch.name, dir_fd=parent)
                os.fsync(parent)
                return actual
            finally:
                os.close(fd)
    except OSError:
        raise StorageError('workload-app-verification-failed-retained') from None

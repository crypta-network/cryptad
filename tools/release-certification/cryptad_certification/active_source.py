"""Bounded selected-source rosters, separate from untrusted artifact inventories.

Git selects tracked and current untracked working files. History/cache exclusions apply only
to untracked files; a tracked member is never silently discarded. Git-less source exports
require an exact full-source roster or their existing installation manifest. A roster establishes
source consistency, never installation approval, original execution, or a private artifact's allowed members.
"""
from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import threading

MAX_PATHS = 100000
MAX_ROSTER = 16 * 1024 * 1024
MAX_EXPORT_SOURCE_BYTES = 512 * 1024 * 1024
UNTRACKED_HISTORY = {'.stversions', '.git', 'build', '.gradle', '__pycache__', '.cache'}
SOURCE_EXPORT_ROSTER = '.cryptad-source-roster.json'


class SourceRosterError(ValueError):
    """Fixed source-discovery failure without local paths or command output."""


@dataclass(frozen=True)
class SourceRoster:
    paths: tuple[str, ...]
    source_commit: str
    source_tree: str | None
    source_class: str


def _deny():
    raise SourceRosterError('active-source-roster-invalid')


def _name(value):
    if (not isinstance(value, str) or not value or len(value) > 1024
            or '\\' in value or ':' in value or any(ord(c) < 32 for c in value)
            or PurePosixPath(value).is_absolute()
            or any(part in {'', '.', '..'} for part in value.split('/'))):
        _deny()
    return value


def _link(info):
    return (stat.S_ISLNK(info.st_mode)
            or bool(getattr(info, 'st_file_attributes', 0)
                    & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)))


def _checked_path(root, name):
    path = Path(root).absolute()
    if '..' in path.parts or len(path.parts) > 64:
        _deny()
    for parent in (*reversed(path.parents), path):
        info = parent.lstat()
        if _link(info) or not stat.S_ISDIR(info.st_mode):
            _deny()
    for component in PurePosixPath(_name(name)).parts:
        path /= component
        if _link(path.lstat()):
            _deny()
    return path


@contextmanager
def _source_handle(path):
    """Pin directory entries on providers exposing descriptor-relative no-follow opens."""
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0)
    descriptors, bindings = [], []
    try:
        if os.open in os.supports_dir_fd and hasattr(os, 'O_DIRECTORY') and hasattr(os, 'O_NOFOLLOW'):
            descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            descriptors.append(descriptor)
            for component in path.parts[1:-1]:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                descriptors.append(child)
                info = os.fstat(child)
                bindings.append((descriptor, component, (info.st_dev, info.st_ino, info.st_mode)))
                descriptor = child
            handle = os.open(path.name, flags, dir_fd=descriptor)
        else:
            handle = os.open(path, flags)
        with os.fdopen(handle, 'rb') as source:
            yield source
        for parent, name, expected in bindings:
            actual = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (actual.st_dev, actual.st_ino, actual.st_mode) != expected:
                _deny()
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _source_identity(info, *, cross_api=False):
    mode = info.st_mode
    changed = info.st_ctime_ns
    if cross_api and os.name == 'nt':
        # Windows path stat synthesizes execute bits from the filename and exposes birth time
        # as ctime, while fstat exposes ChangeTime. Compare birth time across the two APIs;
        # retain each API's full mode and change time when checking its own before/after pair.
        mode &= ~0o111
        changed = getattr(info, 'st_birthtime_ns', None)
        if changed is None:
            _deny()
    return (info.st_dev, info.st_ino, mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, changed, getattr(info, 'st_birthtime_ns', None))


def read_source(root, name, maximum=MAX_ROSTER):
    """Read selected bytes with bounded size and observable identity/change checks.

    Windows uses reparse-point checks and handle identity verification. This portable source
    observation does not claim a persistent race-free directory handle on that provider.
    """
    try:
        path = _checked_path(root, name)
        ancestors = tuple((parent, parent.lstat()) for parent in path.parents)
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or not 0 <= before.st_size <= maximum):
            _deny()
        with _source_handle(path) as source:
            opened = os.fstat(source.fileno())
            if _link(opened) or _source_identity(before, cross_api=True) != _source_identity(opened, cross_api=True):
                _deny()
            raw = source.read(maximum + 1)
            after = os.fstat(source.fileno())
        if (len(raw) != before.st_size or _link(after)
                or _source_identity(opened) != _source_identity(after)
                or _source_identity(before) != _source_identity(_checked_path(root, name).lstat())):
            _deny()
        for parent, expected in ancestors:
            actual = parent.lstat()
            if _link(actual) or (actual.st_dev, actual.st_ino, actual.st_mode) != (expected.st_dev, expected.st_ino, expected.st_mode):
                _deny()
        return raw
    except OSError:
        _deny()


def _git(root, *args):
    try:
        environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        environment.update(GIT_NO_REPLACE_OBJECTS='1', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
        with subprocess.Popen(['git', '-c', 'safe.directory=', '-c', f'safe.directory={root}',
                               '-c', 'core.fsmonitor=false', '-c', 'core.untrackedCache=false',
                               '--no-optional-locks', *args], cwd=root, env=environment,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
            timer = threading.Timer(15, process.kill)
            timer.daemon = True
            timer.start()
            try:
                raw = process.stdout.read(MAX_ROSTER + 1)
                if len(raw) > MAX_ROSTER:
                    process.kill()
                    _deny()
                if process.wait(timeout=15):
                    _deny()
                return raw
            finally:
                timer.cancel()
                if process.poll() is None:
                    process.kill()
                process.wait()
    except (OSError, subprocess.SubprocessError):
        _deny()


def _git_names(raw):
    if raw and not raw.endswith(b'\0'):
        _deny()
    try:
        names = tuple(_name(value.decode('utf-8')) for value in raw.split(b'\0') if value)
    except UnicodeError:
        _deny()
    if len(names) > MAX_PATHS or len(set(names)) != len(names):
        _deny()
    return names


def source_roster(root):
    """Select current Git bytes or a manifest-bound source export; never recursively scan."""
    root = Path(root).absolute()
    if (root / '.git').exists():
        _checked_path(root, '.git')
        top = _git(root, 'rev-parse', '--show-toplevel').decode('utf-8').strip()
        if Path(top).resolve() != root:
            _deny()
        commit = _git(root, 'rev-parse', '--verify', 'HEAD^{commit}').decode().strip()
        tree = _git(root, 'rev-parse', '--verify', 'HEAD^{tree}').decode().strip()
        if not re.fullmatch('[0-9a-f]{40}|[0-9a-f]{64}', commit) or not re.fullmatch('[0-9a-f]{40}|[0-9a-f]{64}', tree):
            _deny()
        tracked = _git_names(_git(root, 'ls-files', '--cached', '-z'))
        deleted = _git_names(_git(root, 'ls-files', '--deleted', '-z'))
        exclusions = tuple(f':(exclude,glob)**/{name}/**' for name in sorted(UNTRACKED_HISTORY))
        untracked = _git_names(_git(root, 'ls-files', '--others', '--exclude-standard', '-z', '--', '.', *exclusions))
        current = [name for name in untracked if not UNTRACKED_HISTORY.intersection(PurePosixPath(name).parts)]
        paths = tuple(sorted((set(tracked) - set(deleted)) | set(current)))
        if len(paths) > MAX_PATHS:
            _deny()
        changed = _git(root, 'status', '--porcelain', '--untracked-files=no')
        return SourceRoster(paths, commit, tree, 'working-source' if changed or current else 'committed-source')
    source_export = (root / SOURCE_EXPORT_ROSTER).exists() or (root / SOURCE_EXPORT_ROSTER).is_symlink()
    raw = read_source(root, SOURCE_EXPORT_ROSTER if source_export else '.restricted-manifest.json')
    try:
        def unique(pairs):
            result = {}
            for name, value in pairs:
                if name in result:
                    _deny()
                result[name] = value
            return result
        manifest = json.loads(raw, object_pairs_hook=unique)
        if not isinstance(manifest, dict):
            _deny()
        tree = None
        if source_export:
            if (set(manifest) != {'schemaVersion', 'kind', 'sourceCommit', 'sourceTree', 'sourceClass', 'files'}
                    or type(manifest['schemaVersion']) is not int or manifest['schemaVersion'] != 1
                    or manifest['kind'] != 'cryptad-source-export'
                    or not re.fullmatch('[0-9a-f]{40}', manifest['sourceCommit'])
                    or not re.fullmatch('[0-9a-f]{40}', manifest['sourceTree'])
                    or manifest['sourceClass'] not in {'committed-source', 'working-source'}):
                _deny()
            tree = manifest['sourceTree']
        elif (set(manifest) != {'schemaVersion', 'kind', 'exportPolicy', 'sourceCommit', 'files'}
              or type(manifest['schemaVersion']) is not int or manifest['schemaVersion'] != 2
              or manifest['kind'] != 'cryptad-restricted-installation'
              or manifest['exportPolicy'] != 'production-without-test-seams-v1'
              or not re.fullmatch('[0-9a-f]{40}|[0-9a-f]{64}', manifest['sourceCommit'])):
            _deny()
        if not isinstance(manifest['files'], dict) or not 0 < len(manifest['files']) <= MAX_PATHS:
            _deny()
        paths = tuple(sorted(_name(name) for name in manifest['files']))
        total = 0
        for name in paths:
            record = manifest['files'][name]
            if (not isinstance(record, dict) or set(record) != {'sha256', 'size', 'executable'}
                    or type(record['size']) is not int or not 0 <= record['size'] <= MAX_ROSTER
                    or type(record['executable']) is not bool
                    or not isinstance(record['sha256'], str)
                    or not re.fullmatch('[0-9a-f]{64}', record['sha256'])):
                _deny()
            total += record['size']
            if total > MAX_EXPORT_SOURCE_BYTES:
                _deny()
            selected = read_source(root, name)
            # Windows stat execute flags are synthesized, not portable Unix permission bits.
            executable = None if os.name == 'nt' else bool(_checked_path(root, name).stat().st_mode & 0o111)
            if (hashlib.sha256(selected).hexdigest() != record['sha256']
                    or len(selected) != record['size']
                    or (executable is not None and executable != record['executable'])):
                _deny()
        # Export declarations bind the selected bytes, never committed-source or approval authority.
        return SourceRoster(paths, manifest['sourceCommit'], tree, 'manifest-source-export')
    except (KeyError, TypeError, UnicodeError, RecursionError, json.JSONDecodeError):
        _deny()


def active_files(root):
    return source_roster(root).paths

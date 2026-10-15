"""Closed public certification artifacts; private summaries are never uploaded as originals.

The only exported source-derived values are closed verdicts, booleans and bounded
counts. Reports are generated from that projection, never copied from input text.
The member hashes bind public bytes; no private summary/selection hash is exposed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from .envelope import validate_envelope
from .io import read_json_bytes
from .redaction import scan_value

ROSTER = frozenset({'summary.json', 'report.md', 'artifact-manifest.json'})
STATUSES = ('pass', 'warn', 'fail', 'missing', 'skip')
FAILURES = frozenset({'none', 'source-unavailable', 'source-invalid', 'source-redaction-failed'})
LIMIT = 8 * 1024 * 1024


class ExportError(ValueError):
    """A fixed classification; source exception text and filenames are never included."""


def _need(condition):
    if not condition:
        raise ExportError('certification-public-export-invalid')


def _json(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def _digest(value):
    return 'sha256:' + hashlib.sha256(value).hexdigest()


def _open_directory(path):
    parts = Path(path).absolute().parts
    _need('..' not in parts)
    descriptor = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_regular(path, maximum=LIMIT):
    """Open every directory through descriptors, rejecting links and oversized/hardlinked files."""
    path = Path(path).absolute()
    descriptor = _open_directory(path.parent)
    try:
        handle = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        try:
            before = os.fstat(handle)
            _need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= maximum)
            chunks, length = [], 0
            while True:
                block = os.read(handle, min(65536, maximum + 1 - length))
                if not block:
                    break
                chunks.append(block)
                length += len(block)
                _need(length <= maximum)
            after = os.fstat(handle)
            _need(before.st_size == length and
                  (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                  (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))
            return b''.join(chunks)
        finally:
            os.close(handle)
    finally:
        os.close(descriptor)


def _safe_summary(value, source_commit):
    _need(isinstance(source_commit, str) and re.fullmatch('[0-9a-f]{40}', source_commit))
    fields = {'schemaVersion', 'kind', 'sourceCommit', 'status', 'exportFailure',
              'promotionReady', 'counts', 'evidenceStatuses', 'gateStatuses',
              'originalAcceptance', 'phaseComplete'}
    _need(isinstance(value, dict) and set(value) == fields
          and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
          and value['kind'] == 'release-certification-public-projection'
          and value['sourceCommit'] == source_commit and value['status'] in {'pass', 'warn', 'fail'}
          and value['exportFailure'] in FAILURES and type(value['promotionReady']) is bool
          and value['originalAcceptance'] is False and value['phaseComplete'] is False)
    _need(isinstance(value['counts'], dict)
          and set(value['counts']) == {'evidence', 'blockers', 'warnings', 'waivers'})
    for counts in (value['counts'], value['evidenceStatuses'], value['gateStatuses']):
        _need(isinstance(counts, dict) and all(type(n) is int and 0 <= n <= 100000 for n in counts.values()))
    _need(set(value['evidenceStatuses']) == set(STATUSES) and set(value['gateStatuses']) == set(STATUSES)
          and sum(value['evidenceStatuses'].values()) == value['counts']['evidence'])
    if value['status'] == 'fail' or value['exportFailure'] != 'none':
        _need(value['promotionReady'] is False and value['status'] == 'fail')
    _need(not scan_value(value))
    return value


def _status_counts(rows):
    _need(isinstance(rows, list) and len(rows) <= 10000)
    counts = dict.fromkeys(STATUSES, 0)
    for row in rows:
        _need(isinstance(row, dict) and row.get('status') in counts)
        counts[row['status']] += 1
    return counts


def project(value, source_commit, release_id=None):
    """Validate the owning v2 envelope, then project only closed public facts."""
    validate_envelope(value, expected_kind='release-certification', release_id=release_id)
    if value['redaction']['status'] != 'pass':
        return failure(source_commit, 'source-redaction-failed')
    legacy = value['payload'].get('legacy')
    _need(isinstance(legacy, dict) and isinstance(legacy.get('ecosystemGates'), list)
          and isinstance(legacy.get('metadata'), dict)
          and legacy['metadata'].get('gitCommit') == source_commit)
    evidence = _status_counts(value['evidence'])
    gates = _status_counts(legacy['ecosystemGates'])
    _need(sum(evidence.values()) > 0 and sum(gates.values()) > 0)
    public = dict(schemaVersion=1, kind='release-certification-public-projection',
        sourceCommit=source_commit, status=value['result']['status'], exportFailure='none',
        promotionReady=value['result']['promotionReady'] is True,
        counts=dict(value['counts']), evidenceStatuses=evidence, gateStatuses=gates,
        originalAcceptance=False, phaseComplete=False)
    return _safe_summary(public, source_commit)


def failure(source_commit, classification):
    _need(classification in FAILURES - {'none'})
    return _safe_summary(dict(schemaVersion=1, kind='release-certification-public-projection',
        sourceCommit=source_commit, status='fail', exportFailure=classification,
        promotionReady=False, counts=dict.fromkeys(('evidence', 'blockers', 'warnings', 'waivers'), 0),
        evidenceStatuses=dict.fromkeys(STATUSES, 0), gateStatuses=dict.fromkeys(STATUSES, 0),
        originalAcceptance=False, phaseComplete=False), source_commit)


def render_report(value):
    _safe_summary(value, value['sourceCommit'])
    lines = ['# Release certification public report', '',
        f"Source commit: `{value['sourceCommit']}`", f"Status: `{value['status']}`",
        f"Export result: `{value['exportFailure']}`",
        f"Promotion readiness reported by certification: `{str(value['promotionReady']).lower()}`", '',
        '| Status | Evidence | Ecosystem gates |', '| --- | ---: | ---: |']
    lines.extend(f"| {status} | {value['evidenceStatuses'][status]} | {value['gateStatuses'][status]} |"
                 for status in STATUSES)
    lines.extend(['', f"Blockers: {value['counts']['blockers']}. Warnings: {value['counts']['warnings']}. "
                  f"Waivers: {value['counts']['waivers']}.", '',
        'This public projection is not original protected evidence and does not establish Phase 12 completion.'])
    return ('\n'.join(lines) + '\n').encode()


def _tool_digest():
    return _digest(_read_regular(Path(__file__)))


def create_export(manifest, workspace, destination, source_commit):
    """Read the exact selected aggregate; create a fresh, disjoint three-member public root."""
    workspace, destination = Path(workspace).absolute(), Path(destination).absolute()
    _need(workspace != destination and workspace not in destination.parents
          and destination not in workspace.parents and not destination.exists()
          and not destination.is_symlink())
    try:
        selected = read_json_bytes(_read_regular(manifest, 1024 * 1024), 'certification-source')
        release_id = selected['release']['id']
        _need(isinstance(release_id, str) and re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}', release_id)
              and selected['output']['root'] == 'build/release-certification')
        source = workspace / 'build/release-certification' / release_id / 'release-certification/summary.json'
        raw = read_json_bytes(_read_regular(source), 'certification-source')
        _need(raw['subject']['version'] == selected['release']['version']
              and raw['subject']['profile'] == selected['release']['profile'])
        summary = project(raw, source_commit, release_id)
    except FileNotFoundError:
        summary = failure(source_commit, 'source-unavailable')
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        summary = failure(source_commit, 'source-invalid')
    members = {'summary.json': _json(summary), 'report.md': render_report(summary)}
    inventory = dict(schemaVersion=1, kind='release-certification-public-members',
        sourceCommit=source_commit, projectionToolDigest=_tool_digest(),
        members={name: {'size': len(raw), 'digest': _digest(raw)} for name, raw in members.items()})
    members['artifact-manifest.json'] = _json(inventory)
    # An existing destination is never cleaned or reused after a failed/interrupted export.
    parent = _open_directory(destination.parent)
    try:
        os.mkdir(destination.name, mode=0o700, dir_fd=parent)
        target = os.open(destination.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            for name, raw in members.items():
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=target)
                with os.fdopen(fd, 'wb') as handle:
                    handle.write(raw)
                    handle.flush()
                    os.fsync(handle.fileno())
        finally:
            os.close(target)
    finally:
        os.close(parent)
    return verify_export(destination, source_commit)


def verify_export(root, source_commit):
    """Verify exact transferred membership and digests; regenerate the public report byte for byte."""
    root = Path(root)
    _need(not root.is_symlink() and root.is_dir() and {p.name for p in root.iterdir()} == ROSTER)
    raw = {name: _read_regular(root / name, 1024 * 1024) for name in ROSTER}
    return verify_export_bytes(raw, source_commit)


def verify_export_bytes(raw, source_commit):
    """Apply the same transfer policy to bounded original member bytes without writing them."""
    _need(isinstance(raw, dict) and set(raw) == ROSTER
          and all(isinstance(value, bytes) and 0 < len(value) <= 1024 * 1024
                  for value in raw.values()))
    inventory = read_json_bytes(raw['artifact-manifest.json'], 'public-members')
    _need(isinstance(inventory, dict) and set(inventory) ==
          {'schemaVersion', 'kind', 'sourceCommit', 'projectionToolDigest', 'members'}
          and type(inventory['schemaVersion']) is int and inventory['schemaVersion'] == 1
          and inventory['kind'] == 'release-certification-public-members'
          and inventory['sourceCommit'] == source_commit
          and inventory['projectionToolDigest'] == _tool_digest()
          and set(inventory['members']) == {'summary.json', 'report.md'})
    for name, member in inventory['members'].items():
        _need(member == {'size': len(raw[name]), 'digest': _digest(raw[name])})
    summary = _safe_summary(read_json_bytes(raw['summary.json'], 'public-summary'), source_commit)
    _need(raw['summary.json'] == _json(summary) and raw['report.md'] == render_report(summary))
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('action', choices=('create', 'verify', 'job-summary'))
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--workspace', type=Path)
    parser.add_argument('--job-summary', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.action == 'create':
            _need(args.manifest is not None and args.workspace is not None)
            create_export(args.manifest, args.workspace, args.root, args.source_commit)
        else:
            summary = verify_export(args.root, args.source_commit)
            if args.action == 'job-summary':
                _need(args.job_summary is not None)
                parent = _open_directory(args.job_summary.absolute().parent)
                try:
                    fd = os.open(args.job_summary.name, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
                                 0o600, dir_fd=parent)
                    with os.fdopen(fd, 'wb') as handle:
                        _need(stat.S_ISREG(os.fstat(handle.fileno()).st_mode)
                              and os.fstat(handle.fileno()).st_nlink == 1)
                        handle.write(render_report(summary))
                finally:
                    os.close(parent)
    except (OSError, ValueError, KeyError, TypeError, RecursionError, KeyboardInterrupt):
        print('certification-public-export-failed')
        return 1
    print('certification-public-export-verified')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

"""Retain exact public export and transfer observations privately for the privacy owner.

This reader performs no upload. Its inputs are the actual pre-transfer root, transferred
root and generated job summary. It never creates a successful substitute for missing files.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path

from . import certification_public_export as export
from . import composed_budget_privacy_evidence as privacy


def capture(native_path, public_root, transferred_root, job_summary, output, *, source_commit):
    native_raw = export._read_regular(native_path, privacy.MAX_BYTES)
    from .composed_budget_campaign_evidence import _decode
    native = _decode(native_raw)
    if native.get('kind') == 'pr320-private-native-privacy':
        native = privacy._installed_privacy_owner().decode_private(native_raw)['component']
    public_root, transferred_root, output = map(Path, (public_root, transferred_root, output))
    export._need(public_root.resolve() != transferred_root.resolve()
                 and not output.exists() and not output.is_symlink()
                 and all(root.resolve() not in output.absolute().parents
                         for root in (public_root, transferred_root)))
    # The descriptor readers verify membership, source, public field policy and every digest.
    export.verify_export(public_root, source_commit)
    export.verify_export(transferred_root, source_commit)
    value = dict(schemaVersion=1, kind='composed-budget-artifact-component',
        nativeMemberDigest='sha256:' + hashlib.sha256(native_raw).hexdigest(), sourceCommit=source_commit,
        files={name: base64.b64encode(export._read_regular(public_root / name)).decode('ascii')
               for name in sorted(export.ROSTER)},
        transferFiles={name: base64.b64encode(export._read_regular(transferred_root / name)).decode('ascii')
                       for name in sorted(export.ROSTER)},
        jobSummary=export._read_regular(job_summary, 1024 * 1024).decode('utf-8'))
    result = privacy.verify_artifacts(value, native, native_digest=value['nativeMemberDigest'],
                                      source_commit=source_commit)
    raw = privacy._encoded(value)
    parent = export._open_directory(output.absolute().parent)
    try:
        fd = os.open(output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(parent)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    for field in ('native', 'public-root', 'transferred-root', 'job-summary', 'output'):
        parser.add_argument('--' + field, type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    args = parser.parse_args(argv)
    try:
        capture(args.native, args.public_root, args.transferred_root, args.job_summary,
                args.output, source_commit=args.source_commit)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        print('composed-budget-artifact-capture-failed')
        return 1
    print('composed-budget-artifact-capture-verified')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

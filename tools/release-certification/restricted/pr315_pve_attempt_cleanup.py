#!/usr/bin/env python3
"""PVE-only release of exact successful guest duplicates after Mac verification.

The separate inventory program has no deletion code. Apply repeats that
read-only inventory while holding the task lease, binds its result to the
Mac-selected check digest, then removes only this stopped attempt's copies.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import shutil

import pr315_pve_attempt_inventory as inventory


def apply(plan, expected_check_digest):
    """Refuse changes before the first unlink if any identity changed."""
    if (inventory.HEX64.fullmatch(str(expected_check_digest)) is None
            or not shutil.rmtree.avoids_symlink_attacks):
        raise ValueError('pr315-cleanup-check-digest-or-platform-invalid')
    checked = inventory.inspect(plan)
    if (hashlib.sha256(inventory._canonical(checked)).hexdigest()
            != expected_check_digest):
        raise ValueError('pr315-cleanup-check-changed')
    base = inventory.TASK / plan['suite'] / 'attempt-01'
    for name in inventory.FILES:
        info = (base / name).lstat()
        selected = checked['files'][name]
        if (info.st_dev, info.st_ino) != (selected['device'],
                                          selected['inode']):
            raise ValueError('pr315-cleanup-file-replaced')
    for name in inventory.DIRECTORIES:
        info = (base / name).lstat()
        selected = checked['directories'][name]
        if (info.st_dev, info.st_ino) != (selected['device'],
                                          selected['inode']):
            raise ValueError('pr315-cleanup-directory-replaced')
    for name in inventory.FILES:
        (base / name).unlink()
    for name in inventory.DIRECTORIES:
        shutil.rmtree(base / name)
    descriptor = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return {**checked, 'checkDigest': expected_check_digest,
            'release': 'completed-remote-success-duplicates-only'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--check-digest', required=True)
    args = parser.parse_args(argv)
    if (inventory.SUITE.fullmatch(args.suite) is None
            or inventory.HEX40.fullmatch(args.source_commit) is None):
        raise SystemExit('pr315-cleanup-selection-invalid')
    root = inventory.TASK / 'host-release'
    info = inventory._directory(root, 0)
    if info.st_mode & 0o077:
        raise SystemExit('pr315-cleanup-plan-root-not-private')
    plan_path = root / (args.suite + '.plan.private.json')
    inventory._regular(plan_path, 0, 16384)
    plan = inventory._plan(json.loads(plan_path.read_bytes()))
    if (plan['suite'] != args.suite
            or plan['sourceCommit'] != args.source_commit):
        raise SystemExit('pr315-cleanup-selection-invalid')
    lease = inventory.TASK / 'workload-suite.lock'
    inventory._regular(lease, inventory.OWNER_UID)
    descriptor = os.open(lease, os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(json.dumps(apply(plan, args.check_digest), sort_keys=True))
    finally:
        os.close(descriptor)


if __name__ == '__main__':
    main()

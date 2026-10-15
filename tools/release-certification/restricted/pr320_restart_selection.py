#!/usr/bin/python3
"""Freeze the exact prospective signed cohort for the fixed restart successor."""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import pr320_storage_selection as fixtures
import pr320_restart_contract as contract

FIXED_GUEST_ROOT = Path('/root/cryptad/build/pr320-restart-inputs')


def prepare(args):
    if not contract.historical.valid_operation_budget(args.max_operations):
        raise ValueError('pr320-restart-operation-budget-invalid')
    return fixtures.prepare_profile(args, contract.profile())


def verify(root, digest, source, product_source_commit, *, installed_source=None):
    return fixtures.verify(root, digest, source, product_source_commit, selected_profile=contract.profile(), installed_source=installed_source)


def materialize_selection(root, source, expected_manifest_digest=None, product_source_commit=None, *, installed_source=None):
    if os.geteuid() != 0 or Path(root) != FIXED_GUEST_ROOT:
        raise ValueError('pr320-restart-fixed-guest-root-required')
    profile, inputs = verify(root, expected_manifest_digest, source, product_source_commit, installed_source=installed_source)
    result = fixtures.legacy.materialize_verified(Path(root) / 'inputs', inputs, profile)
    if not contract.verify_selection_contract(**result):
        raise ValueError('pr320-restart-selection-invalid')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'output', 'candidate', 'previous', 'java-home', 'feed-reader',
                 'budget-importer', 'budget-no-trust', 'budget-no-fetch', 'trusted-keys', 'statement'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('candidate-commit', 'previous-commit', 'jdk-digest'):
        parser.add_argument('--' + name, required=True)
    for name in ('max-seconds', 'max-operations', 'boundary-epoch-second'):
        parser.add_argument('--' + name, type=int, required=True)
    try:
        digest = prepare(parser.parse_args())
    except (OSError, ValueError, RuntimeError, fixtures.legacy.subprocess.SubprocessError):
        print('{"status":"pr320-restart-preparation-failed","installedPositiveExecuted":false}')
        return 2
    print(fixtures.json.dumps({'status': 'pr320-restart-fixtures-prepared', 'manifestDigest': digest,
        'installedPositiveExecuted': False}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

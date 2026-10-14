#!/usr/bin/python3
"""Freeze one prospective route profile using the existing signed fixture construction."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
if ROOT == Path('/opt/cryptad-restricted-test-kit'):
    ROOT = Path('/opt/cryptad-cross-version/current').resolve(strict=True)
for relative in ('tools/interop', 'tools/release-certification/protected',
                 'tools/release-certification', 'tools/release-certification/restricted'):
    sys.path.insert(0, str(ROOT / relative))
import pr320_storage_selection as signed
import pr320_route_contract as contract

MANIFEST = signed.MANIFEST
FIXED_ROOT = Path('/root/cryptad/build/pr320-route-inputs')


def prepare(args):
    return signed.prepare_profile(args, contract.profile(args.profile))


def verify(root, expected_manifest_digest, source, product_source_commit, *, installed_source=None):
    # The manifest selects only one code-owned finite class, then the shared reader
    # rechecks its exact bytes, worker, signed manifests and source closure.
    from runtime_snapshot import read_file
    raw = read_file(Path(root).absolute(), MANIFEST, maximum=1024 * 1024, timeout=30)
    value = signed.legacy.metadata.read_json(raw)
    selected = contract.selected_profile(value['profile']['executionClass'])
    return signed.verify(root, expected_manifest_digest, source, product_source_commit,
                         selected_profile=selected, installed_source=installed_source)


def materialize_selection(root, source, expected_manifest_digest=None, product_source_commit=None, *, installed_source=None):
    root = Path(root)
    selected, inputs = verify(root, expected_manifest_digest, source, product_source_commit, installed_source=installed_source)
    if os.geteuid() != 0 or root != FIXED_ROOT / selected['experiment']:
        raise ValueError('pr320-route-fixed-guest-root-required')
    value = signed.legacy.materialize_verified(root / 'inputs', inputs, selected)
    if not contract.verify_selection_contract(**value):
        raise ValueError('pr320-route-selection-invalid')
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'output', 'candidate', 'previous', 'java-home', 'feed-reader',
                 'budget-importer', 'budget-no-trust', 'budget-no-fetch', 'trusted-keys', 'statement'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('candidate-commit', 'previous-commit', 'jdk-digest'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--profile', choices=contract.NAMES, required=True)
    for name in ('max-seconds', 'max-operations', 'boundary-epoch-second'):
        parser.add_argument('--' + name, type=int, required=True)
    try:
        digest = prepare(parser.parse_args(argv))
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, signed.legacy.subprocess.SubprocessError):
        print('{"status":"pr320-route-preparation-failed","installedPositiveExecuted":false}')
        return 2
    print(json.dumps({'status': 'pr320-route-fixtures-prepared', 'manifestDigest': digest,
                      'installedPositiveExecuted': False}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

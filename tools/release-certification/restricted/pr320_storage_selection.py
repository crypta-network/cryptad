#!/usr/bin/python3
"""Freeze a finite storage direction around the existing signed PR-318 fixture producer."""
from __future__ import annotations

import argparse
import hashlib
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

import pr318_storage_selection as legacy
import pr320_storage_contract as contract
from pr320_budget_contract import PRIVACY_EXECUTION_CLASS
import cross_version_runtime as runtime

MANIFEST = 'manifest.private.json'
FIXED_ROOT = Path('/root/cryptad/build/pr320-storage-inputs')


def tool_identities(source, paths=None, *, installed_source=None):
    values = {}
    for name, relative in (contract.TOOL_PATHS if paths is None else paths).items():
        path = Path(source) / relative if installed_source is None else installed_source.tool_path(relative)
        if not path.is_file() or path.is_symlink():
            raise ValueError('pr320-storage-tool-unavailable')
        values[name] = runtime.digest_file(path)
    return values


def prepare(args):
    """Prepare immutable signed inputs once; the outer profile is frozen before execution."""
    selected = contract.profile(args.case_id, args.variant)
    return prepare_profile(args, selected)


def prepare_profile(args, selected):
    """Reuse signed fixture construction under a code-owned prospective profile."""
    if type(args.max_operations) is not int or not 1000 <= args.max_operations <= 10000:
        raise ValueError('pr320-storage-operation-budget-invalid')
    output = args.output.absolute()
    os.umask(0o077)
    output.mkdir(mode=0o700, exist_ok=False)
    inherited = argparse.Namespace(**vars(args))
    inherited.output = output / 'inputs'
    manifest_digest = legacy.prepare(inherited, permissions=selected['permissions'],
        process_client=(Path(args.source) / selected['toolPaths']['processClient']).read_bytes(),
        maximum_seconds=7200 if selected['executionClass'] == PRIVACY_EXECUTION_CLASS else 3600)
    value = {'schemaVersion': 1, 'kind': 'pr320-budget-profile-fixtures',
        'profile': selected, 'inputManifestDigest': manifest_digest,
        'toolIdentities': tool_identities(args.source, selected['toolPaths'])}
    (output / MANIFEST).write_text(json.dumps(value, sort_keys=True) + '\n')
    return legacy.base.digest(output / MANIFEST)


def verify(root, expected_manifest_digest, source, product_source_commit, *, selected_profile=None, installed_source=None):
    root = Path(root)
    if legacy.base.digest(root / MANIFEST) != expected_manifest_digest:
        raise ValueError('pr320-storage-manifest-mismatch')
    from runtime_snapshot import read_file
    raw = read_file(root.absolute(), MANIFEST, maximum=1024 * 1024, timeout=30)
    if hashlib.sha256(raw).hexdigest() != expected_manifest_digest:
        raise ValueError('pr320-storage-manifest-mismatch')
    value = legacy.metadata.read_json(raw)
    if (not isinstance(value, dict) or set(value) != {
            'schemaVersion', 'kind', 'profile', 'inputManifestDigest', 'toolIdentities'}
            or value['schemaVersion'] != 1 or value['kind'] != 'pr320-budget-profile-fixtures'):
        raise ValueError('pr320-storage-manifest-invalid')
    selected = (contract.selected_profile(value['profile'].get('executionClass'))
                if selected_profile is None else selected_profile)
    # JSON changes tuples to lists. Compare canonical bytes to preserve the closed profile.
    if (contract.canonical_digest(value['profile']) != contract.canonical_digest(selected)
            or value['toolIdentities'] != tool_identities(source, selected['toolPaths'], installed_source=installed_source)):
        raise ValueError('pr320-storage-profile-substituted')
    options = {} if installed_source is None else {'installed_source': installed_source}
    inputs = legacy.verify(root / 'inputs', value['inputManifestDigest'], source, product_source_commit,
                           **options, permissions=selected['permissions'],
                           process_client=(Path(source) / selected['toolPaths']['processClient']
                               if installed_source is None else installed_source.tool_path(selected['toolPaths']['processClient'])).read_bytes(),
                           maximum_seconds=7200 if selected['executionClass'] == PRIVACY_EXECUTION_CLASS else 3600)
    # The legacy input manifest is retained unchanged; a new prospective selection binds new helpers.
    inputs = {**inputs, 'toolIdentities': value['toolIdentities']}
    return selected, inputs


def materialize_selection(root, source, expected_manifest_digest=None, product_source_commit=None, *, installed_source=None):
    root = Path(root)
    selected, inputs = verify(root, expected_manifest_digest, source, product_source_commit, installed_source=installed_source)
    if os.geteuid() != 0 or root != FIXED_ROOT / selected['experiment']:
        raise ValueError('pr320-storage-fixed-guest-root-required')
    result = legacy.materialize_verified(root / 'inputs', inputs, selected)
    if not contract.verify_selection_contract(result['plan'], result['private'], result['authorization']):
        raise ValueError('pr320-storage-selection-invalid')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'output', 'candidate', 'previous', 'java-home', 'feed-reader',
                 'budget-importer', 'budget-no-trust', 'budget-no-fetch', 'trusted-keys', 'statement'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('candidate-commit', 'previous-commit', 'jdk-digest'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--case-id', choices=sorted({pair[0] for pair in contract.VARIANTS}), required=True)
    parser.add_argument('--variant', choices=sorted({pair[1] for pair in contract.VARIANTS}), required=True)
    for name in ('max-seconds', 'max-operations', 'boundary-epoch-second'):
        parser.add_argument('--' + name, type=int, required=True)
    try:
        digest = prepare(parser.parse_args())
    except (OSError, ValueError, RuntimeError, legacy.subprocess.SubprocessError):
        print('{"status":"pr320-storage-preparation-failed","installedPositiveExecuted":false}')
        return 2
    print(json.dumps({'status': 'pr320-storage-fixtures-prepared', 'manifestDigest': digest,
                      'installedPositiveExecuted': False}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

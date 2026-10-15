#!/usr/bin/python3
"""Freeze prospective signed privacy inputs and exact qualified browser identities."""
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
import pr318_storage_selection as historical
import pr320_privacy_contract as contract
import cross_version_runtime as runtime
from cryptad_certification.io import read_json_bytes

MANIFEST = 'manifest.private.json'
FIXED_ROOT = Path('/root/cryptad/build/pr320-privacy-inputs')


def tool_identities(source, *, installed_source=None):
    result = {}
    for key, relative in contract.TOOL_PATHS.items():
        path = Path(source) / relative if installed_source is None else installed_source.tool_path(relative)
        if not path.is_file() or path.is_symlink():
            raise ValueError('pr320-privacy-tool-unavailable')
        result[key] = runtime.digest_file(path)
    return result


def prepare(args):
    from runtime_snapshot import read_file
    provider = read_json_bytes(read_file(args.browser_provider.absolute().parent,
        args.browser_provider.name, maximum=65536, timeout=30), 'privacy-provider')
    if not contract.valid_browser_provider(provider):
        raise ValueError('pr320-privacy-provider-invalid')
    if type(args.max_operations) is not int or not 1000 <= args.max_operations <= 10000:
        raise ValueError('pr320-privacy-operation-budget-invalid')
    os.umask(0o077)
    output = args.output.absolute()
    output.mkdir(mode=0o700, exist_ok=False)
    inherited = argparse.Namespace(**vars(args))
    inherited.output = output / 'inputs'
    process = (args.source / contract.TOOL_PATHS['processClient']).read_bytes()
    input_digest = historical.prepare(inherited, permissions=contract.PERMISSIONS, process_client=process, maximum_seconds=7200)
    value = {'schemaVersion': 1, 'kind': 'pr320-privacy-fixture-selection', 'profile': contract.profile(),
        'inputManifestDigest': input_digest, 'toolIdentities': tool_identities(args.source),
        'browserProvider': provider}
    (output / MANIFEST).write_text(json.dumps(value, sort_keys=True) + '\n')
    return historical.base.digest(output / MANIFEST)


def verify(root, expected_manifest_digest, source, product_source_commit, *, installed_source=None):
    from runtime_snapshot import read_file
    root = Path(root)
    raw = read_file(root.absolute(), MANIFEST, maximum=1024 * 1024, timeout=30)
    if hashlib.sha256(raw).hexdigest() != expected_manifest_digest:
        raise ValueError('pr320-privacy-manifest-mismatch')
    value = read_json_bytes(raw, 'privacy-selection')
    if (not isinstance(value, dict) or set(value) != {'schemaVersion', 'kind', 'profile',
            'inputManifestDigest', 'toolIdentities', 'browserProvider'} or value['schemaVersion'] != 1
            or value['kind'] != 'pr320-privacy-fixture-selection'
            or contract.canonical_digest(value['profile']) != contract.canonical_digest(contract.profile())
            or value['toolIdentities'] != tool_identities(source, installed_source=installed_source)
            or not contract.valid_browser_provider(value['browserProvider'])):
        raise ValueError('pr320-privacy-selection-invalid')
    options = {} if installed_source is None else {'installed_source': installed_source}
    inputs = historical.verify(root / 'inputs', value['inputManifestDigest'], source, product_source_commit,
        **options, permissions=contract.PERMISSIONS, process_client=(Path(source) / contract.TOOL_PATHS['processClient']
            if installed_source is None else installed_source.tool_path(contract.TOOL_PATHS['processClient'])).read_bytes(), maximum_seconds=7200)
    return {**inputs, 'toolIdentities': value['toolIdentities'], 'browserProvider': value['browserProvider'],
        'profile': contract.profile()}


def materialize_selection(root, source, expected_manifest_digest=None, product_source_commit=None, *, installed_source=None):
    root = Path(root)
    selected = verify(root, expected_manifest_digest, source, product_source_commit, installed_source=installed_source)
    if os.geteuid() != 0 or root != FIXED_ROOT:
        raise ValueError('pr320-privacy-fixed-guest-root-required')
    result = historical.materialize_verified(root / 'inputs', selected, contract.profile())
    authorization, plan = result['authorization'], result['plan']
    authorization['browserProvider'] = selected['browserProvider']
    plan['composedBudgetInputs']['configurationDigest'] = contract.configuration_digest(plan, selected['browserProvider'])
    authorization['budgetSelection']['composedBudgetInputs'] = dict(plan['composedBudgetInputs'])
    from cryptad_certification.composed_budget_journal_member import campaign_inputs
    plan['budgetCampaignInputs'] = campaign_inputs(plan, selected['toolIdentities'])
    authorization['planDigest'] = contract.canonical_digest(plan)
    authorization['selectionDigest'] = contract.selection_digest(authorization)
    if not contract.verify_selection_contract(plan, result['private'], authorization):
        raise ValueError('pr320-privacy-selection-invalid')
    return result


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__)
    for name in ('source', 'output', 'candidate', 'previous', 'java-home', 'feed-reader',
                 'budget-importer', 'budget-no-trust', 'budget-no-fetch', 'trusted-keys', 'statement', 'browser-provider'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('candidate-commit', 'previous-commit', 'jdk-digest'):
        parser.add_argument('--' + name, required=True)
    for name in ('max-seconds', 'max-operations', 'boundary-epoch-second'):
        parser.add_argument('--' + name, type=int, required=True)
    try:
        digest = prepare(parser.parse_args())
    except (OSError, ValueError, RuntimeError, historical.subprocess.SubprocessError):
        print('{"status":"pr320-privacy-preparation-failed","installedPositiveExecuted":false}')
        return 2
    print(json.dumps({'status': 'pr320-privacy-fixtures-prepared', 'manifestDigest': digest,
                      'installedPositiveExecuted': False}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

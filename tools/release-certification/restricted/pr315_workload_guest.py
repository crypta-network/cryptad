#!/usr/bin/python3
"""Fixed disposable-guest installation and workload handoff; administrator test kit only."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

SOURCE = Path('/root/cryptad')
FIXTURES = SOURCE / 'build/pr315-inputs'
KIT = Path('/opt/cryptad-restricted-test-kit/tools/release-certification/restricted')


def execute(manifest_digest, product_commit):
    import disposable_integration as integration
    # The workload driver performs the same fixed guest prerequisite checks again after
    # installation. Check the OS/VM boundary before any account or service mutation here.
    import pr314_workload_driver as driver
    missing = set(driver.prerequisites()) - {
        'fixed-installed-source-required', 'separate-measured-test-kit-required'}
    if missing:
        return {'status': 'not-executed', 'protectedExecutionEnabled': False}, 78
    import pr315_workload_fixtures as fixtures
    fixtures.verify(FIXTURES, manifest_digest, SOURCE, product_commit)
    integration.load_installation(SOURCE)
    with tempfile.TemporaryDirectory(dir='/root') as temporary:
        integration.provision(SOURCE, Path(temporary))
    # Execute the committed test-kit copy, not a source-tree replacement. Fixture
    # materialization and the driver independently reverify the installed closure.
    result = subprocess.run(['/usr/bin/python3', '-I', '-S', str(KIT / Path(__file__).name),
        '--installed', '--fixture-manifest-digest', manifest_digest,
        '--product-source-commit', product_commit], stdin=subprocess.DEVNULL,
        timeout=3900, env=integration.ENV, check=False)
    return None, result.returncode


def installed(manifest_digest, product_commit):
    sys.path.insert(0, str(KIT))
    for relative in ('tools/release-certification/protected', 'tools/interop'):
        sys.path.insert(0, str(Path('/opt/cryptad-cross-version/current') / relative))
    import pr315_workload_fixtures as fixtures
    import pr314_workload_driver as driver
    if Path(__file__).resolve() != KIT / Path(__file__).name:
        raise ValueError('workload-installed-test-kit-required')
    fixtures.verify(FIXTURES, manifest_digest, SOURCE, product_commit)
    selection = fixtures.materialize_selection(FIXTURES, SOURCE, manifest_digest, product_commit)
    sys.path.insert(0, '/opt/cryptad-cross-version/current/tools/release-certification/protected')
    import restricted_workload as workload
    workload.write(driver.SELECTION, selection, create=True)
    return driver.execute(), 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture-manifest-digest', required=True)
    parser.add_argument('--product-source-commit', required=True)
    parser.add_argument('--installed', action='store_true')
    args = parser.parse_args()
    if (re.fullmatch('[0-9a-f]{64}', args.fixture_manifest_digest) is None
            or re.fullmatch('[0-9a-f]{40}', args.product_source_commit) is None):
        parser.error('invalid fixed source or fixture identity')
    operation = installed if args.installed else execute
    result, code = operation(args.fixture_manifest_digest, args.product_source_commit)
    if result is not None:
        print(json.dumps(result, sort_keys=True))
    return code


if __name__ == '__main__':
    try:
        code = main()
    except Exception:
        print('{"status":"failed-private-reconciliation-required","protectedExecutionEnabled":false}')
        code = 1
    raise SystemExit(code)

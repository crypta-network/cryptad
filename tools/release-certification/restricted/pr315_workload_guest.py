#!/usr/bin/python3
"""Fixed disposable-guest installation and workload handoff; administrator test kit only."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

# Root can write through ordinary read-only mode bits. Never create bytecode inside
# the immutable installed closure while provisioning or importing its verified owners.
sys.dont_write_bytecode = True

SOURCE = Path('/root/cryptad')
FIXTURES = SOURCE / 'build/pr315-inputs'
KIT = Path('/opt/cryptad-restricted-test-kit/tools/release-certification/restricted')
STAGE = 'prerequisites'
FAILURE = Path('/root/pr315-workload-failure.private.json')


def execute(manifest_digest, product_commit):
    global STAGE
    import disposable_integration as integration
    # The workload driver performs the same fixed guest prerequisite checks again after
    # installation. Check the OS/VM boundary before any account or service mutation here.
    import pr314_workload_driver as driver
    missing = set(driver.prerequisites()) - {
        'fixed-installed-source-required', 'separate-measured-test-kit-required'}
    if missing:
        return {'status': 'not-executed', 'protectedExecutionEnabled': False}, 78
    import pr315_workload_fixtures as fixtures
    STAGE = 'fixture-verification'
    fixtures.verify(FIXTURES, manifest_digest, SOURCE, product_commit)
    integration.load_installation(SOURCE)
    STAGE = 'installation'
    with tempfile.TemporaryDirectory(dir='/root') as temporary:
        integration.provision(SOURCE, Path(temporary))
    # Execute the committed test-kit copy, not a source-tree replacement. Fixture
    # materialization and the driver independently reverify the installed closure.
    STAGE = 'installed-workload-driver'
    result = subprocess.run(['/usr/bin/python3', '-I', '-S', '-B', str(KIT / Path(__file__).name),
        '--installed', '--fixture-manifest-digest', manifest_digest,
        '--product-source-commit', product_commit], stdin=subprocess.DEVNULL,
        timeout=3900, env=integration.ENV, check=False)
    return None, result.returncode


def installed(manifest_digest, product_commit):
    global STAGE
    sys.path.insert(0, str(KIT))
    for relative in ('tools/release-certification/protected', 'tools/interop'):
        sys.path.insert(0, str(Path('/opt/cryptad-cross-version/current') / relative))
    import pr315_workload_fixtures as fixtures
    import pr314_workload_driver as driver
    if Path(__file__).resolve() != KIT / Path(__file__).name:
        raise ValueError('workload-installed-test-kit-required')
    STAGE = 'selection-materialization'
    fixtures.verify(FIXTURES, manifest_digest, SOURCE, product_commit)
    selection = fixtures.materialize_selection(FIXTURES, SOURCE, manifest_digest, product_commit)
    sys.path.insert(0, '/opt/cryptad-cross-version/current/tools/release-certification/protected')
    import restricted_workload as workload
    workload.write(driver.SELECTION, selection, create=True)
    STAGE = 'positive-driver'
    return driver.execute(), 0


def _bounded_text(value, maximum):
    """Limit the actual ASCII-escaped JSON bytes, including surrogate pairs."""
    value = value[:maximum]
    while len(json.dumps(value).encode('ascii')) > maximum:
        value = value[:max(0, len(value) - max(1, len(value) // 4))]
    return value


def retain_failure(error):
    """Bounded private setup diagnostics; never copy this exception into public output."""
    if os.geteuid() != 0:
        return
    value = {'stage': _bounded_text(STAGE, 128),
             'exceptionType': _bounded_text(type(error).__name__, 128),
             'privateDetail': _bounded_text(str(error), 1024), 'installedAcceptance': False,
             'exceptionChainMeaning': 'observed-python-propagation-not-causal-acceptance',
             'exceptionChain': [], 'networkFailures': [], 'networkFailuresOmitted': 0}
    seen, current, relationship = set(), error, 'top-level'
    for depth in range(4):
        if id(current) in seen:
            value['exceptionChainEnd'] = 'cycle'
            break
        seen.add(id(current))
        value['exceptionChain'].append({'depth': depth, 'relationship': relationship,
            'exceptionType': _bounded_text(type(current).__name__, 128),
            'privateDetail': _bounded_text(str(current), 512)})
        diagnostic = getattr(current, 'private_diagnostics', None)
        if (isinstance(diagnostic, dict)
            and set(diagnostic) == {'arguments', 'stderr', 'failureClass'}
            and isinstance(diagnostic['arguments'], list) and len(diagnostic['arguments']) <= 32
            and all(isinstance(argument, str) for argument in diagnostic['arguments'])
            and sum(len(argument) for argument in diagnostic['arguments']) <= 2048
            and isinstance(diagnostic['stderr'], str) and len(diagnostic['stderr']) <= 2048
            and isinstance(diagnostic['failureClass'], str) and len(diagnostic['failureClass']) <= 128):
            arguments, remaining = [], 1024
            for argument in diagnostic['arguments']:
                if remaining < 2:
                    break
                selected = _bounded_text(argument, remaining)
                arguments.append(selected)
                remaining -= len(json.dumps(selected).encode('ascii'))
            value['networkFailures'].append({'source': {'depth': depth, 'relationship': relationship},
                'command': {'arguments': arguments,
                    'stderr': _bounded_text(diagnostic['stderr'], 512),
                    'failureClass': _bounded_text(diagnostic['failureClass'], 128)}})
            # Prefer the earliest reachable failures over additional wrapping/cleanup
            # failures. These are propagation relationships, not inferred temporal proof.
            if len(value['networkFailures']) > 2:
                value['networkFailures'].pop(0)
                value['networkFailuresOmitted'] += 1
        if current.__cause__ is not None:
            current, relationship = current.__cause__, 'explicit-cause'
        elif current.__context__ is not None:
            relationship = 'suppressed-context' if current.__suppress_context__ else 'context'
            current = current.__context__
        else:
            value['exceptionChainEnd'] = 'complete'
            break
    else:
        value['exceptionChainEnd'] = 'depth-limit'
    raw = json.dumps(value, sort_keys=True)
    # Keep both bounded network failures while trimming redundant propagation details first.
    while len(raw.encode('ascii')) + 1 > 8000 and value['exceptionChain']:
        value['exceptionChain'].pop()
        value['exceptionChainEnd'] = 'byte-limit'
        raw = json.dumps(value, sort_keys=True)
    while len(raw.encode('ascii')) + 1 > 8000 and value['networkFailures']:
        value['networkFailures'].pop(0)
        value['networkFailuresOmitted'] += 1
        raw = json.dumps(value, sort_keys=True)
    try:
        descriptor = os.open(FAILURE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(raw)
            stream.write('\n')
    except OSError:
        pass


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
    except Exception as error:
        retain_failure(error)
        print('{"status":"failed-private-reconciliation-required","protectedExecutionEnabled":false}')
        code = 1
    raise SystemExit(code)

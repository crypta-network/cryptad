"""Private, bounded synthetic INPUT preparation; never an original authority or verdict.

The existing Java producers run once on the explicitly selected local Java 25 installation.
Guest consumers still execute the installed native exporters, signature verification and CMS.
Only this separate test kit understands the prepared-input selection.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time
from unittest.mock import patch

MAX_FILES = 512
MAX_BYTES = 128 * 1024 * 1024
MEMBERS = frozenset(('signed', 'federated', 'app-products', 'previous-api.jar'))


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def inventory(root):
    rows, total = [], 0
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root).as_posix()
        if relative == 'manifest.private.json':
            continue
        info = path.lstat()
        if relative.split('/')[0] not in MEMBERS:
            raise ValueError('fixture-member-invalid')
        if stat.S_ISDIR(info.st_mode):
            continue
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or path.name in ('producer-env.json', 'review-private.der')):
            raise ValueError('fixture-member-invalid')
        total += info.st_size
        if len(rows) >= MAX_FILES or total > MAX_BYTES:
            raise ValueError('fixture-input-bound-exceeded')
        rows.append({'path': relative, 'size': info.st_size, 'sha256': digest(path)})
    if {row['path'].split('/')[0] for row in rows} != MEMBERS:
        raise ValueError('fixture-input-roster-incomplete')
    if not rows:
        raise ValueError('fixture-input-empty')
    return rows


def verify(root, expected_digest, source, product_commit):
    """Reopen a copied input tree; source/tool binding is local reproducibility, not attestation."""
    root, source = Path(root), Path(source)
    manifest = root / 'manifest.private.json'
    if manifest.is_symlink() or manifest.stat().st_size > 256 * 1024 or digest(manifest) != expected_digest:
        raise ValueError('fixture-manifest-substituted')
    sys.path.insert(0, str(source / 'tools/release-certification/protected'))
    import maintenance_runtime_metadata as metadata
    value = metadata.read_json(manifest.read_bytes())
    if (not isinstance(value, dict) or set(value) != {'schemaVersion', 'kind', 'productionEligible', 'sourceCommit',
            'productSourceCommit', 'jdkIdentity', 'toolIdentity', 'members', 'producerSources'}
            or type(value['schemaVersion']) is not int or value['schemaVersion'] != 1 or value['kind'] != 'pr313-synthetic-inputs'
            or value['productionEligible'] is not False
            or value['productSourceCommit'] != product_commit or value['members'] != inventory(root)
            or not isinstance(value['producerSources'], list)
            or len(value['producerSources']) != len(PRODUCERS)
            or re.fullmatch('sha256:[0-9a-f]{64}', str(value['jdkIdentity'])) is None):
        raise ValueError('fixture-input-identity-mismatch')
    actual_commit = subprocess.run(['git', '-C', str(source), 'rev-parse', 'HEAD'],
        capture_output=True, text=True, check=True, timeout=10).stdout.strip()
    if value['sourceCommit'] != actual_commit:
        raise ValueError('fixture-helper-source-mismatch')
    for row in value['producerSources']:
        if not isinstance(row, dict) or set(row) != {'path', 'sha256'}:
            raise ValueError('fixture-producer-source-invalid')
        if (not isinstance(row['path'], str) or row['path'] not in PRODUCERS
                or re.fullmatch('[0-9a-f]{64}', str(row['sha256'])) is None
                or digest(source / row['path']) != row['sha256']):
            raise ValueError('fixture-producer-source-mismatch')
    if {row['path'] for row in value['producerSources']} != set(PRODUCERS):
        raise ValueError('fixture-producer-source-missing')
    sys.path.insert(0, str(source / 'tools/release-certification/protected'))
    import app_subject_projection as projection
    if projection.tree_digest(source / 'platform-devtools/build/install/crypta-app') != value['toolIdentity']:
        raise ValueError('fixture-tool-substituted')
    return root


PRODUCERS = (
    'platform-devtools/src/test/java/network/crypta/platform/devtools/fixtures/Pr304SignedFixture.java',
    'platform-appcatalog/src/test/java/network/crypta/platform/appcatalog/Pr305SignedCatalogFixture.java',
    'platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java',
    'tools/release-certification/protected/maintenance_app_products.py',
    'tools/release-certification/cryptad_certification/tests/test_pr304_product_consumer_integration.py',
    'tools/release-certification/cryptad_certification/tests/test_pr307_product_consumer_integration.py',
    'tools/release-certification/restricted/pr313_fixtures.py',
)



def command_record(arguments, environment, timeout, phase):
    program = Path(arguments[0])
    if not program.is_absolute():
        selected = shutil.which(str(program), path=environment.get('PATH'))
        if selected is None:
            raise ValueError('fixture-executable-unavailable')
        program = Path(selected)
    return {'phase': phase, 'executableSha256': digest(program.resolve(strict=True)),
        'argumentCount': len(arguments), 'argumentsDigest': hashlib.sha256(
            json.dumps([str(arg) for arg in arguments]).encode()).hexdigest(),
        'argumentsClass': 'compiler' if program.name == 'javac' else
            'java-producer' if program.name == 'java' else 'trusted-fixture-helper',
        'environmentDigest': hashlib.sha256(json.dumps(dict(environment), sort_keys=True).encode()).hexdigest(),
        'timeoutSeconds': timeout}


def classify_diagnostic(raw, additional=b''):
    def encoded(value):
        return value.encode() if isinstance(value, str) else (value or b'')
    raw = (encoded(raw) + encoded(additional))[:65536]
    return {'diagnosticSha256': hashlib.sha256(raw).hexdigest(),
        'fatalSignal': 'SIGILL' if b'SIGILL' in raw else 'unclassified',
        'failureClass': 'jvm-sigill' if b'SIGILL' in raw else 'producer-command-failed',
        'fatalFrame': 'split-constant-pool-entry' if b'SplitConstantPool.entryByIndex' in raw else
            'regex-branch-match' if b'Pattern$Branch.match' in raw else 'unclassified'}


def prepare(source, output, product_commit):
    os.umask(0o077)
    if any(os.environ.get(name) for name in ('JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS',
                                            '_JAVA_OPTIONS', 'JAVA_OPTS')):
        raise ValueError('fixture-ambient-jvm-options-forbidden')
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    # Private diagnostics live beside, not inside, the closed input payload.
    diagnostic = output.parent / (output.name + '.diagnostic.private.json')
    if diagnostic.exists():
        raise ValueError('fixture-diagnostic-already-exists')
    started = time.monotonic()
    phase = 'java-producers'
    report = {'kind': 'pr313-trusted-input-preparation', 'status': 'failed',
              'productionEligible': False, 'budgetSeconds': 900}
    sys.path.insert(0, str(source / 'tools/release-certification'))
    from cryptad_certification.tests import test_pr304_product_consumer_integration as legacy
    cls = legacy.ProductConsumerIntegrationTest
    if legacy.ROOT.resolve() != source.resolve():
        raise ValueError('fixture-source-selection-mismatch')
    if re.fullmatch('[0-9a-f]{40}', product_commit) is None:
        raise ValueError('fixture-product-source-invalid')
    stack = ExitStack()
    commands = report['commands'] = []
    original_run = subprocess.run
    import bounded_process
    original_bounded = bounded_process.run
    def observe(arguments, options, function, *, bounded=False):
        if time.monotonic() - started >= 900:
            raise TimeoutError('fixture-preparation-budget-exceeded')
        if hasattr(cls, 'java') and (cls.java / 'bin/java').is_file() and 'jdkIdentity' not in report:
            report['jdkIdentity'] = legacy.projection.tree_digest(cls.java)
            report['toolIdentity'] = legacy.projection.tree_digest(cls.tool)
            report['toolJars'] = [{'name': jar.name, 'sha256': digest(jar)}
                for jar in sorted((cls.tool / 'lib').glob('*.jar'))]
        if len(commands) >= 128:
            raise ValueError('fixture-command-bound-exceeded')
        remaining = 900 - (time.monotonic() - started)
        options['timeout'] = min(options.get('timeout', remaining), remaining)
        row = command_record(arguments, options.get('environment' if bounded else 'env', os.environ),
            options.get('timeout', 180 if bounded else None), phase)
        commands.append(row)
        began = time.monotonic()
        if bounded:
            sink = options.pop('diagnostic_sink', None)
            def diagnostic_sink(_stdout, stderr):
                row.update(classify_diagnostic(_stdout + stderr))
                if sink is not None:
                    sink(_stdout, stderr)
            options['diagnostic_sink'] = diagnostic_sink
        try:
            result = function(arguments, **options)
            row['status'] = 'completed'
            # A completed process is not a signal/frame failure, regardless of harmless text.
            row.pop('failureClass', None)
            row.pop('fatalFrame', None)
            row.pop('fatalSignal', None)
            return result
        except subprocess.CalledProcessError as error:
            row.update(classify_diagnostic(error.stdout, error.stderr),
                returnCode=error.returncode, status='failed')
            raise
        except Exception:
            row['status'] = 'failed'
            raise
        finally:
            row['elapsedSeconds'] = round(time.monotonic() - began, 3)
    stack.enter_context(patch.object(subprocess, 'run', side_effect=lambda arguments, **options:
        observe(arguments, options, original_run)))
    stack.enter_context(patch.object(bounded_process, 'run', side_effect=lambda arguments, **options:
        observe(arguments, options, original_bounded, bounded=True)))
    try:
        selected_javac = shutil.which('javac')
        if selected_javac is None:
            raise ValueError('fixture-java25-unavailable')
        version = subprocess.run([selected_javac, '-version'], check=True,
            capture_output=True, text=True, timeout=10).stdout.strip()
        if re.fullmatch(r'javac (?:2[5-9]|[3-9][0-9])(?:[.][0-9]+)*', version) is None:
            raise ValueError('fixture-java25-unavailable')
        report['javacVersion'] = version
        cls.setUpClass()
        report['jdkIdentity'] = cls.java_digest
        report['toolIdentity'] = cls.tool_digest
        report['toolJars'] = [{'name': jar.name, 'sha256': digest(jar)}
            for jar in sorted((cls.tool / 'lib').glob('*.jar'))]
        signed = output / 'signed'
        signed.mkdir(mode=0o700)
        for path in cls.root.iterdir():
            if path.name in ('jdk', 'installed-jdk', 'variant', 'network',
                             'producer-env.json', 'review-private.der'):
                continue
            if path.is_dir():
                shutil.copytree(path, signed / path.name)
            else:
                shutil.copyfile(path, signed / path.name)
        (output / 'previous-api.jar').write_bytes(cls.previous_api)
        phase = 'federated-producer'
        classes = cls.root / 'federated-classes'
        classes.mkdir()
        cp = str(cls.tool / 'lib/*')
        subprocess.run([str(cls.java / 'bin/javac'), '-cp', cp, '-d', str(classes),
            str(source / PRODUCERS[1])], check=True, capture_output=True, timeout=60)
        subprocess.run([str(cls.java / 'bin/java'), '-cp', str(classes) + os.pathsep + cp,
            'network.crypta.platform.appcatalog.Pr305SignedCatalogFixture', str(output / 'federated')],
            check=True, capture_output=True, timeout=60)
        phase = 'ordinary-maintenance-product'
        workspace = cls.root / 'workspace'
        for app in sorted(legacy.metadata.FIRST_PARTY | {'mail-prototype'}):
            built = workspace / 'apps' / app / 'build'
            (built / 'cryptad-app-bundle').mkdir(parents=True)
            version = '3.1' if app == 'site-publisher' else '1'
            shutil.copyfile(cls.root / (app + '.zip'), built / 'cryptad-app-bundle' / (app + '-' + version + '.zip'))
            shutil.copytree(cls.root / app, built / 'cryptad-app' / app)
        signing = json.loads((cls.root / 'producer-env.json').read_bytes())
        with patch.dict(os.environ, {**signing, 'GITHUB_SHA': product_commit,
                'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1'}), \
                patch.object(legacy.app_products, 'datetime', legacy.FixedClock):
            legacy.app_products.produce_app_products(workspace, output / 'app-products',
                release_id='stable-1.0-maintenance-302', build_version='302',
                source_commit=product_commit, include_mail=True,
                artifact_base='https://example.invalid/synthetic-artifacts',
                exporter=cls.tool / 'bin/crypta-app', java_home=cls.java)
        # Signing keys never enter the immutable guest input kit.
        for name in ('producer-env.json', 'review-private.der'):
            (signed / name).unlink(missing_ok=True)
        source_commit = subprocess.run(['git', '-C', str(source), 'rev-parse', 'HEAD'],
            capture_output=True, text=True, check=True).stdout.strip()
        value = {'schemaVersion': 1, 'kind': 'pr313-synthetic-inputs', 'productionEligible': False,
            'sourceCommit': source_commit, 'productSourceCommit': product_commit,
            'jdkIdentity': cls.java_digest, 'toolIdentity': cls.tool_digest,
            'producerSources': [{'path': name, 'sha256': digest(source / name)} for name in PRODUCERS],
            'members': inventory(output)}
        (output / 'manifest.private.json').write_text(json.dumps(value, sort_keys=True) + '\n')
        report.update(status='prepared', manifestDigest=digest(output / 'manifest.private.json'))
    except subprocess.CalledProcessError as error:
        report.update(classify_diagnostic(error.stdout, error.stderr),
            returnCode=error.returncode)
        raise
    except Exception as error:
        report['failureClass'] = 'phase-deadline' if isinstance(error, TimeoutError) else 'producer-setup-failed'
        raise
    finally:
        stack.close()
        report.update(phase=phase, elapsedSeconds=round(time.monotonic() - started, 3))
        diagnostic.write_text(json.dumps(report, sort_keys=True) + '\n')
        cls.doClassCleanups()
    return report['manifestDigest']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--product-source-commit', required=True)
    args = parser.parse_args()
    # The process-wide fixture phase is separately bounded; native owner budgets are unchanged.
    import signal
    def expired(_signum, _frame):
        raise TimeoutError('fixture-preparation-budget-exceeded')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(900)
    prepare(args.source.resolve(strict=True), args.output.absolute(), args.product_source_commit)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

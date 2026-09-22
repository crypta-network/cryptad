#!/usr/bin/python3
"""Prepare private installed-workload inputs from real, previously built artifacts.

Compilation/signing precede this entrypoint. It never manufactures a predecessor or
original release evidence. The guest binds its installed helper/runtime separately.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[3]
if ROOT == Path('/opt/cryptad-restricted-test-kit'):
    ROOT = Path('/opt/cryptad-cross-version/current').resolve(strict=True)
for _relative in ('tools/interop', 'tools/release-certification/protected',
                  'tools/release-certification'):
    sys.path.insert(0, str(ROOT / _relative))
import cross_version_runtime as runtime
import maintenance_runtime_metadata as metadata
import restricted_workload_prepare as preparation
from cryptad_certification import cross_version_evidence as evidence

ROLES = ('candidate-sender', 'candidate-recipient', 'previous', 'relay-no-apps')
MANIFEST = 'manifest.private.json'
FIXED_GUEST_ROOT = Path('/root/cryptad/build/pr315-inputs')
MAX_BYTES = 2 * 1024**3
MAX_FILES = 32768
CLASSIFICATION = 'synthetic-source-build-not-original-authority'


def digest(path):
    path = Path(path).absolute()
    from runtime_snapshot import _directory, _file
    # Existing descriptor-pinned bounded reader checks every ancestor and the leaf.
    with _directory(path.parent) as parent:
        checksum, _size, _identity = _file(parent, path.name, MAX_BYTES, time.monotonic() + 60)
    return checksum.removeprefix('sha256:')


def inventory(root):
    """Bound every private payload file; no links, devices or multiply linked files."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('workload-fixture-root-invalid')
    rows, total, entries = [], 0, 0
    until = time.monotonic() + 60
    for directory, directories, files in os.walk(root, followlinks=False):
        entries += len(directories) + len(files)
        if entries > MAX_FILES or time.monotonic() >= until:
            raise ValueError('workload-fixture-inventory-invalid')
        for name in sorted(directories):
            if (Path(directory) / name).is_symlink():
                raise ValueError('workload-fixture-link-invalid')
        for name in sorted(files):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if relative == MANIFEST:
                continue
            info = path.lstat()
            total += info.st_size
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or total > MAX_BYTES or len(rows) >= MAX_FILES or time.monotonic() >= until):
                raise ValueError('workload-fixture-inventory-invalid')
            rows.append({'path': relative, 'size': info.st_size,
                         'executable': bool(info.st_mode & 0o111), 'sha256': digest(path)})
    return sorted(rows, key=lambda row: row['path'])


def copy_input(source, target, maximum):
    from runtime_snapshot import _directory, _unchanged
    source = Path(source).absolute()
    until = time.monotonic() + 60
    with _directory(source.parent) as parent:
        pinned = os.open(source.name, os.O_PATH | os.O_NOFOLLOW, dir_fd=parent)
        try:
            before = os.fstat(pinned)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= maximum:
                raise ValueError('workload-fixture-input-invalid')
            descriptor = os.open('/proc/self/fd/' + str(pinned), os.O_RDONLY | os.O_NONBLOCK)
            with os.fdopen(descriptor, 'rb') as incoming, target.open('xb') as outgoing:
                _unchanged(before, os.fstat(incoming.fileno()))
                remaining = before.st_size
                while remaining:
                    if time.monotonic() >= until:
                        raise ValueError('workload-fixture-copy-deadline')
                    block = incoming.read(min(65536, remaining))
                    if not block:
                        raise ValueError('workload-fixture-input-changed')
                    outgoing.write(block)
                    remaining -= len(block)
                if incoming.read(1):
                    raise ValueError('workload-fixture-input-changed')
                _unchanged(before, os.fstat(incoming.fileno()))
            _unchanged(before, os.stat(source.name, dir_fd=parent, follow_symlinks=False))
        finally:
            os.close(pinned)
    target.chmod(0o600)


def validate_roster(products):
    if not isinstance(products, dict) or set(products) != {'candidate', 'previous'}:
        raise ValueError('workload-fixture-products-invalid')
    for name, value in products.items():
        if (set(value) != {'sourceCommit', 'artifactDigest', 'artifactSize', 'daemonDigest',
                          'packageTarget', 'contractVersion', 'classification'}
                or not re.fullmatch('[0-9a-f]{40}', str(value['sourceCommit']))
                or value['packageTarget'] != 'linux-x64'
                or value['classification'] != ('historical-source-build' if name == 'previous' else 'source-build')
                or any(not re.fullmatch('sha256:[0-9a-f]{64}', str(value[key]))
                       for key in ('artifactDigest', 'daemonDigest'))
                or type(value['artifactSize']) is not int or not 0 < value['artifactSize'] <= 512 * 1024**2
                or type(value['contractVersion']) is not int or not 25 <= value['contractVersion'] <= 10000):
            raise ValueError('workload-fixture-products-invalid')
    if any(products['candidate'][key] == products['previous'][key]
           for key in ('sourceCommit', 'artifactDigest', 'daemonDigest')):
        raise ValueError('workload-fixture-previous-not-distinct')


def portable_bound(path):
    """Apply the installed preparation expansion cap before extracting either product."""
    total, count = 0, 0
    until = time.monotonic() + 60
    with tarfile.open(path, 'r:*') as archive:
        for member in archive:
            total += member.size
            count += 1
            if total > 512 * 1024**2 or count > 30000 or time.monotonic() >= until:
                raise ValueError('workload-fixture-package-too-large')


def prepare(args):
    """Package verified artifacts; all work occurs before a controller campaign exists."""
    if (type(args.max_seconds) is not int or not 30 <= args.max_seconds <= 3600
            or type(args.max_operations) is not int or not 1 <= args.max_operations <= 10000
            or not re.fullmatch('[0-9a-f]{40}', args.candidate_commit)
            or not re.fullmatch('[0-9a-f]{40}', args.previous_commit)
            or args.candidate_commit == args.previous_commit):
        raise ValueError('workload-fixture-selection-invalid')
    if subprocess.check_output(['git', '-C', str(args.source), 'status', '--porcelain',
                                '--untracked-files=normal'], timeout=10):
        raise ValueError('workload-fixture-clean-helper-source-required')
    output = args.output.absolute()
    os.umask(0o077)
    output.mkdir(mode=0o700, exist_ok=False)
    metadata.stage_jdk(args.java_home, output / 'jdk', args.jdk_digest)
    if sum(p.stat().st_size for p in (output / 'jdk').rglob('*') if p.is_file()) > 512 * 1024**2:
        raise ValueError('workload-fixture-jdk-too-large')
    products = {}
    with tempfile.TemporaryDirectory(prefix='pr315-fixture-', dir=output.parent) as temporary:
        stage = Path(temporary)
        for name in ('candidate', 'previous'):
            archive = output / (name + '.tar.gz')
            copy_input(getattr(args, name), archive, 512 * 1024**2)
            portable_bound(archive)
            checksum = runtime.digest_file(archive)
            package = runtime.extract_package(archive, stage / name, checksum, archive.stat().st_size)
            commit = getattr(args, name + '_commit')
            daemon = runtime.packaged_daemon_identity(package, commit)
            runtime.require_native_target(package, 'linux-x64', output / 'jdk')
            snapshot, _registry, executable = metadata.observe_package(archive, output / 'jdk', stage)
            if executable['digest'] != daemon:
                raise ValueError('workload-fixture-export-daemon-mismatch')
            (output / (name + '-contract.json')).write_bytes(snapshot)
            products[name] = {'sourceCommit': commit, 'artifactDigest': checksum,
                'artifactSize': archive.stat().st_size, 'daemonDigest': daemon, 'packageTarget': 'linux-x64',
                'contractVersion': json.loads(snapshot)['contract']['contractVersion'],
                'classification': 'historical-source-build' if name == 'previous' else 'source-build'}
        validate_roster(products)
        copy_input(args.mail_bundle, output / 'mail.zip', 64 * 1024**2)
        copy_input(args.trusted_keys, output / 'trusted-app-keys.properties', 65536)
        runtime.extract_app_bundle(output / 'mail.zip', stage / 'mail', runtime.digest_file(output / 'mail.zip'))
        # Normal signature verifier; unsigned mode and bundle rewriting are never used.
        from bounded_process import run
        tool = args.source / 'platform-devtools/build/install/crypta-app'
        run([str(output / 'jdk/bin/java'), '-cp', str(tool / 'lib/*'),
             'network.crypta.platform.devtools.CryptaAppCli', 'verify', '--bundle-dir', str(stage / 'mail'),
             '--trusted-keys-file', str(output / 'trusted-app-keys.properties')],
            environment={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, timeout=60, output_limit=65536)
        # The authoritative Java verifier parses the properties; constrain the selected app
        # independently through its fixed admitted manifest value.
        manifest = (stage / 'mail/cryptad-app.properties').read_text()
        if re.findall(r'(?m)^app\.id\s*=\s*(\S+)\s*$', manifest) != ['mail-prototype']:
            raise ValueError('workload-fixture-mail-identity-invalid')
    value = {'schemaVersion': 1, 'kind': 'pr315-workload-fixtures', 'classification': CLASSIFICATION,
        'sourceCommit': subprocess.check_output(['git', '-C', str(args.source), 'rev-parse', 'HEAD'],
                                              text=True, timeout=10).strip(),
        'products': products, 'roles': list(ROLES), 'runtimeDigest': runtime.tree_digest(output / 'jdk'),
        'jdkClosureDigest': args.jdk_digest, 'mailDigest': runtime.digest_file(output / 'mail.zip'),
        'trustDigest': runtime.digest_file(output / 'trusted-app-keys.properties'),
        'verifierDigest': runtime.tree_digest(tool, require_java=False),
        'maxSeconds': args.max_seconds, 'maxOperations': args.max_operations,
        'members': inventory(output)}
    (output / MANIFEST).write_text(json.dumps(value, sort_keys=True) + '\n')
    return digest(output / MANIFEST)


def verify(root, expected_manifest_digest, source, product_source_commit):
    root, source = Path(root), Path(source)
    path = root / MANIFEST
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 8 * 1024**2
            or digest(path) != expected_manifest_digest):
        raise ValueError('workload-fixture-manifest-mismatch')
    from runtime_snapshot import read_file
    raw = read_file(root.absolute(), MANIFEST, maximum=8 * 1024**2, timeout=30)
    if hashlib.sha256(raw).hexdigest() != expected_manifest_digest:
        raise ValueError('workload-fixture-manifest-mismatch')
    value = metadata.read_json(raw)
    if (set(value) != {'schemaVersion', 'kind', 'classification', 'sourceCommit', 'products', 'roles',
                      'runtimeDigest', 'jdkClosureDigest', 'mailDigest', 'trustDigest', 'verifierDigest',
                      'maxSeconds', 'maxOperations', 'members'}
            or value['schemaVersion'] != 1 or value['kind'] != 'pr315-workload-fixtures'
            or value['classification'] != CLASSIFICATION or value['roles'] != list(ROLES)
            or type(value['maxSeconds']) is not int or not 30 <= value['maxSeconds'] <= 3600
            or type(value['maxOperations']) is not int or not 1 <= value['maxOperations'] <= 10000
            or value['members'] != inventory(root)):
        raise ValueError('workload-fixture-manifest-invalid')
    validate_roster(value['products'])
    commit = subprocess.check_output(['git', '-c', 'safe.directory=' + str(source), '-C', str(source),
                                      'rev-parse', 'HEAD'], text=True, timeout=10).strip()
    if value['sourceCommit'] != commit or value['products']['candidate']['sourceCommit'] != product_source_commit:
        raise ValueError('workload-fixture-source-mismatch')
    for name, product in value['products'].items():
        archive = root / (name + '.tar.gz')
        if runtime.digest_file(archive) != product['artifactDigest'] or archive.stat().st_size != product['artifactSize']:
            raise ValueError('workload-fixture-product-mismatch')
    if (runtime.tree_digest(root / 'jdk') != value['runtimeDigest']
            or runtime.digest_file(root / 'mail.zip') != value['mailDigest']
            or runtime.digest_file(root / 'trusted-app-keys.properties') != value['trustDigest']
            or runtime.tree_digest(source / 'platform-devtools/build/install/crypta-app', require_java=False) != value['verifierDigest']):
        raise ValueError('workload-fixture-runtime-or-app-mismatch')
    return value


def materialize_selection(root, source, expected_manifest_digest=None, product_source_commit=None):
    """Bind only the fixed copied guest inputs to the currently installed helper closure."""
    root = Path(root)
    if root != FIXED_GUEST_ROOT or os.geteuid() != 0:
        raise ValueError('workload-fixture-fixed-guest-root-required')
    if expected_manifest_digest is None or product_source_commit is None:
        raise ValueError('workload-fixture-expected-binding-required')
    selected = verify(root, expected_manifest_digest, source, product_source_commit)
    experiment = 'pr315-installed-workload'
    private = {'root': '/var/lib/cryptad-cross-version/experiments/' + experiment, 'nodes': {}}
    nodes = []
    for role in ROLES:
        product_name = 'previous' if role == 'previous' else 'candidate'
        product = selected['products'][product_name]
        apps = [{'appId': 'mail-prototype', 'bundlePath': str(root / 'mail.zip'),
                 'bundleDigest': selected['mailDigest']}] if role.startswith('candidate-') else []
        private['nodes'][role] = {'archivePath': str(root / (product_name + '.tar.gz')),
            'javaHome': str(root / 'jdk'), 'fnpPort': 19400, 'fcpPort': 19401, 'httpPort': 19402,
            'apps': apps, 'trustedKeysPath': str(root / 'trusted-app-keys.properties'),
            'trustedKeysDigest': selected['trustDigest']}
        nodes.append({key: product[key] for key in ('sourceCommit', 'artifactDigest', 'artifactSize',
                                                   'packageTarget', 'contractVersion')})
        nodes[-1].update(role=role, product='cryptad', runtimeDigest=selected['runtimeDigest'],
            configDigest=preparation.configuration_identity(role, selected['trustDigest']),
            appDigests=[app['bundleDigest'] for app in apps])
    plan = {'schemaVersion': 1, 'kind': evidence.KIND, 'experimentId': experiment, 'profile': 'bounded-live',
        'topologyClass': 'single-host-independent-processes', 'provenanceClass': 'source-build-comparison',
        'requestedSeconds': selected['maxSeconds'], 'probeIntervalSeconds': 1,
        'policy': {'id': 'cross-version-observed-v1', 'minimumObservedSeconds': 0, 'maxGapSeconds': 600,
                   'maxEvents': 10000}, 'requiredScenarios': sorted(evidence.SCENARIOS),
        'producer': runtime.runner_identity(), 'nodes': nodes}
    evidence.validate_plan(plan)
    return {'plan': plan, 'private': private, 'authorization': {'syntheticContent': True,
        'experimentId': experiment, 'root': private['root'], 'planDigest': runtime.canonical_digest(plan),
        'maxSeconds': selected['maxSeconds'], 'maxOperations': selected['maxOperations']}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'output', 'candidate', 'previous', 'java-home', 'mail-bundle', 'trusted-keys'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('candidate-commit', 'previous-commit', 'jdk-digest'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--max-seconds', type=int, required=True)
    parser.add_argument('--max-operations', type=int, required=True)
    args = parser.parse_args()
    try:
        prepare(args)
    except (OSError, ValueError, runtime.RuntimeFailure, subprocess.SubprocessError):
        print(json.dumps({'status': 'fixture-preparation-failed', 'installedPositiveExecuted': False}))
        return 2
    print(json.dumps({'status': 'fixtures-prepared', 'installedPositiveExecuted': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/python3
"""Execute the fixed finite suite in fresh disposable guests and derive a local assessment.

There is no report-import or upload operation. Every private report consumed below comes from a
reference attempt this invocation created. Missing observer implementations remain not-executed
in the full inventory, including when all implemented guest groups happen to exit successfully.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import shutil
import subprocess
import time
from types import SimpleNamespace

import pr312_reference_vm as reference
import pr313_acceptance as acceptance
import pr313_faults as faults
import pr313_worker_faults as worker_faults
import pr313_public_faults as public_faults

MAX_PRIVATE_RECORD = 256 * 1024
# Reserve bounded guest write space plus room to retain terminal reports before another copy.
# This is a conservative launch prerequisite, not a disk quota or permission to remove history.
GUEST_WRITE_RESERVE = 4 * 1024**3
REPORT_RESERVE = 256 * 1024**2
CASE_FAILURE_STAGES = {
    'installed-pr313-fault': frozenset(faults.CASES),
    'installed-pr313-worker-fault': frozenset(worker_faults.CASES),
    'installed-pr313-public-fault': frozenset(public_faults.CASES),
    'installed-keyless-sandbox-probe': frozenset(('construction-probe',)),
    'production-bootstrap-readiness': frozenset(('bootstrap-ready',)),
    'socket-admission': frozenset(('socket-wrong-uid', 'socket-unknown-handle')),
    'installed-package-api-owner-validation': frozenset(('package-api',)),
    'installed-app-projection-owner-validation': frozenset(('signed-app',)),
    'native-cms-owning-consumer': frozenset(('wrong-product', 'wrong-app', 'cms-five-member-context',
        'cms-wrong-recipient', 'cms-tampered-envelope', 'cms-subject-substitution',
        'product-selection-native-consumers', 'retained-exact-retry')),
    'installed-native-hostile-fixtures': frozenset(name for name in acceptance.CASES
        if name.startswith('hostile-') and not name.startswith('hostile-output-')) | {'openat2-safe'},
    'installed-projection-output-hostile-fixtures': frozenset(name for name in acceptance.CASES
        if name.startswith('hostile-output-')),
    'production-restart-readiness': frozenset(('restart-ready',)),
}
SETUP_FAILURE_STAGES = frozenset(('installation', 'installation-export', 'dependency-profile-measurement',
    'installation-publication', 'installed-profile-verification', 'production-test-kit-separation',
    'socket-listening', 'prepared-fixture-verification'))


def missing_status(report, declared, case):
    """A stage can conservatively classify missing evidence; it can never grant a pass."""
    guest = report.get('guestSummary')
    if not isinstance(guest, dict):
        return 'setup-failed' if report.get('executed') is False else 'not-executed'
    stage = guest.get('failedStage')
    if not isinstance(stage, str):
        return 'not-executed'
    if stage in SETUP_FAILURE_STAGES:
        return 'setup-failed'
    if case in CASE_FAILURE_STAGES.get(stage, ()):
        # The selected driver was reached, but no complete causal result survived. Do not
        # invent either a successful denial or a claim that its attack never happened.
        return 'inconclusive'
    if len(declared) == 1 and stage in CASE_FAILURE_STAGES:
        return 'setup-failed'
    return 'not-executed'


def _tree_bytes(path):
    total, count = 0, 0
    deadline = time.monotonic() + 30
    if Path(path).is_file():
        return Path(path).stat().st_size
    for directory, _directories, files in os.walk(path, followlinks=False):
        for name in files:
            count += 1
            if count > 500000 or time.monotonic() >= deadline:
                raise ValueError('pr313-capacity-inventory-limit')
            selected = Path(directory) / name
            info = selected.stat()
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
    return total


def required_attempt_bytes(args):
    """Bound copied image/tool/source inputs plus fixed guest/report reserve before launch."""
    source = args.source.resolve(strict=True)
    tracked = reference.command(['git', '-C', str(source), 'ls-tree', '-r', '-z', '-l', 'HEAD'],
                                capture_output=True).stdout
    source_bytes = 0
    for entry in tracked.split(b'\0'):
        if entry:
            metadata, _name = entry.split(b'\t', 1)
            size = metadata.split()[-1]
            if not size.isdigit():
                raise ValueError('pr313-capacity-source-invalid')
            source_bytes += int(size)
    copied = source_bytes + _tree_bytes(source / '.git')
    copied += sum(_tree_bytes(source / relative) for relative in reference.PRODUCTS)
    copied += _tree_bytes(args.prepared_fixtures)
    return (args.prepared_image.stat().st_size + 3 * copied + _tree_bytes(args.qemu_root)
            + args.seed.stat().st_size + GUEST_WRITE_RESERVE + REPORT_RESERVE)


def groups():
    """Fixed disjoint coverage assignment, not a caller-selected command or case list."""
    assigned = set(faults.CASES) | set(worker_faults.CASES) | set(public_faults.CASES)
    native = [name for name in acceptance.CASES if name.startswith('hostile-')
              and not name.startswith('hostile-output-')]
    native.append('openat2-safe')
    output = [name for name in acceptance.CASES if name.startswith('hostile-output-')]
    assigned.update(native + output)
    positive = [name for name in acceptance.CASES if name not in assigned]
    return [('positive', None, positive), ('native-hostile', None, native),
            ('output-hostile', None, output),
            *(('fault', name, [name]) for name in faults.CASES),
            *(('worker', name, [name]) for name in worker_faults.CASES),
            *(('public', name, [name]) for name in public_faults.CASES)]


def private_json(path):
    """Read one bounded owner-private regular file without following its final link."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.geteuid() or before.st_mode & 0o077
                or before.st_size > MAX_PRIVATE_RECORD):
            raise ValueError('pr313-private-record-invalid')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(MAX_PRIVATE_RECORD + 1)
        after = os.fstat(fd)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns) or len(raw) > MAX_PRIVATE_RECORD:
            raise ValueError('pr313-private-record-changed')
    finally:
        os.close(fd)
    # Reuse the installation contract's strict JSON parser over the already retained bytes.
    from installation import InstallationError
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise InstallationError('restricted-json-duplicate')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(InstallationError('restricted-json-invalid')))


def _save(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')


def collect_attempt(directory, declared):
    """Read only host-verified private observations from the just-completed owned attempt."""
    report = private_json(directory / 'attempt.private.json')
    identity = report.get('hostVerifiedIdentity')
    observations = []
    evidence = directory / 'pr313-observation.private.json'
    if evidence.exists():
        value = private_json(evidence)
        observations = value if isinstance(value, list) else [value]
    if any(not isinstance(row, dict) or row.get('caseId') not in declared for row in observations):
        raise ValueError('pr313-group-observation-invalid')
    observed = [row['caseId'] for row in observations]
    if len(set(observed)) != len(observed):
        raise ValueError('pr313-group-observation-duplicate')
    # Missing fixture/observer code does not become infrastructure success or a denial.
    observations.extend({'caseId': name, 'status': missing_status(report, declared, name)}
                        for name in declared if name not in observed)
    return dict(contract=acceptance.CONTRACT, identity=identity, declaredCases=declared,
                observations=observations, guestStopped=report.get('guestStopped') is True,
                attemptCompleted=(report.get('status') == 'guest-report-retained'
                                  and type(report.get('guestExitCode')) is int
                                  and report['guestExitCode'] == 0))


def run(args):
    if os.geteuid() == 0:
        raise ValueError('reference-unprivileged-host-required')
    os.umask(0o077)
    output = args.output.absolute()
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    attempts, history = [], []
    _save(output / 'plan.private.json', {'contract': acceptance.CONTRACT, 'groups': [
        {'group': group, 'caseId': case, 'declaredCases': declared}
        for group, case, declared in groups()]})
    expected = None
    capacity_exhausted = False
    for index, (group, case, declared) in enumerate(groups()):
        directory = output / ('attempt-' + str(index + 1).zfill(2))
        selected = SimpleNamespace(**vars(args))
        selected.attempt = directory
        selected.mode = 'native-slice'
        selected.case_group, selected.fault_case = group, case
        try:
            if capacity_exhausted or shutil.disk_usage(output).free < required_attempt_bytes(args):
                capacity_exhausted = True
                attempts.append(dict(contract=acceptance.CONTRACT, identity=expected, declaredCases=declared,
                    observations=[{'caseId': name, 'status': 'setup-failed'} for name in declared], guestStopped=True, attemptCompleted=False))
                history.append({'group': group, 'caseId': case, 'status': 'setup-failed',
                                'reason': 'external-capacity-unavailable'})
                _save(output / ('history-' + str(index + 1).zfill(2) + '.private.json'), history)
                continue
            exit_code = reference.run(selected)
            attempt = collect_attempt(directory, declared)
            if expected is None and acceptance._identity(attempt['identity']):
                expected = attempt['identity']
            attempts.append(attempt)
            history.append({'group': group, 'caseId': case, 'exitCode': exit_code,
                            'status': 'observations-retained'})
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            attempts.append(dict(contract=acceptance.CONTRACT, identity=None, declaredCases=declared,
                observations=[{'caseId': name, 'status': 'setup-failed'} for name in declared], guestStopped=False, attemptCompleted=False))
            history.append({'group': group, 'caseId': case, 'status': 'setup-failed'})
        # Preserve incremental state on interruption; each uniquely named snapshot is immutable.
        _save(output / ('history-' + str(index + 1).zfill(2) + '.private.json'), history)
    result = acceptance.verify_attempts(expected, attempts)
    result['attemptHistory'] = history
    _save(output / 'observations.private.json', attempts)
    _save(output / 'assessment.json', result)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['installedKeylessNativeAcceptanceSatisfied'] else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'output', 'prepared-image', 'qemu-root', 'seed', 'ssh-key', 'known-hosts',
                 'prepared-fixtures'):
        parser.add_argument('--' + name, required=True, type=Path)
    for name in ('product-source-commit', 'prepared-image-digest', 'fixture-manifest-digest'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--profile', choices=tuple(reference.PROFILES), default='tcg-multi')
    parser.add_argument('--port', type=int, default=23112)
    parser.add_argument('--timeout', type=int, default=1800)
    parser.add_argument('--development-snapshot', action='store_true')
    parser.add_argument('--host-key-pin-origin', required=True,
        choices=('preselected-host-key', 'administrator-preparation-tofu'))
    args = parser.parse_args()
    if (not acceptance._digest(args.product_source_commit, 40)
            or not acceptance._digest(args.prepared_image_digest)
            or not acceptance._digest(args.fixture_manifest_digest)
            or not 1024 <= args.port <= 65535 or not 60 <= args.timeout <= 3600):
        parser.error('invalid fixed reference identity or bounded execution option')
    return run(args)


if __name__ == '__main__':
    raise SystemExit(main())

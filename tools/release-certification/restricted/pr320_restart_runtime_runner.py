#!/usr/bin/python3
"""Run the fixed same-cohort successor with existing host and v5 lifecycle consumers."""
from pathlib import Path
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
for relative in ('tools/interop', 'tools/release-certification/protected',
                 'tools/release-certification', 'tools/release-certification/restricted'):
    sys.path.insert(0, str(ROOT / relative))

import pr318_storage_runtime_runner as host
import pr319_restart_runtime_runner as historical
import pr320_storage_runtime_runner as bindings
import pr320_restart_selection as fixtures
import pr320_restart_runtime_evidence as evidence
import pr320_restart_contract as contract
import cross_version_installed_pr320_restart_budgets as installed
import pr320_campaign_capture as capture


def _source_modules(args):
    host._source_modules(args)
    import pr320_restart_admin
    for module, name in ((fixtures, 'selection'), (evidence, 'runtimeEvidence'),
        (contract, 'selectionContract'), (installed, 'installedDriver'), (pr320_restart_admin, 'administrator'),
        (capture, 'campaignCapture')):
        expected = (args.source / contract.TOOL_PATHS[name]).resolve(strict=True)
        if Path(module.__file__).resolve(strict=True) != expected or host.reference.sha256(module.__file__) != host.reference.sha256(expected):
            raise ValueError('pr320-restart-executing-source-mismatch')
    if host.reference.sha256(__file__) != host.reference.sha256(args.source / contract.TOOL_PATHS['hostRunner']):
        raise ValueError('pr320-restart-executing-source-mismatch')


def _fixture(root, digest, source, product_source):
    profile, value = fixtures.verify(root, digest, source, product_source)
    return {**value, 'caseIds': list(profile['cases']), 'environment': profile['environment'],
        'normalizedConfiguration': profile['normalizedConfiguration'], 'profile': profile}


def _selection(value, fixture):
    return bindings._selection(value, fixture, verify_selection=contract.verify_selection_contract)


def _closed_public(value):
    if value.get('kind') != evidence.PUBLIC_KIND or value.get('executionClass') != contract.EXECUTION_CLASS:
        raise ValueError('pr320-restart-public-projection-invalid')
    historical._closed_public({**value, 'kind': historical.evidence.PUBLIC_KIND,
        'executionClass': historical.evidence.EXECUTION_CLASS, 'sourceIdentityDigest': None})
    return value


def _driver_observation(value):
    if not isinstance(value, dict) or not host.EXTRA_FIELDS <= set(value):
        raise ValueError('pr320-restart-observation-invalid')
    installed.validate_guest_observation({key: item for key, item in value.items() if key not in host.EXTRA_FIELDS})
    if (value['cleanupState'] != 'completed' or value['protectedExecutionEnabled'] is not False
            or value['workloadAcceptance'] != 'incomplete-pr320-restart-private-evidence-not-verified'
            or not isinstance(value['identity'], dict) or not isinstance(value['runtimePolicy'], dict)
            or type(value['campaignDeadlineMonotonicNs']) is not int or value['campaignDeadlineMonotonicNs'] <= 0):
        raise ValueError('pr320-restart-observation-invalid')
    return value


def _attempt_projection(args, attempt, report, fixture, source_commit, watcher_finished):
    return historical._attempt_projection(args, attempt, report, fixture, source_commit, watcher_finished,
        suite=SimpleNamespace(selection=_selection, driver_observation=_driver_observation,
            public_projection=evidence.public_projection, closed_public=_closed_public,
            original_validator=evidence.validate_originals))


def run(args):
    return host.run_fixed_suite(args, SimpleNamespace(execution_class=contract.EXECUTION_CLASS,
        source_modules=_source_modules, verify_fixture=_fixture, scan=_scan,
        attempt_projection=_attempt_projection, closed_public=_closed_public, failed_projection=evidence.failed_projection,
        capture_originals=lambda _args, attempt, report: capture.prepare(attempt, report, 'pr320_restart_runtime_evidence')))


def _scan(root):
    return historical._scan_budget_privacy(root, capsule_decoder=capture.decode_capsule,
                                         root_capsule_decoder=capture.decode_root_capsule)


def main(argv=None):
    args = host.parser().parse_args(argv)
    try:
        return run(args)
    except (OSError, ValueError, KeyError, TypeError, host.subprocess.SubprocessError) as error:
        host._retain_failure(args, error, SimpleNamespace(scan=_scan, execution_class=contract.EXECUTION_CLASS))
        print(host.json.dumps(evidence.failed_projection('setup-or-execution-failed'), sort_keys=True))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())

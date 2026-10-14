#!/usr/bin/python3
"""One bounded copied-reference owner cancellation attempt; no protected authority is supplied."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
for relative in ('tools/interop', 'tools/release-certification/protected',
                 'tools/release-certification', 'tools/release-certification/restricted'):
    sys.path.insert(0, str(ROOT / relative))

import pr318_storage_runtime_runner as host
import pr320_storage_runtime_runner as shared
import pr320_owner_selection as fixtures
import pr320_owner_runtime_evidence as evidence
import pr320_cancellation_contract as contract
import cross_version_installed_owner_budgets as installed
import pr320_campaign_capture as capture


def _source_modules(args):
    host._source_modules(args)
    import pr320_owner_admin
    for module, name in ((fixtures, 'selection'), (evidence, 'runtimeEvidence'),
                         (contract, 'selectionContract'), (installed, 'installedDriver'),
                         (pr320_owner_admin, 'administrator'), (capture, 'campaignCapture')):
        expected = (args.source / contract.TOOL_PATHS[name]).resolve(strict=True)
        if Path(module.__file__).resolve(strict=True) != expected or host.reference.sha256(module.__file__) != host.reference.sha256(expected):
            raise ValueError('pr320-owner-executing-source-mismatch')
    if host.reference.sha256(__file__) != host.reference.sha256(args.source / contract.TOOL_PATHS['hostRunner']):
        raise ValueError('pr320-owner-executing-source-mismatch')


def _fixture(root, digest, source, product_source):
    profile, value = fixtures.verify(root, digest, source, product_source)
    return {**value, 'caseIds': list(profile['cases']), 'environment': profile['environment'],
            'normalizedConfiguration': profile['normalizedConfiguration'], 'profile': profile}


def _closed_public(value):
    if (not isinstance(value, dict) or set(value) != set(evidence.failed_projection('private-evidence-invalid'))
            or value['schemaVersion'] != 1 or value['kind'] != 'pr320-owner-cancellation-assessment'
            or value['status'] not in {'observed', 'incomplete', 'failed'}
            or value['observedCases'] not in ([], ['cancellation'])
            or value['evidenceClass'] != 'installed-process-owner'
            or value['fullAppBudgets'] != 'not-observed'
            or value['releaseEligible'] is not False or value['phaseComplete'] is not False):
        raise ValueError('pr320-owner-public-projection-invalid')
    return value


def _scan(root):
    return host.scan_retained_surfaces(root, private_name=evidence.PRIVATE_FILE,
        decode_private=evidence.decode_private, decode_checkpoints=evidence.decode_checkpoints,
        checkpoint_name=evidence.CHECKPOINT_FILE,
        private_readers={evidence.ROOT_NATIVE_FILE: (evidence.MAX_PRIVATE_BYTES, evidence.decode_root_native),
            capture.FILE: (capture.LIMIT, capture.decode_capsule),
            capture.ROOT_FILE: (capture.LIMIT, capture.decode_root_capsule)})


def _attempt_projection(args, attempt, report, fixture, source_commit, watcher_finished):
    if (not isinstance(report, dict) or report.get('schemaVersion') != 7
            or report.get('mode') != 'workload-positive' or report.get('workloadPurpose') != 'budget-owner'
            or report.get('status') != 'guest-report-retained' or report.get('guestExitCode') != 0
            or report.get('guestStopped') is not True or report.get('helperSourceCommit') != source_commit
            or report.get('productSourceCommit') != args.product_source_commit
            or report.get('preparedImageDigest') != args.prepared_image_digest
            or report.get('fixtureManifestDigest') != args.fixture_manifest_digest):
        raise ValueError('pr320-owner-reference-attempt-invalid')
    identity = host.shared._source_identity(report)
    raw = host.shared._private_bytes(attempt / evidence.PRIVATE_FILE, evidence.MAX_PRIVATE_BYTES)
    private = evidence.decode_private(raw)
    selected = host.shared._private_json(attempt / 'pr320-selection.private.json', 262144)
    selected_digest = shared._selection(selected, fixture, verify_selection=contract.verify_selection_contract)
    observed = host.shared._private_json(attempt / 'pr314-workload-observation.private.json', 131072)
    if not isinstance(observed, dict) or not host.EXTRA_FIELDS <= set(observed):
        raise ValueError('pr320-owner-observation-invalid')
    installed.validate_guest_observation({key: value for key, value in observed.items()
                                         if key not in host.EXTRA_FIELDS}, selected_digest)
    if (private['selectionDigest'] != selected_digest
            or observed['privateEvidenceDigest'] != 'sha256:' + hashlib.sha256(raw).hexdigest()
            or observed['cleanupState'] != 'completed' or observed['protectedExecutionEnabled'] is not False
            or observed['workloadAcceptance'] != 'incomplete-pr320-private-evidence-not-verified'
            or observed['identity'].get('sourceCommit') != identity['helperSourceCommit']
            or observed['identity'].get('bundleIdentity') != identity['bundleIdentity']):
        raise ValueError('pr320-owner-observation-substituted')
    checkpoints = evidence.decode_checkpoints(host.shared._private_bytes(
        attempt / evidence.CHECKPOINT_FILE, evidence.MAX_PRIVATE_BYTES))
    terminal = host.shared._private_json(attempt / 'pr315-workload-volatile.private.json', 262144)
    diagnostics = host.shared._private_json(attempt / 'pr315-workload-memory.private.json', 262144)
    original_raw = host.shared._private_bytes(attempt / evidence.ROOT_NATIVE_FILE, evidence.MAX_PRIVATE_BYTES)
    if diagnostics.get('ownerNativeOriginalDigest') != 'sha256:' + hashlib.sha256(original_raw).hexdigest():
        raise ValueError('pr320-owner-root-native-substituted')
    evidence.validate_originals(private, selected, diagnostics, terminal, checkpoints,
                               evidence.decode_root_native(original_raw))
    return _closed_public(evidence.public_projection(private,
        source_identity_digest=contract.canonical_digest(identity), originals_verified=True,
        privacy_verified=True, watcher_finished=watcher_finished, guest_stopped=True))


def run(args):
    return host.run_fixed_suite(args, SimpleNamespace(execution_class=contract.EXECUTION_CLASS,
        source_modules=_source_modules, verify_fixture=_fixture, scan=_scan,
        attempt_projection=_attempt_projection, closed_public=_closed_public,
        failed_projection=evidence.failed_projection,
        capture_originals=lambda _args, attempt, report: capture.prepare(attempt, report, 'pr320_owner_runtime_evidence')))


def main(argv=None):
    args = host.parser().parse_args(argv)
    try:
        return run(args)
    except (OSError, ValueError, KeyError, TypeError, host.subprocess.SubprocessError) as error:
        host._retain_failure(args, error, SimpleNamespace(scan=_scan, execution_class=contract.EXECUTION_CLASS))
        print(json.dumps(evidence.failed_projection('setup-or-execution-failed'), sort_keys=True))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())

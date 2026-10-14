#!/usr/bin/python3
"""One fixed PR-320 storage profile through the existing copied-reference host lifecycle."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
for relative in ('tools/interop', 'tools/release-certification/protected',
                 'tools/release-certification', 'tools/release-certification/restricted'):
    sys.path.insert(0, str(ROOT / relative))

import pr318_storage_runtime_runner as legacy
import pr320_storage_selection as fixtures
import pr320_storage_runtime_evidence as evidence
import pr320_campaign_capture as capture
import pr320_storage_contract as contract


def _source_modules(args):
    legacy._source_modules(args)
    import pr320_storage_admin
    for module, name in ((fixtures, 'selection'), (evidence, 'runtimeEvidence'),
                         (contract, 'selectionContract'), (pr320_storage_admin, 'administrator'),
                         (capture, 'campaignCapture')):
        expected = (args.source / contract.TOOL_PATHS[name]).resolve(strict=True)
        if (Path(module.__file__).resolve(strict=True) != expected
                or legacy.reference.sha256(module.__file__) != legacy.reference.sha256(expected)):
            raise ValueError('pr320-storage-executing-source-mismatch')
    expected = args.source / contract.TOOL_PATHS['hostRunner']
    if legacy.reference.sha256(__file__) != legacy.reference.sha256(expected):
        raise ValueError('pr320-storage-executing-source-mismatch')


def _fixture(root, digest, source, product_source):
    profile, value = fixtures.verify(root, digest, source, product_source)
    return {**value, 'caseIds': list(profile['cases']), 'environment': profile['environment'],
            'normalizedConfiguration': profile['normalizedConfiguration'], 'profile': profile}


def _selection(value, fixture, *, verify_selection=None):
    verify_selection = contract.verify_selection_contract if verify_selection is None else verify_selection
    if (not isinstance(value, dict) or set(value) != {'plan', 'private', 'authorization'}
            or not verify_selection(value['plan'], value['private'], value['authorization'])):
        raise ValueError('pr320-storage-host-selection-invalid')
    authorization, plan = value['authorization'], value['plan']
    budget = authorization['budgetSelection']
    bindings = {'timePlan': 'timePlan', 'toolIdentities': 'toolIdentities',
        'trustedKeysDigest': 'trustDigest', 'permissions': 'permissions', 'caseIds': 'caseIds',
        'environment': 'environment', 'normalizedConfiguration': 'normalizedConfiguration',
        'failurePolicy': 'failurePolicy', 'statementFingerprint': 'statementFingerprint',
        'statementDigest': 'statementDigest', 'appBundleDigests': 'apps'}
    if (authorization['executionClass'] != fixture['profile']['executionClass']
            or any(budget[key] != fixture[name] for key, name in bindings.items())
            or plan.get('producer', {}).get('sourceCommit') != fixture['sourceCommit']
            or plan.get('requestedSeconds') != fixture['maxSeconds']
            or any(authorization.get(key) != fixture[key] for key in ('maxSeconds', 'maxOperations'))):
        raise ValueError('pr320-storage-host-fixture-substituted')
    for node in plan['nodes']:
        product = fixture['products']['previous' if node['role'] == 'previous' else 'candidate']
        if (node.get('product') != 'cryptad' or node.get('runtimeDigest') != fixture['runtimeDigest']
                or any(node.get(key) != product[key] for key in
                       ('sourceCommit', 'artifactDigest', 'artifactSize', 'packageTarget', 'contractVersion'))):
            raise ValueError('pr320-storage-host-product-substituted')
    return authorization['selectionDigest']


def _closed_public(value):
    expected = set(evidence.failed_projection(contract.profile(*contract.VARIANTS[0]), 'private-evidence-invalid'))
    if (not isinstance(value, dict) or set(value) != expected
            or value['kind'] != 'pr320-storage-direction-assessment'
            or value['schemaVersion'] != 1
            or (value['caseId'], value['variant']) not in contract.VARIANTS
            or value['status'] not in {'observed', 'incomplete', 'failed'}
            or value['evidenceClass'] != 'installed-real-time-filesystem'
            or value['fullAppBudgets'] != 'not-observed'
            or value['releaseEligible'] is not False or value['phaseComplete'] is not False):
        raise ValueError('pr320-storage-public-projection-invalid')
    return value


def _attempt_projection(args, attempt, report, fixture, source_commit, watcher_finished):
    if (not isinstance(report, dict) or report.get('schemaVersion') != 7
            or report.get('mode') != 'workload-positive' or report.get('workloadPurpose') != 'budget-storage'
            or report.get('status') != 'guest-report-retained'
            or report.get('guestExitCode') != 0 or report.get('guestStopped') is not True
            or report.get('helperSourceCommit') != source_commit
            or report.get('productSourceCommit') != args.product_source_commit
            or report.get('preparedImageDigest') != args.prepared_image_digest
            or report.get('fixtureManifestDigest') != args.fixture_manifest_digest):
        raise ValueError('pr320-storage-reference-attempt-invalid')
    identity = legacy.shared._source_identity(report)
    raw = legacy.shared._private_bytes(attempt / evidence.PRIVATE_FILE, evidence.MAX_PRIVATE_BYTES)
    private = evidence.decode_private(raw)
    selected = legacy.shared._private_json(attempt / 'pr320-selection.private.json', 262144)
    selected_digest = _selection(selected, fixture)
    observed = legacy.shared._private_json(attempt / 'pr314-workload-observation.private.json', 131072)
    if not isinstance(observed, dict) or set(observed) != {
            'schemaVersion', 'kind', 'executionClass', 'selectionDigest', 'privateEvidenceDigest',
            'evidenceClass', 'caseId', 'variant', 'status', 'fullAppBudgets', 'phaseComplete',
            'releaseEligible', 'cleanupState'} | legacy.EXTRA_FIELDS:
        raise ValueError('pr320-storage-observation-invalid')
    legacy.installed.validate_complete_guest_observation({key: value for key, value in observed.items()
                                                        if key not in legacy.EXTRA_FIELDS})
    if (observed['workloadAcceptance'] != 'incomplete-pr320-private-evidence-not-verified'
            or observed['protectedExecutionEnabled'] is not False
            or type(observed['campaignDeadlineMonotonicNs']) is not int
            or observed['campaignDeadlineMonotonicNs'] <= 0):
        raise ValueError('pr320-storage-observation-invalid')
    if (observed.get('selectionDigest') != selected_digest
            or private['selectionDigest'] != selected_digest
            or observed.get('executionClass') != fixture['profile']['executionClass']
            or observed.get('privateEvidenceDigest') != 'sha256:' + hashlib.sha256(raw).hexdigest()
            or observed.get('cleanupState') != 'completed'
            or observed.get('identity', {}).get('sourceCommit') != identity['helperSourceCommit']
            or observed.get('identity', {}).get('bundleIdentity') != identity['bundleIdentity']):
        raise ValueError('pr320-storage-observation-substituted')
    checkpoints = evidence.decode_checkpoints(legacy.shared._private_bytes(
        attempt / evidence.CHECKPOINT_FILE, evidence.MAX_PRIVATE_BYTES))
    if any(row['phase'] == 'interrupted' for row in checkpoints):
        raise ValueError('pr320-storage-interrupted-original')
    terminal = legacy.shared._private_json(attempt / 'pr315-workload-volatile.private.json', 262144)
    diagnostics = legacy.shared._private_json(attempt / 'pr315-workload-memory.private.json', 262144)
    evidence.validate_originals(private, selected, diagnostics, terminal, report)
    return _closed_public(evidence.public_projection(private,
        source_identity_digest=contract.canonical_digest(identity), originals_verified=True,
        privacy_verified=True, watcher_finished=watcher_finished, guest_stopped=True))


def _scan(root):
    # Reuse the bounded scanner. Only the two fixed typed private members change;
    # no arbitrary private-directory exemption is introduced.
    return legacy.scan_retained_surfaces(root, private_name=evidence.PRIVATE_FILE,
        decode_private=evidence.decode_private, decode_checkpoints=evidence.decode_checkpoints,
        checkpoint_name=evidence.CHECKPOINT_FILE,
        private_readers={capture.FILE: (capture.LIMIT, capture.decode_capsule),
            capture.ROOT_FILE: (capture.LIMIT, capture.decode_root_capsule)})


def run(args):
    profile = contract.profile(args.case_id, args.variant)
    return legacy.run_fixed_suite(args, SimpleNamespace(execution_class=profile['executionClass'],
        source_modules=_source_modules, verify_fixture=_fixture, scan=_scan,
        attempt_projection=_attempt_projection, closed_public=_closed_public,
        failed_projection=lambda reason: evidence.failed_projection(profile, reason),
        capture_originals=lambda _args, attempt, report: capture.prepare(attempt, report, 'pr320_storage_runtime_evidence')))


def main(argv=None):
    parser = legacy.parser()
    parser.add_argument('--case-id', choices=sorted({pair[0] for pair in contract.VARIANTS}), required=True)
    parser.add_argument('--variant', choices=sorted({pair[1] for pair in contract.VARIANTS}), required=True)
    args = parser.parse_args(argv)
    profile = contract.profile(args.case_id, args.variant)
    if (re.fullmatch('[0-9a-f]{40}', args.product_source_commit) is None
            or any(re.fullmatch('[0-9a-f]{64}', value) is None
                   for value in (args.prepared_image_digest, args.fixture_manifest_digest))):
        parser.error('invalid fixed source or fixture identity')
    try:
        return run(args)
    except (OSError, ValueError, KeyError, TypeError, legacy.subprocess.SubprocessError) as error:
        # The original runner already retains capacity and attempt originals. Preserve
        # failure classification without exposing exception text or private paths.
        legacy._retain_failure(args, error, SimpleNamespace(scan=_scan,
                                                           execution_class=profile['executionClass']))
        print(json.dumps(evidence.failed_projection(profile, 'setup-or-execution-failed'), sort_keys=True))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())

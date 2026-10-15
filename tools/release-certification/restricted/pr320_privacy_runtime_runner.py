#!/usr/bin/python3
"""One fixed installed privacy attempt through the existing copied-reference lifecycle.

This entry point does not allocate or execute unless invoked under separately
supplied authorization. Original observations remain private; exports are closed.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
for relative in ('tools/interop', 'tools/release-certification/protected',
                 'tools/release-certification', 'tools/release-certification/restricted'):
    sys.path.insert(0, str(ROOT / relative))
import pr318_storage_runtime_runner as historical
import pr320_privacy_selection as fixtures
import pr320_privacy_runtime_evidence as evidence
import pr320_privacy_contract as contract
import cross_version_installed_privacy_budgets as installed


def _source_modules(args):
    historical._source_modules(args)
    import pr320_privacy_admin
    import pr320_privacy_browser_admin
    for module, key in ((fixtures, 'selection'), (evidence, 'runtimeEvidence'),
                        (contract, 'selectionContract'), (installed, 'installedDriver'),
                        (pr320_privacy_admin, 'administrator'), (pr320_privacy_browser_admin, 'browserAdministrator')):
        expected = (args.source / contract.TOOL_PATHS[key]).resolve(strict=True)
        if (Path(module.__file__).resolve(strict=True) != expected
                or historical.reference.sha256(module.__file__) != historical.reference.sha256(expected)):
            raise ValueError('pr320-privacy-executing-source-mismatch')
    if historical.reference.sha256(__file__) != historical.reference.sha256(args.source / contract.TOOL_PATHS['hostRunner']):
        raise ValueError('pr320-privacy-executing-source-mismatch')


def _selection(value, fixture):
    if (not isinstance(value, dict) or set(value) != {'plan', 'private', 'authorization'}
            or not contract.verify_selection_contract(value['plan'], value['private'], value['authorization'])):
        raise ValueError('pr320-privacy-host-selection-invalid')
    plan, authorization = value['plan'], value['authorization']
    budget = authorization['budgetSelection']
    bindings = {'timePlan': 'timePlan', 'toolIdentities': 'toolIdentities',
        'trustedKeysDigest': 'trustDigest', 'permissions': 'permissions', 'appBundleDigests': 'apps',
        'failurePolicy': 'failurePolicy', 'statementFingerprint': 'statementFingerprint', 'statementDigest': 'statementDigest'}
    if (authorization.get('browserProvider') != fixture['browserProvider']
            or any(budget[key] != fixture[name] for key, name in bindings.items())
            or plan.get('producer', {}).get('sourceCommit') != fixture['sourceCommit']
            or any(authorization[key] != fixture[key] for key in ('maxSeconds', 'maxOperations'))):
        raise ValueError('pr320-privacy-host-fixture-substituted')
    for node in plan['nodes']:
        product = fixture['products']['previous' if node['role'] == 'previous' else 'candidate']
        if (node.get('product') != 'cryptad' or node.get('runtimeDigest') != fixture['runtimeDigest']
                or any(node.get(key) != product[key] for key in
                       ('sourceCommit', 'artifactDigest', 'artifactSize', 'packageTarget', 'contractVersion'))):
            raise ValueError('pr320-privacy-host-product-substituted')
    return authorization['selectionDigest']


def _closed_public(value):
    if (not isinstance(value, dict) or set(value) != set(evidence.failed_projection('private-evidence-invalid'))
            or value['kind'] != 'pr320-native-privacy-assessment'
            or value['status'] not in {'observed', 'failed'}
            or value['observedComponents'] not in ([], ['native', 'browser'])
            or value['fullAppBudgets'] != 'not-observed' or value['releaseEligible'] is not False
            or value['phaseComplete'] is not False):
        raise ValueError('pr320-privacy-public-projection-invalid')
    if historical.shared.evidence.payload_exposed(json.dumps(value).encode()):
        raise ValueError('pr320-privacy-public-projection-invalid')
    return value


def _attempt_projection(args, attempt, report, fixture, source_commit, watcher_finished):
    if (not isinstance(report, dict) or report.get('schemaVersion') != 7
            or report.get('mode') != 'workload-positive' or report.get('workloadPurpose') != 'budget-privacy'
            or report.get('status') != 'guest-report-retained' or report.get('guestExitCode') != 0
            or report.get('guestStopped') is not True or report.get('helperSourceCommit') != source_commit
            or report.get('productSourceCommit') != args.product_source_commit
            or report.get('preparedImageDigest') != args.prepared_image_digest
            or report.get('fixtureManifestDigest') != args.fixture_manifest_digest or watcher_finished is not True):
        raise ValueError('pr320-privacy-reference-attempt-invalid')
    raw = historical.shared._private_bytes(attempt / evidence.PRIVATE_FILE, evidence.MAX_PRIVATE_BYTES)
    private = evidence.decode_private(raw)
    selected = historical.shared._private_json(attempt / 'pr320-selection.private.json', 262144)
    selection_digest = _selection(selected, fixture)
    observation = historical.shared._private_json(attempt / 'pr314-workload-observation.private.json', 131072)
    if not isinstance(observation, dict) or not historical.EXTRA_FIELDS <= set(observation):
        raise ValueError('pr320-privacy-observation-invalid')
    base = {key: value for key, value in observation.items() if key not in historical.EXTRA_FIELDS}
    installed.validate_guest_observation(base, selection_digest)
    if (set(observation) != set(base) | historical.EXTRA_FIELDS
            or observation['workloadAcceptance'] != 'incomplete-pr320-privacy-originals-not-verified'
            or observation['protectedExecutionEnabled'] is not False
            or private['selectionDigest'] != selection_digest
            or observation['privateEvidenceDigest'] != 'sha256:' + hashlib.sha256(raw).hexdigest()
            or observation['cleanupState'] != 'completed'):
        raise ValueError('pr320-privacy-observation-substituted')
    browser_raw = historical.shared._private_bytes(attempt / evidence.BROWSER_FILE, 2 * 1024 * 1024)
    if observation['browserEvidenceDigest'] != 'sha256:' + hashlib.sha256(browser_raw).hexdigest():
        raise ValueError('pr320-privacy-browser-transferred-substituted')
    browser = evidence.decode_browser(browser_raw)
    import pr320_privacy_artifact_producer as artifact_producer
    artifact_raw = historical.shared._private_bytes(attempt / artifact_producer.FILE, artifact_producer.LIMIT)
    artifact = artifact_producer.decode_artifact(artifact_raw)
    evidence.privacy.verify_artifacts(artifact, private['component'],
        native_digest='sha256:' + hashlib.sha256(raw).hexdigest(),
        source_commit=next(row['sourceCommit'] for row in selected['plan']['nodes'] if row['role']=='candidate-sender'))
    checkpoint_raw = historical.shared._private_bytes(attempt / evidence.CHECKPOINT_FILE, evidence.MAX_PRIVATE_BYTES)
    checkpoints = evidence.decode_checkpoints(checkpoint_raw)
    if [row['phase'] for row in checkpoints] != ['native-collected', 'browser-collected']:
        raise ValueError('pr320-privacy-checkpoint-incomplete')
    if checkpoints[0]['component'] != private['component'] or checkpoints[1]['component'] != browser:
        raise ValueError('pr320-privacy-checkpoint-substituted')
    original_raw = historical.shared._private_bytes(attempt / evidence.ORIGINALS_FILE, evidence.MAX_ORIGINAL_BYTES)
    originals = evidence.decode_originals(original_raw)
    terminal = historical.shared._private_json(attempt / 'pr315-workload-volatile.private.json', 262144)
    diagnostics = historical.shared._private_json(attempt / 'pr315-workload-memory.private.json', 65536)
    if (diagnostics.get('privacyOriginalsFile') != evidence.ORIGINALS_FILE
            or diagnostics.get('privacyOriginalsBytes') != len(original_raw)
            or diagnostics.get('privacyOriginalsDigest') != 'sha256:' + hashlib.sha256(original_raw).hexdigest()):
        raise ValueError('pr320-privacy-root-transfer-substituted')
    evidence.validate_originals(private, selected, diagnostics, terminal, report, originals=originals,
        browser=browser, native_digest='sha256:' + hashlib.sha256(raw).hexdigest())
    return _closed_public(evidence.public_projection(private, browser=browser,
        native_digest='sha256:' + hashlib.sha256(raw).hexdigest(), selected=selected,
        diagnostics=diagnostics, terminal=terminal, report=report, originals=originals))


def _scan(root):
    """Delegate bounded retention, admitting only exact owner-validated private members."""
    import pr320_campaign_capture
    import pr320_privacy_artifact_producer as artifact_producer
    return historical.scan_retained_surfaces(root, private_name=evidence.PRIVATE_FILE,
        decode_private=evidence.decode_private, decode_checkpoints=evidence.decode_checkpoints,
        checkpoint_name=evidence.CHECKPOINT_FILE, private_readers={
            artifact_producer.FILE: (artifact_producer.LIMIT,artifact_producer.decode_artifact),
            evidence.ORIGINALS_FILE: (8 * 1024 * 1024, evidence.decode_originals),
            evidence.BROWSER_FILE: (4 * 1024 * 1024, evidence.decode_browser),
            pr320_campaign_capture.FILE: (pr320_campaign_capture.LIMIT,pr320_campaign_capture.decode_capsule),
            pr320_campaign_capture.ROOT_FILE: (pr320_campaign_capture.LIMIT,pr320_campaign_capture.decode_root_capsule)})


def _capture_originals(args, attempt, report):
    import pr320_campaign_capture
    expected=(args.source/contract.TOOL_PATHS['campaignCapture']).resolve(strict=True)
    if Path(pr320_campaign_capture.__file__).resolve(strict=True) != expected:
        raise ValueError('pr320-privacy-capture-source-invalid')
    return pr320_campaign_capture.prepare(attempt,report,'pr320_privacy_runtime_evidence')


def run(args):
    return historical.run_fixed_suite(args, SimpleNamespace(execution_class=contract.EXECUTION_CLASS,
        timeout_seconds=8100, capture_originals=_capture_originals, source_modules=_source_modules, verify_fixture=fixtures.verify, scan=_scan,
        attempt_projection=_attempt_projection, closed_public=_closed_public,
        failed_projection=evidence.failed_projection))


def main(argv=None):
    args = historical.parser().parse_args(argv)
    if (re.fullmatch('[0-9a-f]{40}', args.product_source_commit) is None
            or any(re.fullmatch('[0-9a-f]{64}', value) is None for value in
                   (args.prepared_image_digest, args.fixture_manifest_digest))):
        print(json.dumps(evidence.failed_projection('setup-or-execution-failed'), sort_keys=True))
        return 2
    try:
        return run(args)
    except (OSError, ValueError, KeyError, TypeError, historical.subprocess.SubprocessError, KeyboardInterrupt) as error:
        historical._retain_failure(args, error, SimpleNamespace(scan=_scan, execution_class=contract.EXECUTION_CLASS))
        print(json.dumps(evidence.failed_projection('setup-or-execution-failed'), sort_keys=True))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())

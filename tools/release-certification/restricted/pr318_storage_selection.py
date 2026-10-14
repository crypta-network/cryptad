#!/usr/bin/python3
"""Prepare and bind the fixed PR-318 installed composed-budget cohort.

This is a separate prospective fixture contract.  It deliberately does not extend the
historical PR-315 manifest or reinterpret PR-316 Mail selections.  The only installed
application role is ``candidate-sender`` and every mutable operation choice is fixed here
before the protected controller prepares a campaign.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[3]
if ROOT == Path('/opt/cryptad-restricted-test-kit'):
    ROOT = Path('/opt/cryptad-cross-version/current').resolve(strict=True)
for _relative in ('tools/interop', 'tools/release-certification/protected',
                  'tools/release-certification', 'tools/release-certification/restricted'):
    sys.path.insert(0, str(ROOT / _relative))

import cross_version_runtime as runtime
import maintenance_runtime_metadata as metadata
import pr315_workload_fixtures as base
import pr318_storage_contract as contract
import restricted_workload_prepare as preparation
from cryptad_certification import cross_version_evidence as evidence


KIND = 'pr318-storage-budget-fixtures'
CLASSIFICATION = 'synthetic-source-build-not-original-authority'
FIXED_GUEST_ROOT = Path('/root/cryptad/build/pr318-inputs')
MANIFEST = 'manifest.private.json'
# The protected side-effect-free contract is authoritative; local literals above remain readable
# the fixed profile is shared by fixture preparation and protected admission.
EXECUTION_CLASS, EXPERIMENT = contract.EXECUTION_CLASS, contract.EXPERIMENT
ROLES, APP_IDS, CASES = contract.ROLES, contract.APP_IDS, contract.CASES
PERMISSIONS, ENVIRONMENT = contract.PERMISSIONS, contract.ENVIRONMENT
NORMALIZED_CONFIGURATION = contract.NORMALIZED_CONFIGURATION
FAILURE_POLICY, TOOL_PATHS = contract.FAILURE_POLICY, contract.TOOL_PATHS
HOST_EVIDENCE_PATHS = contract.HOST_EVIDENCE_PATHS


def canonical_digest(value):
    return contract.canonical_digest(value)


def tool_identities(source, *, installed_source=None):
    """Measure only the closed reviewed tool roster used by this execution class."""
    source = Path(source)
    values = {}
    for name, relative in TOOL_PATHS.items():
        path = source / relative if installed_source is None else installed_source.tool_path(relative)
        if not path.is_file() or path.is_symlink():
            raise ValueError('pr318-storage-tool-unavailable')
        values[name] = runtime.digest_file(path)
    return values


def _property(text, name):
    values = re.findall(r'(?m)^' + re.escape(name) + r'\s*=\s*([^\r\n]*)\s*$', text)
    if len(values) != 1:
        raise ValueError('pr318-storage-app-manifest-invalid')
    return values[0]


def _verify_app(extracted, app_id, permissions=None, process_client=None):
    """Bind identity, permissions and the exact non-Java fixture process shape."""
    allowed = PERMISSIONS if permissions is None else permissions
    manifest = (Path(extracted) / 'cryptad-app.properties').read_text()
    permissions = tuple(value for value in _property(manifest, 'app.permissions').split(',') if value)
    start_bytes = b'#!/bin/sh\nset -eu\nexec sleep 600\n'
    if process_client is not None and app_id in ('feed-reader', 'budget-importer'):
        from pr320_budget_contract import PROCESS_START_BYTES
        start_bytes = PROCESS_START_BYTES
        if (not isinstance(process_client, bytes)
                or (Path(extracted) / 'lib/pr320-budget-process-client.py').read_bytes() != process_client):
            raise ValueError('pr320-storage-process-client-invalid')
    if (_property(manifest, 'app.id') != app_id
            or _property(manifest, 'app.exec') != 'bin/start.sh'
            or permissions != allowed[app_id]
            or _property(manifest, 'sandbox.mode') != 'restricted-process'
            or _property(manifest, 'sandbox.required') != 'true'
            or _property(manifest, 'api.targetStability') != 'experimental'
            or _property(manifest, 'api.experimentalCapabilitiesAccepted') != 'true'
            or (Path(extracted) / 'bin/start.sh').read_bytes()
                != start_bytes):
        raise ValueError('pr318-storage-app-manifest-invalid')


def _verify_statement(path):
    raw = Path(path).read_bytes()
    if not 1 <= len(raw) <= 65536:
        raise ValueError('pr318-storage-statement-invalid')
    value = json.loads(raw)
    payload = value.get('payload') if isinstance(value, dict) else None
    issuer = payload.get('issuer') if isinstance(payload, dict) else None
    subject = payload.get('subject') if isinstance(payload, dict) else None
    signature = value.get('signature') if isinstance(value, dict) else None
    try:
        signature_bytes = base64.b64decode(signature.get('value', ''), validate=True)
        public_key = base64.b64decode(issuer.get('publicKeyBase64', ''), validate=True)
    except (AttributeError, ValueError):
        signature_bytes = b''
        public_key = b''
    if (not isinstance(value, dict) or set(value) != {'type', 'payload', 'signature'}
            or value.get('type') != 'crypta.trust.statement.v1'
            or not isinstance(payload, dict) or not isinstance(issuer, dict)
            or issuer.get('identityId') != 'PR309_PRIVATE_ISSUER_CANARY'
            or issuer.get('publicKeyFingerprint') != hashlib.sha256(public_key).hexdigest()
            or not 32 <= len(public_key) <= 128
            or not isinstance(subject, dict) or subject.get('kind') != 'profile'
            or subject.get('uri') != 'USK@synthetic/pr309-private-subject/0'
            or payload.get('context') != 'profile'
            or payload.get('reason') != 'PR309_PRIVATE_BODY_CANARY'
            or payload.get('tags') != ['synthetic']
            or not isinstance(signature, dict)
            or signature.get('algorithm') != 'app-vault-ed25519-preview'
            or signature.get('domain') != 'crypta.trust.statement.v1'
            or len(signature_bytes) != 64):
        raise ValueError('pr318-storage-statement-invalid')


def _verify_statement_signature(root, source, selected, *, verifier_root=None):
    """Verify exact selected bytes and return their product-defined document fingerprint."""
    from bounded_process import run
    root, source = Path(root), Path(source)
    product = selected['products']['candidate']
    with tempfile.TemporaryDirectory(
            prefix='pr318-statement-signature-', dir=root.parent) as temporary:
        stage = Path(temporary)
        package = runtime.extract_package(root / 'candidate.tar.gz', stage / 'package',
            product['artifactDigest'], product['artifactSize'])
        classes = stage / 'classes'
        classes.mkdir()
        java_home = root / 'jdk'
        verifier = source / 'platform-devtools/build/install/crypta-app' if verifier_root is None else Path(verifier_root)
        classpath = (str(verifier / 'lib/*')
                     + os.pathsep + str(package / 'lib/*'))
        source_file = source / TOOL_PATHS['statementVerifier']
        environment = {'PATH': str(java_home / 'bin') + ':/usr/bin:/bin',
                       'JAVA_HOME': str(java_home), 'LANG': 'C.UTF-8'}
        run([str(java_home / 'bin/javac'), '-cp', classpath, '-d', str(classes),
             str(source_file)], environment=environment, timeout=60, output_limit=65536)
        fingerprint_path = stage / 'statement-fingerprint.private.txt'
        run([str(java_home / 'bin/java'), '-cp', str(classes) + os.pathsep + classpath,
             'network.crypta.platform.devtools.fixtures.Pr317SignedBudgetStatementVerifier',
             str(root / 'statement.json'), str(fingerprint_path)], environment=environment,
            timeout=30, output_limit=4096)
        fingerprint = fingerprint_path.read_text(encoding='ascii').strip()
        if re.fullmatch('[0-9a-f]{64}', fingerprint) is None:
            raise ValueError('pr318-storage-statement-fingerprint-invalid')
        return fingerprint


def _verify_bundles(root, source, selected, permissions=None, process_client=None, *, verifier_root=None):
    """Run the normal signed-bundle verifier and then constrain the synthetic subjects."""
    tool = Path(source) / 'platform-devtools/build/install/crypta-app' if verifier_root is None else Path(verifier_root)
    from bounded_process import run
    with tempfile.TemporaryDirectory(prefix='pr318-storage-verify-', dir=Path(root).parent) as temporary:
        stage = Path(temporary)
        for app_id in APP_IDS:
            bundle = Path(root) / (app_id + '.zip')
            extracted = runtime.extract_app_bundle(bundle, stage / app_id,
                                                   selected['apps'][app_id])
            run([str(Path(root) / 'jdk/bin/java'), '-cp', str(tool / 'lib/*'),
                 'network.crypta.platform.devtools.CryptaAppCli', 'verify',
                 '--bundle-dir', str(extracted), '--trusted-keys-file',
                 str(Path(root) / 'publisher-keys.properties')],
                environment={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'},
                timeout=60, output_limit=65536)
            _verify_app(extracted, app_id, permissions, process_client)


def prepare(args, *, permissions=None, process_client=None, maximum_seconds=3600):
    """Create signed fixture inputs under an owning fixed permission roster."""
    permissions = PERMISSIONS if permissions is None else permissions
    if (maximum_seconds not in (3600, 7200) or type(args.max_seconds) is not int or not 60 <= args.max_seconds <= maximum_seconds
            or type(args.max_operations) is not int or not 1 <= args.max_operations <= 10000
            or not re.fullmatch('[0-9a-f]{40}', args.candidate_commit)
            or not re.fullmatch('[0-9a-f]{40}', args.previous_commit)
            or args.candidate_commit == args.previous_commit):
        raise ValueError('pr318-storage-fixture-selection-invalid')
    if subprocess.check_output(['git', '-C', str(args.source), 'status', '--porcelain',
                                '--untracked-files=normal'], timeout=10):
        raise ValueError('pr318-storage-clean-helper-source-required')
    selected_at = int(time.time())
    time_plan = {'boundaryEpochSecond': args.boundary_epoch_second,
        'selectedAtEpochSecond': selected_at, 'startMarginSeconds': 10,
        'requestDeadlineMillis': 45000}
    if not contract.valid_time_plan(time_plan):
        raise ValueError('pr318-time-plan-invalid')
    output = args.output.absolute()
    os.umask(0o077)
    output.mkdir(mode=0o700, exist_ok=False)
    metadata.stage_jdk(args.java_home, output / 'jdk', args.jdk_digest)
    if sum(path.stat().st_size for path in (output / 'jdk').rglob('*') if path.is_file()) > 512 * 1024**2:
        raise ValueError('pr318-storage-jdk-too-large')
    products = {}
    with tempfile.TemporaryDirectory(prefix='pr318-product-', dir=output.parent) as temporary:
        stage = Path(temporary)
        for name in ('candidate', 'previous'):
            archive = output / (name + '.tar.gz')
            base.copy_input(getattr(args, name), archive, 512 * 1024**2)
            base.portable_bound(archive)
            checksum = runtime.digest_file(archive)
            package = runtime.extract_package(archive, stage / name, checksum,
                                              archive.stat().st_size)
            preparation.verify_wrapper_options(package)
            commit = getattr(args, name + '_commit')
            daemon = runtime.packaged_daemon_identity(package, commit)
            implementation = base.daemon_implementation_identity(package / 'lib/cryptad.jar')
            runtime.require_native_target(package, 'linux-x64', output / 'jdk')
            snapshot, _registry, executable = metadata.observe_package(
                archive, output / 'jdk', stage)
            if executable['digest'] != daemon:
                raise ValueError('pr318-storage-export-daemon-mismatch')
            (output / (name + '-contract.json')).write_bytes(snapshot)
            products[name] = {'sourceCommit': commit, 'artifactDigest': checksum,
                'artifactSize': archive.stat().st_size, 'daemonDigest': daemon,
                'packageTarget': 'linux-x64',
                'daemonImplementationDigest': implementation,
                'contractVersion': json.loads(snapshot)['contract']['contractVersion'],
                'classification': 'historical-source-build' if name == 'previous' else 'source-build'}
        base.validate_roster(products)
    inputs = {
        'feed-reader': args.feed_reader,
        'budget-importer': args.budget_importer,
        'budget-no-trust': args.budget_no_trust,
        'budget-no-fetch': args.budget_no_fetch,
    }
    apps = {}
    for app_id, source in inputs.items():
        target = output / (app_id + '.zip')
        base.copy_input(source, target, 64 * 1024**2)
        apps[app_id] = runtime.digest_file(target)
    base.copy_input(args.trusted_keys, output / 'publisher-keys.properties', 65536)
    base.copy_input(args.statement, output / 'statement.json', 65536)
    tools = tool_identities(args.source)
    selected = {'apps': apps}
    _verify_bundles(output, args.source, selected, permissions, process_client)
    _verify_statement(output / 'statement.json')
    statement_fingerprint = _verify_statement_signature(
        output, args.source, {'products': products})
    verifier = args.source / 'platform-devtools/build/install/crypta-app'
    value = {'schemaVersion': 1, 'kind': KIND, 'executionClass': EXECUTION_CLASS,
        'classification': CLASSIFICATION, 'timePlan': time_plan,
        'runtimePolicy': {'launcher': preparation.launcher_policy(),
                          'budget': preparation.budget_launcher_policy(EXECUTION_CLASS)},
        'sourceCommit': subprocess.check_output(
            ['git', '-C', str(args.source), 'rev-parse', 'HEAD'], text=True,
            timeout=10).strip(),
        'products': products, 'roles': list(ROLES),
        'runtimeDigest': runtime.tree_digest(output / 'jdk'),
        'jdkClosureDigest': args.jdk_digest, 'apps': apps,
        'trustDigest': runtime.digest_file(output / 'publisher-keys.properties'),
        'statementDigest': runtime.digest_file(output / 'statement.json'),
        'statementFingerprint': statement_fingerprint,
        'verifierDigest': runtime.tree_digest(verifier, require_java=False),
        'toolIdentities': tools, 'permissions': {key: list(value) for key, value in permissions.items()},
        'caseIds': list(CASES), 'environment': dict(ENVIRONMENT),
        'normalizedConfiguration': NORMALIZED_CONFIGURATION,
        'failurePolicy': dict(FAILURE_POLICY), 'maxSeconds': args.max_seconds,
        'maxOperations': args.max_operations, 'members': base.inventory(output)}
    (output / MANIFEST).write_text(json.dumps(value, sort_keys=True) + '\n')
    return base.digest(output / MANIFEST)


def _source_verifier_identity(source, root, verifier_digest, installed_source=None):
    """Historical Git identity or a separately sealed prospective installed source."""
    if installed_source is None:
        commit = subprocess.check_output(['git', '-c', 'safe.directory=' + str(source), '-C',
            str(source), 'rev-parse', 'HEAD'], text=True, timeout=10).strip()
        return commit, source / 'platform-devtools/build/install/crypta-app'
    from pr320_original_acquisition import InstalledFixtureSource
    if not isinstance(installed_source, InstalledFixtureSource):
        raise ValueError('pr318-installed-fixture-source-authority-required')
    return installed_source.require(source, root, verifier_digest)


def verify(root, expected_manifest_digest, source, product_source_commit, *, permissions=None, process_client=None, maximum_seconds=3600, installed_source=None):
    """Verify every prospective fixture, signer registry and current fixed tool byte."""
    permissions = PERMISSIONS if permissions is None else permissions
    root, source = Path(root), Path(source)
    path = root / MANIFEST
    if (expected_manifest_digest is None or product_source_commit is None
            or base.digest(path) != expected_manifest_digest):
        raise ValueError('pr318-storage-fixture-manifest-mismatch')
    from runtime_snapshot import read_file
    raw = read_file(root.absolute(), MANIFEST, maximum=8 * 1024**2, timeout=30)
    if hashlib.sha256(raw).hexdigest() != expected_manifest_digest:
        raise ValueError('pr318-storage-fixture-manifest-mismatch')
    value = metadata.read_json(raw)
    fields = {'schemaVersion', 'kind', 'executionClass', 'classification', 'runtimePolicy',
        'sourceCommit', 'products', 'roles', 'runtimeDigest', 'jdkClosureDigest', 'apps',
        'trustDigest', 'statementDigest', 'statementFingerprint', 'verifierDigest',
        'toolIdentities', 'permissions',
        'caseIds', 'environment', 'normalizedConfiguration', 'failurePolicy',
        'maxSeconds', 'maxOperations', 'members', 'timePlan'}
    if (set(value) != fields or value['schemaVersion'] != 1 or not contract.valid_time_plan(value['timePlan']) or value['kind'] != KIND
            or value['executionClass'] != EXECUTION_CLASS
            or value['classification'] != CLASSIFICATION or value['roles'] != list(ROLES)
            or value['runtimePolicy'] != {
                'launcher': preparation.launcher_policy(),
                'budget': preparation.budget_launcher_policy(EXECUTION_CLASS)}
            or value['permissions'] != {key: list(entry) for key, entry in permissions.items()}
            or value['caseIds'] != list(CASES) or value['environment'] != ENVIRONMENT
            or value['normalizedConfiguration'] != NORMALIZED_CONFIGURATION
            or value['failurePolicy'] != FAILURE_POLICY
            or maximum_seconds not in (3600, 7200)
            or type(value['maxSeconds']) is not int or not 60 <= value['maxSeconds'] <= maximum_seconds
            or type(value['maxOperations']) is not int or not 1 <= value['maxOperations'] <= 10000
            or value['members'] != base.inventory(root)):
        raise ValueError('pr318-storage-fixture-manifest-invalid')
    base.validate_roster(value['products'])
    commit, verifier_root = _source_verifier_identity(source, root, value['verifierDigest'], installed_source)
    if value['sourceCommit'] != commit or value['products']['candidate']['sourceCommit'] != product_source_commit:
        raise ValueError('pr318-storage-fixture-source-mismatch')
    for name, product in value['products'].items():
        measured = base.portable_daemon_identities(root / (name + '.tar.gz'),
            expected_digest=product['artifactDigest'], expected_size=product['artifactSize'])
        if (measured['daemonDigest'] != product['daemonDigest']
                or measured['daemonImplementationDigest'] != product['daemonImplementationDigest']):
            raise ValueError('pr318-storage-daemon-identity-mismatch')
    observed_apps = {app_id: runtime.digest_file(root / (app_id + '.zip'))
                     for app_id in APP_IDS}
    if (set(value['apps']) != set(APP_IDS) or value['apps'] != observed_apps
            or runtime.tree_digest(root / 'jdk') != value['runtimeDigest']
            or runtime.digest_file(root / 'publisher-keys.properties') != value['trustDigest']
            or runtime.digest_file(root / 'statement.json') != value['statementDigest']
            or re.fullmatch('[0-9a-f]{64}', str(value['statementFingerprint'])) is None
            or runtime.tree_digest(verifier_root,
                                   require_java=False) != value['verifierDigest']
            or tool_identities(source, **({} if installed_source is None else {'installed_source': installed_source})) != value['toolIdentities']):
        raise ValueError('pr318-storage-runtime-or-app-mismatch')
    if installed_source is None:
        _verify_bundles(root, source, value, permissions, process_client)
    else:
        _verify_bundles(root, source, value, permissions, process_client, verifier_root=verifier_root)
    _verify_statement(root / 'statement.json')
    fingerprint = (_verify_statement_signature(root, source, value) if installed_source is None else
                   _verify_statement_signature(root, source, value, verifier_root=verifier_root))
    if fingerprint != value['statementFingerprint']:
        raise ValueError('pr318-storage-statement-fingerprint-mismatch')
    return value


def _budget_selection(selected, plan, private):
    tools = selected['toolIdentities']
    app_bundles = {app_id: selected['apps'][app_id] for app_id in APP_IDS}
    composed = plan['composedBudgetInputs']
    return {'schemaVersion': 1, 'caseIds': list(CASES),
        'appRoster': {'candidate-sender': list(APP_IDS), 'candidate-recipient': [],
                      'previous': [], 'relay-no-apps': []},
        'permissions': {key: list(value) for key, value in PERMISSIONS.items()},
        'appBundleDigests': app_bundles, 'trustedKeysDigest': selected['trustDigest'],
        'statementDigest': selected['statementDigest'],
        'statementFingerprint': selected['statementFingerprint'],
        'environment': dict(ENVIRONMENT),
        'normalizedConfiguration': NORMALIZED_CONFIGURATION,
        'failurePolicy': dict(FAILURE_POLICY), 'toolIdentities': dict(tools),
        'composedBudgetInputs': dict(composed),
        'privateRootClass': 'controller-derived-' + EXPERIMENT, 'timePlan': selected['timePlan']}


def materialize_selection(root, source, expected_manifest_digest=None,
                          product_source_commit=None):
    """Create the exact four-role PR-318 selection before any controller mutation."""
    root, source = Path(root), Path(source)
    if root != FIXED_GUEST_ROOT or os.geteuid() != 0:
        raise ValueError('pr318-storage-fixed-guest-root-required')
    selected = verify(root, expected_manifest_digest, source, product_source_commit)
    return materialize_verified(root, selected)


def materialize_verified(root, selected, profile=None):
    """Assemble immutable inputs using the owning finite execution profile."""
    profile = profile or {"executionClass": EXECUTION_CLASS, "experiment": EXPERIMENT,
        "cases": CASES, "environment": ENVIRONMENT,
        "normalizedConfiguration": NORMALIZED_CONFIGURATION, "toolPaths": TOOL_PATHS}
    execution_class, experiment = profile['executionClass'], profile['experiment']
    environment, normalized = profile['environment'], profile['normalizedConfiguration']
    private = {'root': '/var/lib/cryptad-cross-version/experiments/' + experiment,
               'nodes': {}}
    nodes = []
    for role in ROLES:
        product_name = 'previous' if role == 'previous' else 'candidate'
        product = selected['products'][product_name]
        apps = ([{'appId': app_id, 'bundlePath': str(root / (app_id + '.zip')),
                  'bundleDigest': selected['apps'][app_id]} for app_id in APP_IDS]
                if role == 'candidate-sender' else [])
        trust_digest = (selected['trustDigest'] if apps
                        else 'sha256:' + hashlib.sha256(b'').hexdigest())
        private['nodes'][role] = {'archivePath': str(root / (product_name + '.tar.gz')),
            'javaHome': str(root / 'jdk'), 'fnpPort': 19400, 'fcpPort': 19401,
            'httpPort': 19402, 'apps': apps,
            'trustedKeysPath': str(root / 'publisher-keys.properties'),
            'trustedKeysDigest': trust_digest}
        if role == 'candidate-sender':
            private['nodes'][role].update(
                budgetStatementPath=str(root / 'statement.json'),
                budgetStatementDigest=selected['statementDigest'])
        node = {key: product[key] for key in ('sourceCommit', 'artifactDigest',
            'artifactSize', 'packageTarget', 'contractVersion')}
        node.update(role=role, product='cryptad', runtimeDigest=selected['runtimeDigest'],
            configDigest=preparation.configuration_identity(
                role, trust_digest, execution_class),
            appDigests=[app['bundleDigest'] for app in apps])
        nodes.append(node)
    workload_digest = selected['toolIdentities']['installedDriver']
    collector_digest = canonical_digest({key: selected['toolIdentities'][key] for key in
        profile.get('collectorTools', ('installedDriver', 'localBudgetAdapter', 'schedulerRuntime', 'evidenceOracle',
         'storageOracle', 'administrator', 'roleClients', 'runtimeEvidence'))})
    configuration_digest = canonical_digest({
        'nodeConfigDigest': nodes[0]['configDigest'], 'environment': environment,
        'normalizedConfiguration': normalized})
    plan = {'schemaVersion': 1, 'kind': evidence.KIND, 'experimentId': experiment,
        'profile': 'bounded-live', 'topologyClass': 'single-host-independent-processes',
        'provenanceClass': 'source-build-comparison',
        'requestedSeconds': selected['maxSeconds'], 'probeIntervalSeconds': 1,
        'policy': {'id': 'cross-version-observed-v1', 'minimumObservedSeconds': 0,
                   'maxGapSeconds': 600, 'maxEvents': 10000},
        'requiredScenarios': sorted(evidence.SCENARIOS), 'producer': runtime.runner_identity(),
        'nodes': nodes, 'workloadInputs': {'scheduler': workload_digest},
        'composedBudgetInputs': {'collectorDigest': collector_digest,
                                 'configurationDigest': configuration_digest}}
    if 'campaignJournal' in profile['toolPaths']:
        from cryptad_certification.composed_budget_journal_member import campaign_inputs
        plan['budgetCampaignInputs'] = campaign_inputs(plan, selected['toolIdentities'])
    evidence.validate_plan(plan)
    budget_selection = _budget_selection(selected, plan, private)
    budget_selection.update(caseIds=list(profile['cases']), environment=dict(environment),
        permissions={key: list(value) for key, value in profile.get('permissions', PERMISSIONS).items()},
        normalizedConfiguration=normalized, privateRootClass='controller-derived-' + experiment)
    authorization = {'syntheticContent': True, 'executionClass': execution_class,
        'experimentId': experiment, 'root': private['root'],
        'planDigest': runtime.canonical_digest(plan), 'maxSeconds': selected['maxSeconds'],
        'maxOperations': selected['maxOperations'], 'budgetSelection': budget_selection}
    authorization['selectionDigest'] = runtime.canonical_digest({
        'executionClass': execution_class, 'planDigest': authorization['planDigest'],
        'budgetSelection': budget_selection})
    return {'plan': plan, 'private': private, 'authorization': authorization}


def verify_selection_contract(plan, private, authorization):
    """Delegate to the side-effect-free protected contract shared with admission."""
    return contract.verify_selection_contract(plan, private, authorization)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'output', 'candidate', 'previous', 'java-home', 'feed-reader',
                 'budget-importer', 'budget-no-trust', 'budget-no-fetch', 'trusted-keys',
                 'statement'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('candidate-commit', 'previous-commit', 'jdk-digest'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--max-seconds', type=int, required=True)
    parser.add_argument('--max-operations', type=int, required=True)
    parser.add_argument('--boundary-epoch-second', type=int, required=True)
    args = parser.parse_args()
    try:
        digest = prepare(args)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        print(json.dumps({'status': 'pr318-fixture-preparation-failed',
                          'installedPositiveExecuted': False}))
        return 2
    print(json.dumps({'status': 'pr318-fixtures-prepared', 'manifestDigest': digest,
                      'installedPositiveExecuted': False}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

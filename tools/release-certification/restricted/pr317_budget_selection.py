#!/usr/bin/python3
"""Prepare and bind the fixed PR-317 installed composed-budget cohort.

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


ROOT = Path(__file__).resolve().parents[3]
if ROOT == Path('/opt/cryptad-restricted-test-kit'):
    ROOT = Path('/opt/cryptad-cross-version/current').resolve(strict=True)
for _relative in ('tools/interop', 'tools/release-certification/protected',
                  'tools/release-certification', 'tools/release-certification/restricted'):
    sys.path.insert(0, str(ROOT / _relative))

import cross_version_runtime as runtime
import maintenance_runtime_metadata as metadata
import pr315_workload_fixtures as base
import pr317_budget_contract as contract
import restricted_workload_prepare as preparation
from cryptad_certification import cross_version_evidence as evidence


EXECUTION_CLASS = 'pr317-namespace-bound-composed-budget-v1'
EXPERIMENT = 'pr317-namespace-bound-composed-budget'
KIND = 'pr317-composed-budget-fixtures'
CLASSIFICATION = 'synthetic-source-build-not-original-authority'
FIXED_GUEST_ROOT = Path('/root/cryptad/build/pr317-inputs')
MANIFEST = 'manifest.private.json'
ROLES = ('candidate-sender', 'candidate-recipient', 'previous', 'relay-no-apps')
APP_IDS = ('feed-reader', 'budget-importer', 'budget-no-trust', 'budget-no-fetch')
CASES = ('import-concurrency', 'fetch-concurrency', 'timeout', 'cancellation', 'retry')
PERMISSIONS = {
    'feed-reader': ('content.fetch', 'content.subscribe', 'trust.read', 'trust.write'),
    'budget-importer': ('content.fetch', 'content.subscribe', 'trust.read', 'trust.write'),
    'budget-no-trust': ('content.fetch',),
    'budget-no-fetch': ('trust.read', 'trust.write'),
}
ENVIRONMENT = {
    'CRYPTAD_CONTENT_SUBSCRIPTIONS_SCHEDULER_ENABLED': 'false',
    'CRYPTAD_CONTENT_SUBSCRIPTIONS_SCHEDULER_INITIAL_DELAY_SECONDS': '1',
    'CRYPTAD_CONTENT_SUBSCRIPTIONS_SCHEDULER_POLL_INTERVAL_SECONDS': '1',
    'CRYPTAD_CONTENT_SUBSCRIPTIONS_MINIMUM_POLL_INTERVAL_SECONDS': '2',
    'CRYPTAD_CONTENT_SUBSCRIPTIONS_SCHEDULER_JITTER_SECONDS': '0',
    'CRYPTAD_CONTENT_SUBSCRIPTIONS_FAILURE_BACKOFF_SECONDS': '2',
    'CRYPTAD_CONTENT_SUBSCRIPTIONS_MAXIMUM_FAILURE_BACKOFF_SECONDS': '2',
    'CRYPTAD_CONTENT_SUBSCRIPTIONS_PRESSURE_MAX_IN_FLIGHT': '1',
    'CRYPTAD_CONTENT_SUBSCRIPTIONS_PRESSURE_RESUME_AT_OR_BELOW': '0',
    'CRYPTAD_APP_NETWORK_BUDGET_FOREGROUND_CONTENT_FETCH_CONCURRENT_PER_APP': '2',
    'CRYPTAD_APP_NETWORK_BUDGET_FOREGROUND_CONTENT_FETCH_CONCURRENT_GLOBAL': '1',
    'CRYPTAD_APP_NETWORK_BUDGET_FOREGROUND_CONTENT_FETCH_PER_APP_PER_MINUTE': '32',
    'CRYPTAD_APP_NETWORK_BUDGET_FOREGROUND_CONTENT_FETCH_GLOBAL_PER_MINUTE': '64',
    'CRYPTAD_APP_NETWORK_BUDGET_TRUST_GRAPH_IMPORT_CONCURRENT_PER_APP': '1',
    'CRYPTAD_APP_NETWORK_BUDGET_TRUST_GRAPH_IMPORT_CONCURRENT_GLOBAL': '4',
    'CRYPTAD_APP_NETWORK_BUDGET_TRUST_GRAPH_IMPORT_PER_APP_PER_HOUR': '32',
    'CRYPTAD_APP_NETWORK_BUDGET_TRUST_GRAPH_IMPORT_GLOBAL_PER_HOUR': '64',
    'CRYPTAD_APP_NETWORK_BUDGET_SUBSCRIPTION_POLL_PER_APP_PER_HOUR': '48',
    'CRYPTAD_APP_NETWORK_BUDGET_SUBSCRIPTION_POLL_GLOBAL_PER_HOUR': '1024',
    'CRYPTAD_APP_NETWORK_BUDGET_SUBSCRIPTION_POLL_CONCURRENT_PER_APP': '1',
    'CRYPTAD_APP_NETWORK_BUDGET_SUBSCRIPTION_POLL_CONCURRENT_GLOBAL': '8',
}
NORMALIZED_CONFIGURATION = {
    'schedulerEnabled': False,
    'budgetConfiguration': {
        'foregroundContentFetchPerAppPerMinute': 32,
        'foregroundContentFetchGlobalPerMinute': 64,
        'foregroundContentFetchConcurrentPerApp': 2,
        'foregroundContentFetchConcurrentGlobal': 1,
        'subscriptionPollPerAppPerHour': 48,
        'subscriptionPollGlobalPerHour': 1024,
        'subscriptionPollConcurrentPerApp': 1,
        'subscriptionPollConcurrentGlobal': 8,
        'trustGraphImportPerAppPerHour': 32,
        'trustGraphImportGlobalPerHour': 64,
        'trustGraphImportConcurrentPerApp': 1,
        'trustGraphImportConcurrentGlobal': 4,
    },
}
FAILURE_POLICY = {
    'maximumSetupAttempts': 2,
    'requestDeadlineMillis': 45_000,
    'ownerAcknowledgmentDeadlineMillis': 45_000,
    'clientCleanupMillis': 5_000,
    'maximumConcurrentRequests': 3,
    'retainFailedAttempts': True,
    'unknownOwnerTermination': 'inconclusive',
    'collectionGap': 'fail-closed',
}
HOST_EVIDENCE_PATHS = {
    'installedRuntime': 'tools/interop/cross_version_runtime.py',
    'installedWorkload': 'tools/interop/cross_version_workload.py',
    'runtimePressureEvidence':
        'tools/release-certification/cryptad_certification/runtime_pressure_evidence.py',
    'runtimeBaseline': 'tools/perf/runtime_baseline.py',
    'interopSmoke': 'tools/interop/interop_smoke.py',
    'mailDemo': 'tools/mail-prototype/two_node_demo.py',
    'certificationPackage':
        'tools/release-certification/cryptad_certification/__init__.py',
    'certificationModels':
        'tools/release-certification/cryptad_certification/models.py',
}
TOOL_PATHS = {
    'installedDriver': 'tools/interop/cross_version_installed_budgets.py',
    'localBudgetAdapter': 'tools/interop/cross_version_app_budgets.py',
    'schedulerRuntime': 'tools/interop/scheduler_pressure_runtime.py',
    'evidenceOracle': 'tools/release-certification/cryptad_certification/composed_budget_evidence.py',
    'selection': 'tools/release-certification/restricted/pr317_budget_selection.py',
    'selectionContract': 'tools/release-certification/protected/pr317_budget_contract.py',
    'statementVerifier': 'platform-devtools/src/test/java/network/crypta/platform/devtools/fixtures/'
                         'Pr317SignedBudgetStatementVerifier.java',
    **HOST_EVIDENCE_PATHS,
}
# The protected side-effect-free contract is authoritative; local literals above remain readable
# fixture documentation and are checked by using these aliases everywhere below.
EXECUTION_CLASS, EXPERIMENT = contract.EXECUTION_CLASS, contract.EXPERIMENT
ROLES, APP_IDS, CASES = contract.ROLES, contract.APP_IDS, contract.CASES
PERMISSIONS, ENVIRONMENT = contract.PERMISSIONS, contract.ENVIRONMENT
NORMALIZED_CONFIGURATION = contract.NORMALIZED_CONFIGURATION
FAILURE_POLICY, TOOL_PATHS = contract.FAILURE_POLICY, contract.TOOL_PATHS
HOST_EVIDENCE_PATHS = contract.HOST_EVIDENCE_PATHS


def canonical_digest(value):
    return contract.canonical_digest(value)


def tool_identities(source):
    """Measure only the closed reviewed tool roster used by this execution class."""
    source = Path(source)
    values = {}
    for name, relative in TOOL_PATHS.items():
        path = source / relative
        if not path.is_file() or path.is_symlink():
            raise ValueError('pr317-budget-tool-unavailable')
        values[name] = runtime.digest_file(path)
    return values


def _property(text, name):
    values = re.findall(r'(?m)^' + re.escape(name) + r'\s*=\s*([^\r\n]*)\s*$', text)
    if len(values) != 1:
        raise ValueError('pr317-budget-app-manifest-invalid')
    return values[0]


def _verify_app(extracted, app_id):
    """Bind identity, permissions and the exact non-Java fixture process shape."""
    manifest = (Path(extracted) / 'cryptad-app.properties').read_text()
    permissions = tuple(value for value in _property(manifest, 'app.permissions').split(',') if value)
    if (_property(manifest, 'app.id') != app_id
            or _property(manifest, 'app.exec') != 'bin/start.sh'
            or permissions != PERMISSIONS[app_id]
            or _property(manifest, 'sandbox.mode') != 'restricted-process'
            or _property(manifest, 'sandbox.required') != 'true'
            or _property(manifest, 'api.targetStability') != 'experimental'
            or _property(manifest, 'api.experimentalCapabilitiesAccepted') != 'true'
            or (Path(extracted) / 'bin/start.sh').read_bytes()
                != b'#!/bin/sh\nset -eu\nexec sleep 600\n'):
        raise ValueError('pr317-budget-app-manifest-invalid')


def _verify_statement(path):
    raw = Path(path).read_bytes()
    if not 1 <= len(raw) <= 65536:
        raise ValueError('pr317-budget-statement-invalid')
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
        raise ValueError('pr317-budget-statement-invalid')


def _verify_statement_signature(root, source, selected):
    """Use the production Trust Graph parser and Ed25519 verifier on exact selected bytes."""
    from bounded_process import run
    root, source = Path(root), Path(source)
    product = selected['products']['candidate']
    with tempfile.TemporaryDirectory(
            prefix='pr317-statement-signature-', dir=root.parent) as temporary:
        stage = Path(temporary)
        package = runtime.extract_package(root / 'candidate.tar.gz', stage / 'package',
            product['artifactDigest'], product['artifactSize'])
        classes = stage / 'classes'
        classes.mkdir()
        java_home = root / 'jdk'
        classpath = (str(source / 'platform-devtools/build/install/crypta-app/lib/*')
                     + os.pathsep + str(package / 'lib/*'))
        source_file = source / TOOL_PATHS['statementVerifier']
        environment = {'PATH': str(java_home / 'bin') + ':/usr/bin:/bin',
                       'JAVA_HOME': str(java_home), 'LANG': 'C.UTF-8'}
        run([str(java_home / 'bin/javac'), '-cp', classpath, '-d', str(classes),
             str(source_file)], environment=environment, timeout=60, output_limit=65536)
        run([str(java_home / 'bin/java'), '-cp', str(classes) + os.pathsep + classpath,
             'network.crypta.platform.devtools.fixtures.Pr317SignedBudgetStatementVerifier',
             str(root / 'statement.json')], environment=environment,
            timeout=30, output_limit=4096)


def _verify_bundles(root, source, selected):
    """Run the normal signed-bundle verifier and then constrain the synthetic subjects."""
    tool = Path(source) / 'platform-devtools/build/install/crypta-app'
    from bounded_process import run
    with tempfile.TemporaryDirectory(prefix='pr317-budget-verify-', dir=Path(root).parent) as temporary:
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
            _verify_app(extracted, app_id)


def prepare(args):
    """Create a new PR-317 fixture root without changing PR-315 fixture bytes."""
    if (type(args.max_seconds) is not int or not 60 <= args.max_seconds <= 3600
            or type(args.max_operations) is not int or not 1 <= args.max_operations <= 10000
            or not re.fullmatch('[0-9a-f]{40}', args.candidate_commit)
            or not re.fullmatch('[0-9a-f]{40}', args.previous_commit)
            or args.candidate_commit == args.previous_commit):
        raise ValueError('pr317-budget-fixture-selection-invalid')
    if subprocess.check_output(['git', '-C', str(args.source), 'status', '--porcelain',
                                '--untracked-files=normal'], timeout=10):
        raise ValueError('pr317-budget-clean-helper-source-required')
    output = args.output.absolute()
    os.umask(0o077)
    output.mkdir(mode=0o700, exist_ok=False)
    metadata.stage_jdk(args.java_home, output / 'jdk', args.jdk_digest)
    if sum(path.stat().st_size for path in (output / 'jdk').rglob('*') if path.is_file()) > 512 * 1024**2:
        raise ValueError('pr317-budget-jdk-too-large')
    products = {}
    with tempfile.TemporaryDirectory(prefix='pr317-product-', dir=output.parent) as temporary:
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
                raise ValueError('pr317-budget-export-daemon-mismatch')
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
    _verify_bundles(output, args.source, selected)
    _verify_statement(output / 'statement.json')
    verifier = args.source / 'platform-devtools/build/install/crypta-app'
    value = {'schemaVersion': 1, 'kind': KIND, 'executionClass': EXECUTION_CLASS,
        'classification': CLASSIFICATION,
        'runtimePolicy': {'launcher': preparation.launcher_policy(),
                          'budget': preparation.budget_launcher_policy()},
        'sourceCommit': subprocess.check_output(
            ['git', '-C', str(args.source), 'rev-parse', 'HEAD'], text=True,
            timeout=10).strip(),
        'products': products, 'roles': list(ROLES),
        'runtimeDigest': runtime.tree_digest(output / 'jdk'),
        'jdkClosureDigest': args.jdk_digest, 'apps': apps,
        'trustDigest': runtime.digest_file(output / 'publisher-keys.properties'),
        'statementDigest': runtime.digest_file(output / 'statement.json'),
        'verifierDigest': runtime.tree_digest(verifier, require_java=False),
        'toolIdentities': tools, 'permissions': {key: list(value) for key, value in PERMISSIONS.items()},
        'caseIds': list(CASES), 'environment': dict(ENVIRONMENT),
        'normalizedConfiguration': NORMALIZED_CONFIGURATION,
        'failurePolicy': dict(FAILURE_POLICY), 'maxSeconds': args.max_seconds,
        'maxOperations': args.max_operations, 'members': base.inventory(output)}
    _verify_statement_signature(output, args.source, value)
    (output / MANIFEST).write_text(json.dumps(value, sort_keys=True) + '\n')
    return base.digest(output / MANIFEST)


def verify(root, expected_manifest_digest, source, product_source_commit):
    """Verify every prospective fixture, signer registry and current fixed tool byte."""
    root, source = Path(root), Path(source)
    path = root / MANIFEST
    if (expected_manifest_digest is None or product_source_commit is None
            or base.digest(path) != expected_manifest_digest):
        raise ValueError('pr317-budget-fixture-manifest-mismatch')
    from runtime_snapshot import read_file
    raw = read_file(root.absolute(), MANIFEST, maximum=8 * 1024**2, timeout=30)
    if hashlib.sha256(raw).hexdigest() != expected_manifest_digest:
        raise ValueError('pr317-budget-fixture-manifest-mismatch')
    value = metadata.read_json(raw)
    fields = {'schemaVersion', 'kind', 'executionClass', 'classification', 'runtimePolicy',
        'sourceCommit', 'products', 'roles', 'runtimeDigest', 'jdkClosureDigest', 'apps',
        'trustDigest', 'statementDigest', 'verifierDigest', 'toolIdentities', 'permissions',
        'caseIds', 'environment', 'normalizedConfiguration', 'failurePolicy',
        'maxSeconds', 'maxOperations', 'members'}
    if (set(value) != fields or value['schemaVersion'] != 1 or value['kind'] != KIND
            or value['executionClass'] != EXECUTION_CLASS
            or value['classification'] != CLASSIFICATION or value['roles'] != list(ROLES)
            or value['runtimePolicy'] != {
                'launcher': preparation.launcher_policy(),
                'budget': preparation.budget_launcher_policy()}
            or value['permissions'] != {key: list(entry) for key, entry in PERMISSIONS.items()}
            or value['caseIds'] != list(CASES) or value['environment'] != ENVIRONMENT
            or value['normalizedConfiguration'] != NORMALIZED_CONFIGURATION
            or value['failurePolicy'] != FAILURE_POLICY
            or type(value['maxSeconds']) is not int or not 60 <= value['maxSeconds'] <= 3600
            or type(value['maxOperations']) is not int or not 1 <= value['maxOperations'] <= 10000
            or value['members'] != base.inventory(root)):
        raise ValueError('pr317-budget-fixture-manifest-invalid')
    base.validate_roster(value['products'])
    commit = subprocess.check_output(['git', '-c', 'safe.directory=' + str(source), '-C',
        str(source), 'rev-parse', 'HEAD'], text=True, timeout=10).strip()
    if value['sourceCommit'] != commit or value['products']['candidate']['sourceCommit'] != product_source_commit:
        raise ValueError('pr317-budget-fixture-source-mismatch')
    for name, product in value['products'].items():
        measured = base.portable_daemon_identities(root / (name + '.tar.gz'),
            expected_digest=product['artifactDigest'], expected_size=product['artifactSize'])
        if (measured['daemonDigest'] != product['daemonDigest']
                or measured['daemonImplementationDigest'] != product['daemonImplementationDigest']):
            raise ValueError('pr317-budget-daemon-identity-mismatch')
    observed_apps = {app_id: runtime.digest_file(root / (app_id + '.zip'))
                     for app_id in APP_IDS}
    if (set(value['apps']) != set(APP_IDS) or value['apps'] != observed_apps
            or runtime.tree_digest(root / 'jdk') != value['runtimeDigest']
            or runtime.digest_file(root / 'publisher-keys.properties') != value['trustDigest']
            or runtime.digest_file(root / 'statement.json') != value['statementDigest']
            or runtime.tree_digest(source / 'platform-devtools/build/install/crypta-app',
                                   require_java=False) != value['verifierDigest']
            or tool_identities(source) != value['toolIdentities']):
        raise ValueError('pr317-budget-runtime-or-app-mismatch')
    _verify_bundles(root, source, value)
    _verify_statement(root / 'statement.json')
    _verify_statement_signature(root, source, value)
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
        'statementDigest': selected['statementDigest'], 'environment': dict(ENVIRONMENT),
        'normalizedConfiguration': NORMALIZED_CONFIGURATION,
        'failurePolicy': dict(FAILURE_POLICY), 'toolIdentities': dict(tools),
        'composedBudgetInputs': dict(composed),
        'privateRootClass': 'controller-derived-' + EXPERIMENT}


def materialize_selection(root, source, expected_manifest_digest=None,
                          product_source_commit=None):
    """Create the exact four-role PR-317 selection before any controller mutation."""
    root, source = Path(root), Path(source)
    if root != FIXED_GUEST_ROOT or os.geteuid() != 0:
        raise ValueError('pr317-budget-fixed-guest-root-required')
    selected = verify(root, expected_manifest_digest, source, product_source_commit)
    private = {'root': '/var/lib/cryptad-cross-version/experiments/' + EXPERIMENT,
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
                role, trust_digest, EXECUTION_CLASS),
            appDigests=[app['bundleDigest'] for app in apps])
        nodes.append(node)
    workload_digest = selected['toolIdentities']['installedDriver']
    collector_digest = canonical_digest({key: selected['toolIdentities'][key] for key in
        ('installedDriver', 'localBudgetAdapter', 'schedulerRuntime', 'evidenceOracle')})
    configuration_digest = canonical_digest({
        'nodeConfigDigest': nodes[0]['configDigest'], 'environment': ENVIRONMENT,
        'normalizedConfiguration': NORMALIZED_CONFIGURATION})
    plan = {'schemaVersion': 1, 'kind': evidence.KIND, 'experimentId': EXPERIMENT,
        'profile': 'bounded-live', 'topologyClass': 'single-host-independent-processes',
        'provenanceClass': 'source-build-comparison',
        'requestedSeconds': selected['maxSeconds'], 'probeIntervalSeconds': 1,
        'policy': {'id': 'cross-version-observed-v1', 'minimumObservedSeconds': 0,
                   'maxGapSeconds': 600, 'maxEvents': 10000},
        'requiredScenarios': sorted(evidence.SCENARIOS), 'producer': runtime.runner_identity(),
        'nodes': nodes, 'workloadInputs': {'scheduler': workload_digest},
        'composedBudgetInputs': {'collectorDigest': collector_digest,
                                 'configurationDigest': configuration_digest}}
    evidence.validate_plan(plan)
    budget_selection = _budget_selection(selected, plan, private)
    authorization = {'syntheticContent': True, 'executionClass': EXECUTION_CLASS,
        'experimentId': EXPERIMENT, 'root': private['root'],
        'planDigest': runtime.canonical_digest(plan), 'maxSeconds': selected['maxSeconds'],
        'maxOperations': selected['maxOperations'], 'budgetSelection': budget_selection}
    authorization['selectionDigest'] = runtime.canonical_digest({
        'executionClass': EXECUTION_CLASS, 'planDigest': authorization['planDigest'],
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
    args = parser.parse_args()
    try:
        digest = prepare(args)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        print(json.dumps({'status': 'pr317-fixture-preparation-failed',
                          'installedPositiveExecuted': False}))
        return 2
    print(json.dumps({'status': 'pr317-fixtures-prepared', 'manifestDigest': digest,
                      'installedPositiveExecuted': False}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

"""Side-effect-free closed selection contract for the PR-319 protected boundary."""
from __future__ import annotations

import hashlib
import json
import re


EXECUTION_CLASS = 'pr319-composed-budget-restart-diagnostics-v1'
EXPERIMENT = 'pr319-composed-budget-restart-diagnostics'
ROLES = ('candidate-sender', 'candidate-recipient', 'previous', 'relay-no-apps')
APP_IDS = ('feed-reader', 'budget-importer', 'budget-no-trust', 'budget-no-fetch')
CASES = ('graceful-restart', 'abrupt-restart', 'diagnostics-unavailable')
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
NORMALIZED_CONFIGURATION = {'schedulerEnabled': False, 'budgetConfiguration': {
    'foregroundContentFetchPerAppPerMinute': 32,
    'foregroundContentFetchGlobalPerMinute': 64,
    'foregroundContentFetchConcurrentPerApp': 2,
    'foregroundContentFetchConcurrentGlobal': 1,
    'subscriptionPollPerAppPerHour': 48, 'subscriptionPollGlobalPerHour': 1024,
    'subscriptionPollConcurrentPerApp': 1, 'subscriptionPollConcurrentGlobal': 8,
    'trustGraphImportPerAppPerHour': 32, 'trustGraphImportGlobalPerHour': 64,
    'trustGraphImportConcurrentPerApp': 1, 'trustGraphImportConcurrentGlobal': 4}}
FAILURE_POLICY = {'maximumSetupAttempts': 2, 'requestDeadlineMillis': 45_000,
    'ownerAcknowledgmentDeadlineMillis': 45_000, 'maximumConcurrentRequests': 3,
    'clientCleanupMillis': 5_000,
    'retainFailedAttempts': True, 'unknownOwnerTermination': 'inconclusive',
    'collectionGap': 'fail-closed'}
# Conservative allocation for the complete fixed lane, including app requests made by
# spawned clients. Additional provider-readiness retries still use the caller's finite cap.
MIN_OPERATIONS = (
    # ClientHello/GetNode, two setup attempts for four initial starts and three restarts.
    2 * FAILURE_POLICY['maximumSetupAttempts'] * (len(ROLES) + 3)
    # Three peer pairs: two handshakes/adds and two ListPeers per 2s poll over 150s.
    + (len(ROLES) - 1) * (4 + 2 * 75)
    # Host bootstrap, contract/inventory, install/start for each app, controller bootstrap.
    + 3 + 2 * len(APP_IDS) + 1
    # Initial sample, two seeds, exhaustion, two key generations/one publish, subscription.
    + 1 + 2 + NORMALIZED_CONFIGURATION['budgetConfiguration']['trustGraphImportPerAppPerHour']
    + 3 * 3 + 2
    # Three restart samples/checks/rebootstraps, graceful FCP shutdown, in-flight setup sample.
    + 3 * (3 + 2 + 2 + 2 * len(APP_IDS)) + 2 + 1
    # Two diagnostics variants: five samples (including invalid resampling), two requests.
    + 2 * (5 + 2)
    # Interrupted URI request and native snapshots every 50ms for the fixed eight-second wait.
    + 1 + 160
    # Final native sample.
    + 1
)


def valid_operation_budget(value):
    """Reject allocations below the fixed lane's conservative request/poll allowance."""
    return type(value) is int and MIN_OPERATIONS <= value <= 10000


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
    'storageAdapter': 'tools/interop/cross_version_installed_storage_budgets.py',
    'storageOracle': 'tools/release-certification/cryptad_certification/composed_budget_storage_evidence.py',
    'transitionDispatch': 'tools/release-certification/restricted/pr319_installed_dispatch.py',
    'hostRunner': 'tools/release-certification/restricted/pr319_restart_runtime_runner.py',
    'restartOracle': 'tools/release-certification/cryptad_certification/composed_budget_restart_evidence.py',
    'runtimeEvidence': 'tools/release-certification/restricted/pr319_restart_runtime_evidence.py',
    'administrator': 'tools/release-certification/restricted/pr319_restart_admin.py',
    'roleClients': 'tools/interop/cross_version_installed_budgets.py',
    'installedDriver': 'tools/interop/cross_version_installed_restart_budgets.py',
    'localBudgetAdapter': 'tools/interop/cross_version_app_budgets.py',
    'schedulerRuntime': 'tools/interop/scheduler_pressure_runtime.py',
    'evidenceOracle': 'tools/release-certification/cryptad_certification/composed_budget_evidence.py',
    'selection': 'tools/release-certification/restricted/pr319_restart_selection.py',
    'selectionContract': 'tools/release-certification/protected/pr319_restart_contract.py',
    'statementVerifier': 'platform-devtools/src/test/java/network/crypta/platform/devtools/fixtures/'
                         'Pr317SignedBudgetStatementVerifier.java',
    **HOST_EVIDENCE_PATHS,
}


def canonical_digest(value):
    return 'sha256:' + hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def verify_selection_contract(plan, private, authorization):
    """Validate the full class member without importing a runner or mutating state."""
    try:
        if (authorization.get('executionClass') != EXECUTION_CLASS
                or not valid_operation_budget(authorization.get('maxOperations'))
                or plan.get('experimentId') != EXPERIMENT
                or private.get('root') != '/var/lib/cryptad-cross-version/experiments/' + EXPERIMENT
                or authorization.get('experimentId') != EXPERIMENT
                or authorization.get('root') != private.get('root')):
            return False
        budget = authorization.get('budgetSelection')
        if not isinstance(budget, dict) or set(budget) != {
                'schemaVersion', 'caseIds', 'appRoster', 'permissions', 'appBundleDigests',
                'trustedKeysDigest', 'statementDigest', 'statementFingerprint',
                'environment', 'failurePolicy',
                'normalizedConfiguration', 'toolIdentities', 'composedBudgetInputs',
                'privateRootClass', 'timePlan'}:
            return False
        roster = {'candidate-sender': list(APP_IDS), 'candidate-recipient': [],
                  'previous': [], 'relay-no-apps': []}
        apps = private['nodes']['candidate-sender']['apps']
        bundles = {row['appId']: row['bundleDigest'] for row in apps}
        nodes = plan['nodes']
        expected_app_digests = {
            'candidate-sender': [bundles[app_id] for app_id in APP_IDS],
            'candidate-recipient': [], 'previous': [], 'relay-no-apps': []}
        tools = budget['toolIdentities']
        composed = plan.get('composedBudgetInputs')
        expected_collector = canonical_digest({key: tools[key] for key in
            ('installedDriver', 'localBudgetAdapter', 'schedulerRuntime', 'evidenceOracle',
             'restartOracle', 'administrator', 'roleClients', 'runtimeEvidence',
             'storageAdapter', 'storageOracle', 'transitionDispatch', 'hostRunner')})
        expected_configuration = canonical_digest({
            'nodeConfigDigest': plan['nodes'][0]['configDigest'], 'environment': ENVIRONMENT,
            'normalizedConfiguration': NORMALIZED_CONFIGURATION})
        return (budget['schemaVersion'] == 1 and valid_time_plan(budget['timePlan']) and budget['caseIds'] == list(CASES)
            and authorization.get('planDigest') == canonical_digest(plan)
            and budget['appRoster'] == roster
            and budget['permissions'] == {key: list(value) for key, value in PERMISSIONS.items()}
            and [row['appId'] for row in apps] == list(APP_IDS)
            and bundles == budget['appBundleDigests'] and set(bundles) == set(APP_IDS)
            and [row['role'] for row in nodes] == list(ROLES)
            and {row['role']: row['appDigests'] for row in nodes} == expected_app_digests
            and all(private['nodes'][role]['apps'] == [] for role in ROLES[1:])
            and budget['trustedKeysDigest'] == private['nodes']['candidate-sender']['trustedKeysDigest']
            and budget['statementDigest'] == private['nodes']['candidate-sender'].get(
                'budgetStatementDigest')
            and re.fullmatch(r'sha256:[0-9a-f]{64}', str(budget['statementDigest'])) is not None
            and re.fullmatch(r'[0-9a-f]{64}', str(budget['statementFingerprint'])) is not None
            and budget['environment'] == ENVIRONMENT and budget['failurePolicy'] == FAILURE_POLICY
            and budget['normalizedConfiguration'] == NORMALIZED_CONFIGURATION
            and set(tools) == set(TOOL_PATHS)
            and all(re.fullmatch(r'sha256:[0-9a-f]{64}', str(value)) for value in tools.values())
            and budget['privateRootClass'] == 'controller-derived-' + EXPERIMENT
            and composed == budget['composedBudgetInputs']
            and composed == {'collectorDigest': expected_collector,
                             'configurationDigest': expected_configuration}
            and plan.get('workloadInputs') == {'scheduler': tools['installedDriver']}
            and authorization.get('selectionDigest') == canonical_digest({
                'executionClass': EXECUTION_CLASS,
                'planDigest': authorization.get('planDigest'),
                'budgetSelection': budget}))
    except (KeyError, TypeError, ValueError):
        return False


def valid_time_plan(value):
    """One immutable UTC hour ending at the selected boundary; launch must fit its original deadline."""
    return (isinstance(value, dict) and set(value) == {"boundaryEpochSecond",
        "selectedAtEpochSecond", "startMarginSeconds", "requestDeadlineMillis"}
        and type(value["boundaryEpochSecond"]) is int
        and type(value["selectedAtEpochSecond"]) is int
        and value["boundaryEpochSecond"] % 3600 == 0
        and value["startMarginSeconds"] == 10
        and 60 + value["startMarginSeconds"] <= value["boundaryEpochSecond"] - value["selectedAtEpochSecond"] <= 3600
        and value["requestDeadlineMillis"] == 45000)

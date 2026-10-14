"""Seven finite successor route profiles; historical v1-v5 evidence remains unchanged."""
from __future__ import annotations
import copy
import pr318_storage_contract as historical
from pr320_budget_contract import APPROVED_PERMISSIONS, APP_IDS, ROLES, PROCESS_CLIENT_PATH

MAIN_CASES = tuple(('direct-valid direct-malformed pasted-preview-valid uri-preview-valid '
    'uri-preview-malformed uri-valid uri-malformed uri-fingerprint-mismatch uri-duplicate '
    'authorization-denied invalid-uri invalid-utf8 oversized').split())
INTERFERENCE_CASES = ('app-import-rate', 'global-import-rate', 'app-fetch-rate',
                      'global-fetch-rate', 'shared-foreground', 'shared-subscription')
NAMES = ('main', 'interference', 'import-app', 'import-global', 'fetch-app', 'fetch-global', 'lifecycle')
EXECUTION_CLASSES = tuple('pr320-routes-' + name + '-v1' for name in NAMES)
PERMISSIONS = APPROVED_PERMISSIONS
FAILURE_POLICY = historical.FAILURE_POLICY
canonical_digest = historical.canonical_digest
PRIVATE_FILE = 'pr320-route-budget.private.json'
CHECKPOINT_FILE = 'pr320-route-attempts.private.jsonl'
TOOL_PATHS = {**historical.TOOL_PATHS,
    'installedDriver': 'tools/interop/cross_version_installed_route_budgets.py',
    'roleClients': 'tools/interop/cross_version_installed_budgets.py',
    'administrator': 'tools/release-certification/restricted/pr320_route_admin.py',
    'runtimeEvidence': 'tools/release-certification/restricted/pr320_route_runtime_evidence.py',
    'routeOracle': 'tools/release-certification/cryptad_certification/composed_budget_route_evidence.py',
    'selection': 'tools/release-certification/restricted/pr320_route_selection.py',
    'selectionContract': 'tools/release-certification/protected/pr320_route_contract.py',
    'hostRunner': 'tools/release-certification/restricted/pr320_route_runtime_runner.py',
    'prospectiveCohort': 'tools/release-certification/protected/pr320_budget_contract.py',
    'prospectiveFixture': 'tools/release-certification/restricted/pr320_storage_selection.py',
    'historicalSelection': 'tools/release-certification/restricted/pr318_storage_selection.py',
    'historicalContract': 'tools/release-certification/protected/pr318_storage_contract.py',
    'historicalHostRunner': 'tools/release-certification/restricted/pr318_storage_runtime_runner.py',
    'historicalReadback': 'tools/release-certification/restricted/pr319_restart_admin.py',
    'processClient': PROCESS_CLIENT_PATH,
    'stdioCapture': 'tools/release-certification/protected/pr320_stdio_capture.py',
    'campaignCapture': 'tools/release-certification/restricted/pr320_campaign_capture.py',
    'campaignJournal': 'tools/release-certification/cryptad_certification/composed_budget_journal_member.py',
    'finiteDispatch': 'tools/release-certification/restricted/pr320_installed_dispatch.py'}


def profile(name):
    if name not in NAMES:
        raise ValueError('pr320-route-profile-invalid')
    environment = dict(historical.ENVIRONMENT)
    normalized = copy.deepcopy(historical.NORMALIZED_CONFIGURATION)
    def quota(field, value):
        normalized['budgetConfiguration'][field] = value
        words = {'foregroundContentFetch': 'FOREGROUND_CONTENT_FETCH',
                 'trustGraphImport': 'TRUST_GRAPH_IMPORT'}
        suffixes = {'ConcurrentPerApp': 'CONCURRENT_PER_APP', 'ConcurrentGlobal': 'CONCURRENT_GLOBAL',
                    'PerAppPerMinute': 'PER_APP_PER_MINUTE', 'GlobalPerMinute': 'GLOBAL_PER_MINUTE',
                    'PerAppPerHour': 'PER_APP_PER_HOUR', 'GlobalPerHour': 'GLOBAL_PER_HOUR'}
        for prefix, encoded in words.items():
            if field.startswith(prefix):
                environment['CRYPTAD_APP_NETWORK_BUDGET_' + encoded + '_' + suffixes[field[len(prefix):]]] = str(value)
                return
        raise ValueError('pr320-route-quota-invalid')
    if name in {'main', 'interference'}:
        quota('foregroundContentFetchConcurrentGlobal', 8)
        quota('trustGraphImportConcurrentPerApp', 2)
        quota('trustGraphImportConcurrentGlobal', 8)
    if name == 'interference':
        quota('foregroundContentFetchPerAppPerMinute', 3)
        quota('foregroundContentFetchGlobalPerMinute', 5)
        quota('trustGraphImportPerAppPerHour', 4)
        quota('trustGraphImportGlobalPerHour', 6)
    elif name == 'import-global':
        quota('foregroundContentFetchConcurrentGlobal', 8)
        quota('trustGraphImportConcurrentPerApp', 2)
        quota('trustGraphImportConcurrentGlobal', 1)
    elif name == 'import-app':
        quota('foregroundContentFetchConcurrentGlobal', 8)
    elif name == 'fetch-app':
        quota('foregroundContentFetchConcurrentPerApp', 1)
        quota('foregroundContentFetchConcurrentGlobal', 8)
        quota('trustGraphImportConcurrentPerApp', 2)
    cases = (MAIN_CASES if name == 'main' else INTERFERENCE_CASES if name == 'interference'
             else ('timeout', 'retry') if name == 'lifecycle'
             else ('import-concurrency' if name.startswith('import') else 'fetch-concurrency',))
    variants = []
    for case in cases:
        selected = ('no-trust', 'no-fetch') if case == 'authorization-denied' else (
            (name.rsplit('-', 1)[1],) if case.endswith('concurrency') else
            ('deferred-normal-owner',) if case == 'timeout' else ('independently-charged',) if case == 'retry'
            else ('native-route',))
        variants.extend({'caseId': case, 'variant': variant} for variant in selected)
    return {'executionClass': 'pr320-routes-' + name + '-v1',
        'experiment': 'pr320-routes-' + name, 'name': name, 'cases': cases, 'variants': variants,
        'environment': environment, 'normalizedConfiguration': normalized,
        'permissions': dict(PERMISSIONS), 'toolPaths': dict(TOOL_PATHS)}


def selected_profile(execution_class):
    for name in NAMES:
        selected = profile(name)
        if selected['executionClass'] == execution_class:
            return selected
    raise ValueError('pr320-route-class-invalid')


def verify_selection_contract(plan, private, authorization):
    try:
        selected = selected_profile(authorization.get('executionClass'))
        from cryptad_certification.composed_budget_journal_member import validate_selected_sources
        validate_selected_sources(plan, authorization['budgetSelection']['toolIdentities'])
        return (canonical_digest(authorization.get('budgetSelection', {}).get('normalizedConfiguration'))
            == canonical_digest(selected['normalizedConfiguration'])
            and type(authorization.get('maxOperations')) is int and 1000 <= authorization['maxOperations'] <= 10000
            and type(authorization.get('maxSeconds')) is int and 60 <= authorization['maxSeconds'] <= 3600
            and authorization['maxSeconds'] == plan.get('requestedSeconds')
            and historical.verify_profile_selection(plan, private, authorization,
                selected))
    except (ValueError, KeyError, TypeError):
        return False

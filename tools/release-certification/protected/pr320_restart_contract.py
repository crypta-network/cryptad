"""Fixed prospective same-cohort wrapper; the v5 restart oracle is unchanged."""
from __future__ import annotations
import copy
import pr318_storage_contract as bindings
import pr319_restart_contract as historical
from pr320_budget_contract import APPROVED_PERMISSIONS, PROCESS_CLIENT_PATH, RESTART_EXECUTION_CLASS

EXECUTION_CLASS = RESTART_EXECUTION_CLASS
EXPERIMENT = 'pr320-installed-restart-diagnostics'
CASES = historical.CASES
PERMISSIONS = APPROVED_PERMISSIONS
APP_IDS, ROLES = historical.APP_IDS, historical.ROLES
ENVIRONMENT, NORMALIZED_CONFIGURATION = historical.ENVIRONMENT, historical.NORMALIZED_CONFIGURATION
canonical_digest = historical.canonical_digest
COLLECTOR_TOOLS = ('installedDriver', 'localBudgetAdapter', 'schedulerRuntime', 'evidenceOracle',
    'restartOracle', 'administrator', 'roleClients', 'runtimeEvidence', 'storageAdapter',
    'storageOracle', 'transitionDispatch', 'hostRunner')
TOOL_PATHS = {**historical.TOOL_PATHS,
    'campaignJournal': 'tools/release-certification/cryptad_certification/composed_budget_journal_member.py',
    'campaignCapture': 'tools/release-certification/restricted/pr320_campaign_capture.py',
    'installedDriver': 'tools/interop/cross_version_installed_pr320_restart_budgets.py',
    'selection': 'tools/release-certification/restricted/pr320_restart_selection.py',
    'selectionContract': 'tools/release-certification/protected/pr320_restart_contract.py',
    'administrator': 'tools/release-certification/restricted/pr320_restart_admin.py',
    'runtimeEvidence': 'tools/release-certification/restricted/pr320_restart_runtime_evidence.py',
    'hostRunner': 'tools/release-certification/restricted/pr320_restart_runtime_runner.py',
    'historicalDriver': historical.TOOL_PATHS['installedDriver'],
    'historicalAdministrator': historical.TOOL_PATHS['administrator'],
    'historicalRuntimeEvidence': historical.TOOL_PATHS['runtimeEvidence'],
    'historicalHostRunner': historical.TOOL_PATHS['hostRunner'],
    'historicalSelection': 'tools/release-certification/restricted/pr318_storage_selection.py',
    'prospectiveFixture': 'tools/release-certification/restricted/pr320_storage_selection.py',
    'prospectiveCohort': 'tools/release-certification/protected/pr320_budget_contract.py',
    'processClient': PROCESS_CLIENT_PATH,
    'stdioCapture': 'tools/release-certification/protected/pr320_stdio_capture.py',
    'finiteDispatch': 'tools/release-certification/restricted/pr320_installed_dispatch.py',
}


def profile():
    return dict(executionClass=EXECUTION_CLASS, experiment=EXPERIMENT, cases=CASES,
        environment=dict(ENVIRONMENT), normalizedConfiguration=copy.deepcopy(NORMALIZED_CONFIGURATION),
        permissions=dict(PERMISSIONS), toolPaths=dict(TOOL_PATHS), collectorTools=COLLECTOR_TOOLS)


def verify_selection_contract(plan, private, authorization):
    return (historical.valid_operation_budget(authorization.get('maxOperations'))
        and type(authorization.get('maxSeconds')) is int and 60 <= authorization['maxSeconds'] <= 3600
        and authorization['maxSeconds'] == plan.get('requestedSeconds')
        and bindings.verify_profile_selection(plan, private, authorization, profile()))

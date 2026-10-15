"""Prospective process-owned cancellation; historical PR-317 remains unchanged."""
from __future__ import annotations
import copy
import pr318_storage_contract as historical
from pr320_budget_contract import APPROVED_PERMISSIONS, PROCESS_CLIENT_PATH, CANCELLATION_EXECUTION_CLASS

EXECUTION_CLASS = CANCELLATION_EXECUTION_CLASS
EXPERIMENT = 'pr320-installed-owner-cancellation'
CASES = ('cancellation',)
PERMISSIONS = APPROVED_PERMISSIONS
ENVIRONMENT = historical.ENVIRONMENT
NORMALIZED_CONFIGURATION = historical.NORMALIZED_CONFIGURATION
canonical_digest = historical.canonical_digest
TOOL_PATHS = {**historical.TOOL_PATHS,
    'campaignJournal': 'tools/release-certification/cryptad_certification/composed_budget_journal_member.py',
    'campaignCapture': 'tools/release-certification/restricted/pr320_campaign_capture.py',
    'installedDriver': 'tools/interop/cross_version_installed_owner_budgets.py',
    'administrator': 'tools/release-certification/restricted/pr320_owner_admin.py',
    'runtimeEvidence': 'tools/release-certification/restricted/pr320_owner_runtime_evidence.py',
    'selection': 'tools/release-certification/restricted/pr320_owner_selection.py',
    'selectionContract': 'tools/release-certification/protected/pr320_cancellation_contract.py',
    'cohortContract': 'tools/release-certification/protected/pr320_budget_contract.py',
    'processClient': PROCESS_CLIENT_PATH,
    'stdioCapture': 'tools/release-certification/protected/pr320_stdio_capture.py',
    'hostRunner': 'tools/release-certification/restricted/pr320_owner_runtime_runner.py',
    'finiteDispatch': 'tools/release-certification/restricted/pr320_installed_dispatch.py',
    'historicalSelection': 'tools/release-certification/restricted/pr318_storage_selection.py',
    'prospectiveFixture': 'tools/release-certification/restricted/pr320_storage_selection.py',
    'historicalHostRunner': 'tools/release-certification/restricted/pr318_storage_runtime_runner.py',
    'historicalStoreReader': 'tools/release-certification/restricted/pr319_restart_admin.py',
}


def profile():
    return {'executionClass': EXECUTION_CLASS, 'experiment': EXPERIMENT, 'cases': CASES,
        'environment': dict(ENVIRONMENT), 'normalizedConfiguration': copy.deepcopy(NORMALIZED_CONFIGURATION),
        'permissions': dict(PERMISSIONS), 'toolPaths': dict(TOOL_PATHS)}


def verify_selection_contract(plan, private, authorization):
    return (type(authorization.get('maxOperations')) is int and 1000 <= authorization['maxOperations'] <= 10000
            and type(authorization.get('maxSeconds')) is int and 60 <= authorization['maxSeconds'] <= 3600
            and authorization['maxSeconds'] == plan.get('requestedSeconds')
            and historical.verify_profile_selection(plan, private, authorization, profile()))

"""Finite native privacy profile and exact source closure; no execution authority is granted."""
from __future__ import annotations
import copy
import re
import pr318_storage_contract as historical
from pr320_budget_contract import ROLES, APP_IDS, APPROVED_PERMISSIONS

EXECUTION_CLASS = 'pr320-installed-budget-privacy-v1'
EXPERIMENT = 'pr320-installed-budget-privacy'
CASES = ('privacy',)
PERMISSIONS = APPROVED_PERMISSIONS
FAILURE_POLICY = historical.FAILURE_POLICY
ENVIRONMENT = historical.ENVIRONMENT
NORMALIZED_CONFIGURATION = historical.NORMALIZED_CONFIGURATION
canonical_digest = historical.canonical_digest
PRIVATE_FILE = 'pr320-privacy-native.private.json'
CHECKPOINT_FILE = 'pr320-privacy-checkpoints.private.jsonl'
TOOL_PATHS = {
    **historical.TOOL_PATHS,
    'installedDriver': 'tools/interop/cross_version_installed_privacy_budgets.py',
    'privacyOracle': 'tools/release-certification/cryptad_certification/composed_budget_privacy_evidence.py',
    'administrator': 'tools/release-certification/restricted/pr320_privacy_admin.py',
    'runtimeEvidence': 'tools/release-certification/restricted/pr320_privacy_runtime_evidence.py',
    'selection': 'tools/release-certification/restricted/pr320_privacy_selection.py',
    'selectionContract': 'tools/release-certification/protected/pr320_privacy_contract.py',
    'cohortContract': 'tools/release-certification/protected/pr320_budget_contract.py',
    'hostRunner': 'tools/release-certification/restricted/pr320_privacy_runtime_runner.py',
    'historicalSelection': 'tools/release-certification/restricted/pr318_storage_selection.py',
    'historicalContract': 'tools/release-certification/protected/pr318_storage_contract.py',
    'historicalAdministrator': 'tools/release-certification/restricted/pr319_restart_admin.py',
    'historicalHostRunner': 'tools/release-certification/restricted/pr318_storage_runtime_runner.py',
    'finiteDispatch': 'tools/release-certification/restricted/pr320_installed_dispatch.py',
    'processClient': 'tools/release-certification/restricted/pr320_budget_process_client.py',
    'stdioCapture': 'tools/release-certification/protected/pr320_stdio_capture.py',
    'browserAdministrator': 'tools/release-certification/restricted/pr320_privacy_browser_admin.py',
    'browserCollector': 'tools/interop/pr320_installed_privacy_browser.cjs',
    'webShellScript': 'platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js',
    'artifactProducer': 'tools/release-certification/restricted/pr320_privacy_artifact_producer.py',
    'artifactCapture': 'tools/release-certification/cryptad_certification/composed_budget_artifact_capture.py',
    'certificationEnvelope': 'tools/release-certification/cryptad_certification/envelope.py',
    'certificationIo': 'tools/release-certification/cryptad_certification/io.py',
    'certificationRedaction': 'tools/release-certification/cryptad_certification/redaction.py',
    'campaignCapture': 'tools/release-certification/restricted/pr320_campaign_capture.py',
    'campaignOriginalConsumer': 'tools/release-certification/protected/composed_budget_campaign_admission.py',
    'campaignJournal': 'tools/release-certification/cryptad_certification/composed_budget_journal_member.py',
    'historicalStorageAdministrator': 'tools/release-certification/restricted/pr318_storage_admin.py',
    'privacyController': 'tools/release-certification/protected/restricted_workload_controller.py',
    'privacyProcessBinder': 'tools/release-certification/protected/restricted_workload_app.py',
    'nativeCleanupConsumer': 'tools/release-certification/restricted/pr316_mail_runtime_runner.py',
    'browserProcessBudget': 'tools/release-certification/protected/bounded_process.py',
    'snapshotDescriptorReaders': 'tools/interop/runtime_snapshot.py',
    'publicDescriptorReaders': 'tools/release-certification/cryptad_certification/certification_public_export.py',
}


def profile():
    return {'executionClass': EXECUTION_CLASS, 'experiment': EXPERIMENT, 'cases': CASES,
        'environment': dict(ENVIRONMENT), 'normalizedConfiguration': copy.deepcopy(NORMALIZED_CONFIGURATION),
        'permissions': dict(PERMISSIONS), 'toolPaths': dict(TOOL_PATHS)}


def verify_selection_contract(plan, private, authorization):
    try:
        provider = authorization['browserProvider']
        if not valid_browser_provider(provider):
            return False
        from cryptad_certification.composed_budget_journal_member import validate_selected_sources
        validate_selected_sources(plan, authorization['budgetSelection']['toolIdentities'])
        # The old structural validator retains its exact digest contract. The new
        # owner verifies its additional provider binding against the original below.
        old_configuration = configuration_digest(plan, provider=None)
        structural_inputs = dict(plan['composedBudgetInputs'], configurationDigest=old_configuration)
        structural_plan = dict(plan, composedBudgetInputs=structural_inputs)
        structural_budget = dict(authorization['budgetSelection'], composedBudgetInputs=structural_inputs)
        from cryptad_certification.composed_budget_journal_member import campaign_inputs
        structural_plan['budgetCampaignInputs'] = campaign_inputs(structural_plan, structural_budget['toolIdentities'])
        structural_digest = canonical_digest(structural_plan)
        structural = dict(authorization, budgetSelection=structural_budget, planDigest=structural_digest,
            selectionDigest=historical.canonical_digest({
            'executionClass': EXECUTION_CLASS, 'planDigest': structural_digest,
            'budgetSelection': structural_budget}))
        return (type(authorization.get('maxOperations')) is int and 1000 <= authorization['maxOperations'] <= 10000
                and type(authorization.get('maxSeconds')) is int and 60 <= authorization['maxSeconds'] <= 7200
                and authorization['maxSeconds'] == plan.get('requestedSeconds')
                and authorization.get('planDigest') == canonical_digest(plan)
                and plan['composedBudgetInputs']['configurationDigest'] == configuration_digest(plan, provider)
                and authorization['budgetSelection']['composedBudgetInputs'] == plan['composedBudgetInputs']
                and historical.verify_profile_selection(structural_plan, private, structural, profile())
                and authorization['selectionDigest'] == selection_digest(authorization))
    except (KeyError, TypeError, ValueError):
        return False


def valid_browser_provider(value):
    return (isinstance(value, dict) and set(value) == {'schemaVersion', 'kind', 'nodeDigest',
        'chromiumDigest', 'packageDigest'} and type(value['schemaVersion']) is int
        and value['schemaVersion'] == 1 and value['kind'] == 'pr320-qualified-browser-provider'
        and all(isinstance(value[key], str) and re.fullmatch('sha256:[0-9a-f]{64}', value[key])
                for key in ('nodeDigest', 'chromiumDigest', 'packageDigest')))


def selection_digest(authorization):
    return canonical_digest({'executionClass': EXECUTION_CLASS, 'planDigest': authorization['planDigest'],
        'budgetSelection': authorization['budgetSelection'], 'browserProvider': authorization['browserProvider']})


def configuration_digest(plan, provider):
    value = {'nodeConfigDigest': plan['nodes'][0]['configDigest'], 'environment': ENVIRONMENT,
             'normalizedConfiguration': NORMALIZED_CONFIGURATION}
    if provider is not None:
        value['browserProvider'] = provider
    return canonical_digest(value)

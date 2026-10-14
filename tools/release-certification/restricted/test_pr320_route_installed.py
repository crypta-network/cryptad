"""Prospective route selection and original-controller regressions; no installed run claimed."""
import copy
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import cross_version_installed_route_budgets as driver
import cross_version_installed_budgets as lifecycle
import pr318_storage_contract as historical
import pr320_route_contract as contract
import pr320_route_runtime_evidence as evidence
import pr320_route_runtime_runner as runner
from cryptad_certification import composed_budget_route_evidence as routes
from cryptad_certification.tests.test_composed_budget_routes import native_component
from test_pr318_storage_installed import host_selection, resign


def selected(name):
    value, fixture=host_selection()
    profile=contract.profile(name)
    plan,private,authorization=value['plan'],value['private'],value['authorization']
    plan['experimentId']=profile['experiment'];private['root']='/var/lib/cryptad-cross-version/experiments/'+profile['experiment']
    authorization.update(executionClass=profile['executionClass'],experimentId=profile['experiment'],root=private['root'])
    tools={key:'sha256:'+'d'*64 for key in contract.TOOL_PATHS}
    budget=authorization['budgetSelection']
    budget.update(caseIds=list(profile['cases']),environment=profile['environment'],normalizedConfiguration=profile['normalizedConfiguration'],toolIdentities=tools,
        permissions={app:list(perms) for app,perms in contract.PERMISSIONS.items()},privateRootClass='controller-derived-'+profile['experiment'])
    plan['workloadInputs']={'scheduler':tools['installedDriver']}
    plan['composedBudgetInputs']={'collectorDigest':contract.canonical_digest({key:tools[key] for key in
        ('installedDriver','localBudgetAdapter','schedulerRuntime','evidenceOracle','storageOracle','administrator','roleClients','runtimeEvidence')}),
        'configurationDigest':contract.canonical_digest({'nodeConfigDigest':plan['nodes'][0]['configDigest'],
            'environment':profile['environment'],'normalizedConfiguration':profile['normalizedConfiguration']})}
    budget['composedBudgetInputs']=dict(plan['composedBudgetInputs'])
    from cryptad_certification.composed_budget_journal_member import campaign_inputs
    plan['budgetCampaignInputs']=campaign_inputs(plan,tools)
    resign(plan,authorization)
    fixture.update(profile=profile,caseIds=list(profile['cases']),environment=profile['environment'],normalizedConfiguration=profile['normalizedConfiguration'],toolIdentities=tools,
        permissions={app:list(perms) for app,perms in contract.PERMISSIONS.items()})
    return value,fixture


def originals():
    selected_value,_=selected('import-app')
    authorization=selected_value['authorization'];plan=selected_value['plan']
    component=native_component('import-app');component['evidenceClass']='installed-controller-bound'
    binding=component['bindings'];node=next(row for row in plan['nodes'] if row['role']=='candidate-sender')
    binding.update(workloadDigest=plan['workloadInputs']['scheduler'],productDigest=node['artifactDigest'],sourceCommit=node['sourceCommit'],
        appCohortDigest=contract.canonical_digest(node['appDigests']),**plan['composedBudgetInputs'],selectionDigest=authorization['selectionDigest'],
        appBundleDigests=authorization['budgetSelection']['appBundleDigests'])
    for key in component['attachment']:
        if key in binding:component['attachment'][key]=binding[key]
    # Independently retained root controls occur before offered business work. Their
    # exact native bytes are retained and cannot themselves fill selected variants.
    template=copy.deepcopy(component['finalSnapshot']['work']['events'][0]);controls=[];prefix=[]
    for index,app in enumerate(contract.APP_IDS):
        first=len(prefix)
        for kind in ['COMPOSED_URI_IMPORT_START']+([] if index<2 else ['CAPABILITY_DENIED'])+['REQUEST_FAILED']:
            prefix.append(dict(template,kind=kind,operationId=1000+index,scope=3+index,operation=None,value=0,windowStartEpochSecond=0,
                sequence=len(prefix)+1,elapsedNanos=len(prefix)))
        controls.append(dict(appId=app,status=400 if index<2 else 403,beforeSequence=first,afterSequence=len(prefix),collectorEpoch=binding['collectorEpoch'],events=copy.deepcopy(prefix[first:])))
    shift=len(prefix)
    for row in component['attachment']['causalCases']:
        row['sequenceStart']+=shift;row['sequenceEnd']+=shift
        for snapshot in row['snapshots'].values():snapshot['sequence']+=shift
    for event in component['finalSnapshot']['work']['events']:event['sequence']+=shift;event['elapsedNanos']+=shift
    component['finalSnapshot']['work']['events']=prefix+component['finalSnapshot']['work']['events']
    component['finalSnapshot']['work']['lastSequence']+=shift
    role_digest='sha256:'+binding['nodeEpoch']+'a'*32
    contexts={app:dict(appId=app,role='candidate-sender',roleEpochDigest=role_digest,**{key:'sha256:'+'a'*64 for key in
        ('daemonEpochDigest','workerEpochDigest','originDigest','sessionDigest','sessionExpiryDigest')}) for app in contract.APP_IDS}
    record=dict(roleEpochDigest=role_digest,generation='a'*64,managerInvocation='b'*32,bootId='c'*36,handle='d'*64)
    private=dict(schemaVersion=1,kind='pr320-private-route-budget',executionClass=authorization['executionClass'],selectionDigest=authorization['selectionDigest'],
        contexts=contexts,component=component,coverage=routes.derive_complete_routes(component))
    root_native=copy.deepcopy(component['finalSnapshot']);root_native.pop('retainedStatements')
    raw=json.dumps(root_native,sort_keys=True,separators=(',',':')).encode()
    usage=[]
    for rate in root_native['budget']['rates']:
        usage.append(dict(appId='_cryptad_global' if rate['scope']==1 else contract.APP_IDS[rate['scope']-3],operation=rate['operation'],
            windowStart='2026-09-14T12:00:00Z',windowSeconds=3600 if rate['operation']=='trust_graph_import' else 60,count=rate['count'],
            lastDecisionAt=None,lastDecision=None,nextAvailableAt=None))
    diagnostics=dict(routeBudgetCollectorCleanup='completed',routeBudgetSelectionDigest=authorization['selectionDigest'],
        routeBudgetBootstrapContext=dict(apps=contexts,routeScopeBindings=[dict(appId=app,scope=3+index) for index,app in enumerate(contract.APP_IDS)],
            routeScopeControls=controls,**{key:record[key] for key in ('generation','managerInvocation','bootId','handle')}),
        routeBudgetOriginalRecord=dict(durableUsage=usage,graphFacts=[],captureSource='administrator-fixed-file-store-readback',capturedMonotonicNs=1,
            nativeDigest='sha256:'+hashlib.sha256(raw).hexdigest()))
    terminal={'controllerRecords':{'candidate-sender':{'record':record}}}
    checkpoints=[{'phase':'native-collected','component':copy.deepcopy(component)}]
    return private,selected_value,diagnostics,terminal,checkpoints,raw


class RouteInstalledTest(unittest.TestCase):
    def test_real_factories_materialize_all_route_campaigns_for_protected_admission(self):
        import pr320_route_selection as factory
        import cross_version_supervisor_authority as authority
        from cryptad_certification.composed_budget_journal_member import validate_selected_sources
        for name in contract.NAMES:
            _value, fixture = selected(name)
            with self.subTest(profile=name), patch.object(factory, 'verify', return_value=(fixture['profile'], fixture)), \
                    patch.object(factory.os, 'geteuid', return_value=0), \
                    patch.object(factory.signed.legacy.preparation, 'configuration_identity',
                        side_effect=lambda role, trust, execution:
                            'sha256:' + str(contract.ROLES.index(role) + 4) * 64), \
                    patch.object(factory.signed.legacy.runtime, 'runner_identity', return_value={
                        'sourceCommit': fixture['sourceCommit'], 'runnerDigest': 'sha256:' + 'e' * 64,
                        'adapterDigest': 'sha256:' + 'f' * 64}):
                root = factory.FIXED_ROOT / fixture['profile']['experiment']
                value = factory.materialize_selection(root, Path('/owned/source'))
                self.assertTrue(contract.verify_selection_contract(**value))
                self.assertTrue(authority.is_budget_selection(**value))
                self.assertEqual(1, len(validate_selected_sources(value['plan'], fixture['toolIdentities'])))
                incomplete = copy.deepcopy(value)
                del incomplete['plan']['budgetCampaignInputs']
                resign(incomplete['plan'], incomplete['authorization'])
                self.assertFalse(contract.verify_selection_contract(**incomplete))

    def test_seven_configs_bind_closed_native_configuration_and_actual_source_closure(self):
        old=copy.deepcopy(historical.NORMALIZED_CONFIGURATION)
        for name in contract.NAMES:
            value,fixture=selected(name)
            self.assertTrue(contract.verify_selection_contract(**value))
            self.assertFalse(historical.verify_selection_contract(**value))
            self.assertEqual(routes.required_variants(name),fixture['profile']['variants'])
            self.assertEqual(routes.native_configuration(name),fixture['normalizedConfiguration']['budgetConfiguration'])
            self.assertEqual(value['authorization']['selectionDigest'],runner.shared._selection(value,fixture,verify_selection=contract.verify_selection_contract))
        self.assertEqual(old,historical.NORMALIZED_CONFIGURATION)
        root=Path(__file__).resolve().parents[3]
        for path in contract.TOOL_PATHS.values():self.assertTrue((root/path).is_file(),path)
        runner._source_modules(SimpleNamespace(source=root))

    def test_rehashing_selected_quota_or_privilege_or_class_cannot_widen_profile(self):
        for fault in ('quota','permissions','class'):
            value,_=selected('main');budget=value['authorization']['budgetSelection']
            if fault=='quota':budget['environment']['CRYPTAD_APP_NETWORK_BUDGET_TRUST_GRAPH_IMPORT_PER_APP_PER_HOUR']='999'
            elif fault=='permissions':budget['permissions']['budget-no-trust'].append('trust.write')
            else:value['authorization']['executionClass']='pr320-routes-interference-v1'
            resign(value['plan'],value['authorization'])
            self.assertFalse(contract.verify_selection_contract(**value))

    def test_complete_controller_originals_have_accepting_validator_and_exact_private_decode(self):
        args=originals()
        with patch('pr316_mail_runtime_runner._terminal_cleanup_verified',return_value=True):
            derived=evidence.validate_originals(*args)
        self.assertEqual('complete',derived['status'])
        private=args[0]
        self.assertEqual(private,evidence.decode_private(json.dumps(private).encode()))
        self.assertEqual(args[4],evidence.decode_checkpoints(json.dumps(args[4][0]).encode()+b'\n'))

    def test_actual_root_scope_session_bytes_counter_or_original_checkpoint_substitution_reject(self):
        for fault in ('scope','session','native-bytes','counter','checkpoint','selection'):
            args=[copy.deepcopy(value) for value in originals()]
            if fault=='scope':args[2]['routeBudgetBootstrapContext']['routeScopeBindings'][0]['appId']='budget-importer'
            elif fault=='session':args[2]['routeBudgetBootstrapContext']['apps']['feed-reader']['sessionDigest']='sha256:'+'f'*64
            elif fault=='native-bytes':args[5]+=b' '
            elif fault=='counter':args[2]['routeBudgetOriginalRecord']['durableUsage'][0]['count']+=1
            elif fault=='checkpoint':args[4][0]['component']['observations'][0]['scope']=4
            else:args[2]['routeBudgetSelectionDigest']='sha256:'+'f'*64
            with patch('pr316_mail_runtime_runner._terminal_cleanup_verified',return_value=True):
                with self.assertRaises(ValueError):evidence.validate_originals(*args)

    def test_recorder_facade_reuses_actual_accounting_and_checkpoints_exceed_one_line_budget_safely(self):
        import cross_version_app_budgets as local
        self.assertIs(local.AppBudgetLane.case,driver.RouteRecorder.case)
        self.assertIs(local.AppBudgetLane.shared_segment,driver.RouteRecorder.shared_segment)
        self.assertIs(local.AppBudgetLane.reconcile_ambiguous_request,driver.RouteRecorder.reconcile_ambiguous_request)
        self.assertFalse(hasattr(driver.RouteRecorder,'start'))
        with TemporaryDirectory() as temporary:
            adapter=SimpleNamespace(root=Path(temporary))
            driver._checkpoint(adapter,{'phase':'native-collected','component':native_component('main')})
            raw=(adapter.root/contract.CHECKPOINT_FILE).read_bytes()
            self.assertGreater(len(raw),65536)
            self.assertEqual(1,len(evidence.decode_checkpoints(raw)))

    def test_public_missing_run_and_unknown_private_failure_keep_fixed_classification(self):
        value=evidence.failed_projection(contract.profile('main'),'/secret/raw-path')
        self.assertEqual(['setup-or-execution-failed'],value['reasons'])
        self.assertEqual(value,runner._closed_public(value))
        self.assertFalse(value['releaseEligible'])


if __name__=='__main__':unittest.main()

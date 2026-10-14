"""Checkpoint-bound private member references; local vectors never become original authority."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from cryptad_certification import composed_budget_journal_member as members
from cryptad_certification import composed_budget_evidence as legacy
from cryptad_certification import cross_version_evidence as journal
from cryptad_certification.tests.test_cross_version_evidence import fixture_plan
from cryptad_certification.tests.test_composed_budget_routes import native_component


def fixture(profile='import-app'):
    component=native_component(profile)
    plan=fixture_plan();plan['experimentId']='pr320-routes-'+profile
    plan['policy']['minimumObservedSeconds']=0
    for node in plan['nodes']:
        node['appDigests']=list(component['bindings']['appBundleDigests'].values()) if node['role']=='candidate-sender' else []
    node=plan['nodes'][0]
    component['bindings'].update(sourceCommit=node['sourceCommit'],productDigest=node['artifactDigest'])
    component['attachment'].update(sourceCommit=node['sourceCommit'],productDigest=node['artifactDigest'])
    plan['workloadInputs']={'scheduler':component['bindings']['workloadDigest']}
    plan['composedBudgetInputs']={key:component['bindings'][key] for key in ('collectorDigest','configurationDigest')}
    tools={'installedDriver':'sha256:'+'1'*64,'browserCollector':'sha256:'+'2'*64,
           'webShellScript':'sha256:'+'4'*64,'publicDescriptorReaders':'sha256:'+'3'*64}
    plan['budgetCampaignInputs']=members.campaign_inputs(plan,tools)
    return plan,component,tools


def event_for(plan,component,raw=None,inline=True):
    raw=json.dumps(component,sort_keys=True,separators=(',',':')).encode() if raw is None else raw
    descriptor=plan['budgetCampaignInputs']['members'][0]
    return {'kind':'operation','operation':'composed-budget-campaign-member','scenario':'app-budgets',
        'role':'candidate-sender','outcome':'partial','nodeEpoch':component['bindings']['nodeEpoch'],
        'wallTime':'2026-10-14T12:00:00Z','composedBudgetCampaignMember':dict(schemaVersion=1,
            kind='pr320-private-budget-campaign-member',campaignId=members.CAMPAIGN_ID,
            member=descriptor['member'],digest='sha256:'+hashlib.sha256(raw).hexdigest(),size=len(raw),
            collectorEpoch=component['bindings']['collectorEpoch'],rawBase64=base64.b64encode(raw).decode() if inline else None)}


class PrivateJournalMemberTest(unittest.TestCase):
    def test_privacy_journal_binds_served_script_independently_of_browser_collector(self):
        from test_pr320_privacy_installed import vector, encoded
        args = vector()
        plan = dict(fixture_plan(), **args['selected']['plan'])
        plan['producer'] = dict(fixture_plan()['producer'], **plan['producer'])
        tools = args['selected']['authorization']['budgetSelection']['toolIdentities']
        descriptors = members.validate_selected_sources(plan, tools)
        from cryptad_certification.schema_validation import validate_schema
        self.assertEqual([], validate_schema(plan['budgetCampaignInputs'],
                         'pr320-private-budget-campaign-inputs-v1.schema.json'))
        browser_descriptor = next(row for row in descriptors if row['kind'] == 'installed-browser-privacy')
        self.assertNotEqual(browser_descriptor['producerDigest'], browser_descriptor['servedScriptDigest'])
        self.assertEqual(args['browser']['scriptDigest'], browser_descriptor['servedScriptDigest'])
        with tempfile.TemporaryDirectory() as root, journal.Journal(Path(root), plan) as log:
            log.append('node-start', role='candidate-sender', node_epoch='a' * 32)
            members.append_member(log, 'installed-privacy', encoded(args['private']))
            members.append_member(log, 'installed-browser-privacy', encoded(args['browser']),
                                  collector_epoch=args['private']['component']['surfaces']['workSnapshot']['collectorEpoch'])
            derived = legacy.derive_journal(plan, log.events, prospective=True)
            self.assertEqual(['locally-verified', 'locally-verified', 'not-observed'],
                             [row['status'] for row in derived['prospectiveMembers']['members']])
            self.assertFalse(derived['phaseComplete'])
            tampered = copy.deepcopy(plan)
            tampered['budgetCampaignInputs']['members'][1]['servedScriptDigest'] = browser_descriptor['producerDigest']
            with self.assertRaises(ValueError):
                members.validate_selected_sources(tampered, tools)
            with self.assertRaisesRegex(ValueError, 'installed-browser-binding-invalid'):
                members.resolve_journal_members(tampered, log.events)
            missing = copy.deepcopy(plan)
            del missing['budgetCampaignInputs']['members'][1]['servedScriptDigest']
            with self.assertRaises(ValueError):
                members.validate_inputs(missing)
            self.assertTrue(validate_schema(missing['budgetCampaignInputs'],
                            'pr320-private-budget-campaign-inputs-v1.schema.json'))

    def test_actual_journal_append_private_member_checkpoint_and_native_owner_accept(self):
        plan,component,tools=fixture()
        self.assertEqual(plan,journal.validate_plan(plan))
        self.assertEqual(plan['budgetCampaignInputs']['members'],members.validate_selected_sources(plan,tools))
        raw=json.dumps(component,sort_keys=True,separators=(',',':')).encode()
        with tempfile.TemporaryDirectory() as root:
            with journal.Journal(Path(root),plan) as log:
                log.append('node-start',role='candidate-sender',node_epoch=component['bindings']['nodeEpoch'])
                emitted=members.append_member(log,'route-component',raw)
                checkpoint=log.checkpoint('complete')
                self.assertEqual(emitted['composedBudgetCampaignMember']['digest'],'sha256:'+hashlib.sha256(raw).hexdigest())
                self.assertLess(len(json.dumps(emitted).encode()),journal.event_byte_limit(plan))
                self.assertEqual(journal.digest(emitted),checkpoint['tailDigest'])
                derived=legacy.derive_journal(plan,log.events,prospective=True)
                self.assertEqual('locally-verified',derived['prospectiveMembers']['members'][0]['status'])
                self.assertEqual('not-observed',derived['fullAppBudgets'])
                self.assertFalse(derived['phaseComplete'])
                self.assertIsNone(legacy.derive_journal(plan,log.events))

    def test_reference_only_requires_actual_retained_original_bytes(self):
        plan,component,_=fixture();raw=json.dumps(component).encode();event=event_for(plan,component,raw,False)
        result=members.resolve_journal_members(plan,[event])
        self.assertEqual('original-bytes-unavailable',result['members'][0]['reason'])
        result=members.resolve_journal_members(plan,[event],members={plan['budgetCampaignInputs']['members'][0]['member']:raw})
        self.assertEqual('locally-verified',result['members'][0]['status'])
        with self.assertRaises(ValueError):members.resolve_journal_members(plan,[event],members={plan['budgetCampaignInputs']['members'][0]['member']:raw+b' '})

    def test_missing_member_or_replay_never_becomes_coverage(self):
        plan,component,_=fixture();event=event_for(plan,component)
        result=members.resolve_journal_members(plan,[])
        self.assertEqual('member-event-unobserved',result['members'][0]['reason'])
        with self.assertRaises(ValueError):members.resolve_journal_members(plan,[event,event])
        with self.assertRaises(ValueError):members.resolve_journal_members(plan,[],members={'member-02.json':b'{}'})

    def test_source_digest_kind_planned_variants_and_old_experiment_relabel_reject(self):
        plan,_component,tools=fixture()
        for fault in ('producer','kind','variant','old-class','schema-bool'):
            changed=copy.deepcopy(plan);descriptor=changed['budgetCampaignInputs']['members'][0]
            if fault=='producer':descriptor['producerDigest']='sha256:'+'f'*64
            elif fault=='kind':descriptor['kind']='storage-component'
            elif fault=='variant':descriptor['plannedVariants']=[['import-concurrency','global']]
            elif fault=='old-class':changed['experimentId']='pr317-namespace-bound-composed-budget'
            else:changed['budgetCampaignInputs']['schemaVersion']=True
            with self.assertRaises(ValueError):members.validate_selected_sources(changed,tools)

    def test_event_outer_epoch_wrong_collector_primitive_bool_and_corrupt_native_reject(self):
        for fault in ('epoch','collector','scope','size-bool','schema-bool','native'):
            plan,component,_=fixture();event=event_for(plan,component)
            reference=event['composedBudgetCampaignMember']
            if fault=='epoch':event['nodeEpoch']='f'*32
            elif fault=='collector':reference['collectorEpoch']='f'*36
            elif fault=='scope':event['role']='previous'
            elif fault=='size-bool':reference['size']=True
            elif fault=='schema-bool':reference['schemaVersion']=True
            else:
                component['attachment']['causalCases'][0]['events'][2]['kind']='BUDGET_CHECK'
                event=event_for(plan,component)
            with self.assertRaises(ValueError):members.resolve_journal_members(plan,[event])

    def test_historical_event_and_attachment_limits_remain_unchanged(self):
        self.assertEqual(4096,journal.event_byte_limit(fixture_plan()))
        plan,_component,_=fixture()
        self.assertEqual(1024*1024+4096,journal.event_byte_limit(plan))
        legacy_plan={key:value for key,value in plan.items() if key!='budgetCampaignInputs'}
        with self.assertRaisesRegex(ValueError,'attachment-limit'):
            legacy.derive_journal(legacy_plan,[{'composedBudgetEvidence':{}}]*9)

    def test_all_19_fixed_slots_declared_source_and_restart_v5_unmodified(self):
        plan,_component,tools=fixture();slots=[]
        experiments=['pr320-routes-'+name for name in members.routes.PROFILE_NAMES]
        experiments+=['pr320-installed-owner-cancellation']
        experiments+=['pr320-storage-'+case+'-'+variant for case,variant in members.STORAGE_VARIANTS]
        experiments+=['pr320-installed-budget-privacy','pr320-installed-restart-diagnostics']
        for experiment in experiments:
            selected=copy.deepcopy(plan);selected['experimentId']=experiment
            selected['budgetCampaignInputs']=members.campaign_inputs(selected,tools)
            slots.extend(row['member'] for row in members.validate_inputs(selected))
        self.assertEqual(['member-%02d.json'%index for index in range(19)],slots)
        self.assertEqual(5,len(selected['budgetCampaignInputs']['members'][0]['plannedVariants']))


if __name__=='__main__':unittest.main()

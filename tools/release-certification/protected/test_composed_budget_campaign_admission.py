"""Accepting budget composition supplies upstream observation capabilities and root reads.

Every budget native and independent-original owning verifier executes unchanged on explicit
synthetic vectors. The upstream runtime observation capability is substituted at its admission
entrypoint; this suite does not establish external supervisor or product authentication. No
protected fixture flag or serialized coverage assertion can create the budget capability.
"""
from __future__ import annotations
import base64
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import composed_budget_campaign_admission as admission
import pr320_campaign_original_vectors as vectors
from cryptad_certification import composed_budget_campaign_evidence as campaign
from cryptad_certification import composed_budget_journal_member as journal
from cryptad_certification import cross_version_evidence as evidence
from cryptad_certification.tests.test_cross_version_evidence import fixture_plan


def full_originals(*, provenance='production-artifact-comparison'):
    values=vectors.all_original_members()
    grouped=[]
    for row in values:
        if row[0] in (16,17):grouped[-1].append(row)
        else:grouped.append([row])
    originals,reports,retained,facts,descriptors=[],{}, {},{},[]
    for group_index,group in enumerate(grouped):
        first=group[0][3];selected=first['selected'];plan=selected['plan'];auth=selected['authorization']
        # Complete ordinary plan fields before the prospective original authorization
        # is frozen; existing owner fixture bindings stay intact.
        base=fixture_plan()
        for key,value in base.items():plan.setdefault(key,copy.deepcopy(value))
        for key,value in base['producer'].items():plan['producer'].setdefault(key,value)
        for node in plan['nodes']:
            template=next(row for row in base['nodes'] if row['role']==node['role'])
            for key,value in template.items():node.setdefault(key,copy.deepcopy(value))
        plan['provenanceClass']=provenance
        old=auth['selectionDigest'];vectors.complete_selection(selected, provenance=provenance);new=auth['selectionDigest']
        evidence.validate_plan(plan)
        def rebind(value):
            if isinstance(value,dict):return {key:rebind(child) for key,child in value.items()}
            if isinstance(value,list):return [rebind(child) for child in value]
            return new if value==old else value
        fixed=[]
        for slot,kind,raw,source in group:
            source=rebind(source);source['selected']=copy.deepcopy(selected)
            for member in ('native','privacyOriginals'):
                if source[member] is not None:source[member]=vectors.b64(rebind(json.loads(base64.b64decode(source[member]))))
            checkpoint_rows=[rebind(json.loads(line)) for line in base64.b64decode(source['checkpoints']).splitlines()]
            source['checkpoints']=vectors.b64(b'\n'.join(vectors.encoded(row) for row in checkpoint_rows)+b'\n')
            value=campaign._decode(raw)
            if slot==15:
                value=rebind(value);raw=vectors.encoded(value)
            elif slot in (16,17):
                value['nativeMemberDigest']='sha256:'+hashlib.sha256(fixed[0][2]).hexdigest()
                raw=vectors.encoded(value)
            # The private original wrapper changes its selection digest after the
            # exact plan freezes; propagate that original change through native
            # component bindings and independently retained root receipts.
            private=rebind(json.loads(base64.b64decode(source['private'])))
            if kind=='route-component':
                private['component']['bindings']['selectionDigest']=new
                private['coverage']=vectors.routes.derive_complete_routes(private['component'])
                raw=vectors.encoded(private['component'])
                lines=[json.loads(line) for line in base64.b64decode(source['checkpoints']).splitlines()]
                for line in lines:
                    if line['phase']=='native-collected':line['component']=copy.deepcopy(private['component'])
                source['checkpoints']=vectors.b64(b'\n'.join(vectors.encoded(line) for line in lines)+b'\n')
            if slot in (15,16,17):
                private=json.loads(fixed[0][2]) if fixed else value
                source['private']=vectors.b64(private)
                browser=json.loads(base64.b64decode(source['browser']));browser['nativeMemberDigest']='sha256:'+hashlib.sha256(fixed[0][2] if fixed else raw).hexdigest()
                roots=json.loads(base64.b64decode(source['privacyOriginals']))
                roots['receipts'][2]['component']=copy.deepcopy(browser)
                roots['receipts'][2]['collectorOutput']=[dict(stdout=vectors.encoded(browser).decode(),stderr='')]
                source['browser']=vectors.b64(browser);source['privacyOriginals']=vectors.b64(roots)
                source['checkpoints']=vectors.b64(vectors.encoded({'phase':'native-collected','component':private['component']})+b'\n'+
                    vectors.encoded({'phase':'browser-collected','component':browser})+b'\n')
            else:source['private']=vectors.b64(private)
            if kind=='legacy-attachment':
                raw=vectors.encoded(private['composedBudgetEvidence'])
            if kind=='storage-component':raw=vectors.encoded(private['storageComponent'])
            fixed.append((slot,kind,raw,source))
        if any(row[0] == 17 for row in fixed):
            artifact_raw = next(row[2] for row in fixed if row[0] == 17)
            for row in fixed: row[3]['artifact'] = vectors.b64(artifact_raw)
        group=fixed;events=[];entries={}
        now=dt.datetime(2026,10,14,2,tzinfo=dt.timezone.utc)+dt.timedelta(minutes=group_index*2)
        started=now.isoformat();finished=(now+dt.timedelta(minutes=1)).isoformat()
        coordinate=dict(runId=str(1000+group_index),runAttempt=1,artifactId=str(2000+group_index))
        identity=dict(runId=coordinate['runId'],runAttempt=1,jobId='budget-job-%02d'%group_index)
        historical=dict(schemaVersion=6,operation='finish',job=identity,status='pass')
        public=dict(schemaVersion=1,kind='pr320-original-budget-member-receipt',receiptId='%032x'%(group_index+1))
        report=dict(historical,schemaVersion=8,budgetCampaignBaseVersion=6,budgetCampaignReceipt=public)
        node=next(n for n in plan['nodes'] if n['role']=='candidate-sender')
        for slot,kind,raw,source in group:
            # Owner-verification is intentionally real, including terminal cleanup.
            admission.verify_original_member(kind,raw,source)
            value=campaign._decode(raw)
            native=value['component'] if kind=='installed-privacy' else value
            epoch=(native['bindings']['collectorEpoch'] if kind=='route-component' else
                   native['storageCases'][0]['collectorEpoch'] if kind=='storage-component' else
                   native['surfaces']['workSnapshot']['collectorEpoch'] if kind=='installed-privacy' else
                   campaign._decode(group[0][2])['component']['surfaces']['workSnapshot']['collectorEpoch'] if kind in {'installed-browser-privacy','artifact-privacy'} else native['collectorEpoch'])
            node_epoch=(native['bindings']['nodeEpoch'] if kind=='route-component' else
                        native['storageCases'][0]['nodeEpoch'] if kind=='storage-component' else
                        native['nodeEpoch'] if kind=='legacy-attachment' else 'a'*32)
            name='member-%02d.json'%slot
            metadata=next(row for row in plan['budgetCampaignInputs']['members'] if row['member']==name)
            reference=dict(schemaVersion=1,kind='pr320-private-budget-campaign-member',campaignId=journal.CAMPAIGN_ID,
                member=name,digest='sha256:'+hashlib.sha256(raw).hexdigest(),size=len(raw),collectorEpoch=epoch,rawBase64=None)
            event=dict(kind='operation',operation='composed-budget-campaign-member',scenario='app-budgets',role='candidate-sender',
                outcome='partial',nodeEpoch=node_epoch,wallTime=finished,composedBudgetCampaignMember=reference)
            journal.validate_reference(plan,event);events.append(event)
            entries[name]=dict(schemaVersion=1,kind='pr320-root-captured-budget-member',planDigest=evidence.digest(plan),rawBase64=vectors.b64(raw),originals=source,
                activationDigest='sha256:'+'a'*64,checkpointDigest='sha256:'+'b'*64)
            binding={key:metadata[key] for key in ('collectorDigest','configurationDigest','producerDigest')}
            binding.update(nodeEpoch=node_epoch,collectorEpoch=epoch,role='candidate-sender',observedAt=finished,workloadDigest=plan['workloadInputs']['scheduler'])
            if kind == 'installed-browser-privacy':
                binding['servedScriptDigest'] = json.loads(source['browser'] and base64.b64decode(source['browser']))['scriptDigest']
            descriptors.append(dict(member=name,kind=kind,digest=reference['digest'],size=len(raw),binding=binding,plannedVariants=metadata['plannedVariants']))
        checkpoint=dict(schemaVersion=1,status='complete',sequence=len(events),tailDigest=evidence.digest(events[-1]))
        retained[public['receiptId']]=dict(schemaVersion=1,kind='pr320-private-original-budget-receipt',publicReceipt=public,job=identity,
            reportDigest=evidence.digest(historical),planDigest=evidence.digest(plan),checkpointDigest=evidence.digest(checkpoint),entries=entries)
        activation=dict(schemaVersion=1,planDigest=evidence.digest(plan),privateConfigDigest=evidence.digest(selected['private']),authorizationDigest=evidence.digest(auth))
        for entry in entries.values():
            entry['activationDigest'] = evidence.digest(activation)
            entry['checkpointDigest'] = evidence.digest(checkpoint)
        bundle=dict(plan=plan,events=events,checkpoint=checkpoint,authorization=auth,privateConfig=copy.deepcopy(selected['private']),activation=activation)
        originals.append(dict(coordinates=coordinate,bundle=bundle));reports[coordinate['artifactId']]=report
        facts[coordinate['artifactId']]=dict(outcome='pass',findings=[],origin=identity,startedAt=started,finishedAt=finished)
    node=originals[0]['bundle']['plan']['nodes'][0]
    subject=dict(productDigest=node['artifactDigest'],sourceCommit=node['sourceCommit'],appCohortDigest=evidence.digest(node['appDigests']),
        workloadDigest=evidence.digest({row['member']:row['binding']['workloadDigest'] for row in sorted(descriptors,key=lambda r:r['member'])}),contractVersion=node['contractVersion'])
    selection=dict(schemaVersion=1,kind='composed-budget-campaign',evidenceClass='installed-cohort-local-consistency',subject=subject,
        members=sorted(descriptors,key=lambda row:row['member']),attempts=[dict(member=row['member'],attempt=1,outcome='observed') for row in sorted(descriptors,key=lambda row:row['member'])])
    return selection,originals,reports,retained,facts


class OriginalCampaignAdmissionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture=full_originals()

    def call(self,values=None):
        selection,originals,reports,retained,facts=copy.deepcopy(self.fixture if values is None else values)
        def proof(coordinates,_bundle,_scratch,*,cutoff):
            return SimpleNamespace(values=lambda:copy.deepcopy(facts[coordinates['artifactId']]))
        def report(coordinates,_scratch):return copy.deepcopy(reports[coordinates['artifactId']]),{}
        def read_root(path):
            if path.stem not in retained:raise FileNotFoundError('missing-original-receipt')
            return copy.deepcopy(retained[path.stem])
        with tempfile.TemporaryDirectory() as temporary, \
             patch('runtime_baseline_admission.authenticate_budget_observation',side_effect=proof), \
             patch('cross_version_supervisor_authority.authenticate_report',side_effect=report), \
             patch.object(admission,'_read_root',side_effect=read_root):
            # The original API normally creates each root stage before return.
            for index in range(len(originals)):(Path(temporary)/('original-%02d'%index)).mkdir()
            return admission.authenticate_campaign(selection,originals,temporary,cutoff='2026-10-14T06:00:00Z')

    def test_full_19_native_original_members_accept_without_mocking_budget_owners_or_coverage(self):
        proof=self.call()
        value=proof.coverage()
        self.assertEqual('complete-original',value['budgetCohortStatus'])
        self.assertEqual('observed',value['fullAppBudgets'])
        self.assertEqual(31,len(value['observedCases']))
        self.assertFalse(value['phaseComplete'])
        self.assertFalse(value['releaseEligible'])
        for original in self.fixture[1]:proof.bind(original['bundle']['plan'])
        with self.assertRaises(ValueError):proof._raw=b'{}'

        with self.assertRaises(ValueError):admission.OriginalBudgetCampaign(object(),value,self.fixture[0]['subject'],{}, plans={})
        # A consumer cannot move this capability onto another profile workload,
        # source, product, cohort, or contract after its original inputs freeze.
        for field in ('workload','sourceCommit','artifactDigest','appDigests','contractVersion'):
            plan=copy.deepcopy(self.fixture[1][0]['bundle']['plan'])
            node=next(row for row in plan['nodes'] if row['role']=='candidate-sender')
            if field=='workload':plan['workloadInputs']['scheduler']='sha256:'+'f'*64
            elif field=='sourceCommit':node[field]='f'*40
            elif field=='artifactDigest':node[field]='sha256:'+'f'*64
            elif field=='appDigests':node[field]=['sha256:'+'f'*64]
            else:node[field]+=1
            with self.subTest(field=field),self.assertRaises(ValueError):proof.bind(plan)
        plan = copy.deepcopy(self.fixture[1][0]['bundle']['plan'])
        plan['composedBudgetInputs']['configurationDigest'] = 'sha256:' + 'f'*64
        for member in plan['budgetCampaignInputs']['members']:
            member['configurationDigest'] = plan['composedBudgetInputs']['configurationDigest']
        journal.validate_inputs(plan)
        with self.assertRaisesRegex(ValueError, 'consumer-selection-substituted'):
            proof.bind(plan)

    def test_original_order_uses_instants_across_offsets_and_rejects_future_or_overlap(self):
        values = copy.deepcopy(self.fixture)
        for index, row in enumerate(values[4].values()):
            offset = dt.timezone(dt.timedelta(hours=14 if index % 2 else -12))
            for key in ('startedAt', 'finishedAt'):
                row[key] = dt.datetime.fromisoformat(row[key]).astimezone(offset).isoformat()
        times = {event['composedBudgetCampaignMember']['member']:
                 values[4][original['coordinates']['artifactId']]['finishedAt']
                 for original in values[1] for event in original['bundle']['events']}
        for member in values[0]['members']:
            member['binding']['observedAt'] = times[member['member']]
        self.assertEqual('complete-original', self.call(values).coverage()['budgetCohortStatus'])
        first, second = list(values[4].values())[:2]
        first['finishedAt'] = second['finishedAt']
        with self.assertRaisesRegex(ValueError, 'replayed-or-overlapping'):
            self.call(values)
        values = copy.deepcopy(self.fixture)
        next(iter(values[4].values()))['finishedAt'] = '2026-10-15T00:00:00Z'
        with self.assertRaisesRegex(ValueError, 'clock-invalid'):
            self.call(values)

    def test_receipt_report_selection_member_and_source_changes_cannot_be_rehashed_into_authority(self):
        for fault in ('receipt','report','selection','raw','source','checkpoint','job','roster','collector','configuration'):
            values=copy.deepcopy(self.fixture);selection,originals,reports,retained,facts=values
            receipt=retained[next(iter(retained))];entry=next(iter(receipt['entries'].values()))
            if fault=='receipt':receipt['publicReceipt']['receiptId']='f'*32
            elif fault=='report':receipt['reportDigest']='sha256:'+'f'*64
            elif fault=='selection':entry['originals']['selected']['plan']['nodes'][0]['sourceCommit']='f'*40
            elif fault=='raw':entry['rawBase64']=base64.b64encode(base64.b64decode(entry['rawBase64'])+b' ').decode()
            elif fault=='source':entry['originals']['selected']['authorization']['budgetSelection']['toolIdentities']['installedDriver']='sha256:'+'f'*64
            elif fault=='checkpoint':receipt['checkpointDigest']='sha256:'+'f'*64
            elif fault=='job':receipt['job']=dict(receipt['job'],jobId='another-job')
            elif fault=='roster':receipt['entries']['member-99.json']=copy.deepcopy(entry)
            elif fault=='collector':selection['members'][0]['binding']['collectorEpoch']='another-collector'
            else:selection['members'][0]['binding']['configurationDigest']='sha256:'+'f'*64
            with self.subTest(fault=fault),self.assertRaises((ValueError,OSError)):self.call(values)

    def test_external_failure_replay_overlap_partial_roster_and_copied_coverage_reject(self):
        for fault in ('failure','replay','overlap','missing','summary','future'):
            values=copy.deepcopy(self.fixture);selection,originals,reports,retained,facts=values
            if fault=='failure':next(iter(facts.values()))['outcome']='failed'
            elif fault=='replay':originals.append(copy.deepcopy(originals[0]))
            elif fault=='overlap':list(facts.values())[1]['startedAt']=list(facts.values())[0]['startedAt']
            elif fault=='missing':originals.pop()
            elif fault=='summary':selection['evidenceClass']='synthetic-local-cohort'
            else:selection['members'][0]['binding']['observedAt']='2027-01-01T00:00:00Z'
            with self.subTest(fault=fault),self.assertRaises((ValueError,OSError)):self.call(values)

    def test_authenticated_budget_capability_preserves_all_49_phase_requirements_and_other_blockers(self):
        from cryptad_certification import phase_12_closeout as closeout
        from cryptad_certification import phase_12_runtime_adapters as runtime
        proof=self.call()
        selection,originals,*_=self.fixture
        payloads={'campaign.json':vectors.encoded(selection),'originals.json':vectors.encoded(originals),
                  'plan.json':vectors.encoded(originals[0]['bundle']['plan'])}
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve()
            result=runtime.verify_authenticated('budget-campaign',payloads,'2026-10-14T06:00:00Z',root,proof)
            self.assertEqual('observed',result['components']['appBudgets'])
            self.assertEqual('partial',result['dimensions']['coverage'])
            self.assertEqual(31,len(result['coverage']['observed']))
            self.assertFalse(result['components']['phaseComplete'])
            self.assertFalse(result['components']['releaseEligible'])
            self.assertIn('reviewed-resource-baseline-required',result['blockers'])
            self.assertIn('remaining-runtime-adapters-required',result['blockers'])
            with self.assertRaises(ValueError):
                runtime.verify_authenticated('budget-campaign',payloads,'2026-10-14T06:00:00Z',root,proof.coverage())
        rules,_=closeout.policy()
        self.assertEqual(49,len(rules['requirements']))

    def test_root_retainer_accepts_actual_owner_bytes_only_after_terminal_activation_checks(self):
        selection,originals,reports,retained,_=copy.deepcopy(self.fixture)
        original=originals[0];bundle=original['bundle'];plan=bundle['plan']
        receipt=next(iter(retained.values()));staged=copy.deepcopy(next(iter(receipt['entries'].values())))
        staged.pop('activationDigest');staged.pop('checkpointDigest')
        activation=copy.deepcopy(bundle['activation'])
        report=copy.deepcopy(reports[original['coordinates']['artifactId']])
        report.pop('budgetCampaignReceipt');report.pop('budgetCampaignBaseVersion');report['schemaVersion']=6
        checks=[];writes=[]
        terminal=SimpleNamespace(require=lambda actual:checks.append(copy.deepcopy(actual)))
        with tempfile.TemporaryDirectory() as temporary:
            root=MagicMock(wraps=Path(temporary))
            root.stat.return_value=SimpleNamespace(st_uid=0,st_mode=0o40700)
            root.is_symlink.return_value=False
            root.__truediv__.side_effect=lambda name:Path(temporary)/name
            with patch.object(admission,'ROOT',root), \
             patch.object(admission.os,'geteuid',return_value=0), \
             patch.object(admission,'_read_root',return_value=staged), \
             patch('cross_version_supervisor_authority._atomic',side_effect=lambda path,value:writes.append((path,copy.deepcopy(value)))):
                public=admission.retain_owned_members(plan,bundle['events'],bundle['checkpoint'],activation,report,terminal)
        self.assertEqual([activation]*3,checks)
        self.assertEqual(1,len(writes))
        self.assertEqual(public,writes[0][1]['publicReceipt'])
        entry=next(iter(writes[0][1]['entries'].values()))
        self.assertEqual(evidence.digest(activation),entry['activationDigest'])
        self.assertEqual(evidence.digest(bundle['checkpoint']),entry['checkpointDigest'])
        # These are root-file and terminal OS boundaries; native verification above
        # runs unchanged and cannot be substituted by a caller coverage summary.
        with self.assertRaises(ValueError):
            admission.retain_owned_members(plan,bundle['events'],bundle['checkpoint'],activation,report,None)


if __name__=='__main__':unittest.main()

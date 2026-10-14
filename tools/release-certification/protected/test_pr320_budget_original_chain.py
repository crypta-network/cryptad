"""Actual original budget chain verification with synthetic external artifact providers.

The real journal, report validator, supervisor relationships, raw selection/activation checks,
and native budget owner execute here. Artifact download, attestation and environment APIs
are replaced; deterministic clocks create the local journal fixture. The production branch
separately supplies an external original-product provider. These vectors prove acceptance
and rejection paths, never protected execution.
"""
from __future__ import annotations

import base64
import copy
import datetime as dt
import io
import itertools
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import composed_budget_campaign_admission as budget_owner
import cross_version_supervisor_authority as supervisor
import maintenance_runtime_projection as maintenance
from original_artifact_authentication import OriginalArtifact
import runtime_baseline_admission as upstream
import cross_version_product_admission as products
import test_composed_budget_campaign_admission as original_vectors
from cryptad_certification import composed_budget_journal_member as members
from cryptad_certification import cross_version_evidence as evidence

CUTOFF = '2026-10-15T00:00:00Z'


def chain_vector(original_fixture):
    retained = copy.deepcopy(original_fixture[3])
    entry = next(iter(next(iter(retained.values()))['entries'].values()))
    raw = base64.b64decode(entry['rawBase64'], validate=True)
    native_originals = entry['originals']
    # This is the actual root/native owning validator, not a coverage stub.
    selected = budget_owner.verify_original_member('route-component', raw, native_originals)
    plan, private, authorization = (selected[key] for key in ('plan', 'private', 'authorization'))
    component = json.loads(raw)
    seconds = itertools.count()
    class FixedClock(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return dt.datetime(2026, 10, 14, 2, tzinfo=dt.timezone.utc) + dt.timedelta(seconds=next(seconds))
    monotonic = itertools.count(1_000_000_000, 1_000_000_000)
    with tempfile.TemporaryDirectory() as temporary, \
         patch.object(evidence.dt, 'datetime', FixedClock), \
         patch.object(evidence.time, 'monotonic_ns', side_effect=lambda: next(monotonic)), \
         evidence.Journal(Path(temporary), plan) as journal:
        journal.append('start')
        for index, node in enumerate(plan['nodes']):
            node_epoch = component['bindings']['nodeEpoch'] if node['role'] == 'candidate-sender' else '%032x' % (index + 2)
            journal.append('node-start', role=node['role'], node_epoch=node_epoch)
        members.append_member(journal, 'route-component', raw)
        for node in plan['nodes']:journal.append('node-stop', role=node['role'])
        journal.append('cleanup')
        journal.append('finish', outcome='partial')
        checkpoint = journal.checkpoint('partial')
        events = copy.deepcopy(journal.events)
        # Read back the actual fsynced journal and terminal checkpoint.
        assert events == [json.loads(line) for line in (Path(temporary) / 'journal.jsonl').read_bytes().splitlines()]
        assert checkpoint == json.loads((Path(temporary) / 'checkpoint.json').read_bytes())
    producer = plan['producer']
    origins = [dict(sourceFamily='cross-version-supervisor', sourceCommit=producer['sourceCommit'],
        runId=100 + index, runAttempt=1, artifactId=200 + index,
        artifactName='cross-version-supervisor-%d-1' % (100 + index), jobId=300 + index)
        for index in range(3)]
    raw_inputs = {key: upstream.encode(value).decode() for key, value in
                  (('plan', plan), ('private-config', private), ('authorization', authorization))}
    bindings = {'serviceDigest': 'sha256:' + 'a' * 64,
        **{field: upstream.byte_digest(raw_inputs[key].encode()) for key, field in
           (('plan', 'planDigest'), ('private-config', 'privateConfigDigest'), ('authorization', 'authorizationDigest'))}}
    common = dict(kind='cryptad-cross-version-supervisor', experimentId=plan['experimentId'],
        planDigest=evidence.digest(plan), producer=producer, purpose='nonrelease-observed-experiment',
        releaseEligible=False, selectionDigest=evidence.digest(bindings))
    authorize = dict(common, schemaVersion=1, operation='authorize',
        job={key: origins[0][key] for key in ('sourceCommit', 'runId', 'runAttempt')},
        approvedBounds={'maxSeconds': authorization['maxSeconds'], 'maxOperations': authorization['maxOperations'], 'syntheticContent': True},
        plan=plan, serviceDigest=bindings['serviceDigest'])
    start = dict(common, schemaVersion=1, operation='start',
        job={key: origins[1][key] for key in ('sourceCommit', 'runId', 'runAttempt')},
        previousOrigin=origins[0], previousReportDigest=evidence.digest(authorize), serviceState='running',
        approvalOrigin=origins[0], approvalReportDigest=evidence.digest(authorize))
    cutoff = dt.datetime.fromisoformat(CUTOFF)
    observation = evidence.verify(plan, events, checkpoint, now=cutoff)
    historical = maintenance.project(plan, events, checkpoint, [], now=cutoff)
    final = dict(common, schemaVersion=8, budgetCampaignBaseVersion=2,
        budgetCampaignReceipt={'schemaVersion': 1, 'kind': 'pr320-original-budget-member-receipt', 'receiptId': 'a' * 32},
        operation='finish', job={key: origins[2][key] for key in ('sourceCommit', 'runId', 'runAttempt')},
        previousOrigin=origins[1], previousReportDigest=evidence.digest(start), serviceState='stopped',
        approvalOrigin=origins[0], approvalReportDigest=evidence.digest(authorize),
        checkpoint={key: checkpoint[key] for key in ('sequence', 'tailDigest', 'status')},
        observation=observation, maintenanceMeasurements=historical)
    final['checkpoint']['digest'] = evidence.digest(checkpoint)
    for report in (authorize, start, final):supervisor.validate_report(report)
    activation = dict(schemaVersion=1, planDigest=evidence.digest(plan), producer=producer,
        approvalOrigin=origins[0], approvalReportDigest=evidence.digest(authorize),
        privateConfigDigest=upstream.byte_digest(raw_inputs['private-config'].encode()),
        authorizationDigest=upstream.byte_digest(raw_inputs['authorization'].encode()))
    bundle = dict(plan=plan, events=events, checkpoint=checkpoint, privateConfig=private,
        authorization=authorization, privateAuthorization=None, inputSnapshot=None,
        activation=activation, rawInputs=raw_inputs)
    return dict(bundle=bundle, origins=origins, reports=[authorize, start, final],
                native=raw, nativeOriginals=native_originals)


class BudgetOriginalChainTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vector = chain_vector(original_vectors.full_originals(provenance='source-build-comparison'))

    def authenticate(self, vector=None, *, legacy=False, attestation=True, product_provider=None):
        # Historical test modules load the supervisor under its canonical name again.
        # Patch the providers on the currently executing owner used by admission.
        import importlib
        current_supervisor = importlib.import_module('cross_version_supervisor_authority')
        current_products = importlib.import_module('cross_version_product_admission')
        value = copy.deepcopy(self.vector if vector is None else vector)
        calls = []
        def original(coordinates, _scratch):
            index = value['origins'].index(coordinates)
            calls.append(index)
            output = io.BytesIO()
            with zipfile.ZipFile(output, 'w') as archive:
                archive.writestr('cross-version-supervisor.json', upstream.encode(value['reports'][index]))
            return OriginalArtifact(output.getvalue(), coordinates, CUTOFF)
        def attest(args, _environment):
            if not attestation:return []
            report = json.loads(Path(args[2]).read_bytes())
            invocation = 'https://github.com/crypta-network/cryptad/actions/runs/%d/attempts/1' % report['job']['runId']
            return [{'verificationResult': {'signature': {'certificate': {'runInvocationURI': invocation}}}}]
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(current_supervisor, 'authenticate_original', side_effect=original), \
             patch.object(current_supervisor, '_gh', side_effect=attest), \
             patch.object(current_supervisor, '_environment', return_value={}), \
             patch.object(current_products, 'authenticate_products', side_effect=product_provider or
                 AssertionError('source-built-observation-must-not-claim-original-products')):
            method = upstream.authenticate_observation if legacy else upstream.authenticate_budget_observation
            proof = method(value['origins'][-1], value['bundle'], Path(temporary), cutoff=CUTOFF)
        return proof, calls

    def test_actual_partial_original_chain_and_native_owner_accept_without_upstream_validator_mocks(self):
        proof, calls = self.authenticate()
        self.assertEqual([2, 1, 0], calls)
        value = proof.values()
        self.assertEqual('partial-budget-component', value['outcome'])
        self.assertEqual(self.vector['origins'][-1], value['origin'])
        self.assertIsNone(value['series'])
        self.assertEqual(evidence.digest(self.vector['bundle']['activation']), value['activationDigest'])
        self.assertEqual(evidence.digest(self.vector['bundle']['checkpoint']), value['checkpointDigest'])
        budget_owner.verify_original_member('route-component', self.vector['native'], self.vector['nativeOriginals'])
        assessment = members.resolve_journal_members(self.vector['bundle']['plan'], self.vector['bundle']['events'])
        self.assertEqual('locally-verified', assessment['members'][0]['status'])
        self.assertEqual('not-observed', assessment['fullAppBudgets'])
        self.assertFalse(assessment['phaseComplete'])
        with self.assertRaises(ValueError):self.authenticate(legacy=True)

    def test_raw_inputs_activation_private_authorization_and_original_checkpoint_substitution_reject(self):
        for fault in ('raw', 'activation', 'authorization', 'selection', 'checkpoint', 'cleanup', 'attestation'):
            value = copy.deepcopy(self.vector)
            bundle = value['bundle']
            if fault == 'raw':bundle['rawInputs']['private-config'] = '{}'
            elif fault == 'activation':bundle['activation']['approvalReportDigest'] = 'sha256:' + 'f' * 64
            elif fault == 'authorization':bundle['privateAuthorization'] = {
                'schemaVersion': 1, 'kind': 'private-runtime-authorization', 'publicContext': {}, 'privateBindings': {}}
            elif fault == 'selection':value['reports'][0]['selectionDigest'] = 'sha256:' + 'f' * 64
            elif fault == 'checkpoint':value['reports'][-1]['checkpoint']['tailDigest'] = 'sha256:' + 'f' * 64
            elif fault == 'cleanup':bundle['events'] = [row for row in bundle['events'] if row['kind'] != 'cleanup']
            with self.subTest(fault=fault), self.assertRaises((ValueError, KeyError)):
                self.authenticate(value, attestation=fault != 'attestation')

    def test_valid_private_authorization_context_keeps_exact_raw_bindings(self):
        value = copy.deepcopy(self.vector)
        bundle = value['bundle']
        bindings = {'serviceDigest': value['reports'][0]['serviceDigest'],
            **{field: upstream.byte_digest(bundle['rawInputs'][key].encode()) for key, field in
               (('plan', 'planDigest'), ('private-config', 'privateConfigDigest'), ('authorization', 'authorizationDigest'))}}
        context = {'kind': 'sealed-runtime-authorization', 'operationId': '12345678-1234-1234-1234-123456789012',
                   'planDigest': bindings['planDigest'], 'serviceDigest': bindings['serviceDigest']}
        bundle['privateAuthorization'] = {'schemaVersion': 1, 'kind': 'private-runtime-authorization',
                                         'publicContext': context, 'privateBindings': bindings}
        for report in value['reports']:report['selectionDigest'] = evidence.digest(context)
        self.rechain_reports(value)
        proof, _ = self.authenticate(value)
        self.assertEqual('partial-budget-component', proof.values()['outcome'])
        value['bundle']['privateAuthorization']['privateBindings']['authorizationDigest'] = 'sha256:' + 'f' * 64
        with self.assertRaises(ValueError):self.authenticate(value)

    def test_fault_cannot_be_rehashed_into_an_accepted_partial_budget_observation(self):
        value = copy.deepcopy(self.vector)
        events = value['bundle']['events']
        fault = copy.deepcopy(events[0])
        fault.update(kind='fault', outcome='fail', wallTime=events[-2]['wallTime'], monotonicNs=events[-2]['monotonicNs'])
        events.insert(-2, fault)
        for index, event in enumerate(events):
            event['sequence'] = index + 1
            event['previousDigest'] = evidence.digest(events[index - 1]) if index else evidence.ZERO
        checkpoint = value['bundle']['checkpoint']
        checkpoint.update(sequence=len(events), tailDigest=evidence.digest(events[-1]), status='partial')
        self.rechain_reports(value)
        with self.assertRaisesRegex(ValueError, 'runtime-budget-original-failed-experiment'):
            self.authenticate(value)

    def test_production_artifact_branch_still_requires_product_provider_and_exact_activation_identities(self):
        value = chain_vector(original_vectors.full_originals())
        identities = [{'role': row['role'], 'artifactDigest': row['artifactDigest']} for row in value['bundle']['plan']['nodes']]
        value['bundle']['activation']['products'] = identities
        calls = []
        expected = value['bundle']
        class OriginalProductsProvider:
            def __enter__(self):return self
            def __exit__(self, *_):calls.append('close')
            def bind(self, plan, private):
                self_test.assertEqual(expected['plan'], plan)
                self_test.assertEqual(expected['privateConfig'], private)
                calls.append('bind')
            def bind_apps(self, plan):
                self_test.assertEqual(expected['plan'], plan)
                calls.append('bind-apps')
            def public_identities(self):return copy.deepcopy(identities)
        self_test = self
        def provider(_plan, _selection, _root):
            calls.append('open')
            return OriginalProductsProvider()
        proof, _ = self.authenticate(value, product_provider=provider)
        self.assertEqual('partial-budget-component', proof.values()['outcome'])
        self.assertEqual(['open', 'bind', 'bind-apps', 'close'], calls)
        changed = copy.deepcopy(value)
        changed['bundle']['activation']['products'] = []
        with self.assertRaisesRegex(ValueError, 'runtime-baseline-original-products-mismatch'):
            self.authenticate(changed, product_provider=provider)
        def unavailable(*_):raise products.ProductAdmissionError('synthetic-original-product-provider-unavailable')
        with self.assertRaises(products.ProductAdmissionError):self.authenticate(value, product_provider=unavailable)

    @staticmethod
    def rechain_reports(value):
        authorize, start, final = value['reports']
        start.update(previousReportDigest=evidence.digest(authorize), approvalReportDigest=evidence.digest(authorize))
        final.update(previousReportDigest=evidence.digest(start), approvalReportDigest=evidence.digest(authorize))
        bundle = value['bundle']
        final['checkpoint'] = {key: bundle['checkpoint'][key] for key in ('sequence', 'tailDigest', 'status')}
        final['checkpoint']['digest'] = evidence.digest(bundle['checkpoint'])
        now = dt.datetime.fromisoformat(CUTOFF)
        final['observation'] = evidence.verify(bundle['plan'], bundle['events'], bundle['checkpoint'], now=now)
        final['maintenanceMeasurements'] = maintenance.project(bundle['plan'], bundle['events'], bundle['checkpoint'], [], now=now)
        bundle['activation']['approvalReportDigest'] = evidence.digest(authorize)
        for report in value['reports']:supervisor.validate_report(report)


if __name__ == '__main__':
    unittest.main()

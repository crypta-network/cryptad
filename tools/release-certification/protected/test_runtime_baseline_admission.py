"""Synthetic original-context tests; seal constructors are test-only provider seams."""
import copy
import datetime as dt
import json
import os
import io
import tempfile
import zipfile
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import runtime_baseline_admission as admission
import runtime_baseline_approval as approval
import maintenance_runtime_projection as projection
import test_maintenance_runtime_projection as consumer_fixtures
from cryptad_certification.tests.test_runtime_pressure_evidence import evidence_fixture

UTC = dt.timezone.utc
CUTOFF = '2026-01-01T00:10:00+00:00'


def stamp(seconds):
    return (dt.datetime(2025, 12, 31, 23, 50, tzinfo=UTC) + dt.timedelta(seconds=seconds)).isoformat()


def vector():
    evidence = evidence_fixture()
    policy = evidence['policy']
    fingerprint = copy.deepcopy(evidence['series']['fingerprint'])
    fingerprint.update(sourceCommit='e' * 40, productDigest='sha256:' + 'e' * 64)
    campaign = {'schemaVersion': 1, 'kind': 'runtime-reference-campaign', 'campaignId': 'synthetic-campaign',
        'plannedAt': stamp(0), 'scope': 'daemon-resource-regression-unchanged-app-cohort',
        'evidenceClass': 'synthetic-local', 'referenceFingerprint': fingerprint,
        'policyDigest': admission.digest(policy), 'attempts': ['reference-1', 'reference-2'],
        'requiredRepetitions': 2, 'timeoutSeconds': 60, 'replacementOutcomes': [],
        'maximumReplacements': 0, 'concurrency': 'serial-exclusive'}
    rows = []
    for index in range(2):
        series = copy.deepcopy(evidence['series'])
        series.update(runId=campaign['attempts'][index], startedAt=stamp(20 + index * 40),
                      finishedAt=stamp(32 + index * 40), fingerprint=copy.deepcopy(fingerprint))
        series['selection']['selectedAt'] = stamp(10)
        for sample in series['samples']:
            sample['epoch'] = 'reference-process-' + str(index)
        rows.append({'experimentId': series['runId'], 'planDigest': 'sha256:' + str(index + 1) * 64,
            'origin': {'runId': 100 + index, 'runAttempt': 1, 'jobId': 200 + index},
            'producer': {}, 'campaign': copy.deepcopy(campaign), 'selection': None,
            'activationDigest': 'sha256:' + '4' * 64, 'checkpointDigest': 'sha256:' + '5' * 64,
            'startedAt': stamp(15 + index * 40), 'finishedAt': stamp(35 + index * 40),
            'outcome': 'pass', 'series': series, 'policy': copy.deepcopy(policy),
            'role': 'candidate-sender', 'epoch': 'reference-process-' + str(index), 'findings': []})
    return campaign, rows, policy


def originals(rows):
    return [admission.OriginalRuntimeObservation(admission._SEAL, row) for row in rows]


def proposal_vector():
    campaign, rows, policy = vector()
    return admission.prepare_proposal(campaign, originals(rows), policy)


def candidate_vector(proposal):
    helper = consumer_fixtures.MaintenanceRuntimeProjectionTest()
    fixture = helper.scheduler_fixture()
    plan, events, checkpoint, _products = fixture
    attached = next(event for event in events if 'runtimeEvidence' in event)
    selection = {'schemaVersion': 1, 'proposalDigest': admission.digest(proposal),
        'baselineDigest': proposal['baselineSemanticDigest'], 'approvalContext': 'f' * 64,
        'policyDigest': admission.digest(proposal['baseline']['policy']), 'selectedAt': stamp(300),
        'role': attached['role'], 'scope': proposal['campaign']['scope'], 'approvalOrigin': {}}
    series = attached['runtimeEvidence']['series']
    # Reference and candidate cohorts must match; source/product alone may differ.
    for key in admission.baseline.COMPARABLE:
        series['fingerprint'][key] = proposal['campaign']['referenceFingerprint'][key]
    # Native journal checks bind the app cohort, so adopt its exact selected app roster upstream.
    node = next(node for node in plan['nodes'] if node['role'] == attached['role'])
    series['fingerprint']['appCohortDigest'] = admission.digest(node['appDigests'])
    series['selection'] = {key: selection[key] for key in ('baselineDigest', 'policyDigest', 'selectedAt')}
    consumer_fixtures.rechain(events)
    checkpoint = consumer_fixtures.checkpoint_for(plan, events)
    fixture = plan, events, checkpoint, fixture[3]
    observed = {'experimentId': plan['experimentId'], 'planDigest': admission.digest(plan),
        'origin': {'runId': 900, 'runAttempt': 1, 'jobId': 901}, 'producer': plan['producer'],
        'campaign': None, 'selection': selection, 'activationDigest': 'sha256:' + '7' * 64,
        'checkpointDigest': admission.digest(checkpoint), 'startedAt': events[0]['wallTime'],
        'finishedAt': events[-1]['wallTime'], 'outcome': 'pass', 'series': series,
        'policy': attached['runtimeEvidence']['policy'], 'role': attached['role'],
        'epoch': attached['nodeEpoch'], 'findings': []}
    binding = {key: observed[key] for key in ('planDigest', 'activationDigest', 'role', 'epoch', 'checkpointDigest')}
    binding.update(sourceCommit=series['fingerprint']['sourceCommit'], productDigest=series['fingerprint']['productDigest'])
    return fixture, selection, admission.OriginalRuntimeObservation(admission._SEAL, observed), binding


def prepared_pair():
    campaign, rows, policy = vector()
    helper = consumer_fixtures.MaintenanceRuntimeProjectionTest()
    plan = helper.scheduler_fixture()[0]
    cohort = admission.digest(next(node['appDigests'] for node in plan['nodes'] if node['role'] == 'candidate-sender'))
    campaign['referenceFingerprint']['appCohortDigest'] = cohort
    for row in rows:
        row['campaign'] = copy.deepcopy(campaign)
        row['series']['fingerprint']['appCohortDigest'] = cohort
    proposal = admission.prepare_proposal(campaign, originals(rows), policy)
    return proposal, candidate_vector(proposal)


def decision_vector(proposal):
    return {'proposalDigest': admission.digest(proposal), 'proposalByteDigest': admission.byte_digest(admission.encode(proposal)),
        'approvalContext': 'f' * 64, 'approvalCompletedBy': stamp(200), 'effectiveAt': stamp(100),
        'expiresAt': '2026-01-02T00:00:00+00:00', 'status': 'active', 'originalCoordinates': {},
        'policyDigest': admission.digest(proposal['baseline']['policy']),
        'scopeDigest': admission.digest(proposal['campaign']['scope'])}


def reference_vectors(proposal):
    """Recreate explicit synthetic original-provider vectors, never production credentials."""
    _, rows, _ = vector()
    for index, row in enumerate(rows):
        row['campaign'] = copy.deepcopy(proposal['campaign'])
        row['series'] = copy.deepcopy(proposal['baseline']['referenceSeries'][index])
    return originals(rows)


class RuntimeBaselineAdmissionTest(unittest.TestCase):
    def test_original_references_actual_approval_and_original_candidate_reach_consumer(self):
        """Compose original member verifiers and native approval storage without seal bypasses."""
        if not hasattr(os, 'geteuid') or os.geteuid() != 0:
            self.skipTest('isolated sudo invocation required for real root ownership checks')
        import cross_version_supervisor_authority as supervisor
        import test_runtime_baseline_approval as approval_fixtures
        from original_artifact_authentication import OriginalArtifact
        from cryptad_certification.tests.test_phase_12_runtime_adapters import supervisor_fixture
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'interop'))
        import scheduler_pressure_runtime as collector
        from test_scheduler_runtime_inputs import snapshot
        common_snapshot = snapshot()
        derived = collector.derive_snapshot_fingerprints(common_snapshot)
        helper = consumer_fixtures.MaintenanceRuntimeProjectionTest()
        initial = helper.scheduler_fixture()
        initial_series = next(event['runtimeEvidence']['series'] for event in initial[1] if 'runtimeEvidence' in event)
        campaign, _, policy = vector()
        campaign['plannedAt'] = '2025-12-31T23:30:00+00:00'
        campaign['timeoutSeconds'] = 120
        campaign['referenceFingerprint'] = {**initial_series['fingerprint'], **derived,
                                           'sourceCommit': 'e' * 40, 'productDigest': 'sha256:' + 'e' * 64}

        def authenticate_execution(experiment, offset, run_base, *, selected=None):
            plan, events, _, products = helper.scheduler_fixture()
            plan.update(experimentId=experiment, provenanceClass='source-build-comparison')
            attachment = next(event for event in events if 'runtimeEvidence' in event)
            evidence = attachment['runtimeEvidence']
            series = evidence['series']
            reference = selected is None
            node = next(node for node in plan['nodes'] if node['role'] == attachment['role'])
            if reference:
                for selected_node in plan['nodes']:
                    if selected_node['role'].startswith('candidate-'):
                        selected_node.update(sourceCommit='e' * 40, artifactDigest='sha256:' + 'e' * 64)
                        next(row for row in products if row['role'] == selected_node['role']).update(
                            sourceCommit=selected_node['sourceCommit'], artifactDigest=selected_node['artifactDigest'])
            series.update(runId=experiment)
            series['fingerprint'].update(derived, sourceCommit=node['sourceCommit'], productDigest=node['artifactDigest'])
            evidence['configurationDigest'] = derived['configurationDigest']
            for key in ('startedAt', 'finishedAt'):
                series[key] = (dt.datetime.fromisoformat(series[key]) + dt.timedelta(seconds=offset)).isoformat()
            if selected is None:
                series['selection']['selectedAt'] = series['startedAt']
            else:
                series['selection'] = {key: selected[key] for key in ('baselineDigest', 'policyDigest', 'selectedAt')}
            for sample in series['samples']:
                sample['epoch'] = 'series-process-' + str(run_base)
            node_epochs = {epoch: format(run_base + index, '032x') for index, epoch in enumerate(
                sorted({event['nodeEpoch'] for event in events if event.get('nodeEpoch')}))}
            for event in events:
                event['wallTime'] = (dt.datetime.fromisoformat(event['wallTime']) + dt.timedelta(seconds=offset)).isoformat()
                event['planDigest'] = admission.digest(plan)
                if event.get('nodeEpoch'):
                    event['nodeEpoch'] = node_epochs[event['nodeEpoch']]
                if event.get('peerNodeEpoch'):
                    event['peerNodeEpoch'] = node_epochs[event['peerNodeEpoch']]
            # Native causal timestamps shift with the measured execution, preserving terminal timing.
            for event in evidence['workEvents']:
                event['observedAt'] = (dt.datetime.fromisoformat(event['observedAt']) + dt.timedelta(seconds=offset)).isoformat()
                if event['sourceSampledAtEpochMillis']:
                    event['sourceSampledAtEpochMillis'] += offset * 1000
                if event['windowStartEpochSecond']:
                    window = 3600 if event['operation'] in {'subscription_poll', 'subscription_manual_refresh', 'trust_graph_import'} else 60
                    event['windowStartEpochSecond'] = ((event['windowStartEpochSecond'] + offset) // window) * window
            for sample in evidence['contentFetchSamples']:
                sample['sampledAtEpochMillis'] += offset * 1000
            consumer_fixtures.rechain(events)
            checkpoint = consumer_fixtures.checkpoint_for(plan, events)
            input_snapshot = copy.deepcopy(common_snapshot)
            input_snapshot['fingerprint'] = copy.deepcopy(series['fingerprint'])
            private = {'runtimeBaseline': selected} if selected else {}
            authorization = {'runtimeReference': campaign} if reference else {}
            chain = supervisor_fixture(plan, events, checkpoint)
            bindings = {'serviceDigest': chain[-1]['report']['serviceDigest'],
                **{field: admission.byte_digest(admission.encode(value)) for field, value in (
                    ('planDigest', plan), ('privateConfigDigest', private), ('authorizationDigest', authorization))}}
            for number, entry in enumerate(reversed(chain)):
                origin, report = entry['origin'], entry['report']
                origin.update(runId=run_base + number, artifactId=run_base + number,
                    sourceFamily='cross-version-supervisor', sourceCommit=plan['producer']['sourceCommit'],
                    artifactName=f'cross-version-supervisor-{run_base + number}-1', jobId=run_base + number + 1000)
                report['job'] = {key: origin[key] for key in ('sourceCommit', 'runId', 'runAttempt')}
                report['selectionDigest'] = admission.digest(bindings)
                if report['operation'] != 'authorize':
                    report['approvalReportDigest'] = admission.digest(chain[-1]['report'])
            chain[-2]['report']['previousReportDigest'] = admission.digest(chain[-1]['report'])
            chain[0]['report'].update(previousReportDigest=admission.digest(chain[-2]['report']),
                observation=admission.verify(plan, events, checkpoint, now=dt.datetime.fromisoformat(CUTOFF)))
            activation = {'planDigest': admission.digest(plan), 'producer': plan['producer'],
                'approvalOrigin': chain[-1]['origin'], 'approvalReportDigest': admission.digest(chain[-1]['report'])}
            bundle = {'plan': plan, 'events': events, 'checkpoint': checkpoint, 'privateConfig': private,
                'authorization': authorization, 'privateAuthorization': None, 'inputSnapshot': input_snapshot,
                'activation': activation, 'rawInputs': {key: admission.encode(value).decode() for key, value in
                    (('plan', plan), ('private-config', private), ('authorization', authorization))}}
            def original(coordinates, _root):
                entry = next(row for row in chain if row['origin'] == coordinates)
                raw = io.BytesIO()
                with zipfile.ZipFile(raw, 'w') as archive:
                    archive.writestr('cross-version-supervisor.json', admission.encode(entry['report']))
                return OriginalArtifact(raw.getvalue(), coordinates, CUTOFF)
            def attest(args, _environment):
                report = json.loads(Path(args[2]).read_bytes())
                invocation = f"https://github.com/crypta-network/cryptad/actions/runs/{report['job']['runId']}/attempts/1"
                return [{'verificationResult': {'signature': {'certificate': {'runInvocationURI': invocation}}}}]
            with tempfile.TemporaryDirectory() as scratch, patch.object(supervisor, 'authenticate_original', side_effect=original), \
                    patch.object(supervisor, '_gh', side_effect=attest), patch.object(supervisor, '_environment', return_value={}):
                observed = admission.authenticate_observation(chain[0]['origin'], bundle, Path(scratch), cutoff=CUTOFF)
            return observed, (plan, events, checkpoint, products)

        references = [authenticate_execution('reference-1', -1200, 100)[0],
                      authenticate_execution('reference-2', -900, 200)[0]]
        proposal = admission.prepare_proposal(campaign, references, policy)
        reviewer = approval_fixtures.ApprovalTest()
        reviewer.setUp()
        self.addCleanup(reviewer.doCleanups)
        reviewer.proposal = admission.encode(proposal)
        reviewer.request.update(proposalDigest=admission.digest(proposal), proposalByteDigest=admission.byte_digest(reviewer.proposal),
            proposalFinishedAt=proposal['finishedAt'], policyDigest=admission.digest(policy),
            scopeDigest=admission.digest(campaign['scope']), effectiveAt=stamp(100), expiresAt='2026-01-02T00:00:00+00:00')
        reviewer.job.update(started_at=stamp(150), completed_at=stamp(200))
        reviewer.kwargs.update(proposal_digest=reviewer.request['proposalDigest'],
            proposal_byte_digest=reviewer.request['proposalByteDigest'], proposal_finished_at=proposal['finishedAt'], cutoff=CUTOFF)
        original_provider = reviewer.original
        def approval_original(coordinates, root):
            result = original_provider(coordinates, root)
            return OriginalArtifact(result.content, result.coordinates, stamp(110)) if coordinates['sourceFamily'] == 'runtime-baseline-proposal' else result
        reviewer.original = approval_original
        approved = reviewer.verify()
        selection = {'schemaVersion': 1, 'proposalDigest': admission.digest(proposal),
            'baselineDigest': proposal['baselineSemanticDigest'], 'approvalContext': approved.decision()['approvalContext'],
            'approvalOrigin': approved.decision()['originalCoordinates'], 'policyDigest': admission.digest(policy),
            'selectedAt': stamp(300), 'role': 'candidate-sender', 'scope': campaign['scope']}
        candidate, fixture = authenticate_execution('candidate-execution', 0, 300, selected=selection)
        capability = admission.admit_candidate(proposal, approved, selection, candidate, cutoff=CUTOFF,
                                               original_references=references)
        original = candidate.values()
        binding = {key: original[key] for key in ('planDigest', 'activationDigest', 'checkpointDigest', 'role', 'epoch')}
        binding.update({key: original['series']['fingerprint'][key] for key in ('sourceCommit', 'productDigest')})
        result = projection.project(*fixture, now=dt.datetime.fromisoformat(CUTOFF),
            authenticated_baseline=capability, baseline_binding=binding)
        self.assertEqual('observed', result['runtimeBaselineAdmission']['status'])
        self.assertEqual('synthetic', result['runtimeBaselineAdmission']['evidenceClass'])
        self.assertTrue(all(row['status'] == 'blocked' for row in result['rows']))
        self.assertIn('original-production-products-required', result['subjectAdmission']['blockers'])
        self.assertEqual('not-observed', result['runtimeBaselineAdmission']['fullAppBudgets'])

    def test_owned_stopped_producer_reads_confined_inputs_and_recomputes_component(self):
        if not hasattr(os, 'geteuid') or os.geteuid() != 0:
            self.skipTest('isolated sudo invocation required for real private-root ownership checks')
        import cross_version_supervisor_authority as supervisor
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'interop'))
        import scheduler_pressure_runtime as collector
        from test_scheduler_runtime_inputs import snapshot
        private_snapshot = snapshot()
        fingerprints = collector.derive_snapshot_fingerprints(private_snapshot)
        prior, _ = prepared_pair()
        references = [item.values() for item in reference_vectors(prior)]
        campaign = copy.deepcopy(prior['campaign'])
        campaign['referenceFingerprint'].update(fingerprints)
        for row in references:
            row['campaign'] = campaign
            row['series']['fingerprint'].update(fingerprints)
        proposal = admission.prepare_proposal(campaign, originals(references), prior['baseline']['policy'])
        fixture, selection, _, _ = candidate_vector(proposal)
        plan, events, checkpoint, products = fixture
        attached = next(event for event in events if 'runtimeEvidence' in event)
        attached['runtimeEvidence']['configurationDigest'] = fingerprints['configurationDigest']
        consumer_fixtures.rechain(events)
        checkpoint = consumer_fixtures.checkpoint_for(plan, events)
        private_snapshot['fingerprint'] = copy.deepcopy(attached['runtimeEvidence']['series']['fingerprint'])
        approved = approval.AuthenticatedApproval(approval._AUTHORITY, decision_vector(proposal))
        class FrozenClock(dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return cls.fromisoformat(CUTOFF)
        with tempfile.TemporaryDirectory(dir='/run') as temporary:
            root = Path(temporary)
            state, authority, runtime = (root / name for name in ('state', 'authority', 'runtime'))
            for path in (state, authority, runtime, state / 'selected', runtime / 'scheduler-observation'):
                path.mkdir(mode=0o700)
            activation = {'schemaVersion': 1, 'planDigest': admission.digest(plan), 'producer': plan['producer'],
                          'ownerUid': 0}
            values = {'plan': plan, 'private-config': {'root': str(runtime), 'runtimeBaseline': selection},
                      'authorization': {}, 'service-selection': {}}
            for name, value in values.items():
                path = state / 'selected' / (name + '.json')
                path.write_bytes(admission.encode(value))
                path.chmod(0o600)
            activation_file = authority / 'activation.json'
            activation_file.write_bytes(admission.encode(activation))
            activation_file.chmod(0o600)
            snapshot_file = runtime / 'scheduler-observation/runtime-input-snapshot.json'
            snapshot_file.write_bytes(admission.encode(private_snapshot))
            snapshot_file.chmod(0o600)
            with patch.object(supervisor, 'STATE', state), patch.object(supervisor, 'AUTHORITY', authority), \
                    patch.object(supervisor, '_service_state', return_value='stopped'), \
                    patch.object(admission, 'authenticate_selected', return_value=(proposal, approved, originals(references))), \
                    patch.object(admission.dt, 'datetime', FrozenClock):
                arguments = admission.project_owned_baseline(plan, events, checkpoint, activation)
                result = projection.project(plan, events, checkpoint, products, **arguments)
                self.assertEqual('observed', result['runtimeBaselineAdmission']['status'])
                self.assertEqual(5, result['schemaVersion'])
                snapshot_file.chmod(0o644)
                with self.assertRaisesRegex(admission.AdmissionError, 'private-observation-unavailable'):
                    admission.project_owned_baseline(plan, events, checkpoint, activation)

    def test_sealed_report6_reaches_phase12_owner_without_private_commitments(self):
        self.test_report6_reaches_phase12_owner_with_exact_typed_context(sealed=True)

    def test_sealed_uncompared_report6_reaches_phase12_owner_without_baseline_authority(self):
        self.test_report6_reaches_phase12_owner_with_exact_typed_context(sealed=True, uncompared=True)

    def test_report6_reaches_phase12_owner_with_exact_typed_context(self, sealed=False, uncompared=False):
        from cryptad_certification import phase_12_runtime_adapters as phase
        from cryptad_certification.tests.test_phase_12_runtime_adapters import supervisor_fixture
        import cross_version_supervisor_authority as supervisor
        proposal, (fixture, selection, observed, binding) = prepared_pair()
        plan, events, checkpoint, products = fixture
        private_products = None
        outward = products
        if sealed:
            import cross_version_product_admission as product_owner
            products.sort(key=lambda row: row['role'])
            for row in products:
                row['frozenPortableBinding'] = 'existing-maintenance-freeze-exact-product-v3'
                row['sealedRuntimeBinding'] = {
                    'descriptor': {'fileName': 'runtime-companion.json', 'sizeBytes': 512,
                                   'digest': 'sha256:' + 'a' * 64},
                    'ciphertextDigest': 'sha256:' + 'b' * 64}
                row['requiredAppIds'] = ['private-selected-baseline-canary']
            private_products = product_owner.AuthenticatedProducts(product_owner._SEAL, admission.digest(plan),
                {row['role']: row for row in products})
            self.addCleanup(private_products.close)
            outward = private_products.public_identities()
        capability = self.capability(proposal, selection, observed)
        now = dt.datetime.fromisoformat(CUTOFF)
        measured = projection.project(*fixture, now=now,
                                      **({} if uncompared else {'authenticated_baseline': capability, 'baseline_binding': binding}),
                                      **({'public_products': outward} if sealed else {}))
        if uncompared:
            measured = projection.without_current_baseline(measured, selection['scope'])
        chain = supervisor_fixture(plan, events, checkpoint)
        for entry in chain:
            entry['report'].update(schemaVersion=5, admittedProductsDigest=admission.digest(outward))
        chain[0]['report'].update(schemaVersion=6, maintenanceMeasurements=measured,
            observation=admission.verify(plan, events, checkpoint, now=now))
        for entry in chain[:-1]:
            entry['report']['approvalReportDigest'] = admission.digest(chain[-1]['report'])
        chain[-2]['report']['previousReportDigest'] = admission.digest(chain[-1]['report'])
        chain[0]['report']['previousReportDigest'] = admission.digest(chain[-2]['report'])
        for entry in chain:
            supervisor.validate_report(entry['report'])
        original = observed.values()
        original['origin'] = chain[0]['origin']
        original['selection'] = selection
        authority = phase._AuthenticatedSupervisor(chain, phase._ORIGINAL_SUPERVISOR,
            runtime_baseline=None if uncompared else capability, baseline_binding=binding, private_products=private_products,
            runtime_observation=admission.OriginalRuntimeObservation(admission._SEAL, original) if uncompared else None)
        values = {'plan.json': plan, 'events.json': events, 'checkpoint.json': checkpoint, 'products.json': outward}
        payloads = {name: admission.encode(value) for name, value in values.items()}
        final, _ = phase._supervisor_relationships(authority, values, now)
        self.assertEqual(6, final['schemaVersion'])
        with tempfile.TemporaryDirectory() as temporary:
            # macOS temporary roots can have symlinked parents; the owner requires a canonical path.
            scratch = Path(temporary).resolve(strict=True)
            result = phase.verify_authenticated('maintenance-measurements', payloads, CUTOFF, scratch, authority)
            self.assertEqual('not-observed' if uncompared else 'observed', result['components']['scopedRuntimeBaseline']['status'])
            self.assertEqual('partial', result['dimensions']['coverage'])
            self.assertIn('maintenance-required-consumer-adapters-incomplete', result['blockers'])
            self.assertNotIn('private-selected-baseline-canary', json.dumps(result))
            missing = phase._AuthenticatedSupervisor(chain, phase._ORIGINAL_SUPERVISOR, private_products=private_products)
            blocked = phase.verify_authenticated('maintenance-measurements', payloads, CUTOFF, scratch, missing)
            self.assertIn('runtime-baseline-private-original-context-required', blocked['blockers'])
            if uncompared:
                return
            rebound = phase._AuthenticatedSupervisor(chain, phase._ORIGINAL_SUPERVISOR,
                runtime_baseline=capability, baseline_binding={**binding, 'epoch': 'other'}, private_products=private_products)
            with self.assertRaisesRegex(ValueError, 'phase12-runtime-original-admission-rejected'):
                phase.verify_authenticated('maintenance-measurements', payloads, CUTOFF, scratch, rebound)

    def test_uncompared_original_reports_reach_consumer_without_approval_or_candidate_admission(self):
        if not hasattr(os, 'geteuid') or os.geteuid() != 0:
            self.skipTest('isolated sudo invocation required for original private retention')
        for status in ('complete', 'failed', 'partial'):
            with self.subTest(status=status):
                self.test_original_candidate_chain_member_snapshot_and_checkpoint_are_reverified(terminal_status=status)

    def test_original_candidate_chain_member_snapshot_and_checkpoint_are_reverified(self, terminal_status=None):
        import cross_version_supervisor_authority as supervisor
        from original_artifact_authentication import OriginalArtifact
        from cryptad_certification.tests.test_phase_12_runtime_adapters import supervisor_fixture
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'interop'))
        import scheduler_pressure_runtime as collector
        from test_scheduler_runtime_inputs import snapshot
        helper = consumer_fixtures.MaintenanceRuntimeProjectionTest()
        plan, events, checkpoint, products = helper.scheduler_fixture()
        plan['provenanceClass'] = 'source-build-comparison'
        original_snapshot = snapshot()
        attachment = next(event for event in events if 'runtimeEvidence' in event)
        evidence = attachment['runtimeEvidence']
        original_snapshot['fingerprint'] = copy.deepcopy(evidence['series']['fingerprint'])
        derived = collector.derive_snapshot_fingerprints(original_snapshot)
        evidence['configurationDigest'] = derived['configurationDigest']
        evidence['series']['fingerprint'].update(derived)
        original_snapshot['fingerprint'] = copy.deepcopy(evidence['series']['fingerprint'])
        for event in events:
            event['planDigest'] = admission.digest(plan)
        if terminal_status in {'failed', 'partial'}:
            events.pop()
            events.insert(-1, {**events[-1], 'kind': 'fault',
                'outcome': 'fail' if terminal_status == 'failed' else 'partial',
                'role': '', 'scenario': '', 'operation': ''})
        consumer_fixtures.rechain(events)
        checkpoint = consumer_fixtures.checkpoint_for(plan, events)
        if terminal_status:
            checkpoint['status'] = terminal_status
        chain = supervisor_fixture(plan, events, checkpoint)
        authorization = {'runtimeReference': None}
        private = {'runtimeBaseline': prepared_pair()[1][1]} if terminal_status else {}
        if terminal_status:
            for entry in chain:
                entry['report'].update(schemaVersion=5, admittedProductsDigest=admission.digest(products))
            measured = projection.without_current_baseline(
                projection.project(plan, events, checkpoint, products, now=dt.datetime.fromisoformat(CUTOFF)),
                private['runtimeBaseline']['scope'])
            chain[0]['report'].update(schemaVersion=6, maintenanceMeasurements=measured)
        bindings = {'serviceDigest': chain[-1]['report']['serviceDigest'],
            'planDigest': admission.byte_digest(admission.encode(plan)),
            'privateConfigDigest': admission.byte_digest(admission.encode(private)),
            'authorizationDigest': admission.byte_digest(admission.encode(authorization))}
        for entry in reversed(chain):
            origin, report = entry['origin'], entry['report']
            origin.update(sourceFamily='cross-version-supervisor', sourceCommit=plan['producer']['sourceCommit'],
                artifactName=f"cross-version-supervisor-{origin['runId']}-1", jobId=origin['runId'] + 100)
            if terminal_status:
                from original_artifact_authentication import PRODUCERS
                origin.update(repository='crypta-network/cryptad', jobName=PRODUCERS['cross-version-supervisor'][2],
                              artifactDigest='sha256:' + 'c' * 64, artifactSize=100)
            report['job'] = {key: origin[key] for key in ('sourceCommit', 'runId', 'runAttempt')}
            report['selectionDigest'] = admission.digest(bindings)
            if report['operation'] != 'authorize':
                report['approvalReportDigest'] = admission.digest(chain[-1]['report'])
        chain[-2]['report']['previousReportDigest'] = admission.digest(chain[-1]['report'])
        chain[0]['report']['previousReportDigest'] = admission.digest(chain[-2]['report'])
        chain[0]['report']['observation'] = admission.verify(plan, events, checkpoint, now=dt.datetime.fromisoformat(CUTOFF))
        activation = {'planDigest': admission.digest(plan), 'producer': plan['producer'],
            'approvalOrigin': chain[-1]['origin'], 'approvalReportDigest': admission.digest(chain[-1]['report'])}
        bundle = {'plan': plan, 'events': events, 'checkpoint': checkpoint, 'privateConfig': private,
            'authorization': authorization, 'privateAuthorization': None, 'inputSnapshot': original_snapshot,
            'activation': activation, 'rawInputs': {key: admission.encode(value).decode() for key, value in
                (('plan', plan), ('private-config', private), ('authorization', authorization))}}
        def original(coordinates, _root):
            selected = next(row for row in chain if row['origin'] == coordinates)
            raw = io.BytesIO()
            with zipfile.ZipFile(raw, 'w') as archive:
                archive.writestr('cross-version-supervisor.json', admission.encode(selected['report']))
            return OriginalArtifact(raw.getvalue(), coordinates, CUTOFF)
        def attest(args, _environment):
            report = json.loads(Path(args[2]).read_bytes())
            invocation = f"https://github.com/crypta-network/cryptad/actions/runs/{report['job']['runId']}/attempts/1"
            return [{'verificationResult': {'signature': {'certificate': {'runInvocationURI': invocation}}}}]
        with tempfile.TemporaryDirectory(dir='/run' if terminal_status else None) as temporary, patch.object(supervisor, 'authenticate_original', side_effect=original), \
                patch.object(supervisor, '_gh', side_effect=attest), patch.object(supervisor, '_environment', return_value={}):
            observed = admission.authenticate_observation(chain[0]['origin'], bundle, Path(temporary) / 'good', cutoff=CUTOFF)
            self.assertEqual(evidence['series'], observed.values()['series'])
            self.assertEqual(admission.digest(checkpoint), observed.values()['checkpointDigest'])
            if terminal_status:
                from cryptad_certification import phase_12_runtime_adapters as phase
                store = Path(temporary) / 'observations'
                store.mkdir(mode=0o700)
                retained = store / (plan['experimentId'] + '.json')
                retained.write_bytes(admission.encode(bundle))
                retained.chmod(0o400)
                payloads = {name: admission.encode(value) for name, value in (
                    ('plan.json', plan), ('events.json', events), ('checkpoint.json', checkpoint), ('products.json', products))}
                proof = {'coordinates': chain[0]['origin'], 'members': phase.ORIGINAL_MEMBERS['maintenance-measurements']}
                with patch.object(approval, 'PRIVATE_STORE', Path(temporary)), \
                        patch.object(admission, 'authenticate_selected', side_effect=AssertionError('approval must not be reacquired')), \
                        patch.object(admission, 'admit_candidate', side_effect=AssertionError('terminal evidence is not candidate admission')):
                    result = phase.collect_and_verify('maintenance-measurements', payloads, CUTOFF, Path(temporary), proof)
                self.assertEqual('authenticated', result['originalProof']['state'])
                self.assertEqual(measured['runtimeBaselineAdmission'], result['components']['scopedRuntimeBaseline'])
                self.assertEqual('not-observed', result['components']['scopedRuntimeBaseline']['status'])
                self.assertIn('maintenance-required-consumer-adapters-incomplete', result['blockers'])
                forged = copy.deepcopy(chain)
                forged[0]['report']['maintenanceMeasurements']['runtimeBaselineAdmission']['reasons'] = ['runtime-baseline-approval-expired']
                with self.assertRaisesRegex(ValueError, 'phase12-runtime-original-admission-rejected'):
                    phase.verify_authenticated('maintenance-measurements', payloads, CUTOFF, Path(temporary),
                        phase._AuthenticatedSupervisor(forged, phase._ORIGINAL_SUPERVISOR, runtime_observation=observed))
                rebound = observed.values()
                rebound['checkpointDigest'] = 'sha256:' + '0' * 64
                with self.assertRaisesRegex(ValueError, 'phase12-runtime-original-admission-rejected'):
                    phase.verify_authenticated('maintenance-measurements', payloads, CUTOFF, Path(temporary),
                        phase._AuthenticatedSupervisor(chain, phase._ORIGINAL_SUPERVISOR,
                            runtime_observation=admission.OriginalRuntimeObservation(admission._SEAL, rebound)))
            altered = copy.deepcopy(bundle)
            altered['inputSnapshot']['jvmConfiguration']['heapMaxBytes'] *= 2
            with self.assertRaisesRegex(admission.AdmissionError, 'snapshot-mismatch'):
                admission.authenticate_observation(chain[0]['origin'], altered, Path(temporary) / 'wrong', cutoff=CUTOFF)

    def test_actual_approval_producer_verifier_and_owning_consumer(self):
        if not hasattr(os, 'geteuid') or os.geteuid() != 0:
            self.skipTest('isolated sudo invocation required for real private-root ownership checks')
        import test_runtime_baseline_approval as approval_fixtures
        helper = approval_fixtures.ApprovalTest()
        helper.setUp()
        self.addCleanup(helper.doCleanups)
        proposal, (fixture, selection, observed, binding) = prepared_pair()
        helper.proposal = admission.encode(proposal)
        helper.request.update(proposalDigest=admission.digest(proposal),
            proposalByteDigest=admission.byte_digest(helper.proposal), proposalFinishedAt=proposal['finishedAt'],
            policyDigest=admission.digest(proposal['baseline']['policy']), scopeDigest=admission.digest(proposal['campaign']['scope']),
            effectiveAt=stamp(100), expiresAt='2026-01-02T00:00:00+00:00')
        helper.job.update(started_at=stamp(150), completed_at=stamp(200))
        helper.kwargs.update(proposal_digest=helper.request['proposalDigest'],
            proposal_byte_digest=helper.request['proposalByteDigest'],
            proposal_finished_at=proposal['finishedAt'], cutoff=CUTOFF)
        # Keep the existing native preparation/member verifier intact; only original provider
        # clocks and network responses are deterministic synthetic inputs.
        original_provider = helper.original
        def original(coordinates, root):
            result = original_provider(coordinates, root)
            if coordinates['sourceFamily'] == 'runtime-baseline-proposal':
                from original_artifact_authentication import OriginalArtifact
                return OriginalArtifact(result.content, result.coordinates, stamp(110))
            return result
        helper.original = original
        verified = helper.verify()
        selection['approvalOrigin'] = helper.coords
        row = observed.values()
        row['selection'] = selection
        observed = admission.OriginalRuntimeObservation(admission._SEAL, row)
        capability = admission.admit_candidate(proposal, verified, selection, observed, cutoff=CUTOFF, original_references=reference_vectors(proposal))
        result = projection.project(*fixture, now=dt.datetime.fromisoformat(CUTOFF),
            authenticated_baseline=capability, baseline_binding=binding)
        self.assertEqual('observed', result['runtimeBaselineAdmission']['status'])
        self.assertEqual('synthetic', result['runtimeBaselineAdmission']['evidenceClass'])
        self.assertTrue(all(row['status'] == 'blocked' for row in result['rows']))
        with self.assertRaises(admission.AdmissionError):
            admission.admit_candidate(proposal, verified, {**selection, 'approvalContext': '0' * 64},
                                      observed, cutoff=CUTOFF, original_references=reference_vectors(proposal))

    def test_original_repetitions_collect_exact_fixed_statistics_without_review(self):
        proposal = proposal_vector()
        self.assertIsNone(proposal['baseline']['review'])
        self.assertEqual(['accepted', 'accepted'], [row['disposition'] for row in proposal['attemptLedger']])
        for assessed in proposal['baseline']['assessments']:
            for phase in ('reference', 'recovery', 'sustained'):
                metrics = assessed['phases'][phase]['metrics']['rssBytes']
                self.assertEqual(100, metrics['median'])
                self.assertEqual(100, metrics['p95'])
                self.assertEqual(100, metrics['peak'])
                self.assertEqual(0, metrics['slopePerSecond'])

    def test_renamed_copied_overlapping_and_reordered_references_reject(self):
        mutations = [lambda rows: rows[1].update(origin=rows[0]['origin']),
            lambda rows: rows[1].update(epoch=rows[0]['epoch']),
            lambda rows: rows[1].update(startedAt=rows[0]['startedAt']),
            lambda rows: [sample.update(epoch='reference-process-0') for sample in rows[1]['series']['samples']],
            lambda rows: rows.reverse()]
        for mutate in mutations:
            campaign, rows, policy = vector()
            mutate(rows)
            with self.assertRaises(admission.AdmissionError):
                admission.prepare_proposal(campaign, originals(rows), policy)

    def test_observation_and_capability_hold_immutable_defensive_values(self):
        proposal, (_, selection, observed, _) = prepared_pair()
        original = observed.values()
        original['series']['samples'][0]['metrics']['rssBytes'] = 999
        self.assertEqual(100, observed.values()['series']['samples'][0]['metrics']['rssBytes'])
        capability = self.capability(proposal, selection, observed)
        for value in (observed, capability):
            with self.assertRaises(admission.AdmissionError):
                value._raw = b'{}'

    def test_original_journal_integrity_failure_cannot_be_numerically_accepted(self):
        campaign, rows, policy = vector()
        rows[0]['findings'] = ['journal-lineage-invalid']
        with self.assertRaises(admission.AdmissionError):
            admission.prepare_proposal(campaign, originals(rows), policy)

    def test_planned_failed_attempt_is_retained_and_cannot_be_silently_removed(self):
        campaign, rows, policy = vector()
        campaign.update(attempts=['failed-attempt', 'reference-1', 'reference-2'], maximumReplacements=1,
                        replacementOutcomes=['failed'])
        failed = copy.deepcopy(rows[0])
        failed.update(experimentId='failed-attempt', series=None, startedAt=stamp(1), finishedAt=stamp(5),
                      outcome='fail', origin={'runId': 99, 'runAttempt': 1, 'jobId': 199})
        rows.insert(0, failed)
        for row in rows:
            row['campaign'] = copy.deepcopy(campaign)
        result = admission.prepare_proposal(campaign, originals(rows), policy)
        self.assertEqual(['failed', 'accepted', 'accepted'], [row['disposition'] for row in result['attemptLedger']])
        with self.assertRaisesRegex(admission.AdmissionError, 'roster-mismatch'):
            admission.prepare_proposal(campaign, originals(rows[1:]), policy)

    def test_invalid_progress_phase_metric_gap_and_dispersion_do_not_approve(self):
        mutations = [lambda row: row['series']['samples'][4]['metrics'].update(rssBytes=None),
            lambda row: row['series']['samples'][4]['work'].update(successful=0, failed=1),
            lambda row: row['series']['samples'][4].update(intervalMillis=2000),
            lambda row: [sample['metrics'].update(rssBytes=200) for sample in row['series']['samples']],
            lambda row: row['series']['samples'][4].update(phase='warmup')]
        for mutate in mutations:
            campaign, rows, policy = vector()
            mutate(rows[1])
            with self.assertRaises((admission.AdmissionError, admission.baseline.BaselineError)):
                admission.prepare_proposal(campaign, originals(rows), policy)

    def test_local_review_or_plain_decision_cannot_construct_authority(self):
        proposal, (_, selection, observed, _) = prepared_pair()
        with self.assertRaises(admission.AdmissionError):
            admission.admit_candidate(proposal, decision_vector(proposal), selection, observed, cutoff=CUTOFF, original_references=reference_vectors(proposal))
        with self.assertRaises(admission.AdmissionError):
            admission.AuthenticatedRuntimeBaseline(None, proposal, {}, selection, observed, CUTOFF)
        with self.assertRaises(admission.AdmissionError):
            admission.OriginalRuntimeObservation(None, {})

    def test_exact_approval_still_requires_original_reference_recomputation(self):
        proposal, (_, selection, observed, _) = prepared_pair()
        approved = approval.AuthenticatedApproval(approval._AUTHORITY, decision_vector(proposal))
        for references in ([], [row.values() for row in reference_vectors(proposal)],
                           reference_vectors(proposal)[:1]):
            with self.assertRaises(admission.AdmissionError):
                admission.admit_candidate(proposal, approved, selection, observed, cutoff=CUTOFF,
                                          original_references=references)

    def test_regression_requires_both_product_and_source_to_differ(self):
        for key in ('sourceCommit', 'productDigest'):
            proposal, (_, selection, observed, _) = prepared_pair()
            row = observed.values()
            row['series']['fingerprint'][key] = proposal['campaign']['referenceFingerprint'][key]
            with self.assertRaisesRegex(admission.AdmissionError, 'comparison-scope-invalid'):
                self.capability(proposal, selection, admission.OriginalRuntimeObservation(admission._SEAL, row))

    def test_same_product_comparison_is_explicitly_repeatability(self):
        prior, _ = prepared_pair()
        references = [item.values() for item in reference_vectors(prior)]
        campaign = copy.deepcopy(prior['campaign'])
        campaign['scope'] = 'same-product-repeatability'
        for row in references:
            row['campaign'] = campaign
        proposal = admission.prepare_proposal(campaign, originals(references), prior['baseline']['policy'])
        _, selection, observed, binding = candidate_vector(proposal)
        row = observed.values()
        for key in ('sourceCommit', 'productDigest'):
            row['series']['fingerprint'][key] = campaign['referenceFingerprint'][key]
            binding[key] = campaign['referenceFingerprint'][key]
        capability = self.capability(proposal, selection, admission.OriginalRuntimeObservation(admission._SEAL, row))
        result = capability.compare_candidate(row['series'], binding=binding, cutoff=CUTOFF, candidate_policy=row['policy'])
        self.assertEqual('observed', result['status'])
        self.assertEqual('same-product-repeatability', result['scope'])

    def capability(self, proposal, selection, observed, decision=None):
        approved = approval.AuthenticatedApproval(approval._AUTHORITY, decision or decision_vector(proposal))
        return admission.admit_candidate(proposal, approved, selection, observed, cutoff=CUTOFF, original_references=reference_vectors(proposal))

    def test_candidate_cannot_reuse_reference_plan_node_or_sample_epoch(self):
        for field in ('planDigest', 'epoch', 'sampleEpoch'):
            with self.subTest(field=field):
                proposal, (_, selection, observed, _) = prepared_pair()
                row = observed.values()
                reference = reference_vectors(proposal)[0].values()
                if field == 'sampleEpoch':
                    for sample in row['series']['samples']:
                        sample['epoch'] = reference['series']['samples'][0]['epoch']
                else:
                    row[field] = reference[field]
                with self.assertRaises(admission.AdmissionError):
                    self.capability(proposal, selection,
                        admission.OriginalRuntimeObservation(admission._SEAL, row))

    def test_actual_capability_recomputes_and_owning_consumer_removes_only_baseline_blocker(self):
        proposal, (fixture, selection, observed, binding) = prepared_pair()
        capability = self.capability(proposal, selection, observed)
        result = projection.project(*fixture, now=dt.datetime.fromisoformat(CUTOFF),
            authenticated_baseline=capability, baseline_binding=binding)
        self.assertIs(result, projection.validate(result))
        self.assertEqual('observed', result['runtimeBaselineAdmission']['status'])
        performance = next(row for row in result['rows'] if row['id'] == projection.PREFIX + 'performance')
        self.assertNotIn('reviewed-runtime-baseline-missing', performance['blockers'])
        self.assertTrue(all(row['status'] == 'blocked' for row in result['rows']))
        self.assertEqual('not-observed', result['runtimeBaselineAdmission']['fullAppBudgets'])
        encoded = json.dumps(result['runtimeBaselineAdmission'])
        for fingerprint in proposal['campaign']['referenceFingerprint'].values():
            self.assertNotIn(fingerprint, encoded)

    def test_wrong_binding_series_policy_and_cutoff_cannot_reuse_capability(self):
        proposal, (_, selection, observed, binding) = prepared_pair()
        capability = self.capability(proposal, selection, observed)
        row = observed.values()
        for field in binding:
            changed = {**binding, field: 'substituted'}
            with self.assertRaises(admission.AdmissionError):
                capability.compare_candidate(row['series'], binding=changed, cutoff=CUTOFF, candidate_policy=row['policy'])
        with self.assertRaises(admission.AdmissionError):
            capability.compare_candidate(row['series'], binding=binding, cutoff=stamp(250), candidate_policy=row['policy'])
        with self.assertRaises(admission.AdmissionError):
            capability.compare_candidate(row['series'], binding=binding, cutoff=CUTOFF, candidate_policy={})

    def test_each_comparable_input_change_remains_incomparable_under_valid_approval(self):
        for key in admission.baseline.COMPARABLE:
            with self.subTest(fingerprint=key):
                proposal, (_, selection, observed, binding) = prepared_pair()
                row = observed.values()
                row['series']['fingerprint'][key] = 'sha256:' + '0' * 64
                changed = admission.OriginalRuntimeObservation(admission._SEAL, row)
                capability = self.capability(proposal, selection, changed)
                result = capability.compare_candidate(row['series'], binding=binding, cutoff=CUTOFF,
                                                      candidate_policy=row['policy'])
                self.assertEqual('incomparable', result['numericComparison'])
                self.assertEqual('not-observed', result['status'])

    def test_late_selection_wrong_scope_and_rebound_proposal_reject(self):
        proposal, (_, selection, observed, _) = prepared_pair()
        for change in ({'selectedAt': '2026-01-01T00:01:00+00:00'}, {'scope': 'same-product-repeatability'},
                       {'proposalDigest': 'sha256:' + '0' * 64}, {'approvalContext': '0' * 64}):
            with self.assertRaises(admission.AdmissionError):
                self.capability(proposal, {**selection, **change}, observed)

    def test_approved_actual_regression_is_failure_and_expiry_does_not_erase_history(self):
        proposal, (fixture, selection, observed, binding) = prepared_pair()
        row = observed.values()
        for sample in row['series']['samples']:
            sample['metrics']['rssBytes'] = 200
        changed = admission.OriginalRuntimeObservation(admission._SEAL, row)
        capability = self.capability(proposal, selection, changed)
        result = capability.compare_candidate(row['series'], binding=binding, cutoff=CUTOFF, candidate_policy=row['policy'])
        self.assertEqual('regression', result['scopedPerformanceVerdict'])
        decision = decision_vector(proposal)
        decision['expiresAt'] = '2026-01-01T00:05:00+00:00'
        capability = self.capability(proposal, selection, observed, decision)
        row = observed.values()
        result = capability.compare_candidate(row['series'], binding=binding, cutoff=CUTOFF, candidate_policy=row['policy'])
        self.assertEqual('expired', result['applicability'])
        self.assertEqual('authenticated', result['originalCandidateObservation'])
        self.assertEqual('not-observed', result['status'])


if __name__ == '__main__':
    unittest.main()

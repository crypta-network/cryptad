"""Offline driver/original regressions; synthetic vectors never claim installed execution."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import cross_version_installed_storage_budgets as driver
import pr318_storage_contract as historical
import pr318_storage_selection as legacy_selection
import pr320_storage_contract as contract
import pr320_storage_runtime_evidence as evidence
import pr320_storage_runtime_runner as runner
import pr320_installed_dispatch as dispatch
import pr315_workload_guest as guest
import restricted_workload_launcher as launcher
import restricted_workload_prepare as preparation
from cryptad_certification import composed_budget_storage_evidence as oracle
from cryptad_certification.tests.test_composed_budget_complete_storage import uri_row, contested_row, component
from cryptad_certification.tests.test_composed_budget_storage_evidence import EPOCH, NODE, GENERATION
from test_pr318_storage_installed import host_selection, resign, clock_sample


def selected(case, variant):
    value, fixture = host_selection()
    profile = contract.profile(case, variant)
    plan, private, authorization = value['plan'], value['private'], value['authorization']
    plan['experimentId'] = profile['experiment']
    private['root'] = '/var/lib/cryptad-cross-version/experiments/' + profile['experiment']
    authorization.update(executionClass=profile['executionClass'], experimentId=profile['experiment'],
                         root=private['root'])
    budget = authorization['budgetSelection']
    tools = {name: 'sha256:' + 'd' * 64 for name in contract.TOOL_PATHS}
    budget.update(caseIds=[case], environment=profile['environment'],
        normalizedConfiguration=profile['normalizedConfiguration'], toolIdentities=tools,
        permissions={key: list(value) for key, value in contract.PERMISSIONS.items()},
        privateRootClass='controller-derived-' + profile['experiment'])
    plan['workloadInputs'] = {'scheduler': tools['installedDriver']}
    plan['composedBudgetInputs'] = {
        'collectorDigest': contract.canonical_digest({key: tools[key] for key in
            ('installedDriver', 'localBudgetAdapter', 'schedulerRuntime', 'evidenceOracle',
             'storageOracle', 'administrator', 'roleClients', 'runtimeEvidence')}),
        'configurationDigest': contract.canonical_digest({'nodeConfigDigest': plan['nodes'][0]['configDigest'],
            'environment': profile['environment'], 'normalizedConfiguration': profile['normalizedConfiguration']})}
    budget['composedBudgetInputs'] = dict(plan['composedBudgetInputs'])
    from cryptad_certification.composed_budget_journal_member import campaign_inputs
    plan['budgetCampaignInputs'] = campaign_inputs(plan, tools)
    resign(plan, authorization)
    fixture.update(profile=profile, caseIds=[case], environment=profile['environment'],
        normalizedConfiguration=profile['normalizedConfiguration'], toolIdentities=tools,
        permissions={key: list(value) for key, value in contract.PERMISSIONS.items()})
    return value, fixture


class FixedProfilesTest(unittest.TestCase):
    def test_all_seven_finite_profiles_bind_and_old_class_stays_separate(self):
        for pair in contract.VARIANTS:
            with self.subTest(pair=pair):
                value, fixture = selected(*pair)
                self.assertTrue(contract.verify_selection_contract(**value))
                self.assertFalse(historical.verify_selection_contract(**value))
                self.assertEqual(value['authorization']['selectionDigest'], runner._selection(value, fixture))
                self.assertTrue(preparation.valid_execution_selection(**value))
                _arguments, environment = launcher.command('candidate-sender', value['authorization']['executionClass'])
                self.assertEqual(fixture['profile']['environment'], {
                    name: environment[name] for name in fixture['profile']['environment']})
                guest._validate_mode(startup_measurement=False, lifecycle_scenario='none',
                    workload_group=None, retired_authority_preparation=False,
                    execution_class=value['authorization']['executionClass'])

    def test_fixed_capture_roster_and_fake_prefix_reject(self):
        for pair in contract.VARIANTS:
            profile = contract.profile(*pair)
            members = dispatch.capture_members(profile['executionClass'])
            self.assertEqual(4, len(members))
            self.assertEqual(4, len({row[0] for row in members}))
            self.assertEqual('pr320-storage-attempts.private.jsonl', members[2][0])
            self.assertIn(profile['experiment'], members[1][1])
        with self.assertRaises(ValueError):
            dispatch.capture_members('pr320-storage-arbitrary-directory-v1')
        with self.assertRaises(ValueError):
            guest._validate_mode(startup_measurement=False, lifecycle_scenario='none',
                workload_group=None, retired_authority_preparation=False,
                execution_class='pr320-storage-arbitrary-directory-v1')

    def test_configuration_changes_rehashing_and_variant_relabeling_reject(self):
        value, fixture = selected('window-crossing', 'contested-capacity')
        for fault in ('quota', 'class', 'tool'):
            changed = copy.deepcopy(value)
            if fault == 'quota':
                changed['authorization']['budgetSelection']['environment'][
                    'CRYPTAD_APP_NETWORK_BUDGET_TRUST_GRAPH_IMPORT_PER_APP_PER_HOUR'] = '2'
            elif fault == 'class':
                changed['authorization']['executionClass'] = contract.profile('window-crossing',
                    'available-capacity')['executionClass']
            else:
                changed['authorization']['budgetSelection']['toolIdentities']['hostRunner'] = 'sha256:' + 'f' * 64
            resign(changed['plan'], changed['authorization'])
            if fault == 'tool':
                # Tool digests become meaningful only when bound to the independently verified fixture.
                self.assertTrue(contract.verify_selection_contract(**changed))
                with self.assertRaisesRegex(ValueError, 'fixture-substituted'):
                    runner._selection(changed, fixture)
            else:
                self.assertFalse(contract.verify_selection_contract(**changed))

    def test_prospective_profile_does_not_mutate_historical_configuration(self):
        old = copy.deepcopy(historical.NORMALIZED_CONFIGURATION)
        contested = contract.profile('window-crossing', 'contested-capacity')
        self.assertEqual(2, contested['normalizedConfiguration']['budgetConfiguration']['trustGraphImportConcurrentPerApp'])
        self.assertEqual(1, contested['normalizedConfiguration']['budgetConfiguration']['trustGraphImportPerAppPerHour'])
        contested['environment'].clear()
        self.assertEqual(old, historical.NORMALIZED_CONFIGURATION)
        self.assertTrue(contract.profile('window-crossing', 'contested-capacity')['environment'])

    def test_materialization_uses_exact_profile_before_launch(self):
        value, fixture = selected('window-crossing', 'contested-capacity')
        profile = fixture['profile']
        with patch.object(legacy_selection.preparation, 'configuration_identity',
                side_effect=lambda role, trust, selected_class: 'sha256:' + str(contract.ROLES.index(role) + 4) * 64) as configuration, \
                patch.object(legacy_selection.runtime, 'runner_identity', return_value={
                    'sourceCommit': fixture['sourceCommit'], 'runnerDigest': 'sha256:' + 'e' * 64,
                    'adapterDigest': 'sha256:' + 'f' * 64}):
            result = legacy_selection.materialize_verified(Path('/owned/inputs'), fixture, profile)
        self.assertTrue(contract.verify_selection_contract(**result))
        for role in contract.ROLES:
            configuration.assert_any_call(role, result['private']['nodes'][role]['trustedKeysDigest'],
                                          profile['executionClass'])


class UriDriversTest(unittest.TestCase):
    def test_contested_real_hour_stimulus_charges_competitor_before_primary_fulfillment(self):
        row = contested_row()
        boundary = row['timePlan']['boundaryEpochSecond']
        handle, recovery_handle = SimpleNamespace(context={}), SimpleNamespace(context={})
        order = []
        class Client:
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return None
            def release(self):
                order.append('primary')
            def result(self):
                return {'status': 429}
        def request(adapter, owner, statement, response=False):
            order.append('recovery' if owner is recovery_handle else 'competitor')
            return {'status': 200, 'value': {'importResult': {'documentFingerprint': 'a' * 64}}} if response else 200
        adapter = SimpleNamespace(deadline=driver.time.monotonic() + 1000,
            nodes={'candidate-sender': {'generation': GENERATION}},
            journal=SimpleNamespace(node_epochs={('', 'candidate-sender'): NODE}))
        raw = {'work': {'collectorEpoch': EPOCH, 'events': row['events']}}
        time_plan = {key: value for key, value in row['timePlan'].items()
                     if key not in {'observedReservationEpochSecond', 'releasedAtEpochSecond'}}
        with patch.object(driver.time, 'time', side_effect=[boundary - 11, boundary - 10,
                boundary - 2, boundary - 1, boundary - 1, boundary, boundary]), \
                patch.object(driver, '_request', side_effect=request), \
                patch.object(driver, '_snapshot', side_effect=[(raw, row[name]) for name in
                    ('before', 'after', 'recoveryAfter')]), \
                patch.object(driver, '_graph', side_effect=[row['graphBefore'], [], row['graphAfter'], row['graphRecovery']]), \
                patch.object(driver.transport, '_evidence_snapshot', return_value=row['during']), \
                patch.object(driver.transport, '_wait_for', return_value=raw), \
                patch.object(driver.transport, '_new_content_key', return_value={'uri': 'owned-key'}), \
                patch.object(driver.transport, '_publish', side_effect=lambda *args: order.append('fulfilled')), \
                patch.object(driver.transport, '_start_client', return_value=Client()):
            observed, attempt = driver._boundary_case(adapter, handle, b'{}', time_plan,
                contender=handle, recovery_handle=recovery_handle, selected_fingerprint='a' * 64)
        self.assertEqual(['primary', 'competitor', 'fulfilled', 'recovery'], order)
        self.assertEqual('executed', attempt['status'])
        self.assertEqual([{'caseId': 'window-crossing', 'variant': 'contested-capacity'}],
                         oracle.derive_complete_storage(component([observed]))['verifiedVariants'])

    def test_child_commit_and_graph_stimuli_produce_accepting_rows_and_restore_before_retry(self):
        for variant in ('uri-child-write-denial', 'uri-import-commit-denial', 'uri-readable-directory-denial'):
            with self.subTest(variant=variant):
                row = uri_row(variant)
                order = []
                class Client:
                    def __enter__(self):
                        return self
                    def __exit__(self, *_):
                        order.append('client-closed')
                    def release(self):
                        order.append('released')
                    def result(self):
                        return {'status': 503}
                adapter = SimpleNamespace(nodes={'candidate-sender': {'generation': GENERATION}},
                    journal=SimpleNamespace(node_epochs={('', 'candidate-sender'): NODE}))
                handle = SimpleNamespace(context={})
                case = row['caseId']
                def request(*args, response=False, **kwargs):
                    order.append('prime' if response else 'retry')
                    return {'status': 200, 'value': {'importResult': {'documentFingerprint': 'a' * 64}}} if response else 200
                def admin(command):
                    order.append(command)
                    return row['adminReceipt']['restriction' if command.endswith(':restrict') else 'restoration']
                raw = {'work': {'collectorEpoch': EPOCH, 'events': row['events']}}
                states = [row['before'], row['during'], row['after'], row['after'], row['recoveryAfter']]
                with patch.object(driver, '_request', side_effect=request), \
                        patch.object(driver, '_snapshot', side_effect=[(raw, state) for state in states]), \
                        patch.object(driver, '_graph', side_effect=[row['graphBefore'], row['graphAfter'], row['graphRecovery']]), \
                        patch.object(driver.transport, '_new_content_key', return_value={'uri': 'owned-key'}), \
                        patch.object(driver.transport, '_publish', side_effect=lambda *args: order.append('published')), \
                        patch.object(driver.transport, '_start_client', return_value=Client()), \
                        patch.object(driver.transport, '_wait_for', return_value=raw):
                    observed = driver._uri_filesystem_variant(adapter, handle, b'{}', case, variant, admin, lambda row: None)
                result = oracle.derive_complete_storage(component([observed]))
                self.assertEqual([{'caseId': case, 'variant': variant}], result['verifiedVariants'])
                self.assertLess(order.index(case + ':restore'), order.index('retry'))
                if variant == 'uri-import-commit-denial':
                    self.assertLess(order.index('released'), order.index(case + ':restrict'))
                    self.assertLess(order.index(case + ':restrict'), order.index('published'))
                else:
                    self.assertLess(order.index(case + ':restrict'), order.index('released'))

    def test_commit_premise_loss_never_injects_fault_or_claims_coverage(self):
        class Client:
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return None
            def release(self):
                pass
        with patch.object(driver, '_request', return_value={'status': 200, 'value': {
                'importResult': {'documentFingerprint': 'a' * 64}}}), \
                patch.object(driver, '_snapshot', return_value=({}, {'sequence': 0})), \
                patch.object(driver, '_graph', return_value=[]), \
                patch.object(driver.transport, '_new_content_key', return_value={'uri': 'owned-key'}), \
                patch.object(driver.transport, '_start_client', return_value=Client()), \
                patch.object(driver.transport, '_wait_for', return_value=None), \
                patch.object(driver.transport, '_publish') as publish:
            administrator = unittest.mock.Mock()
            with self.assertRaisesRegex(driver.runtime.RuntimeFailure, 'premise-unobserved'):
                driver._uri_filesystem_variant(SimpleNamespace(), SimpleNamespace(context={}), b'{}',
                    'partial-rate-write', 'uri-import-commit-denial', administrator, lambda row: None)
            administrator.assert_not_called()
            publish.assert_not_called()


class PrivateOriginalTest(unittest.TestCase):
    def test_root_bootstrap_receipt_scope_and_cleanup_substitution_reject(self):
        case, variant = 'partial-rate-write', 'uri-child-write-denial'
        selected_value, _fixture = selected(case, variant)
        authorization = selected_value['authorization']
        authorization['budgetSelection']['statementFingerprint'] = 'a' * 64
        resign(selected_value['plan'], authorization)
        row = uri_row(variant)
        role_digest = 'sha256:' + NODE + 'a' * 32
        contexts = {app: {'appId': app, 'role': 'candidate-sender',
            'roleEpochDigest': role_digest, **{key: 'sha256:' + 'a' * 64 for key in
                ('daemonEpochDigest', 'workerEpochDigest', 'originDigest', 'sessionDigest', 'sessionExpiryDigest')}}
            for app in contract.APP_IDS}
        private = {'selectionDigest': authorization['selectionDigest'],
            'executionClass': authorization['executionClass'], 'contexts': contexts,
            'storageComponent': component([row])}
        record = {'roleEpochDigest': role_digest, 'generation': GENERATION,
            'managerInvocation': 'b' * 32, 'bootId': 'c' * 36, 'handle': 'd' * 32}
        terminal = {'controllerRecords': {'candidate-sender': {'record': record}}}
        diagnostics = {'storageAccessCleanup': 'completed', 'storageSelectionDigest': authorization['selectionDigest'],
            'storageBootstrapContext': {'apps': contexts, **{key: record[key] for key in
                ('generation', 'managerInvocation', 'bootId', 'handle')}},
            'storageFaultReceipts': [row['adminReceipt']['restriction'], row['adminReceipt']['restoration']]}
        report = {'storageClock': {'before': clock_sample(10**12, 10**10),
                                   'after': clock_sample(2 * 10**12, 2 * 10**10)}}
        with patch.object(runner.legacy.shared, '_terminal_cleanup_verified', return_value=True):
            result = evidence.validate_originals(private, selected_value, diagnostics, terminal, report)
            self.assertEqual([{'caseId': case, 'variant': variant}], result['verifiedVariants'])
            for fault in ('bootstrap', 'receipt', 'cleanup', 'selected'):
                changed = copy.deepcopy(diagnostics)
                if fault == 'bootstrap':
                    changed['storageBootstrapContext']['apps']['feed-reader']['workerEpochDigest'] = 'sha256:' + 'f' * 64
                elif fault == 'receipt':
                    changed['storageFaultReceipts'][0]['observedMonotonicNs'] += 1
                elif fault == 'cleanup':
                    changed['storageAccessCleanup'] = 'restoration-required'
                else:
                    changed['storageSelectionDigest'] = 'sha256:' + 'f' * 64
                with self.assertRaises(ValueError):
                    evidence.validate_originals(private, selected_value, changed, terminal, report)

    def test_actual_component_revalidated_and_wrong_claim_rejected(self):
        case, variant = 'partial-rate-write', 'uri-child-write-denial'
        source = component([uri_row(variant)])
        value = {'schemaVersion': 1, 'kind': 'pr320-private-storage-budget',
            'selectionDigest': 'sha256:' + 'a' * 64,
            'executionClass': contract.profile(case, variant)['executionClass'],
            'contexts': {app: {'appId': app, 'role': 'candidate-sender',
                **{key: 'sha256:' + 'a' * 64 for key in ('roleEpochDigest', 'daemonEpochDigest',
                    'workerEpochDigest', 'originDigest', 'sessionDigest', 'sessionExpiryDigest')}}
                for app in contract.APP_IDS},
            'attempts': [{'caseId': case, 'status': 'executed'}],
            'storageComponent': source, 'storageCoverage': oracle.derive_complete_storage(source)}
        self.assertEqual(value, evidence.decode_private(json.dumps(value).encode()))
        forged = copy.deepcopy(value)
        forged['storageCoverage']['verifiedVariants'] = []
        with self.assertRaisesRegex(ValueError, 'coverage-substituted'):
            evidence.decode_private(json.dumps(forged).encode())
        forged = copy.deepcopy(value)
        forged['executionClass'] = contract.profile(case, 'uri-import-commit-denial')['executionClass']
        with self.assertRaisesRegex(ValueError, 'variant-substituted'):
            evidence.decode_private(json.dumps(forged).encode())

    def test_public_failure_contains_only_fixed_classification(self):
        profile = contract.profile('window-crossing', 'contested-capacity')
        value = evidence.failed_projection(profile, '/private/path/body-or-session')
        self.assertEqual(['setup-or-execution-failed'], value['reasons'])
        self.assertNotIn('/private/', json.dumps(value))
        self.assertEqual(value, runner._closed_public(value))
        self.assertFalse(value['releaseEligible'])


if __name__ == '__main__':
    unittest.main()

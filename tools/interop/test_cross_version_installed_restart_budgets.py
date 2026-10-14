"""Bounded helper regressions; simulated helpers never grant installed execution credit."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import cross_version_installed_restart_budgets as driver


EPOCH = '01234567-89ab-cdef-0123-456789abcdef'
OLD_EPOCH = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
STAMP = '2026-10-13T19:00:00Z'
WINDOW = 1791918000


def context(app, *, fresh=False):
    return {'appId': app, 'role': driver.ROLE, 'handle': 'a' * 64,
            'generation': ('d' if fresh else 'b') * 64,
            'managerInvocation': ('e' if fresh else 'c') * 32,
            'bootId': EPOCH,
            'daemonEpoch': {'hostPid': 202 if fresh else 101,
                            'startTicks': 20 if fresh else 10, 'pidNamespace': 'pid:[123]'},
            'worker': {'fixtureProcess': {'startTicks': 30 if fresh else 15}},
            'origin': 'http://127.0.0.1:21001', 'session': 'fresh-session' if fresh else 'old-session',
            'sessionExpiresAt': '2026-10-13T19:05:00Z'}


def usage(app, operation='trust_graph_import'):
    return {'appId': app, 'operation': operation, 'windowStart': STAMP,
            'windowSeconds': 3600, 'count': 1, 'limit': 32,
            'lastDecisionAt': STAMP, 'lastDecision': 'allowed', 'nextAvailableAt': None}


def native(rows=None, *, valid=True, epoch=EPOCH, events=None):
    rows = [] if rows is None else rows
    events = [] if events is None else events
    return {'work': {'version': 4, 'lastSequence': len(events), 'dropped': 0,
                     'events': events, 'collectorEpoch': epoch},
            'budget': {'valid': valid, 'observedAt': STAMP,
                       'activeFamilyLeases': 0, 'reservedFamilyRates': 0,
                       'rates': rows if valid else []}}


def rate(row, scope):
    return {'operation': row['operation'], 'scope': scope, 'count': row['count'],
            'windowStartEpochSecond': int(driver.oracle._time(row['windowStart']))}


class TimePlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(driver.__file__).resolve().parents[1] / 'release-certification/protected/pr319_restart_contract.py'
        spec = importlib.util.spec_from_file_location('pr319_time_plan_contract', path)
        cls.contract = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.contract)

    def plan(self, lead_seconds):
        boundary = WINDOW + 3600
        return {'boundaryEpochSecond': boundary, 'selectedAtEpochSecond': boundary - lead_seconds,
                'startMarginSeconds': 10, 'requestDeadlineMillis': 45000}

    def test_selection_must_leave_start_margin_before_runtime_cutoff(self):
        for lead_seconds in (60, 61, 69):
            with self.subTest(lead_seconds=lead_seconds):
                self.assertFalse(self.contract.valid_time_plan(self.plan(lead_seconds)))

    def test_valid_selection_keeps_minimum_margin_and_same_hour_upper_bound(self):
        for lead_seconds in (70, 71, 3600):
            with self.subTest(lead_seconds=lead_seconds):
                self.assertTrue(self.contract.valid_time_plan(self.plan(lead_seconds)))
        self.assertFalse(self.contract.valid_time_plan(self.plan(3601)))

    def test_minimum_selection_can_start_until_its_margin_expires(self):
        plan = self.plan(70)
        adapter = SimpleNamespace(authorization={'budgetSelection': {'timePlan': plan}}, remaining=Mock())
        with patch.object(driver.time, 'time', return_value=plan['selectedAtEpochSecond'] + 9):
            driver._same_hour(adapter)
        adapter.remaining.assert_called_once_with()
        with patch.object(driver.time, 'time', return_value=plan['selectedAtEpochSecond'] + 10), \
                self.assertRaisesRegex(driver.runtime.RuntimeFailure, 'restart-selected-hour-missed'):
            driver._same_hour(adapter)

    def test_fixed_start_margin_cannot_be_substituted_or_malformed(self):
        for margin in (None, '10', True, 0, 9, 11):
            plan = dict(self.plan(70), startMarginSeconds=margin)
            with self.subTest(margin=margin):
                self.assertFalse(self.contract.valid_time_plan(plan))


class RetainedAppRecoveryTests(unittest.TestCase):
    def setup_recovery(self, *, running=True):
        statement = b'selected-signed-statement-private-fixture'
        contexts = {app: context(app, fresh=True) for app in driver.transport.APP_IDS}
        selected = contexts[driver.transport.APP_IDS[0]]
        adapter = SimpleNamespace(
            events=[], inventory=[{'appId': app} for app in reversed(driver.transport.APP_IDS)],
            running={app: running for app in driver.transport.APP_IDS},
            nodes={driver.ROLE: {key: selected[key] for key in driver.transport.ROLE_EPOCH}},
            private={'nodes': {driver.ROLE: {'httpPort': 19402}}},
            handles={driver.ROLE: selected['handle']}, apps={},
            control=SimpleNamespace(request=Mock(return_value={
                'apps': contexts,
                'corpus': {'statementDigest': 'sha256:' + hashlib.sha256(statement).hexdigest(),
                           'statementBase64': 'private-corpus'}})))
        old = {app: SimpleNamespace(context=context(app)) for app in driver.transport.APP_IDS}

        class Handle(driver.transport.BudgetAppHandle):
            def host_bootstrap(self):
                self.supervisor.events.append(('bootstrap', self.app_id))
                self.password = 'new-private-form-password'

            def request(self, method, path, parameters=None, *, principal='host', **_):
                self.supervisor.events.append((method, path, parameters, principal))
                if path == '/api/v1/apps':
                    return 200, {'apps': self.supervisor.inventory}
                if path.endswith('/runtime'):
                    return 200, {'runtime': {'running': self.supervisor.running[self.app_id]}}
                if path.endswith('/start'):
                    self.supervisor.running[self.app_id] = True
                    return 200, {}
                raise AssertionError('Unexpected management request')

        return adapter, old, statement, Handle

    def test_rebootstrap_uses_retained_install_and_new_controller_context_without_regrant(self):
        adapter, old, statement, handle_type = self.setup_recovery(running=False)
        before = copy.deepcopy({app: handle.context for app, handle in old.items()})
        with patch.object(driver.transport, 'BudgetAppHandle', handle_type):
            fresh = driver._rebootstrap(adapter, old, statement)
        self.assertEqual(set(driver.transport.APP_IDS), set(fresh))
        adapter.control.request.assert_called_once_with('bootstrap-budget', adapter.handles[driver.ROLE])
        starts = [row for row in adapter.events if row[0] == 'POST']
        self.assertEqual([('POST', '/api/v1/apps/' + app + '/start', None, 'host')
                          for app in driver.transport.APP_IDS], starts)
        self.assertEqual(before, {app: handle.context for app, handle in old.items()})
        for app, handle in fresh.items():
            self.assertIs(adapter.apps[(driver.ROLE, app)], handle)
            self.assertIsNot(old[app], handle)
            self.assertNotEqual(old[app].context['generation'], handle.context['generation'])
            self.assertEqual('fresh-session', handle.session)
        self.assertFalse(any('/install' in str(row) or '/permissions' in str(row) for row in adapter.events))

    def test_running_retained_apps_need_no_start_or_install(self):
        adapter, old, statement, handle_type = self.setup_recovery()
        with patch.object(driver.transport, 'BudgetAppHandle', handle_type):
            driver._rebootstrap(adapter, old, statement)
        self.assertFalse(any(row[0] == 'POST' for row in adapter.events))

    def test_stale_daemon_worker_or_controller_epoch_is_rejected(self):
        for field in ('generation', 'managerInvocation', 'daemonEpoch', 'worker'):
            with self.subTest(field=field):
                adapter, old, statement, handle_type = self.setup_recovery()
                response = adapter.control.request.return_value
                response['apps']['feed-reader'][field] = copy.deepcopy(old['feed-reader'].context[field])
                with patch.object(driver.transport, 'BudgetAppHandle', handle_type), self.assertRaisesRegex(
                        driver.runtime.RuntimeFailure, 'restart-app-context-stale'):
                    driver._rebootstrap(adapter, old, statement)
                self.assertEqual({}, adapter.apps)

    def test_boot_change_rejects_process_continuity(self):
        adapter, old, statement, handle_type = self.setup_recovery()
        adapter.control.request.return_value['apps']['feed-reader']['bootId'] = OLD_EPOCH
        with patch.object(driver.transport, 'BudgetAppHandle', handle_type), self.assertRaisesRegex(
                driver.runtime.RuntimeFailure, 'restart-app-context-stale'):
            driver._rebootstrap(adapter, old, statement)

    def test_malformed_roster_and_substituted_corpus_cannot_recover(self):
        for change in ('roster', 'corpus', 'app-context'):
            with self.subTest(change=change):
                adapter, old, statement, handle_type = self.setup_recovery()
                if change == 'roster': adapter.inventory.append({'appId': 'unselected-app'})
                elif change == 'corpus': adapter.control.request.return_value['corpus']['statementDigest'] = 'sha256:' + 'f' * 64
                else: adapter.control.request.return_value['apps']['feed-reader']['appId'] = 'budget-importer'
                with patch.object(driver.transport, 'BudgetAppHandle', handle_type), self.assertRaises(driver.runtime.RuntimeFailure):
                    driver._rebootstrap(adapter, old, statement)


class NativeSamplingTests(unittest.TestCase):
    def test_bindings_follow_native_sorted_store_order_and_remap_per_epoch(self):
        rows = [usage('_cryptad_global'), usage('budget-importer'), usage('feed-reader')]
        for scope_map in ({'_cryptad_global': 1, 'budget-importer': 3, 'feed-reader': 4},
                          {'_cryptad_global': 1, 'budget-importer': 4, 'feed-reader': 3}):
            view = native([rate(row, scope_map[row['appId']]) for row in rows])
            expected = {**scope_map, '_cryptad_operator': 2}
            self.assertEqual(expected, {row['appId']: row['scope'] for row in driver._scope_bindings(view, rows)})

    def test_scope_mapping_refuses_changed_record_family_window_and_reserved_scope(self):
        rows = [usage('_cryptad_global'), usage('feed-reader')]
        view = native([rate(rows[0], 1), rate(rows[1], 3)])
        for field, replacement in (('operation', 'subscription_poll'), ('count', 0),
                                   ('windowStartEpochSecond', WINDOW + 3600), ('scope', 3)):
            selected = copy.deepcopy(view)
            selected['budget']['rates'][0][field] = replacement
            with self.subTest(field=field), self.assertRaises(driver.runtime.RuntimeFailure):
                driver._scope_bindings(selected, rows)

    def test_unsorted_or_duplicate_scope_mapping_is_rejected_before_binding(self):
        rows = [usage('feed-reader'), usage('budget-importer')]
        view = native([rate(rows[0], 3), rate(rows[1], 4)])
        with self.assertRaises(driver.runtime.RuntimeFailure):
            driver._scope_bindings(view, rows)
        rows = [usage('budget-importer'), usage('feed-reader')]
        with self.assertRaises(driver.runtime.RuntimeFailure):
            driver._scope_bindings(native([rate(rows[0], 3), rate(rows[1], 3)]), rows)

    def sampler(self, snapshots, *, daemon=None):
        expected = {'hostPid': 202, 'startTicks': 20, 'pidNamespace': 'pid:[123]',
                    'executableDigest': 'sha256:' + 'a' * 64, 'namespacePids': [202, 2],
                    'networkNamespaceIdentity': [1, 2]}
        adapter = SimpleNamespace(root='private-fixture-root', daemon_epochs={driver.ROLE: expected})
        handles = {'feed-reader': object()}
        state = {'bindings': [{'appId': '_cryptad_global', 'scope': 1},
                              {'appId': '_cryptad_operator', 'scope': 2},
                              {'appId': 'feed-reader', 'scope': 3}], 'phaseReceipts': []}
        receipt = {'daemon': expected if daemon is None else daemon,
                   'durableUsage': [usage('feed-reader')], 'graphFacts': []}
        return adapter, handles, state, Mock(return_value=receipt), snapshots

    def test_actual_second_invalid_snapshot_preserves_first_unavailable_interval(self):
        first = native(valid=False)
        second = native(valid=False, events=[{'sequence': 1, 'kind': 'STORE_UNAVAILABLE'}])
        adapter, handles, state, admin, snapshots = self.sampler([first, second])
        with patch.object(driver.transport, '_snapshot', side_effect=snapshots) as sampled, patch.object(driver, '_checkpoint') as retained:
            result, _ = driver._sample(adapter, handles, admin, state, 'diagnostics-unavailable', 'enumeration-only', 'during')
        self.assertEqual(2, sampled.call_count)
        self.assertEqual(2, admin.call_count)
        self.assertEqual(2, retained.call_count)
        self.assertEqual([], retained.call_args_list[0].args[1]['sample']['nativeSnapshot']['events'])
        self.assertFalse(result['diagnostics']['valid'])
        self.assertEqual([], result['diagnostics']['usage'])
        self.assertEqual(state['bindings'], result['scopeBindings'])
        self.assertEqual('STORE_UNAVAILABLE', result['nativeSnapshot']['events'][0]['kind'])
        self.assertEqual(1, len(state['phaseReceipts']))

    def test_invalid_interval_cannot_be_erased_by_later_valid_resampling(self):
        adapter, handles, state, admin, snapshots = self.sampler([native(valid=False), native(valid=True)])
        with patch.object(driver.transport, '_snapshot', side_effect=snapshots), patch.object(driver, '_checkpoint') as retained, self.assertRaisesRegex(
                driver.runtime.RuntimeFailure, 'restart-diagnostic-interval-changed'):
            driver._sample(adapter, handles, admin, state, 'diagnostics-unavailable', 'enumeration-only', 'during')
        self.assertEqual(1, retained.call_count)
        self.assertEqual([], state['phaseReceipts'])

    def test_pid_reuse_cannot_substitute_current_daemon_epoch(self):
        adapter, handles, state, admin, snapshots = self.sampler([native()])
        admin.return_value['daemon'] = {**admin.return_value['daemon'], 'startTicks': 999,
                                       'pidNamespace': 'pid:[other]'}
        admin.return_value['durableUsage'] = []
        with patch.object(driver.transport, '_snapshot', side_effect=snapshots), patch.object(driver, '_checkpoint'), self.assertRaisesRegex(
                driver.runtime.RuntimeFailure, 'restart-daemon-sample-substituted'):
            driver._sample(adapter, handles, admin, state, 'graceful-restart', 'settled-graceful', 'before')

    def test_inflight_setup_is_retained_without_duplicating_accepted_before_receipt(self):
        adapter, handles, state, admin, snapshots = self.sampler([native()])
        admin.return_value['durableUsage'] = []
        with patch.object(driver.transport, '_snapshot', side_effect=snapshots), patch.object(driver, '_checkpoint') as retained:
            driver._sample(adapter, handles, admin, state, 'abrupt-restart', 'inflight-abrupt', 'setup')
        self.assertEqual([], state['phaseReceipts'])
        self.assertEqual('before', retained.call_args.args[1]['phase'])


class ClosedDriverSurfaceTests(unittest.TestCase):
    def test_import_is_independent_of_checkout_cwd_and_keeps_sys_path_unchanged(self):
        script = '''import sys
sys.path.insert(0, sys.argv[1])
before = list(sys.path)
import cross_version_installed_restart_budgets as driver
assert driver.EXECUTION_CLASS == 'pr319-composed-budget-restart-diagnostics-v1'
assert sys.path == before
'''
        with tempfile.TemporaryDirectory() as root:
            result = subprocess.run([sys.executable, '-I', '-B', '-c', script,
                                     str(Path(driver.__file__).parent)], cwd=root,
                                    capture_output=True, text=True, timeout=15, check=False)
        self.assertEqual(0, result.returncode, result.stderr)

    def test_old_execution_class_is_rejected_before_any_launch(self):
        path = Path(driver.__file__).resolve().parents[1] / 'release-certification/protected/pr319_restart_contract.py'
        spec = importlib.util.spec_from_file_location('pr319_restart_contract', path)
        contract = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(contract)
        adapter = SimpleNamespace(plan={}, private={}, authorization={
            'executionClass': driver.transport.EXECUTION_CLASS}, start=Mock())
        with patch.dict(sys.modules, {'pr319_restart_contract': contract}), self.assertRaisesRegex(
                driver.runtime.RuntimeFailure, 'restart-selection-invalid'):
            driver.run_restart_lane(adapter, Mock())
        adapter.start.assert_not_called()

    def test_real_cli_lists_only_existing_fixed_execution_classes_and_the_successor(self):
        path = Path(driver.__file__).resolve().parents[1] / 'release-certification/restricted/pr314_workload_driver.py'
        with tempfile.TemporaryDirectory() as root:
            result = subprocess.run([sys.executable, str(path), '--help'], cwd=root,
                                    capture_output=True, text=True, timeout=15, check=False)
        self.assertEqual(0, result.returncode, result.stderr)
        selected = re.search(r'--execution-class\s+\{([^}]+)\}', result.stdout)
        self.assertIsNotNone(selected)
        from pr320_budget_contract import PROSPECTIVE_EXECUTION_CLASSES
        actual_classes = tuple(value.strip() for value in selected.group(1).split(','))
        self.assertEqual(('pr316-installed-mail-runtime-v1',
                          'pr317-namespace-bound-composed-budget-v1',
                          'pr318-fixed-window-partial-store-v1',
                          'pr319-composed-budget-restart-diagnostics-v1'),
                         actual_classes[:4])
        self.assertEqual(PROSPECTIVE_EXECUTION_CLASSES, actual_classes[4:])
        self.assertEqual(len(actual_classes), len(set(actual_classes)))
        self.assertNotIn('--kill-pid', result.stdout)
        self.assertNotIn('--chmod-path', result.stdout)

    def observation(self):
        return {'schemaVersion': 1, 'kind': 'pr319-installed-restart-budget-observation',
                'executionClass': driver.EXECUTION_CLASS, 'selectionDigest': 'sha256:' + 'a' * 64,
                'privateEvidenceDigest': 'sha256:' + 'b' * 64,
                'evidenceClass': driver.oracle.INSTALLED, 'observedCases': [],
                'fullAppBudgets': 'not-observed', 'phaseComplete': False, 'releaseEligible': False,
                'cleanupState': 'administrator-required'}

    def test_public_observation_cannot_claim_full_phase_or_substitute_digest(self):
        for field, value in (('schemaVersion', True), ('selectionDigest', 'private-fixture-path'),
                             ('privateEvidenceDigest', 'digest-unavailable'), ('phaseComplete', True),
                             ('releaseEligible', True), ('observedCases', ['privacy']), ('extra', 'private-canary')):
            candidate = self.observation()
            candidate[field] = value
            with self.subTest(field=field), self.assertRaises(driver.runtime.RuntimeFailure):
                driver.validate_guest_observation(candidate)

    def test_checkpoint_partial_write_must_complete_a_whole_retained_record(self):
        payload = {'phase': 'before', 'status': 'private-selected-evidence'}
        with tempfile.TemporaryDirectory() as root:
            original_write = os.write
            def partial(fd, data): return original_write(fd, data[:max(1, len(data) // 2)])
            with patch.object(driver.os, 'write', side_effect=partial):
                driver._checkpoint(root, payload)
            saved = Path(root, driver.ATTEMPTS_FILE).read_bytes()
            self.assertTrue(saved.endswith(b'\n'))
            self.assertEqual(payload, json.loads(saved))

    def test_checkpoint_zero_progress_fails_closed(self):
        with tempfile.TemporaryDirectory() as root, patch.object(driver.os, 'write', return_value=0), self.assertRaisesRegex(
                driver.runtime.RuntimeFailure, 'restart-checkpoint-write-incomplete'):
            driver._checkpoint(root, {'phase': 'before'})

    def test_checkpoint_never_writes_through_a_linked_target(self):
        for kind in ('symlink', 'hardlink', 'public-mode'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as root:
                original = Path(root, 'private-original')
                original.write_bytes(b'private-original-canary')
                original.chmod(0o600)
                checkpoint = Path(root, driver.ATTEMPTS_FILE)
                if kind == 'symlink': checkpoint.symlink_to(original)
                elif kind == 'hardlink': os.link(original, checkpoint)
                else:
                    checkpoint.write_bytes(b'private-original-canary')
                    checkpoint.chmod(0o644)
                with self.assertRaises((OSError, driver.runtime.RuntimeFailure)):
                    driver._checkpoint(root, {'phase': 'before'})
                self.assertEqual(b'private-original-canary', original.read_bytes())

    def test_only_fixed_administrator_commands_can_reach_the_private_channel(self):
        path = Path(driver.__file__).resolve().parents[1] / 'release-certification/restricted/pr319_restart_admin.py'
        spec = importlib.util.spec_from_file_location('pr319_restart_admin', path)
        admin_module = importlib.util.module_from_spec(spec)
        with patch.object(sys, 'path', [str(path.parent), *sys.path]):
            spec.loader.exec_module(admin_module)
        channel = Mock()
        administrator = driver._Administrator(channel, driver.time.monotonic_ns() + 1000000000)
        for command in ('kill:101', 'chmod:/private/path', 'restart:arbitrary-role', 'reset-quota'):
            with self.subTest(command=command), patch.dict(sys.modules, {'pr319_restart_admin': admin_module}), self.assertRaises(driver.runtime.RuntimeFailure):
                administrator(command)
        channel.sendall.assert_not_called()


class FailureCleanupTests(unittest.TestCase):
    def handles(self):
        return {app: SimpleNamespace(context=context(app)) for app in driver.transport.APP_IDS}

    def test_wrong_graceful_pin_prevents_shutdown_and_new_start(self):
        adapter = SimpleNamespace(root='private-root', client=Mock(), restart=Mock())
        administrator = Mock(return_value={'daemon': {'hostPid': 999}})
        with patch.object(driver, '_same_hour'), self.assertRaisesRegex(driver.runtime.RuntimeFailure, 'restart-graceful-target-changed'):
            driver._transition(adapter, self.handles(), b'synthetic-statement', administrator,
                               {'epochContexts': []}, {'pid': 101}, 'settled-graceful')
        adapter.client.assert_not_called()
        adapter.restart.assert_not_called()

    def test_finished_inflight_request_prevents_fault_and_restart(self):
        for alive, response_ready in ((False, False), (True, True)):
            adapter = SimpleNamespace(root='private-root', restart=Mock())
            administrator = Mock()
            client = SimpleNamespace(process=SimpleNamespace(is_alive=lambda: alive),
                channel=SimpleNamespace(poll=lambda _timeout: response_ready))
            with self.subTest(alive=alive, response_ready=response_ready), patch.object(driver, '_same_hour'), self.assertRaisesRegex(
                    driver.runtime.RuntimeFailure, 'inflight-premise-finished-before-fault'):
                driver._transition(adapter, self.handles(), b'synthetic-statement', administrator,
                    {'epochContexts': []}, {'pid': 101}, 'inflight-abrupt', active_client=client)
            administrator.assert_not_called()
            adapter.restart.assert_not_called()

    def test_old_owner_quiescence_failure_prevents_rebootstrap(self):
        adapter = SimpleNamespace(root='private-root', restart=Mock(side_effect=driver.runtime.RuntimeFailure('role-quiescence-unestablished')))
        administrator = Mock(return_value={'pidfdDeathObserved': True})
        with patch.object(driver, '_same_hour'), patch.object(driver, '_checkpoint'), patch.object(driver, '_rebootstrap') as bootstrap, self.assertRaisesRegex(
                driver.runtime.RuntimeFailure, 'role-quiescence-unestablished'):
            driver._transition(adapter, self.handles(), b'synthetic-statement', administrator,
                               {'epochContexts': []}, {'pid': 101}, 'settled-abrupt')
        administrator.assert_called_once_with('abrupt-settled:terminate')
        adapter.restart.assert_called_once_with(driver.ROLE)
        bootstrap.assert_not_called()

    def test_observer_request_failure_still_restores_the_fixed_permission_fault(self):
        administrator = Mock(return_value={'roleUidEnumerationDenied': True})
        with patch.object(driver, '_sample', return_value=({}, {})), patch.object(driver.storage, '_request', side_effect=driver.runtime.RuntimeFailure('native-response-unavailable')), self.assertRaisesRegex(
                driver.runtime.RuntimeFailure, 'native-response-unavailable'):
            driver._diagnostic_case(SimpleNamespace(), self.handles(), b'synthetic-statement',
                                    administrator, {}, 'enumeration-only', 'a' * 64)
        self.assertEqual(['diagnostics-enumeration:restrict', 'diagnostics-enumeration:restore'],
                         [call.args[0] for call in administrator.call_args_list])


if __name__ == '__main__':
    unittest.main()

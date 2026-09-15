"""Durable request semantics with explicit authority seams; not a multi-UID isolation test."""
from contextlib import ExitStack, contextmanager, nullcontext
import datetime as dt
import json
import sys
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import restricted_worker as worker

AUTHENTICATE_JOB = worker.authenticate_job


@unittest.skipIf(worker.pwd is None, 'Linux worker state semantics require pwd')
class DurableWorkerTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name)
        self.operations = self.state / 'operations'
        self.operations.mkdir()
        self.handle = 'a' * 64
        self.root = self.operations / self.handle
        self.root.mkdir()
        (self.root / 'inputs').mkdir()
        current = worker.now()
        self.record = {'schemaVersion': 1, 'method': 'baseline-prepare', 'handle': self.handle,
            'bundleIdentity': 'b' * 64, 'callerUid': 62001,
            'context': {'sourceCommit': 'c' * 40, 'runId': 1, 'runAttempt': 1, 'jobId': 2},
            'notBefore': (current - dt.timedelta(minutes=1)).isoformat(),
            'expiresAt': (current + dt.timedelta(minutes=5)).isoformat(),
            'collectUntil': (current + dt.timedelta(days=1)).isoformat(),
            'inputFiles': {}, 'configurationFiles': {}}
        from restricted_configuration import PREPARATION
        config_raw = worker.encode({'campaignPath': PREPARATION, 'policyPath': PREPARATION,
            'requestPath': PREPARATION, 'observations': [{'coordinates': {}, 'bundlePath': PREPARATION}]})
        self.record['configurationFiles'] = {PREPARATION: {'digest': worker.digest(config_raw), 'size': len(config_raw)}}
        original_read = worker.read
        config_read = patch.object(worker, 'read', side_effect=lambda path, maximum=worker.MAX_RECORD:
            config_raw if str(path) == PREPARATION else original_read(path, maximum))
        config_read.start()
        self.addCleanup(config_read.stop)
        (self.root / 'registration.json').write_bytes(worker.encode(self.record))
        (self.state / 'revocations.json').write_text('[]')
        self.client = worker.Worker('b' * 64)
        self.selected = {'method': 'baseline-prepare', 'handle': self.handle}
        for change in (patch.object(worker, 'STATE', self.state),
                       patch.object(worker, 'OPERATIONS', self.operations),
                       patch.object(worker, 'secure', side_effect=lambda path, **_: Path(path)),
                       patch.object(worker.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=62001)),
                       patch.object(worker, 'original_environment', return_value=nullcontext({})),
                       patch.object(worker, 'authenticate_job')):
            change.start()
            self.addCleanup(change.stop)

    def test_completed_retry_after_restart_never_dispatches_again(self):
        with patch.object(worker, 'dispatch', return_value={'schemaVersion': 1, 'status': 'prepared'}) as owner:
            first = self.client.process(self.selected, 62001)
            second = worker.Worker('b' * 64).process(self.selected, 62001)
            collected = self.client.process({'method': 'collect', 'handle': self.handle}, 62001)
        self.assertEqual(first, second)
        self.assertEqual(first, collected)
        owner.assert_called_once()

    def test_revocation_during_owner_retains_intent_without_new_result(self):
        def revoke(*_):
            (self.root / 'revoked.json').write_text('{}')
            return {'status': 'prepared'}
        with patch.object(worker, 'dispatch', side_effect=revoke):
            with self.assertRaisesRegex(worker.BoundaryError, 'operation-revoked'):
                self.client.process(self.selected, 62001)
        self.assertTrue((self.root / 'intent.json').exists())
        self.assertFalse((self.root / 'result.json').exists())

    @unittest.skipUnless(sys.platform == 'linux', 'native owning boundary requires Linux')
    def test_real_revocation_callback_stops_native_before_worker_result(self):
        """Local composition test: real worker/native callbacks, synthetic service manager."""
        import os
        import restricted_native as native
        import cross_version_supervisor_authority as authority
        native_root = self.state / 'native'
        native_root.mkdir()
        cgroup = self.state / 'owned-cgroup'
        cgroup.mkdir()
        (cgroup / 'cgroup.events').write_text('populated 0\n')
        calls = []
        active = False
        def manager(action, **_kwargs):
            nonlocal active
            calls.append(action)
            if action == 'start':
                active = True
                (self.root / 'revoked.json').write_text('{}')
            elif action == 'stop':
                # Cleanup must remain permitted while the real owner revocation is active.
                with self.assertRaisesRegex(worker.BoundaryError, 'operation-revoked'):
                    worker.require_not_revoked(self.root, self.record)
                active = False
            elif action == 'show':
                return {'InvocationID': 'e' * 32 if active else '',
                        'ControlGroup': native.CGROUP if active else '',
                        'ActiveState': 'active' if active else 'inactive',
                        'SubState': 'running' if active else 'dead',
                        'ExecMainStatus': '0', 'Result': 'success'}
        def paths(value):
            return cgroup if str(value) == '/sys/fs/cgroup' + native.CGROUP else Path(value)
        def owner(_method):
            native._execute({'operation': 'probe'}, {}, timeout=20, output_limit=4096)
            self.fail('revoked native invocation returned an accepted result')
        with ExitStack() as stack:
            for change in (patch.object(native, 'ROOT', native_root),
                           patch.object(native, 'Path', side_effect=paths),
                           patch.object(native, '_secured'),
                           patch.object(native, '_native_identity', return_value=(os.geteuid(), os.getegid())),
                           patch.object(native.os, 'geteuid', return_value=0),
                           patch.object(native.os, 'chown'),
                           patch.object(native, '_installation_identity', return_value='sha256:' + 'f' * 64),
                           patch.object(native, '_manager', side_effect=manager),
                           patch.object(authority, 'dispatch_owned', side_effect=owner)):
                stack.enter_context(change)
            with self.assertRaisesRegex(native.NativeBoundaryError, 'execution-failed'):
                self.client.process(self.selected, 62001)
        self.assertEqual(['show', 'start', 'show', 'stop', 'show'], calls)
        self.assertFalse(active)
        self.assertTrue((self.root / 'intent.json').exists())
        self.assertFalse((self.root / 'result.json').exists())
        self.assertFalse((native_root / 'active.json').exists())
        self.assertEqual(1, len(list(native_root.glob('*/failure.json'))))
        self.assertEqual([], list(native_root.glob('*/complete.json')))

    def test_lost_response_after_durable_result_collects_without_new_work(self):
        persist = worker.persist
        def lose_response(path, value):
            persist(path, value)
            if path.name == 'result.json':
                raise OSError('synthetic-response-loss-after-durable-result')
        with patch.object(worker, 'persist', side_effect=lose_response), \
                patch.object(worker, 'dispatch', return_value={'status': 'prepared'}) as owner:
            with self.assertRaisesRegex(OSError, 'synthetic-response-loss'):
                self.client.process(self.selected, 62001)
            owner.assert_called_once()
        retained = (self.root / 'result.json').read_bytes()
        expected = json.loads(retained)
        with patch.object(worker, 'dispatch') as owner, \
                patch.object(worker, 'authenticate_job') as authentication, \
                patch.object(worker, 'operation_deadline') as deadline:
            restarted = worker.Worker(self.record['bundleIdentity'])
            retried = restarted.process(self.selected, 62001)
            collected = restarted.process({'method': 'collect', 'handle': self.handle}, 62001)
        self.assertEqual({'status': 'complete', 'receipt': expected['receipt'], 'result': expected['result']}, retried)
        self.assertEqual(retried, collected)
        self.assertEqual(retained, (self.root / 'result.json').read_bytes())
        for operation in (owner, authentication, deadline):
            operation.assert_not_called()

    def test_secret_bearing_public_owner_output_is_rejected_before_persistence(self):
        secret = 'Authorization: Bearer synthetic-private-token-123456789'
        with patch.object(worker, 'dispatch', return_value={'status': 'prepared', 'diagnostic': secret}) as owner:
            with self.assertRaisesRegex(worker.BoundaryError, '^restricted-public-projection-rejected$') as rejected:
                self.client.process(self.selected, 62001)
            self.assertNotIn(secret, str(rejected.exception))
            with self.assertRaisesRegex(worker.BoundaryError, 'reconciliation-required'):
                worker.Worker(self.record['bundleIdentity']).process(self.selected, 62001)
            owner.assert_called_once()
        self.assertTrue((self.root / 'intent.json').exists())
        self.assertFalse((self.root / 'result.json').exists())
        self.assertNotIn(secret.encode(), (self.root / 'intent.json').read_bytes())

    def test_registration_replacement_during_owner_cannot_reuse_intent(self):
        def replace(*_):
            (self.root / 'registration.json').write_bytes(worker.encode(
                {**self.record, 'bundleIdentity': 'd' * 64}))
            return {'status': 'prepared'}
        with patch.object(worker, 'dispatch', side_effect=replace):
            with self.assertRaisesRegex(worker.BoundaryError, 'registration-substituted'):
                self.client.process(self.selected, 62001)
        self.assertTrue((self.root / 'intent.json').exists())
        self.assertFalse((self.root / 'result.json').exists())

    def test_owner_expiry_retains_intent_without_authority(self):
        original = worker.now()
        with patch.object(worker, 'now', return_value=original) as clock:
            def expire(*_):
                clock.return_value = worker.utc(self.record['expiresAt'])
                return {'status': 'prepared'}
            with patch.object(worker, 'dispatch', side_effect=expire) as owner:
                with self.assertRaisesRegex(worker.BoundaryError, 'operation-expired'):
                    self.client.process(self.selected, 62001)
                clock.return_value = original
                with self.assertRaisesRegex(worker.BoundaryError, 'reconciliation-required'):
                    self.client.process(self.selected, 62001)
                owner.assert_called_once()
        self.assertTrue((self.root / 'intent.json').exists())
        self.assertFalse((self.root / 'result.json').exists())

    def test_original_signal_budget_covers_durable_result_write(self):
        persist = worker.persist
        handler = None
        def select_handler(_signal, selected):
            nonlocal handler
            if callable(selected):
                handler = selected
            return None
        def write(path, value):
            if path.name == 'result.json':
                self.assertIsNotNone(worker._DEADLINE.get())
                handler(None, None)
            return persist(path, value)
        with patch.object(worker.signal, 'signal', side_effect=select_handler), \
                patch.object(worker.signal, 'setitimer') as timer, \
                patch.object(worker, 'persist', side_effect=write), \
                patch.object(worker, 'dispatch', return_value={'status': 'prepared'}):
            with self.assertRaisesRegex(worker.BoundaryError, 'operation-deadline'):
                self.client.process(self.selected, 62001)
        self.assertEqual([(worker.signal.ITIMER_REAL, 900), (worker.signal.ITIMER_REAL, 0)],
                         [call.args for call in timer.call_args_list])
        self.assertIsNone(worker._DEADLINE.get())
        self.assertTrue((self.root / 'intent.json').exists())
        self.assertFalse((self.root / 'result.json').exists())

    def test_completed_retry_does_not_reauthenticate_or_restart_deadline(self):
        with patch.object(worker, 'dispatch', return_value={'status': 'prepared'}):
            original = self.client.process(self.selected, 62001)
        retained = (self.root / 'result.json').read_bytes()
        with patch.object(worker, 'authenticate_job') as authentication, \
                patch.object(worker, 'dispatch') as owner, \
                patch.object(worker, 'operation_deadline') as deadline, \
                patch.object(worker, 'check_inputs') as input_validation, \
                patch.object(worker, 'now', return_value=worker.utc(self.record['expiresAt'])):
            self.assertEqual(original, self.client.process(self.selected, 62001))
            self.assertEqual(original, self.client.process({'method': 'collect', 'handle': self.handle}, 62001))
        for operation in (authentication, owner, deadline, input_validation):
            operation.assert_not_called()
        self.assertEqual(retained, (self.root / 'result.json').read_bytes())

    @unittest.skipUnless(sys.platform == 'linux', 'native owning boundary requires Linux')
    def test_native_nested_owner_keeps_deadline_and_revocation_callback(self):
        import restricted_native as native
        import restricted_maintenance as maintenance
        deadline = worker.time.monotonic() + 30
        token = worker._DEADLINE.set(deadline)
        self.addCleanup(worker._DEADLINE.reset, token)
        def consume(*_args):
            context, check = native._ACTIVE.get()
            self.assertEqual(deadline, context['deadlineMonotonic'])
            self.assertEqual(self.handle, context['operationId'])
            self.assertEqual(worker.digest((self.root / 'registration.json').read_bytes()),
                             context['registrationDigest'])
            check()
            with native.owning_boundary():
                self.assertEqual((context, check), native._ACTIVE.get())
                (self.root / 'revoked.json').write_text('{}')
                with self.assertRaisesRegex(worker.BoundaryError, 'operation-revoked'):
                    native._ACTIVE.get()[1]()
            return {'status': 'prepared'}
        with patch.object(native, '_secured'), patch.object(native.os, 'geteuid', return_value=0), \
                patch.object(maintenance, 'dispatch', side_effect=consume):
            worker.dispatch({**self.record, 'method': 'maintenance-prepare'}, self.root)
        self.assertFalse(native._ACTIVE.get())

    def test_revocation_during_final_input_validation_prevents_durable_authority(self):
        validate = worker.check_inputs
        calls = 0
        def check(record, root):
            nonlocal calls
            validate(record, root)
            calls += 1
            if calls == 2:
                (self.root / 'revoked.json').write_text('{}')
        with patch.object(worker, 'check_inputs', side_effect=check), \
                patch.object(worker, 'dispatch', return_value={'status': 'prepared'}):
            with self.assertRaisesRegex(worker.BoundaryError, 'operation-revoked'):
                self.client.process(self.selected, 62001)
        self.assertTrue((self.root / 'intent.json').exists())
        self.assertFalse((self.root / 'result.json').exists())

    def test_monotonic_expiry_during_final_validation_prevents_durable_authority(self):
        import cryptad_certification.redaction as redaction
        with patch.object(worker.time, 'monotonic', return_value=100) as clock:
            def scan(_public):
                clock.return_value = 1000
                return []
            with patch.object(redaction, 'scan_value', side_effect=scan), \
                    patch.object(worker, 'dispatch', return_value={'status': 'prepared'}):
                with self.assertRaisesRegex(worker.BoundaryError, 'operation-expired'):
                    self.client.process(self.selected, 62001)
        self.assertTrue((self.root / 'intent.json').exists())
        self.assertFalse((self.root / 'result.json').exists())

    def test_native_success_never_enables_supervisor_role_operations(self):
        for method in ('supervisor-authorize', 'supervisor-start', 'supervisor-checkpoint'):
            with self.subTest(method=method):
                with self.assertRaisesRegex(worker.BoundaryError, 'workload-observer-boundary-unavailable'):
                    worker.dispatch({**self.record, 'method': method}, self.root)

    def finish_provider(self, status, conclusion=None):
        self.record['method'] = 'supervisor-finish'
        self.selected['method'] = 'supervisor-finish'
        (self.root / 'registration.json').write_bytes(worker.encode(self.record))
        context = self.record['context']
        responses = {
            'repos/crypta-network/cryptad/actions/runs/1': {'run_attempt': 1},
            'repos/crypta-network/cryptad/actions/runs/1/attempts/1': {
                'id': 1, 'run_attempt': 1, 'path': worker.POLICIES['supervisor-finish'][0],
                'head_sha': context['sourceCommit'], 'event': 'workflow_dispatch',
                'repository': {'full_name': 'crypta-network/cryptad'},
                'actor': {'login': 'leumor'}, 'triggering_actor': {'login': 'leumor'}},
            'repos/crypta-network/cryptad/actions/jobs/2': {
                'id': 2, 'run_id': 1, 'run_attempt': 1,
                'name': worker.POLICIES['supervisor-finish'][1], 'head_sha': context['sourceCommit'],
                'status': status, 'conclusion': conclusion, 'started_at': self.record['notBefore']},
        }
        return lambda arguments, environment: responses[arguments[1]]

    def test_finished_job_cannot_execute_terminal_owner_or_persist_intent(self):
        import original_artifact_authentication as original
        for status, conclusion in (('completed', 'success'), ('completed', 'failure'),
                                   ('completed', 'cancelled'), ('queued', None)):
            with self.subTest(status=status, conclusion=conclusion):
                provider = self.finish_provider(status, conclusion)
                with patch.object(original, '_gh', side_effect=provider), \
                        patch.object(worker, 'authenticate_job', side_effect=AUTHENTICATE_JOB), \
                        patch.object(worker, 'dispatch') as owner:
                    with self.assertRaisesRegex(worker.BoundaryError, 'original-job-rejected'):
                        self.client.process(self.selected, 62001)
                owner.assert_not_called()
                self.assertFalse((self.root / 'intent.json').exists())
                self.assertFalse((self.root / 'result.json').exists())

    def test_active_finish_executes_once_and_retained_result_survives_job_completion(self):
        import original_artifact_authentication as original
        with patch.object(original, '_gh', side_effect=self.finish_provider('in_progress')), \
                patch.object(worker, 'authenticate_job', side_effect=AUTHENTICATE_JOB), \
                patch.object(worker, 'dispatch', return_value={'status': 'stopped'}) as owner:
            first = self.client.process(self.selected, 62001)
            owner.assert_called_once()
            with patch.object(original, '_gh', side_effect=self.finish_provider('completed', 'success')) as provider, \
                    patch.object(worker, 'now', return_value=worker.utc(self.record['expiresAt']) + dt.timedelta(seconds=1)):
                retried = worker.Worker('b' * 64).process(self.selected, 62001)
                collected = self.client.process({'method': 'collect', 'handle': self.handle}, 62001)
                provider.assert_not_called()
            self.assertEqual(first, retried)
            self.assertEqual(first, collected)
            owner.assert_called_once()

    def test_lost_owner_response_leaves_intent_and_prevents_repeat(self):
        with patch.object(worker, 'dispatch', side_effect=OSError('synthetic disconnect')) as owner:
            with self.assertRaises(OSError):
                self.client.process(self.selected, 62001)
            with self.assertRaisesRegex(worker.BoundaryError, 'reconciliation-required'):
                self.client.process(self.selected, 62001)
        self.assertTrue((self.root / 'intent.json').exists())
        self.assertFalse((self.root / 'result.json').exists())
        owner.assert_called_once()

    def test_another_uid_or_changed_method_cannot_use_registered_handle(self):
        with patch.object(worker, 'dispatch') as owner:
            for selected, uid in ((self.selected, 62002),
                                  ({'method': 'baseline-approve', 'handle': self.handle}, 62001)):
                with self.assertRaises(worker.BoundaryError):
                    self.client.process(selected, uid)
        owner.assert_not_called()

    def test_replaced_result_and_revoked_version_fail_collection(self):
        with patch.object(worker, 'dispatch', return_value={'status': 'prepared'}):
            self.client.process(self.selected, 62001)
        path = self.root / 'result.json'
        path.chmod(0o600)
        result = json.loads(path.read_bytes())
        result['result'] = {'status': 'approved'}
        path.write_bytes(worker.encode(result))
        with self.assertRaisesRegex(worker.BoundaryError, 'result-substituted'):
            self.client.process({'method': 'collect', 'handle': self.handle}, 62001)
        (self.state / 'revocations.json').write_bytes(worker.encode(['b' * 64]))
        with self.assertRaisesRegex(worker.BoundaryError, 'operation-revoked'):
            self.client.process(self.selected, 62001)

    @contextmanager
    def original_admission(self):
        import hashlib
        import restricted_results
        with patch.object(worker, 'dispatch', return_value={'status': 'prepared'}):
            public = self.client.process(self.selected, 62001)['result']
        prefix = self.state / 'installed'
        manifest = worker.encode({'sourceCommit': 'd' * 40})  # Helper revision differs from workflow.
        version = prefix / 'versions' / hashlib.sha256(manifest).hexdigest()
        version.mkdir(parents=True)
        (version / '.restricted-manifest.json').write_bytes(manifest)
        (self.operations / '.registration-unfinished').mkdir()
        with patch.object(restricted_results, 'PREFIX', prefix), \
                patch.object(restricted_results, '__file__', str(prefix / 'restricted_results.py')), \
                patch.object(restricted_results.os, 'geteuid', return_value=0):
            def verify(raw=worker.encode(public) + b'\n'):
                restricted_results.verify_original(raw, self.record['context'], {'baseline-prepare'})
            yield verify

    def test_original_result_with_distinct_workflow_revision_still_requires_exact_retained_bytes(self):
        with self.original_admission() as verify:
            verify()
            with self.assertRaisesRegex(worker.BoundaryError, 'original-owner-result-unavailable'):
                verify(b'{"status":"approved"}\n')

    def test_original_admission_rejects_completed_operation_revoked_after_upload(self):
        with self.original_admission() as verify:
            verify()
            (self.root / 'revoked.json').write_text('{}')
            with self.assertRaisesRegex(worker.BoundaryError, 'operation-revoked'):
                verify()
            with self.assertRaisesRegex(worker.BoundaryError, 'operation-revoked'):
                self.client.process({'method': 'collect', 'handle': self.handle}, 62001)

    def test_original_admission_rejects_completed_bundle_revoked_after_upload(self):
        with self.original_admission() as verify:
            verify()
            (self.state / 'revocations.json').write_bytes(worker.encode([self.record['bundleIdentity']]))
            with self.assertRaisesRegex(worker.BoundaryError, 'operation-revoked'):
                verify()
            with self.assertRaisesRegex(worker.BoundaryError, 'operation-revoked'):
                self.client.process({'method': 'collect', 'handle': self.handle}, 62001)

    def test_original_admission_fails_closed_on_missing_or_invalid_revocations(self):
        with self.original_admission() as verify:
            for raw in (b'{}', b'[null]', b'["invalid"]', b'[', worker.encode([int('1' * 64)])):
                with self.subTest(raw=raw):
                    (self.state / 'revocations.json').write_bytes(raw)
                    with self.assertRaises(worker.BoundaryError):
                        verify()
            (self.state / 'revocations.json').unlink()
            with self.assertRaises(OSError):
                verify()

    def test_unrelated_revocations_do_not_invalidate_original_result(self):
        with self.original_admission() as verify:
            (self.state / 'revocations.json').write_bytes(worker.encode(['e' * 64]))
            unrelated = self.operations / ('f' * 64)
            unrelated.mkdir()
            (unrelated / 'registration.json').write_bytes(worker.encode({**self.record,
                'handle': 'f' * 64, 'context': {**self.record['context'], 'runId': 99}}))
            (unrelated / 'revoked.json').write_text('{}')
            verify()

    def test_dangling_operation_revocation_marker_still_blocks_original_admission(self):
        with self.original_admission() as verify:
            (self.root / 'revoked.json').symlink_to('missing-marker-target')
            with self.assertRaisesRegex(worker.BoundaryError, 'operation-revoked'):
                verify()


if __name__ == '__main__':
    unittest.main()

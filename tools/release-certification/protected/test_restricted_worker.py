"""Durable request semantics with explicit authority seams; not a multi-UID isolation test."""
from contextlib import contextmanager, nullcontext
import datetime as dt
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import restricted_worker as worker


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

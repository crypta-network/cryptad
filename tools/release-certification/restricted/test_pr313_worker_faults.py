"""Actual Worker revocation semantics with explicit existing offline authority fixtures."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'protected'))
import restricted_worker as worker
import test_restricted_worker as fixtures
import pr313_worker_faults as faults


class WorkerFaultWitnessTest(unittest.TestCase):
    def test_completed_result_is_denied_after_actual_marker(self):
        fixture = fixtures.DurableWorkerTest()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        with patch.object(worker, 'dispatch', return_value={'schemaVersion': 1, 'status': 'prepared'}):
            fixture.client.process(fixture.selected, fixture.record['callerUid'])
        retained = (fixture.root / 'result.json').read_bytes()
        worker.persist(fixture.root / 'revoked.json', {'reason': 'synthetic'})
        faults.require_revoked_retry(fixture.client, fixture.record)
        self.assertEqual(retained, (fixture.root / 'result.json').read_bytes())

    def test_public_artifacts_reject_unknown_fields_before_returning_bytes(self):
        for response in (b'{"status":"unavailable","detail":"private-prose"}',
                         b'{"status":"complete","accepted":true}', b'not-json'):
            with self.subTest(response=response), self.assertRaises(ValueError):
                faults.public_artifacts(response, 'private-prose', 'candidate-payload')
        artifacts = faults.public_artifacts(b'{"status":"unavailable"}', 'private-prose', 'candidate-payload')
        self.assertEqual({'report.json', 'summary.md', 'client.log'}, set(artifacts))
        for raw in artifacts.values():
            self.assertNotIn(b'private-prose', raw)
            self.assertNotIn(b'candidate-payload', raw)

    def test_setup_failure_is_not_credited_as_revocation(self):
        fixture = fixtures.DurableWorkerTest()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        (fixture.root / 'registration.json').write_bytes(b'invalid')
        with self.assertRaises(ValueError):
            faults.require_revoked_retry(fixture.client, fixture.record)


if __name__ == '__main__':
    unittest.main()

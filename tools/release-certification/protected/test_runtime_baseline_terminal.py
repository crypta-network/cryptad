"""Expired baseline eligibility must not erase original stopped execution evidence."""
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import cross_version_supervisor_authority as owner
import runtime_baseline_admission as admission
import runtime_baseline_approval as approval
import maintenance_runtime_projection as projection
from test_runtime_baseline_admission import prepared_pair
from test_maintenance_runtime_projection import checkpoint_for, rechain


class BaselineTerminalTest(unittest.TestCase):
    def test_uncompared_projection_preserves_blockers_and_hides_private_commitments(self):
        _, (fixture, selection, _, _) = prepared_pair()
        historical = projection.project(*fixture)
        result = projection.without_current_baseline(historical, selection['scope'])
        self.assertEqual(5, result['schemaVersion'])
        self.assertEqual('not-observed', result['runtimeBaselineAdmission']['status'])
        self.assertEqual('blocked', result['runtimeBaselineAdmission']['scopedPerformanceVerdict'])
        self.assertEqual(historical['rows'], result['rows'])
        for field in ('workloadDigest', 'seriesDigest', 'evidenceDigest'):
            self.assertNotIn(field, result['runtimeComponents'])
            self.assertIn(field, historical['runtimeComponents'])
        self.assertEqual(result, projection.validate(result))

    def exercise(self, status, error, *, collect=True):
        if not hasattr(os, 'geteuid') or os.geteuid() != 0:
            self.skipTest('isolated sudo invocation required for original private retention')
        _, (fixture, selection, _, _) = prepared_pair()
        plan, events, checkpoint, _ = copy.deepcopy(fixture)
        if status != 'complete':
            events.pop()  # The fixed controller records fault/cleanup, without finish.
            cleanup = events[-1]
            fault = {**cleanup, 'kind': 'fault', 'outcome': 'fail' if status == 'failed' else 'partial',
                     'role': '', 'scenario': '', 'operation': ''}
            events.insert(-1, fault)
            rechain(events)
            checkpoint = checkpoint_for(plan, events)
            checkpoint['status'] = status
        with tempfile.TemporaryDirectory(dir='/run') as temporary:
            root = Path(temporary)
            state, authority, runtime, store = (root / name for name in ('state', 'authority', 'runtime', 'store'))
            for path in (state, authority, runtime, store, state / 'selected', runtime / 'scheduler-observation'):
                path.mkdir(mode=0o700)
            authority.chmod(0o755)
            private = {'root': str(runtime), 'runtimeBaseline': selection}
            authorization = {}
            values = {'plan': plan, 'private-config': private, 'authorization': authorization, 'service-selection': {}}
            for name, value in values.items():
                path = state / 'selected' / (name + '.json')
                path.write_bytes(admission.encode(value))
                path.chmod(0o600)
            for path, raw in (
                    (runtime / 'checkpoint.json', admission.encode(checkpoint)),
                    (runtime / 'journal.jsonl', b''.join(admission.encode(event) + b'\n' for event in events)),
                    (runtime / 'scheduler-observation/runtime-input-snapshot.json', admission.encode({'synthetic': True}))):
                path.write_bytes(raw)
                path.chmod(0o600)
            bindings = {'serviceDigest': 'sha256:' + 'a' * 64, 'planDigest': admission.digest(plan)}
            with patch.object(owner, 'AUTHORITY', authority), patch.object(owner, 'STATE', state), \
                    patch.object(owner, 'CONFIG', authority), patch.object(approval, 'PRIVATE_STORE', store), \
                    patch.object(owner, 'selected_inputs', return_value=(plan, private, authorization, 0, bindings)), \
                    patch.object(owner, 'run_identity', return_value=plan['producer']), \
                    patch.object(owner, '_service_state', return_value='stopped'), \
                    patch.object(admission, 'authenticate_selected', side_effect=approval.ApprovalError(error)), \
                    patch.object(admission, 'project_owned_baseline') as compare:
                binding = owner._runtime_authorization(bindings, create=True)
                activation = {'schemaVersion': 2, 'planDigest': admission.digest(plan), 'producer': plan['producer'],
                    'ownerUid': 0, 'bootId': owner.boot_id(), 'products': [], 'selectionDigest': binding,
                    'approvalOrigin': {'artifactId': 1}, 'approvalReportDigest': 'sha256:' + 'b' * 64,
                    'privateRuntimeContext': 'runtime-baseline-v1'}
                for name, value in (('activation', activation), ('cross-version-previous', {})):
                    path = authority / (name + '.json')
                    path.write_bytes(admission.encode(value))
                    path.chmod(0o600)
                previous = {'schemaVersion': 5, 'operation': 'start', 'experimentId': plan['experimentId'],
                    'planDigest': admission.digest(plan), 'producer': plan['producer'], 'selectionDigest': binding,
                    'approvalOrigin': activation['approvalOrigin']}
                with patch.object(owner, 'authenticate_report', return_value=(previous, {'artifactId': 2})):
                    for operation in ('authorize', 'start'):
                        with self.assertRaisesRegex(approval.ApprovalError, error):
                            owner.control(operation)
                    if not collect:
                        with self.assertRaisesRegex(approval.ApprovalError, error):
                            owner.control('finish')
                        return
                    report = owner.control('finish')
                    retained = store / 'observations' / (plan['experimentId'] + '.json')
                    raw = retained.read_bytes()
                    capsule = admission.decode(raw)
                    self.assertEqual(events, capsule['events'])
                    self.assertEqual(checkpoint, capsule['checkpoint'])
                    self.assertEqual(activation, capsule['activation'])
                    self.assertEqual(admission.digest(checkpoint), report['checkpoint']['digest'])
                    self.assertEqual(status, report['checkpoint']['status'])
                    measurements = report['maintenanceMeasurements']
                    self.assertNotIn('runtimeBaselineAdmission', measurements)
                    performance = next(row for row in measurements['rows'] if row['id'].endswith('.performance'))
                    self.assertIn('reviewed-runtime-baseline-missing', performance['blockers'])
                    self.assertTrue(all(row['status'] == 'blocked' for row in measurements['rows']))
                    owner.control('finish')
                    self.assertEqual(raw, retained.read_bytes())
                    compare.assert_not_called()

    def test_expired_approval_preserves_complete_failed_and_cancelled_terminal_evidence(self):
        for status in ('complete', 'failed', 'partial'):
            with self.subTest(status=status):
                self.exercise(status, 'runtime-approval-not-currently-applicable')

    def test_revoked_approval_preserves_terminal_evidence_without_comparison(self):
        self.exercise('complete', 'runtime-approval-context-revoked-or-superseded')

    def test_invalid_approval_provenance_remains_an_error(self):
        for error in ('runtime-approval-attested-attempt-mismatch', 'runtime-approval-original-job-integrity-invalid'):
            with self.subTest(error=error):
                self.exercise('complete', error, collect=False)


if __name__ == '__main__':
    unittest.main()

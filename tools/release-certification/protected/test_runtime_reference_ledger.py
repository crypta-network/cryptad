"""Root ledger native file tests; terminal capsules remain synthetic owner fixtures."""
import copy
import datetime as dt
import os
from pathlib import Path
import tempfile
import unittest
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import runtime_reference_ledger as ledger
import runtime_baseline_approval as approvals
import runtime_baseline_admission as admission
from test_runtime_baseline_admission import vector, stamp


class Clock(dt.datetime):
    seconds = 1

    @classmethod
    def now(cls, tz=None):
        return cls.fromisoformat(stamp(cls.seconds))


class ReferenceLedgerTest(unittest.TestCase):
    def setUp(self):
        if not hasattr(os, 'geteuid') or os.geteuid() != 0:
            self.skipTest('isolated sudo invocation required for real root ownership checks')
        self.temp = tempfile.TemporaryDirectory(dir='/run')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = self.root / 'store'
        self.store.mkdir(mode=0o700)
        (self.store / 'observations').mkdir(mode=0o700)
        self.patch_store = patch.object(approvals, 'PRIVATE_STORE', self.store)
        self.patch_store.start()
        self.addCleanup(self.patch_store.stop)
        self.patch_clock = patch.object(ledger.dt, 'datetime', Clock)
        self.patch_clock.start()
        self.addCleanup(self.patch_clock.stop)
        Clock.seconds = 1
        self.campaign, self.rows, self.policy = vector()

    def terminal(self, index, *, outcome='pass', invalid=False, no_series=False):
        row = copy.deepcopy(self.rows[index])
        evidence = {'series': row['series'], 'policy': self.policy}
        if invalid:
            evidence['series']['samples'][4]['metrics']['rssBytes'] = None
        event = {'wallTime': row['startedAt'], 'outcome': 'pass', 'kind': 'start'}
        if not no_series:
            event['runtimeEvidence'] = evidence
        cleanup = {'wallTime': row['finishedAt'], 'outcome': 'pass', 'kind': 'cleanup',
                   'role': '', 'scenario': '', 'operation': ''}
        if outcome in {'fail', 'cancelled'}:
            fault = {**cleanup, 'kind': 'fault', 'outcome': 'fail' if outcome == 'fail' else 'partial'}
            events = [event, fault, cleanup]
            status = 'failed' if outcome == 'fail' else 'partial'
        else:
            events = [event, cleanup, {**cleanup, 'kind': 'finish'}]
            status = 'complete'
        capsule = {'plan': {'experimentId': row['experimentId']},
                   'authorization': {'runtimeReference': self.campaign},
                   'checkpoint': {'status': status}, 'events': events}
        path = self.store / 'observations' / (row['experimentId'] + '.json')
        path.write_bytes(admission.encode(capsule))
        path.chmod(0o400)
        return path

    def first(self):
        ledger.begin(self.campaign, self.campaign['attempts'][0], self.policy)
        self.terminal(0)
        Clock.seconds = 40

    def complete(self):
        self.first()
        ledger.begin(self.campaign, self.campaign['attempts'][1], self.policy)
        self.terminal(1)
        Clock.seconds = 80

    def test_complete_actual_roster_stops_further_measurement(self):
        self.complete()
        ledger.verify_complete(self.campaign, self.campaign['attempts'])
        with self.assertRaisesRegex(ledger.LedgerError, 'next-attempt-invalid'):
            ledger.begin(self.campaign, 'reference-3', self.policy)
        with self.assertRaisesRegex(ledger.LedgerError, 'roster-mismatch'):
            ledger.verify_complete(self.campaign, self.campaign['attempts'][:1])

    def test_unused_replacement_slot_cannot_become_favorable_extra_measurement(self):
        self.campaign.update(maximumReplacements=1, replacementOutcomes=['invalid'],
                             attempts=['reference-1', 'reference-2', 'spare-attempt'])
        self.complete()
        ledger.verify_complete(self.campaign, ['reference-1', 'reference-2'])
        with self.assertRaisesRegex(ledger.LedgerError, 'next-attempt-invalid'):
            ledger.begin(self.campaign, 'spare-attempt', self.policy)

    def test_pending_started_attempt_blocks_next_and_verification(self):
        ledger.begin(self.campaign, 'reference-1', self.policy)
        with self.assertRaisesRegex(ledger.LedgerError, 'attempt-pending'):
            ledger.begin(self.campaign, 'reference-2', self.policy)
        with self.assertRaisesRegex(ledger.LedgerError, 'attempt-pending'):
            ledger.verify_complete(self.campaign, ['reference-1'])

    def test_exact_activation_retry_preserves_marker_and_cannot_advance_campaign(self):
        identity = 'sha256:' + 'a' * 64
        ledger.begin(self.campaign, 'reference-1', self.policy, activation_digest=identity)
        path = self.store / 'campaigns' / self.campaign['campaignId'] / 'attempt-00.json'
        raw = path.read_bytes()
        Clock.seconds = 5
        ledger.begin(self.campaign, 'reference-1', self.policy, activation_digest=identity)
        self.assertEqual(raw, path.read_bytes())
        with self.assertRaisesRegex(ledger.LedgerError, 'start-substituted'):
            ledger.begin(self.campaign, 'reference-1', self.policy, activation_digest='sha256:' + 'b' * 64)
        with self.assertRaisesRegex(ledger.LedgerError, 'attempt-pending'):
            ledger.begin(self.campaign, 'reference-2', self.policy, activation_digest=identity)
        with self.assertRaisesRegex(ledger.LedgerError, 'attempt-pending'):
            ledger.verify_complete(self.campaign, ['reference-1'])

    def test_historical_marker_cannot_acquire_activation_retry_authority(self):
        ledger.begin(self.campaign, 'reference-1', self.policy)
        with self.assertRaisesRegex(ledger.LedgerError, 'start-substituted'):
            ledger.begin(self.campaign, 'reference-1', self.policy, activation_digest='sha256:' + 'a' * 64)

    def test_renamed_reordered_and_changed_campaign_cannot_reselect(self):
        with self.assertRaisesRegex(ledger.LedgerError, 'next-attempt-invalid'):
            ledger.begin(self.campaign, 'reference-2', self.policy)
        ledger.begin(self.campaign, 'reference-1', self.policy)
        changed = copy.deepcopy(self.campaign)
        changed['timeoutSeconds'] += 1
        with self.assertRaisesRegex(ledger.LedgerError, 'campaign-substituted'):
            ledger.begin(changed, 'reference-1', self.policy)
        changed = copy.deepcopy(self.campaign)
        changed['attempts'][0] = 'renamed-reference'
        with self.assertRaisesRegex(ledger.LedgerError, 'campaign-substituted'):
            ledger.verify_complete(changed, changed['attempts'])

    def test_failed_attempt_requires_predeclared_replacement_and_remains_in_roster(self):
        self.campaign.update(maximumReplacements=1, replacementOutcomes=['failed'],
                             attempts=['failed-attempt', 'reference-1', 'reference-2'])
        failed = copy.deepcopy(self.rows[0])
        failed.update(experimentId='failed-attempt', startedAt=stamp(2), finishedAt=stamp(5))
        self.rows.insert(0, failed)
        ledger.begin(self.campaign, 'failed-attempt', self.policy)
        self.terminal(0, outcome='fail', no_series=True)
        Clock.seconds = 10
        ledger.begin(self.campaign, 'reference-1', self.policy)
        self.terminal(1)
        Clock.seconds = 40
        ledger.begin(self.campaign, 'reference-2', self.policy)
        self.terminal(2)
        Clock.seconds = 80
        ledger.verify_complete(self.campaign, self.campaign['attempts'])
        with self.assertRaisesRegex(ledger.LedgerError, 'roster-mismatch'):
            ledger.verify_complete(self.campaign, ['reference-1', 'reference-2'])

    def test_unplanned_invalid_reference_cannot_be_replaced(self):
        ledger.begin(self.campaign, 'reference-1', self.policy)
        self.terminal(0, invalid=True)
        Clock.seconds = 40
        with self.assertRaisesRegex(ledger.LedgerError, 'replacement-not-planned'):
            ledger.begin(self.campaign, 'reference-2', self.policy)

    def test_cancellation_requires_its_own_predeclared_disposition(self):
        self.campaign.update(maximumReplacements=1, replacementOutcomes=['failed'],
                             attempts=['reference-1', 'reference-2', 'spare-attempt'])
        ledger.begin(self.campaign, 'reference-1', self.policy)
        self.terminal(0, outcome='cancelled', no_series=True)
        Clock.seconds = 40
        with self.assertRaisesRegex(ledger.LedgerError, 'replacement-not-planned'):
            ledger.begin(self.campaign, 'reference-2', self.policy)

    def test_failed_controller_with_retained_numeric_series_uses_failed_disposition(self):
        self.campaign.update(maximumReplacements=1, replacementOutcomes=['failed'],
                             attempts=['reference-1', 'reference-2', 'spare-attempt'])
        ledger.begin(self.campaign, 'reference-1', self.policy)
        self.terminal(0, outcome='fail')
        Clock.seconds = 40
        ledger.begin(self.campaign, 'reference-2', self.policy)
        with self.assertRaisesRegex(ledger.LedgerError, 'attempt-pending'):
            ledger.verify_complete(self.campaign, ['reference-1', 'reference-2'])

    def test_actual_controller_interruption_allows_predeclared_cancelled_replacement(self):
        self.campaign.update(maximumReplacements=1, replacementOutcomes=['cancelled'],
                             attempts=['reference-1', 'reference-2', 'spare-attempt'])
        ledger.begin(self.campaign, 'reference-1', self.policy)
        self.terminal(0, outcome='cancelled')
        Clock.seconds = 40
        ledger.begin(self.campaign, 'reference-2', self.policy)

    def test_partial_checkpoint_without_controller_fault_cannot_claim_cancellation(self):
        self.campaign.update(maximumReplacements=1, replacementOutcomes=['cancelled'],
                             attempts=['reference-1', 'reference-2', 'spare-attempt'])
        ledger.begin(self.campaign, 'reference-1', self.policy)
        path = self.terminal(0, outcome='cancelled')
        value = admission.decode(path.read_bytes())
        value['events'] = [event for event in value['events'] if event['kind'] != 'fault']
        path.write_bytes(admission.encode(value))
        Clock.seconds = 40
        with self.assertRaisesRegex(ledger.LedgerError, 'terminal-capsule-invalid'):
            ledger.begin(self.campaign, 'reference-2', self.policy)

    def test_terminal_capsule_cannot_be_rebound_or_marked_complete_by_upload(self):
        ledger.begin(self.campaign, 'reference-1', self.policy)
        path = self.terminal(0)
        Clock.seconds = 40
        value = admission.decode(path.read_bytes())
        value['checkpoint']['status'] = 'running'
        path.write_bytes(admission.encode(value))
        with self.assertRaisesRegex(ledger.LedgerError, 'terminal-capsule-invalid'):
            ledger.begin(self.campaign, 'reference-2', self.policy)
        value['checkpoint']['status'] = 'complete'
        value['events'][0]['runtimeEvidence']['policy']['maximumOutstanding'] += 1
        path.write_bytes(admission.encode(value))
        with self.assertRaisesRegex(ledger.LedgerError, 'applicability-mismatch'):
            ledger.begin(self.campaign, 'reference-2', self.policy)

    def test_extra_markers_and_marker_substitution_reject(self):
        self.complete()
        directory = self.store / 'campaigns' / self.campaign['campaignId']
        extra = directory / 'attempt-16.json'
        extra.write_text('{}')
        extra.chmod(0o400)
        with self.assertRaisesRegex(ledger.LedgerError, 'unexpected-record'):
            ledger.verify_complete(self.campaign, self.campaign['attempts'])
        extra.unlink()
        marker = directory / 'attempt-00.json'
        value = admission.decode(marker.read_bytes())
        value['experimentId'] = 'renamed'
        marker.write_bytes(admission.encode(value))
        with self.assertRaisesRegex(ledger.LedgerError, 'marker-substituted'):
            ledger.verify_complete(self.campaign, self.campaign['attempts'])

    def test_missing_private_capsule_and_public_permissions_do_not_mean_empty(self):
        self.complete()
        path = self.store / 'observations/reference-1.json'
        path.chmod(0o644)
        with self.assertRaisesRegex(ledger.LedgerError, 'private-record-invalid'):
            ledger.verify_complete(self.campaign, self.campaign['attempts'])
        path.unlink()
        with self.assertRaisesRegex(ledger.LedgerError, 'attempt-pending'):
            ledger.verify_complete(self.campaign, self.campaign['attempts'])

    def test_terminal_before_begin_marker_cannot_represent_started_attempt(self):
        Clock.seconds = 25
        ledger.begin(self.campaign, 'reference-1', self.policy)
        self.terminal(0)
        Clock.seconds = 40
        with self.assertRaisesRegex(ledger.LedgerError, 'terminal-clock-invalid'):
            ledger.begin(self.campaign, 'reference-2', self.policy)


if __name__ == '__main__':
    unittest.main()

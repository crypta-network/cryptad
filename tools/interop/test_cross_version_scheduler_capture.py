"""Synthetic event-prefix regressions; no original runtime authority is asserted."""
import copy
import datetime as dt
import unittest
from unittest.mock import patch

import cross_version_runtime as runtime

with runtime.fixed_helper_imports():
    import scheduler_pressure_runtime as scheduler
    from cryptad_certification.tests.test_runtime_pressure_evidence import evidence_fixture, DIGEST, STAMP


def completed_fixture():
    value = evidence_fixture()
    events = []
    for event in value['workEvents']:
        if event['kind'] == 'RATE_CHARGED':
            events.append({**event, 'kind': 'RATE_WRITE_ATTEMPT'})
        events.append(dict(event))
    charged = next(event for event in reversed(events) if event['kind'] == 'RATE_CHARGED')
    events[-1:-1] = [{**charged, 'kind': 'RATE_METADATA_WRITE_ATTEMPT'},
                     {**charged, 'kind': 'RATE_METADATA_WRITTEN'}]
    for sequence, event in enumerate(events, 1):
        event.update(sequence=sequence, elapsedNanos=sequence * 100000000,
                     observedAt=(STAMP + dt.timedelta(milliseconds=100 * sequence)).isoformat())
    value.update(schemaVersion=4, collectorEpoch='01234567-89ab-cdef-0123-456789abcdef', workEvents=events)
    return value


class SchedulerCaptureTest(unittest.TestCase):
    def lane(self, value):
        lane = object.__new__(scheduler.SchedulerLane)
        lane.remaining = lambda seconds: seconds
        lane.runtime_evidence = lambda: copy.deepcopy(value['selected'])
        return lane

    def test_completed_subscription_state_cannot_finalize_an_inflight_native_write(self):
        complete = completed_fixture()
        pending = copy.deepcopy(complete)
        pending['workEvents'] = pending['workEvents'][:-2]
        self.assertEqual('RATE_METADATA_WRITE_ATTEMPT', pending['workEvents'][-1]['kind'])
        selected = {'selected': pending}
        lane = self.lane(selected)
        samples = iter((pending, complete))

        def sample():
            selected['selected'] = next(samples)
            return {'work': {'known': True, 'events': selected['selected']['workEvents']},
                    'budget': {'valid': True, 'activeFamilyLeases': 0, 'reservedFamilyRates': 0},
                    'contentFetch': {'known': True, 'inFlightOperations': 0}}

        lane.sample = sample
        with patch.object(scheduler.time, 'sleep'):
            captured = lane.capture_runtime_evidence()
        before = scheduler.pressure_evidence.derive(pending, workload_digest=DIGEST)
        after = scheduler.pressure_evidence.derive(captured, workload_digest=DIGEST)

        for claim in scheduler.pressure_evidence.CLAIMS[:4]:
            self.assertEqual('not-observed', before['claims'][claim])
            self.assertEqual('observed', after['claims'][claim])
        self.assertEqual(complete['workEvents'], captured['workEvents'])
        self.assertFalse(after['releaseEligible'])

    def test_capture_waits_for_family_holds_and_content_work_to_finish(self):
        complete = completed_fixture()
        selected = {'selected': None}
        lane = self.lane(selected)
        remaining = iter(((1, 0, 0), (0, 1, 0), (0, 0, 1), (0, 0, 0)))

        def sample():
            active, reserved, in_flight = next(remaining)
            selected['selected'] = complete if not (active or reserved or in_flight) else None
            return {'work': {'known': True, 'events': complete['workEvents']},
                    'budget': {'valid': True, 'activeFamilyLeases': active, 'reservedFamilyRates': reserved},
                    'contentFetch': {'known': True, 'inFlightOperations': in_flight}}

        lane.sample = sample
        with patch.object(scheduler.time, 'sleep'):
            self.assertEqual(complete, lane.capture_runtime_evidence())

    def test_capture_keeps_the_existing_deadline_when_no_complete_cut_is_available(self):
        lane = self.lane({'selected': None})
        lane.remaining = lambda seconds: 0
        with self.assertRaisesRegex(scheduler.runtime.RuntimeFailure,
                                    'scheduler-native-capture-not-quiescent'):
            lane.capture_runtime_evidence()

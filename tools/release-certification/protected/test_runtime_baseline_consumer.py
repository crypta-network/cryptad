"""Successor public format tests; structural validity grants no original authority."""
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import maintenance_runtime_projection as projection
import test_maintenance_runtime_projection as fixtures
import test_sealed_runtime_measurements as sealed_fixtures
from cryptad_certification import runtime_pressure_evidence as runtime


def public_comparison():
    return {'schemaVersion': 1, 'kind': 'authenticated-runtime-baseline-comparison',
            'numericComparison': 'within-reviewed-local-bounds',
            'referenceProvenance': 'authenticated', 'approvalAuthentication': 'authenticated',
            'preselectionBinding': 'authenticated', 'originalCandidateObservation': 'authenticated',
            'applicability': 'applicable', 'scopedPerformanceVerdict': 'accepted',
            'claim': 'runtime-within-reviewed-bounds', 'status': 'observed',
            'scope': 'daemon-resource-regression-unchanged-app-cohort', 'evidenceClass': 'synthetic',
            'reasons': [], 'fullAppBudgets': 'not-observed', 'releaseEligible': False}


def serialized_measurement():
    """Construct only an unauthenticated schema vector, never a verifier capability."""
    fixture = fixtures.MaintenanceRuntimeProjectionTest()
    value = fixture.project(fixture.scheduler_fixture())
    value.update(runtimeBaselineBaseVersion=value['schemaVersion'], schemaVersion=5,
                 runtimeBaselineAdmission=public_comparison())
    for key in ('workloadDigest', 'seriesDigest', 'evidenceDigest'):
        value['runtimeComponents'].pop(key)
    for row in value['rows']:
        if row['id'] == projection.PREFIX + 'performance':
            row['blockers'].remove('reviewed-runtime-baseline-missing')
    return value


class RuntimeBaselineConsumerFormatTest(unittest.TestCase):
    def test_successor_preserves_sealed_base_version_and_ciphertext_only_subjects(self):
        helper, fixture = sealed_fixtures.SealedMeasurementsTest().fixture()
        value = helper.project(fixture)
        self.assertEqual(4, value['schemaVersion'])
        value.update(runtimeBaselineBaseVersion=4, schemaVersion=5,
                     runtimeBaselineAdmission=public_comparison())
        self.assertIs(value, projection.validate(value))
        self.assertEqual(2, value['baseMeasurementVersion'])
        encoded = json.dumps(value)
        for private in ('private-selected-canary', 'sha256:' + '9' * 64,
                        'experimentCohortDigest', 'appMatrixDigest', 'bindingDigest'):
            self.assertNotIn(private, encoded)
        malformed = copy.deepcopy(value)
        malformed['baseMeasurementVersion'] = 5
        with self.assertRaises(projection.ProjectionError):
            projection.validate(malformed)

    def test_successor_format_preserves_parent_blockers_and_legacy_claim(self):
        value = serialized_measurement()
        self.assertIs(value, projection.validate(value))
        self.assertTrue(all(row['status'] == 'blocked' for row in value['rows']))
        self.assertEqual('blocked', value['maintenanceEligibility'])
        self.assertEqual('not-observed', value['runtimeComponents']['claims']['runtime-within-reviewed-bounds'])
        self.assertEqual('not-observed', value['runtimeBaselineAdmission']['fullAppBudgets'])

    def test_safe_comparison_cannot_claim_success_without_every_required_proof(self):
        for key, replacement in (
                ('numericComparison', 'fail'), ('numericComparison', 'incomparable'),
                ('referenceProvenance', 'missing'), ('approvalAuthentication', 'missing'),
                ('preselectionBinding', 'missing'), ('originalCandidateObservation', 'missing'),
                ('applicability', 'revoked'), ('applicability', 'expired')):
            with self.subTest(key=key, replacement=replacement):
                value = public_comparison()
                value[key] = replacement
                with self.assertRaises(runtime.RuntimeEvidenceError):
                    runtime.validate_authenticated_comparison(value)

    def test_baseline_blocker_removal_requires_subject_and_derivation_admission(self):
        for component in ('subjectAdmission', 'measurementDerivation'):
            with self.subTest(component=component):
                value = serialized_measurement()
                value[component]['status'] = 'blocked'
                with self.assertRaises(projection.ProjectionError):
                    projection.validate(value)

    def test_private_commitments_are_rejected_in_successor_public_component(self):
        for key in ('workloadDigest', 'seriesDigest', 'evidenceDigest'):
            with self.subTest(key=key):
                value = serialized_measurement()
                value['runtimeComponents'][key] = 'sha256:' + 'a' * 64
                with self.assertRaises(projection.ProjectionError):
                    projection.validate(value)
        value = public_comparison()
        value['baselineDigest'] = 'sha256:' + 'a' * 64
        with self.assertRaises(runtime.RuntimeEvidenceError):
            runtime.validate_authenticated_comparison(value)

    def test_legacy_format_cannot_inherit_successor_claim(self):
        fixture = fixtures.MaintenanceRuntimeProjectionTest()
        value = fixture.project(fixture.scheduler_fixture())
        value['runtimeComponents']['claims']['runtime-within-reviewed-bounds'] = 'observed'
        with self.assertRaises(projection.ProjectionError):
            projection.validate(value)

    def test_successor_cannot_promote_complete_performance_or_other_rows(self):
        for key, replacement in (('fullAppBudgets', 'observed'), ('releaseEligible', True)):
            value = public_comparison()
            value[key] = replacement
            with self.assertRaises(runtime.RuntimeEvidenceError):
                runtime.validate_authenticated_comparison(value)
        value = serialized_measurement()
        value['rows'][0]['status'] = 'pass'
        with self.assertRaises(projection.ProjectionError):
            projection.validate(value)

    def test_regression_and_missing_proof_are_distinct_public_outcomes(self):
        regression = public_comparison()
        regression.update(numericComparison='fail', scopedPerformanceVerdict='regression',
                          status='not-observed', reasons=['runtime-baseline-regression'])
        self.assertIs(regression, runtime.validate_authenticated_comparison(regression))
        missing = copy.deepcopy(regression)
        missing.update(numericComparison='measured-but-uncompared', scopedPerformanceVerdict='blocked',
                       approvalAuthentication='missing', reasons=['runtime-baseline-approval-missing'])
        self.assertIs(missing, runtime.validate_authenticated_comparison(missing))


if __name__ == '__main__':
    unittest.main()

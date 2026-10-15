"""Known representation negatives and separately executed native producer integration."""
import base64
import copy
import hashlib
import html
import json
from pathlib import Path
import unittest
from urllib.parse import quote

from cryptad_certification import composed_budget_privacy_evidence as privacy
from cryptad_certification.composed_budget_evidence import REQUIRED_CASES

ROOT = Path(__file__).resolve().parents[4]
MARKER = 'private-path-/private/data & credential=synthetic-boundary'


class PrivacyBoundaryTests(unittest.TestCase):
    def test_support_digest_preserves_java_number_and_string_wire_encodings(self):
        wire = '{"fraction":1.0,"exponent":1.0E-7,"integer":9007199254740993,"text":"space and \\u0061"}'
        expected = hashlib.sha256(wire.encode()).hexdigest()
        complete = wire[:-1] + ',"supportDigest":{"algorithm":"SHA-256","digest":"' + expected + '"}}'
        value = privacy.verify_support_wire(complete)
        self.assertEqual(9007199254740993, value['integer'])
        self.assertEqual(value, privacy.verify_support_wire(complete.replace(',"', ', \n "')))
        changed = complete.replace('1.0E-7', '0.0000001')
        with self.assertRaisesRegex(ValueError, 'support-digest-invalid'):
            privacy.verify_support_wire(changed)
        duplicate = complete.replace('"fraction":1.0', '"fraction":1.0,"fraction":1.0')
        with self.assertRaises(ValueError): privacy.verify_support_wire(duplicate)

    def test_stack_representations_values_keys_labels_and_names_fail_closed(self):
        candidates = [MARKER, quote(MARKER, safe=''), html.escape(MARKER),
                      base64.b64encode(MARKER.encode()).decode(),
                      base64.urlsafe_b64encode(MARKER.encode()).decode().rstrip('='),
                      hashlib.sha256(MARKER.encode()).hexdigest()]
        for candidate in candidates:
            for value in ({'nested': {'innocent': candidate}}, {candidate: 1},
                          {'omittedFields': [candidate]}, {'members': [candidate]}):
                with self.subTest(valueType=type(value)), self.assertRaisesRegex(
                        ValueError, '^composed-budget-privacy-output-contaminated$') as error:
                    privacy.check_omission(value, [MARKER], public=True)
                self.assertNotIn(MARKER, str(error.exception))

    def test_clean_candidate_retains_useful_counts_and_typed_public_product_hash(self):
        value = {'count': 3, 'status': 'pass', 'productDigest': 'sha256:' + 'a' * 64}
        self.assertEqual(value, json.loads(privacy.check_omission(value, [MARKER], public=True)))

    def test_local_support_private_digest_contract_is_distinct_from_public(self):
        value = {'sourceUriHash': hashlib.sha256(MARKER.encode()).hexdigest()}
        privacy.check_omission(value, [MARKER])
        with self.assertRaises(ValueError):
            privacy.check_omission(value, [MARKER], public=True)

    def test_tree_size_depth_and_member_limits_reject_fixed_classification(self):
        nested = {'safe': 'value'}
        for _ in range(privacy.MAX_DEPTH + 1):
            nested = {'nested': nested}
        for value in (nested, {'content': 'x' * (privacy.MAX_BYTES + 1)},
                      {'items': [0] * (privacy.MAX_MEMBERS + 1)}):
            with self.assertRaisesRegex(ValueError, '^composed-budget-privacy-'):
                privacy.check_omission(value, [MARKER])

    def test_public_projection_removes_all_private_correlations(self):
        coverage = {'requiredCases': list(REQUIRED_CASES), 'observedCases': ['direct-valid'],
                    'missingCases': sorted(set(REQUIRED_CASES) - {'direct-valid'}),
                    'evidenceClass': 'native-observation-local-consistency',
                    'originalAuthentication': 'not-established',
                    'sourceUriHash': 'b' * 64, 'selectionDigest': 'sha256:' + 'c' * 64,
                    'graph': {'privateBody': MARKER}, 'appId': MARKER}
        result = privacy.public_projection(coverage)
        privacy.check_omission(result, [MARKER, 'b' * 64, 'c' * 64], public=True)
        self.assertFalse(result['releaseEligible'])
        self.assertFalse(result['phaseComplete'])
        self.assertEqual('not-observed', result['fullAppBudgets'])
        self.assertEqual(set(REQUIRED_CASES), set(result['observedCases']) | set(result['missingCases']))

    def test_shrunk_duplicate_or_invented_coverage_rejects(self):
        value = {'requiredCases': list(REQUIRED_CASES), 'observedCases': [],
                 'missingCases': list(REQUIRED_CASES), 'evidenceClass': 'synthetic-local-cohort',
                 'originalAuthentication': 'not-established'}
        for mutation in ('shrink', 'duplicate', 'invent', 'authority'):
            candidate = copy.deepcopy(value)
            if mutation == 'shrink': candidate['requiredCases'].pop()
            if mutation == 'duplicate': candidate['missingCases'].append('privacy')
            if mutation == 'invent': candidate['observedCases'] = ['invented']
            if mutation == 'authority': candidate['originalAuthentication'] = 'authenticated'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                privacy.public_projection(candidate)


class NativePrivacyIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = ROOT / 'platform-api/build/test-results/pr320-native/privacy.json'
        if not path.exists():
            raise unittest.SkipTest('actual PR320 native privacy producer has not executed')
        cls.value = json.loads(path.read_bytes())

    def test_actual_production_readback_and_exports_reach_privacy_owner(self):
        result = privacy.verify_native(self.value)
        self.assertEqual('verified', result['status'])
        self.assertGreaterEqual(result['stimulusCount'], len(privacy.PURPOSES))
        self.assertFalse(result['installedObservation'])
        self.assertEqual('not-established', result['originalAuthentication'])

    def test_missing_private_stimulus_or_useful_export_cannot_pass(self):
        for key in ('privateSurfaces', 'surfaces', 'denials', 'counters'):
            value = copy.deepcopy(self.value)
            value[key] = [] if key == 'denials' else {}
            with self.subTest(key=key), self.assertRaises(ValueError):
                privacy.verify_native(value)

    def test_actual_output_contamination_fails_without_echoing_private_marker(self):
        for surface in privacy.NATIVE_SURFACES:
            value = copy.deepcopy(self.value)
            value['surfaces'][surface] = {'innocent': value['stimuli'][0]['marker']}
            with self.subTest(surface=surface), self.assertRaisesRegex(
                    ValueError, '^composed-budget-privacy-output-contaminated$'):
                privacy.verify_native(value)

    def test_server_side_composition_before_denial_or_forged_digest_reject(self):
        value = copy.deepcopy(self.value)
        value['denials'][0]['composerCallsAfter'] += 1
        with self.assertRaisesRegex(ValueError, '^composed-budget-privacy-composition-before-denial$'):
            privacy.verify_native(value)
        value = copy.deepcopy(self.value)
        bundle = json.loads(value['surfaces']['supportBundle'])
        bundle['supportDigest']['digest'] = 'a' * 64
        value['surfaces']['supportBundle'] = json.dumps(bundle)
        with self.assertRaisesRegex(ValueError, '^composed-budget-privacy-support-digest-invalid$'):
            privacy.verify_native(value)


if __name__ == '__main__':
    unittest.main()

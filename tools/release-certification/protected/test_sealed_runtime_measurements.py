"""Private relation calculation must never project plaintext subject commitments."""
import copy
import json
import unittest

import test_maintenance_runtime_projection as fixtures
import maintenance_runtime_projection as projection
from cross_version_product_admission import public_product_identity


class SealedMeasurementsTest(unittest.TestCase):
    def fixture(self):
        helper = fixtures.MaintenanceRuntimeProjectionTest()
        values = helper.runtime_fixture()
        for row in values[3]:
            row['sealedRuntimeBinding'] = {
                'descriptor': {'fileName': 'runtime-companion.json', 'sizeBytes': 512,
                               'digest': 'sha256:' + 'a' * 64},
                'ciphertextDigest': 'sha256:' + 'b' * 64}
            row['runtimeBinding']['experimentCohortDigest'] = 'sha256:' + '9' * 64
            row['requiredAppIds'] = ['private-selected-canary']
        return helper, values

    def test_private_native_relations_emit_only_sealed_subjects(self):
        helper, values = self.fixture()
        public = [public_product_identity(row) for row in values[3]]
        result = helper.project(values, public_products=public)
        self.assertEqual(4, result['schemaVersion'])
        self.assertEqual('pass', result['subjectAdmission']['status'])
        self.assertIs(result, projection.validate(result))
        encoded = json.dumps(result)
        for private in ('private-selected-canary', 'sha256:' + '9' * 64,
                        'experimentCohortDigest', 'appMatrixDigest', 'bindingDigest'):
            self.assertNotIn(private, encoded)
        self.assertTrue(all(row['status'] == 'blocked' for row in result['rows']))
        self.assertEqual(9, len(result['rows']))

    def test_ciphertext_identity_alone_cannot_prove_native_relations(self):
        helper, values = self.fixture()
        public = [public_product_identity(row) for row in values[3]]
        result = helper.project((*values[:3], public))
        self.assertEqual('blocked', result['subjectAdmission']['status'])
        self.assertIs(result, projection.validate(result))

    def test_public_substitution_and_plaintext_fields_in_v4_reject(self):
        helper, values = self.fixture()
        public = [public_product_identity(row) for row in values[3]]
        changed = copy.deepcopy(public)
        changed[0]['sealedRuntimeBinding']['ciphertextDigest'] = 'sha256:' + 'c' * 64
        with self.assertRaises(projection.ProjectionError):
            helper.project(values, public_products=changed)
        result = helper.project(values)
        result['subjectAdmission']['subjects'][0]['bindingDigest'] = 'sha256:' + '9' * 64
        with self.assertRaises(projection.ProjectionError):
            projection.validate(result)


if __name__ == '__main__':
    unittest.main()

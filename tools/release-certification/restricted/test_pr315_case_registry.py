"""Offline source-path coverage checks; never installed case evidence."""
from pathlib import Path
import unittest
from unittest.mock import patch

import pr315_case_registry as registry


class ClosedEmitterRegistryTest(unittest.TestCase):
    def test_all_45_paths_require_the_real_worker_provider_contract(self):
        source = Path(__file__).resolve().parents[3]
        self.assertEqual(set(registry.acceptance.CASES), set(registry.CASE_PATHS))
        self.assertEqual('incomplete', registry.implementation_coverage(source))
        policy = registry.fixtures.preparation.launcher_policy()
        upgraded = {**policy,
            'providerAuthorityProbe':
                'fixed-installed-worker-synthetic-provider-credential-v2'}
        with patch.object(registry.fixtures.preparation, 'launcher_policy',
                          return_value=upgraded):
            self.assertEqual('complete',
                             registry.implementation_coverage(source))
            with patch.dict(registry.CASE_PATHS, {}, clear=True):
                self.assertEqual('incomplete',
                                 registry.implementation_coverage(source))
            changed = dict(registry.CASE_PATHS['stale-handle'])
            changed['validator'] = (registry.VERIFIER,
                                    'synthetic_acceptance_grant')
            with patch.dict(registry.CASE_PATHS,
                            {'stale-handle': changed}):
                self.assertEqual('incomplete',
                                 registry.implementation_coverage(source))


if __name__ == '__main__':
    unittest.main()

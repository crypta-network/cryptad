"""Offline source-path coverage checks; never installed case evidence."""
from pathlib import Path
import unittest
from unittest.mock import patch

import pr315_case_registry as registry


class ClosedEmitterRegistryTest(unittest.TestCase):
    def test_all_45_paths_require_real_provider_and_reachable_coordinator(self):
        source = Path(__file__).resolve().parents[3]
        self.assertEqual(set(registry.acceptance.CASES), set(registry.CASE_PATHS))
        self.assertEqual('complete', registry.implementation_coverage(source))
        policy = registry.fixtures.preparation.launcher_policy()
        self.assertEqual('fixed-installed-worker-synthetic-provider-credential-v2',
                         policy['providerAuthorityProbe'])
        actual_functions = registry._functions

        def missing_release(path):
            found = actual_functions(path)
            if path.name == 'pr315_workload_coordinator.py':
                return found - {'release_completed_attempt'}
            return found

        with patch.object(registry, '_functions', side_effect=missing_release):
            self.assertEqual('incomplete',
                             registry.implementation_coverage(source))
        with patch.object(registry.fixtures.preparation, 'launcher_policy',
                          return_value={**policy,
                              'providerAuthorityProbe': 'obsolete-canary-v1'}):
            self.assertEqual('incomplete',
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

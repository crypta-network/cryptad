"""Baseline registration and owning-read contracts; no deployed authority claim."""
import unittest
from unittest.mock import patch
from pathlib import Path

import restricted_configuration as config
import restricted_worker as worker


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.paths = {key: config.BASE + key + '.json' for key in ('campaign', 'policy', 'request', 'observation')}
        self.document = {'campaignPath': self.paths['campaign'], 'policyPath': self.paths['policy'],
            'requestPath': self.paths['request'],
            'observations': [{'coordinates': {}, 'bundlePath': self.paths['observation']}]}
        self.files = {path: b'{}' for path in self.paths.values()}
        self.files[config.PREPARATION] = worker.encode(self.document)
        self.bindings = {name: {'digest': worker.digest(raw), 'size': len(raw)} for name, raw in self.files.items()}

    def reader(self, path, maximum):
        return self.files[str(path)]

    def test_complete_preparation_and_approval_rosters_accepted(self):
        config.require_roster('baseline-prepare', self.bindings, self.reader)
        config.require_roster('baseline-approve', [config.ORIGIN], self.reader)

    def test_each_omitted_preparation_member_and_extra_member_rejected(self):
        for name in self.bindings:
            with self.subTest(name=name), self.assertRaises(worker.BoundaryError):
                config.require_roster('baseline-prepare', set(self.bindings) - {name}, self.reader)
        with self.assertRaises(worker.BoundaryError):
            config.require_roster('baseline-prepare', [*self.bindings, config.ORIGIN], self.reader)
        with self.assertRaises(worker.BoundaryError):
            config.require_roster('baseline-approve', [], self.reader)

    def test_retargeted_preparation_descriptor_rejected(self):
        self.files[config.PREPARATION] = worker.encode({**self.document, 'policyPath': config.BASE + 'new.json'})
        with self.assertRaises(worker.BoundaryError):
            config.require_roster('baseline-prepare', self.bindings, self.reader)

    def test_configuration_mutation_before_execution_rejected(self):
        self.files[self.paths['policy']] = b'{"changed":true}'
        root = Path('/synthetic-operation')
        with patch.object(worker, 'read', side_effect=self.reader), \
                patch.object(worker, 'secure', side_effect=lambda path: path), \
                patch.object(worker.os, 'walk', return_value=[]):
            with self.assertRaisesRegex(worker.BoundaryError, 'selection-substituted'):
                worker.check_inputs({'method': 'baseline-prepare', 'configurationFiles': self.bindings,
                                     'inputFiles': {}}, root)

    def test_owning_read_rejects_mutation_or_unregistered_path_after_preflight(self):
        config.require_roster('baseline-prepare', self.bindings, self.reader)
        with config.owning_configuration({'configurationFiles': self.bindings}):
            self.assertEqual(b'{}', config.check_read(self.paths['policy'], b'{}'))
            for path, raw in ((self.paths['policy'], b'{"changed":true}'), (config.ORIGIN, b'{}')):
                with self.assertRaisesRegex(worker.BoundaryError, 'read-substituted'):
                    config.check_read(path, raw)
        self.assertEqual(b'legacy', config.check_read(config.ORIGIN, b'legacy'))

    def test_dynamic_paths_cannot_escape_configuration_root_or_select_credentials(self):
        for path in ('/tmp/unbound', config.BASE + '../secret', config.BASE + 'restricted-provider.json'):
            with self.subTest(path=path):
                self.files[config.PREPARATION] = worker.encode({**self.document, 'policyPath': path})
                with self.assertRaises(worker.BoundaryError):
                    config.require_roster('baseline-prepare', self.bindings, self.reader)

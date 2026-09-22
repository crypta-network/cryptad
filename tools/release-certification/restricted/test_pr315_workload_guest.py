"""Regression for privileged imports mutating the immutable installation's byte roster."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import installation
import pr315_workload_guest as guest


class PrivateFailureTest(unittest.TestCase):
    def test_fixed_network_diagnostic_is_private_and_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'failure.json'
            error = ValueError('closed-failure')
            error.private_diagnostics = {'arguments': ['/fixed/tool', '--fixed'],
                'stderr': 'private diagnostic', 'failureClass': 'bounded_process_failed'}
            with patch.object(guest.os, 'geteuid', return_value=0), patch.object(guest, 'FAILURE', path):
                guest.retain_failure(error)
            value = json.loads(path.read_text())
            self.assertEqual(error.private_diagnostics, value['networkFailures'][0]['command'])
            self.assertFalse(value['installedAcceptance'])
            self.assertEqual(0o600, path.stat().st_mode & 0o777)

    def test_oversized_or_unrecognized_diagnostics_are_not_serialized(self):
        for diagnostic in ({'unexpected': 'value'},
                {'arguments': ['x' * 2049], 'stderr': '', 'failureClass': 'failed'},
                {'arguments': [], 'stderr': 'x' * 2049, 'failureClass': 'failed'}):
            with self.subTest(diagnostic=list(diagnostic)), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / 'failure.json'
                error = ValueError('closed-failure')
                error.private_diagnostics = diagnostic
                with patch.object(guest.os, 'geteuid', return_value=0), patch.object(guest, 'FAILURE', path):
                    guest.retain_failure(error)
                self.assertEqual([], json.loads(path.read_text())['networkFailures'])
                self.assertLess(path.stat().st_size, 8192)

    def retain(self, error):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'failure.json'
            with patch.object(guest.os, 'geteuid', return_value=0), patch.object(guest, 'FAILURE', path):
                guest.retain_failure(error)
            raw = path.read_bytes()
            self.assertLessEqual(len(raw), 8000)
            return json.loads(raw)

    def test_actual_cleanup_masking_retains_original_network_failure(self):
        primary = ValueError('network setup failed')
        primary.private_diagnostics = {'arguments': ['/fixed/nft', '-f', '-'],
            'stderr': 'original setup diagnostic', 'failureClass': 'bounded_process_failed'}
        try:
            try:
                raise primary
            finally:
                raise RuntimeError('cleanup incomplete')
        except RuntimeError as error:
            value = self.retain(error)
        self.assertEqual('RuntimeError', value['exceptionType'])
        self.assertEqual(primary.private_diagnostics, value['networkFailures'][0]['command'])
        self.assertEqual({'depth': 1, 'relationship': 'context'}, value['networkFailures'][0]['source'])
        self.assertEqual('ValueError', value['exceptionChain'][1]['exceptionType'])
        self.assertFalse(value['installedAcceptance'])

    def test_non_bmp_details_and_type_names_remain_valid_bounded_json(self):
        exception = type('\U0001f600' * 1024, (Exception,), {})
        error = exception('\U0001f600' * 1024)
        error.private_diagnostics = {'arguments': ['\U0001f600' * 64] * 32,
            'stderr': '\U0001f600' * 2048, 'failureClass': '\U0001f600' * 128}
        cause = exception('\U0001f600' * 1024)
        cause.private_diagnostics = error.private_diagnostics
        error.__context__ = cause
        value = self.retain(error)
        self.assertEqual(2, len(value['networkFailures']))
        self.assertTrue(value['privateDetail'])
        self.assertFalse(value['installedAcceptance'])

    def test_cyclic_exception_context_is_bounded(self):
        first, second = ValueError('first'), RuntimeError('second')
        first.__context__ = second
        second.__context__ = first
        value = self.retain(first)
        self.assertEqual('cycle', value['exceptionChainEnd'])
        self.assertEqual(2, len(value['exceptionChain']))

    def test_deep_exception_context_is_bounded(self):
        error = ValueError('last')
        for index in range(10):
            outer = ValueError(str(index))
            outer.__context__ = error
            error = outer
        value = self.retain(error)
        self.assertEqual('depth-limit', value['exceptionChainEnd'])
        self.assertEqual(4, len(value['exceptionChain']))

    def test_suppressed_context_is_labeled_instead_of_claimed_explicit_cause(self):
        error = RuntimeError('cleanup')
        error.__context__ = ValueError('first')
        error.__suppress_context__ = True
        value = self.retain(error)
        self.assertEqual('suppressed-context', value['exceptionChain'][1]['relationship'])

    def test_setup_and_cleanup_network_failures_are_both_retained(self):
        setup, cleanup = ValueError('setup'), RuntimeError('cleanup')
        for error, detail in ((setup, 'setup stderr'), (cleanup, 'cleanup stderr')):
            error.private_diagnostics = {'arguments': ['/fixed/nft'],
                'stderr': detail, 'failureClass': 'bounded_process_failed'}
        try:
            try:
                raise setup
            finally:
                raise cleanup
        except RuntimeError as error:
            value = self.retain(error)
        self.assertEqual([cleanup.private_diagnostics, setup.private_diagnostics],
                         [row['command'] for row in value['networkFailures']])
        self.assertEqual([{'depth': 0, 'relationship': 'top-level'},
                          {'depth': 1, 'relationship': 'context'}],
                         [row['source'] for row in value['networkFailures']])
        self.assertEqual(0, value['networkFailuresOmitted'])

    def test_more_than_two_network_failures_prioritize_deepest_reachable_context(self):
        error = None
        for name in ('original', 'cleanup-one', 'cleanup-two', 'wrapper'):
            outer = ValueError(name)
            outer.__context__ = error
            outer.private_diagnostics = {'arguments': ['/fixed/nft'],
                'stderr': name, 'failureClass': 'bounded_process_failed'}
            error = outer
        value = self.retain(error)
        self.assertEqual(['cleanup-one', 'original'],
                         [row['command']['stderr'] for row in value['networkFailures']])
        self.assertEqual([2, 3], [row['source']['depth'] for row in value['networkFailures']])
        self.assertEqual(2, value['networkFailuresOmitted'])


class GuestImportTest(unittest.TestCase):
    def test_guest_disables_bytecode_before_importing_installed_owners(self):
        guest = Path(__file__).with_name('pr315_workload_guest.py')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for suppress in (False, True):
                bundle = root / str(suppress)
                bundle.mkdir(mode=0o755)
                (bundle / 'installed_owner.py').write_text('VALUE = 1\n')
                (bundle / 'installed_owner.py').chmod(0o444)
                manifest = {'schemaVersion': 1, 'kind': 'cryptad-restricted-installation',
                    'sourceCommit': 'a' * 40, 'files': installation.inventory(bundle, protected=False)}
                raw = installation.encode(manifest)
                (bundle / installation.MANIFEST).write_bytes(raw)
                script = "import importlib.util,sys\n"
                if suppress:
                    script += ("spec=importlib.util.spec_from_file_location('guest',sys.argv[2]); "
                               "module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)\n")
                script += 'sys.path.insert(0,sys.argv[1]); import installed_owner\n'
                subprocess.run([sys.executable, '-I', '-S', '-c', script, str(bundle), str(guest)],
                               check=True, timeout=10, capture_output=True)
                if suppress:
                    self.assertFalse((bundle / '__pycache__').exists())
                    installation.verify_bundle(bundle, hashlib.sha256(raw).hexdigest(), protected=False)
                else:
                    self.assertTrue((bundle / '__pycache__').exists())
                    with self.assertRaisesRegex(installation.InstallationError, 'bundle-content-mismatch'):
                        installation.verify_bundle(bundle, hashlib.sha256(raw).hexdigest(), protected=False)


class StartupTransportTests(unittest.TestCase):
    def test_guest_reexec_preserves_startup_flag_and_exact_fixture_bindings(self):
        from contextlib import nullcontext
        from types import SimpleNamespace
        from unittest.mock import Mock
        integration = SimpleNamespace(load_installation=Mock(), provision=Mock(), ENV={'LANG': 'C'})
        fixtures = SimpleNamespace(verify=Mock())
        driver = SimpleNamespace(prerequisites=lambda: ['fixed-installed-source-required',
                                                      'separate-measured-test-kit-required'])
        modules = {'disposable_integration': integration, 'pr315_workload_fixtures': fixtures,
                   'pr314_workload_driver': driver}
        with tempfile.TemporaryDirectory() as temporary, \
                patch.dict(sys.modules, modules), \
                patch.object(guest.tempfile, 'TemporaryDirectory', return_value=nullcontext(temporary)), \
                patch.object(guest.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as run:
            self.assertEqual((None, 0), guest.execute('a' * 64, 'b' * 40, startup_measurement=True))
        self.assertEqual(['/usr/bin/python3', '-I', '-S', '-B',
            str(guest.KIT / 'pr315_workload_guest.py'), '--installed',
            '--fixture-manifest-digest', 'a' * 64, '--product-source-commit', 'b' * 40,
            '--startup-measurement'], run.call_args.args[0])
        fixtures.verify.assert_called_once_with(guest.FIXTURES, 'a' * 64, guest.SOURCE, 'b' * 40)

    def test_installed_guest_passes_measurement_to_driver_without_changing_selection(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        selection = {'fixed': 'private-selection'}
        fixtures = SimpleNamespace(verify=Mock(), materialize_selection=Mock(return_value=selection))
        driver = SimpleNamespace(SELECTION=Path('/root/pr314-workload-selection.json'),
            execute=Mock(return_value={'installedPositiveExecuted': False}))
        workload = SimpleNamespace(write=Mock())
        with patch.dict(sys.modules, {'pr315_workload_fixtures': fixtures,
                'pr314_workload_driver': driver, 'restricted_workload': workload}), \
                patch.object(guest.sys, 'path', list(sys.path)), \
                patch.object(guest, 'KIT', Path(guest.__file__).resolve().parent):
            result, code = guest.installed('a' * 64, 'b' * 40, startup_measurement=True)
        driver.execute.assert_called_once_with(startup_measurement=True)
        fixtures.materialize_selection.assert_called_once_with(guest.FIXTURES, guest.SOURCE, 'a' * 64, 'b' * 40)
        workload.write.assert_called_once_with(driver.SELECTION, selection, create=True)
        self.assertFalse(result['installedPositiveExecuted'])
        self.assertEqual(0, code)


if __name__ == '__main__':
    unittest.main()

"""Read-only harness checks, not substitutes for its VM/service/UID execution."""
import contextlib
import io
import json
import datetime as dt
import sys
import subprocess
import tempfile
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import disposable_integration as harness


class DisposableHarnessTest(unittest.TestCase):
    def test_synthetic_preparation_job_passes_real_worker_authentication(self):
        with patch.object(sys, 'path', [str(Path(__file__).parent.parent / 'protected'), *sys.path]):
            import restricted_worker as worker
            import original_artifact_authentication as original
        context = {'sourceCommit': 'a' * 40, 'runId': 310, 'runAttempt': 1, 'jobId': 31001}
        timestamp = worker.now() - dt.timedelta(seconds=1)
        def unexpected(*args, **kwargs):
            self.fail('Unexpected upstream request')
        provider = harness.preparation_provider(context, timestamp, unexpected)
        record = {'context': context, 'method': 'maintenance-prepare',
                  'notBefore': (timestamp - dt.timedelta(seconds=1)).isoformat()}
        with patch.object(original, '_gh', side_effect=provider):
            worker.authenticate_job(record, {})
            with self.assertRaises(worker.BoundaryError):
                worker.authenticate_job({**record, 'context': {**context, 'sourceCommit': 'b' * 40}}, {})

    def test_provider_mutations_fail_real_original_job_comparisons(self):
        with patch.object(sys, 'path', [str(Path(__file__).parent.parent / 'protected'), *sys.path]):
            import restricted_worker as worker
            import original_artifact_authentication as original
        context = {'sourceCommit': 'a' * 40, 'runId': 310, 'runAttempt': 1, 'jobId': 31001}
        timestamp = worker.now() - dt.timedelta(seconds=1)
        provider = harness.preparation_provider(context, timestamp, Mock(side_effect=AssertionError))
        record = {'context': context, 'method': 'maintenance-prepare',
                  'notBefore': (timestamp - dt.timedelta(seconds=1)).isoformat()}
        mutations = [
            ('runs/310', {'run_attempt': 2}),
            ('runs/310/attempts/1', {'actor': {'login': 'outsider'}}),
            ('runs/310/attempts/1', {'triggering_actor': {'login': 'outsider'}}),
            ('runs/310/attempts/1', {'event': 'pull_request'}),
            ('runs/310/attempts/1', {'path': '.github/workflows/unrelated.yml'}),
            ('jobs/31001', {'id': 31002}),
            ('jobs/31001', {'run_attempt': 2}),
            ('jobs/31001', {'name': 'freeze-and-validate'}),
            ('jobs/31001', {'status': 'completed'}),
        ]
        for suffix, mutation in mutations:
            with self.subTest(suffix=suffix, mutation=mutation):
                def altered(arguments, environment, **options):
                    value = provider(arguments, environment, **options)
                    if arguments[-1] == 'repos/crypta-network/cryptad/actions/' + suffix:
                        value.update(mutation)
                    return value
                with patch.object(original, '_gh', side_effect=altered):
                    with self.assertRaisesRegex(worker.BoundaryError, 'restricted-original-job-rejected'):
                        worker.authenticate_job(record, {})

    def test_reaped_child_is_not_signalled_after_replacement_fork_fails(self):
        child = harness.PreparationChild()
        with patch.object(harness.os, 'fork', side_effect=[101, OSError('fork failed')]), \
                patch.object(harness.os, 'waitpid', return_value=(101, 0)), \
                patch.object(harness.os, 'kill') as kill:
            child.start(Mock())
            child.stop()
            with self.assertRaises(OSError):
                child.start(Mock())
            child.stop()
        kill.assert_not_called()
        self.assertIsNone(child.pid)

    def test_owned_child_escalates_and_reaps_with_bounded_waits(self):
        child = harness.PreparationChild()
        with patch.object(harness.os, 'fork', return_value=101), \
                patch.object(harness.os, 'waitpid', side_effect=[(0, 0), (0, 0), (101, 0)]), \
                patch.object(harness.os, 'kill') as kill, \
                patch.object(harness.time, 'monotonic', side_effect=[0, 11, 12, 13]):
            child.start(Mock())
            child.stop()
        self.assertEqual([(101, harness.signal.SIGTERM), (101, harness.signal.SIGKILL)],
                         [row.args for row in kill.call_args_list])
        self.assertIsNone(child.pid)

    def test_unreaped_child_retains_identity_after_bounded_escalation(self):
        child = harness.PreparationChild()
        with patch.object(harness.os, 'fork', return_value=101), \
                patch.object(harness.os, 'waitpid', return_value=(0, 0)), \
                patch.object(harness.os, 'kill') as kill, \
                patch.object(harness.time, 'monotonic', side_effect=[0, 11, 12, 23]):
            child.start(Mock())
            with self.assertRaisesRegex(ValueError, 'disposable-child-reconciliation-required'):
                child.stop()
        self.assertEqual(2, kill.call_count)
        self.assertEqual(101, child.pid)

    def test_normal_child_return_exits_without_returning_into_parent_harness(self):
        child = harness.PreparationChild()
        entrypoint = Mock()
        with patch.object(harness.os, 'fork', return_value=0), \
                patch.object(harness.os, '_exit', side_effect=SystemExit) as exited:
            with self.assertRaises(SystemExit):
                child.start(entrypoint)
        entrypoint.assert_called_once_with()
        exited.assert_called_once_with(0)

    def test_socket_setup_failure_closes_listener_and_restores_activation(self):
        listener = Mock()
        endpoint = Mock()
        endpoint.exists.return_value = False
        with patch.object(harness, 'Path', return_value=endpoint), \
                patch.object(harness, 'call') as call, \
                patch.object(harness.socket, 'socket', return_value=listener), \
                patch.object(harness.grp, 'getgrnam', return_value=Mock(gr_gid=62005)), \
                patch.object(harness.os, 'chown', side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                with harness.preparation_socket():
                    self.fail('Failed setup must not yield')
        listener.close.assert_called_once_with()
        endpoint.unlink.assert_called_once_with(missing_ok=True)
        self.assertEqual(['/usr/bin/systemctl', 'start', 'cryptad-restricted.socket'],
                         call.call_args.args[0])

    def test_client_response_failure_reaps_controller_and_restores_socket(self):
        listener = Mock()
        endpoint = Mock()
        endpoint.exists.return_value = False
        with patch.object(harness, 'Path', return_value=endpoint), \
                patch.object(harness, 'call') as call, \
                patch.object(harness.socket, 'socket', return_value=listener), \
                patch.object(harness.grp, 'getgrnam', return_value=Mock(gr_gid=62005)), \
                patch.object(harness.os, 'chown'), \
                patch.object(harness.os, 'fork', return_value=101), \
                patch.object(harness.os, 'waitpid', return_value=(101, 0)) as wait:
            with self.assertRaisesRegex(ValueError, 'client response failed'):
                with harness.preparation_socket() as (_listener, child):
                    child.start(Mock())
                    raise ValueError('client response failed')
        wait.assert_called_once_with(101, harness.os.WNOHANG)
        listener.close.assert_called_once_with()
        endpoint.unlink.assert_called_once_with(missing_ok=True)
        self.assertEqual(['/usr/bin/systemctl', 'start', 'cryptad-restricted.socket'],
                         call.call_args.args[0])

    def test_failed_controller_reap_preserves_endpoint_and_stopped_activation(self):
        listener = Mock()
        endpoint = Mock()
        endpoint.exists.return_value = False
        with patch.object(harness, 'Path', return_value=endpoint), \
                patch.object(harness, 'call') as call, \
                patch.object(harness.socket, 'socket', return_value=listener), \
                patch.object(harness.grp, 'getgrnam', return_value=Mock(gr_gid=62005)), \
                patch.object(harness.os, 'chown'), \
                patch.object(harness.PreparationChild, 'stop', side_effect=ValueError('reap failed')):
            with self.assertRaisesRegex(ValueError, 'reap failed'):
                with harness.preparation_socket():
                    pass
        listener.close.assert_called_once_with()
        endpoint.unlink.assert_not_called()
        self.assertEqual(1, call.call_count)

    def test_test_kit_exports_exact_committed_seams_outside_production_bundle(self):
        spec = importlib.util.spec_from_file_location('installation', Path(__file__).with_name('installation.py'))
        installation = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installation)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, installed, kit = root / 'source', root / 'installed', root / 'kit'
            source.mkdir()
            seam = 'tools/release-certification/restricted/disposable_integration.py'
            selected = source / seam
            selected.parent.mkdir(parents=True)
            selected.write_bytes(b'COMMITTED_TEST_SEAM = True\n')
            (source / 'production.py').write_bytes(b'PRODUCTION = True\n')
            for arguments in (['init', '--quiet'], ['add', '.'],
                    ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                     'commit', '--quiet', '-m', 'test kit fixture']):
                subprocess.run(['git', *arguments], cwd=source, check=True, capture_output=True)
            planned = installation.plan(source, installed)
            self.assertFalse((installed / seam).exists())
            subprocess.run(['git', 'update-index', '--assume-unchanged', seam], cwd=source, check=True)
            selected.write_bytes(b'UNREVIEWED_TEST_SEAM = True\n')
            with patch.dict(sys.modules, {'installation': installation}), \
                    patch.object(harness, 'INSTALLED', installed), patch.object(harness, 'TEST_KIT', kit):
                harness.install_test_kit(source)
                with self.assertRaisesRegex(ValueError, 'test-kit-must-be-new'):
                    harness.install_test_kit(source)
            self.assertEqual(b'COMMITTED_TEST_SEAM = True\n', (kit / seam).read_bytes())
            self.assertFalse((kit / 'production.py').exists())
            identity = json.loads((kit / '.test-kit.json').read_bytes())
            self.assertEqual(planned['sourceCommit'], identity['sourceCommit'])
            self.assertFalse(identity['productionEligible'])
            self.assertEqual(installed / 'build', (kit / 'build').readlink())
            installation.verify_bundle(installed, planned['bundleIdentity'], protected=False)

    def test_controller_probe_uses_fixed_external_kit_entrypoint(self):
        endpoint = Mock()
        override = Mock()
        override.__truediv__ = Mock(return_value=endpoint)
        with patch.object(harness, 'Path', return_value=override), \
                patch.dict(sys.modules, {'installation': Mock()}), \
                patch.object(harness, 'call', return_value=b'Result=success\nExecMainStatus=0\n'):
            harness.controller_unit_probe('baseline_workspace_probe.py')
        text = endpoint.write_text.call_args.args[0]
        self.assertIn('/opt/cryptad-restricted-test-kit/tools/release-certification/restricted/', text)
        self.assertNotIn('/opt/cryptad-cross-version/current/', text)
        with self.assertRaisesRegex(ValueError, 'controller-probe-not-fixed'):
            harness.controller_unit_probe('../unreviewed.py')

    def test_explicit_product_source_does_not_relabel_the_helper_commit(self):
        helper, product = 'a' * 40, 'b' * 40
        with patch.object(harness, 'call', return_value=(helper + '\n').encode()):
            identities = harness.test_source_identities(Path('/synthetic/source'), product)
        self.assertEqual({'helperSourceCommit': helper, 'productSourceCommit': product}, identities)
        self.assertNotEqual(identities['helperSourceCommit'], identities['productSourceCommit'])

    def test_default_product_source_retains_explicit_helper_identity(self):
        helper = 'a' * 40
        with patch.object(harness, 'call', return_value=(helper + '\n').encode()):
            identities = harness.test_source_identities(Path('/synthetic/source'))
        self.assertEqual({'helperSourceCommit': helper, 'productSourceCommit': helper}, identities)

    def test_product_source_selection_rejects_abbreviations_refs_and_extra_arguments(self):
        for value in ('main', 'a' * 10, 'g' * 40, 'a' * 40 + ' --skip-auth', ''):
            with self.subTest(value=value):
                with self.assertRaises(harness.argparse.ArgumentTypeError):
                    harness.source_commit(value)

    def test_probe_always_reports_unexecuted_without_provisioning(self):
        output = io.StringIO()
        with patch('sys.argv', ['harness', '--probe']), \
                patch.object(harness, 'prerequisites', return_value=['dedicated-disposable-vm-required']), \
                patch.object(harness, 'provision') as install, contextlib.redirect_stdout(output):
            status = harness.main()
        install.assert_not_called()
        self.assertEqual(78, status)
        result = json.loads(output.getvalue())
        self.assertFalse(result['executed'])
        self.assertFalse(result['mandatoryIsolationTestSatisfied'])

    def test_explicit_vm_flag_cannot_override_missing_real_prerequisites(self):
        output = io.StringIO()
        with patch('sys.argv', ['harness', '--disposable-vm']), \
                patch.object(harness, 'prerequisites', return_value=['dedicated-disposable-vm-required']), \
                patch.object(harness, 'provision') as install, contextlib.redirect_stdout(output):
            self.assertEqual(78, harness.main())
        install.assert_not_called()
        self.assertEqual('unexecuted', json.loads(output.getvalue())['status'])

    def test_default_does_not_provision_even_with_supported_profile(self):
        with patch('sys.argv', ['harness']), patch.object(harness, 'prerequisites', return_value=[]), \
                patch.object(harness, 'provision') as install, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(78, harness.main())
        install.assert_not_called()


if __name__ == '__main__':
    unittest.main()

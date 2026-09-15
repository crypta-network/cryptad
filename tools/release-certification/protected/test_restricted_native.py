"""Offline native boundary contract checks; these do not claim multi-UID isolation."""
import os
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

import restricted_native as native


@unittest.skipUnless(sys.platform == 'linux', 'native execution boundary requires Linux')
class RestrictedNativeTest(unittest.TestCase):
    def test_unsupported_platform_import_does_not_load_unix_account_modules(self):
        import importlib.util
        import builtins
        original_import = builtins.__import__
        def without_unix(name, *args, **kwargs):
            if name in ('fcntl', 'grp', 'pwd'):
                raise AssertionError('unsupported platform imported Unix-only module')
            return original_import(name, *args, **kwargs)
        spec = importlib.util.spec_from_file_location('unsupported_native_boundary', native.__file__)
        module = importlib.util.module_from_spec(spec)
        with patch.object(sys, 'platform', 'win32'), patch('builtins.__import__', side_effect=without_unix):
            spec.loader.exec_module(module)
            with self.assertRaises(module.NativeBoundaryError):
                with module.owning_boundary():
                    self.fail('unsupported platform entered owning boundary')

    def test_installed_execution_cannot_fall_back_without_owning_context(self):
        with patch.object(native, '__file__', '/opt/cryptad-cross-version/current/protected/restricted_native.py'):
            with self.assertRaisesRegex(native.NativeBoundaryError, 'boundary-rejected'):
                native.run(['/usr/bin/true'], environment={})

    @unittest.skipIf(getattr(os, 'geteuid', lambda: 1)() == 0, 'requires the actual non-root test principal')
    def test_unprivileged_process_cannot_enter_owning_context(self):
        with self.assertRaisesRegex(native.NativeBoundaryError, 'boundary-rejected'):
            with native.owning_boundary():
                self.fail('non-root owner admitted')

    def test_native_input_copy_has_no_writable_alias_to_resolver_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            source.mkdir()
            (source / 'selection').write_bytes(b'scoped-selection')
            target = root / 'target'
            native._copy(source, target, os.geteuid(), os.getegid(), [0, 0])
            (target / 'selection').chmod(0o600)
            (target / 'selection').write_bytes(b'candidate-replacement')
            self.assertEqual(b'scoped-selection', (source / 'selection').read_bytes())
            self.assertNotEqual((source / 'selection').stat().st_ino,
                                (target / 'selection').stat().st_ino)

    def test_materialized_jdk_internal_link_preserves_approved_tree_through_copy(self):
        import maintenance_runtime_metadata as metadata
        import app_subject_projection as projection
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / 'jdk-installed'
            legal = original / 'legal'
            legal.mkdir(parents=True)
            (legal / 'notice').write_bytes(b'approved-jdk-notice')
            (legal / 'duplicate').write_bytes(b'approved-jdk-notice')
            expected = projection.tree_digest(original)
            (legal / 'duplicate').unlink()
            (legal / 'duplicate').symlink_to('notice')
            staged = metadata.stage_jdk(original, root / 'jdk-approved', expected)
            native._copy(staged, root / 'jdk-native', os.geteuid(), os.getegid(), [0, 0])
            self.assertEqual(expected, projection.tree_digest(root / 'jdk-native'))
            self.assertFalse((root / 'jdk-native/legal/duplicate').is_symlink())

    def test_unmaterialized_jdk_link_cannot_bypass_original_owner_identity(self):
        import app_subject_projection as projection
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jdk = root / 'jdk'
            jdk.mkdir()
            (root / 'external-cacerts').write_bytes(b'not-in-approved-closure')
            (jdk / 'cacerts').symlink_to(root / 'external-cacerts')
            with self.assertRaises(projection.ProjectionFailure):
                projection.tree_digest(jdk)
            with self.assertRaises(native.NativeBoundaryError):
                native._copy(jdk, root / 'native', os.geteuid(), os.getegid(), [0, 0])

    def test_input_symlink_and_hardlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            source.write_bytes(b'private-canary')
            link = root / 'link'
            link.symlink_to(source)
            with self.assertRaises(native.NativeBoundaryError):
                native._copy(link, root / 'target', os.geteuid(), os.getegid(), [0, 0])
            link.unlink()
            os.link(source, link)
            with self.assertRaises(native.NativeBoundaryError):
                native._copy(source, root / 'target', os.geteuid(), os.getegid(), [0, 0])

    def test_output_collection_rejects_link_oversize_and_existing_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target = root / 'source', root / 'target'
            source.symlink_to(target)
            with self.assertRaises((OSError, ValueError)):
                native._collect(source, target)
            source.unlink()
            source.write_bytes(b'x' * 32769)
            with self.assertRaises(native.NativeBoundaryError):
                native._collect(source, target)
            source.write_bytes(b'{"untrusted":"private-canary"}')
            target.write_bytes(b'owning-record')
            with self.assertRaises(FileExistsError):
                native._collect(source, target)
            self.assertEqual(b'owning-record', target.read_bytes())

    def test_output_collection_preserves_exact_bytes_for_owning_semantic_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target = root / 'source', root / 'projection.json'
            raw = b'{"untrusted":"not-an-admission-capability"}'
            source.write_bytes(raw)
            native._collect(source, target)
            self.assertEqual(raw, target.read_bytes())
            self.assertEqual(0o600, target.stat().st_mode & 0o777)


class FixedNativeContractTest(unittest.TestCase):
    def package_command(self, root):
        return ['/usr/bin/prlimit', '--cpu=60', '--fsize=8388608', '--nofile=128', '--',
            '/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session',
            '--ro-bind', '/usr', '/usr', '--ro-bind', '/lib', '/lib', '--ro-bind', '/lib64', '/lib64',
            '--proc', '/proc', '--dev', '/dev', '--size', '16777216', '--tmpfs', '/tmp',
            '--ro-bind', str(root / 'jdk'), '/jdk', '--ro-bind', str(root / 'work'), '/work',
            '--chdir', '/work', '--', '/jdk/bin/java', '-Xmx128m', '-cp', '/work/cryptad.jar',
            'network.crypta.platform.api.PackagedApiExport']

    def test_package_command_is_reconstructed_from_closed_type(self):
        import restricted_native_launcher as launcher
        root = Path('/private/owner')
        spec, bindings = native._spec(self.package_command(root), 'package-api')
        command, environment = launcher.command({'spec': spec, 'inputs': bindings}, Path('/stage'))
        self.assertEqual({'jdk': root / 'jdk', 'work': root / 'work'}, bindings)
        self.assertEqual('network.crypta.platform.api.PackagedApiExport', command[-1])
        self.assertNotIn('/private/owner', ' '.join(command))
        self.assertNotIn('GH_TOKEN', environment)
        self.assertIn('--unshare-all', command)
        self.assertIn('--cap-drop', command)
        for flag in ('--unshare-user', '--disable-userns', '--assert-userns-disabled'):
            self.assertIn(flag, command)
        for path in ('/', '/dev', '/dev/pts'):
            self.assertTrue(any(command[index:index + 2] == ['--remount-ro', path]
                                for index in range(len(command) - 1)))

    def test_arbitrary_executable_mount_and_classpath_are_rejected(self):
        command = self.package_command(Path('/owner'))
        for index, replacement in ((0, '/usr/bin/systemd-run'), (-1, 'attacker.Main'),
                                   (-2, '/inputs/attacker.jar'), (command.index('/proc'), '/host-proc')):
            with self.subTest(index=index):
                hostile = list(command)
                hostile[index] = replacement
                with self.assertRaises(ValueError):
                    native._spec(hostile, 'package-api')
        with self.assertRaises(ValueError):
            native._spec(command, 'arbitrary-operation')

    def test_projection_has_readonly_inputs_separate_private_scratch_and_output(self):
        import restricted_native_launcher as launcher
        spec = {'operation': 'app-projection', 'exporter': '/tools/bin/crypta-app', 'options': {
            '--catalog': '/work/catalog', '--catalog-signature': '/work/catalogSignature',
            '--bundle': '/work/bundle', '--catalog-keys': '/inputs/catalog-keys',
            '--publisher-keys': '/inputs/publisher-keys', '--catalog-key-id': 'catalog', '--app-id': 'feed-reader'}}
        command, environment = launcher.command({'spec': spec, 'inputs': dict.fromkeys(('jdk', 'tools', 'work', 'inputs'))}, Path('/stage'))
        self.assertEqual(['/scratch', '--output', '/output/projection.json'], command[-3:])
        position = command.index('/stage/work')
        self.assertEqual('--ro-bind', command[position - 1])
        self.assertEqual('/work', command[position + 1])
        self.assertNotIn('/stage/output', command)
        self.assertEqual('/jdk', environment['JAVA_HOME'])
        for option, value in (('--unit', 'evil.service'), ('--federation-selection', '/work/federation/../secret'),
                              ('--catalog', '/etc/cryptad-certification/key')):
            with self.subTest(option=option), self.assertRaises(ValueError):
                launcher.validate_spec({**spec, 'options': {**spec['options'], option: value}})

    def test_descriptor_collection_rejects_replaced_ancestor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root / 'output'
            parent.mkdir()
            source = parent / 'projection.json'
            source.write_bytes(b'{}')
            original = os.read
            replaced = False
            def read(fd, size):
                nonlocal replaced
                value = original(fd, size)
                if not replaced:
                    replaced = True
                    parent.rename(root / 'old')
                    parent.mkdir()
                    (parent / 'projection.json').write_bytes(b'{}')
                return value
            with patch.object(native.os, 'read', side_effect=read), self.assertRaises(ValueError):
                native._read_output(source, 32768)

    def test_manager_timeout_retains_intent_and_stops_before_uid_reuse(self):
        import time
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            stack.enter_context(patch.object(native, 'ROOT', root))
            stack.enter_context(patch.object(native, '_secured'))
            stack.enter_context(patch.object(native, '_installation_identity', return_value='sha256:' + 'd' * 64))
            stack.enter_context(patch.object(native, '_native_identity', return_value=(os.geteuid(), os.getegid())))
            stack.enter_context(patch.object(native.os, 'chown'))
            calls = []
            def manager(action, **kwargs):
                calls.append(action)
                if action == 'start':
                    raise ValueError('lost-manager-response')
                return {'InvocationID': '', 'ControlGroup': '', 'ActiveState': 'inactive',
                        'SubState': 'dead', 'ExecMainStatus': '0', 'Result': 'success'}
            stack.enter_context(patch.object(native, '_manager', side_effect=manager))
            stopped = stack.enter_context(patch.object(native, '_quiesce'))
            context = {'operationId': 'a' * 64, 'registrationDigest': 'sha256:' + 'b' * 64,
                       'bundleIdentity': 'c' * 64, 'deadlineMonotonic': time.monotonic() + 20}
            token = native._ACTIVE.set((context, None))
            try:
                with self.assertRaises(native.NativeBoundaryError):
                    native._execute({'operation': 'probe'}, {}, timeout=20, output_limit=4096)
            finally:
                native._ACTIVE.reset(token)
            stopped.assert_called_once()
            self.assertEqual(['show', 'start'], calls)
            self.assertFalse((root / 'active.json').exists())
            stages = [path for path in root.iterdir() if path.is_dir()]
            self.assertEqual(1, len(stages))
            self.assertTrue((stages[0] / 'invocation.json').exists())
            self.assertTrue((stages[0] / 'failure.json').exists())
            self.assertEqual(0o700, stages[0].stat().st_mode & 0o777)

    def test_uncertain_cleanup_keeps_active_marker_and_private_evidence(self):
        import time
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            stack.enter_context(patch.object(native, 'ROOT', root))
            stack.enter_context(patch.object(native, '_secured'))
            stack.enter_context(patch.object(native, '_installation_identity', return_value='sha256:' + 'd' * 64))
            stack.enter_context(patch.object(native, '_native_identity', return_value=(os.geteuid(), os.getegid())))
            stack.enter_context(patch.object(native.os, 'chown'))
            stack.enter_context(patch.object(native, '_manager', side_effect=[{'ActiveState': 'inactive'}, ValueError('lost')]))
            stack.enter_context(patch.object(native, '_quiesce', side_effect=ValueError('not-quiescent')))
            token = native._ACTIVE.set(({'operationId': 'a' * 64, 'registrationDigest': 'sha256:' + 'b' * 64,
                'bundleIdentity': 'c' * 64, 'deadlineMonotonic': time.monotonic() + 20}, None))
            try:
                with self.assertRaises(ValueError):
                    native._execute({'operation': 'probe'}, {}, timeout=20, output_limit=4096)
            finally:
                native._ACTIVE.reset(token)
            self.assertTrue((root / 'active.json').exists())
            self.assertEqual(1, len(list(root.glob('*/failure.json'))))


class NativeLifecycleTest(unittest.TestCase):
    """Controller lifecycle tests use a fake manager, never claim installed/kernel acceptance."""

    def execute(self, *, states=None, check=None, collection_error=False, quiesce_error=False):
        import json
        import time
        from contextlib import ExitStack
        result = {}
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            stack.enter_context(patch.object(native, 'ROOT', root))
            stack.enter_context(patch.object(native, '_secured'))
            stack.enter_context(patch.object(native, '_installation_identity', return_value='sha256:' + 'd' * 64))
            stack.enter_context(patch.object(native, '_native_identity', return_value=(os.geteuid(), os.getegid())))
            stack.enter_context(patch.object(native.os, 'chown'))
            initial = {'InvocationID': '', 'ControlGroup': '', 'ActiveState': 'inactive',
                       'SubState': 'dead', 'ExecMainStatus': '0', 'Result': 'success'}
            active = {'InvocationID': 'e' * 32, 'ControlGroup': native.CGROUP, 'ActiveState': 'active',
                      'SubState': 'exited', 'ExecMainStatus': '0', 'Result': 'success'}
            observations = iter([initial, *(states if states is not None else [active, active])])
            calls = []
            def manager(action, **kwargs):
                calls.append(action)
                if action == 'start':
                    stage = next(path for path in root.iterdir() if path.is_dir())
                    (stage / 'output' / 'stdout').write_bytes(b'')
                    (stage / 'output' / 'complete.json').write_text(json.dumps({'invocation': stage.name, 'status': 'complete'}))
                    return None
                return next(observations)
            stack.enter_context(patch.object(native, '_manager', side_effect=manager))
            def stop():
                calls.append('quiesce')
                if quiesce_error:
                    raise ValueError('owned-cgroup-not-empty')
            stack.enter_context(patch.object(native, '_quiesce', side_effect=stop))
            if collection_error:
                original = native._read_output
                def collect(path, *args, **kwargs):
                    if Path(path).name == 'stdout':
                        calls.append('collect')
                        raise ValueError('replaced-output')
                    return original(path, *args, **kwargs)
                stack.enter_context(patch.object(native, '_read_output', side_effect=collect))
            token = native._ACTIVE.set(({'operationId': 'a' * 64, 'registrationDigest': 'sha256:' + 'b' * 64,
                'bundleIdentity': 'c' * 64, 'deadlineMonotonic': time.monotonic() + 20}, check))
            try:
                result['value'] = native._execute({'operation': 'probe'}, {}, timeout=20, output_limit=4096)
            except ValueError as error:
                result['error'] = str(error)
            finally:
                native._ACTIVE.reset(token)
            result['calls'] = calls
            result['active'] = (root / 'active.json').exists()
            result['failures'] = len(list(root.glob('*/failure.json')))
            result['completed'] = len(list(root.glob('*/complete.json')))
            result['cleanup_failures'] = len(list(root.glob('*/cleanup-failure.json')))
            result['intents'] = len(list(root.glob('*/invocation.json')))
            result['modes'] = [path.stat().st_mode & 0o777 for path in root.iterdir() if path.is_dir()]
        return result

    def test_success_requires_quiescence_and_retains_exact_invocation(self):
        result = self.execute()
        self.assertEqual(b'', result['value'])
        self.assertEqual(['show', 'start', 'show', 'show', 'quiesce'], result['calls'])
        self.assertEqual(1, result['intents'])
        self.assertEqual(1, result['completed'])
        self.assertEqual([0o700], result['modes'])
        self.assertFalse(result['active'])

    def test_revocation_during_execution_stops_owned_unit_before_rejection(self):
        checks = 0
        def revoked():
            nonlocal checks
            checks += 1
            if checks == 3:
                raise ValueError('revoked')
        result = self.execute(check=revoked)
        self.assertIn('error', result)
        self.assertEqual(['show', 'start', 'show', 'quiesce'], result['calls'])
        self.assertEqual(1, result['failures'])
        self.assertEqual(0, result['completed'])
        self.assertFalse(result['active'])

    def test_stale_manager_invocation_never_accepts_output(self):
        running = {'InvocationID': 'e' * 32, 'ControlGroup': native.CGROUP, 'ActiveState': 'active',
                   'SubState': 'running', 'ExecMainStatus': '0', 'Result': 'success'}
        stale = {**running, 'InvocationID': 'f' * 32, 'SubState': 'exited'}
        result = self.execute(states=[running, stale])
        self.assertIn('error', result)
        self.assertEqual('quiesce', result['calls'][-1])
        self.assertEqual(0, result['completed'])
        self.assertEqual(1, result['failures'])

    def test_native_output_limit_service_failure_is_stopped_and_retained(self):
        running = {'InvocationID': 'e' * 32, 'ControlGroup': native.CGROUP, 'ActiveState': 'active',
                   'SubState': 'running', 'ExecMainStatus': '0', 'Result': 'success'}
        failed = {**running, 'ActiveState': 'failed', 'SubState': 'failed', 'ExecMainStatus': '1', 'Result': 'exit-code'}
        result = self.execute(states=[running, failed])
        self.assertIn('error', result)
        self.assertEqual('quiesce', result['calls'][-1])
        self.assertEqual(1, result['intents'])
        self.assertEqual(1, result['failures'])
        self.assertEqual(0, result['completed'])

    def test_failed_collection_happens_after_quiescence_and_preserves_intent(self):
        result = self.execute(collection_error=True)
        self.assertIn('error', result)
        self.assertLess(result['calls'].index('quiesce'), result['calls'].index('collect'))
        self.assertEqual(1, result['intents'])
        self.assertEqual(1, result['failures'])
        self.assertEqual(0, result['completed'])
        self.assertFalse(result['active'])

    def test_uncertain_cleanup_never_accepts_result_or_releases_uid(self):
        result = self.execute(quiesce_error=True)
        self.assertEqual('restricted-native-cleanup-failed', result['error'])
        self.assertEqual(1, result['cleanup_failures'])
        self.assertTrue(result['active'])
        self.assertEqual(0, result['completed'])
        self.assertEqual(1, result['intents'])

    def test_environment_injection_is_rejected_before_any_manager_operation(self):
        token = native._ACTIVE.set(({}, None))
        try:
            with patch.object(native, '_manager') as manager, self.assertRaises(native.NativeBoundaryError):
                native.run(['/usr/bin/true'], environment={'GH_TOKEN': 'must-not-be-inherited'}, operation='package-api')
            manager.assert_not_called()
        finally:
            native._ACTIVE.reset(token)


    def test_interrupted_staging_reserves_capacity_without_a_final_manifest(self):
        import time
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            for identity in ('1' * 64, '2' * 64):
                (root / identity).mkdir()
                (root / identity / 'staging.json').write_text('{}')
            stack.enter_context(patch.object(native, 'ROOT', root))
            stack.enter_context(patch.object(native, '_secured'))
            stack.enter_context(patch.object(native, '_native_identity', return_value=(os.geteuid(), os.getegid())))
            manager = stack.enter_context(patch.object(native, '_manager'))
            token = native._ACTIVE.set(({'operationId': 'a' * 64, 'registrationDigest': 'sha256:' + 'b' * 64,
                'bundleIdentity': 'c' * 64, 'deadlineMonotonic': time.monotonic() + 20}, None))
            try:
                with self.assertRaises(native.NativeBoundaryError):
                    native._execute({'operation': 'probe'}, {}, timeout=20, output_limit=4096)
            finally:
                native._ACTIVE.reset(token)
            manager.assert_not_called()
            self.assertEqual(2, len([path for path in root.iterdir() if path.is_dir()]))

    def test_failed_copy_retains_operation_binding_before_manifest_and_seals_stage(self):
        import json
        import time
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            stack.enter_context(patch.object(native, 'ROOT', root))
            stack.enter_context(patch.object(native, '_secured'))
            stack.enter_context(patch.object(native, '_native_identity', return_value=(os.geteuid(), os.getegid())))
            stack.enter_context(patch.object(native.os, 'chown'))
            manager = stack.enter_context(patch.object(native, '_manager', return_value={'ActiveState': 'inactive'}))
            stack.enter_context(patch.object(native, '_copy', side_effect=ValueError('changed-source')))
            context = {'operationId': 'a' * 64, 'registrationDigest': 'sha256:' + 'b' * 64,
                'bundleIdentity': 'c' * 64, 'deadlineMonotonic': time.monotonic() + 20}
            token = native._ACTIVE.set((context, None))
            try:
                with self.assertRaises(native.NativeBoundaryError):
                    native._execute({'operation': 'package-api', 'historicalJars': []},
                                    {'work': root / 'source'}, timeout=20, output_limit=4096)
            finally:
                native._ACTIVE.reset(token)
            manager.assert_called_once_with('show')
            stage = next(path for path in root.iterdir() if path.is_dir())
            self.assertEqual(context, json.loads((stage / 'staging.json').read_bytes())['owner'])
            self.assertFalse((stage / 'invocation.json').exists())
            self.assertTrue((stage / 'failure.json').exists())
            self.assertEqual(0o700, stage.stat().st_mode & 0o777)


    def test_native_copy_deadline_stops_before_read_and_preserves_original(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target = root / 'input', root / 'copy'
            source.write_bytes(b'original-scoped-input')
            with patch.object(native.time, 'monotonic', side_effect=[0.0, 2.0]), \
                    self.assertRaises(native.NativeBoundaryError):
                native._copy(source, target, os.geteuid(), os.getegid(), [0, 0], deadline=1.0)
            self.assertEqual(b'original-scoped-input', source.read_bytes())
            if target.exists():
                self.assertEqual(b'', target.read_bytes())

    def test_tree_hash_deadline_prevents_unbounded_staging_verification(self):
        import restricted_native_launcher as launcher
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'input').write_bytes(b'bounded-input')
            with patch.object(launcher.time, 'monotonic', return_value=2.0), \
                    patch.object(launcher.os, 'read') as read, self.assertRaises(ValueError):
                launcher.tree_identity(root, deadline=1.0)
            read.assert_not_called()

    def test_exactly_sixty_four_retained_completed_stages_refuse_new_launch(self):
        import time
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            for index in range(64):
                stage = root / f'{index:064x}'
                stage.mkdir()
                (stage / 'invocation.json').write_text('{"inputs":{}}')
                (stage / 'complete.json').write_text('{"status":"collected"}')
            stack.enter_context(patch.object(native, 'ROOT', root))
            stack.enter_context(patch.object(native, '_secured'))
            stack.enter_context(patch.object(native, '_native_identity', return_value=(os.geteuid(), os.getegid())))
            manager = stack.enter_context(patch.object(native, '_manager'))
            token = native._ACTIVE.set(({'operationId': 'a' * 64, 'registrationDigest': 'sha256:' + 'b' * 64,
                'bundleIdentity': 'c' * 64, 'deadlineMonotonic': time.monotonic() + 20}, None))
            try:
                with self.assertRaises(native.NativeBoundaryError):
                    native._execute({'operation': 'probe'}, {}, timeout=20, output_limit=4096)
            finally:
                native._ACTIVE.reset(token)
            manager.assert_not_called()
            self.assertEqual(64, len([path for path in root.iterdir() if path.is_dir()]))


if __name__ == '__main__':
    unittest.main()

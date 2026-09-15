"""Offline measurement regressions; no target-image code or host mounts are executed."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('measurement', Path(__file__).with_name('measure_runtime_image.py'))
measurement = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(measurement)


class RuntimeImageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.records = {}
        for name in ('/usr/lib/python3.13', '/usr/bin'):
            (self.root / name[1:]).mkdir(parents=True, mode=0o755)
            self.records[name] = {'directory': True}
        self.records[measurement.ZIP] = {'absent': True}
        self.records[measurement.PRELOAD] = {'absent': True}
        for name in ('/usr/lib/python3.13/hashlib.py', '/usr/lib/python3.13/json.py',
                     '/usr/bin/python3.13'):
            self.write(name, b'approved fixture; never executed\n')
        (self.root / 'usr/bin/python3').symlink_to('python3.13')
        self.records['/usr/bin/python3'] = {'link': 'python3.13', 'target': '/usr/bin/python3.13'}
        # Model root-owned image metadata without creating accounts or requiring root tests.
        original = Path.lstat
        def owned(path):
            info = original(path)
            values = list(info)
            values[4] = 0
            return os.stat_result(values)
        change = patch.object(Path, 'lstat', owned)
        change.start()
        self.addCleanup(change.stop)

    def write(self, name, raw):
        path = self.root / name[1:]
        path.write_bytes(raw)
        path.chmod(0o644)
        self.records[name] = {'sha256': measurement.hashlib.sha256(raw).hexdigest(),
                              'size': len(raw), 'executable': False}

    def test_exact_runtime_matches_without_executing_fixture_code(self):
        measurement.measure(self.root, self.records)

    def test_substituted_standard_library_cannot_execute_or_falsify_measurement(self):
        marker = self.root / 'executed'
        for module in ('hashlib', 'json'):
            with self.subTest(module=module):
                path = self.root / ('usr/lib/python3.13/' + module + '.py')
                original = path.read_bytes()
                path.write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\n')
                with self.assertRaisesRegex(ValueError, 'file-mismatch'):
                    measurement.measure(self.root, self.records)
                self.assertFalse(marker.exists())
                path.write_bytes(original)

    def test_added_import_and_zip_reject_even_with_original_files_intact(self):
        for relative in ('usr/lib/python3.13/added.py', 'usr/lib/python313.zip'):
            path = self.root / relative
            path.write_bytes(b'unapproved code')
            path.chmod(0o644)
            with self.subTest(relative=relative), self.assertRaises(ValueError):
                measurement.measure(self.root, self.records)
            path.unlink()

    def test_absolute_image_alias_stays_within_target_image(self):
        (self.root / 'lib').symlink_to('/usr/lib')
        self.assertEqual(self.root / 'usr/lib/python3.13/hashlib.py',
                         measurement.image_path(self.root, '/lib/python3.13/hashlib.py'))

    def test_missing_python_runtime_record_rejects(self):
        del self.records['/usr/bin/python3.13']
        with self.assertRaisesRegex(ValueError, 'inventory-incomplete'):
            measurement.measure(self.root, self.records)

    def test_cli_rejects_writable_mount_before_reading_target_code(self):
        import json
        import subprocess
        mount = {'filesystems': [{'target': str(self.root), 'vfs-options': 'rw,relatime'}]}
        with patch.object(measurement.sys, 'argv', ['measure', '--image-root', str(self.root),
                '--approved-inventory', '/approved/runtime.json']), \
                patch.object(measurement.subprocess, 'run', return_value=subprocess.CompletedProcess(
                    [], 0, json.dumps(mount).encode())), \
                patch.object(measurement, 'measure') as compare, \
                self.assertRaisesRegex(ValueError, 'read-only-mount-required'):
            measurement.main()
        compare.assert_not_called()

    def test_cli_rejects_running_host_as_target(self):
        with patch.object(measurement.sys, 'argv', ['measure', '--image-root', '/',
                '--approved-inventory', '/approved/runtime.json']), \
                patch.object(measurement.subprocess, 'run') as mounts, \
                self.assertRaisesRegex(ValueError, 'separate-measuring-environment-required'):
            measurement.main()
        mounts.assert_not_called()

    def test_added_native_library_plugin_policy_and_empty_directory_reject(self):
        for directory in ('/usr/lib/x86_64-linux-gnu', '/usr/libexec/sudo',
                          '/usr/share/polkit-1/rules.d', '/etc/ssl/certs'):
            path = self.root / directory[1:]
            path.mkdir(parents=True, mode=0o755)
            self.records[directory] = {'directory': True}
            measurement.measure(self.root, self.records)
            addition = path / 'glibc-hwcaps'
            addition.mkdir(mode=0o755)
            for populated in (False, True):
                if populated:
                    (addition / 'unapproved.so').write_bytes(b'unapproved native code')
                with self.subTest(directory=directory, populated=populated), self.assertRaisesRegex(
                        ValueError, 'directory-roster-mismatch'):
                    measurement.measure(self.root, self.records)
            (addition / 'unapproved.so').unlink()
            addition.rmdir()

    def test_absent_optional_entries_do_not_count_as_directory_children(self):
        directory = self.root / 'etc'
        directory.mkdir(mode=0o755)
        self.records['/etc'] = {'directory': True}
        measurement.measure(self.root, self.records)

    def test_dangling_loader_hook_and_later_target_creation_reject(self):
        (self.root / 'etc').mkdir(mode=0o755)
        hook = self.root / 'etc/ld.so.preload'
        hook.symlink_to('/tmp/runner-preload')
        with self.assertRaises(ValueError):
            measurement.measure(self.root, self.records)
        (self.root / 'tmp').mkdir(mode=0o755)
        (self.root / 'tmp/runner-preload').write_bytes(b'unapproved loader config')
        with self.assertRaises(ValueError):
            measurement.measure(self.root, self.records)

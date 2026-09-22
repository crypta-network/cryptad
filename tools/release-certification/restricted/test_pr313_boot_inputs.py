"""Real ELF snapshot checks; no QEMU guest is launched by this module."""
from pathlib import Path
import json
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import pr313_boot_inputs as boot


class BootInputsTest(unittest.TestCase):
    def source(self, root):
        source = root / 'source'
        for relative in boot.TREES:
            (source / relative).mkdir(parents=True)
        (source / 'usr/share/seabios/bios-256k.bin').write_bytes(b'synthetic-firmware')
        output = root / 'private'
        output.mkdir(mode=0o700)
        tools = output / 'tools'
        tools.mkdir()
        executable = tools / 'true'
        shutil.copyfile('/usr/bin/true', executable)
        executable.chmod(0o500)
        return source, output, {'true': executable}

    def test_copied_loader_and_dependencies_execute_after_caller_tree_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, output, executables = self.source(Path(temporary))
            runtime, environment = boot.snapshot_runtime(source, output, executables)
            shutil.rmtree(source)
            argv = boot.invocation([str(executables['true'])], environment)
            self.assertTrue(Path(argv[0]).is_relative_to(output))
            self.assertIn('--inhibit-cache', argv)
            subprocess.run(argv, env=environment, check=True, timeout=5, capture_output=True)
            self.assertEqual(b'synthetic-firmware',
                (runtime / 'usr/share/seabios/bios-256k.bin').read_bytes())
            inventory = json.loads((output / 'boot-inputs.private.json').read_bytes())
            for relative, expected in inventory['files'].items():
                self.assertEqual(expected, boot.digest(output / relative))
            self.assertNotIn('HOME', environment)
            self.assertNotIn('LD_PRELOAD', environment)

    def test_dependency_free_shared_elf_module_is_retained_and_not_mistaken_for_missing_dependency(self):
        compiler = shutil.which('cc')
        if compiler is None:
            self.skipTest('C compiler unavailable; real dependency-free ELF module not built')
        with tempfile.TemporaryDirectory() as temporary:
            source, output, executables = self.source(Path(temporary))
            module = source / 'usr/lib/x86_64-linux-gnu/qemu/synthetic-module.so'
            module.parent.mkdir()
            subprocess.run([compiler, '-shared', '-nostdlib', '-x', 'c', '-o', str(module), '-'],
                input=b'int pr313_test_module(void) { return 313; }\n', check=True,
                capture_output=True, timeout=15, env=boot.ENVIRONMENT)
            dependencies = subprocess.run(['/usr/bin/ldd', str(module)], check=True,
                capture_output=True, timeout=10, env=boot.ENVIRONMENT)
            self.assertEqual(b'statically linked', dependencies.stdout.strip())
            runtime, environment = boot.snapshot_runtime(source, output, executables)
            retained = runtime / module.relative_to(source)
            self.assertEqual(boot.digest(module), boot.digest(retained))
            record = json.loads((output / 'boot-inputs.private.json').read_bytes())
            self.assertEqual(boot.digest(module), record['files'][retained.relative_to(output).as_posix()])
            subprocess.run(boot.invocation([str(executables['true'])], environment),
                env=environment, check=True, capture_output=True, timeout=5)

    def test_unresolved_dependency_prevents_usable_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, output, executables = self.source(Path(temporary))
            with patch.object(boot.subprocess, 'run', return_value=subprocess.CompletedProcess(
                    [], 0, b'libmissing.so => not found\n', b'')):
                with self.assertRaisesRegex(ValueError, 'dependency-unresolved'):
                    boot.snapshot_runtime(source, output, executables)
            self.assertFalse((output / 'boot-inputs.private.json').exists())

    def test_file_bound_and_directory_symlinks_fail_before_inventory(self):
        for mode in ('bound', 'link'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                source, output, executables = self.source(Path(temporary))
                if mode == 'link':
                    (source / 'usr/share/qemu/escape').symlink_to('/tmp', target_is_directory=True)
                with patch.object(boot, 'MAX_FILES', 0 if mode == 'bound' else 8192):
                    with self.assertRaises(ValueError):
                        boot.snapshot_runtime(source, output, executables)
                self.assertFalse((output / 'boot-inputs.private.json').exists())

    def test_seed_and_trust_records_remain_separate_from_nonsecret_file_roster(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, output, executables = self.source(Path(temporary))
            boot.snapshot_runtime(source, output, executables)
            boot.record_private_inputs(output, seedDigest='private-seed-commitment',
                sshHostKeyPinDigest='private-trust-commitment')
            record = json.loads((output / 'boot-inputs.private.json').read_bytes())
            self.assertEqual('private-seed-commitment', record['bootInputs']['seedDigest'])
            self.assertNotIn('private-seed-commitment', str(record['files']))

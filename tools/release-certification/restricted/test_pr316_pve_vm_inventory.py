"""Offline contract checks for the root PVE PR-316 inventory producer."""
from pathlib import Path
import os
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import installation
import pr316_pve_vm_inventory as inventory


class PveInventoryTest(unittest.TestCase):
    def test_inventory_helper_is_host_only_test_seam(self):
        self.assertIn(
            'tools/release-certification/restricted/pr316_pve_vm_inventory.py',
            installation.TEST_SEAMS)

    def test_snapshot_reports_actual_allocated_storage_and_task_qemu(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            proc, root = base / 'proc', base / 'task'
            proc.mkdir()
            root.mkdir()
            (root / 'retained.bin').write_bytes(b'x' * 4096)
            process = proc / '123'
            process.mkdir()
            (process / 'cmdline').write_bytes(
                b'/usr/bin/qemu-system-x86_64\0-drive\0file=/work/pr315-task/suite-1/disk.qcow2\0')
            (process / 'stat').write_text('123 (qemu) S ' + ' '.join(['0'] * 18 + ['42']))
            with patch.object(inventory.os, 'geteuid', return_value=0):
                value = inventory.snapshot(proc, root)
            self.assertEqual([{'pid': 123, 'startTicks': 42}],
                             value['activeTaskQemu'])
            self.assertGreater(value['allocatedTaskBytes'], 0)
            self.assertGreater(value['availableTaskBytes'], 0)

    def test_snapshot_fails_closed_without_root_or_proc(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(inventory.os, 'geteuid', return_value=1000), \
                    self.assertRaisesRegex(ValueError, 'root-required'):
                inventory.snapshot(root / 'missing', root)

    def test_allocated_bytes_counts_each_directory_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            device = root.stat().st_dev
            child = root / 'child'
            walk = [(str(root), ['child'], ['root.bin']),
                    (str(child), [], ['leaf.bin'])]
            blocks = {root: 1, child: 2, root / 'root.bin': 3,
                      child / 'leaf.bin': 4}

            def info(path):
                selected = Path(path)
                mode = stat.S_IFDIR if selected in (root, child) else stat.S_IFREG
                return SimpleNamespace(st_dev=device, st_mode=mode,
                                       st_blocks=blocks[selected])

            with patch.object(inventory.os, 'walk', return_value=walk), \
                    patch.object(Path, 'lstat', autospec=True,
                                 side_effect=info):
                self.assertEqual(10 * 512, inventory._allocated_bytes(root))

    def test_receipt_directory_rejects_symlink_without_chmodding_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root, target = base / 'task', base / 'target'
            root.mkdir(mode=0o700)
            target.mkdir(mode=0o700)
            (root / 'host-inventory').symlink_to(target, target_is_directory=True)
            before = stat.S_IMODE(target.stat().st_mode)
            with self.assertRaises((OSError, ValueError)):
                with inventory._pinned_receipt_directory(
                        root, task_uid=os.geteuid(), receipt_uid=os.geteuid()):
                    self.fail('symlinked receipt directory was accepted')
            self.assertEqual(before, stat.S_IMODE(target.stat().st_mode))
            self.assertEqual([], list(target.iterdir()))

    def test_receipt_directory_is_pinned_relative_to_validated_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            with inventory._pinned_receipt_directory(
                    root, task_uid=os.geteuid(), receipt_uid=os.geteuid()) as descriptor:
                info = os.fstat(descriptor)
                self.assertTrue(stat.S_ISDIR(info.st_mode))
                leaf = os.open('receipt', os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                               0o600, dir_fd=descriptor)
                os.close(leaf)
            self.assertTrue((root / 'host-inventory/receipt').is_file())


if __name__ == '__main__':
    unittest.main()

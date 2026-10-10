"""Disposable checks for exact host copy release; never touch PVE task paths."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import pr315_pve_attempt_cleanup as cleanup
import pr315_pve_attempt_inventory as inventory


class CleanupPlanTest(unittest.TestCase):
    def test_package_directory_alias_keeps_real_target_image_in_inventory(self):
        with tempfile.TemporaryDirectory(prefix='pr315-inventory-links-') as temporary:
            root = Path(temporary)
            target = root / 'qemu-system-common'
            target.mkdir()
            (root / 'qemu-system-x86').symlink_to(target.name, target_is_directory=True)
            retained = target / 'retained.qcow2'
            retained.write_bytes(b'overlay')
            selected = root / 'prepared.qcow2'
            selected.write_bytes(b'prepared')

            def image_info(command, **_kwargs):
                value = {'format': 'qcow2'}
                if Path(command[-1]) == retained:
                    value['full-backing-filename'] = str(selected)
                return SimpleNamespace(stdout=json.dumps(value).encode())

            with patch.object(inventory, '_retained_image_roots', return_value=[root]), \
                    patch.object(inventory.subprocess, 'run', side_effect=image_info):
                dependents, scanned = inventory._external_backing_users({selected})

            self.assertEqual([str(retained)], dependents)
            self.assertEqual(2, scanned)

    def test_directory_alias_outside_inventory_roots_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix='pr315-inventory-links-') as temporary, \
                tempfile.TemporaryDirectory(prefix='pr315-inventory-outside-') as outside:
            root = Path(temporary)
            (root / 'outside').symlink_to(outside, target_is_directory=True)
            with patch.object(inventory, '_retained_image_roots', return_value=[root]):
                with self.assertRaisesRegex(ValueError, 'storage-inventory-unavailable'):
                    inventory._external_backing_users(set())

    def test_alias_into_another_configured_root_keeps_external_data_dependency(self):
        with tempfile.TemporaryDirectory(prefix='pr315-inventory-links-') as temporary, \
                tempfile.TemporaryDirectory(prefix='pr315-inventory-other-') as other:
            root, other_root = Path(temporary), Path(other)
            (root / 'alias').symlink_to(other_root, target_is_directory=True)
            selected = root / 'prepared.qcow2'
            selected.write_bytes(b'prepared')
            retained = other_root / 'retained.qcow2'
            retained.write_bytes(b'overlay')

            def image_info(command, **_kwargs):
                value = {'format': 'qcow2'}
                if Path(command[-1]) == retained:
                    value['format-specific'] = {'data': {'data-file': str(selected)}}
                return SimpleNamespace(stdout=json.dumps(value).encode())

            with patch.object(inventory, '_retained_image_roots',
                              return_value=[root, other_root]), \
                    patch.object(inventory.subprocess, 'run', side_effect=image_info):
                dependents, scanned = inventory._external_backing_users({selected})

            self.assertEqual([str(retained)], dependents)
            self.assertEqual(2, scanned)

    def test_directory_alias_target_not_walked_cannot_grant_release(self):
        with tempfile.TemporaryDirectory(prefix='pr315-inventory-links-') as temporary:
            root = Path(temporary)
            target = root / 'real'
            target.mkdir()
            (root / 'alias').symlink_to(target.name, target_is_directory=True)
            with patch.object(inventory, '_retained_image_roots', return_value=[root]), \
                    patch.object(inventory.os, 'walk', return_value=[
                        (str(root), ['alias'], [])]):
                with self.assertRaisesRegex(ValueError, 'storage-inventory-unavailable'):
                    inventory._external_backing_users(set())

    def test_directory_alias_changed_during_inventory_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix='pr315-inventory-links-') as temporary:
            root = Path(temporary)
            target = root / 'real'
            target.mkdir()
            replacement = root / 'other'
            replacement.mkdir()
            link = root / 'alias'
            link.symlink_to(target.name, target_is_directory=True)
            image = root / 'probe.qcow2'
            image.write_bytes(b'probe')

            def image_info(_command, **_kwargs):
                link.unlink()
                link.symlink_to(replacement.name, target_is_directory=True)
                return SimpleNamespace(stdout=b'{"format":"qcow2"}')

            with patch.object(inventory, '_retained_image_roots', return_value=[root]), \
                    patch.object(inventory.subprocess, 'run', side_effect=image_info):
                with self.assertRaisesRegex(ValueError, 'storage-inventory-unavailable'):
                    inventory._external_backing_users(set())

    def test_retained_overlay_outside_task_blocks_release(self):
        with tempfile.TemporaryDirectory(prefix='pr315-inventory-task-') as task_dir, \
                tempfile.TemporaryDirectory(prefix='pr315-inventory-store-') as store_dir:
            task = Path(task_dir) / 'task'
            selected = task / 'suite-201/attempt-01/prepared.qcow2'
            selected.parent.mkdir(parents=True)
            selected.write_bytes(b'prepared')
            store = Path(store_dir)
            overlay = store / 'retained.qcow2'
            overlay.write_bytes(b'overlay')
            config = task / 'storage.cfg'
            config.write_text('dir: retained\n\tpath ' + str(store) +
                              '\n\tcontent images\n')

            def image_info(command, **_kwargs):
                disk = Path(command[-1])
                value = {'format': 'qcow2'}
                if disk == overlay:
                    value['full-backing-filename'] = str(selected)
                return SimpleNamespace(stdout=json.dumps(value).encode())

            with patch.object(inventory, 'TASK', task), \
                    patch.object(inventory, 'PVE_STORAGE_CONFIG', config), \
                    patch.object(inventory.subprocess, 'run', side_effect=image_info):
                dependents, scanned = inventory._external_backing_users({selected})

            self.assertEqual([str(overlay)], dependents)
            self.assertGreaterEqual(scanned, 2)

    def test_missing_storage_inventory_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix='pr315-inventory-task-') as task_dir:
            task = Path(task_dir) / 'task'
            task.mkdir()
            with patch.object(inventory, 'TASK', task), \
                    patch.object(inventory, 'PVE_STORAGE_CONFIG',
                                 task / 'missing-storage.cfg'):
                with self.assertRaisesRegex(ValueError,
                                            'storage-inventory-unavailable'):
                    inventory._external_backing_users(set())

    def test_unavailable_configured_image_store_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix='pr315-inventory-task-') as task_dir:
            task = Path(task_dir) / 'task'
            task.mkdir()
            config = task / 'storage.cfg'
            config.write_text('dir: retained\n\tpath ' +
                              str(task / 'missing-image-store') +
                              '\n\tcontent images\n')
            with patch.object(inventory, 'TASK', task), \
                    patch.object(inventory, 'PVE_STORAGE_CONFIG', config):
                with self.assertRaisesRegex(ValueError,
                                            'storage-inventory-unavailable'):
                    inventory._external_backing_users(set())

    def test_plan_rejects_arbitrary_path_and_incomplete_file_set(self):
        plan = {'schemaVersion': 1,
            'kind': 'pr315-host-success-copy-release-plan-v1',
            'suite': 'suite-201', 'sourceCommit': 'a' * 40,
            'campaignPlanDigest': 'b' * 64,
            'sealedReceiptDigest': 'c' * 64,
            'macFullArchiveDigest': 'd' * 64,
            'fileDigests': {name: 'e' * 64 for name in inventory.FILES}}
        self.assertEqual(plan, inventory._plan(plan))
        with self.assertRaisesRegex(ValueError, 'plan-invalid'):
            inventory._plan({**plan, 'suite': '../suite-201'})
        with self.assertRaisesRegex(ValueError, 'plan-invalid'):
            inventory._plan({**plan, 'fileDigests': {
                'guest.qcow2': 'e' * 64}})

    def test_check_digest_mismatch_cannot_remove_a_file(self):
        with patch.object(inventory, 'inspect', return_value={'files': {}}), \
                patch.object(Path, 'unlink') as unlink, \
                patch.object(cleanup.shutil, 'rmtree') as rmtree:
            with self.assertRaisesRegex(ValueError, 'check-changed'):
                cleanup.apply({'suite': 'suite-201'}, '0' * 64)
            unlink.assert_not_called()
            rmtree.assert_not_called()


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0,
                     'requires disposable native Linux root directory')
class DisposableRootReleaseTest(unittest.TestCase):
    def test_check_then_apply_removes_only_owned_success_copies(self):
        self.assert_release(False)

    def test_preparation_copies_require_the_exact_failed_outcome(self):
        self.assert_release(True)

    def assert_release(self, preparation):
        with tempfile.TemporaryDirectory(dir='/root',
                                         prefix='pr315-release-test-') as temporary:
            task = Path(temporary)
            base = task / 'suite-201/attempt-01'
            base.mkdir(parents=True)
            for name in inventory.DIRECTORIES:
                (base / name).mkdir()
            jar = base / 'cryptad/build/cryptad-dist/lib/cryptad.jar'
            jar.parent.mkdir(parents=True)
            jar.write_bytes(b'candidate-jar')
            head = base / 'cryptad/.git/HEAD'
            head.parent.mkdir()
            head.write_text('a' * 40 + '\n')
            file_digests = {}
            for name in inventory.FILES:
                raw = ('copied-' + name).encode()
                (base / name).write_bytes(raw)
                file_digests[name] = hashlib.sha256(raw).hexdigest()
            report = {'status': 'guest-operation-failed' if preparation else 'guest-report-retained',
                'guestStopped': True, 'guestExitCode': 1 if preparation else 0,
                'helperSourceCommit': 'a' * 40,
                'sourceArchiveDigest': file_digests['source.tar.gz'],
                'preparedImageDigest': file_digests['prepared.qcow2'],
                'productDigest': hashlib.sha256(b'candidate-jar').hexdigest()}
            (base / 'attempt.private.json').write_text(json.dumps(report))
            monitor = task / 'host-monitor'
            monitor.mkdir()
            (monitor / 'suite-201.finished.json').write_text(json.dumps({
                'kind': 'pr315-pve-watch-finished', 'suite': 'suite-201',
                'sourceCommit': 'a' * 40, 'action': 'completed',
                'seenTaskQemu': True}))
            sentinel = task / 'unrelated-sentinel'
            sentinel.write_text('preserve')
            plan = {'schemaVersion': 1,
                'kind': ('pr315-host-preparation-copy-release-plan-v1' if preparation
                         else 'pr315-host-success-copy-release-plan-v1'),
                'suite': 'suite-201', 'sourceCommit': 'a' * 40,
                'campaignPlanDigest': 'b' * 64,
                'sealedReceiptDigest': 'c' * 64,
                'macFullArchiveDigest': 'd' * 64,
                'fileDigests': file_digests}

            def image_info(command, **_kwargs):
                path = Path(command[-1])
                value = {'format': 'qcow2'}
                if path.name == 'guest.qcow2':
                    value['full-backing-filename'] = (
                        '/work/pr315-task/suite-201/attempt-01/prepared.qcow2')
                return SimpleNamespace(stdout=json.dumps(value).encode())

            with patch.object(inventory, 'TASK', task), \
                    patch.object(inventory, 'OWNER_UID', 0), \
                    patch.object(inventory, '_qemu_processes', return_value=[]), \
                    patch.object(inventory, '_open_users', return_value=[]), \
                    patch.object(inventory, '_external_backing_users',
                                 return_value=([], 2)), \
                    patch.object(inventory.subprocess, 'run',
                                 side_effect=image_info):
                checked = inventory.inspect(plan)
                self.assertEqual('suite-201', checked['suite'])
                wrong_kind = ('pr315-host-success-copy-release-plan-v1' if preparation
                              else 'pr315-host-preparation-copy-release-plan-v1')
                with self.assertRaisesRegex(ValueError, 'stop-proof-invalid'):
                    inventory.inspect(dict(plan, kind=wrong_kind))
                with self.assertRaisesRegex(ValueError, 'check-changed'):
                    cleanup.apply(plan, '0' * 64)
                self.assertTrue((base / 'guest.qcow2').exists())
                receipt = cleanup.apply(plan,
                    hashlib.sha256(inventory._canonical(checked)).hexdigest())
            self.assertEqual('completed-remote-preparation-duplicates-only' if preparation
                             else 'completed-remote-success-duplicates-only',
                             receipt['release'])
            self.assertFalse((base / 'guest.qcow2').exists())
            self.assertFalse((base / 'cryptad').exists())
            self.assertEqual('preserve', sentinel.read_text())


if __name__ == '__main__':
    unittest.main()

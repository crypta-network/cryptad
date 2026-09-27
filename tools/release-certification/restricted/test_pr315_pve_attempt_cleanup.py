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
            report = {'status': 'guest-report-retained',
                'guestStopped': True, 'guestExitCode': 0,
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
                'kind': 'pr315-host-success-copy-release-plan-v1',
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
                with self.assertRaisesRegex(ValueError, 'check-changed'):
                    cleanup.apply(plan, '0' * 64)
                self.assertTrue((base / 'guest.qcow2').exists())
                receipt = cleanup.apply(plan,
                    hashlib.sha256(inventory._canonical(checked)).hexdigest())
            self.assertEqual('completed-remote-success-duplicates-only',
                             receipt['release'])
            self.assertFalse((base / 'guest.qcow2').exists())
            self.assertFalse((base / 'cryptad').exists())
            self.assertEqual('preserve', sentinel.read_text())


if __name__ == '__main__':
    unittest.main()

"""Stop marker parsing and owner-binding tests; no installed acceptance claim."""
from contextlib import ExitStack
import copy
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import restricted_workload as workload
import restricted_workload_mark as mark

ROLE = 'candidate-sender'
GENERATION = 'a' * 64
INVOCATION = 'b' * 32
BOOT = 'test-boot'


class MembershipTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)

    def test_only_exact_helper_membership_is_accepted(self):
        (self.path / 'cgroup.procs').write_text(str(os.getpid()) + '\n')
        mark._members(self.fd, os.getpid())

    def test_empty_other_duplicate_malformed_and_flooded_membership_reject(self):
        for raw in ('', '2\n', '3\n3\n', '3 \n', '3\n4\n', '3\n' * 5000):
            with self.subTest(raw=raw[:20]):
                (self.path / 'cgroup.procs').write_text(raw)
                with self.assertRaises(workload.WorkloadError):
                    mark._members(self.fd, 3)

    def test_missing_membership_is_unavailable(self):
        with self.assertRaises(FileNotFoundError):
            mark._members(self.fd, 3)

    def test_symlink_fifo_hardlink_and_child_cgroup_reject(self):
        member = self.path / 'cgroup.procs'
        other = self.path / 'other'
        other.write_text('3\n')
        member.symlink_to(other)
        with self.assertRaises(workload.WorkloadError):
            mark._members(self.fd, 3)
        member.unlink()
        os.mkfifo(member)
        with self.assertRaises(workload.WorkloadError):
            mark._members(self.fd, 3)
        member.unlink()
        os.link(other, member)
        with self.assertRaises(workload.WorkloadError):
            mark._members(self.fd, 3)
        member.unlink()
        member.write_text('3\n')
        (self.path / 'child').mkdir()
        with self.assertRaisesRegex(workload.WorkloadError, 'subtree'):
            mark._members(self.fd, 3)

    def test_directory_entry_flood_is_bounded(self):
        (self.path / 'cgroup.procs').write_text('3\n')
        for index in range(129):
            (self.path / str(index)).touch()
        with self.assertRaisesRegex(workload.WorkloadError, 'subtree'):
            mark._members(self.fd, 3)

    def test_actual_self_epoch_is_stable_without_privilege(self):
        first = mark._self_epoch()
        self.assertEqual(os.getpid(), first[0])
        self.assertGreater(first[1], 0)
        self.assertEqual(first, mark._self_epoch())


class StopReceiptTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.group = self.root / 'group'
        self.group.mkdir()
        (self.group / 'cgroup.procs').write_text(str(os.getpid()) + '\n')
        info = self.group.stat()
        self.identity = [info.st_dev, info.st_ino]
        self.record = dict(state='stopping', campaign='campaign', generation=GENERATION,
                           bootId=BOOT, managerInvocation=INVOCATION, cgroupIdentity=self.identity)
        self.campaign = dict(generation='campaign', bootId=BOOT, state='terminalizing')
        self.marker = dict(generation=GENERATION, bootId=BOOT,
                           managerInvocation=INVOCATION, cgroupIdentity=self.identity)
        self.stack.enter_context(patch.object(workload, 'group', return_value=self.group))
        self.stack.enter_context(patch.object(workload, 'ROOT', self.root))
        self.stack.enter_context(patch.object(workload, 'boot', return_value=BOOT))
        self.stack.enter_context(patch.object(workload, 'read', side_effect=lambda _path: copy.deepcopy(self.marker)))
        self.write = self.stack.enter_context(patch.object(workload, 'write'))
        self.current = self.stack.enter_context(patch.object(workload, 'current', side_effect=AssertionError('no admission')))
        self.lease = self.stack.enter_context(patch.object(workload, 'locked', side_effect=AssertionError('no lease')))

    def receipt(self):
        mark.stop_receipt(ROLE, INVOCATION, self.record, self.campaign)
        return self.write.call_args.args[1]

    def test_exact_helper_only_receipt_is_create_only_after_observation(self):
        receipt = self.receipt()
        self.assertEqual(self.root / 'authority' / (ROLE + '-stop.json'), self.write.call_args.args[0])
        self.assertEqual({'create': True}, self.write.call_args.kwargs)
        self.assertEqual({'schemaVersion', 'role', 'campaign', 'generation', 'bootId',
                          'managerInvocation', 'cgroupIdentity', 'helperPid', 'helperStartTimeTicks',
                          'startedMonotonicNs', 'observedMonotonicNs', 'membership', 'descendantCgroups'}, set(receipt))
        self.assertEqual('only-stop-helper', receipt['membership'])
        self.assertEqual(0, receipt['descendantCgroups'])
        self.assertEqual(self.identity, receipt['cgroupIdentity'])
        self.assertEqual(os.getpid(), receipt['helperPid'])
        self.assertGreaterEqual(receipt['observedMonotonicNs'], receipt['startedMonotonicNs'])
        self.current.assert_not_called()
        self.lease.assert_not_called()

    def test_lost_start_response_can_bind_exact_start_marker(self):
        self.record.update(state='launching', managerInvocation=None, cgroupIdentity=None)
        self.assertEqual(INVOCATION, self.receipt()['managerInvocation'])

    def test_stale_record_campaign_and_marker_fields_reject_without_write(self):
        changes = [('record', 'state', 'prepared'), ('record', 'generation', 'invalid'),
                   ('record', 'managerInvocation', None), ('record', 'cgroupIdentity', None),
                   ('record', 'managerInvocation', 'c' * 32), ('record', 'cgroupIdentity', [1, 2]),
                   ('record', 'campaign', 'other'), ('record', 'bootId', 'other'),
                   ('campaign', 'bootId', 'other'), ('marker', 'generation', 'c' * 64),
                   ('marker', 'bootId', 'other'), ('marker', 'managerInvocation', 'c' * 32),
                   ('marker', 'cgroupIdentity', [1, 2])]
        for subject, key, value in changes:
            with self.subTest(subject=subject, key=key):
                record = getattr(self, subject)
                old = record[key]
                record[key] = value
                try:
                    with self.assertRaises(workload.WorkloadError):
                        self.receipt()
                    self.write.assert_not_called()
                finally:
                    record[key] = old

    def test_other_member_between_observations_rejects(self):
        original = mark._members
        calls = []
        def observe(fd, pid):
            if calls:
                (self.group / 'cgroup.procs').write_text(str(pid) + '\n1\n')
            calls.append(None)
            original(fd, pid)
        with patch.object(mark, '_members', side_effect=observe):
            with self.assertRaises(workload.WorkloadError):
                self.receipt()
        self.write.assert_not_called()

    def test_replaced_group_helper_epoch_and_expired_observation_reject(self):
        epoch = mark._self_epoch()
        with patch.object(mark, '_self_epoch', side_effect=[epoch, (epoch[0], epoch[1] + 1)]):
            with self.assertRaisesRegex(workload.WorkloadError, 'observation-changed'):
                self.receipt()
        with patch.object(mark.time, 'monotonic_ns', side_effect=[1, 6_000_000_002]):
            with self.assertRaisesRegex(workload.WorkloadError, 'observation-changed'):
                self.receipt()
        def replace(_fd, _pid):
            if self.group.exists():
                self.group.rename(self.root / 'old-group')
                self.group.mkdir()
        with patch.object(mark, '_members', side_effect=[None, None]), \
                patch.object(mark, '_self_epoch', side_effect=lambda: (replace(None, None) or epoch)):
            with self.assertRaisesRegex(workload.WorkloadError, 'observation-changed'):
                self.receipt()
        self.write.assert_not_called()

    def test_existing_receipt_cannot_be_overwritten(self):
        self.write.side_effect = FileExistsError('retained receipt')
        with self.assertRaises(FileExistsError):
            self.receipt()
        self.assertEqual({'create': True}, self.write.call_args.kwargs)


class ArchivedReceiptTest(unittest.TestCase):
    def setUp(self):
        self.receipt = {'schemaVersion': 1, 'role': ROLE, 'campaign': 'campaign',
            'generation': GENERATION, 'bootId': BOOT, 'managerInvocation': INVOCATION,
            'cgroupIdentity': [1, 2], 'helperPid': 42, 'helperStartTimeTicks': 100,
            'startedMonotonicNs': 200, 'observedMonotonicNs': 300,
            'membership': 'only-stop-helper', 'descendantCgroups': 0}
        self.old = dict(self.receipt, generation='c' * 64, managerInvocation='d' * 32)

    def test_durably_archived_previous_generation_allows_atomic_current_replacement(self):
        with patch.object(mark.os.path, 'lexists', return_value=True), \
                patch.object(workload, 'read', side_effect=[self.old, self.old, self.old]) as read, \
                patch.object(workload, 'write') as write:
            mark._publish(ROLE, self.receipt)
        self.assertEqual(ROLE + '-stop-' + 'c' * 64 + '.json', read.call_args_list[1].args[0].name)
        self.assertEqual({}, write.call_args.kwargs)
        self.assertEqual(self.receipt, write.call_args.args[1])

    def test_missing_mismatched_archive_or_changed_current_copy_is_retained(self):
        for observations in ([self.old, FileNotFoundError()],
                             [self.old, dict(self.old, helperPid=99)],
                             [self.old, self.old, dict(self.old, helperPid=99)]):
            with self.subTest(observations=observations), \
                    patch.object(mark.os.path, 'lexists', return_value=True), \
                    patch.object(workload, 'read', side_effect=observations), \
                    patch.object(workload, 'write') as write:
                with self.assertRaises((workload.WorkloadError, FileNotFoundError)):
                    mark._publish(ROLE, self.receipt)
                write.assert_not_called()

    def test_same_generation_invalid_generation_and_foreign_campaign_reject(self):
        for old in (self.receipt, dict(self.old, generation='../x'),
                    dict(self.old, campaign='other'), dict(self.old, bootId='other'),
                    dict(self.old, membership='unknown')):
            with self.subTest(old=old), patch.object(mark.os.path, 'lexists', return_value=True), \
                    patch.object(workload, 'read', return_value=old), \
                    patch.object(workload, 'write') as write:
                with self.assertRaisesRegex(workload.WorkloadError, 'receipt-retained'):
                    mark._publish(ROLE, self.receipt)
                write.assert_not_called()


class EntryTest(unittest.TestCase):
    def test_existing_start_entry_retains_admission_and_original_receipt_shape(self):
        with ExitStack() as stack:
            stack.enter_context(patch.object(mark.sys, 'flags', SimpleNamespace(isolated=1, no_site=1)))
            stack.enter_context(patch.object(mark.sys, 'argv', ['marker', ROLE]))
            stack.enter_context(patch.object(mark.os, 'geteuid', return_value=0))
            stack.enter_context(patch.dict(mark.os.environ, {'INVOCATION_ID': INVOCATION}, clear=True))
            stack.enter_context(patch.object(Path, 'read_text', return_value='0::/system.slice/' + workload.unit(ROLE)))
            stack.enter_context(patch.object(workload, 'read', side_effect=[
                {'state': 'launching', 'bootId': BOOT, 'generation': GENERATION}, {'campaign': True}]))
            stack.enter_context(patch.object(workload, 'boot', return_value=BOOT))
            stack.enter_context(patch.object(Path, 'stat', return_value=SimpleNamespace(st_dev=1, st_ino=2)))
            current = stack.enter_context(patch.object(workload, 'current'))
            write = stack.enter_context(patch.object(workload, 'write'))
            stop = stack.enter_context(patch.object(mark, 'stop_receipt'))
            mark.main()
            current.assert_called_once_with({'campaign': True})
            stop.assert_not_called()
            self.assertEqual({'generation': GENERATION, 'bootId': BOOT,
                              'managerInvocation': INVOCATION, 'cgroupIdentity': [1, 2]},
                             write.call_args.args[1])

    def test_closed_stop_entry_checks_scope_and_never_checks_current_authority(self):
        with ExitStack() as stack:
            stack.enter_context(patch.object(mark.sys, 'flags', SimpleNamespace(isolated=1, no_site=1)))
            stack.enter_context(patch.object(mark.sys, 'argv', ['marker', ROLE, 'stop']))
            stack.enter_context(patch.object(mark.os, 'geteuid', return_value=0))
            stack.enter_context(patch.dict(mark.os.environ, {'INVOCATION_ID': INVOCATION}, clear=True))
            stack.enter_context(patch.object(Path, 'read_text', return_value='0::/system.slice/' + workload.unit(ROLE)))
            stack.enter_context(patch.object(workload, 'read', side_effect=[{'record': True}, {'campaign': True}]))
            stop = stack.enter_context(patch.object(mark, 'stop_receipt'))
            current = stack.enter_context(patch.object(workload, 'current'))
            mark.main()
            stop.assert_called_once_with(ROLE, INVOCATION, {'record': True}, {'campaign': True})
            current.assert_not_called()

    def test_arbitrary_extra_operation_rejects_before_reads(self):
        with patch.object(mark.sys, 'flags', SimpleNamespace(isolated=1, no_site=1)), \
                patch.object(mark.os, 'geteuid', return_value=0), \
                patch.object(workload, 'read') as read:
            for arguments in (['marker', ROLE, 'start'], ['marker', ROLE, 'stop', '/tmp/path'],
                              ['marker', 'unknown', 'stop']):
                with patch.object(mark.sys, 'argv', arguments), self.assertRaises(workload.WorkloadError):
                    mark.main()
            read.assert_not_called()


if __name__ == '__main__':
    unittest.main()

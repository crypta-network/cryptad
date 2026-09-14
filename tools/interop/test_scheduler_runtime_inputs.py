"""Offline original-input roster and private runtime snapshot regression tests."""
import copy
from pathlib import Path
import tempfile
import unittest

import scheduler_pressure_runtime as scheduler


def snapshot():
    return {'schemaVersion': 1, 'kind': 'cryptad-runtime-input-snapshot', 'lane': 'standalone-v1',
        'environment': {'javaExecutable': 'sha256:' + 'a' * 64, 'javaVersion': 'synthetic-jdk-25',
            'os': 'Linux', 'arch': 'x86_64', 'kernel': 'synthetic', 'cpuCount': 4,
            'container': {'known': True, 'scope': 'selected-process-visible-cgroup-v2-hierarchy',
                'ancestorCount': 1, 'controllerConfigurationDigest': 'sha256:' + 'b' * 64,
                'memoryMax': 4096, 'cpuMax': {'quotaMicros': 100000, 'periodMicros': 100000},
                'processAllowedCpuList': '0-3', 'unlimitedMeaning': 'no-finite-limit-in-visible-controller-hierarchy',
                'membershipDigest': 'sha256:' + 'c' * 64},
            'hardware': {'known': True, 'descriptorDigest': 'sha256:' + 'd' * 64}, 'hostRamBytes': 8192,
            'processObservation': 'selected-daemon', 'network': {'class': 'single-node-isolated-loopback'},
            'storage': {'known': True, 'class': 'private-owned-workload-directory', 'blockSizeBytes': 4096,
                'fragmentSizeBytes': 4096, 'filesystemIdentityDigest': 'sha256:' + 'e' * 64}},
        'jvmConfiguration': {'javaVendor': 'synthetic', 'javaVersion': '25', 'vmName': 'synthetic',
            'vmVersion': '25', 'garbageCollectors': ['synthetic'], 'availableProcessors': 4,
            'heapInitialBytes': 1024, 'heapMaxBytes': 4096},
        'configuration': {
            'schedulerConfiguration': {'enabled': True, **dict.fromkeys([
                'initialDelayMillis', 'schedulerPollIntervalMillis', 'defaultPollIntervalMillis',
                'minimumPollIntervalMillis', 'maximumPollIntervalMillis', 'jitterMillis',
                'failureBackoffMillis', 'maximumFailureBackoffMillis', 'perTickFetchLimit',
                'perAppSubscriptionLimit', 'globalSubscriptionLimit', 'defaultMaxBytes',
                'hardMaxBytes', 'defaultTimeoutMillis', 'hardTimeoutMillis'], 1)},
            'budgetConfiguration': dict.fromkeys([
                'foregroundContentFetchPerAppPerMinute', 'foregroundContentFetchGlobalPerMinute',
                'foregroundContentFetchConcurrentPerApp', 'foregroundContentFetchConcurrentGlobal',
                'subscriptionPollPerAppPerHour', 'subscriptionPollGlobalPerHour',
                'subscriptionPollConcurrentPerApp', 'subscriptionPollConcurrentGlobal',
                'trustGraphImportPerAppPerHour', 'trustGraphImportGlobalPerHour',
                'trustGraphImportConcurrentPerApp', 'trustGraphImportConcurrentGlobal'], 1),
            'pressureConfiguration': {'known': True, 'family': 'bounded-content-fetch-operations',
                'maximumInFlight': 1, 'resumeAtOrBelow': 0}},
        'fingerprint': dict.fromkeys(scheduler.pressure_evidence.baseline.FINGERPRINT, 'sha256:' + 'a' * 64)}


class RuntimeInputTest(unittest.TestCase):
    def test_writable_addition_does_not_change_original_members(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / 'original.jar'
            original.write_bytes(b'original immutable package bytes')
            members = scheduler.input_package_members(root)
            (root / 'runtime.log').write_bytes(b'new runtime output')
            scheduler.verify_input_package_members(root, members)
            self.assertNotEqual(scheduler.runtime.canonical_digest(members), scheduler.runtime.tree_digest(root, False))
            original.write_bytes(b'substituted executable')
            with self.assertRaisesRegex(scheduler.runtime.RuntimeFailure, 'scheduler-input-package-member-changed'):
                scheduler.verify_input_package_members(root, members)

    def test_effective_inputs_change_recomputed_fingerprint(self):
        original = snapshot()
        expected = scheduler.derive_snapshot_fingerprints(original)
        for owner, key, value in [('jvmConfiguration', 'heapMaxBytes', 8192),
                                 ('jvmConfiguration', 'garbageCollectors', ['other']),
                                 ('jvmConfiguration', 'javaVersion', '26')]:
            changed = copy.deepcopy(original)
            changed[owner][key] = value
            self.assertNotEqual(expected['environmentDigest'],
                                scheduler.derive_snapshot_fingerprints(changed)['environmentDigest'])
        for key, value in [('memoryMax', 8192), ('cpuMax', {'quotaMicros': 50000, 'periodMicros': 100000})]:
            changed = copy.deepcopy(original)
            changed['environment']['container'][key] = value
            self.assertNotEqual(expected['environmentDigest'],
                                scheduler.derive_snapshot_fingerprints(changed)['environmentDigest'])
        changed = copy.deepcopy(original)
        changed['configuration']['pressureConfiguration']['maximumInFlight'] = 2
        self.assertNotEqual(expected['configurationDigest'],
                            scheduler.derive_snapshot_fingerprints(changed)['configurationDigest'])

    def test_snapshot_rejects_unknown_extra_and_unbounded_inputs(self):
        for mutate in [lambda value: value['environment']['container'].update(known=False),
                       lambda value: value['configuration'].update(arbitraryPolicy={}),
                       lambda value: value['jvmConfiguration'].update(commandLine='private'),
                       lambda value: value['environment'].update(javaVersion='x' * 65536)]:
            changed = snapshot()
            mutate(changed)
            with self.assertRaises(scheduler.runtime.RuntimeFailure):
                scheduler.derive_snapshot_fingerprints(changed)

    def test_private_snapshot_accessor_does_not_share_mutable_state(self):
        lane = object.__new__(scheduler.SchedulerLane)
        lane.runtime_input_snapshot = snapshot()
        selected = lane.input_snapshot()
        selected['environment']['container']['memoryMax'] = 1
        self.assertEqual(4096, lane.input_snapshot()['environment']['container']['memoryMax'])


if __name__ == '__main__':
    unittest.main()

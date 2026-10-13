"""Real local descriptor-reader tests; these are not installed acceptance observations."""
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'interop'))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'protected'))
import pr315_workload_evidence as evidence
import restricted_workload_launcher as launcher
import restricted_workload_network as network


class VolatileEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'authority').mkdir()
        self.state = self.root / 'state/candidate-sender'
        self.state.mkdir(parents=True)
        self.raw = b'0123456789abcdef0123456789abcdef'
        self.assertEqual(32, len(self.raw))
        self.expected = 'sha256:' + hashlib.sha256(self.raw).hexdigest()
        self.path = self.state / evidence.SENTINEL
        self.path.write_bytes(self.raw)
        (self.root / 'campaign.json').write_text(json.dumps({'state': 'prepared',
            'deadlineMonotonicNs': 123, 'handles': {'candidate-sender': 'must-not-copy'}}))
        for role in evidence.ROLES:
            (self.root / 'authority' / (role + '.json')).write_text(json.dumps({
                'state': 'quiescent', 'managerInvocation': 'a' * 32, 'cgroupIdentity': [1, 2],
                'handle': 'must-not-copy'}))

    def test_capture_matches_exact_subject_and_filters_authority(self):
        result = evidence._capture(self.root, self.expected, True)
        self.assertEqual('matched', result['sentinel']['status'])
        self.assertFalse(result['quiescenceIndependentlyEstablished'])
        self.assertEqual(6, len(result['controllerRecords']))
        self.assertNotIn('must-not-copy', json.dumps(result))
        self.assertLess(len(json.dumps(result)), evidence.MAX_OUTPUT)

    def test_role_epoch_digest_binds_controller_identity_without_retaining_handle(self):
        epoch = {'handle': 'a' * 64, 'generation': 'b' * 64,
                 'managerInvocation': 'c' * 32,
                 'bootId': '01234567-89ab-cdef-0123-456789abcdef'}
        value = {**epoch, 'state': 'quiescent', 'cgroupIdentity': [1, 2]}

        with patch.object(evidence.snapshot, 'read_file',
                          return_value=json.dumps(value).encode()):
            result = evidence._record(
                Path('/fixed'), 'candidate-sender.json', evidence.ROLE_FIELDS,
                float('inf'), role_epoch=True)

        expected = 'sha256:' + hashlib.sha256(json.dumps(
            epoch, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        record = result['record']
        self.assertEqual(expected, record['roleEpochDigest'])
        self.assertNotIn(epoch['handle'], json.dumps(result))

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux O_PATH reader required')
    def test_resolver_audit_preserves_only_active_root_target_and_denied_syscall(self):
        actor = {'hostPid': 123, 'hostParentPid': 100, 'pidNamespace': 'pid:[5]',
                 'networkNamespaceIdentity': [1, 2], 'mountNamespaceIdentity': [1, 3],
                 'userNamespaceIdentity': [1, 4], 'namespacePids': [123, 2],
                 'startTicks': 45, 'executableDigest': 'sha256:' + 'a' * 64,
                 'rssBytes': 1024, 'processThreads': 1,
                 'noNewPrivileges': True, 'effectiveCapabilities': 0}
        target = {'role': None, 'managerInvocation': 'c' * 32,
                  'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                  'cgroupIdentity': [1, 22], 'mainPid': 211,
                  'mainStartTicks': 30, 'canaryIdentity': [1, 23],
                  'observedMonotonicNs': 20, 'controlDigest': 'd' * 64}
        audit = {'schemaVersion': 1,
                 'kind': 'pr315-administrator-resolver-authority-denial',
                 'caseId': 'resolver-authority', 'sourceDigest': 'a' * 64,
                 'nonceDigest': 'b' * 64, 'actorUid': 1001,
                 'actorBefore': actor, 'actorAfter': dict(actor),
                 'actorInvocationBefore': 'e' * 32,
                 'actorInvocationAfter': 'e' * 32,
                 'actorCgroupBefore': [1, 10], 'actorCgroupAfter': [1, 10],
                 'actorStateBefore': 'f' * 64, 'actorStateAfter': 'f' * 64,
                 'targetBefore': target,
                 'targetAfter': dict(target, observedMonotonicNs=50),
                 'targetPathDigest': '1' * 64,
                 'attackStartedNs': 30, 'attackFinishedNs': 40,
                 'kernelOpenResult': {'opened': False, 'errno': 'ENOENT'}}
        path = self.root / 'authority/resolver-authority-denial.json'
        path.write_text(json.dumps(audit))
        self.assertEqual('captured', evidence._capture(
            self.root, self.expected, False)['resolverAuthorityAudit']['status'])
        self.assertEqual(audit, evidence._capture(
            self.root, self.expected, True)['resolverAuthorityAudit']['record'])
        for changed in (
                dict(audit, targetAfter=dict(audit['targetAfter'], mainStartTicks=31)),
                dict(audit, kernelOpenResult={'opened': True, 'errno': None}),
                dict(audit, privateToken='must-not-copy')):
            path.write_text(json.dumps(changed))
            retained = evidence._capture(self.root, self.expected, True)
            self.assertEqual('unavailable-or-unsafe',
                             retained['resolverAuthorityAudit']['status'])
            self.assertNotIn('must-not-copy', json.dumps(retained))

    def _output_symlink_audit(self):
        actor = {'hostPid': 123, 'hostParentPid': 100, 'pidNamespace': 'pid:[5]',
                 'networkNamespaceIdentity': [1, 2], 'mountNamespaceIdentity': [1, 3],
                 'userNamespaceIdentity': [1, 4], 'namespacePids': [123, 2],
                 'startTicks': 45, 'executableDigest': 'sha256:' + 'a' * 64,
                 'rssBytes': 1024, 'processThreads': 1,
                 'noNewPrivileges': True, 'effectiveCapabilities': 0}
        collector = {'pid': 211, 'uid': 0, 'gid': 0, 'startTicks': 30,
                     'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                     'namespacePids': [211],
                     'namespaces': {'pid': 11, 'net': 12, 'mnt': 13, 'user': 14},
                     'cgroupIdentity': [1, 20], 'cgroupDigest': 'b' * 64,
                     'invocationId': 'c' * 32, 'sourceDigest': 'd' * 64,
                     'observedMonotonicNs': 20}
        target = {'controlDigest': 'e' * 64, 'fileIdentity': [1, 21, 32, 100, 101],
                  'observedMonotonicNs': 10}
        audit = {'schemaVersion': 1,
                 'kind': 'pr315-administrator-output-symlink-denial',
                 'caseId': 'output-symlink', 'sourceDigest': 'a' * 64,
                 'nonceDigest': 'b' * 64, 'actorUid': 1001,
                 'actorBefore': actor, 'actorAfter': dict(actor),
                 'actorInvocationBefore': 'f' * 32,
                 'actorInvocationAfter': 'f' * 32,
                 'actorCgroupBefore': [1, 10], 'actorCgroupAfter': [1, 10],
                 'senderStateBefore': '1' * 64, 'senderStateAfter': '1' * 64,
                 'collectorBefore': collector,
                 'collectorAfter': dict(collector, observedMonotonicNs=80),
                 'collectorStartedNs': 55, 'collectorFinishedNs': 60,
                 'collectorDenial': 'workload-snapshot-file-invalid',
                 'targetBefore': target,
                 'targetAfter': dict(target, observedMonotonicNs=70),
                 'artifactIdentity': [1, 22], 'artifactOwnerUid': 1001,
                 'linkTargetDigest': '2' * 64,
                 'triggerMonotonicNs': 30,
                 'attackStartedNs': 40, 'attackFinishedNs': 50}
        return audit

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux O_PATH reader required')
    def test_output_symlink_audit_requires_real_collector_epoch_and_bounded_denial(self):
        audit = self._output_symlink_audit()
        target = audit['targetBefore']
        path = self.root / 'authority/output-symlink-denial.json'
        path.write_text(json.dumps(audit))
        self.assertEqual(audit, evidence._capture(
            self.root, self.expected, True)['outputSymlinkAudit']['record'])
        for changed in (
                dict(audit, collectorDenial='timeout'),
                dict(audit, collectorBefore=dict(audit['collectorBefore'], gid=1001)),
                dict(audit, collectorAfter=dict(audit['collectorAfter'], uid=False)),
                dict(audit, collectorBefore=dict(audit['collectorBefore'], namespacePids=[212])),
                dict(audit, collectorBefore=dict(audit['collectorBefore'], namespaces={'pid': 11})),
                dict(audit, collectorAfter=dict(audit['collectorAfter'],
                    namespaces=dict(audit['collectorAfter']['namespaces'], net=99))),
                dict(audit, collectorBefore={key:value for key,value in
                    audit['collectorBefore'].items()
                    if key not in ('gid', 'namespacePids', 'namespaces')}),
                dict(audit, targetAfter=dict(target, controlDigest='3' * 64,
                                              observedMonotonicNs=70)),
                dict(audit, privateToken='must-not-copy')):
            path.write_text(json.dumps(changed))
            retained = evidence._capture(self.root, self.expected, True)
            self.assertEqual('unavailable-or-unsafe',
                             retained['outputSymlinkAudit']['status'])
            self.assertNotIn('must-not-copy', json.dumps(retained))
        fifo = dict(audit, kind='pr315-administrator-output-fifo-denial',
                    caseId='output-fifo', artifactType='fifo', artifactMode=0o600)
        del fifo['linkTargetDigest']
        fifo_path = self.root / 'authority/output-fifo-denial.json'
        fifo_path.write_text(json.dumps(fifo))
        self.assertEqual(fifo, evidence._capture(
            self.root, self.expected, True)['outputFifoAudit']['record'])
        for changed in (dict(fifo, artifactMode=0o666),
                        dict(fifo, collectorDenial='timeout'),
                        dict(fifo, privateToken='must-not-copy')):
            fifo_path.write_text(json.dumps(changed))
            retained = evidence._capture(self.root, self.expected, True)
            self.assertEqual('unavailable-or-unsafe', retained['outputFifoAudit']['status'])
            self.assertNotIn('must-not-copy', json.dumps(retained))
        hardlink = dict(fifo, kind='pr315-administrator-output-hardlink-denial',
                        caseId='output-hardlink', artifactType='hardlink',
                        artifactLinkCount=2, artifactIdentity=target['fileIdentity'][:2],
                        targetBefore=dict(target, linkCount=1),
                        targetAfter=dict(target, observedMonotonicNs=70,
                            fileIdentity=[1, 21, 32, 100, 102], linkCount=2))
        hardlink_path = self.root / 'authority/output-hardlink-denial.json'
        hardlink_path.write_text(json.dumps(hardlink))
        self.assertEqual(hardlink, evidence._capture(
            self.root, self.expected, True)['outputHardlinkAudit']['record'])
        for changed in (dict(hardlink, artifactLinkCount=1),
                        dict(hardlink, targetAfter=dict(hardlink['targetAfter'], linkCount=1)),
                        dict(hardlink, artifactIdentity=[1, 22])):
            hardlink_path.write_text(json.dumps(changed))
            self.assertEqual('unavailable-or-unsafe', evidence._capture(
                self.root, self.expected, True)['outputHardlinkAudit']['status'])
        flood = dict(fifo, kind='pr315-administrator-output-flood-denial',
                     caseId='output-flood', artifactType='regular',
                     artifactSize=65537,
                     artifactDigest=hashlib.sha256(b'F' * 65537).hexdigest())
        flood_path = self.root / 'authority/output-flood-denial.json'
        flood_path.write_text(json.dumps(flood))
        self.assertEqual(flood, evidence._capture(
            self.root, self.expected, True)['outputFloodAudit']['record'])
        for changed in (dict(flood, artifactSize=65536),
                        dict(flood, artifactDigest='0' * 64),
                        dict(flood, artifactMode=0o666)):
            flood_path.write_text(json.dumps(changed))
            self.assertEqual('unavailable-or-unsafe', evidence._capture(
                self.root, self.expected, True)['outputFloodAudit']['status'])
        replacement = dict(fifo,
            kind='pr315-administrator-output-replacement-denial',
            caseId='output-replacement', artifactType='replacement',
            collectorDenial='workload-snapshot-changed',
            replacementIdentity=[1, 23],
            initialDigest=hashlib.sha256(b'A' * 32).hexdigest(),
            replacementDigest=hashlib.sha256(b'B' * 32).hexdigest(),
            swapTriggerNs=56, swapStartedNs=57, swapFinishedNs=58)
        replacement_path = self.root / 'authority/output-replacement-denial.json'
        replacement_path.write_text(json.dumps(replacement))
        self.assertEqual(replacement, evidence._capture(
            self.root, self.expected, True)['outputReplacementAudit']['record'])
        for changed in (dict(replacement, swapStartedNs=54),
                        dict(replacement, replacementIdentity=[1, 22]),
                        dict(replacement, replacementDigest='0' * 64)):
            replacement_path.write_text(json.dumps(changed))
            self.assertEqual('unavailable-or-unsafe', evidence._capture(
                self.root, self.expected, True)['outputReplacementAudit']['status'])

    @unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0,
                         'Native Linux root collector process required')
    def test_actual_administrator_collector_epoch_survives_output_descriptor_capture(self):
        import pr314_workload_driver as driver
        audit = self._output_symlink_audit()
        audit['targetBefore']['observedMonotonicNs'] = time.monotonic_ns()
        audit['collectorBefore'] = driver._administrator_collector_epoch('output-symlink')
        for key in ('triggerMonotonicNs', 'attackStartedNs', 'attackFinishedNs',
                    'collectorStartedNs', 'collectorFinishedNs'):
            audit[key] = time.monotonic_ns()
        audit['targetAfter']['observedMonotonicNs'] = time.monotonic_ns()
        audit['collectorAfter'] = driver._administrator_collector_epoch('output-symlink')
        self.assertEqual(os.getpid(), audit['collectorBefore']['pid'])
        self.assertEqual(os.getpid(), audit['collectorBefore']['namespacePids'][0])
        path = self.root / 'authority/output-symlink-denial.json'
        path.write_text(json.dumps(audit))
        retained = evidence._output_symlink_audit(self.root, time.monotonic()+5)
        self.assertEqual('captured', retained['status'])
        self.assertEqual(audit, retained['record'])
        self.assertEqual({'pid', 'net', 'mnt', 'user'},
                         set(retained['record']['collectorBefore']['namespaces']))
        changed = dict(audit, collectorAfter=dict(audit['collectorAfter'],
            namespaces=dict(audit['collectorAfter']['namespaces'], user=1)))
        path.write_text(json.dumps(changed))
        self.assertEqual('unavailable-or-unsafe', evidence._output_symlink_audit(
            self.root, time.monotonic()+5)['status'])

    def test_private_read_audit_keeps_only_fixed_root_process_evidence(self):
        actor = {'hostPid': 123, 'hostParentPid': 100, 'pidNamespace': 'pid:[5]',
                 'networkNamespaceIdentity': [1, 2], 'mountNamespaceIdentity': [1, 3],
                 'userNamespaceIdentity': [1, 4], 'namespacePids': [123, 2],
                 'startTicks': 45, 'executableDigest': 'sha256:' + 'a' * 64,
                 'rssBytes': 1024, 'processThreads': 1,
                 'noNewPrivileges': True, 'effectiveCapabilities': 0}
        audit = {'schemaVersion': 1, 'kind': 'pr315-administrator-observer-private-read',
                 'caseId': 'observer-private-read', 'sourceDigest': 'a' * 64,
                 'nonceDigest': 'b' * 64, 'actorUid': 1001,
                 'actorBefore': actor, 'actorAfter': actor,
                 'roleInvocationBefore': 'c' * 32, 'roleInvocationAfter': 'c' * 32,
                 'targetDigestBefore': 'd' * 64, 'targetDigestAfter': 'd' * 64,
                 'triggerMonotonicNs': 20, 'attackStartedNs': 30,
                 'attackFinishedNs': 40, 'controllerObservedBeforeNs': 10,
                 'controllerObservedAfterNs': 50,
                 'kernelOpenResult': {'opened': False, 'errno': 'ENOENT'}}
        path = self.root / 'authority/observer-private-read-denial.json'
        path.write_text(json.dumps(audit))
        result = evidence._capture(self.root, self.expected, True)
        self.assertEqual(audit, result['observerPrivateReadAudit']['record'])
        write = dict(audit, kind='pr315-administrator-observer-private-write',
                     caseId='observer-private-write', attackStartedNs=41,
                     attackFinishedNs=45)
        write_path = self.root / 'authority/observer-private-write-denial.json'
        write_path.write_text(json.dumps(write))
        result = evidence._capture(self.root, self.expected, True)
        self.assertEqual(write, result['observerPrivateWriteAudit']['record'])
        write_path.write_text(json.dumps(dict(write, caseId='observer-private-read')))
        result = evidence._capture(self.root, self.expected, True)
        self.assertEqual('unavailable-or-unsafe', result['observerPrivateWriteAudit']['status'])
        self.assertEqual('captured', result['observerPrivateReadAudit']['status'])
        audit['actorBefore'] = dict(actor, candidateSecret='must-not-copy')
        path.write_text(json.dumps(audit))
        result = evidence._capture(self.root, self.expected, True)
        self.assertEqual('unavailable-or-unsafe', result['observerPrivateReadAudit']['status'])
        self.assertNotIn('must-not-copy', json.dumps(result))

    def test_fixed_false_claim_audits_require_current_kernel_comparison(self):
        actor = {'hostPid': 123, 'hostParentPid': 100, 'pidNamespace': 'pid:[5]',
                 'networkNamespaceIdentity': [1, 2], 'mountNamespaceIdentity': [1, 3],
                 'userNamespaceIdentity': [1, 4], 'namespacePids': [123, 2],
                 'startTicks': 45, 'executableDigest': 'sha256:' + 'a' * 64,
                 'rssBytes': 1024, 'processThreads': 1,
                 'noNewPrivileges': True, 'effectiveCapabilities': 0}
        common = {'schemaVersion': 1, 'sourceDigest': 'a' * 64,
                  'nonceDigest': 'b' * 64, 'actorUid': 1001,
                  'actorBefore': actor, 'actorAfter': actor,
                  'roleInvocationBefore': 'c' * 32, 'roleInvocationAfter': 'c' * 32,
                  'cgroupIdentityBefore': [1, 99], 'cgroupIdentityAfter': [1, 99],
                  'targetActiveBeforeNs': 10, 'targetActiveAfterNs': 60,
                  'denial': 'kernel-mismatch-observed'}
        identity = {**common, 'kind': 'pr315-administrator-forged-runtime-identity',
                    'caseId': 'forged-runtime-identity', 'attackStartedNs': 46,
                    'attackFinishedNs': 47, 'claimedHostPid': 1, 'claimedHostUid': 0,
                    'actualHostPid': 123, 'actualHostUid': 1001}
        counters = {**common, 'kind': 'pr315-administrator-forged-counters',
                    'caseId': 'forged-counters', 'attackStartedNs': 48,
                    'attackFinishedNs': 49, 'claimedMemoryCurrentBytes': 0,
                    'claimedTasksCurrent': 0, 'actualMemoryBefore': 200,
                    'actualTasksBefore': 3, 'actualMemoryAfter': 210,
                    'actualTasksAfter': 3}
        (self.root / 'authority/forged-runtime-identity-denial.json').write_text(json.dumps(identity))
        counter_path = self.root / 'authority/forged-counters-denial.json'
        counter_path.write_text(json.dumps(counters))
        retained = evidence._capture(self.root, self.expected, True)
        self.assertEqual(identity, retained['forgedRuntimeIdentityAudit']['record'])
        self.assertEqual(counters, retained['forgedCountersAudit']['record'])
        counter_path.write_text(json.dumps(dict(counters, actualMemoryAfter=0)))
        retained = evidence._capture(self.root, self.expected, True)
        self.assertEqual('captured', retained['forgedRuntimeIdentityAudit']['status'])
        self.assertEqual('unavailable-or-unsafe', retained['forgedCountersAudit']['status'])

    def test_sibling_drop_audit_retains_fixed_kernel_witness_and_rejects_extra_fields(self):
        actor = {'hostPid': 123, 'hostParentPid': 100, 'pidNamespace': 'pid:[5]',
                 'networkNamespaceIdentity': [1, 2], 'mountNamespaceIdentity': [1, 3],
                 'userNamespaceIdentity': [1, 4], 'namespacePids': [123, 2],
                 'startTicks': 45, 'executableDigest': 'sha256:' + 'a' * 64,
                 'rssBytes': 1024, 'processThreads': 1,
                 'noNewPrivileges': True, 'effectiveCapabilities': 0}
        target = {'role': 'candidate-recipient', 'managerInvocation': 'c' * 32,
                  'bootId': 'boot', 'cgroupIdentity': [1, 100],
                  'observedMonotonicNs': 10, 'controlObservedNs': 11,
                  'controlDigest': 'd' * 64}
        counters = {'schemaVersion': 1, 'kind': 'pr315-fixed-sibling-drop-counters',
                    'policyDigest': 'e' * 64, 'bootId': 'boot',
                    'roleNamespaceIdentity': [1, 2], 'observedMonotonicNs': 12,
                    'counters': {'pr315_sibling_fcp_drop': {'packets': 0, 'bytes': 0},
                                 'pr315_sibling_http_drop': {'packets': 0, 'bytes': 0}}}
        audit = {'schemaVersion': 1,
                 'kind': 'pr315-administrator-sibling-network-denial',
                 'caseId': 'sibling-fcp', 'sourceDigest': 'a' * 64,
                 'nonceDigest': 'b' * 64, 'actorUid': 986,
                 'actorBefore': actor, 'actorAfter': actor,
                 'senderInvocationBefore': 'f' * 32,
                 'senderInvocationAfter': 'f' * 32,
                 'senderCgroupBefore': [1, 99], 'senderCgroupAfter': [1, 99],
                 'senderStateBefore': 'a' * 64, 'senderStateAfter': 'a' * 64,
                 'targetBefore': target,
                 'targetAfter': dict(target, observedMonotonicNs=20,
                                     controlObservedNs=21),
                 'counterBefore': counters,
                 'counterAfter': dict(counters, observedMonotonicNs=19),
                 'triggerMonotonicNs': 13, 'attackStartedNs': 14,
                 'attackFinishedNs': 15,
                 'targetEndpointDigest': '0' * 64,
                 'kernelConnectResult': {'connected': False, 'errno': 'ETIMEDOUT'},
                 'counterName': 'pr315_sibling_fcp_drop'}
        path = self.root / 'authority/sibling-fcp-denial.json'
        path.write_text(json.dumps(audit))
        retained = evidence._capture(self.root, self.expected, True)
        self.assertEqual(audit, retained['siblingFcpAudit']['record'])
        self.assertLess(len(json.dumps(retained).encode()), evidence.MAX_OUTPUT)
        path.write_text(json.dumps(dict(audit, browserToken='must-not-copy')))
        rejected = evidence._capture(self.root, self.expected, True)
        self.assertEqual('unavailable-or-unsafe', rejected['siblingFcpAudit']['status'])
        self.assertNotIn('must-not-copy', json.dumps(rejected))

    def test_fixed_role_access_audits_reject_replaced_targets(self):
        actor = {'hostPid': 123, 'hostParentPid': 100, 'pidNamespace': 'pid:[5]',
                 'networkNamespaceIdentity': [1, 2], 'mountNamespaceIdentity': [1, 3],
                 'userNamespaceIdentity': [1, 4], 'namespacePids': [123, 2],
                 'startTicks': 45, 'executableDigest': 'sha256:' + 'a' * 64,
                 'rssBytes': 1024, 'processThreads': 1,
                 'noNewPrivileges': True, 'effectiveCapabilities': 0}
        common = {'schemaVersion': 1,
                  'kind': 'pr315-administrator-fixed-role-access-denial',
                  'sourceDigest': 'a' * 64, 'nonceDigest': 'b' * 64,
                  'actorUid': 1001, 'actorBefore': actor, 'actorAfter': actor,
                  'actorInvocationBefore': 'c' * 32,
                  'actorInvocationAfter': 'c' * 32,
                  'actorCgroupBefore': [1, 99], 'actorCgroupAfter': [1, 99]}
        for case_id, role, errno_code, start in (
                ('sibling-data', 'candidate-recipient', 'ENOENT', 60),
                ('package-expectation', 'candidate-sender', 'EACCES', 71),
                ('cgroup-migration', 'candidate-recipient', 'ENOENT', 81)):
            with self.subTest(case_id=case_id):
                target = {'role': role, 'managerInvocation': 'd' * 32,
                          'cgroupIdentity': [1, 100], 'observedMonotonicNs': 40,
                          'controlDigest': 'e' * 64}
                audit = {**common, 'caseId': case_id,
                         'targetBefore': target,
                         'targetAfter': dict(target, observedMonotonicNs=100),
                         'attackStartedNs': start, 'attackFinishedNs': start + 1,
                         'kernelOpenResult': {'opened': False, 'errno': errno_code},
                         'writtenBytes': 0}
                path = self.root / 'authority' / (case_id + '-denial.json')
                path.write_text(json.dumps(audit))
                retained = evidence._capture(self.root, self.expected, True)
                field = {'sibling-data': 'siblingDataAudit',
                         'package-expectation': 'packageExpectationAudit',
                         'cgroup-migration': 'cgroupMigrationAudit'}[case_id]
                self.assertEqual(audit, retained[field]['record'])
                changed = dict(audit, targetAfter=dict(target,
                    observedMonotonicNs=100, controlDigest='f' * 64))
                path.write_text(json.dumps(changed))
                retained = evidence._capture(self.root, self.expected, True)
                self.assertEqual('unavailable-or-unsafe', retained[field]['status'])
                path.unlink()

    def test_fixed_exchange_audits_are_private_bounded_projections_after_cleanup(self):
        import pr315_workload_runner as runner
        self.assertEqual(set(evidence.EXCHANGE_FIELDS), runner.EXCHANGE_AUDIT_FIELDS)
        for case, method in (('own-management', 'connect-fcp'),
                             ('dynamic-app-bootstrap', 'bootstrap-mail')):
            (self.root / 'authority' / (case + '-exchange.json')).write_text(json.dumps({
                'schemaVersion': 1, 'kind': 'pr315-fixed-exchange-audit',
                'caseId': case, 'method': method, 'role': 'candidate-sender',
                'managerInvocation': 'a' * 32, 'bootId': 'boot',
                'cgroupIdentity': [1, 2], 'requestDigest': 'b' * 64,
                'responseDigest': 'c' * 64, 'startedMonotonicNs': 1,
                'finishedMonotonicNs': 2, 'serverRequests': 1,
                'browserSessionToken': 'must-not-copy'}))
        pending = evidence._capture(self.root, self.expected, False)
        self.assertEqual({'not-captured-cleanup-unverified'},
                         {row['status'] for row in pending['exchangeAudits'].values()})
        result = evidence._capture(self.root, self.expected, True)
        self.assertEqual({'captured'}, {row['status'] for row in result['exchangeAudits'].values()})
        self.assertNotIn('must-not-copy', json.dumps(result))
        self.assertEqual('b' * 64, result['exchangeAudits']['own-management']['record']['requestDigest'])

    def test_fnp_counter_pair_requires_same_fixed_policy_and_six_links(self):
        self.assertEqual(set(network.FNP_COUNTERS.values()), evidence.FNP_COUNTER_NAMES)
        def sample(moment):
            return {'schemaVersion': 1, 'kind': 'pr315-fixed-fnp-counters',
                    'policyDigest': 'a' * 64, 'bootId': 'boot',
                    'switchNamespaceIdentity': [1, 42], 'observedMonotonicNs': moment,
                    'counters': {name: {'packets': 2, 'bytes': 200}
                                 for name in evidence.FNP_COUNTER_NAMES}}
        pair = {'schemaVersion': 1, 'kind': 'pr315-administrator-fnp-counter-pair',
                'caseId': 'fnp-content-retrieval', 'role': 'candidate-recipient',
                'managerInvocation': 'b' * 32, 'before': sample(10), 'after': sample(20)}
        path = self.root / 'authority/fnp-content-probe.json'
        path.write_text(json.dumps(pair))
        self.assertEqual('not-captured-cleanup-unverified',
                         evidence._capture(self.root, self.expected, False)['fnpCounterPair']['status'])
        self.assertEqual('captured', evidence._capture(self.root, self.expected, True)[
            'fnpCounterPair']['status'])
        path.write_text(json.dumps(dict(pair, kind='pr315-fnp-counter-pair')))
        self.assertEqual('unavailable-or-unsafe', evidence._capture(self.root, self.expected, True)[
            'fnpCounterPair']['status'])
        path.write_text(json.dumps(pair))
        pair['after']['switchNamespaceIdentity'] = [1, 43]
        path.write_text(json.dumps(pair))
        self.assertEqual('unavailable-or-unsafe', evidence._capture(self.root, self.expected, True)[
            'fnpCounterPair']['status'])

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux O_PATH reader required')
    def test_signed_probe_result_is_bounded_candidate_origin_only(self):
        directory = self.root / 'state/candidate-sender/data/node/apps/data/pr315-probe'
        directory.mkdir(parents=True)
        path = directory / 'pr315-probe-result.json'
        record = {'schemaVersion': 1, 'kind': 'pr315-signed-apphost-probe',
                  'pid': 123, 'uid': 1001, 'gid': 1001, 'startedMonotonicNs': 10,
                  'namespaceInodes': {'mnt': 11, 'pid': 12, 'net': 13, 'user': 14},
                  'mountEscape': {'operation': 'unshare-mount', 'startedMonotonicNs': 20,
                                  'finishedMonotonicNs': 21, 'returnCode': -1, 'errno': 'EPERM'}}
        path.write_text(json.dumps(record))
        self.assertEqual('not-captured-cleanup-unverified', evidence._capture(
            self.root, self.expected, False)['probeAppResult']['status'])
        captured = evidence._capture(self.root, self.expected, True)['probeAppResult']
        self.assertEqual('signed-app-candidate-origin-not-acceptance', captured['classification'])
        self.assertEqual(record, captured['record'])
        (directory / 'pr315-probe-result-first.json').write_text(json.dumps(record))
        second = dict(record, pid=124, startedMonotonicNs=30)
        (directory / 'pr315-probe-result-second.json').write_text(json.dumps(second))
        captured = evidence._capture(self.root, self.expected, True)
        self.assertEqual(record, captured['probeAppFirstResult']['record'])
        self.assertEqual(second, captured['probeAppSecondResult']['record'])
        with self.assertRaisesRegex(ValueError, 'selection-invalid'):
            evidence._probe_app_result(self.root, float('inf'), '../arbitrary')
        path.write_text(json.dumps(dict(record, privateToken='must-not-copy')))
        rejected = evidence._capture(self.root, self.expected, True)
        self.assertEqual('unavailable-or-unsafe', rejected['probeAppResult']['status'])
        self.assertNotIn('must-not-copy', json.dumps(rejected))

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux O_PATH reader required')
    def test_probe_process_log_is_private_bounded_and_requires_cleanup(self):
        directory = self.root / 'state/candidate-sender/run/node/apps/pr315-probe'
        directory.mkdir(parents=True)
        path = directory / 'process.log'
        raw = b'private-probe-log\n' * 300
        path.write_bytes(raw)
        self.assertEqual('not-captured-cleanup-unverified', evidence._capture(
            self.root, self.expected, False)['probeAppLog']['status'])
        captured = evidence._capture(self.root, self.expected, True)['probeAppLog']
        self.assertEqual('apphost-process-private-diagnostic-not-acceptance',
                         captured['classification'])
        self.assertEqual(raw[-2048:], base64.b64decode(captured['tailBase64']))
        self.assertEqual(2048, captured['tailBytes'])
        path.unlink()
        path.symlink_to(self.path)
        self.assertEqual('unavailable-or-unsafe', evidence._capture(
            self.root, self.expected, True)['probeAppLog']['status'])

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux O_PATH reader required')
    def test_probe_kernel_checkpoint_survives_later_observer_failure_without_extra_fields(self):
        observer = self.observer()
        path = observer / 'pr315-probe-kernel.private.json'
        record = {'schemaVersion': 1, 'kind': 'pr315-observer-probe-kernel-checkpoint',
                  'appId': 'pr315-probe', 'bundleDigest': 'sha256:' + 'a' * 64,
                  'roleKernelRoster': {}, 'roleKernelRosterWindow': {},
                  'senderStateBefore': 'b' * 64, 'probeWorker': {},
                  'administratorRecordDigest': 'c' * 64}
        path.write_text(json.dumps(record))
        self.assertEqual('not-captured-cleanup-unverified', evidence._capture(
            self.root, self.expected, False, observer_root=observer)['probeKernelCheckpoint']['status'])
        captured = evidence._capture(self.root, self.expected, True,
                                     observer_root=observer)['probeKernelCheckpoint']
        self.assertEqual('observer-origin-private-checkpoint-not-acceptance',
                         captured['classification'])
        self.assertEqual(record, captured['record'])
        path.write_text(json.dumps(dict(record, privateToken='must-not-copy')))
        rejected = evidence._capture(self.root, self.expected, True, observer_root=observer)
        self.assertEqual('unavailable-or-unsafe', rejected['probeKernelCheckpoint']['status'])
        self.assertNotIn('must-not-copy', json.dumps(rejected))

    def test_observer_control_denial_copies_only_fixed_root_and_observer_fields(self):
        observer = self.observer()
        checkpoint = {'schemaVersion': 1,
                      'kind': 'pr315-observer-control-denial-checkpoint',
                      'caseId': 'observer-control', 'actorPid': 123,
                      'actorStartTicks': 456, 'roleKernelRoster': {},
                      'roleKernelRosterWindow': {}, 'senderStateBefore': 'a' * 64,
                      'requestDigest': 'b' * 64, 'responseDigest': 'c' * 64}
        target = {'invocationId': 'd' * 32, 'cgroupIdentity': [1, 2],
                  'bootId': 'boot', 'observedMonotonicNs': 10}
        audit = {'schemaVersion': 1,
                 'kind': 'pr315-administrator-observer-control-denial',
                 'caseId': 'observer-control',
                 'actor': {'pid': 123, 'uid': 987, 'startTicks': 456},
                 'targetBefore': target, 'targetAfter': dict(target, observedMonotonicNs=20),
                 'senderManagerInvocation': 'e' * 32, 'senderCgroupIdentity': [1, 3],
                 'senderStateBefore': 'a' * 64, 'senderStateAfter': 'a' * 64,
                 'requestObservedNs': 12, 'responseSentNs': 13,
                 'requestDigest': 'b' * 64, 'responseDigest': 'c' * 64}
        (observer / 'pr315-observer-control.private.json').write_text(json.dumps(checkpoint))
        path = self.root / 'authority/observer-control-denial.json'
        path.write_text(json.dumps(audit))
        captured = evidence._capture(self.root, self.expected, True, observer_root=observer)
        self.assertEqual(checkpoint, captured['observerControlCheckpoint']['record'])
        self.assertEqual(audit, captured['observerControlAudit']['record'])
        path.write_text(json.dumps(dict(audit, browserToken='must-not-copy')))
        rejected = evidence._capture(self.root, self.expected, True, observer_root=observer)
        self.assertEqual('unavailable-or-unsafe', rejected['observerControlAudit']['status'])
        self.assertNotIn('must-not-copy', json.dumps(rejected))

    def test_arbitrary_endpoint_retains_only_fixed_observer_and_root_controls(self):
        observer = self.observer()
        checkpoint = {'schemaVersion': 1,
                      'kind': 'pr315-arbitrary-endpoint-denial-checkpoint',
                      'caseId': 'arbitrary-endpoint', 'actorPid': 123,
                      'actorStartTicks': 456, 'roleKernelRoster': {},
                      'roleKernelRosterWindow': {},
                      'requestDigest': 'b' * 64, 'responseDigest': 'c' * 64}
        controller = {'invocationId': 'd' * 32, 'cgroupIdentity': [1, 2],
                      'bootId': 'boot', 'observedMonotonicNs': 10}
        role = {'managerInvocation': 'e' * 32, 'cgroupIdentity': [1, 3],
                'bootId': 'boot', 'stateDigest': 'a' * 64,
                'observedMonotonicNs': 11}
        audit = {'schemaVersion': 1,
                 'kind': 'pr315-administrator-arbitrary-endpoint-denial',
                 'caseId': 'arbitrary-endpoint',
                 'actor': {'pid': 123, 'uid': 987, 'startTicks': 456},
                 'targetBefore': controller,
                 'targetAfter': dict(controller, observedMonotonicNs=30),
                 'senderBefore': role, 'senderAfter': dict(role, observedMonotonicNs=29),
                 'recipientBefore': role, 'recipientAfter': dict(role, observedMonotonicNs=25),
                 'recipientControlBeforeNs': 14, 'recipientControlAfterNs': 27,
                 'recipientControlBeforeDigest': 'f' * 64,
                 'recipientControlAfterDigest': 'f' * 64,
                 'endpointSelection': 'sibling-fcp',
                 'denial': 'restricted-workload-network-rejected',
                 'requestObservedNs': 12, 'attackStartedNs': 16,
                 'attackFinishedNs': 17, 'responseSentNs': 18,
                 'requestDigest': 'b' * 64, 'responseDigest': 'c' * 64}
        (observer / 'pr315-arbitrary-endpoint.private.json').write_text(json.dumps(checkpoint))
        path = self.root / 'authority/arbitrary-endpoint-denial.json'
        path.write_text(json.dumps(audit))
        retained = evidence._capture(self.root, self.expected, True, observer_root=observer)
        self.assertEqual(checkpoint, retained['arbitraryEndpointCheckpoint']['record'])
        self.assertEqual(audit, retained['arbitraryEndpointAudit']['record'])
        path.write_text(json.dumps(dict(audit, browserToken='must-not-copy')))
        rejected = evidence._capture(self.root, self.expected, True, observer_root=observer)
        self.assertEqual('unavailable-or-unsafe', rejected['arbitraryEndpointAudit']['status'])
        self.assertNotIn('must-not-copy', json.dumps(rejected))

    def test_runner_control_denial_requires_bounded_real_policy_response(self):
        response = b'Failed to stop fixed unit: Interactive authentication required.\n'
        target = {'invocationId': 'd' * 32, 'cgroupIdentity': [1, 2],
                  'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                  'mainPid': 100, 'mainStartTicks': 200, 'uid': 0, 'gid': 0,
                  'namespacePids': [100],
                  'namespaces': {'pid': 11, 'net': 12, 'mnt': 13, 'user': 14},
                  'pidfdObserved': True,
                  'observedMonotonicNs': 10}
        audit = {'schemaVersion': 1, 'kind': 'pr315-administrator-runner-control-denial',
                 'caseId': 'runner-control',
                 'actor': {'pid': 123, 'uid': 1000, 'startTicks': 456},
                 'roleKernelRoster': {}, 'roleKernelRosterWindow': {},
                 'targetBefore': target, 'targetAfter': dict(target, observedMonotonicNs=20),
                 'senderManagerInvocation': 'e' * 32, 'senderCgroupIdentity': [1, 3],
                 'senderStateBefore': 'a' * 64, 'senderStateAfter': 'a' * 64,
                 'requestStartedNs': 12, 'responseObservedNs': 13,
                 'requestDigest': 'b' * 64, 'responseDigest': hashlib.sha256(response).hexdigest(),
                 'responseBase64': base64.b64encode(response).decode(),
                 'exitCode': 1, 'stdoutBytes': 0}
        path = self.root / 'authority/runner-control-denial.json'
        path.write_text(json.dumps(audit))
        self.assertEqual('not-captured-cleanup-unverified', evidence._capture(
            self.root, self.expected, False)['runnerControlAudit']['status'])
        self.assertEqual(audit, evidence._capture(
            self.root, self.expected, True)['runnerControlAudit']['record'])
        for changed in (dict(audit, exitCode=0),
                        dict(audit, targetBefore=dict(target, uid=1000)),
                        dict(audit, targetAfter=dict(audit['targetAfter'], gid=1000)),
                        dict(audit, targetBefore=dict(target, pidfdObserved=False)),
                        dict(audit, targetBefore=dict(target, namespacePids=[101])),
                        dict(audit, targetBefore=dict(target, namespaces={'pid': 11})),
                        dict(audit, targetAfter=dict(audit['targetAfter'],
                            namespaces=dict(target['namespaces'], net=99))),
                        dict(audit, targetBefore={k:v for k,v in target.items()
                            if k not in ('uid','gid','namespacePids','namespaces','pidfdObserved')}),
                        dict(audit, responseBase64='@@@'),
                        dict(audit, browserToken='must-not-copy')):
            path.write_text(json.dumps(changed))
            rejected = evidence._capture(self.root, self.expected, True)
            self.assertEqual('unavailable-or-unsafe', rejected['runnerControlAudit']['status'])
            self.assertNotIn('must-not-copy', json.dumps(rejected))

    def test_partial_preparation_captures_authority_without_inventing_a_sentinel(self):
        self.path.unlink()
        (self.root / 'authority/network.json').write_text(json.dumps({
            'version': 1, 'phase': 'retained', 'pending': None,
            'namespaces': {'private-topology-not-exported': [1, 2]}}))
        result = evidence._capture(self.root, None, True)
        self.assertEqual({'status': 'not-prepared'}, result['sentinel'])
        self.assertEqual('captured', result['controllerRecords']['campaign']['status'])
        self.assertEqual({'version': 1, 'phase': 'retained', 'pending': None},
                         result['controllerRecords']['network']['record'])
        self.assertFalse(result['quiescenceIndependentlyEstablished'])
        self.assertGreaterEqual(result['finishedMonotonicNs'], result['startedMonotonicNs'])
        self.assertNotIn('private-topology-not-exported', json.dumps(result))

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux O_PATH reader required')
    def test_failed_cleanup_retains_only_root_authority_and_partial_stop_receipts(self):
        (self.root / 'authority/candidate-sender-stop.json').write_text(json.dumps({
            'role': 'candidate-sender', 'managerInvocation': 'a' * 32,
            'membership': 'only-stop-helper', 'privateHandle': 'must-not-copy'}))
        result = evidence._capture(self.root, self.expected, False)
        self.assertFalse(result['cleanupReportedByCaller'])
        self.assertFalse(result['quiescenceIndependentlyEstablished'])
        self.assertEqual('captured', result['controllerRecords']['campaign']['status'])
        self.assertEqual('captured', result['controllerRecords']['candidate-sender']['status'])
        self.assertEqual('captured', result['stopReceipts']['candidate-sender']['current']['status'])
        self.assertEqual('not-captured-cleanup-unverified', result['sentinel']['status'])
        self.assertEqual('not-captured-cleanup-unverified', result['fnpCounterPair']['status'])
        self.assertEqual('not-captured-cleanup-unverified', result['fatalLogs']['candidate-sender']['status'])
        self.assertNotIn('must-not-copy', json.dumps(result))

    def test_stop_receipts_preserve_current_and_previous_epoch_with_fixed_projection(self):
        role = 'candidate-sender'
        authority = self.root / 'authority'
        record = json.loads((authority / (role + '.json')).read_text())
        record['previousStopGeneration'] = 'b' * 64
        (authority / (role + '.json')).write_text(json.dumps(record))
        for suffix, generation in (('-stop.json', 'c' * 64), ('-stop-' + 'b' * 64 + '.json', 'b' * 64)):
            (authority / (role + suffix)).write_text(json.dumps({
                'generation': generation, 'membership': 'only-stop-helper', 'helperPid': 123,
                'privateExtra': 'must-not-copy'}))
        result = evidence._capture(self.root, self.expected, True)
        receipts = result['stopReceipts'][role]
        self.assertEqual('c' * 64, receipts['current']['record']['generation'])
        self.assertEqual('b' * 64, receipts['previous']['record']['generation'])
        self.assertNotIn('must-not-copy', json.dumps(result))
        self.assertFalse(result['quiescenceIndependentlyEstablished'])
        record['previousStopGeneration'] = '../../arbitrary'
        (authority / (role + '.json')).write_text(json.dumps(record))
        self.assertNotIn('previous', evidence._capture(self.root, self.expected, True)['stopReceipts'][role])

    def test_nonliteral_cleanup_reads_only_root_authority(self):
        original = evidence.snapshot.read_file
        def root_only(parent, name, **options):
            self.assertIn(parent, (self.root, self.root / 'authority'))
            return original(parent, name, **options)
        with patch.object(evidence.snapshot, 'read_file', side_effect=root_only):
            for cleanup in (False, None, 1, 'true'):
                result = evidence._capture(self.root, self.expected, cleanup)
                self.assertEqual('not-captured-cleanup-unverified', result['sentinel']['status'])
                self.assertTrue(all(row == {'status': 'not-captured-cleanup-unverified'}
                                    for row in result['wrapperLogs'].values()))

    def test_fatal_sections_stop_at_nonhex_and_exclude_adjacent_private_sections(self):
        raw = (b'Instructions: (pc=0x123)\n0x123: 0f 0b 90\n'
               b'Registers: secret-registers\n0x456: 11 22\n'
               b'CPU: total 4 avx sse2\nCPU Features: avx2\n'
               b'Environment Variables: SECRET=value\n')
        result = evidence._fatal_sections(raw, float('inf'))
        self.assertEqual(b'Instructions: (pc=0x123)\n0x123: 0f 0b 90\n',
                         base64.b64decode(result['instructions']['contentBase64']))
        self.assertEqual(b'CPU: total 4 avx sse2\nCPU Features: avx2\n',
                         base64.b64decode(result['cpu']['contentBase64']))
        self.assertFalse(any(row['truncated'] for row in result.values()))

    def test_fatal_sections_have_independent_caps_and_explicit_missing(self):
        raw = b'Instructions:\n' + b'0x123: 90 90\n' * 300 + b'CPU: ' + b'x' * 2000 + b'\n'
        result = evidence._fatal_sections(raw, float('inf'))
        for name, limit in (('instructions', 2048), ('cpu', 1024)):
            self.assertEqual(limit, result[name]['sizeBytes'])
            self.assertTrue(result[name]['truncated'])
        missing = evidence._fatal_sections(b'Environment Variables: secret\n', float('inf'))
        self.assertTrue(all(row['status'] == 'not-found' and row['sizeBytes'] == 0
                            for row in missing.values()))

    def test_jdk25_highlighted_hex_rows_normalize_without_ascii_column(self):
        # os.cpp print_hex_dump uses two-space/=> row prefixes and an optional
        # three-space ASCII delimiter. print_instructions supplies a numeric PC.
        raw = (b'Instructions: (pc=0x000000000000AB10)\r\n'
               b'  0x000000000000ab00:   0F 0B 90 00   PRIVATE-ascii\r\n'
               b'=>0x000000000000ab10:   48 8B 00 FF\n'
               b'  0x000000000000ab20:   01 02   de ad be ef\n'
               b'\nRegisters: private\n0x111: 11 22\n')
        row = evidence._fatal_sections(raw, float('inf'))['instructions']
        self.assertEqual('captured', row['status'])
        self.assertEqual((b'Instructions: (pc=0x000000000000ab10)\n'
                          b'0x000000000000ab00: 0f 0b 90 00\n'
                          b'0x000000000000ab10: 48 8b 00 ff\n'
                          b'0x000000000000ab20: 01 02\n'),
                         base64.b64decode(row['contentBase64']))

    def test_instruction_heading_without_valid_bytes_is_not_captured(self):
        for raw in (b'Instructions:\n', b'Instructions: (pc=0x123)\n\n',
                    b'Instructions: private-heading\n0x123: 01 02\n',
                    b'Instructions: (pc=0x123 SECRET)\n0x123: 01 02\n',
                    b'Instructions:\n=>0x123:   ?? ??\n',
                    b'Instructions:\n=>0x123:   01 INVALID\n',
                    b'Instructions:\n0x123: ' + b'01 ' * 65 + b'\n'):
            with self.subTest(raw=raw[:80]):
                row = evidence._fatal_sections(raw, float('inf'))['instructions']
                self.assertEqual('not-found', row['status'])
                self.assertEqual(0, row['sizeBytes'])
                self.assertEqual('', row['contentBase64'])

    def test_malformed_instruction_row_ends_section_without_adjacent_byte_capture(self):
        for invalid in (b' =>0x124: 01 02\n', b'=>0x124: 0x01 02\n',
                        b'=>0x124: 01 SECRET\n', b'Registers:\n'):
            with self.subTest(invalid=invalid):
                raw = b'Instructions:\n=>0x123:   0f 0b\n' + invalid + b'0x125: aa bb\n'
                row = evidence._fatal_sections(raw, float('inf'))['instructions']
                self.assertEqual(b'Instructions:\n0x123: 0f 0b\n', base64.b64decode(row['contentBase64']))

    def test_fatal_snapshot_selects_sections_beyond_retained_header(self):
        directory = self.fatal_directory()
        raw = b'H' * 5000 + b'\nInstructions: (pc=0x123)\n0x123: 0f 0b\n\nCPU: synthetic\n'
        (directory / 'hs_err_pid1.log').write_bytes(raw)
        result = evidence._capture(self.root, self.expected, True)
        row = result['fatalLogs']['candidate-sender']['files'][0]
        self.assertEqual(b'H' * 4096, base64.b64decode(row['headBase64']))
        self.assertIn(b'0f 0b', base64.b64decode(row['sections']['instructions']['contentBase64']))
        self.assertLessEqual(len(json.dumps(result, sort_keys=True, allow_nan=False).encode()),
                             evidence.MAX_OUTPUT)

    def test_fatal_sections_deadline_does_not_select_later_bytes(self):
        with patch.object(evidence.time, 'monotonic', return_value=2):
            result = evidence._fatal_sections(b'CPU: hidden\n', 1)
        self.assertTrue(all(row['status'] == 'capture-deadline' and row['sizeBytes'] == 0
                            for row in result.values()))

    def fatal_directory(self):
        directory = self.state / 'tmp'
        directory.mkdir(exist_ok=True)
        return directory

    def test_fatal_selection_is_fixed_bounded_and_retains_header(self):
        directory = self.fatal_directory()
        for name in ('hs_err_pid3.log', 'hs_err_pid1.log', 'hs_err_pid2.log'):
            (directory / name).write_bytes(b'H' * 5000 + b'TAIL')
        (directory / 'credentials').write_bytes(b'must-not-read')
        result = evidence._capture(self.root, self.expected, True)
        logs = result['fatalLogs']['candidate-sender']
        self.assertEqual('too-many-matching-files', logs['status'])
        self.assertEqual(3, logs['matchedFiles'])
        self.assertEqual(['hs_err_pid1.log', 'hs_err_pid2.log'],
                         [row['name'] for row in logs['files']])
        self.assertFalse(logs['locationProven'])
        for row in logs['files']:
            self.assertEqual(b'H' * 4096, base64.b64decode(row['headBase64']))
            self.assertEqual(5004, row['sizeBytes'])
            self.assertTrue(row['truncated'])
        self.assertNotIn('must-not-read', json.dumps(result))

    def test_fatal_empty_and_flooded_directory_are_distinct(self):
        directory = self.fatal_directory()
        self.assertEqual('none', evidence._fatal_logs(self.root, 'candidate-sender', float('inf'))['status'])
        for number in range(65):
            (directory / str(number)).touch()
        with patch.object(evidence.snapshot, 'read_file', side_effect=AssertionError('no reads')):
            self.assertEqual('too-many-directory-entries',
                evidence._fatal_logs(self.root, 'candidate-sender', float('inf'))['status'])

    def test_fatal_special_files_and_oversize_are_rejected(self):
        directory = self.fatal_directory()
        path = directory / 'hs_err_pid1.log'
        for kind in ('symlink', 'fifo', 'hardlink', 'oversize'):
            with self.subTest(kind=kind):
                if kind == 'symlink':
                    path.symlink_to(self.path)
                elif kind == 'fifo':
                    os.mkfifo(path)
                elif kind == 'hardlink':
                    os.link(self.path, path)
                else:
                    with path.open('wb') as stream:
                        stream.truncate(evidence.MAX_WRAPPER_LOG + 1)
                row = evidence._fatal_logs(self.root, 'candidate-sender', float('inf'))['files'][0]
                self.assertEqual('unavailable-or-unsafe', row['status'])
                path.unlink()
        directory.rmdir()
        directory.symlink_to(self.root, target_is_directory=True)
        self.assertEqual('unavailable-or-unsafe',
            evidence._fatal_logs(self.root, 'candidate-sender', float('inf'))['status'])

    def test_fatal_reader_uses_remaining_deadline_and_rejects_directory_replacement(self):
        directory = self.fatal_directory()
        (directory / 'hs_err_pid1.log').write_bytes(b'header')
        with patch.object(evidence.time, 'monotonic', return_value=9.75), \
                patch.object(evidence.snapshot, 'read_file', return_value=b'header') as reader:
            result = evidence._fatal_logs(self.root, 'candidate-sender', 10)
        self.assertEqual('captured', result['files'][0]['status'])
        self.assertEqual(.25, reader.call_args.kwargs['timeout'])
        self.assertEqual(2 * 1024 * 1024, reader.call_args.kwargs['maximum'])
        original = evidence.snapshot.read_file
        def replace(*args, **kwargs):
            raw = original(*args, **kwargs)
            directory.rename(self.state / 'replaced-tmp')
            directory.mkdir()
            return raw
        with patch.object(evidence.snapshot, 'read_file', side_effect=replace):
            result = evidence._fatal_logs(self.root, 'candidate-sender', float('inf'))
        self.assertEqual({'status': 'unavailable-or-unsafe'}, result)

    def test_fatal_deadline_and_output_budget_preserve_higher_priority_records(self):
        output_budget = self.capture_output_budget()
        directory = self.fatal_directory()
        (directory / 'hs_err_pid1.log').write_bytes(b'H' * 4096)
        with patch.object(evidence.snapshot, 'read_file', side_effect=AssertionError('no reads')):
            self.assertEqual('capture-deadline',
                evidence._fatal_logs(self.root, 'candidate-sender', 0)['status'])
        with patch.object(evidence, 'MAX_OUTPUT', output_budget):
            result = evidence._capture(self.root, self.expected, True)
        self.assertEqual('not-captured-output-budget', result['fatalLogs']['candidate-sender']['status'])
        self.assertEqual('matched', result['sentinel']['status'])
        self.assertLess(len(json.dumps(result, sort_keys=True, allow_nan=False).encode()),
                        output_budget)
        with patch.object(evidence, '_fatal_logs', side_effect=AssertionError('no fatal enumeration')):
            result = evidence._capture(self.root, self.expected, False)
        self.assertTrue(all(row['status'] == 'not-captured-cleanup-unverified'
                            for row in result['fatalLogs'].values()))

    def test_recipient_crash_survives_flooded_routine_wrapper_and_observer_logs(self):
        observer = self.observer()
        for role in evidence.ROLES:
            (observer / ('fcp-' + role + '.log')).write_bytes(b'routine FCP\n' * 4096)
            self.wrapper(role).write_bytes(b'INFO | jvm 1 | routine output\n' * 4096)
        directory = self.root / 'state/candidate-recipient/tmp'
        directory.mkdir()
        crash = (b'# SIGILL\n' + b'H' * 4096 + b'\nInstructions:\n'
                 + b'0x12345678: 0f 0b 00 00 01 02 03 04\n' * 128
                 + b'\nCPU Features: ' + b'feature ' * 256 + b'\n')
        for name in ('hs_err_pid1.log', 'hs_err_pid2.log'):
            (directory / name).write_bytes(crash)
        expected = evidence._fatal_logs(self.root, 'candidate-recipient', float('inf'))
        reads = []
        original = evidence.snapshot.read_file
        def read(root, name, **kwargs):
            reads.append(name)
            return original(root, name, **kwargs)
        with patch.object(evidence.snapshot, 'read_file', side_effect=read), \
                patch.object(evidence, 'MAX_OUTPUT', 96 * 1024):
            result = evidence._capture(self.root, self.expected, True, observer_root=observer)
        self.assertEqual(expected, result['fatalLogs']['candidate-recipient'])
        self.assertEqual(2, len(expected['files']))
        for row in expected['files']:
            self.assertEqual('captured', row['status'])
            self.assertEqual(crash[:4096], base64.b64decode(row['headBase64']))
            self.assertIn(b'0f 0b', base64.b64decode(row['sections']['instructions']['contentBase64']))
            self.assertIn(b'CPU Features:', base64.b64decode(row['sections']['cpu']['contentBase64']))
        self.assertLess(reads.index(evidence.SENTINEL), reads.index('hs_err_pid1.log'))
        self.assertLess(reads.index('hs_err_pid2.log'), reads.index('fcp-candidate-sender.log'))
        self.assertLess(reads.index('hs_err_pid2.log'), reads.index('wrapper.log'))
        self.assertTrue(any(row.get('excerpt', {}).get('status') == 'not-captured-output-budget'
                            or row['status'] == 'not-captured-output-budget'
                            for row in result['wrapperLogs'].values()))
        self.assertEqual('matched', result['sentinel']['status'])
        self.assertLessEqual(len(json.dumps(result, sort_keys=True, allow_nan=False).encode()),
                             96 * 1024)

    def test_wrapper_excerpt_finds_buried_error_without_command_lines(self):
        command = b'INFO | wrapper | 2026 | Command[1] : private-command-value\n'
        error = b'ERROR | wrapper | 2026 | Bootstrap failed\n'
        jvm = b'INFO | jvm 4 | 2026 | private-jvm-output\n'
        raw = command * 1000 + error + jvm + command * 1000
        self.wrapper().write_bytes(raw)
        with patch.object(evidence.snapshot, 'read_file', wraps=evidence.snapshot.read_file) as reader:
            log = evidence._wrapper_log(self.root, 'candidate-sender', float('inf'))
        self.assertEqual(1, reader.call_count)
        excerpt = log['excerpt']
        self.assertEqual(error + jvm, base64.b64decode(excerpt['contentBase64']))
        self.assertIn('private-diagnostic-not-acceptance', excerpt['classification'])
        self.assertNotIn(error, base64.b64decode(log['tailBase64']))
        self.assertFalse(excerpt['truncated'])

    def test_wrapper_thread_dump_retains_middle_startup_stack_without_command_line(self):
        prefix = b'INFO | jvm 1 | time | routine\n' * 400
        dump = (b'INFO | jvm 1 | time | Full thread dump OpenJDK:\n'
                b'INFO | jvm 1 | time | "main" #1 runnable\n'
                b'INFO | jvm 1 | time |   at network.crypta.node.Node.start(Node.java:1)\n'
                b'INFO | jvm 1 | time | "WrapperListener_start_runner" #2 runnable\n'
                b'INFO | jvm 1 | time |   at network.crypta.crypt.ECDH.blockingInit(ECDH.java:1)\n'
                b'INFO | jvm 1 | time | JavaCommandLine: private-command-value\n'
                b'INFO | jvm 1 | time | "Entropy Gathering Thread" #3 runnable\n'
                b'INFO | jvm 1 | time |   at network.crypta.crypt.Yarrow.readSeed(Yarrow.java:1)\n'
                b'INFO | jvm 1 | time | JNI global refs: 22\n')
        raw = prefix + dump + b'INFO | jvm 1 | time | routine tail\n' * 400
        self.assertNotIn(b'ECDH.blockingInit', base64.b64decode(
            evidence._wrapper_excerpt(raw, float('inf'))['contentBase64']))
        self.assertNotIn(b'ECDH.blockingInit', raw[-evidence.WRAPPER_TAIL:])
        captured = evidence._wrapper_thread_dump(raw, float('inf'))
        selected = base64.b64decode(captured['contentBase64'])
        self.assertEqual('captured', captured['status'])
        self.assertIn(b'ECDH.blockingInit', selected)
        self.assertIn(b'Yarrow.readSeed', selected)
        self.assertNotIn(b'private-command-value', selected)
        self.assertLessEqual(captured['sizeBytes'], 16384)
        self.assertEqual({'status': 'not-found'},
                         evidence._wrapper_thread_dump(prefix, float('inf')))

    def test_wrapper_excerpt_yields_output_budget_to_existing_tail(self):
        output_budget = self.capture_output_budget(log_bytes=6144)
        self.wrapper().write_bytes(b'ERROR | wrapper | failure ' + b'x' * 10000)
        with patch.object(evidence, 'MAX_OUTPUT', output_budget):
            result = evidence._capture(self.root, self.expected, True)
        log = result['wrapperLogs']['candidate-sender']
        self.assertEqual('captured', log['status'])
        self.assertEqual(4096, log['tailBytes'])
        self.assertEqual({'status': 'not-captured-output-budget'}, log['excerpt'])
        self.assertEqual('matched', result['sentinel']['status'])
        self.assertLess(len(json.dumps(result, sort_keys=True, allow_nan=False).encode()),
                        output_budget)

    def test_wrapper_excerpt_bounds_adversarial_text_and_deadline(self):
        line = b'FATAL | wrapper | spoofed-severity-is-not-proof ' + b'x' * 20000
        excerpt = evidence._wrapper_excerpt(line, float('inf'))
        self.assertEqual(line[:8192], base64.b64decode(excerpt['contentBase64']))
        self.assertEqual(8192, excerpt['sizeBytes'])
        self.assertTrue(excerpt['truncated'])
        excluded = (b'ERROR text | wrapper | invalid\n'
                    b'INFO | jvm evil | invalid\n'
                    b'WARN | wrapper | Command[1] : hidden\n')
        self.assertEqual('', evidence._wrapper_excerpt(excluded, float('inf'))['contentBase64'])
        with patch.object(evidence.time, 'monotonic', side_effect=[0, 2]):
            excerpt = evidence._wrapper_excerpt(b'WARN | wrapper | first\nINFO | jvm 1 | second\n', 1)
        self.assertEqual('capture-deadline', excerpt['status'])
        self.assertEqual(b'WARN | wrapper | first\n', base64.b64decode(excerpt['contentBase64']))
        self.assertTrue(excerpt['truncated'])

    def observer(self):
        root = self.root / 'observer'
        root.mkdir(exist_ok=True)
        return root

    def test_observer_logs_capture_exact_leaves_and_tails_before_candidate_logs(self):
        observer = self.observer()
        raw = b'private FCP transcript\n' * 200
        for role in evidence.ROLES:
            (observer / ('fcp-' + role + '.log')).write_bytes(raw)
        (observer / 'not-selected.log').write_text('must-not-copy')
        (observer / 'nested').mkdir()
        (observer / 'nested/fcp-previous.log').write_text('must-not-copy')
        reads = []
        original = evidence.snapshot.read_file
        def read(root, name, **kwargs):
            reads.append((root, name))
            return original(root, name, **kwargs)
        with patch.object(evidence.snapshot, 'read_file', side_effect=read):
            result = evidence._capture(self.root, self.expected, True, observer_root=observer)
        self.assertEqual(['pr315-probe-kernel.private.json',
                          'pr315-observer-control.private.json',
                          'pr315-arbitrary-endpoint.private.json',
                          *['fcp-' + role + '.log' for role in evidence.ROLES]],
                         [name for root, name in reads if root == observer])
        names = [name for _root, name in reads]
        self.assertLess(names.index(evidence.SENTINEL), names.index('fcp-candidate-sender.log'))
        self.assertLess(names.index('fcp-relay-no-apps.log'), names.index('wrapper.log'))
        for row in result['observerFcpLogs'].values():
            self.assertEqual('captured', row['status'])
            self.assertEqual('observer-origin-private-diagnostic-not-acceptance', row['classification'])
            self.assertEqual(raw[-2048:], base64.b64decode(row['tailBase64']))
            self.assertEqual(len(raw), row['sizeBytes'])
            self.assertEqual(2048, row['tailBytes'])
            self.assertTrue(row['truncated'])
        self.assertLessEqual(len(json.dumps(result, sort_keys=True, allow_nan=False).encode()), evidence.MAX_OUTPUT)

    def test_observer_root_omission_and_nonliteral_cleanup_never_read_transcripts(self):
        with patch.object(evidence, '_observer_fcp_log') as read:
            result = evidence._capture(self.root, self.expected, True)
            self.assertEqual({}, result['observerFcpLogs'])
            read.assert_not_called()
        for cleanup in (False, None, 1, 'true'):
            with self.subTest(cleanup=cleanup), patch.object(evidence, '_observer_fcp_log') as read:
                result = evidence._capture(self.root, self.expected, cleanup, observer_root=self.observer())
                self.assertTrue(all(row == {'status': 'not-captured-cleanup-unverified'}
                                    for row in result['observerFcpLogs'].values()))
                read.assert_not_called()

    def test_observer_log_missing_special_hardlinked_and_oversized_files_are_unavailable(self):
        observer = self.observer()
        path = observer / 'fcp-candidate-sender.log'
        other = observer / 'other'
        other.write_bytes(b'private')
        for kind in ('missing', 'symlink', 'fifo', 'hardlink', 'oversized'):
            with self.subTest(kind=kind):
                if kind == 'symlink':
                    path.symlink_to(other)
                elif kind == 'fifo':
                    os.mkfifo(path)
                elif kind == 'hardlink':
                    os.link(other, path)
                elif kind == 'oversized':
                    with path.open('wb') as stream:
                        stream.truncate(evidence.MAX_OBSERVER_FCP_LOG + 1)
                self.assertEqual({'status': 'unavailable-or-unsafe'},
                    evidence._observer_fcp_log(observer, 'candidate-sender', float('inf')))
                if kind != 'missing':
                    path.unlink()

    def test_observer_transcript_replacement_or_growth_during_read_is_not_exported(self):
        observer = self.observer()
        path = observer / 'fcp-candidate-sender.log'
        original = os.read
        for attack in ('replacement', 'growth'):
            with self.subTest(attack=attack):
                path.write_bytes(b'fixed FCP output')
                changed = []
                def mutate(fd, maximum):
                    value = original(fd, maximum)
                    if value == b'fixed FCP output' and not changed:
                        changed.append(True)
                        if attack == 'replacement':
                            replacement = observer / 'replacement'
                            replacement.write_bytes(value)
                            os.replace(replacement, path)
                        else:
                            with path.open('ab') as stream:
                                stream.write(b'growth')
                    return value
                with patch.object(evidence.snapshot.os, 'read', side_effect=mutate):
                    result = evidence._observer_fcp_log(observer, 'candidate-sender', float('inf'))
                self.assertTrue(changed)
                self.assertEqual({'status': 'unavailable-or-unsafe'}, result)

    def test_observer_transcript_read_shares_global_deadline_and_fixed_input_cap(self):
        observer = self.observer()
        with patch.object(evidence.time, 'monotonic', return_value=10), \
                patch.object(evidence.snapshot, 'read_file', return_value=b'x') as read:
            self.assertEqual({'status': 'capture-deadline'},
                             evidence._observer_fcp_log(observer, 'previous', 9))
            read.assert_not_called()
            row = evidence._observer_fcp_log(observer, 'previous', 10.25)
            read.assert_called_once_with(observer, 'fcp-previous.log', maximum=16 * 1024 * 1024, timeout=.25)
            self.assertEqual(b'x', base64.b64decode(row['tailBase64']))
            self.assertFalse(row['truncated'])
            evidence._observer_fcp_log(observer, 'previous', 20)
            self.assertEqual(2, read.call_args.kwargs['timeout'])

    def test_observer_output_budget_keeps_higher_priority_controller_and_sentinel(self):
        observer = self.observer()
        for role in evidence.ROLES:
            (observer / ('fcp-' + role + '.log')).write_bytes(b'x' * 4096)
        baseline = evidence._capture(self.root, self.expected, True)
        cap = len(json.dumps(baseline, sort_keys=True, allow_nan=False).encode()) + 1500
        with patch.object(evidence, 'MAX_OUTPUT', cap):
            result = evidence._capture(self.root, self.expected, True, observer_root=observer)
        self.assertEqual('matched', result['sentinel']['status'])
        self.assertEqual('captured', result['controllerRecords']['campaign']['status'])
        self.assertTrue(all(row == {'status': 'not-captured-output-budget'}
                            for row in result['observerFcpLogs'].values()))
        self.assertLessEqual(len(json.dumps(result, sort_keys=True, allow_nan=False).encode()), cap)

    def test_public_observer_selection_only_accepts_direct_experiment_child(self):
        allowed = evidence.OBSERVER_EXPERIMENTS / 'fixed-experiment'
        with patch.object(evidence, '_installed'), patch.object(evidence, '_capture', return_value={}) as capture:
            evidence.capture(object(), None, True, observer_root=allowed)
            capture.assert_called_once_with(evidence.ROOT, None, True, observer_root=allowed)
            capture.reset_mock()
            for root in (Path('/tmp/other'), evidence.OBSERVER_EXPERIMENTS,
                         evidence.OBSERVER_EXPERIMENTS / '..', allowed / 'nested',
                         Path('relative/experiment')):
                with self.subTest(root=root), self.assertRaisesRegex(ValueError, 'observer-root-invalid'):
                    evidence.capture(object(), None, True, observer_root=root)
            capture.assert_not_called()

    def wrapper(self, role='candidate-sender'):
        logs = self.root / 'state' / role / 'logs'
        logs.mkdir(parents=True, exist_ok=True)
        return logs / 'wrapper.log'

    def test_wrapper_logs_capture_only_fixed_private_tail_after_authority_and_sentinel(self):
        raw = b'not-in-retained-tail' + bytes(range(256)) * 32
        for role in evidence.ROLES:
            self.wrapper(role).write_bytes(raw)
        original = evidence.snapshot.read_file
        names = []
        def read(root, name, **kwargs):
            names.append(name)
            return original(root, name, **kwargs)
        with patch.object(evidence.snapshot, 'read_file', side_effect=read):
            result = evidence._capture(self.root, self.expected, True)
        self.assertEqual([*(['wrapper.log'] * 4)], names[-4:])
        self.assertLess(names.index(evidence.SENTINEL), names.index('wrapper.log'))
        for log in result['wrapperLogs'].values():
            self.assertEqual('candidate-origin-private-diagnostic-not-acceptance', log['classification'])
            self.assertEqual(len(raw), log['sizeBytes'])
            self.assertEqual(4096, log['tailBytes'])
            self.assertTrue(log['truncated'])
            self.assertEqual(raw[-4096:], base64.b64decode(log['tailBase64']))
        self.assertEqual(128 * 1024, evidence.MAX_OUTPUT)
        self.assertEqual(evidence.MAX_OUTPUT,
                         launcher.launcher_policy()['privateVolatileMaxBytes'])
        self.assertLessEqual(len(json.dumps(result).encode()), evidence.MAX_OUTPUT)

    def test_short_and_missing_wrapper_logs_are_reported_without_invented_bytes(self):
        self.wrapper().write_bytes(b'daemon startup failure\n')
        result = evidence._capture(self.root, self.expected, True)
        log = result['wrapperLogs']['candidate-sender']
        self.assertFalse(log['truncated'])
        self.assertEqual(log['sizeBytes'], log['tailBytes'])
        self.assertEqual({'status': 'unavailable-or-unsafe'}, result['wrapperLogs']['previous'])

    def test_wrapper_log_special_hardlinked_and_oversized_files_are_rejected(self):
        path = self.wrapper()
        other = path.with_name('unselected-file')
        for kind in ('symlink', 'fifo', 'hardlink', 'oversized'):
            with self.subTest(kind=kind):
                path.unlink(missing_ok=True)
                other.unlink(missing_ok=True)
                if kind == 'symlink':
                    other.write_bytes(b'private')
                    path.symlink_to(other)
                elif kind == 'fifo':
                    os.mkfifo(path)
                elif kind == 'hardlink':
                    other.write_bytes(b'private')
                    os.link(other, path)
                else:
                    with path.open('wb') as stream:
                        stream.truncate(evidence.MAX_WRAPPER_LOG + 1)
                result = evidence._capture(self.root, self.expected, True)
                self.assertEqual({'status': 'unavailable-or-unsafe'}, result['wrapperLogs']['candidate-sender'])
                self.assertEqual('matched', result['sentinel']['status'])

    def test_wrapper_replacement_during_descriptor_read_is_not_exported(self):
        path = self.wrapper()
        path.write_bytes(b'fixed wrapper output')
        original = os.read
        replaced = False
        def replace(fd, maximum):
            nonlocal replaced
            value = original(fd, maximum)
            if value == b'fixed wrapper output' and not replaced:
                replacement = path.with_name('replacement')
                replacement.write_bytes(value)
                os.replace(replacement, path)
                replaced = True
            return value
        with patch.object(evidence.snapshot.os, 'read', side_effect=replace):
            result = evidence._capture(self.root, self.expected, True)
        self.assertTrue(replaced)
        self.assertEqual({'status': 'unavailable-or-unsafe'}, result['wrapperLogs']['candidate-sender'])

    def test_remaining_global_deadline_prevents_additional_log_reads(self):
        with patch.object(evidence.time, 'monotonic', return_value=10), \
                patch.object(evidence.snapshot, 'read_file') as read:
            self.assertEqual({'status': 'capture-deadline'}, evidence._wrapper_log(self.root, 'previous', 9))
            read.assert_not_called()
            read.return_value = b'x'
            evidence._wrapper_log(self.root, 'previous', 10.25)
            self.assertEqual(.25, read.call_args.kwargs['timeout'])
            self.assertEqual(2 * 1024 * 1024, read.call_args.kwargs['maximum'])

    def test_output_budget_omits_logs_without_discarding_prior_observations(self):
        output_budget = self.capture_output_budget()
        self.wrapper().write_bytes(b'x' * 8192)
        with patch.object(evidence, 'MAX_OUTPUT', output_budget):
            result = evidence._capture(self.root, self.expected, True)
        self.assertEqual('matched', result['sentinel']['status'])
        self.assertEqual('captured', result['controllerRecords']['campaign']['status'])
        self.assertEqual({'status': 'not-captured-output-budget'}, result['wrapperLogs']['candidate-sender'])
        self.assertLess(len(json.dumps(result, sort_keys=True, allow_nan=False).encode()),
                        output_budget)

    def capture_output_budget(self, *, log_bytes=0):
        """Leave bounded log space after the current mandatory diagnostic metadata."""
        baseline = evidence._capture(self.root, self.expected, True)
        # Allow status/timestamp overhead, but not a log payload unless explicitly reserved.
        return len(json.dumps(baseline, sort_keys=True, allow_nan=False).encode()) + 512 + log_bytes

    def test_capture_rejects_budget_smaller_than_mandatory_metadata(self):
        output_budget = self.capture_output_budget() - 1024

        with patch.object(evidence, 'MAX_OUTPUT', output_budget):
            with self.assertRaisesRegex(ValueError, '^workload-evidence-output-limit$'):
                evidence._capture(self.root, self.expected, True)

    def test_changed_sentinel_is_not_matched(self):
        self.path.write_bytes(b'x' * 32)
        self.assertEqual('changed', evidence._capture(self.root, self.expected, True)['sentinel']['status'])

    def test_missing_sentinel_retains_controller_diagnostics(self):
        self.path.unlink()
        result = evidence._capture(self.root, self.expected, True)
        self.assertEqual('unavailable-or-unsafe', result['sentinel']['status'])
        self.assertEqual('captured', result['controllerRecords']['campaign']['status'])

    def test_special_and_multiply_linked_sentinel_rejected_without_blocking(self):
        for kind in ('symlink', 'fifo', 'hardlink', 'socket', 'oversized'):
            with self.subTest(kind=kind):
                self.path.unlink(missing_ok=True)
                target = self.state / 'other'
                target.unlink(missing_ok=True)
                connection = None
                if kind == 'symlink':
                    target.write_bytes(self.raw)
                    self.path.symlink_to(target)
                elif kind == 'fifo':
                    os.mkfifo(self.path)
                elif kind == 'hardlink':
                    target.write_bytes(self.raw)
                    os.link(target, self.path)
                elif kind == 'socket':
                    connection = socket.socket(socket.AF_UNIX)
                    connection.bind(str(self.path))
                else:
                    self.path.write_bytes(b'x' * 33)
                try:
                    self.assertEqual('unavailable-or-unsafe',
                        evidence._capture(self.root, self.expected, True)['sentinel']['status'])
                finally:
                    if connection is not None:
                        connection.close()

    def test_unsafe_authority_does_not_prevent_safe_sentinel_capture(self):
        path = self.root / 'campaign.json'
        path.unlink()
        os.mkfifo(path)
        result = evidence._capture(self.root, self.expected, True)
        self.assertEqual('unavailable-or-unsafe', result['controllerRecords']['campaign']['status'])
        self.assertEqual('matched', result['sentinel']['status'])

    def test_fixed_leaf_creation_is_exclusive(self):
        with evidence.snapshot._directory(self.state) as parent:
            with self.assertRaises(FileExistsError):
                evidence._create(parent, b'x' * 32)
        self.assertEqual(self.raw, self.path.read_bytes())

    def test_capture_does_not_treat_missing_records_as_quiescence(self):
        for path in (self.root / 'authority').iterdir():
            path.unlink()
        result = evidence._capture(self.root, self.expected, True)
        self.assertFalse(result['quiescenceIndependentlyEstablished'])
        self.assertTrue(all(result['controllerRecords'][role]['status'] == 'unavailable-or-unsafe'
                            for role in evidence.ROLES))

    def test_same_bytes_replaced_during_read_are_rejected(self):
        original = os.read
        replaced = False
        def replacing_read(fd, maximum):
            nonlocal replaced
            raw = original(fd, maximum)
            if raw == self.raw and not replaced:
                replacement = self.state / 'replacement'
                replacement.write_bytes(self.raw)
                os.replace(replacement, self.path)
                replaced = True
            return raw
        with patch.object(evidence.snapshot.os, 'read', side_effect=replacing_read):
            result = evidence._capture(self.root, self.expected, True)
        self.assertTrue(replaced)
        self.assertEqual('unavailable-or-unsafe', result['sentinel']['status'])

    def test_parent_symlink_does_not_export_sentinel(self):
        original = self.root / 'state/original'
        self.state.rename(original)
        self.state.symlink_to(original, target_is_directory=True)
        result = evidence._capture(self.root, self.expected, True)
        self.assertEqual('unavailable-or-unsafe', result['sentinel']['status'])

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux O_PATH reader required')
    def test_hostile_origin_audit_retains_only_closed_digest_witness(self):
        actor = {'hostPid': 123, 'hostParentPid': 100, 'pidNamespace': 'pid:[5]',
                 'networkNamespaceIdentity': [1, 2], 'mountNamespaceIdentity': [1, 3],
                 'userNamespaceIdentity': [1, 4], 'namespacePids': [123, 2],
                 'startTicks': 45, 'executableDigest': 'sha256:' + 'a' * 64,
                 'rssBytes': 1024, 'processThreads': 1,
                 'noNewPrivileges': True, 'effectiveCapabilities': 0}
        target = {'role': 'candidate-sender', 'managerInvocation': 'c' * 32,
                  'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                  'cgroupIdentity': [1, 22], 'workerHostPid': 211,
                  'workerStartTicks': 30, 'javaHostPid': 212,
                  'javaStartTicks': 31, 'observedMonotonicNs': 20,
                  'controlResponseDigest': 'd' * 64}
        control = {'status': 200, 'errorCode': None,
                   'responseDigest': 'e' * 64,
                   'startedMonotonicNs': 30, 'finishedMonotonicNs': 40}
        audit = {'schemaVersion': 1,
            'kind': 'pr315-administrator-hostile-app-origin-denial',
            'caseId': 'hostile-app-origin', 'sourceDigest': 'a' * 64,
            'nonceDigest': 'b' * 64, 'actorUid': 1001,
            'actorBefore': actor, 'actorAfter': dict(actor),
            'actorInvocationBefore': 'c' * 32,
            'actorInvocationAfter': 'c' * 32,
            'actorCgroupBefore': [1, 22], 'actorCgroupAfter': [1, 22],
            'actorStateBefore': 'd' * 64, 'actorStateAfter': 'd' * 64,
            'targetBefore': target,
            'targetAfter': dict(target, observedMonotonicNs=100),
            'inputDigest': 'a' * 64, 'sessionDigest': 'b' * 64,
            'expectedOriginDigest': 'c' * 64,
            'hostileOriginDigest': 'd' * 64,
            'targetEndpointDigest': 'e' * 64,
            'controlBefore': control,
            'controlAfter': dict(control, startedMonotonicNs=75,
                                 finishedMonotonicNs=80),
            'attackStartedNs': 50, 'attackFinishedNs': 60,
            'attackResponseDigest': 'f' * 64,
            'denialStatus': 403, 'denialCode': 'origin_mismatch'}
        path = self.root / 'authority/hostile-app-origin-denial.json'
        path.write_text(json.dumps(audit))
        path.chmod(0o600)
        captured = evidence._hostile_origin_audit(self.root, time.monotonic() + 2)
        self.assertEqual('captured', captured['status'])
        self.assertEqual(audit, captured['record'])
        whole = evidence._capture(self.root, self.expected, True)
        self.assertEqual('captured', whole['hostileAppOriginAudit']['status'])
        audit['browserSessionToken'] = 'must-not-retain'
        path.write_text(json.dumps(audit))
        self.assertEqual('unavailable-or-unsafe', evidence._hostile_origin_audit(
            self.root, time.monotonic() + 2)['status'])
        self.assertNotIn('must-not-retain', json.dumps(evidence._capture(
            self.root, self.expected, True)))

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux O_PATH reader required')
    def test_provider_audit_binds_signed_child_and_redacts_candidate_output(self):
        app_data = self.root / 'state/candidate-sender/data/node/apps/data/pr315-probe'
        app_data.mkdir(parents=True)
        nonce = 'a' * 64
        result = {'schemaVersion': 1,
            'kind': 'pr315-signed-provider-authority-probe',
            'caseId': 'provider-authority', 'nonce': nonce,
            'pid': 2, 'uid': os.geteuid(), 'gid': os.getegid(),
            'startedMonotonicNs': 50, 'finishedMonotonicNs': 60,
            'targetPathDigest': hashlib.sha256(
                b'/etc/cryptad-certification/restricted-provider.json').hexdigest(),
            'outcome': {'opened': False, 'errno': 'ENOENT'}}
        app_result = app_data / 'pr315-provider-result.json'
        app_result.write_text(json.dumps(result))
        app_result.chmod(0o600)
        leader = {'hostPid': 300, 'namespacePids': [300, 20, 1],
            'startTicks': 40, 'executableDigest': 'sha256:' + 'b' * 64,
            'mountNamespaceIdentity': [1, 3], 'userNamespaceIdentity': [1, 4],
            'networkNamespaceIdentity': [1, 2], 'pidNamespaceIdentity': 5}
        actor = {'role': 'candidate-sender', 'hostPid': 301,
            'namespacePid': 20, 'namespacePids': [301, 20, 2],
            'startTicks': 45, 'executableDigest': 'sha256:' + 'a' * 64,
            'mountNamespaceIdentity': [1, 3],
            'outerMountNamespaceIdentity': [1, 7],
            'userNamespaceIdentity': [1, 4], 'pidNamespaceIdentity': 5,
            'managerInvocation': 'c' * 32, 'cgroupIdentity': [1, 99],
            'networkNamespaceIdentity': [1, 2], 'stateDigest': 'd' * 64,
            'observedMonotonicNs': 20, 'sandboxLeader': leader,
            'provenance': 'controller-kernel-sample'}
        target = {'role': None, 'managerInvocation': 'e' * 32,
            'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
            'cgroupIdentity': [3, 5], 'mainPid': 211,
            'mainStartTicks': 42, 'resolverCanaryIdentity': [3, 6],
            'resolverControlDigest': 'a' * 64,
            'providerCanaryIdentity': [3, 7],
            'credentialIdentity': [3, 8],
            'credentialDigest': 'f' * 64,
            'observedMonotonicNs': 10, 'controlDigest': 'b' * 64}
        worker = {'kind': 'pr315-installed-worker-synthetic-provider-control-v2',
            'jobAuthentication': 'installed-policy-fixed-no-network-provider-stub',
            'workerSourceDigest': '1' * 64,
            'credentialDigest': 'f' * 64,
            'registrationDigest': '2' * 64,
            'resultDigest': '3' * 64,
            'bundleIdentity': '4' * 64,
            'callerUid': 1001}
        audit = {'schemaVersion': 2,
            'kind': 'pr315-administrator-provider-authority-denial',
            'caseId': 'provider-authority', 'bundleDigest': 'sha256:' + '8' * 64,
            'nonceDigest': hashlib.sha256(nonce.encode()).hexdigest(),
            'actorUid': os.geteuid(), 'actorBefore': actor,
            'actorAfter': dict(actor, observedMonotonicNs=80),
            'senderStateBefore': 'd' * 64, 'senderStateAfter': 'd' * 64,
            'targetBefore': target,
            'targetAfter': dict(target, observedMonotonicNs=100),
            'workerControlBefore': dict(worker, ordinal=1,
                handleDigest='5' * 64,
                startedMonotonicNs=1, finishedMonotonicNs=5),
            'workerControlAfter': dict(worker, ordinal=2,
                handleDigest='6' * 64,
                startedMonotonicNs=110, finishedMonotonicNs=120),
            'targetPathDigest': result['targetPathDigest'],
            'attackStartedNs': 50, 'attackFinishedNs': 60,
            'kernelOpenResult': result['outcome'],
            'appResultDigest': hashlib.sha256(json.dumps(result,
                sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
        root_audit = self.root / 'authority/provider-authority-denial.json'
        root_audit.write_text(json.dumps(audit))
        root_audit.chmod(0o600)
        captured = evidence._capture(self.root, self.expected, True)
        self.assertEqual('captured', captured['providerAppResult']['status'])
        self.assertEqual('captured', captured['providerAuthorityAudit']['status'])
        self.assertNotIn('provider-token', json.dumps(captured))
        root_audit.write_text(json.dumps(dict(audit, token='provider-token')))
        self.assertEqual('unavailable-or-unsafe', evidence._provider_authority_audit(
            self.root, time.monotonic() + 2)['status'])
        app_result.write_text(json.dumps(dict(result,
            outcome={'opened': True, 'errno': None})))
        self.assertEqual('unavailable-or-unsafe', evidence._provider_app_result(
            self.root, time.monotonic() + 2)['status'])

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux O_PATH reader required')
    def test_sibling_app_audit_keeps_only_exact_signed_syn_and_drop(self):
        app_data = self.root / 'state/candidate-sender/data/node/apps/data/pr315-probe'
        app_data.mkdir(parents=True)
        nonce = 'a' * 64
        endpoint = hashlib.sha256(b'10.231.0.2:19402').hexdigest()
        app_result = {'schemaVersion': 1,
            'kind': 'pr315-signed-sibling-app-probe',
            'caseId': 'sibling-app', 'nonce': nonce,
            'pid': 2, 'uid': os.geteuid(), 'gid': os.getegid(),
            'startedMonotonicNs': 50, 'finishedMonotonicNs': 60,
            'sourcePort': 19404, 'targetEndpointDigest': endpoint,
            'outcome': {'connected': False, 'phase': 'connect',
                        'errno': 'ETIMEDOUT'}}
        app_path = app_data / 'pr315-sibling-app-result.json'
        app_path.write_text(json.dumps(app_result))
        app_path.chmod(0o600)
        leader = {'hostPid': 300, 'namespacePids': [300, 20, 1],
            'startTicks': 40, 'executableDigest': 'sha256:' + 'b' * 64,
            'mountNamespaceIdentity': [1, 3], 'userNamespaceIdentity': [1, 4],
            'networkNamespaceIdentity': [1, 2], 'pidNamespaceIdentity': 5}
        actor = {'role': 'candidate-sender', 'hostPid': 301,
            'namespacePid': 20, 'namespacePids': [301, 20, 2],
            'startTicks': 45, 'executableDigest': 'sha256:' + 'a' * 64,
            'mountNamespaceIdentity': [1, 3],
            'outerMountNamespaceIdentity': [1, 7],
            'userNamespaceIdentity': [1, 4], 'pidNamespaceIdentity': 5,
            'managerInvocation': 'c' * 32, 'cgroupIdentity': [1, 99],
            'networkNamespaceIdentity': [1, 2], 'stateDigest': 'd' * 64,
            'observedMonotonicNs': 10, 'sandboxLeader': leader,
            'provenance': 'controller-kernel-sample'}
        target = {'role': 'candidate-recipient',
            'managerInvocation': 'e' * 32,
            'bootId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
            'cgroupIdentity': [1, 100], 'workerHostPid': 311,
            'workerStartTicks': 52, 'javaHostPid': 312,
            'javaStartTicks': 53, 'observedMonotonicNs': 20,
            'controlObservedNs': 19, 'controlDigest': 'f' * 64,
            'appUiOriginDigest': hashlib.sha256(
                b'http://127.0.0.1:12345').hexdigest()}
        names = network.SIBLING_DROP_COUNTERS
        counters = {name: {'packets': 0, 'bytes': 0} for name in names.values()}
        before = {'schemaVersion': 1,
            'kind': 'pr315-fixed-sibling-drop-counters',
            'policyDigest': hashlib.sha256(network.role_rules(
                'candidate-sender').encode()).hexdigest(),
            'bootId': target['bootId'],
            'roleNamespaceIdentity': [1, 2],
            'observedMonotonicNs': 30, 'counters': counters}
        after_counts = json.loads(json.dumps(counters))
        after_counts[names['sibling-app']] = {'packets': 1, 'bytes': 60}
        after = dict(before, observedMonotonicNs=70, counters=after_counts)
        audit = {'schemaVersion': 1,
            'kind': 'pr315-administrator-sibling-app-denial',
            'caseId': 'sibling-app', 'bundleDigest': 'sha256:' + '8' * 64,
            'nonceDigest': hashlib.sha256(nonce.encode()).hexdigest(),
            'actorUid': os.geteuid(), 'actorBefore': actor,
            'actorAfter': dict(actor, observedMonotonicNs=80),
            'senderStateBefore': 'd' * 64, 'senderStateAfter': 'd' * 64,
            'targetBefore': target,
            'targetAfter': dict(target, observedMonotonicNs=90,
                                controlObservedNs=89),
            'counterBefore': before, 'counterAfter': after,
            'counterName': names['sibling-app'], 'sourcePort': 19404,
            'targetEndpointDigest': endpoint,
            'triggerMonotonicNs': 40, 'attackStartedNs': 50,
            'attackFinishedNs': 60,
            'kernelConnectResult': app_result['outcome'],
            'appResultDigest': hashlib.sha256(json.dumps(app_result,
                sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
        root_path = self.root / 'authority/sibling-app-denial.json'
        root_path.write_text(json.dumps(audit))
        root_path.chmod(0o600)
        captured = evidence._capture(self.root, self.expected, True)
        self.assertEqual('captured', captured['siblingAppResult']['status'])
        self.assertEqual('captured', captured['siblingAppAudit']['status'])
        root_path.write_text(json.dumps(dict(audit, token='must-not-retain')))
        self.assertEqual('unavailable-or-unsafe', evidence._sibling_app_audit(
            self.root, time.monotonic() + 2)['status'])
        self.assertNotIn('must-not-retain', json.dumps(evidence._capture(
            self.root, self.expected, True)))


if __name__ == '__main__':
    unittest.main()

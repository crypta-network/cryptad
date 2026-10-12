"""Exercise delegated output emitters through the real descriptor collector.

Process epochs are offline fixtures; these records never confer installed credit.
"""
import builtins
import hashlib
import json
import os
from pathlib import Path
import sys
import symtable
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'interop'))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'protected'))
import pr314_workload_driver as driver
import pr315_workload_fault_probes as faults


class DelegatedBindingsTest(unittest.TestCase):
    def test_deferred_fault_callbacks_resolve_their_global_dependencies(self):
        source = Path(faults.__file__)
        table = symtable.symtable(source.read_text(), str(source), 'exec')
        known = set(dir(builtins)) | {'__file__', '__name__'} | {
            symbol.get_name() for symbol in table.get_symbols()
            if symbol.is_assigned() or symbol.is_imported() or symbol.is_namespace()}
        missing = []

        def inspect(scope):
            for child in scope.get_children():
                missing.extend((child.get_name(), symbol.get_name())
                    for symbol in child.get_symbols()
                    if symbol.is_global() and symbol.is_referenced()
                    and symbol.get_name() not in known)
                inspect(child)

        inspect(table)

        self.assertEqual([], missing)


class DelegatedOutputReplacementTest(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux descriptor pinning required')
    def test_exported_emitter_rejects_real_replacement_after_descriptor_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            selected = Path(directory).resolve()
            root = selected / 'state/candidate-sender/tmp'
            root.mkdir(parents=True)
            nonce = None
            uid, gid = os.geteuid(), os.getegid()
            pid = 123
            actor = {key: 1 for key in ('hostPid', 'hostParentPid', 'startTicks',
                'pidNamespace', 'networkNamespaceIdentity', 'mountNamespaceIdentity',
                'userNamespaceIdentity', 'executableDigest', 'noNewPrivileges',
                'effectiveCapabilities')}
            actor['namespacePids'] = [pid]

            def write(path, value, **_options):
                nonlocal nonce
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(value))
                path.chmod(0o600)
                if path.name == 'candidate-sender.json':
                    nonce = value['nonce']
                    write(root / driver.OUTPUT_REPLACEMENT_READY, {
                        'schemaVersion': 1, 'kind': 'pr315-candidate-role-probe-ready',
                        'caseId': 'output-replacement', 'nonce': nonce,
                        'pid': pid, 'startedMonotonicNs': time.monotonic_ns()})

            def observe(_handle):
                return {'managerInvocation': 'a' * 32, 'cgroupIdentity': [1, 2],
                        'stateDigest': 'b' * 64, 'observedMonotonicNs': time.monotonic_ns()}

            collector = {'pid': pid, 'uid': uid, 'startTicks': 1, 'bootId': 'boot',
                'cgroupIdentity': [1, 3], 'cgroupDigest': 'c' * 64,
                'invocationId': 'd' * 32, 'sourceDigest': 'e' * 64}
            published = []
            publish = driver._publish_output_trigger

            def trigger(parent, name, case_id, secret):
                publish(parent, name, case_id, secret)
                published.append(name)
                started = time.monotonic_ns()
                artifact = root / driver.OUTPUT_REPLACEMENT
                if name == driver.OUTPUT_REPLACEMENT_TRIGGER:
                    artifact.write_bytes(b'A' * 32)
                    artifact.chmod(0o600)
                    write(root / driver.OUTPUT_REPLACEMENT_RESULT, {
                        'schemaVersion': 1, 'kind': 'pr315-candidate-output-replacement',
                        'caseId': case_id, 'nonce': secret, 'pid': pid, 'uid': uid, 'gid': gid,
                        'startedMonotonicNs': started, 'finishedMonotonicNs': time.monotonic_ns(),
                        'artifactPathDigest': hashlib.sha256(os.fsencode(
                            Path('/node/tmp') / driver.OUTPUT_REPLACEMENT)).hexdigest(),
                        'targetPathDigest': hashlib.sha256(
                            b'/node/tmp/pr315-output-target-canary').hexdigest()})
                elif name == driver.OUTPUT_REPLACEMENT_SWAP_TRIGGER:
                    replacement = artifact.with_name('replacement')
                    replacement.write_bytes(b'B' * 32)
                    replacement.chmod(0o600)
                    os.replace(replacement, artifact)
                    write(root / driver.OUTPUT_REPLACEMENT_SWAP_RESULT, {
                        'schemaVersion': 1, 'kind': 'pr315-candidate-output-replacement-swap',
                        'caseId': case_id, 'nonce': secret, 'pid': pid,
                        'startedMonotonicNs': started, 'finishedMonotonicNs': time.monotonic_ns()})
                else:
                    self.fail('unexpected barrier')

            workload = SimpleNamespace(ROOT=selected, account=lambda _: SimpleNamespace(
                pw_uid=uid, pw_gid=gid), read=lambda _: {'javaDigest': 'f' * 64},
                write=write, boot=lambda: 'boot', observe=observe)
            with patch.object(driver, '_role_probe_actor', return_value=actor), \
                    patch.object(driver, '_administrator_collector_epoch', side_effect=lambda _:
                        {**collector, 'observedMonotonicNs': time.monotonic_ns()}), \
                    patch.object(driver, '_publish_output_trigger', side_effect=trigger):
                digest = driver.probe_output_replacement(workload,
                    {'handles': {'candidate-sender': 'a' * 64}}, 'b' * 64,
                    time.monotonic_ns() + 30 * 10**9)

            audit = json.loads((selected / 'authority/output-replacement-denial.json').read_bytes())
            self.assertEqual([driver.OUTPUT_REPLACEMENT_TRIGGER,
                              driver.OUTPUT_REPLACEMENT_SWAP_TRIGGER], published)
            self.assertEqual('workload-snapshot-changed', audit['collectorDenial'])
            self.assertNotEqual(audit['artifactIdentity'], audit['replacementIdentity'])
            self.assertEqual(hashlib.sha256(b'A' * 32).hexdigest(), audit['initialDigest'])
            self.assertEqual(hashlib.sha256(b'B' * 32).hexdigest(), audit['replacementDigest'])
            self.assertLess(audit['collectorStartedNs'], audit['swapTriggerNs'])
            self.assertLess(audit['swapFinishedNs'], audit['collectorFinishedNs'])
            self.assertEqual(hashlib.sha256(json.dumps(audit, sort_keys=True,
                separators=(',', ':')).encode()).hexdigest(), digest)

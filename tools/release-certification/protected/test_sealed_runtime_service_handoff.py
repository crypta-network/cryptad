"""Offline service authority and lifetime tests, with synthetic OS ownership only."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import cross_version_product_admission as products
import cross_version_supervisor_authority as authority


class ServiceHandoffTest(unittest.TestCase):
    def setUp(self):
        # Other focused suites deliberately reload the protected helper namespace.
        # Match the canonical module used by the service's local import at admission time.
        global products
        import importlib
        products = importlib.import_module('cross_version_product_admission')
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        package = self.root / 'package'
        package.write_bytes(b'authenticated synthetic package')
        identity = 'sha256:' + hashlib.sha256(package.read_bytes()).hexdigest()
        self.plan = {'nodes': [{'role': 'candidate-sender', 'artifactDigest': identity,
                               'artifactSize': package.stat().st_size, 'appDigests': []}]}
        self.private = {'nodes': {'candidate-sender': {'archivePath': str(package), 'apps': []}}}
        self.rows = [{'role': 'candidate-sender', 'artifactDigest': identity,
                      'artifactSize': package.stat().st_size,
                      'sealedRuntimeBinding': {'digest': 'sha256:' + 'a' * 64},
                      'runtimeBinding': {'contractSemanticDigest': authority.digest({'contractVersion': 19})},
                      'contractVersion': 19, 'requiredAppIds': [], 'appMatrix': [],
                      'privateCanary': 'private-selection-canary'}]
        self.authorization = {'private-authorization-canary': True}
        self.activation = {'schemaVersion': 2, 'planDigest': authority.digest(self.plan),
                           'products': [products.public_product_identity(row) for row in self.rows],
                           'bootId': 'test-boot', 'startedMonotonicNs': 100, 'deadlineMonotonicNs': 1000}
        stack = self.enterContext(contextlib.ExitStack())
        stack.enter_context(patch.object(authority, 'AUTHORITY', self.root))
        stack.enter_context(patch.object(authority, 'boot_id', return_value='test-boot'))
        stack.enter_context(patch.object(authority.time, 'monotonic_ns', return_value=500))
        stack.enter_context(patch.object(authority, 'secured', side_effect=lambda path, **kwargs: path))
        stack.enter_context(patch.object(authority, 'authority_directory'))
        stack.enter_context(patch.object(authority.pwd, 'getpwnam', return_value=SimpleNamespace(pw_gid=os.getgid())))
        real_fstat = os.fstat
        class RootOwned:
            def __init__(self, original):
                self.original = original
                self.st_uid = 0
            def __getattr__(self, name):
                return getattr(self.original, name)
        stack.enter_context(patch.object(authority.os, 'fstat', side_effect=lambda fd: RootOwned(real_fstat(fd))))
        self.write_record()

    def write_record(self, **changes):
        self.record = self.root / 'runtime-products.json'
        self.record.write_text(json.dumps({'schemaVersion': 2, 'kind': 'service-private-runtime-products',
            'activationDigest': authority.digest(self.activation), 'products': self.rows,
            'privateConfigDigest': authority.digest(self.private),
            'authorizationDigest': authority.digest(self.authorization), **changes}))
        self.record.chmod(0o640)

    def test_root_private_record_supplies_semantics_without_network_or_key(self):
        self.assertNotIn('private-selection-canary', json.dumps(self.activation))
        self.assertNotIn(authority.digest(self.private), json.dumps(self.activation))
        self.assertNotIn(authority.digest(self.authorization), json.dumps(self.activation))
        runner = authority.AuthenticatedRunner(authority._SEAL, self.activation)
        with patch.object(products, 'authenticate_original') as original:
            with runner.product_admission(self.plan, self.private) as admitted:
                self.assertEqual(self.activation['products'], admitted.public_identities())
                self.assertEqual('private-selection-canary', admitted.private_identities()[0]['privateCanary'])
                self.assertTrue(admitted.verify_runtime_contract('candidate-sender', {'contract': {'contractVersion': 19}}))
            original.assert_not_called()
        with self.assertRaises(products.ProductAdmissionError):
            admitted.bind(self.plan, self.private)

    def test_every_use_rechecks_boot_lifetime_and_private_record(self):
        admitted = authority.AuthenticatedRunner(authority._SEAL, self.activation).product_admission(self.plan, self.private)
        self.addCleanup(admitted.close)
        with patch.object(authority.time, 'monotonic_ns', return_value=1001):
            with self.assertRaisesRegex(authority.AuthorityError, 'lifetime'):
                admitted.bind(self.plan, self.private)
        with patch.object(authority, 'boot_id', return_value='other-boot'):
            with self.assertRaisesRegex(authority.AuthorityError, 'lifetime'):
                admitted.verify_runtime_contract('candidate-sender', {})
        self.record.chmod(0o644)
        with self.assertRaisesRegex(authority.AuthorityError, 'confined'):
            admitted.public_identities()

    def test_safe_public_json_and_cross_activation_record_cannot_reconstruct_authority(self):
        runner = authority.AuthenticatedRunner(authority._SEAL, self.activation)
        self.write_record(activationDigest='sha256:' + 'b' * 64)
        with self.assertRaisesRegex(authority.AuthorityError, 'activation-mismatch'):
            runner.product_admission(self.plan, self.private)
        self.record.unlink()
        with self.assertRaises(OSError):
            runner.product_admission(self.plan, self.private)
        with self.assertRaises(authority.AuthorityError):
            authority.AuthenticatedRunner(None, self.activation)

    def test_private_authorization_retries_retain_random_public_context_and_exact_private_binding(self):
        bindings = {'planDigest': authority.digest(self.plan), 'serviceDigest': 'sha256:' + 'c' * 64,
                    'privateConfigDigest': authority.digest(self.private),
                    'authorizationDigest': authority.digest(self.authorization)}
        selected = authority._runtime_authorization(bindings, create=True)
        path = self.root / 'runtime-authorization.json'
        original = path.read_bytes()
        self.assertEqual(0o600, path.stat().st_mode & 0o777)
        self.assertEqual(selected, authority._runtime_authorization(bindings, create=True))
        self.assertEqual(original, path.read_bytes())
        public = json.loads(original)['publicContext']
        self.assertEqual(selected, authority.digest(public))
        for forbidden in (authority.digest(bindings), authority.digest(self.private), authority.digest(self.authorization)):
            self.assertNotIn(forbidden, json.dumps(public))
            self.assertNotEqual(forbidden, selected)
        with self.assertRaisesRegex(authority.AuthorityError, 'selection-mismatch'):
            authority._runtime_authorization({**bindings, 'privateConfigDigest': 'sha256:' + 'd' * 64})

    def test_authorize_v5_contains_no_private_hash_and_legacy_authorize_stays_v1(self):
        from cryptad_certification.tests.test_cross_version_evidence import fixture_plan
        plan = fixture_plan()
        private = {**self.private, 'root': str(self.root / 'not-created')}
        authorization = {'maxSeconds': 600, 'maxOperations': 1000, 'syntheticContent': True,
                         'private-authorization-canary': True}
        bindings = {'serviceDigest': 'sha256:' + 'c' * 64, 'planDigest': authority.digest(plan),
                    'privateConfigDigest': authority.digest(private), 'authorizationDigest': authority.digest(authorization)}
        with patch.object(authority.os, 'geteuid', return_value=0), \
                patch.object(authority, 'selected_inputs', return_value=(plan, private, authorization, os.getuid(), bindings)), \
                patch.object(authority, 'run_identity', return_value={'sourceCommit': plan['producer']['sourceCommit']}), \
                patch.object(authority, '_service_state', return_value='stopped'), \
                patch.object(authority, '_admit_product_rows', return_value=(self.activation['products'], self.rows)):
            report = authority.control('authorize')
            authority.validate_report(report)
            self.assertEqual(5, report['schemaVersion'])
            rendered = json.dumps(report)
            for forbidden in (authority.digest(bindings), authority.digest(private), authority.digest(authorization),
                              'private-selection-canary', 'private-authorization-canary'):
                self.assertNotIn(forbidden, rendered)
            self.record.unlink()
            (self.root / 'cross-version-start.json').write_text('{}')
            with patch.object(authority, 'CONFIG', self.root), \
                    patch.object(authority, 'authenticate_report', return_value=(report, {'artifactId': 87})), \
                    patch.object(authority, '_service_state', side_effect=['stopped', 'running']), \
                    patch.object(authority.os, 'chown'), patch.object(authority.subprocess, 'run'):
                started = authority.control('start')
            activation = json.loads((self.root / 'activation.json').read_bytes())
            self.assertEqual(2, activation['schemaVersion'])
            self.assertEqual(5, started['schemaVersion'])
            for forbidden in (authority.digest(bindings), authority.digest(private), authority.digest(authorization),
                              'privateConfigDigest', 'authorizationDigest', 'private-selection-canary'):
                self.assertNotIn(forbidden, json.dumps(activation))
                self.assertNotIn(forbidden, json.dumps(started))
            with patch.object(authority, 'owned_cgroup', return_value=True):
                admitted = authority.authenticate_runner(plan, private, authorization)
                self.assertEqual(authority.digest(activation), admitted.public_identity()['activationDigest'])
                with self.assertRaises(authority.AuthorityError):
                    authority.authenticate_runner(plan, {**private, 'changed': True}, authorization)
            with patch.object(authority, '_admit_product_rows', return_value=([], None)):
                legacy = authority.control('authorize')
                authority.validate_report(legacy)
                self.assertEqual(1, legacy['schemaVersion'])
                self.assertEqual(authority.digest(bindings), legacy['selectionDigest'])

    def test_finish_after_deadline_retains_exact_inputs_across_failed_handoffs_and_retry(self):
        from cryptad_certification.tests.test_cross_version_evidence import fixture_plan, fixture_events
        import maintenance_runtime_projection as projection
        plan = fixture_plan()
        rows, nodes = [], {}
        bundle = self.root / 'app.bundle'
        bundle.write_bytes(b'synthetic already-admitted app')
        app = {'appId': 'mail-prototype', 'bundleDigest': 'sha256:' + hashlib.sha256(bundle.read_bytes()).hexdigest(),
               'bundleSize': bundle.stat().st_size, 'nativeAdmission': 'accepted', 'contractVerifier': 'executed'}
        for node in plan['nodes']:
            package = self.root / node['role']
            package.write_bytes(b'candidate' if node['role'].startswith('candidate') else node['role'].encode())
            apps = [app] if node['appDigests'] else []
            node.update(artifactDigest='sha256:' + hashlib.sha256(package.read_bytes()).hexdigest(),
                        artifactSize=package.stat().st_size, appDigests=[row['bundleDigest'] for row in apps])
            rows.append({**self.rows[0], 'role': node['role'], 'artifactDigest': node['artifactDigest'],
                         'artifactSize': node['artifactSize'], 'appMatrix': apps,
                         'requiredAppIds': [row['appId'] for row in apps]})
            nodes[node['role']] = {'archivePath': str(package),
                                  'apps': [{'appId': row['appId'], 'bundleDigest': row['bundleDigest'],
                                            'bundlePath': str(bundle)} for row in apps]}
        journal = self.root / 'journal'
        journal.mkdir(mode=0o700)
        events, checkpoint = fixture_events(plan)
        (journal / 'journal.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in events))
        (journal / 'checkpoint.json').write_text(json.dumps(checkpoint))
        for path in journal.iterdir():
            path.chmod(0o600)
        private = {'root': str(journal), 'nodes': nodes}
        authorization = {'maxSeconds': 60, 'maxOperations': 1000, 'syntheticContent': True}
        bindings = {'serviceDigest': 'sha256:' + 'c' * 64, 'planDigest': authority.digest(plan),
                    'privateConfigDigest': authority.digest(private), 'authorizationDigest': authority.digest(authorization)}
        selection = authority._runtime_authorization(bindings, create=True)
        activation = {**self.activation, 'planDigest': authority.digest(plan), 'producer': plan['producer'],
                      'products': [products.public_product_identity(row) for row in rows],
                      'selectionDigest': selection, 'approvalOrigin': {'artifactId': 1},
                      'approvalReportDigest': 'sha256:' + 'd' * 64}
        self.rows, self.private, self.authorization, self.activation = rows, private, authorization, activation
        self.write_record()
        (self.root / 'activation.json').write_text(json.dumps(activation))
        (self.root / 'cross-version-previous.json').write_text('{}')
        previous = {'schemaVersion': 5, 'operation': 'start', 'experimentId': plan['experimentId'],
                    'planDigest': authority.digest(plan), 'producer': plan['producer'], 'selectionDigest': selection,
                    'approvalOrigin': activation['approvalOrigin'],
                    'admittedProductsDigest': authority.digest(activation['products'])}
        retained = {path: path.read_bytes() for path in (self.record, self.root / 'runtime-authorization.json')}
        with patch.object(authority.os, 'geteuid', return_value=0), \
                patch.object(authority, 'CONFIG', self.root), \
                patch.object(authority, 'selected_inputs', return_value=(plan, private, authorization, 0, bindings)), \
                patch.object(authority, 'run_identity', return_value={'sourceCommit': plan['producer']['sourceCommit']}), \
                patch.object(authority, 'authenticate_report', return_value=(previous, {'artifactId': 2})), \
                patch.object(authority.time, 'monotonic_ns', return_value=2000), \
                patch.object(authority, '_service_state', return_value='stopped'), \
                patch.object(projection, 'project', return_value={'schemaVersion': 4}) as project:
            with self.assertRaises(authority.AuthorityError):
                authority.AuthenticatedRunner(authority._SEAL, activation).product_admission(plan, private)
            result = authority.control('finish')
            with patch.object(authority.sys, 'argv', ['supervisor', 'finish']), \
                    patch.object(authority.sys, 'stderr', io.StringIO()):
                with patch.object(authority, 'scan_value', return_value=['synthetic-redaction-failure']):
                    self.assertEqual(2, authority.main())
                with patch.object(authority, 'scan_value', return_value=[]), \
                        patch.object(authority.sys, 'stdout') as output:
                    output.write.side_effect = OSError('synthetic-output-failure')
                    self.assertEqual(2, authority.main())
            # Upload/attestation happen after control returns and cannot acknowledge durability.
            # An unchanged original start selection can collect again without reconstructing state.
            self.assertEqual(result, authority.control('finish'))
            for path, raw in retained.items():
                self.assertEqual(raw, path.read_bytes())
        self.assertEqual('finish', result['operation'])
        self.assertEqual(authority.digest(checkpoint), result['checkpoint']['digest'])
        self.assertEqual('complete', result['checkpoint']['status'])
        self.assertEqual(events, project.call_args.args[1])
        self.assertEqual(rows, project.call_args.args[3])
        self.assertTrue(self.record.exists())
        self.assertTrue((self.root / 'runtime-authorization.json').exists())

    def test_terminal_read_capability_is_root_only_stopped_bounded_and_cannot_resume_execution(self):
        with self.assertRaises(authority.AuthorityError):
            authority.TerminalEvidence(None, self.activation)
        with patch.object(authority.os, 'geteuid', return_value=0), \
                patch.object(authority, '_service_state', return_value='stopped'), \
                patch.object(authority.time, 'monotonic_ns', return_value=2000):
            with authority.TerminalEvidence(authority._SEAL, self.activation) as terminal:
                self.assertEqual(self.rows, terminal.rows(self.activation))
                with self.assertRaises(authority.AuthorityError):
                    authority.AuthenticatedRunner(authority._SEAL, self.activation).product_admission(self.plan, self.private)
                with patch.object(authority.time, 'monotonic_ns', return_value=120 * 10**9 + 2001):
                    with self.assertRaises(authority.AuthorityError):
                        terminal.rows(self.activation)
                with patch.object(authority, '_service_state', return_value='running'):
                    with self.assertRaises(authority.AuthorityError):
                        terminal.rows(self.activation)
            with self.assertRaises(authority.AuthorityError):
                terminal.rows(self.activation)


class RuntimeOwnerTest(unittest.TestCase):
    def test_original_materialization_lives_until_capability_closes(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'interop'))
        import cross_version_runtime as runtime
        roots = []
        class Admission:
            def bind(self, plan, private):
                return True
            def close(self):
                pass
        def authenticate(plan, selection, root):
            root.mkdir()
            (root / 'private').write_bytes(b'private-native-context')
            roots.append(root)
            return Admission()
        module = SimpleNamespace(AuthenticatedProducts=Admission, authenticate_products=authenticate)
        with patch.object(runtime, 'fixed_helper_imports', side_effect=contextlib.nullcontext), \
                patch.object(runtime, 'fixed_helper', return_value=module):
            admitted = runtime.authenticate_product_selection({}, {'productAdmission': {}})
        self.assertTrue((roots[0] / 'private').is_file())
        admitted.close()
        self.assertFalse(roots[0].exists())


if __name__ == '__main__':
    unittest.main()

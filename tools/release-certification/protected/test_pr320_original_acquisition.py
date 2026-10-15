"""Offline root acquisition boundary tests; no service, daemon, VM, or credential I/O."""
from contextlib import ExitStack
import copy
import inspect
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import pr320_original_acquisition as acquisition
import pr320_budget_contract as common


def encode(value):
    return acquisition._encode(value)


def manager(**changes):
    result = {'ActiveState': 'inactive', 'SubState': 'dead', 'InvocationID': 'a' * 32,
              'MainPID': '0', 'ControlGroup': '', 'Result': 'success',
              'ExecMainCode': '1', 'ExecMainStatus': '0'}
    result.update(changes)
    return result


class InputBoundaryTests(unittest.TestCase):
    def test_public_begin_and_collect_cannot_accept_caller_originals_or_paths(self):
        self.assertEqual({}, dict(inspect.signature(acquisition.begin_owned).parameters))
        self.assertEqual({}, dict(inspect.signature(acquisition.collect_owned).parameters))
        with self.assertRaises(TypeError): acquisition.begin_owned(originals={'claim': True})
        with self.assertRaises(acquisition.AcquisitionError):
            acquisition.OwnedAcquisitionCapture(object(), {}, 'activation', 'plan', {})

    def test_local_checkout_cannot_execute_protected_helper(self):
        with self.assertRaises(acquisition.AcquisitionError): acquisition._installed()

    def test_configuration_closes_execution_class_and_digest_fields(self):
        value = {'schemaVersion': 1, 'kind': 'pr320-original-acquisition-selection',
            'executionClass': common.CANCELLATION_EXECUTION_CLASS,
            'fixtureManifestDigest': '1' * 64, 'candidateCommit': '2' * 40,
            'planDigest': 'sha256:' + '3' * 64, 'verifierDigest': 'sha256:' + '4' * 64}
        def validate(selected):
            raw = encode(selected)
            record = {'configurationFiles': {str(acquisition.CONFIG):
                {'digest': acquisition._digest(raw), 'size': len(raw)}}}
            with patch.object(acquisition, '_read', return_value=raw):
                return acquisition._configuration(record)
        self.assertEqual(value, validate(value))
        for field, replacement in (('schemaVersion', True), ('executionClass', 'pr320-storage-any-v1'),
            ('candidateCommit', 'HEAD'), ('fixtureManifestDigest', '../file'), ('planDigest', 'x')):
            changed = {**value, field: replacement}
            with self.subTest(field=field), self.assertRaises(ValueError): validate(changed)
        with self.assertRaises(ValueError): validate({**value, 'originals': {}})
        with patch.object(acquisition, '_read', return_value=encode(value)):
            with self.assertRaises(ValueError): acquisition._configuration({'configurationFiles': {}})

    def test_strict_json_rejects_duplicate_keys_and_nonfinite_numbers(self):
        for raw in (b'{"a":1,"a":2}', b'{"value":NaN}', b'{"value":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError): acquisition._json(raw)

    def test_descriptor_capture_is_exclusive_readonly_and_rejects_aliases(self):
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(acquisition, '_trusted', side_effect=lambda path, **_: Path(path)):
            root = Path(temporary)
            target = root / 'original.json'
            acquisition._write(target, b'actual original')
            self.assertEqual(0o400, target.stat().st_mode & 0o777)
            self.assertEqual(b'actual original', acquisition._read(target, 32))
            with self.assertRaises(FileExistsError): acquisition._write(target, b'replaced')
            alias = root / 'alias.json'
            os.link(target, alias)
            with self.assertRaises(ValueError): acquisition._read(target, 32)
            alias.unlink()
            alias.symlink_to(target)
            with self.assertRaises(OSError): acquisition._read(alias, 32)
            with self.assertRaises(ValueError): acquisition._read(target, 2)

    def test_same_kernel_clock_brackets_are_actual_and_do_not_claim_vm_stop(self):
        import pr318_storage_runtime_runner as owner
        sample = acquisition._clock()
        self.assertEqual(sample, owner._clock_sample(sample))
        self.assertLessEqual(sample['hostEpochBeforeNanos'], sample['guestEpochNanos'])
        self.assertLessEqual(sample['guestEpochNanos'], sample['hostEpochAfterNanos'])

    def test_stopped_service_requires_successful_real_exit(self):
        self.assertTrue(acquisition._stopped(manager()))
        for field, value in (('ActiveState', 'active'), ('MainPID', '123'), ('Result', 'timeout'),
                             ('ExecMainStatus', '1'), ('ExecMainCode', '2')):
            with self.subTest(field=field): self.assertFalse(acquisition._stopped(manager(**{field: value})))

    def test_historical_git_source_is_unchanged_and_installed_seam_requires_a_sealed_verifier(self):
        import pr318_storage_selection as historical
        import cross_version_runtime as runtime
        source, root = Path('/ordinary/source'), Path('/root/cryptad/build/pr320-owner-inputs/inputs')
        with patch.object(historical.subprocess, 'check_output', return_value='a' * 40 + '\n') as git:
            self.assertEqual(('a' * 40, source / 'platform-devtools/build/install/crypta-app'),
                             historical._source_verifier_identity(source, root, 'ignored'))
            git.assert_called_once_with(['git', '-c', 'safe.directory=' + str(source), '-C', str(source),
                                         'rev-parse', 'HEAD'], text=True, timeout=10)
        with self.assertRaises(ValueError):
            historical._source_verifier_identity(acquisition.CHECKOUT, root, 'digest', {'claimed': 'installed'})
        identity = {'sourceCommit': 'a' * 40, 'bundleIdentity': 'b' * 64}
        digest = 'sha256:' + 'c' * 64
        verifier = root.parent / 'verifier'
        with patch.object(acquisition.os, 'geteuid', return_value=0):
            cap = acquisition.InstalledFixtureSource(acquisition._SEAL, identity, verifier, digest)
        with patch.object(acquisition, '_installed', return_value=identity), \
                patch.object(acquisition, '_trusted'), \
                patch.object(runtime, 'tree_digest', return_value=digest) as tree, \
                patch.object(historical.subprocess, 'check_output') as git:
            self.assertEqual(('a' * 40, verifier),
                historical._source_verifier_identity(acquisition.CHECKOUT, root, digest, cap))
            tree.assert_called_once_with(verifier, require_java=False)
            git.assert_not_called()
            for changed in (('source', Path('/other/source')), ('digest', 'sha256:' + 'd' * 64)):
                with self.subTest(fault=changed[0]), self.assertRaises(ValueError):
                    cap.require(changed[1] if changed[0] == 'source' else acquisition.CHECKOUT,
                                root, changed[1] if changed[0] == 'digest' else digest)
        with self.assertRaises(ValueError): cap._source_commit = 'changed'

    def test_privacy_original_times_are_bracketed_by_this_actual_root_acquisition(self):
        from test_pr318_storage_installed import clock_sample
        before, after = clock_sample(1000 * 10**9, 100 * 10**9), clock_sample(2000 * 10**9, 1100 * 10**9)
        originals = {'receipts': [{'kind': 'pr320-original-privacy-readback',
            'capturedMonotonicNs': 200 * 10**9, 'observedMonotonicNs': 210 * 10**9,
            'boundaryEvidence': {'expiredSession': {'observedMonotonicNs': 900 * 10**9,
                                                   'observedEpochNs': 1800 * 10**9}}},
            {'kind': 'pr320-original-browser-observation', 'startedMonotonicNs': 950 * 10**9,
             'finishedMonotonicNs': 1000 * 10**9, 'capturedMonotonicNs': 1010 * 10**9}]}
        acquisition._privacy_clock_binding(originals, before, after)
        for field, value in (('capturedMonotonicNs', before['hostMonotonicBeforeNanos'] - 1),
                ('observedMonotonicNs', after['hostMonotonicAfterNanos'] + 1)):
            changed = copy.deepcopy(originals)
            changed['receipts'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                acquisition._privacy_clock_binding(changed, before, after)
        for field, value in (('observedMonotonicNs', 50 * 10**9), ('observedEpochNs', 900 * 10**9),
                             ('observedEpochNs', 2100 * 10**9), ('observedEpochNs', True)):
            changed = copy.deepcopy(originals)
            changed['receipts'][0]['boundaryEvidence']['expiredSession'][field] = value
            with self.subTest(boundary=field, value=value), self.assertRaises(ValueError):
                acquisition._privacy_clock_binding(changed, before, after)
        changed = copy.deepcopy(originals)
        changed['receipts'][1]['capturedMonotonicNs'] = 1200 * 10**9
        with self.assertRaises(ValueError): acquisition._privacy_clock_binding(changed, before, after)
        component = {'surfaces': {'workSnapshot': {'events': [{'observedAt': '1970-01-01T00:25:00.123456789Z'}]}}}
        acquisition._privacy_clock_binding(originals, before, after, component=component)
        for stamp in ('1970-01-01T00:15:00Z', '1970-01-01T00:35:00Z', '1970-01-01T00:25:00+01:00', True):
            changed = copy.deepcopy(component)
            changed['surfaces']['workSnapshot']['events'][0]['observedAt'] = stamp
            with self.subTest(event_stamp=stamp), self.assertRaises(ValueError):
                acquisition._privacy_clock_binding(originals, before, after, component=changed)

    def test_merged_source_reader_checks_exact_product_and_complete_kit_bytes(self):
        import hashlib
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            product, kit = root / 'product', root / 'kit'
            production_name = 'tools/release-certification/protected/pr320_budget_contract.py'
            kit_name = 'tools/release-certification/restricted/pr320_owner_selection.py'
            for base, name, raw in ((product, production_name, b'fixed product source'),
                                    (kit, kit_name, b'fixed separate kit source')):
                path = base / name
                path.parent.mkdir(parents=True, mode=0o700)
                path.write_bytes(raw)
            manifest = {'sourceCommit': 'a' * 40, 'files': {production_name: {
                'sha256': hashlib.sha256((product / production_name).read_bytes()).hexdigest()}}}
            manifest_raw = encode(manifest)
            (product / '.restricted-manifest.json').write_bytes(manifest_raw)
            kit_manifest = {'schemaVersion': 1, 'kind': 'synthetic-disposable-test-kit',
                'productionEligible': False, 'sourceCommit': 'a' * 40, 'files': {
                    kit_name: hashlib.sha256((kit / kit_name).read_bytes()).hexdigest()}}
            (kit / '.test-kit.json').write_bytes(encode(kit_manifest))
            identity = {'sourceCommit': 'a' * 40, 'bundleIdentity': hashlib.sha256(manifest_raw).hexdigest()}
            original_path = list(acquisition.sys.path)
            try:
                with patch.object(acquisition, 'CHECKOUT', product), patch.object(acquisition, 'KIT', kit), \
                        patch.object(acquisition, '_KIT_VERIFIED', None), \
                        patch.object(acquisition, '_trusted', side_effect=lambda path, **_: Path(path)):
                    self.assertEqual(product / production_name, acquisition._tool_path(production_name, identity))
                    self.assertEqual(kit / kit_name, acquisition._tool_path(kit_name, identity))
                    (kit / kit_name).write_bytes(b'replaced kit source')
                    with self.assertRaises(ValueError): acquisition._tool_path(kit_name, identity)
                    with self.assertRaises(ValueError): acquisition._verified_kit('a' * 40, force=True)
                    (kit / kit_name).write_bytes(b'fixed separate kit source')
                    (kit / 'unexpected.py').write_bytes(b'unregistered executable')
                    with self.assertRaises(ValueError): acquisition._verified_kit('a' * 40, force=True)
                    with self.assertRaises(ValueError): acquisition._tool_path('../outside', identity)
            finally: acquisition.sys.path[:] = original_path


class AcquisitionLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.configuration = {'schemaVersion': 1, 'kind': 'pr320-original-acquisition-selection',
            'executionClass': common.CANCELLATION_EXECUTION_CLASS,
            'fixtureManifestDigest': '1' * 64, 'candidateCommit': '2' * 40,
            'planDigest': acquisition._digest(encode({'nodes': []})), 'verifierDigest': 'sha256:' + '4' * 64}
        self.selected = {'plan': {'nodes': []}, 'private': {}, 'authorization': {
            'maxSeconds': 3600, 'budgetSelection': {'toolIdentities': {}}}}
        import restricted_worker as worker
        import datetime as dt
        self.record = {'method': 'budget-acquisition-begin', 'context': {
            'sourceCommit': 'c' * 40, 'runId': 1, 'runAttempt': 2, 'jobId': 3},
            'bundleIdentity': 'b' * 64,
            'inputFiles': {'fixture/manifest.private.json': {'digest': 'sha256:' + 'd' * 64, 'size': 1}},
            'expiresAt': (worker.now() + dt.timedelta(hours=3)).isoformat()}
        self.context = {'operationId': 'a' * 64, 'registrationDigest': 'sha256:' + 'd' * 64,
                        'bundleIdentity': 'b' * 64, 'deadlineMonotonic': acquisition.time.monotonic() + 800}
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.activation = {'deadlineMonotonicNs': acquisition.time.monotonic_ns() + 9000 * 10**9}
        for change in (patch.object(acquisition, 'ROOT', self.root / 'acquisition'),
                patch.object(acquisition, 'SELECTION', self.root / 'selection.json'),
                patch.object(acquisition, 'WORKLOAD', self.root / 'workload'),
                patch.object(acquisition, '_trusted', side_effect=lambda path, **_: Path(path)),
                patch.object(acquisition, '_installed', return_value={'sourceCommit': 'c' * 40, 'bundleIdentity': 'b' * 64}),
                patch.object(acquisition, '_verify_unit'),
                patch.object(acquisition, '_kit_driver'),
                patch.object(acquisition, '_boundary', side_effect=lambda: (self.context, self.record, self.root)),
                patch.object(acquisition, '_configuration', side_effect=lambda _: self.configuration),
                patch.object(acquisition, '_fixture_factory', side_effect=lambda *_: self.selected),
                patch.object(acquisition, '_prepared_selection', side_effect=lambda *_: self.selected),
                patch.object(acquisition, '_preparation_request', side_effect=lambda: ({
                    'inputFiles': self.record['inputFiles']}, {}, self.root)),
                patch.object(acquisition, '_activation', side_effect=lambda _: self.activation),
                patch.object(acquisition, '_boot', return_value='00000000-0000-0000-0000-000000000001')):
            self.stack.enter_context(change)
        self.unit = self.stack.enter_context(patch.object(acquisition, '_manager', return_value=manager()))
        acquisition._write(acquisition.SELECTION, encode(self.selected))

    def test_begin_freezes_current_registration_and_starts_only_the_fixed_unit(self):
        public = acquisition.begin_owned()
        self.assertEqual({'status', 'acquisitionId'}, set(public))
        self.assertEqual('started', public['status'])
        directory, start = acquisition._active()
        self.assertEqual(public['acquisitionId'], directory.name)
        self.assertEqual(self.record['context'], start['job'])
        self.assertEqual(self.context['registrationDigest'], start['registrationDigest'])
        self.assertEqual(self.configuration['planDigest'], start['planDigest'])
        self.assertEqual(encode(self.selected), acquisition.SELECTION.read_bytes())
        self.assertEqual(0o400, (directory / 'start.json').stat().st_mode & 0o777)
        self.unit.assert_any_call('start')
        with self.assertRaises(ValueError): acquisition.begin_owned()

    def test_existing_pool_or_selection_is_never_deleted_or_reused(self):
        acquisition.WORKLOAD.write_bytes(b'retained failed attempt')
        with self.assertRaises(ValueError): acquisition.begin_owned()
        self.assertEqual(b'retained failed attempt', acquisition.WORKLOAD.read_bytes())
        acquisition.WORKLOAD.unlink()
        self.record['method'] = 'budget-acquisition-prepare'
        with self.assertRaises(ValueError): acquisition.prepare_owned()
        self.assertEqual(encode(self.selected), acquisition.SELECTION.read_bytes())

    def test_preparation_precedes_activation_and_retains_original_input_registration(self):
        acquisition.SELECTION.unlink()
        self.record['method'] = 'budget-acquisition-prepare'
        with patch.object(acquisition, '_state_selection') as state:
            public = acquisition.prepare_owned()
        self.assertEqual({'status', 'acquisitionId'}, set(public))
        self.assertEqual('started', public['status'])
        state.assert_not_called()
        prepared = json.loads((acquisition.ROOT / 'prepare-request.json').read_bytes())
        self.assertEqual(self.record['inputFiles'], prepared['inputFiles'])
        self.assertEqual(self.configuration, prepared['configuration'])
        self.assertEqual(self.record['context'], prepared['job'])
        self.assertFalse(acquisition.SELECTION.exists())
        self.assertFalse((acquisition.ROOT / 'prepared.json').exists())
        self.assertFalse((acquisition.ROOT / 'active.json').exists())

    def test_begin_rejects_different_plan_or_insufficient_activation_deadline(self):
        self.configuration['planDigest'] = 'sha256:' + 'f' * 64
        with self.assertRaises(ValueError): acquisition.begin_owned()
        self.configuration['planDigest'] = acquisition._digest(encode(self.selected['plan']))
        self.activation['deadlineMonotonicNs'] = acquisition.time.monotonic_ns() + 10**9
        with self.assertRaises(ValueError): acquisition.begin_owned()
        self.assertFalse((acquisition.ROOT / 'active.json').exists())

    def test_collect_is_metadata_only_and_binds_the_original_job(self):
        public = acquisition.begin_owned()
        self.record['method'] = 'budget-acquisition-collect'
        self.assertEqual({'status': 'running', 'acquisitionId': public['acquisitionId']},
                         acquisition.collect_owned())
        self.unit.return_value = manager(ActiveState='failed', Result='signal')
        self.assertEqual('failed', acquisition.collect_owned()['status'])
        self.record['context'] = {**self.record['context'], 'jobId': 4}
        self.assertEqual('failed', acquisition.collect_owned()['status'])
        self.record['context'] = {**self.record['context'], 'sourceCommit': 'f' * 40}
        with self.assertRaises(ValueError): acquisition.collect_owned()

    def test_capture_object_is_frozen_and_nonterminal_dictionary_cannot_unlock_it(self):
        with patch.object(acquisition.os, 'geteuid', return_value=0):
            cap = acquisition.OwnedAcquisitionCapture(acquisition._SEAL, {'root-capture.json': b'{}'},
                'activation', 'plan', {'bootId': 'original'})
        with self.assertRaises(ValueError): cap._activation = 'changed'
        with self.assertRaises(ValueError): cap.members({}, {}, {'terminal': 'asserted'})


class FixedServiceTests(unittest.TestCase):
    def test_service_is_async_fixed_root_source_and_has_no_request_arguments(self):
        path = Path(__file__).resolve().parents[1] / 'restricted/systemd' / acquisition.BUDGET_UNIT
        text = path.read_text()
        settings = dict(row.split('=', 1) for row in text.splitlines() if '=' in row)
        self.assertEqual('exec', settings['Type'])
        self.assertEqual('root', settings['User'])
        self.assertEqual('/usr/bin/python3 -I -S -B /opt/cryptad-cross-version/current/tools/'
                         'release-certification/protected/pr320_original_acquisition.py', settings['ExecStart'])
        self.assertEqual('no', settings['Restart'])
        self.assertEqual('null', settings['StandardOutput'])
        self.assertEqual('null', settings['StandardError'])
        self.assertGreater(int(settings['RuntimeMaxSec']), 7200)
        self.assertEqual('control-group', settings['KillMode'])

    def test_fixed_child_polling_retains_failure_and_uses_only_owned_teardown(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            start = {'deadlineMonotonicNs': acquisition.time.monotonic_ns() + 60 * 10**9}
            with ExitStack() as stack:
                for change in (patch.object(acquisition, 'ROOT', directory),
                    patch.object(acquisition, '_installed'), patch.object(acquisition, '_verify_unit'),
                    patch.object(acquisition, '_active', return_value=(directory, start)),
                    patch.object(acquisition, '_trusted', side_effect=lambda path, **_: Path(path)),
                    patch.object(acquisition, '_manager', return_value=manager(
                        MainPID=str(os.getpid()), ControlGroup='/system.slice/' + acquisition.BUDGET_UNIT)),
                    patch.object(acquisition.os, 'fork', return_value=123456),
                    patch.object(acquisition.os, 'waitpid', return_value=(123456, 256)),
                    patch.object(acquisition, '_boot', return_value='actual-test-boot')):
                    stack.enter_context(change)
                # An immutable private start marker exists; the child is a transport mock.
                (directory / 'active.json').write_bytes(b'original-start')
                teardown = stack.enter_context(patch.object(acquisition, '_stop_fixed_roles'))
                kill = stack.enter_context(patch.object(acquisition.os, 'kill'))
                with self.assertRaises(ValueError): acquisition.run_service()
                teardown.assert_called_once_with()
                kill.assert_not_called()
            failure = directory / 'failed.json'
            self.assertEqual(0o400, failure.stat().st_mode & 0o777)
            self.assertTrue(json.loads(failure.read_bytes())['reconciliationRequired'])
            self.assertFalse((directory / 'complete.json').exists())

    def test_preparation_collection_never_reports_prepared_before_successful_unit_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            request = {'preparationId': '00000000-0000-0000-0000-000000000001',
                       'configuration': {'fixed': 'configuration'}, 'inputFiles': {'fixed': 'original'},
                       'sourceCommit': 'a' * 40, 'bundleIdentity': 'b' * 64}
            record = {'method': 'budget-acquisition-collect', 'inputFiles': request['inputFiles'],
                      'context': {'sourceCommit': request['sourceCommit']}, 'bundleIdentity': request['bundleIdentity']}
            with patch.object(acquisition, 'ROOT', root), patch.object(acquisition, '_installed'), \
                    patch.object(acquisition, '_verify_unit'), \
                    patch.object(acquisition, '_boundary', return_value=({}, record, root)), \
                    patch.object(acquisition, '_preparation_request', return_value=(request, {}, root)), \
                    patch.object(acquisition, '_configuration', return_value=request['configuration']), \
                    patch.object(acquisition, '_manager', return_value=manager(ActiveState='active')) as unit:
                (root / 'prepared.json').write_bytes(b'retained-root-preparation')
                self.assertEqual('running', acquisition.collect_owned()['status'])
                unit.return_value = manager(Result='exit-code', ExecMainStatus='1')
                self.assertEqual('failed', acquisition.collect_owned()['status'])
                unit.return_value = manager()
                public = acquisition.collect_owned()
                self.assertEqual({'status': 'prepared', 'acquisitionId': request['preparationId']}, public)

    def test_actual_partial_journal_verifier_rejects_lineage_and_checkpoint_replacement(self):
        from cryptad_certification import cross_version_evidence as evidence
        from cryptad_certification import composed_budget_journal_member as members
        from cryptad_certification.tests.test_composed_budget_journal_member import fixture
        plan, component, _tools = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with evidence.Journal(root, plan) as journal:
                journal.append('node-start', role='candidate-sender', node_epoch=component['bindings']['nodeEpoch'])
                members.append_member(journal, 'route-component', encode(component))
                journal.checkpoint('partial')
            raw, checkpoint = (root / 'journal.jsonl').read_bytes(), (root / 'checkpoint.json').read_bytes()
        events, actual_checkpoint = acquisition._verify_journal(plan, raw, checkpoint)
        self.assertEqual('partial', actual_checkpoint['status'])
        events[1]['previousDigest'] = 'sha256:' + '0' * 64
        with self.assertRaises(ValueError):
            acquisition._verify_journal(plan, b'\n'.join(encode(row) for row in events), checkpoint)
        substituted = {**actual_checkpoint, 'sequence': actual_checkpoint['sequence'] - 1}
        with self.assertRaises(ValueError): acquisition._verify_journal(plan, raw, encode(substituted))
        with self.assertRaises(ValueError):
            acquisition._verify_journal(plan, raw, encode({**actual_checkpoint, 'status': 'failed'}))

    def test_root_capability_returns_only_actual_committed_owner_originals(self):
        from cryptad_certification import cross_version_evidence as evidence
        from cryptad_certification import composed_budget_journal_member as members
        from test_pr320_campaign_capture import fixture
        import test_pr320_owner_installed as owner_fixtures
        from cryptad_certification.tests.test_cross_version_evidence import fixture_plan
        from test_pr318_storage_installed import resign
        from cross_version_supervisor_authority import TerminalEvidence
        import base64
        original_selection = owner_fixtures.owner_selection
        def full_selection():
            selected = original_selection()
            plan, base = selected['plan'], fixture_plan()
            for name, value in base.items(): plan.setdefault(name, value)
            for name, value in base['producer'].items(): plan['producer'].setdefault(name, value)
            for node in plan['nodes']:
                template = next(row for row in base['nodes'] if row['role'] == node['role'])
                for name, value in template.items(): node.setdefault(name, value)
            resign(plan, selected['authorization'])
            return selected
        with patch.object(owner_fixtures, 'owner_selection', side_effect=full_selection):
            capsule = fixture()
        from test_pr316_mail_runtime_runner import terminal as cleanup_fixture
        cleanup = cleanup_fixture()
        sender = cleanup['controllerRecords']['candidate-sender']['record']
        sender.update(capsule['originals']['terminal']['controllerRecords']['candidate-sender']['record'])
        cleanup['stopReceipts']['candidate-sender']['current']['record'] = {
            **sender, 'membership': 'only-stop-helper', 'descendantCgroups': 0}
        capsule['originals']['terminal'] = cleanup
        originals, plan = capsule['originals'], capsule['originals']['selected']['plan']
        private = json.loads(base64.b64decode(originals['private']))
        raw_member = encode(private['composedBudgetEvidence'])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with evidence.Journal(root, plan) as journal:
                journal.append('node-start', role='candidate-sender', node_epoch=private['composedBudgetEvidence']['nodeEpoch'])
                members.append_member(journal, 'legacy-attachment', raw_member)
                journal.checkpoint('partial')
            raw_journal, checkpoint = (root / 'journal.jsonl').read_bytes(), (root / 'checkpoint.json').read_bytes()
        activation = {'fixture': 'activation'}
        raws = {'root-capture.json': encode(capsule), 'native-report.json': encode({
                    'schemaVersion': 1, 'kind': 'pr320-root-native-original-report'}),
                'journal.jsonl': raw_journal, 'checkpoint.json': checkpoint}
        start = {'bootId': 'actual-test-boot'}
        # Synthetic terminal capability is an offline policy boundary; the actual owner
        # original validator, typed root decoder and immutable journal checks remain real.
        terminal = object.__new__(TerminalEvidence)
        with patch.object(acquisition.os, 'geteuid', return_value=0), \
                patch.object(acquisition, '_boot', return_value=start['bootId']), \
                patch.object(acquisition, '_manager', return_value=manager()), \
                patch.object(acquisition, '_revalidate'), \
                patch.object(TerminalEvidence, 'require'):
            cap = acquisition.OwnedAcquisitionCapture(acquisition._SEAL, raws,
                acquisition._digest(encode(activation)), acquisition._digest(encode(plan)), start)
            actual = cap.members(activation, plan, terminal)
            self.assertEqual(1, len(actual))
            self.assertEqual('member-07.json', actual[0]['member'])
            self.assertEqual(raw_member, actual[0]['raw'])
            self.assertEqual(originals['native'], actual[0]['originals']['native'])
            with self.assertRaises(ValueError): cap.members({'different': 'activation'}, plan, terminal)
            self.assertEqual(encode(capsule), dict(cap._raw)['root-capture.json'])


if __name__ == '__main__': unittest.main()

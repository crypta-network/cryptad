"""Offline PR-317 fixed selection tests; no installed or protected execution claim."""
from contextlib import nullcontext
import copy
import json
import base64
import hashlib
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import pr315_workload_guest as guest
import pr317_budget_selection as selection
import bounded_process


def closed_selection():
    tools = {key: 'sha256:' + format(index, 'x')[-1] * 64
             for index, key in enumerate(selection.TOOL_PATHS, 1)}
    bundles = {app_id: 'sha256:' + str(index + 1) * 64
               for index, app_id in enumerate(selection.APP_IDS)}
    nodes = []
    private_nodes = {}
    for index, role in enumerate(selection.ROLES):
        apps = ([{'appId': app_id, 'bundlePath': '/fixed/' + app_id + '.zip',
                  'bundleDigest': bundles[app_id]} for app_id in selection.APP_IDS]
                if role == 'candidate-sender' else [])
        nodes.append({'role': role, 'configDigest': 'sha256:' + str(index + 5) * 64,
                      'appDigests': ([bundles[app_id] for app_id in selection.APP_IDS]
                                     if role == 'candidate-sender' else [])})
        private_nodes[role] = {'apps': apps, 'trustedKeysDigest': 'sha256:' + 'a' * 64}
    private_nodes['candidate-sender'].update(
        budgetStatementPath='/fixed/statement.json',
        budgetStatementDigest='sha256:' + 'b' * 64)
    collector = selection.canonical_digest({key: tools[key] for key in
        ('installedDriver', 'localBudgetAdapter', 'schedulerRuntime', 'evidenceOracle')})
    configuration = selection.canonical_digest({
        'nodeConfigDigest': nodes[0]['configDigest'],
        'environment': selection.ENVIRONMENT,
        'normalizedConfiguration': selection.NORMALIZED_CONFIGURATION})
    plan = {'experimentId': selection.EXPERIMENT, 'nodes': nodes,
            'workloadInputs': {'scheduler': tools['installedDriver']},
            'composedBudgetInputs': {'collectorDigest': collector,
                                     'configurationDigest': configuration}}
    private = {'root': '/var/lib/cryptad-cross-version/experiments/' + selection.EXPERIMENT,
               'nodes': private_nodes}
    budget = {'schemaVersion': 1, 'caseIds': list(selection.CASES),
        'appRoster': {'candidate-sender': list(selection.APP_IDS),
                      'candidate-recipient': [], 'previous': [], 'relay-no-apps': []},
        'permissions': {key: list(value) for key, value in selection.PERMISSIONS.items()},
        'appBundleDigests': bundles, 'trustedKeysDigest': 'sha256:' + 'a' * 64,
        'statementDigest': 'sha256:' + 'b' * 64,
        'environment': dict(selection.ENVIRONMENT),
        'normalizedConfiguration': selection.NORMALIZED_CONFIGURATION,
        'failurePolicy': dict(selection.FAILURE_POLICY), 'toolIdentities': tools,
        'composedBudgetInputs': dict(plan['composedBudgetInputs']),
        'privateRootClass': 'controller-derived-' + selection.EXPERIMENT}
    authorization = {'executionClass': selection.EXECUTION_CLASS,
        'experimentId': selection.EXPERIMENT, 'root': private['root'],
        'planDigest': selection.canonical_digest(plan), 'budgetSelection': budget}
    authorization['selectionDigest'] = selection.canonical_digest({
        'executionClass': selection.EXECUTION_CLASS,
        'planDigest': authorization['planDigest'], 'budgetSelection': budget})
    return plan, private, authorization


class SelectionContractTest(unittest.TestCase):
    def test_materializer_builds_exact_four_role_plan_and_class_bound_authorization(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            apps = {app_id: 'sha256:' + str(index) * 64
                    for index, app_id in enumerate(selection.APP_IDS, 1)}
            products = {name: {'sourceCommit': marker * 40,
                'artifactDigest': 'sha256:' + marker * 64, 'artifactSize': 100,
                'packageTarget': 'linux-x64', 'contractVersion': 26}
                for name, marker in (('candidate', 'a'), ('previous', 'b'))}
            selected = {'products': products, 'runtimeDigest': 'sha256:' + 'c' * 64,
                'apps': apps, 'trustDigest': 'sha256:' + 'd' * 64,
                'statementDigest': 'sha256:' + 'e' * 64,
                'toolIdentities': {key: 'sha256:' + format(index + 4, 'x')[-1] * 64
                    for index, key in enumerate(selection.TOOL_PATHS)},
                'maxSeconds': 600, 'maxOperations': 1000}
            runner = {'sourceCommit': 'f' * 40, 'runnerDigest': 'sha256:' + 'f' * 64,
                      'adapterDigest': 'sha256:' + '9' * 64}
            with patch.object(selection, 'FIXED_GUEST_ROOT', root), \
                    patch.object(selection.os, 'geteuid', return_value=0), \
                    patch.object(selection, 'verify', return_value=selected), \
                    patch.object(selection.preparation, 'configuration_identity',
                        side_effect=lambda role, _trust, _class: 'sha256:'
                            + str(selection.ROLES.index(role) + 5) * 64) as configuration, \
                    patch.object(selection.runtime, 'runner_identity', return_value=runner):
                materialized = selection.materialize_selection(
                    root, root, 'a' * 64, 'b' * 40)
        plan, private, authorization = (materialized[key]
            for key in ('plan', 'private', 'authorization'))
        self.assertEqual(selection.EXPERIMENT, plan['experimentId'])
        self.assertEqual(list(selection.ROLES), [row['role'] for row in plan['nodes']])
        self.assertEqual(list(selection.APP_IDS), [row['appId'] for row in
            private['nodes']['candidate-sender']['apps']])
        self.assertTrue(all(private['nodes'][role]['apps'] == []
                            for role in selection.ROLES[1:]))
        empty_trust_digest = 'sha256:' + hashlib.sha256(b'').hexdigest()
        for role in selection.ROLES:
            expected_trust = (selected['trustDigest'] if role == 'candidate-sender'
                              else empty_trust_digest)
            self.assertEqual(expected_trust, private['nodes'][role]['trustedKeysDigest'])
            configuration.assert_any_call(role, expected_trust, selection.EXECUTION_CLASS)
        self.assertEqual(list(selection.CASES),
                         authorization['budgetSelection']['caseIds'])
        self.assertTrue(selection.verify_selection_contract(plan, private, authorization))

    def test_exact_class_roster_cases_configuration_and_failure_policy_pass(self):
        plan, private, authorization = closed_selection()
        self.assertTrue(selection.verify_selection_contract(plan, private, authorization))
        self.assertEqual({'collectorDigest', 'configurationDigest'},
                         set(plan['composedBudgetInputs']))
        self.assertEqual(list(selection.APP_IDS),
                         authorization['budgetSelection']['appRoster']['candidate-sender'])
        self.assertTrue(all(not authorization['budgetSelection']['appRoster'][role]
                            for role in selection.ROLES[1:]))

    def test_wrong_selection_role_app_signature_permission_and_tool_are_rejected(self):
        changes = {
            'selection': lambda plan, private, authorization:
                authorization.update(selectionDigest='sha256:' + '0' * 64),
            'role': lambda plan, private, authorization:
                authorization['budgetSelection']['appRoster'].update(previous=['feed-reader']),
            'app': lambda plan, private, authorization:
                private['nodes']['candidate-sender']['apps'][0].update(appId='mail-prototype'),
            'signature': lambda plan, private, authorization:
                authorization['budgetSelection'].update(statementDigest='sha256:' + '0' * 64),
            'permission': lambda plan, private, authorization:
                authorization['budgetSelection']['permissions'].update(
                    {'budget-no-fetch': ['content.fetch']}),
            'tool': lambda plan, private, authorization:
                authorization['budgetSelection']['toolIdentities'].update(
                    {'installedDriver': 'sha256:' + '0' * 64}),
            'plan': lambda plan, private, authorization:
                plan.update(unboundPlanValue='substituted'),
            'app-digest': lambda plan, private, authorization:
                plan['nodes'][0]['appDigests'].__setitem__(0, 'sha256:' + '0' * 64),
        }
        for name, change in changes.items():
            plan, private, authorization = closed_selection()
            change(plan, private, authorization)
            with self.subTest(name=name):
                self.assertFalse(selection.verify_selection_contract(
                    plan, private, authorization))

    def test_manifest_permissions_and_non_java_fixture_shape_are_exact(self):
        properties = {
            'app.id': 'feed-reader',
            'app.exec': 'bin/start.sh',
            'app.permissions': ','.join(selection.PERMISSIONS['feed-reader']),
            'sandbox.mode': 'restricted-process', 'sandbox.required': 'true',
            'api.targetStability': 'experimental',
            'api.experimentalCapabilitiesAccepted': 'true'}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'bin').mkdir()
            (root / 'bin/start.sh').write_bytes(
                b'#!/bin/sh\nset -eu\nexec sleep 600\n')
            manifest = root / 'cryptad-app.properties'
            valid_manifest = ''.join(key + '=' + value + '\n'
                                     for key, value in properties.items())
            manifest.write_text(valid_manifest)
            selection._verify_app(root, 'feed-reader')
            manifest.write_text(manifest.read_text().replace(
                properties['app.permissions'], 'content.fetch'))
            with self.assertRaisesRegex(ValueError, 'manifest-invalid'):
                selection._verify_app(root, 'feed-reader')
            manifest.write_text(valid_manifest.replace(
                'app.exec=bin/start.sh', 'app.exec=bin/other.sh'))
            with self.assertRaisesRegex(ValueError, 'manifest-invalid'):
                selection._verify_app(root, 'feed-reader')

    def test_statement_requires_the_signed_document_envelope(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'statement.json'
            public_key = b'k' * 44
            document = {'type': 'crypta.trust.statement.v1',
                'payload': {'issuer': {'identityId': 'PR309_PRIVATE_ISSUER_CANARY',
                    'publicKeyFingerprint': hashlib.sha256(public_key).hexdigest(),
                    'publicKeyBase64': base64.b64encode(public_key).decode()},
                    'subject': {'kind': 'profile',
                                'uri': 'USK@synthetic/pr309-private-subject/0'},
                    'context': 'profile', 'reason': 'PR309_PRIVATE_BODY_CANARY',
                    'tags': ['synthetic']},
                'signature': {'algorithm': 'app-vault-ed25519-preview',
                    'domain': 'crypta.trust.statement.v1',
                    'value': base64.b64encode(b'x' * 64).decode()}}
            path.write_text(json.dumps(document))
            selection._verify_statement(path)
            document['payload']['subject']['uri'] = 'USK@real-user/profile/0'
            path.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, 'statement-invalid'):
                selection._verify_statement(path)

    def test_statement_signature_uses_production_parser_and_verifier(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'fixtures'
            source = Path(temporary) / 'source'
            package = Path(temporary) / 'package'
            (root / 'jdk/bin').mkdir(parents=True)
            (package / 'lib').mkdir(parents=True)
            verifier = source / selection.TOOL_PATHS['statementVerifier']
            verifier.parent.mkdir(parents=True)
            verifier.write_text('fixed source identity')
            selected = {'products': {'candidate': {
                'artifactDigest': 'sha256:' + 'a' * 64, 'artifactSize': 1}}}
            with patch.object(selection.runtime, 'extract_package', return_value=package), \
                    patch.object(bounded_process, 'run') as run:
                selection._verify_statement_signature(root, source, selected)
            self.assertEqual(2, run.call_count)
            with patch.object(selection.runtime, 'extract_package', return_value=package), \
                    patch.object(bounded_process, 'run',
                                 side_effect=[None, ValueError('signature invalid')]), \
                    self.assertRaisesRegex(ValueError, 'signature invalid'):
                selection._verify_statement_signature(root, source, selected)

    def test_prepare_constructs_manifest_before_signature_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / 'fixtures'
            source = root / 'source'
            source.mkdir()
            arguments = SimpleNamespace(output=output, source=source,
                java_home=root / 'java-home', jdk_digest='sha256:' + '1' * 64,
                candidate=root / 'candidate.tar.gz', previous=root / 'previous.tar.gz',
                candidate_commit='a' * 40, previous_commit='b' * 40,
                feed_reader=root / 'feed-reader.zip',
                budget_importer=root / 'budget-importer.zip',
                budget_no_trust=root / 'budget-no-trust.zip',
                budget_no_fetch=root / 'budget-no-fetch.zip',
                trusted_keys=root / 'publisher-keys.properties',
                statement=root / 'statement.json', max_seconds=600, max_operations=1000)

            def stage_jdk(_source, target, _digest):
                (target / 'bin').mkdir(parents=True)

            def copy_input(_source, target, _maximum):
                target.write_bytes(b'x')

            def extract_package(_archive, target, _digest, _size):
                (target / 'lib').mkdir(parents=True)
                (target / 'lib/cryptad.jar').write_bytes(b'jar')
                return target

            contract = json.dumps({'contract': {'contractVersion': 26}}).encode()
            daemon = 'sha256:' + '2' * 64
            signature = Mock()
            with patch.object(selection.subprocess, 'check_output',
                              side_effect=[b'', 'f' * 40]), \
                    patch.object(selection.metadata, 'stage_jdk', side_effect=stage_jdk), \
                    patch.object(selection.base, 'copy_input', side_effect=copy_input), \
                    patch.object(selection.base, 'portable_bound'), \
                    patch.object(selection.runtime, 'digest_file',
                                 return_value='sha256:' + '3' * 64), \
                    patch.object(selection.runtime, 'extract_package',
                                 side_effect=extract_package), \
                    patch.object(selection.preparation, 'verify_wrapper_options'), \
                    patch.object(selection.runtime, 'packaged_daemon_identity',
                                 return_value=daemon), \
                    patch.object(selection.base, 'daemon_implementation_identity',
                                 return_value='sha256:' + '4' * 64), \
                    patch.object(selection.runtime, 'require_native_target'), \
                    patch.object(selection.metadata, 'observe_package',
                                 return_value=(contract, None, {'digest': daemon})), \
                    patch.object(selection.base, 'validate_roster'), \
                    patch.object(selection, 'tool_identities', return_value={
                        name: 'sha256:' + '7' * 64 for name in selection.TOOL_PATHS}), \
                    patch.object(selection, '_verify_bundles'), \
                    patch.object(selection, '_verify_statement'), \
                    patch.object(selection, '_verify_statement_signature', signature), \
                    patch.object(selection.runtime, 'tree_digest',
                                 return_value='sha256:' + '5' * 64), \
                    patch.object(selection.base, 'inventory', return_value=[]), \
                    patch.object(selection.base, 'digest', return_value='6' * 64):
                result = selection.prepare(arguments)

            self.assertEqual('6' * 64, result)
            signature.assert_called_once()
            manifest = signature.call_args.args[2]
            self.assertEqual({'candidate', 'previous'}, set(manifest['products']))
            self.assertEqual(manifest, json.loads((output / selection.MANIFEST).read_text()))

    def test_normal_bundle_signature_rejection_cannot_be_bypassed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selected = {'apps': {app_id: 'sha256:' + 'a' * 64
                                 for app_id in selection.APP_IDS}}
            with patch.object(selection.runtime, 'extract_app_bundle'), \
                    patch.object(bounded_process, 'run',
                                 side_effect=ValueError('signature-invalid')) as verify, \
                    self.assertRaisesRegex(ValueError, 'signature-invalid'):
                selection._verify_bundles(root, root, selected)
            verify.assert_called_once()


class GuestDispatchTest(unittest.TestCase):
    def test_budget_class_uses_separate_fixture_selection_and_existing_driver(self):
        selected = {'fixed': 'pr317-selection'}
        fixture = SimpleNamespace(verify=Mock(),
                                  materialize_selection=Mock(return_value=selected))
        legacy = SimpleNamespace(verify=Mock(), materialize_selection=Mock(),
                                 materialize_mail_selection=Mock())
        driver = SimpleNamespace(SELECTION=Path('/root/selection.json'),
            execute=Mock(return_value={'status': 'pr317-budget-executed'}))
        workload = SimpleNamespace(write=Mock())
        modules = {'pr317_budget_selection': fixture,
                   'pr315_workload_fixtures': legacy,
                   'pr314_workload_driver': driver,
                   'restricted_workload': workload}
        with patch.dict(sys.modules, modules), \
                patch.object(guest.sys, 'path', list(sys.path)), \
                patch.object(guest, 'KIT', Path(guest.__file__).resolve().parent):
            result, code = guest.installed('a' * 64, 'b' * 40,
                lifecycle_scenario='none', execution_class=guest.BUDGET_EXECUTION_CLASS)
        fixture.verify.assert_called_once_with(
            guest.BUDGET_FIXTURES, 'a' * 64, guest.SOURCE, 'b' * 40)
        fixture.materialize_selection.assert_called_once_with(
            guest.BUDGET_FIXTURES, guest.SOURCE, 'a' * 64, 'b' * 40)
        legacy.verify.assert_not_called()
        workload.write.assert_called_once_with(driver.SELECTION, selected, create=True)
        driver.execute.assert_called_once_with(startup_measurement=False,
            lifecycle_scenario='none', workload_group=None,
            retired_authority_preparation=False,
            execution_class=guest.BUDGET_EXECUTION_CLASS)
        self.assertEqual('pr317-budget-driver', guest.STAGE)
        self.assertEqual(({'status': 'pr317-budget-executed'}, 0), (result, code))

    def test_budget_execution_class_rejects_every_legacy_mode(self):
        for values in ({'startup_measurement': True, 'lifecycle_scenario': 'none'},
                       {'lifecycle_scenario': 'none', 'workload_group': 'positive'},
                       {'lifecycle_scenario': 'cancellation'}):
            with self.subTest(values=values), self.assertRaisesRegex(
                    ValueError, 'execution-class-invalid'):
                guest.execute('a' * 64, 'b' * 40,
                    execution_class=guest.BUDGET_EXECUTION_CLASS, **values)


if __name__ == '__main__':
    unittest.main()

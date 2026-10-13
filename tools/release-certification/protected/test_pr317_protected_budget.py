"""Focused PR-317 admission, bootstrap, binder and launcher contract tests."""
import base64
import copy
from contextlib import nullcontext
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import restricted_workload as workload
import restricted_workload_app as app
import restricted_workload_controller as controller
import restricted_workload_launcher as launcher
import restricted_workload_prepare as preparation


HANDLE = 'a' * 64
BOOT = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
INVOCATION = 'b' * 32
JAVA = 'sha256:' + '1' * 64
SLEEP = 'sha256:' + '2' * 64
APPS = ('feed-reader', 'budget-importer', 'budget-no-trust', 'budget-no-fetch')


def process(pid, parent, namespace_pids, namespace, digest):
    return {'hostPid': pid, 'hostParentPid': parent, 'startTicks': pid * 100,
            'pidNamespace': namespace, 'namespacePids': namespace_pids,
            'networkNamespaceIdentity': [1, 2],
            'mountNamespaceIdentity': [3, 4],
            'userNamespaceIdentity': [5, 6],
            'executableDigest': digest, 'noNewPrivileges': True,
            'effectiveCapabilities': 0}


class BudgetBinderTest(unittest.TestCase):
    def setUp(self):
        self.processes = {
            100: process(100, 90, [100, 4], 'pid:[5000]', JAVA),
            110: process(110, 100, [110, 8], 'pid:[5000]', 'sha256:' + '3' * 64),
            120: process(120, 110, [120, 9, 1], 'pid:[5001]', 'sha256:' + '4' * 64),
            130: process(130, 120, [130, 10, 2], 'pid:[5001]', SLEEP),
        }
        identity = {'digest': 'sha256:' + '5' * 64, 'fileCount': 7, 'sizeBytes': 80}
        self.launch = {'executionClass': preparation.BUDGET_EXECUTION_CLASS,
            'javaDigest': JAVA, 'budgetExecutableDigest': SLEEP,
            'budgetAppIdentities': {app_id: dict(identity) for app_id in APPS}}

    def observe(self, pid, role, uid):
        self.assertEqual(('candidate-sender', 60001), (role, uid))
        return copy.deepcopy(self.processes[pid])

    def bind(self, app_id='feed-reader', runtime=None):
        with patch.object(app, '_members', return_value=sorted(self.processes)), \
                patch.object(app, '_listener', return_value=9001), \
                patch.object(app, '_budget_cwd', return_value=[7, 8]), \
                patch.object(app.workload, 'read', return_value=self.launch), \
                patch.object(app.workload, 'account',
                             return_value=SimpleNamespace(pw_uid=60001)), \
                patch.object(app.workload, '_process', side_effect=self.observe):
            return app.require_budget_listener('candidate-sender', app_id,
                runtime or {'running': True, 'pid': 8,
                            'sandbox': {'provider': 'bubblewrap', 'active': True}}, 22000)

    def test_non_java_fixture_is_bound_without_mail_jvm_relabeling(self):
        result = self.bind()
        self.assertEqual(100, result['daemon']['hostPid'])
        self.assertEqual(110, result['worker']['appHostLeader']['hostPid'])
        self.assertEqual(130, result['worker']['fixtureProcess']['hostPid'])
        self.assertEqual(SLEEP, result['worker']['executableDigest'])
        self.assertEqual([7, 8], result['worker']['bundleCwdIdentity'])
        self.assertEqual(self.launch['budgetAppIdentities']['feed-reader']['digest'],
                         result['worker']['bundleDigest'])
        self.assertNotIn('appJvm', result)

    def test_wrong_role_app_runtime_and_executable_are_rejected(self):
        for app_id, runtime in (('mail-prototype', None),
                ('feed-reader', {'running': True, 'pid': 8,
                    'sandbox': {'provider': 'none', 'active': True}})):
            with self.subTest(app_id=app_id), self.assertRaises(workload.WorkloadError):
                self.bind(app_id, runtime)
        self.processes[130]['executableDigest'] = 'sha256:' + '9' * 64
        with self.assertRaises(workload.WorkloadError):
            self.bind()

    def test_wrong_execution_class_and_incomplete_roster_are_rejected(self):
        for change in ('class', 'roster'):
            selected = copy.deepcopy(self.launch)
            if change == 'class':
                selected['executionClass'] = preparation.MAIL_EXECUTION_CLASS
            else:
                selected['budgetAppIdentities'].pop('budget-no-fetch')
            with self.subTest(change=change), patch.object(app, '_members') as members, \
                    patch.object(app.workload, 'read', return_value=selected), \
                    self.assertRaises(workload.WorkloadError):
                app.require_budget_listener('candidate-sender', 'feed-reader',
                    {'running': True, 'pid': 8,
                     'sandbox': {'provider': 'bubblewrap', 'active': True}}, 22000)
            members.assert_not_called()


class BudgetBootstrapTest(unittest.TestCase):
    def test_bootstrap_returns_only_fixed_contexts_and_verified_corpus(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            public = root / 'roles/candidate-sender/public'
            public.mkdir(parents=True)
            statement = b'{"type":"crypta.trust.statement.v1","payload":{},"signature":{}}'
            (public / 'budget-statement.json').write_bytes(statement)
            digest = 'sha256:' + hashlib.sha256(statement).hexdigest()
            identities = {app_id: {'digest': 'sha256:' + str(index) * 64,
                'fileCount': 1, 'sizeBytes': 1}
                for index, app_id in enumerate(APPS, 1)}
            launch = {'executionClass': preparation.BUDGET_EXECUTION_CLASS,
                'budgetSelectionDigest': 'sha256:' + 'c' * 64,
                'budgetStatementDigest': digest, 'budgetAppIdentities': identities}
            launch = json.loads(json.dumps(launch, sort_keys=True))
            campaign = {'executionClass': preparation.BUDGET_EXECUTION_CLASS,
                'budgetSelectionDigest': launch['budgetSelectionDigest'],
                'deadlineMonotonicNs': 10**20}
            record = {'generation': 'd' * 64, 'managerInvocation': INVOCATION,
                      'bootId': BOOT}
            ports = {app_id: 23000 + index for index, app_id in enumerate(APPS)}

            def http(sock, path, _headers):
                if path.endswith('?cryptadIsolatedLaunch'):
                    app_id = path.split('/')[2]
                    return 302, {'Location': 'http://127.0.0.1:' + str(ports[app_id])
                        + '/#cryptadBootstrapNonce=' + 'n' * 16}, b''
                if path.endswith('/runtime'):
                    app_id = path.split('/')[4]
                    return 200, {}, json.dumps({'runtime': {'running': True, 'pid': 8,
                        'sandbox': {'provider': 'bubblewrap', 'active': True}},
                        'app': app_id}).encode()
                if path == '/.well-known/cryptad-bootstrap.json':
                    port = sock[1]
                    return 200, {}, json.dumps({'uiOrigin': 'http://127.0.0.1:' + str(port),
                        'browserSessionToken': 'session-' + str(port),
                        'browserSessionExpiresAt': '2099-01-01T00:00:00Z'}).encode()
                raise AssertionError(path)

            def binding(_role, app_id, _runtime, port):
                return {'daemon': {'hostPid': 100, 'startTicks': 10,
                                   'pidNamespace': 'pid:[1]'},
                        'worker': {'appHostLeader': {'hostPid': 110, 'startTicks': 11,
                            'pidNamespace': 'pid:[1]'},
                            'fixtureProcess': {'hostPid': 120 + ports[app_id],
                                'startTicks': 12, 'pidNamespace': 'pid:[2]'},
                            'listenerInode': port,
                            'bundleDigest': identities[app_id]['digest'],
                            'executableDigest': SLEEP}}

            import restricted_workload_app
            import restricted_workload_network
            import restricted_workload_storage
            with patch.object(workload, 'ROOT', root), \
                    patch.object(workload, 'locked', side_effect=nullcontext), \
                    patch.object(controller, 'deadline', side_effect=nullcontext), \
                    patch.object(workload, 'retained', return_value=(
                        campaign, 'candidate-sender', record)), \
                    patch.object(workload, 'admit'), patch.object(workload, 'exact'), \
                    patch.object(workload, 'manager', return_value={}), \
                    patch.object(workload, 'read', return_value=launch), \
                    patch.object(workload, 'current'), \
                    patch.object(restricted_workload_storage, 'verify_installed_app') as verify, \
                    patch.object(restricted_workload_network, 'connect',
                                 return_value=('http', 19402)), \
                    patch.object(restricted_workload_network, '_connect_port',
                                 side_effect=lambda _role, port: ('port', port)), \
                    patch.object(controller, '_http', side_effect=http), \
                    patch.object(restricted_workload_app, 'require_budget_listener',
                                 side_effect=binding):
                result = controller.bootstrap_budget(HANDLE)
            self.assertEqual({'apps', 'corpus'}, set(result))
            self.assertEqual(set(APPS), set(result['apps']))
            self.assertEqual(4, verify.call_count)
            self.assertEqual(base64.b64encode(statement).decode(),
                             result['corpus']['statementBase64'])
            self.assertEqual(digest, result['corpus']['statementDigest'])
            for app_id, context in result['apps'].items():
                self.assertEqual({'appId', 'role', 'handle', 'generation',
                    'managerInvocation', 'bootId', 'daemonEpoch', 'worker', 'origin',
                    'session', 'sessionExpiresAt'}, set(context))
                self.assertEqual(app_id, context['appId'])
                self.assertEqual(HANDLE, context['handle'])
                self.assertEqual('session-' + str(ports[app_id]), context['session'])

    def test_request_has_no_free_form_app_url_port_or_path(self):
        self.assertIn('bootstrap-budget', controller.METHODS)
        for extra in ({'appId': 'feed-reader'}, {'url': 'http://127.0.0.1:1'},
                      {'port': 1}, {'path': '/tmp/app'}, {'executable': '/bin/sh'}):
            raw = {'method': 'bootstrap-budget', 'handle': HANDLE, **extra}
            with self.subTest(extra=extra), self.assertRaises(workload.WorkloadError):
                controller.request(json.dumps(raw).encode())

    def test_wrong_class_and_role_are_rejected_before_app_or_http_access(self):
        for execution_class, role in ((preparation.MAIL_EXECUTION_CLASS, 'candidate-sender'),
                                      (preparation.BUDGET_EXECUTION_CLASS,
                                       'candidate-recipient')):
            with self.subTest(execution_class=execution_class, role=role), \
                    patch.object(workload, 'locked', side_effect=nullcontext), \
                    patch.object(controller, 'deadline', side_effect=nullcontext), \
                    patch.object(workload, 'retained', return_value=(
                        {'executionClass': execution_class}, role, {})), \
                    patch.object(controller, '_http') as http, \
                    self.assertRaises(workload.WorkloadError):
                controller.bootstrap_budget(HANDLE)
            http.assert_not_called()


class BudgetLauncherTest(unittest.TestCase):
    def test_environment_is_selected_only_by_fixed_execution_class(self):
        _arguments, ordinary = launcher.command('candidate-sender')
        _arguments, budget = launcher.command(
            'candidate-sender', preparation.BUDGET_EXECUTION_CLASS)
        self.assertTrue(set(launcher.BUDGET_ENVIRONMENT).isdisjoint(ordinary))
        self.assertEqual(launcher.BUDGET_ENVIRONMENT,
                         {key: budget[key] for key in launcher.BUDGET_ENVIRONMENT})
        self.assertEqual({'executionClass': preparation.BUDGET_EXECUTION_CLASS,
                          'environment': launcher.BUDGET_ENVIRONMENT},
                         launcher.budget_launcher_policy())
        with self.assertRaises(ValueError):
            launcher.command('candidate-sender', 'caller-selected-environment')


if __name__ == '__main__':
    unittest.main()

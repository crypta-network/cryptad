"""Real packaged daemon, signed experimental app sessions and durable Trust Graph accounting."""
import os
from pathlib import Path
import shutil
import subprocess
import unittest

import cross_version_app_budgets as adapter
from test_scheduler_pressure_packaged import retained_on_failure

ROOT = Path(__file__).resolve().parents[2]


class PackagedAppBudgetsTest(unittest.TestCase):
    def test_composed_imports_preserve_budget_graph_and_retry_restored_content_after_restart(self):
        self.run_case(False)

    def test_shared_families_interfere_across_app_principals_and_recover(self):
        self.run_case(True)

    def run_case(self, interference):
        tool = ROOT / 'platform-devtools/build/install/crypta-app'
        distribution = ROOT / 'build/cryptad-dist'
        if (not (tool / 'bin/crypta-app').is_file() or not (distribution / 'bin/cryptad').is_file()
                or not shutil.which('javac') or not shutil.which('node')):
            self.skipTest('requires Java 25, Node, :platform-devtools:installDist and assembleCryptadDist')
        with retained_on_failure('pr309') as temporary:
            private = Path(temporary)
            private.chmod(0o700)
            packaged = private / 'distribution'
            shutil.copytree(distribution, packaged, symlinks=True)
            java = private / 'jdk'
            shutil.copytree(Path(shutil.which('javac')).resolve().parents[1], java,
                            symlinks=False, ignore_dangling_symlinks=True)
            fixture = private / 'fixture'
            classes = private / 'classes'
            classes.mkdir()
            source = ROOT / 'platform-devtools/src/test/java/network/crypta/platform/devtools/fixtures/Pr309SignedBudgetFixture.java'
            environment = {'PATH': str(java / 'bin') + ':/usr/bin:/bin', 'JAVA_HOME': str(java),
                           'HOME': str(private), 'LANG': 'C.UTF-8'}
            for command in ([str(java / 'bin/javac'), '-cp', str(tool / 'lib/*') + os.pathsep + str(packaged / 'lib/*'), '-d', str(classes), str(source)],
                            [str(java / 'bin/java'), '-cp', str(classes) + os.pathsep + str(tool / 'lib/*') + os.pathsep + str(packaged / 'lib/*'),
                             'network.crypta.platform.devtools.fixtures.Pr309SignedBudgetFixture', str(fixture)]):
                completed = subprocess.run(command, capture_output=True, timeout=60, env=environment)
                if completed.returncode:
                    (private / 'fixture-stderr.txt').write_bytes(completed.stderr)
                    self.fail('packaged-budget-fixture-failed; private diagnostic retained')
            source_commit = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, check=True,
                                           capture_output=True, text=True).stdout.strip()
            lane = adapter.AppBudgetLane(private / 'runtime', packaged, java, fixture,
                                         source_commit, Path(shutil.which('node')).resolve(), interference=interference)
            try:
                result = lane.execute_interference() if interference else lane.execute()
            except adapter.runtime.RuntimeFailure as error:
                import traceback
                (private / 'integration-error.txt').write_text(traceback.format_exc())
                raise AssertionError(str(error)) from None
            except Exception:
                import traceback
                (private / 'integration-error.txt').write_text(traceback.format_exc())
                raise AssertionError('packaged-budget-integration-failed; private diagnostic retained') from None
            self.assertEqual(len(adapter.APP_IDS) * (1 if interference else 3),
                             len(lane.stopped_worker_epochs))
            if interference:
                self.assertTrue({'shared-foreground', 'shared-subscription', 'app-fetch-rate', 'global-fetch-rate',
                                 'app-import-rate', 'global-import-rate'} <= set(result['observedChecks']))
                self.assertFalse(result['releaseEligible'])
                self.assertTrue({'shared-foreground', 'shared-subscription', 'app-fetch-rate', 'global-fetch-rate',
                                 'app-import-rate', 'global-import-rate'} <= set(result['composedCoverage']['observedCases']))
                return
            self.assertTrue(set(adapter.composed.ROUTES) | {'authorization-denied'} <= set(result['observedCases']))
            self.assertFalse(result['releaseEligible'])
            self.assertEqual('not-observed', result['fullAppBudgets'])
            self.assertTrue(result['missingCases'])
            self.assertEqual(3, len(set(lane.epochs)))
            self.assertTrue(lane.restored_fixture_content)


if __name__ == '__main__':
    unittest.main()

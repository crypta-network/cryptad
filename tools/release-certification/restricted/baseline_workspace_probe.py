"""Disposable-test entrypoint for the real controller unit's filesystem restrictions.

Only the disposable VM harness installs a temporary ExecStart override for this test. It does
not grant original/provider authority and never runs the production baseline approval decision.
"""
import errno
import os
from pathlib import Path
import sys
import unittest

ROOT = Path('/opt/cryptad-cross-version/current')


def main():
    if (os.geteuid() != 0 or Path(__file__) != ROOT / 'tools/release-certification/restricted/baseline_workspace_probe.py'
            or not any(line.endswith(':/system.slice/cryptad-restricted.service')
                       for line in Path('/proc/self/cgroup').read_text().splitlines())):
        raise ValueError('baseline-workspace-controller-unit-required')
    # Prove the regression is tested with /run still read-only, not a relaxed unit.
    try:
        descriptor = os.open('/run/cryptad-baseline-workspace-probe', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except OSError as error:
        if error.errno != errno.EROFS:
            raise
    else:
        os.close(descriptor)
        Path('/run/cryptad-baseline-workspace-probe').unlink()
        raise ValueError('baseline-workspace-run-not-read-only')
    sys.path.insert(0, str(ROOT / 'tools/release-certification/protected'))
    import runtime_baseline_approval as approval
    approval._private_directory(approval.WORKSPACE)
    import test_runtime_baseline_workspace
    suite = unittest.defaultTestLoader.loadTestsFromModule(test_runtime_baseline_workspace)
    result = unittest.TextTestRunner().run(suite)
    if not result.wasSuccessful() or result.testsRun != 2 or result.skipped:
        raise ValueError('baseline-workspace-unit-tests-failed')


if __name__ == '__main__':
    main()

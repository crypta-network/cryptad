"""Standard-library unittest runner for certification components."""

from __future__ import annotations

import os
import unittest
from pathlib import Path

SUITE_MODULES = {
    "core": [
        "cryptad_certification.tests.test_core",
        "cryptad_certification.tests.test_integrations",
    ],
    "app-platform": ["cryptad_certification.tests.test_app_platform"],
    "app-platform-docs": ["cryptad_certification.tests.test_collectors"],
    "network-scale-soak": ["cryptad_certification.tests.test_collectors"],
    "live-network-beta": ["cryptad_certification.tests.test_collectors"],
    "multi-node-beta": ["cryptad_certification.tests.test_multi_node"],
    "security-response": ["cryptad_certification.tests.test_security_response"],
    "release-certification": ["cryptad_certification.tests.test_release_certification"],
    "production-beta": ["cryptad_certification.tests.test_production_beta"],
    "go-no-go": ["cryptad_certification.tests.test_dashboard"],
    "stable-readiness": ["cryptad_certification.tests.test_stable"],
    "stable-rc": ["cryptad_certification.tests.test_stable_rc"],
    "migration": ["cryptad_certification.tests.test_core"],
}


def run(suite_name: str) -> int:
    """Run one focused suite or every certification test."""

    loader = unittest.defaultTestLoader
    if suite_name == "all":
        module_names = sorted({name for names in SUITE_MODULES.values() for name in names})
    else:
        module_names = SUITE_MODULES.get(suite_name)
        if module_names is None:
            raise ValueError(f"unknown self-test suite: {suite_name}")
    suite = unittest.TestSuite(loader.loadTestsFromName(name) for name in module_names)
    previous = Path.cwd()
    workspace_root = Path(__file__).resolve().parents[3]
    try:
        os.chdir(workspace_root)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return 0 if result.wasSuccessful() else 1
    finally:
        os.chdir(previous)

"""Characterization suite for release-certification aggregation."""

from __future__ import annotations

import unittest

from cryptad_certification.engines import release_certification
from cryptad_certification.tests.support import workspace_root


class ReleaseCertificationCharacterizationTest(unittest.TestCase):
    def test_existing_release_certification_scenarios(self) -> None:
        release_certification.run_self_test(workspace_root())

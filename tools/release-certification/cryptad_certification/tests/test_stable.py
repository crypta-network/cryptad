"""Characterization suite for Stable 1.0 readiness."""

from __future__ import annotations

import unittest

from cryptad_certification.engines import stable_1_0_readiness


class StableCharacterizationTest(unittest.TestCase):
    def test_existing_stable_readiness_scenarios(self) -> None:
        stable_1_0_readiness.run_self_test()

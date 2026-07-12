"""Characterization suite for multi-node beta tooling."""

from __future__ import annotations

import unittest

from cryptad_certification.engines import multi_node_beta_soak


class MultiNodeCharacterizationTest(unittest.TestCase):
    def test_existing_multi_node_scenarios(self) -> None:
        multi_node_beta_soak.run_self_test()

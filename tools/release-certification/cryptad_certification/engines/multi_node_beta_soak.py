"""Composed engine for the former multi_node_beta_soak.py entry point."""

from ._loader import compose

compose(globals(), "multi_node_beta_soak.py", "multi_node_beta_soak_impl.py")

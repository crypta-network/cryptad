"""Composed engine for the former live_network_beta_smoke.py entry point."""

from ._loader import compose

compose(globals(), "live_network_beta_smoke.py", "live_network_beta_smoke_impl.py")

"""Composed engine for the former network_scale_soak.py entry point."""

from ._loader import compose

compose(globals(), "network_scale_soak.py", "network_scale_soak_impl.py")

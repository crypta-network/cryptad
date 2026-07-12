"""Composed engine for the former security_response_runbook.py entry point."""

from ._loader import compose

compose(globals(), "security_response_runbook.py", "security_response_runbook_impl.py")

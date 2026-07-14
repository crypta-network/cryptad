"""Composed engine for the former app_platform_docs_check.py entry point."""

from ._loader import compose

compose(globals(), "app_platform_docs_check.py", "app_platform_docs_check_impl.py")

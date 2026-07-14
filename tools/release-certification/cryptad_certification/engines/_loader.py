"""Compose a mechanically partitioned engine with its original virtual file path."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def compose(namespace: dict[str, Any], virtual_name: str, implementation_name: str) -> None:
    """Execute an implementation segment in its public engine namespace."""

    engine_dir = Path(__file__).resolve().parent
    namespace["__engine_loader__"] = str(Path(namespace["__file__"]).resolve())
    # The unified public entry point is now the source reported in evidence and tracebacks. Its
    # directory still preserves the former scripts' fixture-relative behavior.
    virtual_file = engine_dir.parents[1] / "certify.py"
    implementation = engine_dir / implementation_name
    namespace["__file__"] = str(virtual_file)
    namespace["__engine_implementation__"] = str(implementation)
    exec(compile(implementation.read_text(), str(virtual_file), "exec"), namespace, namespace)

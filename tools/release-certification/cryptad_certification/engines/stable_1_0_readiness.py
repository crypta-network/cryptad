"""Composed engine for the former ``stable_1_0_readiness.py`` entry point."""

from __future__ import annotations

from pathlib import Path

_ENGINE_DIR = Path(__file__).resolve().parent
_VIRTUAL_FILE = _ENGINE_DIR.parents[1] / "certify.py"
_PARTS = ['stable_1_0_readiness_core.py', 'stable_1_0_readiness_domains.py', 'stable_1_0_readiness_policy.py', 'stable_1_0_readiness_reporting.py', 'stable_1_0_readiness_selftest.py', 'stable_1_0_readiness_cli.py']

__engine_loader__ = str(Path(__file__).resolve())
globals()["__file__"] = str(_VIRTUAL_FILE)
for _part_name in _PARTS:
    _part_path = _ENGINE_DIR / _part_name
    exec(compile(_part_path.read_text(), str(_VIRTUAL_FILE), "exec"), globals(), globals())

del _part_name, _part_path

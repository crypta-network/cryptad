"""Composed engine for the former ``app_platform_smoke.py`` entry point."""

from __future__ import annotations

from pathlib import Path

_ENGINE_DIR = Path(__file__).resolve().parent
_VIRTUAL_FILE = _ENGINE_DIR.parents[1] / "certify.py"
_PARTS = ['app_platform_smoke_core.py', 'app_platform_smoke_contracts.py', 'app_platform_smoke_distribution.py', 'app_platform_smoke_data_network.py', 'app_platform_smoke_social_trust.py', 'app_platform_smoke_operations_01.py', 'app_platform_smoke_operations_02.py', 'app_platform_smoke_selftest_assertions.py', 'app_platform_smoke_selftest_workspace.py']

__engine_loader__ = str(Path(__file__).resolve())
globals()["__file__"] = str(_VIRTUAL_FILE)
for _part_name in _PARTS:
    _part_path = _ENGINE_DIR / _part_name
    exec(compile(_part_path.read_text(), str(_VIRTUAL_FILE), "exec"), globals(), globals())

del _part_name, _part_path

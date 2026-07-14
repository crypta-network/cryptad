"""Composed engine for the former ``production_beta_go_no_go_dashboard.py`` entry point."""

from __future__ import annotations

from pathlib import Path

_ENGINE_DIR = Path(__file__).resolve().parent
_VIRTUAL_FILE = _ENGINE_DIR.parents[1] / "certify.py"
_PARTS = ['production_beta_go_no_go_dashboard_core.py', 'production_beta_go_no_go_dashboard_inputs.py', 'production_beta_go_no_go_dashboard_stable.py', 'production_beta_go_no_go_dashboard_selftest.py', 'production_beta_go_no_go_dashboard_selftest_policy.py']

__engine_loader__ = str(Path(__file__).resolve())
globals()["__file__"] = str(_VIRTUAL_FILE)
for _part_name in _PARTS:
    _part_path = _ENGINE_DIR / _part_name
    exec(compile(_part_path.read_text(), str(_VIRTUAL_FILE), "exec"), globals(), globals())

del _part_name, _part_path

"""Composed engine for the former ``release_certification.py`` entry point."""

from __future__ import annotations

from pathlib import Path

_ENGINE_DIR = Path(__file__).resolve().parent
_VIRTUAL_FILE = _ENGINE_DIR.parents[1] / "certify.py"
_PARTS = ['release_certification_core.py', 'release_certification_matrix.py', 'release_certification_gates.py', 'release_certification_reporting.py', 'release_certification_selftest.py']

__engine_loader__ = str(Path(__file__).resolve())
globals()["__file__"] = str(_VIRTUAL_FILE)
for _part_name in _PARTS:
    _part_path = _ENGINE_DIR / _part_name
    exec(compile(_part_path.read_text(), str(_VIRTUAL_FILE), "exec"), globals(), globals())

del _part_name, _part_path

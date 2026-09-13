"""Select preprovisioned private maintenance inputs from a public-safe mode marker.

This module performs no acquisition or policy installation. A mode marker is a request to use the
existing protected cohort authority, never selection authority in its own right. Original producer
and member authentication remains mandatory in the subsequent metadata producer.
"""
from pathlib import Path
import os
import stat

from maintenance_runtime_metadata import _regular, read_json
from original_artifact_authentication import validate_coordinates

PROJECTION_FILE = Path("/etc/cryptad-certification/maintenance-runtime-projection.json")
MARKER = {"schemaVersion": 1, "mode": "selected-federation"}


class RuntimeInputsError(ValueError):
    """Bounded private-input failure without selection details."""


def _deny():
    raise RuntimeInputsError("runtime-metadata-private-inputs-unavailable")


def detect_private_inputs(root: Path) -> bool:
    """Recognize only an exact marker directory; reject legacy private-cohort intake."""
    try:
        root = Path(root)
        if (not root.is_dir() or any(path.is_symlink() for path in (root, *root.parents))):
            _deny()
        marker = root / "mode.json"
        if marker.exists() or marker.is_symlink():
            value = read_json(_regular(marker, 256))
            if (type(value.get("schemaVersion")) is not int or value != MARKER
                    or {path.name for path in root.iterdir()} != {"mode.json"}):
                _deny()
            return True
        cohort = read_json(_regular(root / "cohort.json"))
        if type(cohort.get("schemaVersion")) is not int or cohort["schemaVersion"] != 1:
            _deny()
        return False
    except (ValueError, OSError, KeyError, TypeError, AttributeError):
        raise RuntimeInputsError("runtime-metadata-private-inputs-unavailable") from None


def projection_origin(root: Path) -> dict:
    """Read fixed provisioned selection coordinates for a marker, or legacy public coordinates."""
    try:
        if detect_private_inputs(root):
            import app_subject_projection as projection
            if projection._cohort()["schemaVersion"] != 2:
                _deny()
            # Also require private permissions: root ownership alone does not prevent disclosure.
            raw = _regular(PROJECTION_FILE, 16384)
            info = PROJECTION_FILE.stat()
            permissions = stat.S_IMODE(info.st_mode)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or permissions not in {0o600, 0o640}
                    or permissions == 0o640 and os.geteuid() != 0 and info.st_gid != os.getegid()):
                _deny()
            value = read_json(raw)
        else:
            value = read_json(_regular(Path(root) / "projection-selection.json", 16384))
        if not isinstance(value, dict) or set(value) != {"coordinates"}:
            _deny()
        coordinates = validate_coordinates(value["coordinates"])
        if coordinates["sourceFamily"] != "app-subject-projection":
            _deny()
        return coordinates
    except (ValueError, OSError, KeyError, TypeError, AttributeError):
        raise RuntimeInputsError("runtime-metadata-private-inputs-unavailable") from None

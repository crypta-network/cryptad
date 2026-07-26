#!/usr/bin/env python3
"""Build the dependency-free Stable maintenance provider wheel deterministically."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
from pathlib import Path
import zipfile


NAME = "cryptad_stable_maintenance_backend"
VERSION = "1"
DIST_INFO = f"{NAME}-{VERSION}.dist-info"
ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "src" / NAME


def _record_digest(data: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode("ascii")
    return "sha256=" + encoded.rstrip("=")


def _metadata() -> dict[str, bytes]:
    return {
        f"{DIST_INFO}/METADATA": (
            "Metadata-Version: 2.3\n"
            "Name: cryptad-stable-maintenance-backend\n"
            f"Version: {VERSION}\n"
            "Summary: Protected Stable maintenance publication provider\n"
            "Requires-Python: >=3.12\n\n"
        ).encode("utf-8"),
        f"{DIST_INFO}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: cryptad-deterministic-wheel\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n\n"
        ).encode("utf-8"),
        f"{DIST_INFO}/top_level.txt": (NAME + "\n").encode("utf-8"),
    }


def build(output: Path) -> Path:
    files = {
        f"{NAME}/__init__.py": (SOURCE / "__init__.py").read_bytes(),
        f"{NAME}/lifecycle.py": (SOURCE / "lifecycle.py").read_bytes(),
        f"{NAME}/provider.py": (SOURCE / "provider.py").read_bytes(),
        **_metadata(),
    }
    record_path = f"{DIST_INFO}/RECORD"
    rows = [
        (path, _record_digest(data), str(len(data)))
        for path, data in sorted(files.items())
    ]
    rows.append((record_path, "", ""))
    record = io.StringIO(newline="")
    csv.writer(record, lineterminator="\n").writerows(rows)
    files[record_path] = record.getvalue().encode("utf-8")

    output.mkdir(parents=True, exist_ok=True)
    wheel = output / f"{NAME}-{VERSION}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path, data in sorted(files.items()):
            info = zipfile.ZipInfo(path, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return wheel


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--out", required=True, type=Path)
    arguments = parser.parse_args()
    print(build(arguments.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

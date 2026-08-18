"""Focused archive-boundary tests for Stable protected release execution."""

from __future__ import annotations

import stat
import tarfile
import tempfile
import unittest
import zipfile
from io import BytesIO
from pathlib import Path
from unittest import mock

from cryptad_certification.engines import stable_1_0_supply_chain_archive as archive_safety
from cryptad_certification.engines.stable_1_0_supply_chain_archive import (
    inspect_archive_safety,
)


class StableProtectedArchiveTests(unittest.TestCase):
    """Exercise the stricter no-link and no-nested-archive dispatch boundary."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _zip_bytes(member: str) -> bytes:
        stream = BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            info = zipfile.ZipInfo(member)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, b"safe")
        return stream.getvalue()

    @staticmethod
    def _tar_bytes(mode: str) -> bytes:
        stream = BytesIO()
        with tarfile.open(
            fileobj=stream,
            mode=mode,
            format=tarfile.USTAR_FORMAT,
        ) as archive:
            info = tarfile.TarInfo("safe.txt")
            info.mode = 0o644
            info.size = 4
            archive.addfile(info, BytesIO(b"safe"))
        return stream.getvalue()

    def _outer_archive(self, name: str, outer_kind: str, payload: bytes) -> Path:
        path = self.root / f"{name}.{outer_kind}"
        if outer_kind == "zip":
            with zipfile.ZipFile(path, "w") as archive:
                info = zipfile.ZipInfo("payload.bin")
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(info, payload)
        else:
            with tarfile.open(path, "w") as archive:
                info = tarfile.TarInfo("payload.bin")
                info.mode = 0o644
                info.size = len(payload)
                archive.addfile(info, BytesIO(payload))
        return path

    @staticmethod
    def _inspect(path: Path, maximum_expanded_bytes: int = 4 * 1024 * 1024) -> dict[str, int]:
        return inspect_archive_safety(
            path,
            maximum_entries=20,
            maximum_expanded_bytes=maximum_expanded_bytes,
        )

    def test_archive_rejects_unsafe_members_and_declared_nested_archive(self) -> None:
        cases: list[tuple[str, Path]] = []
        for name, member in (
            ("traversal", "../escape"),
            ("appledouble", "._payload"),
            ("ds-store", ".DS_Store"),
            ("macosx", "__MACOSX/payload"),
        ):
            path = self.root / f"{name}.zip"
            with zipfile.ZipFile(path, "w") as archive:
                info = zipfile.ZipInfo(member)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(info, b"unsafe")
            cases.append((name, path))

        collision = self.root / "case-fold.zip"
        with zipfile.ZipFile(collision, "w") as archive:
            archive.writestr("Payload", b"one")
            archive.writestr("payload", b"two")
        cases.append(("case-fold", collision))

        nested = self._outer_archive(
            "declared-nested",
            "zip",
            self._zip_bytes("safe.txt"),
        )
        with zipfile.ZipFile(nested, "a") as archive:
            original = archive.read("payload.bin")
            archive.writestr("nested.zip", original)
        cases.append(("nested", nested))

        symlink = self.root / "symlink.tar.gz"
        with tarfile.open(symlink, "w:gz") as archive:
            info = tarfile.TarInfo("link")
            info.type = tarfile.SYMTYPE
            info.linkname = "target"
            archive.addfile(info)
        cases.append(("symlink", symlink))

        for name, path in cases:
            with self.subTest(case=name):
                with self.assertRaises(ValueError):
                    self._inspect(path)

    def test_archive_rejects_renamed_nested_containers_in_zip_and_tar(self) -> None:
        payloads = {
            "zip": self._zip_bytes("safe.txt"),
            "jar": self._zip_bytes("META-INF/MANIFEST.MF"),
            "tar": self._tar_bytes("w"),
            "tar-gzip": self._tar_bytes("w:gz"),
            "tar-bzip2": self._tar_bytes("w:bz2"),
            "tar-xz": self._tar_bytes("w:xz"),
        }
        for archive_kind, payload in payloads.items():
            for outer_kind in ("zip", "tar"):
                with self.subTest(archive_kind=archive_kind, outer_kind=outer_kind):
                    path = self._outer_archive(
                        f"renamed-{archive_kind}",
                        outer_kind,
                        payload,
                    )
                    with self.assertRaisesRegex(
                        ValueError,
                        "archive contains a nested archive",
                    ):
                        self._inspect(path)

    def test_archive_scans_complete_bounded_entry_for_prefixed_zip(self) -> None:
        nested_zip = self._zip_bytes("safe.txt")
        for preamble_size in (65_533, 70 * 1024, (1024 * 1024) + 1):
            with self.subTest(preamble_size=preamble_size):
                payload = (b"M" * preamble_size) + nested_zip
                self.assertTrue(zipfile.is_zipfile(BytesIO(payload)))
                path = self._outer_archive(
                    f"prefixed-{preamble_size}",
                    "zip",
                    payload,
                )
                with self.assertRaisesRegex(
                    ValueError,
                    "archive contains a nested archive",
                ):
                    self._inspect(path)

    def test_archive_content_detection_requires_a_valid_nested_container(self) -> None:
        for name, payload in {
            "invalid-zip": b"PK\x03\x04not-a-valid-zip",
            "invalid-gzip": b"\x1f\x8bnot-a-valid-gzip-tar",
        }.items():
            with self.subTest(name=name):
                path = self._outer_archive(name, "zip", payload)
                totals = self._inspect(path)
                self.assertEqual(0, totals["nestedArchiveDepth"])

    def test_strict_content_bound_fails_before_reading_oversized_entry(self) -> None:
        stream = mock.Mock()

        with self.assertRaisesRegex(ValueError, "bounded content inspection size"):
            archive_safety._digest_stream(  # noqa: SLF001
                stream,
                archive_safety._MAX_NESTED_ARCHIVE_BYTES + 1,  # noqa: SLF001
                archive_safety._MAX_NESTED_ARCHIVE_BYTES + 1,  # noqa: SLF001
                detect_archive=True,
            )

        stream.read.assert_not_called()


if __name__ == "__main__":
    unittest.main()

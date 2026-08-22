"""Tests for authenticated Stable catalog-authority closeout assembly."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile

from cryptad_certification.engines import stable_1_0_catalog_authority_inputs as inputs


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


class StableCatalogAuthorityInputsTest(unittest.TestCase):
    """Exercises archive isolation, exact selection, and digest binding."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.archives = self.root / "archives"
        self.archives.mkdir()

    def _write_archive(self, members: dict[str, bytes]) -> Path:
        archive_path = self.archives / "artifact-00.zip"
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
            for name, value in members.items():
                member = zipfile.ZipInfo(name)
                member.create_system = 3
                member.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(member, value)
        return archive_path

    def _coordinates(
        self, archive: Path, source: str, target: str, value: bytes
    ) -> Path:
        coordinate = {
            "schemaVersion": 1,
            "artifacts": [
                {
                    "artifactDigest": _digest(archive.read_bytes()),
                    "artifactId": 293,
                    "artifactName": "stable-1-0-fixture-artifact",
                    "artifactSize": archive.stat().st_size,
                    "members": [
                        {
                            "digest": _digest(value),
                            "sourcePath": source,
                            "targetName": target,
                        }
                    ],
                    "runAttempt": 1,
                    "runId": 293,
                    "workflowPath": ".github/workflows/stable-1.0-rc-release.yml",
                }
            ],
        }
        path = self.root / "coordinates.json"
        path.write_text(json.dumps(coordinate), encoding="utf-8")
        return path

    def test_assemble_when_member_is_exact_expect_flat_digest_bound_evidence(self) -> None:
        value = b'{"kind":"fixture"}\n'
        source = "nested/stable-1.0-release-subject-inventory.json"
        archive = self._write_archive({source: value, "unselected.txt": b"ignored"})
        coordinates = self._coordinates(
            archive,
            source,
            "stable-1.0-release-subject-inventory.json",
            value,
        )
        output = self.root / "output"

        inputs.assemble(coordinates, self.archives, output)

        self.assertEqual(
            value,
            (output / "stable-1.0-release-subject-inventory.json").read_bytes(),
        )
        self.assertEqual(1, len(list(output.iterdir())))

    def test_assemble_when_subject_bundle_exceeds_json_limit_expect_bounded_streaming_copy(
        self,
    ) -> None:
        value = b"x" * (inputs.MAX_EVIDENCE_MEMBER_BYTES + 1)
        source = inputs.PRIMARY_SUBJECT_BUNDLE
        archive = self._write_archive({source: value})
        coordinates = self._coordinates(archive, source, source, value)
        output = self.root / "output"

        inputs.assemble(coordinates, self.archives, output)

        self.assertEqual(_digest(value), inputs._digest_file(output / source))
        self.assertEqual(len(value), (output / source).stat().st_size)

    def test_assemble_when_member_digest_drifts_expect_fail_closed(self) -> None:
        value = b"exact"
        source = "stable-1.0-live-usk-publication.json"
        archive = self._write_archive({source: value})
        coordinates = self._coordinates(archive, source, source, b"different")

        with self.assertRaisesRegex(inputs.AssemblyError, "member-digest-mismatch"):
            inputs.assemble(coordinates, self.archives, self.root / "output")

    def test_assemble_when_later_member_fails_expect_no_partial_output_and_clean_retry(
        self,
    ) -> None:
        first_source = "stable-1.0-protected-release-execution-summary.json"
        second_source = "stable-1.0-independent-reproducibility-summary.json"
        first_value = b'{"kind":"protected-release"}\n'
        second_value = b'{"kind":"independent-reproduction"}\n'
        archive = self._write_archive(
            {first_source: first_value, second_source: second_value}
        )
        coordinates = self._coordinates(
            archive,
            first_source,
            first_source,
            first_value,
        )
        document = json.loads(coordinates.read_text(encoding="utf-8"))
        second_selection = {
            "digest": _digest(b"wrong"),
            "sourcePath": second_source,
            "targetName": second_source,
        }
        document["artifacts"][0]["members"].append(second_selection)
        coordinates.write_text(json.dumps(document), encoding="utf-8")
        output = self.root / "output"

        with self.assertRaisesRegex(inputs.AssemblyError, "member-digest-mismatch"):
            inputs.assemble(coordinates, self.archives, output)

        self.assertFalse(output.exists())
        self.assertEqual([], list(self.root.glob(".output-assembly-*")))

        second_selection["digest"] = _digest(second_value)
        coordinates.write_text(json.dumps(document), encoding="utf-8")

        inputs.assemble(coordinates, self.archives, output)

        self.assertEqual(first_value, (output / first_source).read_bytes())
        self.assertEqual(second_value, (output / second_source).read_bytes())

    def test_assemble_when_archive_digest_or_size_drifts_expect_fail_closed(
        self,
    ) -> None:
        value = b"exact"
        source = "stable-1.0-live-usk-publication.json"
        archive = self._write_archive({source: value})
        for field, replacement, expected in (
            ("artifactDigest", _digest(b"different"), "artifact-digest-mismatch"),
            ("artifactSize", archive.stat().st_size + 1, "artifact-unsafe"),
        ):
            with self.subTest(field=field):
                coordinates = self._coordinates(archive, source, source, value)
                document = json.loads(coordinates.read_text(encoding="utf-8"))
                document["artifacts"][0][field] = replacement
                coordinates.write_text(json.dumps(document), encoding="utf-8")

                with self.assertRaisesRegex(inputs.AssemblyError, expected):
                    inputs.assemble(
                        coordinates,
                        self.archives,
                        self.root / f"output-{field}",
                    )

    def test_assemble_when_artifact_coordinate_is_duplicated_expect_fail_closed(
        self,
    ) -> None:
        value = b"exact"
        source = "stable-1.0-live-usk-publication.json"
        archive = self._write_archive({source: value})
        coordinates = self._coordinates(archive, source, source, value)
        document = json.loads(coordinates.read_text(encoding="utf-8"))
        document["artifacts"].append(document["artifacts"][0])
        coordinates.write_text(json.dumps(document), encoding="utf-8")

        with self.assertRaisesRegex(inputs.AssemblyError, "artifact-duplicate"):
            inputs.assemble(coordinates, self.archives, self.root / "output")

    def test_assemble_when_archive_has_case_collision_expect_fail_closed(self) -> None:
        value = b"exact"
        source = "stable-1.0-live-usk-publication.json"
        archive = self._write_archive({source: value, source.upper(): value})
        coordinates = self._coordinates(archive, source, source, value)

        with self.assertRaisesRegex(inputs.AssemblyError, "path-collision"):
            inputs.assemble(coordinates, self.archives, self.root / "output")

    def test_assemble_when_archive_has_symlink_expect_fail_closed(self) -> None:
        source = "stable-1.0-live-usk-publication.json"
        archive = self.archives / "artifact-00.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            link = zipfile.ZipInfo("link")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            bundle.writestr(link, source)
            member = zipfile.ZipInfo(source)
            member.create_system = 3
            member.external_attr = (stat.S_IFREG | 0o644) << 16
            bundle.writestr(member, b"exact")
        coordinates = self._coordinates(archive, source, source, b"exact")

        with self.assertRaisesRegex(inputs.AssemblyError, "member-unsafe"):
            inputs.assemble(coordinates, self.archives, self.root / "output")

    def test_assemble_when_archive_has_platform_metadata_expect_fail_closed(
        self,
    ) -> None:
        value = b"exact"
        source = "stable-1.0-live-usk-publication.json"
        archive = self._write_archive({source: value, "__MACOSX/._receipt": b"unsafe"})
        coordinates = self._coordinates(archive, source, source, value)

        with self.assertRaisesRegex(inputs.AssemblyError, "metadata-forbidden"):
            inputs.assemble(coordinates, self.archives, self.root / "output")


if __name__ == "__main__":
    unittest.main()

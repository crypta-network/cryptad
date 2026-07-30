"""Tests for encrypted Stable backport workflow handoffs."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[4]
SCRIPT = (
    ROOT
    / "tools/release-certification/protected"
    / "stable_backport_protected_handoff.py"
)
KEY_ENV = "CRYPTAD_STABLE_BACKPORT_HANDOFF_KEY_BASE64"
KEY = base64.b64encode(bytes(range(32))).decode("ascii")
OTHER_KEY = base64.b64encode(bytes(range(1, 33))).decode("ascii")


@unittest.skipUnless(shutil.which("openssl"), "protected handoff tests require OpenSSL")
class StableBackportProtectedHandoffTest(unittest.TestCase):
    """Exercise confidentiality, integrity, context, and archive safety."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "stable-1.0-release-train-queue.json").write_text(
            '{"privateRecordDigest":"sha256:protected-value"}\n',
            encoding="utf-8",
        )
        (self.source / "stable-1.0-release-train-validation.json").write_text(
            '{"authorizationDigest":"sha256:protected-authorization"}\n',
            encoding="utf-8",
        )
        self.binding = self.root / "binding.json"
        self.binding_value = {
            "artifactKind": "release-train-phase",
            "repository": "crypta-network/cryptad",
            "workflow": (
                "crypta-network/cryptad/.github/workflows/"
                "stable-1.0-backport-release-train.yml@" + "a" * 40
            ),
            "workflowCommit": "a" * 40,
            "runId": "287",
            "runAttempt": "1",
            "operation": "validate-authorization",
            "releaseId": "stable-maintenance-301",
            "buildVersion": "301",
            "releaseLane": "routine-maintenance",
            "sourceCommit": "a" * 40,
            "artifactName": (
                "stable-1.0-backport-validate-authorization-"
                "stable-maintenance-301-301"
            ),
        }
        self.binding.write_text(
            json.dumps(self.binding_value, sort_keys=True),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_handoff(
        self,
        operation: str,
        source: Path,
        destination: Path,
        *,
        binding: Path | None = None,
        key: str = KEY,
    ) -> subprocess.CompletedProcess[str]:
        source_option = "--source" if operation == "seal" else "--bundle"
        return subprocess.run(
            (
                "python3",
                str(SCRIPT),
                operation,
                source_option,
                str(source),
                "--out",
                str(destination),
                "--binding",
                str(binding or self.binding),
                "--key-env",
                KEY_ENV,
            ),
            cwd=ROOT,
            env={
                "PATH": os.environ["PATH"],
                "LANG": "C",
                "LC_ALL": "C",
                KEY_ENV: key,
            },
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_encrypted_round_trip_exposes_only_the_sealed_envelope(self) -> None:
        sealed = self.root / "sealed"
        opened = self.root / "opened"

        seal = self.run_handoff("seal", self.source, sealed)
        opened_result = self.run_handoff("open", sealed, opened)

        self.assertEqual(seal.returncode, 0, seal.stdout + seal.stderr)
        self.assertEqual(
            opened_result.returncode,
            0,
            opened_result.stdout + opened_result.stderr,
        )
        self.assertEqual(
            sorted(path.name for path in sealed.iterdir()),
            [
                "stable-1.0-protected-handoff.enc",
                "stable-1.0-protected-handoff.json",
            ],
        )
        sealed_bytes = b"".join(path.read_bytes() for path in sealed.iterdir())
        self.assertNotIn(b"privateRecordDigest", sealed_bytes)
        self.assertNotIn(b"authorizationDigest", sealed_bytes)
        self.assertEqual(
            {
                path.name: path.read_bytes()
                for path in opened.iterdir()
            },
            {
                path.name: path.read_bytes()
                for path in self.source.iterdir()
            },
        )

    def test_wrong_key_or_context_cannot_open_the_handoff(self) -> None:
        sealed = self.root / "sealed"
        self.assertEqual(
            self.run_handoff("seal", self.source, sealed).returncode,
            0,
        )
        wrong_binding = self.root / "wrong-binding.json"
        changed = {**self.binding_value, "runId": "288"}
        wrong_binding.write_text(json.dumps(changed), encoding="utf-8")

        wrong_key = self.run_handoff(
            "open",
            sealed,
            self.root / "wrong-key-output",
            key=OTHER_KEY,
        )
        wrong_context = self.run_handoff(
            "open",
            sealed,
            self.root / "wrong-context-output",
            binding=wrong_binding,
        )

        self.assertNotEqual(wrong_key.returncode, 0)
        self.assertNotEqual(wrong_context.returncode, 0)
        self.assertFalse((self.root / "wrong-key-output").exists())
        self.assertFalse((self.root / "wrong-context-output").exists())

    def test_ciphertext_tampering_fails_before_extraction(self) -> None:
        sealed = self.root / "sealed"
        self.assertEqual(
            self.run_handoff("seal", self.source, sealed).returncode,
            0,
        )
        ciphertext = sealed / "stable-1.0-protected-handoff.enc"
        value = bytearray(ciphertext.read_bytes())
        value[-1] ^= 1
        ciphertext.write_bytes(value)

        result = self.run_handoff(
            "open",
            sealed,
            self.root / "tampered-output",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "protected-handoff-bundle-invalid",
            result.stdout,
        )
        self.assertFalse((self.root / "tampered-output").exists())

    def test_symbolic_link_cannot_enter_the_encrypted_handoff(self) -> None:
        target = self.root / "outside.json"
        target.write_text('{"protected":true}\n', encoding="utf-8")
        (self.source / "linked.json").symlink_to(target)

        result = self.run_handoff(
            "seal",
            self.source,
            self.root / "sealed",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "protected-handoff-source-entry-unsafe",
            result.stdout,
        )
        self.assertFalse((self.root / "sealed").exists())


if __name__ == "__main__":
    unittest.main()

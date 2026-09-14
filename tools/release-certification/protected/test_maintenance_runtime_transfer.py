"""Roster-only transfer tests; crypto and native authority are tested by their owning suites."""
import hashlib
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

import maintenance_runtime_transfer as transfer


class RuntimeTransferTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        self.frozen = {"runtime-companion.json": b'{"fixed":"descriptor"}',
                       "runtime-companion.cms": b"synthetic-roster-only-ciphertext"}
        for name, raw in self.frozen.items():
            (self.source / name).write_bytes(raw)
        def inspect(freeze, root):
            if freeze != {"schemaVersion": 3}:
                raise ValueError("fixture-freeze-mismatch")
            for name, raw in self.frozen.items():
                if (root / name).read_bytes() != raw:
                    raise ValueError("fixture-byte-mismatch")
        module = types.SimpleNamespace(inspect=inspect)
        self.addCleanup(patch.stopall)
        patch.dict(sys.modules, {"maintenance_runtime_companion": module}).start()

    def test_transfer_preserves_exact_bytes_and_existing_destination_is_not_replaced(self):
        destination = self.root / "destination"
        transfer.copy_runtime({"schemaVersion": 3}, self.source, destination)
        self.assertEqual({p.name: p.read_bytes() for p in destination.iterdir()}, self.frozen)
        with self.assertRaises(transfer.RuntimeTransferError):
            transfer.copy_runtime({"schemaVersion": 3}, self.source, destination)
        self.assertEqual({p.name: p.read_bytes() for p in destination.iterdir()}, self.frozen)

    def test_missing_extra_and_reencrypted_members_fail_without_output(self):
        for mutation in ("missing", "extra", "changed"):
            with self.subTest(mutation=mutation):
                path = self.source / "runtime-companion.cms"
                path.write_bytes(self.frozen[path.name])
                extra = self.source / "projection-inventory.json"
                extra.unlink(missing_ok=True)
                if mutation == "missing":
                    path.unlink()
                elif mutation == "extra":
                    extra.write_bytes(b"private-canary")
                else:
                    path.write_bytes(b"different-randomized-ciphertext")
                destination = self.root / mutation
                with self.assertRaises(transfer.RuntimeTransferError):
                    transfer.copy_runtime({"schemaVersion": 3}, self.source, destination)
                self.assertFalse(destination.exists())
                self.assertFalse(list(self.root.glob(".runtime-transfer-*")))

    def test_links_and_overlapping_output_are_rejected(self):
        path = self.source / "runtime-companion.cms"
        raw = path.read_bytes()
        path.unlink()
        target = self.root / "ciphertext"
        target.write_bytes(raw)
        path.symlink_to(target)
        with self.assertRaises(transfer.RuntimeTransferError):
            transfer.copy_runtime({"schemaVersion": 3}, self.source, self.root / "symlink")
        path.unlink()
        import os
        os.link(target, path)
        with self.assertRaises(transfer.RuntimeTransferError):
            transfer.copy_runtime({"schemaVersion": 3}, self.source, self.root / "hardlink")
        with self.assertRaises(transfer.RuntimeTransferError):
            transfer.copy_runtime({"schemaVersion": 3}, self.source, self.source / "nested")

    def test_legacy_runtime_uses_own_validator_and_exact_plaintext_roster(self):
        legacy = self.root / "legacy"
        legacy.mkdir()
        names = {transfer.MANIFEST_FILE, *transfer.MEMBER_NAMES.values()}
        for name in names:
            (legacy / name).write_bytes(b"legacy-fixture")
        with patch.object(transfer, "validate_runtime_metadata") as validate:
            transfer.copy_runtime({"schemaVersion": 2}, legacy, self.root / "copied-legacy")
        self.assertEqual(validate.call_count, 3)
        self.assertEqual({p.name for p in (self.root / "copied-legacy").iterdir()}, names)

    def _inputs(self):
        inputs = self.root / "inputs"
        inputs.mkdir()
        runtime = inputs / "runtime-inputs"
        runtime.mkdir()
        self.source.rename(runtime / "runtime")
        canary = b"private-selected-federation-scope-canary"
        for name in ("cohort.json", "projection-selection.json", "trust/scope.json"):
            path = runtime / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(canary)
        public = inputs / "candidate.json"
        public.write_bytes(b'{"approved":"public-input"}')
        (inputs / "unreferenced.json").write_bytes(canary)
        manifest = {"inputs": {"maintenanceRuntimeInputs": str(runtime),
                               "maintenanceCandidate": str(public)}}
        return inputs, runtime, manifest, canary

    def test_staging_retains_only_referenced_inputs_and_sealed_runtime(self):
        inputs, runtime, manifest, canary = self._inputs()
        destination = self.root / "staged"
        transfer.stage_protected_inputs({"schemaVersion": 3}, manifest, inputs, destination)
        files = {str(p.relative_to(destination)): p.read_bytes()
                 for p in destination.rglob("*") if p.is_file()}
        self.assertEqual(set(files), {"candidate.json", "runtime-inputs/runtime/runtime-companion.json",
                                     "runtime-inputs/runtime/runtime-companion.cms"})
        rendered = repr(files).encode()
        self.assertNotIn(canary, rendered)
        self.assertNotIn(hashlib.sha256(canary).hexdigest().encode(), rendered)
        self.assertEqual(files["runtime-inputs/runtime/runtime-companion.cms"],
                         self.frozen["runtime-companion.cms"])
        self.assertTrue((runtime / "cohort.json").exists())

    def test_other_input_cannot_reintroduce_private_runtime_member(self):
        inputs, runtime, manifest, _ = self._inputs()
        manifest["inputs"]["alias"] = str(runtime / "cohort.json")
        with self.assertRaises(transfer.RuntimeTransferError):
            transfer.stage_protected_inputs({"schemaVersion": 3}, manifest, inputs, self.root / "staged")
        self.assertFalse((self.root / "staged").exists())

    def _freeze_tree(self):
        import json
        from maintenance_runtime_metadata import digest_bytes, semantic_digest
        root = self.root / "freeze"
        root.mkdir()
        self.source.rename(root / "runtime")
        assets = root / "assets"
        assets.mkdir()
        raw = b"exact-public-product"
        (assets / "product.tar.gz").write_bytes(raw)
        rows = [{"fileName": "product.tar.gz", "digest": digest_bytes(raw),
                 "sizeBytes": len(raw), "publicAsset": True, "role": "product"}]
        checksums = b"original-public-checksums"
        (root / "checksums.txt").write_bytes(checksums)
        freeze = {"schemaVersion": 3, "assets": rows, "checksumsDigest": digest_bytes(checksums),
                  "assetSetDigest": semantic_digest(rows)}
        (root / "stable-1.0-maintenance-candidate-freeze.json").write_text(json.dumps(freeze))
        return root, freeze

    def test_complete_freeze_retention_preserves_original_bytes(self):
        source, freeze = self._freeze_tree()
        destination = self.root / "retained-freeze"
        with patch("cryptad_certification.schema_validation.validate_schema", return_value=[]), patch.object(
                sys.modules["maintenance_runtime_companion"], "inspect"):
            transfer.copy_frozen_tree(freeze, source, destination)
        original = {str(p.relative_to(source)): p.read_bytes() for p in source.rglob("*") if p.is_file()}
        retained = {str(p.relative_to(destination)): p.read_bytes() for p in destination.rglob("*") if p.is_file()}
        self.assertEqual(retained, original)

    def test_complete_freeze_rejects_extra_or_substituted_assets(self):
        source, freeze = self._freeze_tree()
        with patch("cryptad_certification.schema_validation.validate_schema", return_value=[]), patch.object(
                sys.modules["maintenance_runtime_companion"], "inspect"):
            (source / "private.json").write_bytes(b"private-canary")
            with self.assertRaises(transfer.RuntimeTransferError):
                transfer.copy_frozen_tree(freeze, source, self.root / "extra")
            (source / "private.json").unlink()
            (source / "assets/product.tar.gz").write_bytes(b"substituted-product")
            with self.assertRaises(transfer.RuntimeTransferError):
                transfer.copy_frozen_tree(freeze, source, self.root / "changed")
        self.assertFalse((self.root / "extra").exists())
        self.assertFalse((self.root / "changed").exists())
        self.assertFalse(list(self.root.glob(".freeze-transfer-*")))

    def test_legacy_staging_cannot_silently_strip_inputs(self):
        inputs, _, manifest, _ = self._inputs()
        with self.assertRaises(transfer.RuntimeTransferError):
            transfer.stage_protected_inputs({"schemaVersion": 2}, manifest, inputs, self.root / "staged")


if __name__ == "__main__":
    unittest.main()

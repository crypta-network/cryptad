"""Offline maintenance semantics require an owning original private capability."""
from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch

import maintenance_runtime_validation as validation


class OriginalRuntimeContextTest(unittest.TestCase):
    def fresh_invocation(self, version):
        from cryptad_certification.models import RunManifest, ReleaseSpec, OutputSpec
        from cryptad_certification.workspace import prepare_run_root, prepare_context
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary).resolve()
            assets = workspace / "assets"
            assets.mkdir()
            package = assets / "package.tar.gz"
            package.write_bytes(b"original public package")
            freeze = {"schemaVersion": version, "assets": [{"role": "product", "fileName": package.name}]}
            freeze_path = workspace / "freeze.json"
            freeze_path.write_text(json.dumps(freeze))
            manifest = RunManifest(workspace / "manifest.json", ReleaseSpec("maintenance-307", "307", "stable-review"),
                OutputSpec(workspace / "output", reset=True), {},
                {"maintenanceCandidateFreeze": "freeze.json", "maintenanceCandidateAssets": "assets"}, {}, {}, {})
            run_root = manifest.output.root / manifest.release.release_id
            opened = []
            @contextmanager
            def original(selected_freeze, selected_package, *, freeze_digest):
                self.assertEqual(freeze, selected_freeze)
                self.assertEqual(package, selected_package)
                self.assertEqual(validation.metadata.digest_bytes(freeze_path.read_bytes()), freeze_digest)
                opened.append("open")
                try:
                    yield
                finally:
                    opened.append("close")
            def certify(arguments):
                self.assertEqual(["stable-maintenance", "--manifest", str(manifest.path)], arguments)
                # No earlier unrelated certify invocation or duplicate reset prepared this root.
                self.assertFalse(run_root.exists())
                prepare_run_root(manifest)
                context = prepare_context(workspace, manifest, "stable-maintenance")
                self.assertTrue(context.component_dir.is_dir())
                self.assertEqual(["open"] if version == 3 else [], opened)
                return 23
            with patch.object(validation.Path, "cwd", return_value=workspace), \
                    patch("cryptad_certification.manifest.load_manifest", return_value=manifest), \
                    patch("cryptad_certification.cli.main", side_effect=certify), \
                    patch.object(validation, "original_context", side_effect=original) as resolver:
                if version == 3:
                    with self.assertRaisesRegex(validation.RuntimeValidationError, "isolated-worker-required"):
                        validation.main(["--manifest", str(manifest.path)])
                else:
                    self.assertEqual(23, validation.main(["--manifest", str(manifest.path)]))
            self.assertEqual([], opened)
            resolver.assert_not_called()
            self.assertEqual(version != 3, (run_root / ".cryptad-certification-run.json").is_file())

    def test_fresh_legacy_workspace_is_prepared_once_by_normal_cli(self):
        self.fresh_invocation(1)

    def test_sealed_hosted_cli_blocks_before_private_opening_or_workspace_creation(self):
        self.fresh_invocation(3)

    def test_cli_delegates_to_canonical_module_authority(self):
        source = Path(validation.__file__).resolve()
        script = ('import runpy, sys; sys.path.insert(0, sys.argv[1]); '
                  'import maintenance_runtime_validation as owner; '
                  'owner.main=lambda: 37; runpy.run_path(sys.argv[2], run_name="__main__")')
        result = subprocess.run([sys.executable, '-c', script, str(source.parent), str(source)],
                                capture_output=True, timeout=30)
        self.assertEqual(37, result.returncode)

    def test_local_outer_integrity_cannot_install_authority(self):
        with patch('maintenance_runtime_companion.inspect') as inspect:
            with self.assertRaisesRegex(validation.RuntimeValidationError, 'original-private-context-required'):
                validation.require_context({'schemaVersion': 3}, Path('sealed'), Path('package'))
            inspect.assert_called_once()

    def test_serialized_flags_cannot_construct_context(self):
        with self.assertRaises(validation.RuntimeValidationError):
            validation._OriginalContext({'authenticated': True}, {}, Path('absent'), {})

    def test_context_is_bound_to_exact_product_and_lifetime(self):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / 'package'
            package.write_bytes(b'public product')
            freeze = {'schemaVersion': 3, 'runtimeMetadata': {'digest': 'original'}}
            binding = {'descriptor': freeze['runtimeMetadata'], 'ciphertextDigest': 'sha256:' + 'a' * 64}
            row = {'_runtimeContext': object(), '_freeze': freeze, 'sealedRuntimeBinding': binding,
                   'artifactDigest': validation.metadata.digest_bytes(b'public product'),
                   'artifactSize': len(b'public product')}
            context = validation._OriginalContext(validation._SEAL, freeze, package, row)
            context.check(freeze, package, binding)
            with self.assertRaisesRegex(validation.RuntimeValidationError, 'original-freeze-substituted'):
                validation._OriginalContext(validation._SEAL,
                    {**freeze, 'runtimeMetadata': {'digest': 'substituted'}}, package, row)
            with self.assertRaisesRegex(validation.RuntimeValidationError, 'original-freeze-substituted'):
                validation._OriginalContext(validation._SEAL, freeze, package,
                    {**row, 'sealedRuntimeBinding': {**binding, 'descriptor': {'digest': 'substituted'}}})
            token = validation._ACTIVE.set(context)
            self.addCleanup(validation._ACTIVE.reset, token)
            with patch('maintenance_runtime_companion.inspect', return_value={'ciphertext': {'digest': 'substituted'}}):
                with self.assertRaisesRegex(validation.RuntimeValidationError, 'context-substituted'):
                    validation.require_context(freeze, Path('local-companion'), package)
            package.write_bytes(b'changed product')
            with self.assertRaises(validation.RuntimeValidationError):
                context.check(freeze, package, binding)
            package.write_bytes(b'public product')
            context.active = False
            with self.assertRaises(validation.RuntimeValidationError):
                context.check(freeze, package, binding)


if __name__ == '__main__':
    unittest.main()

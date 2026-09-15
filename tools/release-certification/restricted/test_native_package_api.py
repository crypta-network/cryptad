"""Test-only stage admission; actual kernel/native acceptance belongs to the guest lane."""
import contextlib
import hashlib
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
import zipfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'protected'))
import disposable_integration as integration
import maintenance_runtime_metadata as metadata
import pr312_native_faults as fixtures
import restricted_native as native


class PackageStageTest(unittest.TestCase):
    def test_installed_product_substitution_rejects_before_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, installed = root / 'source', root / 'installed'
            for folder, raw in ((source, b'selected'), (installed, b'substitution')):
                product = folder / 'build/cryptad-dist/lib/cryptad.jar'
                product.parent.mkdir(parents=True)
                product.write_bytes(raw)
            output = root / 'observation'
            with patch.object(integration, 'INSTALLED', installed), \
                    patch.object(fixtures, '_fixture_jdk') as stage, \
                    patch.object(metadata, 'observe_package') as observe:
                with self.assertRaisesRegex(ValueError, 'product-substituted'):
                    integration.native_package_api(root / 'jdk', 'a' * 64, source, root=output)
            stage.assert_not_called()
            observe.assert_not_called()
            self.assertFalse(output.exists())

    def test_native_owner_receives_exact_selected_jar_and_retains_no_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            product = root / 'source/build/cryptad-dist/lib/cryptad.jar'
            product.parent.mkdir(parents=True)
            jar = io.BytesIO()
            with zipfile.ZipFile(jar, 'w') as archive:
                member = zipfile.ZipInfo('fixture.txt', date_time=(1980, 1, 1, 0, 0, 0))
                member.external_attr = 0o100644 << 16
                archive.writestr(member, b'synthetic-selected-jar')
            product.write_bytes(jar.getvalue())
            digest = 'sha256:' + hashlib.sha256(product.read_bytes()).hexdigest()
            output = root / 'observation'
            def observe(package, java, private_root):
                with tarfile.open(package, 'r:gz') as archive:
                    self.assertEqual(['lib/cryptad.jar'], archive.getnames())
                    self.assertEqual(product.read_bytes(), archive.extractfile('lib/cryptad.jar').read())
                return b'{"contract":{}}', b'{"baselineRegistry":{}}', {
                    'member': 'lib/cryptad.jar', 'digest': digest, 'sizeBytes': product.stat().st_size}
            with patch.object(integration, 'INSTALLED', root / 'source'), \
                    patch.object(fixtures, '_fixture_jdk', return_value=root / 'jdk'), \
                    patch.object(native, 'owning_boundary', return_value=contextlib.nullcontext()), \
                    patch.object(metadata, 'observe_package', side_effect=observe), \
                    patch.object(metadata, 'validate_schema', return_value=[]):
                result = integration.native_package_api(root / 'jdk', 'a' * 64,
                    root / 'source', root=output)
            self.assertEqual(['installed-real-package-api-export-owner-validated'], result)
            self.assertIn('"productionEligible": false', (output / 'observation.json').read_text())


if __name__ == '__main__':
    unittest.main()

"""Host byte binding regressions; these do not boot or attest a guest."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import installation
import pr312_reference_vm as reference


class HostIdentityTest(unittest.TestCase):
    def test_group_identity_binds_private_boot_and_fixture_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = {key: 'a' * (40 if key.endswith(('Commit', 'Tree')) else 64)
                      for key in ('helperSourceCommit', 'helperSourceTree', 'productSourceCommit',
                                  'productDigest', 'preparedImageDigest', 'fixtureManifestDigest')}
            execution = {'sourceCommit': report['helperSourceCommit'], 'bundleIdentity': 'b' * 64,
                         'dependencies': {'fixed': 'identity'}}
            (root / 'execution.private.json').write_text(json.dumps(execution))
            (root / 'test-kit.private.json').write_bytes(b'private expected kit bytes')
            kit = hashlib.sha256((root / 'test-kit.private.json').read_bytes()).hexdigest()
            (root / 'installed-verification.private.json').write_text(json.dumps({
                'sourceCommit': report['helperSourceCommit'], 'bundleIdentity': 'b' * 64,
                'executionClosureDigest': 'sha256:' + installation.digest(installation.encode(execution['dependencies']))}))
            boot = {'files': {'fixed-tool': 'c' * 64}, 'bootInputs': {
                key: 'd' * 64 for key in ('seedDigest', 'sshHostKeyPinDigest', 'sshKeyDigest')}}
            def identify():
                (root / 'boot-inputs.private.json').write_text(json.dumps(boot))
                return reference.verified_attempt_identity(report, root, 'b' * 64, kit)
            original = identify()
            for key in boot['bootInputs']:
                with self.subTest(key=key):
                    boot['bootInputs'][key] = 'e' * 64
                    self.assertNotEqual(original['bootClosureDigest'], identify()['bootClosureDigest'])
                    boot['bootInputs'][key] = 'd' * 64
            report['fixtureManifestDigest'] = 'f' * 64
            self.assertNotEqual(original, identify())
            public = reference.public_report({'hostVerifiedIdentity': identify(), **report})
            self.assertNotIn('hostVerifiedIdentity', public)
            self.assertNotIn('fixtureManifestDigest', public)
            (root / 'test-kit.private.json').write_bytes(b'substituted')
            with self.assertRaisesRegex(ValueError, 'installed-identity-substituted'):
                identify()


if __name__ == '__main__':
    unittest.main()

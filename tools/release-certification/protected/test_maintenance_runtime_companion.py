"""Executable CMS transport checks; these are not native/original admission evidence."""
import contextlib
import datetime as dt
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import maintenance_runtime_companion as companion


@unittest.skipUnless(sys.platform == 'linux', 'maintenance CMS uses the fixed Linux resource limiter')
class CompanionTransportTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / 'private'
        self.source.mkdir(mode=0o700)
        self.files = {name: json.dumps({'private-canary': name}).encode() for name in companion.MEMBERS}
        for name, raw in self.files.items():
            (self.source / name).write_bytes(raw)
        self.cert, self.key, self.policy = (self.root / name for name in ('cert', 'key', 'policy'))
        subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(self.key), '-out', str(self.cert), '-days', '1',
                        '-subj', '/CN=synthetic-maintenance-runtime'],
                       capture_output=True, check=True, timeout=30)
        self.key.chmod(0o600)
        now = dt.datetime.now(dt.timezone.utc)
        self.policy.write_text(json.dumps({'schemaVersion': 1, 'purpose': companion.PURPOSE,
            'policy': companion.POLICY_ID, 'epoch': 1, 'certificateDigest': companion._digest(self.cert.read_bytes()),
            'notBefore': (now - dt.timedelta(days=1)).isoformat(),
            'notAfter': (now + dt.timedelta(days=1)).isoformat(), 'status': 'active'}))
        self.freeze = {'schemaVersion': 3, 'releaseId': 'stable-test', 'buildVersion': 307,
                       'source': {'commit': 'a' * 40}, 'producer': {'runId': 123, 'runAttempt': 1},
                       'assetSetDigest': 'sha256:' + 'b' * 64,
                       'checksumsDigest': 'sha256:' + 'c' * 64}
        stack = self.enterContext(contextlib.ExitStack())
        for name, value in (('POLICY', self.policy), ('RECIPIENT', self.cert), ('RECIPIENT_KEY', self.key)):
            stack.enter_context(patch.object(companion, name, value))
        # Synthetic fixture ownership is the only relaxed policy check in this transport test.
        read = companion._read
        stack.enter_context(patch.object(companion, '_read', side_effect=lambda path, maximum=companion.MAX_BYTES,
            protected=False, key=False: read(path, maximum, key=key)))

    def seal(self, name='transfer'):
        target = self.root / name
        freeze = {**self.freeze, 'runtimeMetadata': companion.seal(self.source, target, self.freeze)}
        freeze['frozenAt'] = companion.dt.datetime.now(companion.dt.timezone.utc).isoformat()
        return freeze, target

    def test_real_randomized_roundtrip_and_owned_cleanup(self):
        first, target = self.seal()
        second, other = self.seal('other')
        self.assertNotEqual((target / companion.CIPHERTEXT).read_bytes(), (other / companion.CIPHERTEXT).read_bytes())
        for freeze, root in ((first, target), (second, other)):
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            self.assertEqual({companion.DESCRIPTOR, companion.CIPHERTEXT}, set(before))
            self.assertNotIn(b'private-canary', b''.join(before.values()))
            for _ in range(2):
                with companion.open_companion(freeze, root, self.root) as opened:
                    self.assertEqual(self.files, {p.name: p.read_bytes() for p in opened.iterdir()})
                self.assertFalse(opened.exists())
            self.assertEqual(before, {p.name: p.read_bytes() for p in root.iterdir()})
        with self.assertRaises(companion.CompanionError):
            companion.seal(self.source, target, first)

    def test_original_authority_is_not_created_and_offline_inspection_needs_no_key(self):
        freeze, target = self.seal()
        self.key.unlink()
        self.assertEqual('maintenance-runtime-companion', companion.inspect(freeze, target)['kind'])
        with self.assertRaisesRegex(companion.CompanionError, 'runtime-companion-recipient-key-missing'):
            with companion.open_companion(freeze, target, self.root):
                self.fail('missing key admitted')

    def test_missing_policy_and_crypto_implementation_have_precise_blockers(self):
        self.policy.unlink()
        with self.assertRaisesRegex(companion.CompanionError, 'runtime-companion-recipient-policy-missing'):
            self.seal()
        for missing, code in (('/usr/bin/openssl', 'runtime-companion-openssl-unavailable'),
                              ('/usr/bin/prlimit', 'runtime-companion-resource-limiter-unavailable')):
            with patch.object(companion.os, 'access', side_effect=lambda path, mode: path != missing):
                with self.assertRaisesRegex(companion.CompanionError, code):
                    companion._openssl(['version'])

    def test_partial_failed_decryption_is_never_parsed_and_is_cleaned(self):
        freeze, target = self.seal()
        openssl, parse = companion._openssl, companion._json
        parsed = []
        partial = b'{"private-partial-canary":true}'
        def execute(arguments, **kwargs):
            if '-decrypt' in arguments:
                Path(arguments[arguments.index('-out') + 1]).write_bytes(partial)
                raise ValueError('simulated failure')
            return openssl(arguments, **kwargs)
        def record(raw):
            parsed.append(raw)
            return parse(raw)
        with patch.object(companion, '_openssl', side_effect=execute), \
                patch.object(companion, '_json', side_effect=record):
            with self.assertRaises(companion.CompanionError):
                with companion.open_companion(freeze, target, self.root):
                    self.fail('partial output admitted')
        self.assertNotIn(partial, parsed)
        self.assertFalse(list(self.root.glob('runtime-open-*')))

    def test_context_substitution_and_bad_tag_do_not_materialize(self):
        freeze, target = self.seal()
        for changed in ({**freeze, 'buildVersion': 308}, {**freeze, 'source': {'commit': 'd' * 40}},
                        {**freeze, 'producer': {'runId': 124, 'runAttempt': 1}}):
            with self.assertRaises(companion.CompanionError):
                with companion.open_companion(changed, target, self.root):
                    self.fail('substitution admitted')
        raw = (target / companion.CIPHERTEXT).read_bytes()
        raw = raw[:-1] + bytes([raw[-1] ^ 1])
        (target / companion.CIPHERTEXT).write_bytes(raw)
        descriptor = json.loads((target / companion.DESCRIPTOR).read_bytes())
        descriptor['ciphertext'] = companion._identity(companion.CIPHERTEXT, raw)
        descriptor_raw = companion._bytes(descriptor)
        (target / companion.DESCRIPTOR).write_bytes(descriptor_raw)
        freeze['runtimeMetadata'] = companion._identity(companion.DESCRIPTOR, descriptor_raw)
        with self.assertRaises(companion.CompanionError):
            with companion.open_companion(freeze, target, self.root):
                self.fail('bad tag admitted')
        self.assertFalse(list(self.root.glob('runtime-open-*')))

    def test_cbc_and_trailing_bytes_are_rejected_by_crypto_shape(self):
        cert = self.cert.read_bytes()
        raw = companion._cms(b'{}', self.root, cert)
        with self.assertRaises(companion.CompanionError):
            companion._cms(raw + b'trailing', self.root, cert, decrypt=True)
        source, output = self.root / 'cbc-input', self.root / 'cbc-output'
        source.write_bytes(b'{}')
        companion._openssl(['cms', '-encrypt', '-binary', '-in', str(source), '-out', str(output),
                            '-outform', 'DER', '-aes-256-cbc', str(self.cert)])
        with self.assertRaises(companion.CompanionError):
            companion._cms(output.read_bytes(), self.root, cert, decrypt=True)

    def test_policy_revocation_and_epoch_change_fail_closed(self):
        freeze, target = self.seal()
        original = json.loads(self.policy.read_bytes())
        for update in ({'status': 'revoked'}, {'epoch': 2}, {'purpose': 'federation-selection'},
                       {'notAfter': '2000-01-01T00:00:00+00:00'}):
            self.policy.write_text(json.dumps({**original, **update}))
            with self.assertRaises(companion.CompanionError):
                with companion.open_companion(freeze, target, self.root):
                    self.fail('unapproved policy admitted')

    def test_wrong_key_and_other_purpose_never_yield_plaintext(self):
        freeze, target = self.seal()
        key_bytes = self.key.read_bytes()
        subprocess.run(['/usr/bin/openssl', 'genpkey', '-algorithm', 'RSA',
                        '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(self.key)],
                       capture_output=True, check=True, timeout=30)
        with self.assertRaises(companion.CompanionError):
            with companion.open_companion(freeze, target, self.root):
                self.fail('wrong key admitted')
        self.key.write_bytes(key_bytes)
        private = companion._json(companion._cms((target / companion.CIPHERTEXT).read_bytes(),
                                  self.root, self.cert.read_bytes(), decrypt=True))
        private['kind'] = 'private-federation-selection'
        ciphertext = companion._cms(companion._bytes(private), self.root, self.cert.read_bytes())
        (target / companion.CIPHERTEXT).write_bytes(ciphertext)
        descriptor = json.loads((target / companion.DESCRIPTOR).read_bytes())
        descriptor['ciphertext'] = companion._identity(companion.CIPHERTEXT, ciphertext)
        raw = companion._bytes(descriptor)
        (target / companion.DESCRIPTOR).write_bytes(raw)
        freeze['runtimeMetadata'] = companion._identity(companion.DESCRIPTOR, raw)
        with self.assertRaises(companion.CompanionError):
            with companion.open_companion(freeze, target, self.root):
                self.fail('other purpose admitted')
        self.assertFalse(list(self.root.glob('runtime-open-*')))

    def test_reencryption_cannot_replace_frozen_bytes_and_missing_member_is_not_recreated(self):
        freeze, target = self.seal()
        _, other = self.seal('other')
        (target / companion.CIPHERTEXT).write_bytes((other / companion.CIPHERTEXT).read_bytes())
        with self.assertRaises(companion.CompanionError):
            companion.inspect(freeze, target)
        (target / companion.CIPHERTEXT).unlink()
        with self.assertRaises(companion.CompanionError):
            companion.inspect(freeze, target)
        self.assertFalse((target / companion.CIPHERTEXT).exists())

    def test_closed_roster_links_overlap_and_duplicate_json(self):
        (self.source / 'extra').write_bytes(b'private-canary')
        with self.assertRaises(companion.CompanionError):
            self.seal()
        (self.source / 'extra').unlink()
        member = self.source / 'snapshot.json'
        member.unlink()
        member.symlink_to(self.source / 'runtime-subjects.json')
        with self.assertRaises(companion.CompanionError):
            self.seal()
        with self.assertRaises(companion.CompanionError):
            companion.seal(self.source, self.source / 'nested', self.freeze)
        with self.assertRaises(companion.CompanionError):
            companion._json(b'{"key":1,"key":2}')


if __name__ == '__main__':
    unittest.main()

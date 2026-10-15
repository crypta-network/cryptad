"""Private capsule ownership, fixed root source mapping, and original adoption regressions."""
import base64
import copy
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import pr320_campaign_capture as capture
import pr320_owner_runtime_evidence as evidence
from test_pr320_owner_installed import originals_fixture


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def fixture():
    private, selected, diagnostics, terminal, checkpoints, native = originals_fixture()
    originals = dict(owner='pr320_owner_runtime_evidence', private=base64.b64encode(raw(private)).decode(),
        selected=selected, diagnostics=diagnostics, terminal=terminal, report=None,
        checkpoints=base64.b64encode(b'\n'.join(raw(row) for row in checkpoints)).decode(),
        native=base64.b64encode(raw(native)).decode(), privacyOriginals=None, browser=None, artifact=None)
    root = dict(schemaVersion=1, kind='pr320-root-original-input-capture',
        planDigest=capture.journal.legacy.pressure.baseline.digest(selected['plan']), originals=originals)
    return root


class PrivateCaptureTest(unittest.TestCase):
    def test_root_precursor_has_no_host_clock_report_or_authentication_claim(self):
        value = fixture()
        self.assertEqual(value, capture.decode_root_capsule(raw(value)))
        for fault in ('report', 'owner', 'digest', 'private'):
            changed = copy.deepcopy(value)
            if fault == 'report': changed['originals']['report'] = {'claimed': 'host-clock'}
            elif fault == 'owner': changed['originals']['owner'] = 'unselected_consumer'
            elif fault == 'digest': changed['planDigest'] = 'sha256:' + '0' * 64
            else: changed['originals']['private'] = base64.b64encode(b'{}').decode()
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                capture.decode_root_capsule(raw(changed))

    def test_descriptor_reader_rejects_mutable_permissions_and_symbolic_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'fixed.json'
            path.write_bytes(b'original')
            path.chmod(0o600)
            self.assertEqual(b'original', capture._read_owned(path, 32, os.geteuid()))
            path.chmod(0o644)
            with self.assertRaises(ValueError): capture._read_owned(path, 32, os.geteuid())
            path.chmod(0o600)
            linked = root / 'link'
            linked.symlink_to(root, target_is_directory=True)
            with self.assertRaises(OSError): capture._read_owned(linked / path.name, 32, os.geteuid())
            with self.assertRaises(ValueError): capture._read_owned(path, 3, os.geteuid())

    def test_fixed_root_mapping_reads_actor_files_and_root_authority_sources_separately(self):
        value = fixture()
        source = value['originals']
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'authority').mkdir(mode=0o700)
            workload = SimpleNamespace(ROOT=root, secured=lambda *_args, **_kwargs: None)
            seen = []
            def read(path, _maximum, uid):
                seen.append((path, uid))
                name = ('native' if path.name == 'pr320-owner-original-native.json' else
                    'private' if path.name == evidence.PRIVATE_FILE else 'checkpoints')
                return base64.b64decode(source[name])
            with patch.object(capture.os, 'geteuid', return_value=0), \
                    patch.object(capture.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=1000)), \
                    patch.object(capture, '_read_owned', side_effect=read):
                metadata = capture.prepare_root(workload, source['selected'], source['diagnostics'], source['terminal'])
            self.assertEqual([1000, 1000, 0], [uid for _path, uid in seen])
            self.assertEqual(root / 'authority/pr320-owner-original-native.json', seen[-1][0])
            self.assertEqual('pr320-campaign-original-inputs.private.json', metadata['file'])
            self.assertEqual(value, capture.decode_root_capsule((root / 'authority' / capture.FILE).read_bytes()))

    def test_host_adopts_root_fields_and_cannot_replace_originals(self):
        value = fixture()
        source = value['originals']
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, content in ((evidence.PRIVATE_FILE, base64.b64decode(source['private'])),
                (evidence.CHECKPOINT_FILE, base64.b64decode(source['checkpoints'])),
                (evidence.ROOT_NATIVE_FILE, base64.b64decode(source['native'])),
                ('pr320-selection.private.json', raw(source['selected'])),
                ('pr315-workload-memory.private.json', raw(source['diagnostics'])),
                ('pr315-workload-volatile.private.json', raw(source['terminal'])), (capture.ROOT_FILE, raw(value))):
                path = root / name; path.write_bytes(content); path.chmod(0o600)
            destination = capture.prepare(root, {'host': 'measured-report'}, source['owner'])
            prepared = json.loads(destination.read_bytes())
            self.assertEqual({'host': 'measured-report'}, prepared['entries'][0]['originals']['report'])
            self.assertEqual(source['diagnostics'], prepared['entries'][0]['originals']['diagnostics'])
            destination.unlink()
            modified = {**source['diagnostics'], 'ownerOriginalCollection': 'incomplete'}
            (root / 'pr315-workload-memory.private.json').write_bytes(raw(modified))
            with self.assertRaises(ValueError): capture.prepare(root, {'host': 'measured-report'}, source['owner'])


if __name__ == '__main__':
    unittest.main()

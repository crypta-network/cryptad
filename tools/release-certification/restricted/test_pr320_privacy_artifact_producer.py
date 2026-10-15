"""Actual certification/export/filesystem-transfer integration; authorization stays test-only."""
import base64
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import pr320_privacy_artifact_producer as producer
from cryptad_certification import composed_budget_privacy_evidence as privacy
from cryptad_certification import certification_public_export as export
from test_pr320_privacy_installed import vector, encoded


class Journal:
    def __init__(self, plan): self.plan, self.events = plan, []
    def append(self, kind, **kwargs):
        value={'kind':kind,**kwargs}; self.events.append(value); return value


def observed_files(root):
    args=vector()
    native_raw=encoded(args['private']); browser_raw=encoded(args['browser'])
    for filename,raw in ((producer.evidence.PRIVATE_FILE,native_raw),(producer.evidence.BROWSER_FILE,browser_raw)):
        path=root/filename; path.write_bytes(raw); path.chmod(0o600)
    selected=args['selected']
    # Only the upstream fixed deployment/root authorization is substituted. Native owners,
    # raw browser verification, certification builders, transfer and artifact validators run.
    adapter=SimpleNamespace(root=root, private=dict(selected['private'],root=str(root)),
        plan=selected['plan'],authorization=selected['authorization'],journal=Journal(selected['plan']))
    return args,adapter


class ArtifactProducerTests(unittest.TestCase):
    def test_real_builder_fresh_export_transfer_summary_and_exact_member17_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); args,adapter=observed_files(root)
            with patch.object(producer.contract,'verify_selection_contract',return_value=True):
                result=producer.produce(adapter)
            raw=(root/producer.FILE).read_bytes(); value=producer.decode_artifact(raw)
            self.assertEqual('sha256:'+hashlib.sha256(encoded(args['private'])).hexdigest(),value['nativeMemberDigest'])
            self.assertEqual('sha256:'+hashlib.sha256(raw).hexdigest(),result['digest'])
            self.assertEqual('verified',result['result']['status'])
            public=root/producer.WORK_ROOT/'public'; transferred=root/producer.WORK_ROOT/'transferred'
            self.assertNotEqual(public.resolve(),transferred.resolve())
            self.assertEqual(export.ROSTER,{path.name for path in public.iterdir()})
            self.assertEqual(export.ROSTER,{path.name for path in transferred.iterdir()})
            summary=export.verify_export(transferred,'a'*40)
            self.assertEqual('fail',summary['status']); self.assertFalse(summary['promotionReady'])
            self.assertEqual('none',summary['exportFailure'])
            self.assertEqual(2,summary['counts']['evidence']); self.assertEqual(1,summary['counts']['blockers'])
            self.assertEqual(value['jobSummary'],(root/producer.WORK_ROOT/'job-summary.md').read_text())
            self.assertEqual(1,len(adapter.journal.events))
            reference=adapter.journal.events[0]['composed_budget_campaign_member']
            self.assertEqual('member-17.json',reference['member'])
            self.assertEqual(raw,base64.b64decode(reference['rawBase64'],validate=True))
            self.assertEqual(value['nativeMemberDigest'],args['browser']['nativeMemberDigest'])
            for name,text in value['files'].items():
                privacy.check_omission(base64.b64decode(text).decode(),
                    [row['marker'] for row in args['private']['component']['stimuli']],public=True)
            with patch.object(producer.contract,'verify_selection_contract',return_value=True):
                with self.assertRaises(FileExistsError): producer.produce(adapter)
            self.assertEqual(1,len(adapter.journal.events))

    def test_missing_or_invalid_native_browser_never_creates_successful_export(self):
        for fault in ('native-missing','native-invalid','browser-invalid','browser-digest'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);args,adapter=observed_files(root)
                if fault=='native-missing':(root/producer.evidence.PRIVATE_FILE).unlink()
                if fault=='native-invalid':(root/producer.evidence.PRIVATE_FILE).write_bytes(b'{}')
                if fault=='browser-invalid':(root/producer.evidence.BROWSER_FILE).write_bytes(b'{}')
                if fault=='browser-digest':
                    args['browser']['nativeMemberDigest']='sha256:'+'0'*64
                    (root/producer.evidence.BROWSER_FILE).write_bytes(encoded(args['browser']))
                with patch.object(producer.contract,'verify_selection_contract',return_value=True):
                    with self.assertRaises((ValueError,OSError)):producer.produce(adapter)
                self.assertFalse((root/producer.FILE).exists());self.assertFalse((root/producer.WORK_ROOT).exists())
                self.assertEqual([],adapter.journal.events)

    def test_actual_transfer_tamper_preserves_failed_roots_and_has_no_member_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);args,adapter=observed_files(root)
            original_write=producer._write
            def tamper(path,raw):
                if path.parent.name=='transferred' and path.name=='report.md':raw+=b'changed transfer\n'
                return original_write(path,raw)
            with patch.object(producer.contract,'verify_selection_contract',return_value=True), \
                 patch.object(producer,'_write',side_effect=tamper):
                with self.assertRaises(ValueError):producer.produce(adapter)
            self.assertTrue((root/producer.WORK_ROOT/'public').is_dir())
            self.assertTrue((root/producer.WORK_ROOT/'transferred/report.md').exists())
            self.assertFalse((root/producer.FILE).exists());self.assertEqual([],adapter.journal.events)

    def test_interrupted_export_retains_originals_and_never_commits_member(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);args,adapter=observed_files(root)
            with patch.object(producer.contract,'verify_selection_contract',return_value=True), \
                 patch.object(producer.export,'create_export',side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):producer.produce(adapter)
            self.assertTrue((root/producer.WORK_ROOT/'workspace').is_dir())
            self.assertTrue((root/producer.evidence.PRIVATE_FILE).is_file())
            self.assertTrue((root/producer.evidence.BROWSER_FILE).is_file())
            self.assertFalse((root/producer.FILE).exists());self.assertEqual([],adapter.journal.events)

    def test_wrong_selection_or_root_is_rejected_before_any_export(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);_args,adapter=observed_files(root)
            with self.assertRaises(ValueError):producer.produce(adapter)
            self.assertFalse((root/producer.WORK_ROOT).exists())


if __name__=='__main__':unittest.main()

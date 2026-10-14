"""Actual export, failed-export, download and job-summary boundaries remain public-only."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptad_certification import certification_public_export as export
from cryptad_certification.envelope import from_legacy

COMMIT = 'a' * 40
CANARY = 'PR320_PRIVATE_CORRELATION_DO_NOT_PUBLISH'


def envelope(workspace, *, status='pass', exit_code=0):
    context = SimpleNamespace(manifest=SimpleNamespace(
        release=SimpleNamespace(release_id='ci-42-1', version='1', profile='pr'), inputs={}),
        workspace_root=workspace, component='release-certification')
    legacy = dict(status=status, releaseCandidatePassed=status == 'pass',
        metadata={'gitCommit': COMMIT},
        generatedAt='2026-10-14T00:00:00Z', evidence=[dict(id='app-platform', status=status,
        summary=CANARY, details={'innocent': CANARY, CANARY: 'private',
        'graphFingerprint': 'b' * 64})], ecosystemGates=[dict(id='native', status=status)],
        redaction={'status': 'pass', 'findingCount': 0, 'findings': [], 'guarantees': {'bounded': True}},
        rawBody=CANARY, selectedAppDigest='sha256:' + 'c' * 64)
    return from_legacy(context, 'release-certification', legacy, exit_code, {}).to_json()


class PublicExportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workspace = self.root / 'workspace'
        self.workspace.mkdir()
        self.destination = self.root / 'public'
        self.manifest = self.root / 'manifest.json'
        self.manifest.write_text(json.dumps({'release': {'id': 'ci-42-1', 'version': '1', 'profile': 'pr'},
                                             'output': {'root': 'build/release-certification'}}))
        self.source = self.workspace / 'build/release-certification/ci-42-1/release-certification/summary.json'
        self.source.parent.mkdir(parents=True)
        self.source.write_bytes(export._json(envelope(self.workspace)))
        (self.source.parent / (CANARY + '.private')).write_text(CANARY)
        (self.source.parent / 'report.md').write_text(CANARY)

    def create(self):
        return export.create_export(self.manifest, self.workspace, self.destination, COMMIT)

    def test_real_envelope_builder_exports_useful_projection_and_transferred_report(self):
        original = self.source.read_bytes()
        result = self.create()
        self.assertEqual('pass', result['status'])
        self.assertEqual(1, result['counts']['evidence'])
        self.assertEqual(1, result['gateStatuses']['pass'])
        self.assertEqual(original, self.source.read_bytes())
        self.assertEqual(export.ROSTER, {p.name for p in self.destination.iterdir()})
        for path in self.destination.iterdir():
            self.assertNotIn(CANARY.encode(), path.read_bytes())
            self.assertNotIn(b'selectedAppDigest', path.read_bytes())
            self.assertNotIn(('b' * 64).encode(), path.read_bytes())
        transfer = self.root / 'downloaded'
        shutil.copytree(self.destination, transfer)
        self.assertEqual(result, export.verify_export(transfer, COMMIT))
        job = self.root / 'job-summary.md'
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, export.main(['job-summary', '--root', str(transfer),
                '--source-commit', COMMIT, '--job-summary', str(job)]))
        self.assertEqual((transfer / 'report.md').read_bytes(), job.read_bytes())
        self.assertFalse(result['originalAcceptance'])
        self.assertFalse(result['phaseComplete'])

    def test_failed_business_candidate_retains_failure_and_useful_counters(self):
        self.source.write_bytes(export._json(envelope(self.workspace, status='fail', exit_code=1)))
        result = self.create()
        self.assertEqual('fail', result['status'])
        self.assertEqual('none', result['exportFailure'])
        self.assertEqual(1, result['evidenceStatuses']['fail'])
        self.assertFalse(result['promotionReady'])

    def test_missing_invalid_redaction_and_empty_collectors_never_export_zero_success(self):
        for case in ('missing', 'malformed', 'redaction', 'empty', 'wrong-kind', 'wrong-release'):
            self.destination = self.root / ('public-' + case)
            candidate = envelope(self.workspace)
            if case == 'missing':
                self.source.unlink()
            elif case == 'malformed':
                self.source.write_text('{"status":"' + CANARY)
            else:
                if case == 'redaction':
                    candidate['redaction']['status'] = 'fail'
                    candidate['result'].update(status='fail', promotionReady=False)
                if case == 'empty':
                    candidate['evidence'] = []
                    candidate['counts']['evidence'] = 0
                if case == 'wrong-kind':
                    candidate['kind'] = 'operator-support'
                if case == 'wrong-release':
                    candidate['subject']['releaseId'] = CANARY
                self.source.write_bytes(export._json(candidate))
            result = self.create()
            self.assertEqual('fail', result['status'])
            self.assertNotEqual('none', result['exportFailure'])
            self.assertFalse(result['promotionReady'])
            self.assertNotIn(CANARY.encode(), (self.destination / 'report.md').read_bytes())

    def test_exact_transferred_roster_digest_and_public_projection_reject_contamination(self):
        self.create()
        (self.destination / (CANARY + '.json')).write_text(CANARY)
        with self.assertRaises(export.ExportError):
            export.verify_export(self.destination, COMMIT)
        (self.destination / (CANARY + '.json')).unlink()
        report = self.destination / 'report.md'
        report.write_text(CANARY)
        with self.assertRaises(export.ExportError):
            export.verify_export(self.destination, COMMIT)
        # Even internally rehashed contamination cannot satisfy the closed projection/report.
        inventory = json.loads((self.destination / 'artifact-manifest.json').read_bytes())
        inventory['members']['report.md'] = {'size': len(report.read_bytes()),
                                             'digest': export._digest(report.read_bytes())}
        (self.destination / 'artifact-manifest.json').write_bytes(export._json(inventory))
        with self.assertRaises(export.ExportError):
            export.verify_export(self.destination, COMMIT)

    def test_unsafe_fields_private_digest_and_wrong_source_reject_even_with_rehashed_manifest(self):
        self.create()
        original = (self.destination / 'summary.json').read_bytes()
        for key, value in (('privateDigest', 'sha256:' + 'd' * 64), (CANARY, True),
                           ('status', CANARY), ('sourceCommit', 'b' * 40)):
            candidate = json.loads(original)
            candidate[key] = value
            body = export._json(candidate)
            (self.destination / 'summary.json').write_bytes(body)
            inventory = json.loads((self.destination / 'artifact-manifest.json').read_bytes())
            inventory['members']['summary.json'] = {'size': len(body), 'digest': export._digest(body)}
            (self.destination / 'artifact-manifest.json').write_bytes(export._json(inventory))
            with self.assertRaises(export.ExportError):
                export.verify_export(self.destination, COMMIT)

    def test_links_and_reused_output_are_rejected_without_copying_private_content(self):
        self.create()
        with self.assertRaises(export.ExportError):
            self.create()
        report = self.destination / 'report.md'
        report.unlink()
        report.symlink_to(self.source)
        with self.assertRaises((OSError, export.ExportError)):
            export.verify_export(self.destination, COMMIT)
        report.unlink()
        os.link(self.source, report)
        with self.assertRaises(export.ExportError):
            export.verify_export(self.destination, COMMIT)
        parent = self.root / 'linked-parent'
        parent.symlink_to(self.workspace, target_is_directory=True)
        with self.assertRaises(OSError):
            export.create_export(self.manifest, self.workspace, parent / 'public', COMMIT)
        self.assertFalse((self.workspace / 'public').exists())

    def test_unreadable_source_disk_failure_and_cancellation_emit_only_fixed_failure(self):
        args = ['create', '--manifest', str(self.manifest), '--workspace', str(self.workspace),
                '--root', str(self.destination), '--source-commit', COMMIT]
        with patch.object(export, 'project', side_effect=OSError(CANARY)):
            result = self.create()
        self.assertEqual('source-invalid', result['exportFailure'])
        for index, exception in enumerate((OSError(CANARY), KeyboardInterrupt(CANARY))):
            args[args.index('--root') + 1] = str(self.root / ('interrupted-' + str(index)))
            capture = io.StringIO()
            with patch.object(export.os, 'fsync', side_effect=exception), contextlib.redirect_stdout(capture):
                self.assertEqual(1, export.main(args))
            self.assertEqual('certification-public-export-failed\n', capture.getvalue())
            with self.assertRaises(export.ExportError):
                export.verify_export(self.root / ('interrupted-' + str(index)), COMMIT)

    def test_source_directory_link_becomes_fixed_failed_public_export(self):
        target = self.root / 'private-root'
        self.source.parent.rename(target)
        self.source.parent.symlink_to(target, target_is_directory=True)
        result = self.create()
        self.assertEqual('source-invalid', result['exportFailure'])
        self.assertNotIn(CANARY.encode(), (self.destination / 'summary.json').read_bytes())

    def test_bounded_source_reader_rejects_output_budget_exhaustion(self):
        self.source.write_bytes(b' ' * (export.LIMIT + 1))
        result = self.create()
        self.assertEqual('source-invalid', result['exportFailure'])
        self.assertFalse(result['promotionReady'])

    def test_stale_source_commit_or_candidate_version_cannot_be_relabelled(self):
        for field in ('commit', 'version', 'profile'):
            self.destination = self.root / ('stale-' + field)
            candidate = envelope(self.workspace)
            if field == 'commit':
                candidate['payload']['legacy']['metadata']['gitCommit'] = 'b' * 40
            else:
                candidate['subject'][field] = 'stale-candidate'
            self.source.write_bytes(export._json(candidate))
            result = self.create()
            self.assertEqual('source-invalid', result['exportFailure'])
            self.assertFalse(result['promotionReady'])

    def test_invalid_download_never_populates_job_summary(self):
        self.create()
        (self.destination / 'report.md').write_text(CANARY)
        job = self.root / 'job-summary.md'
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture):
            code = export.main(['job-summary', '--root', str(self.destination),
                '--source-commit', COMMIT, '--job-summary', str(job)])
        self.assertEqual(1, code)
        self.assertFalse(job.exists())
        self.assertEqual('certification-public-export-failed\n', capture.getvalue())

    def test_actual_workflow_preparation_builds_only_the_verified_public_root(self):
        repository = Path(__file__).resolve().parents[4]
        workflow = (repository / '.github/workflows/release-certification.yml').read_text()
        step = workflow.split('      - name: Prepare exact public certification artifacts\n', 1)[1]
        body = step.split('        run: |\n', 1)[1].split('      - name:', 1)[0]
        shutil.copyfile(self.manifest, self.root / 'release-certification-manifest.json')
        job = self.root / 'workflow-summary.md'
        env = dict(os.environ, RUNNER_TEMP=str(self.root), GITHUB_WORKSPACE=str(self.workspace),
            GITHUB_RUN_ID='42', GITHUB_RUN_ATTEMPT='1', GITHUB_SHA=COMMIT,
            GITHUB_STEP_SUMMARY=str(job))
        process = subprocess.run(['bash', '-c', textwrap.dedent(body)], cwd=repository,
            env=env, capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(0, process.returncode, process.stderr)
        public = self.root / 'certification-public-42-1'
        result = export.verify_export(public, COMMIT)
        self.assertEqual('pass', result['status'])
        self.assertEqual(export.render_report(result), job.read_bytes())
        self.assertNotIn(CANARY, process.stdout + process.stderr)


if __name__ == '__main__':
    unittest.main()

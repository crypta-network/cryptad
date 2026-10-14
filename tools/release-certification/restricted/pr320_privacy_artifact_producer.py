"""Produce the fixed public export/transfer witness from actual installed privacy observations.

The certification result remains failed until original cleanup and the entire cohort are
admitted. Successful privacy omission/transfer does not change that business decision.
No upload, workflow execution or caller-selected input/output root is supported.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
from types import SimpleNamespace

import pr320_privacy_contract as contract
import pr320_privacy_runtime_evidence as evidence
from cryptad_certification import certification_public_export as export
from cryptad_certification import composed_budget_artifact_capture as capture
from cryptad_certification import composed_budget_privacy_evidence as privacy
from cryptad_certification.composed_budget_journal_member import append_member
from cryptad_certification.envelope import from_legacy, utc_now
from cryptad_certification.io import read_json_bytes

FILE = 'pr320-public-artifact.private.json'
LIMIT = 2 * 1024 * 1024
WORK_ROOT = 'pr320-artifact-export.private'
RELEASE_ID = 'pr320-installed-privacy-observation'


def _need(condition):
    if not condition:
        raise ValueError('pr320-privacy-artifact-invalid')


def _write(path, raw):
    _need(isinstance(raw, bytes) and 0 < len(raw) <= LIMIT)
    parent = export._open_directory(path.parent)
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)


def _inputs(adapter):
    _need(contract.verify_selection_contract(adapter.plan, adapter.private, adapter.authorization))
    root = Path(adapter.root)
    _need(root == Path(adapter.private['root']))
    native_raw = export._read_regular(root / evidence.PRIVATE_FILE, evidence.MAX_PRIVATE_BYTES)
    native = evidence.decode_private(native_raw)
    _need(native['selectionDigest'] == adapter.authorization['selectionDigest'])
    browser_raw = export._read_regular(root / evidence.BROWSER_FILE, LIMIT)
    browser = evidence.decode_browser(browser_raw)
    digest = 'sha256:' + hashlib.sha256(native_raw).hexdigest()
    native_result = evidence.verify_component(native['component'])
    # The original root browser receipt later authenticates served script/package identity;
    # this local check grants no source/provider authority from the serialized script hash.
    browser_result = evidence.verify_browser_component(browser, native['component'],
        native_digest=digest, script_digest=browser['scriptDigest'])
    node = next(row for row in adapter.plan['nodes'] if row['role'] == 'candidate-sender')
    _need(re.fullmatch('[0-9a-f]{40}', str(node['sourceCommit'])))
    return root, native_raw, native, browser, native_result, browser_result, node


def _envelope(workspace, native_result, browser_result, node):
    # These statuses follow the actual owner checks above. Original authority and full-cohort
    # admission are unavailable at this pre-shutdown point and remain required failures.
    observations = [native_result, browser_result]
    _need(all(row['status'] == 'verified' and row['originalAuthentication'] == 'not-established'
              and row['releaseEligible'] is False and row['phaseComplete'] is False for row in observations))
    evidence_rows = [{'id': 'installed-privacy-' + row['component'], 'status': 'pass',
                      'summary': 'Owning privacy observation verified at local consistency.'}
                     for row in observations]
    legacy = {'status': 'fail', 'promotionReady': False,
        'generatedAt': utc_now(), 'metadata': {'gitCommit': node['sourceCommit']},
        'evidence': evidence_rows,
        'ecosystemGates': [{'id': 'privacy-export-inputs', 'status': 'pass'},
                           {'id': 'original-cohort-admission', 'status': 'fail'}],
        'blockers': [{'id': 'original-cohort-admission',
                      'summary': 'Original cleanup and full cohort admission remain required.'}],
        'warnings': [], 'waivers': []}
    context = SimpleNamespace(workspace_root=workspace, component='release-certification',
        manifest=SimpleNamespace(inputs={}, release=SimpleNamespace(release_id=RELEASE_ID,
            version=str(node['contractVersion']), profile='pr320-local-privacy')))
    return from_legacy(context, 'release-certification', legacy, 1, {}).to_json()


def decode_artifact(raw):
    """Typed private retention reader; original/native binding belongs to the owning consumer."""
    _need(isinstance(raw, bytes) and 0 < len(raw) <= LIMIT)
    value = read_json_bytes(raw, 'pr320-artifact-member')
    _need(isinstance(value, dict) and set(value) == {'schemaVersion', 'kind', 'nativeMemberDigest',
        'sourceCommit', 'files', 'transferFiles', 'jobSummary'} and value['schemaVersion'] == 1
        and type(value['schemaVersion']) is int and value['kind'] == 'composed-budget-artifact-component'
        and re.fullmatch('sha256:[0-9a-f]{64}', str(value['nativeMemberDigest']))
        and re.fullmatch('[0-9a-f]{40}', str(value['sourceCommit'])))
    contents = []
    for key in ('files', 'transferFiles'):
        _need(isinstance(value[key], dict) and set(value[key]) == export.ROSTER)
        decoded = {}
        for name, text in value[key].items():
            _need(isinstance(text, str) and len(text) <= 1024 * 1024)
            payload = base64.b64decode(text, validate=True)
            _need(payload and len(payload) <= 1024 * 1024 and base64.b64encode(payload).decode() == text)
            decoded[name] = payload
        export.verify_export_bytes(decoded, value['sourceCommit'])
        contents.append(decoded)
    _need(contents[0] == contents[1] and value['jobSummary'].encode() == contents[0]['report.md'])
    return value


def produce(adapter):
    """Execute the finite fresh-root export, real filesystem transfer and journal member17."""
    root, native_raw, native, browser, native_result, browser_result, node = _inputs(adapter)
    work = root / WORK_ROOT
    # Every directory is fresh. Failures retain partial files and cannot reuse stale results.
    parent = export._open_directory(root)
    try:
        os.mkdir(WORK_ROOT, mode=0o700, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)
    workspace = work / 'workspace'
    workspace.mkdir(mode=0o700)
    summary_dir = workspace / 'build/release-certification' / RELEASE_ID / 'release-certification'
    summary_dir.mkdir(parents=True, mode=0o700)
    envelope = _envelope(workspace, native_result, browser_result, node)
    _write(summary_dir / 'summary.json', export._json(envelope))
    manifest = work / 'manifest.private.json'
    _write(manifest, export._json({'release': {'id': RELEASE_ID, 'version': str(node['contractVersion']),
        'profile': 'pr320-local-privacy'}, 'output': {'root': 'build/release-certification'}}))
    public = work / 'public'
    transferred = work / 'transferred'
    public_result = export.create_export(manifest, workspace, public, node['sourceCommit'])
    _need(public_result['status'] == 'fail' and public_result['exportFailure'] == 'none'
          and public_result['promotionReady'] is False and public_result['counts']['evidence'] == 2
          and public_result['counts']['blockers'] == 1)
    transferred.mkdir(mode=0o700)
    for name in sorted(export.ROSTER):
        _write(transferred / name, export._read_regular(public / name, 1024 * 1024))
    export.verify_export(transferred, node['sourceCommit'])
    # The generated job summary is an actual independent file read by the existing capture
    # owner. It contains precisely the report verified after transfer.
    job_summary = work / 'job-summary.md'
    _write(job_summary, export._read_regular(transferred / 'report.md', 1024 * 1024))
    output = root / FILE
    result = capture.capture(root / evidence.PRIVATE_FILE, public, transferred, job_summary,
                             output, source_commit=node['sourceCommit'])
    raw = export._read_regular(output, LIMIT)
    value = decode_artifact(raw)
    privacy.verify_artifacts(value, native['component'],
        native_digest='sha256:' + hashlib.sha256(native_raw).hexdigest(), source_commit=node['sourceCommit'])
    append_member(adapter.journal, 'artifact-privacy', raw,
                  collector_epoch=native['component']['surfaces']['workSnapshot']['collectorEpoch'])
    return {'digest': 'sha256:' + hashlib.sha256(raw).hexdigest(), 'result': result}

#!/usr/bin/python3
"""Host-only PR-315 campaign identity and Ed25519 receipt sealing.

Signature verification authenticates a host receipt's bytes. It does not
promote imported records to installed acceptance; the owning orchestrator
must independently validate transport, case evidence and stopped guests.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

import pr314_acceptance as acceptance
import pr315_workload_campaign as historical

CAMPAIGN = 'pr315-workload-campaign-v2'
CONTRACT = 'pr314-workload-roles-v10'
RECEIPT = 'pr315-host-attempt-receipt-v2'
SIGNATURE_DOMAIN = 'pr315-campaign-v2'
KEY_NAME = 'campaign-ed25519'
_HEX64 = re.compile(r'[0-9a-f]{64}\Z')
_HEX40 = re.compile(r'[0-9a-f]{40}\Z')
_ATTEMPT_ID = re.compile(r'[a-z0-9][a-z0-9-]{0,79}\Z')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _private_directory(root):
    root = Path(root)
    info = root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077):
        raise ValueError('pr315-campaign-private-directory-required')
    return root


def _public_key(raw):
    if not isinstance(raw, bytes) or len(raw) > 256:
        raise ValueError('pr315-campaign-public-key-invalid')
    fields = raw.strip().split()
    if len(fields) not in (2, 3) or fields[0] != b'ssh-ed25519':
        raise ValueError('pr315-campaign-public-key-invalid')
    try:
        decoded = base64.b64decode(fields[1], validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError('pr315-campaign-public-key-invalid') from error
    if len(decoded) != 51 or decoded[:19] != b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 ':
        raise ValueError('pr315-campaign-public-key-invalid')
    return b' '.join(fields)


def prepare_key(root):
    """Create one Mac-only campaign key in an already private directory."""
    root = _private_directory(root)
    key = root / KEY_NAME
    if key.exists() or (root / (KEY_NAME + '.pub')).exists():
        raise ValueError('pr315-campaign-key-already-exists')
    completed = subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519',
        '-N', '', '-f', str(key)], stdin=subprocess.DEVNULL,
        capture_output=True, timeout=15, check=True)
    if completed.stdout or completed.stderr or key.lstat().st_mode & 0o077:
        raise ValueError('pr315-campaign-key-invalid')
    public = _public_key((root / (KEY_NAME + '.pub')).read_bytes())
    return hashlib.sha256(public).hexdigest()


def plan(identity, runtime_policy_digest, host_policy, probe_digest,
         campaign_nonce, key_fingerprint):
    """Pin the exact 21 groups and the host key before any VM allocation."""
    if (not acceptance._identity(identity)
            or any(_HEX64.fullmatch(str(value)) is None for value in
                   (runtime_policy_digest, probe_digest, campaign_nonce,
                    key_fingerprint))
            or host_policy != 'pve-tcg-swap-admission-v1'):
        raise ValueError('pr315-campaign-v2-identity-invalid')
    value = {'schemaVersion': 2, 'kind': CAMPAIGN, 'contract': CONTRACT,
        'identity': identity, 'runtimePolicyDigest': runtime_policy_digest,
        'hostAdmissionPolicy': host_policy, 'probeDigest': probe_digest,
        'campaignNonce': campaign_nonce,
        'hostKeyFingerprint': key_fingerprint,
        'groups': [{'groupId': group, 'cases': list(cases)}
                   for group, cases in historical.GROUPS]}
    value['planDigest'] = _digest(value)
    return value


def _check_plan(value, pinned_source_commit, pinned_fingerprint):
    if (not isinstance(value, dict)
            or not isinstance(value.get('identity'), dict)
            or value.get('identity', {}).get('helperSourceCommit') != pinned_source_commit
            or value.get('hostKeyFingerprint') != pinned_fingerprint):
        raise ValueError('pr315-campaign-v2-pinned-identity-changed')
    expected = plan(value['identity'], value['runtimePolicyDigest'],
        value['hostAdmissionPolicy'], value['probeDigest'],
        value['campaignNonce'], pinned_fingerprint)
    if value != expected:
        raise ValueError('pr315-campaign-v2-plan-changed')


def attempt_receipt(campaign, group_id, attempt_id, source_commit, status,
                    probe_started, case_digests, evidence_digest,
                    stop_digest, monitor_digest, archive_digest):
    """Build a closed receipt; only the live owner may supply verified digests."""
    if (not isinstance(campaign, dict)
            or campaign.get('kind') != CAMPAIGN
            or group_id not in dict(historical.GROUPS)
            or not isinstance(attempt_id, str)
            or _ATTEMPT_ID.fullmatch(attempt_id) is None
            or _HEX40.fullmatch(str(source_commit)) is None
            or source_commit != campaign['identity']['helperSourceCommit']
            or status not in ('setup-failed', 'failed', 'completed')
            or type(probe_started) is not bool
            or not isinstance(case_digests, dict)
            or any(_HEX64.fullmatch(str(digest)) is None
                   for digest in case_digests.values())
            or any(value is not None and _HEX64.fullmatch(str(value)) is None
                   for value in (evidence_digest, stop_digest,
                                 monitor_digest, archive_digest))):
        raise ValueError('pr315-campaign-v2-attempt-invalid')
    owned = set(dict(historical.GROUPS)[group_id])
    if (status == 'completed' and (probe_started is not True
            or set(case_digests) != owned
            or any(value is None for value in (evidence_digest, stop_digest,
                                              monitor_digest, archive_digest)))):
        raise ValueError('pr315-campaign-v2-completion-incomplete')
    if (status == 'setup-failed' and (probe_started or case_digests)):
        raise ValueError('pr315-campaign-v2-setup-phase-invalid')
    if status == 'failed' and not probe_started:
        raise ValueError('pr315-campaign-v2-failure-phase-invalid')
    value = {'schemaVersion': 2, 'kind': RECEIPT,
        'planDigest': campaign['planDigest'],
        'campaignNonce': campaign['campaignNonce'],
        'groupId': group_id, 'attemptId': attempt_id,
        'declaredCases': list(dict(historical.GROUPS)[group_id]),
        'sourceCommit': source_commit, 'status': status,
        'probeStarted': probe_started, 'caseDigests': case_digests,
        'evidenceDigest': evidence_digest, 'stopDigest': stop_digest,
        'monitorDigest': monitor_digest, 'archiveDigest': archive_digest}
    return value


def sign(root, campaign, receipt, *, pinned_source_commit, pinned_fingerprint):
    """Seal one already verified attempt using a key that stays on the Mac."""
    root = _private_directory(root)
    _check_plan(campaign, pinned_source_commit, pinned_fingerprint)
    if not isinstance(receipt, dict):
        raise ValueError('pr315-campaign-receipt-invalid')
    try:
        expected = attempt_receipt(campaign, receipt['groupId'], receipt['attemptId'],
            receipt['sourceCommit'], receipt['status'], receipt['probeStarted'],
            receipt['caseDigests'], receipt['evidenceDigest'], receipt['stopDigest'],
            receipt['monitorDigest'], receipt['archiveDigest'])
    except KeyError as error:
        raise ValueError('pr315-campaign-receipt-invalid') from error
    if receipt != expected:
        raise ValueError('pr315-campaign-receipt-changed')
    key = root / KEY_NAME
    info = key.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('pr315-campaign-key-invalid')
    public = _public_key((root / (KEY_NAME + '.pub')).read_bytes())
    if hashlib.sha256(public).hexdigest() != pinned_fingerprint:
        raise ValueError('pr315-campaign-public-key-changed')
    payload = _canonical(receipt)
    if len(payload) > 65536:
        raise ValueError('pr315-campaign-receipt-limit')
    signed = subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'sign', '-f', str(key),
        '-n', SIGNATURE_DOMAIN], input=payload, capture_output=True,
        timeout=15, check=True)
    signature = signed.stdout.decode('ascii')
    if (not signature.startswith('-----BEGIN SSH SIGNATURE-----\n')
            or not signature.endswith('-----END SSH SIGNATURE-----\n')
            or len(signature) > 4096):
        raise ValueError('pr315-campaign-signature-invalid')
    envelope = {'receipt': receipt, 'signature': signature}
    verify(root, campaign, envelope,
           pinned_source_commit=pinned_source_commit,
           pinned_fingerprint=pinned_fingerprint)
    return envelope


def verify(root, campaign, envelope, *, pinned_source_commit, pinned_fingerprint):
    """Authenticate a receipt for recovery; installed evidence is checked separately."""
    root = _private_directory(root)
    _check_plan(campaign, pinned_source_commit, pinned_fingerprint)
    public = _public_key((root / (KEY_NAME + '.pub')).read_bytes())
    if hashlib.sha256(public).hexdigest() != pinned_fingerprint:
        raise ValueError('pr315-campaign-public-key-changed')
    if not isinstance(envelope, dict) or set(envelope) != {'receipt', 'signature'}:
        raise ValueError('pr315-campaign-envelope-invalid')
    receipt = envelope['receipt']
    if not isinstance(receipt, dict):
        raise ValueError('pr315-campaign-receipt-invalid')
    try:
        expected = attempt_receipt(campaign, receipt['groupId'], receipt['attemptId'],
            receipt['sourceCommit'], receipt['status'], receipt['probeStarted'],
            receipt['caseDigests'], receipt['evidenceDigest'], receipt['stopDigest'],
            receipt['monitorDigest'], receipt['archiveDigest'])
    except KeyError as error:
        raise ValueError('pr315-campaign-receipt-invalid') from error
    if receipt != expected:
        raise ValueError('pr315-campaign-receipt-changed')
    signature = envelope['signature']
    if (not isinstance(signature, str) or len(signature) > 4096
            or not signature.startswith('-----BEGIN SSH SIGNATURE-----\n')):
        raise ValueError('pr315-campaign-signature-invalid')
    with tempfile.TemporaryDirectory(prefix='pr315-campaign-verify-') as temporary:
        directory = Path(temporary)
        allowed = directory / 'allowed'
        sig = directory / 'signature'
        allowed.write_bytes(b'pr315-campaign ' + public + b'\n')
        sig.write_text(signature, encoding='ascii')
        checked = subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'verify',
            '-f', str(allowed), '-I', 'pr315-campaign', '-n', SIGNATURE_DOMAIN,
            '-s', str(sig)], input=_canonical(receipt), capture_output=True,
            timeout=15)
    if checked.returncode != 0:
        raise ValueError('pr315-campaign-signature-mismatch')
    return receipt

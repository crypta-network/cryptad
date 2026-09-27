#!/usr/bin/python3
"""Host-only PR-315 campaign identity and Ed25519 receipt sealing.

Signature verification authenticates a host receipt's bytes. It does not
promote imported records to installed acceptance; the owning orchestrator
must independently validate transport, case evidence and stopped guests.
"""
from __future__ import annotations

import base64
import binascii
import fcntl
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
START_DOMAIN = 'pr315-campaign-start-v1'
START_KIND = 'pr315-frozen-campaign-start-v1'
AUTHORITY_HANDOFF = 'pr315-retired-authority-handoff-v1'
AUTHORITY_DOMAIN = 'pr315-retired-authority-v1'
KEY_NAME = 'campaign-ed25519'
LEDGER_NAME = 'sealed-attempt-ledger.json'
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
                    stop_digest, monitor_digest, archive_digest, *,
                    sequence=1, previous_digest='0' * 64):
    """Build a closed receipt; only the live owner may supply verified digests."""
    if (not isinstance(campaign, dict)
            or campaign.get('kind') != CAMPAIGN
            or group_id not in dict(historical.GROUPS)
            or not isinstance(attempt_id, str)
            or _ATTEMPT_ID.fullmatch(attempt_id) is None
            or _HEX40.fullmatch(str(source_commit)) is None
            or source_commit != campaign['identity']['helperSourceCommit']
            or status not in ('setup-failed', 'preparation-completed',
                              'failed', 'completed')
            or type(sequence) is not int or sequence < 1
            or _HEX64.fullmatch(str(previous_digest)) is None
            or (sequence == 1) != (previous_digest == '0' * 64)
            or (probe_started is not None
                and type(probe_started) is not bool)
            or not isinstance(case_digests, dict)
            or any(_HEX64.fullmatch(str(digest)) is None
                   for digest in case_digests.values())
            or any(value is not None and _HEX64.fullmatch(str(value)) is None
                   for value in (evidence_digest, stop_digest,
                                 monitor_digest, archive_digest))):
        raise ValueError('pr315-campaign-v2-attempt-invalid')
    owned = set(dict(historical.GROUPS)[group_id])
    if not set(case_digests).issubset(owned):
        raise ValueError('pr315-campaign-v2-case-ownership-invalid')
    if (status == 'completed' and (probe_started is not True
            or set(case_digests) != owned
            or any(value is None for value in (evidence_digest, stop_digest,
                                              monitor_digest, archive_digest)))):
        raise ValueError('pr315-campaign-v2-completion-incomplete')
    if (status == 'setup-failed'
            and (probe_started is not False or case_digests)):
        raise ValueError('pr315-campaign-v2-setup-phase-invalid')
    if (status == 'preparation-completed'
            and (group_id != 'authority' or probe_started is not False
                 or case_digests or any(value is None for value in
                     (evidence_digest, stop_digest,
                      monitor_digest, archive_digest)))):
        raise ValueError('pr315-campaign-v2-authority-preparation-invalid')
    if status == 'failed' and probe_started is False:
        raise ValueError('pr315-campaign-v2-failure-phase-invalid')
    value = {'schemaVersion': 2, 'kind': RECEIPT,
        'planDigest': campaign['planDigest'],
        'campaignNonce': campaign['campaignNonce'],
        'groupId': group_id, 'attemptId': attempt_id,
        'declaredCases': list(dict(historical.GROUPS)[group_id]),
        'sourceCommit': source_commit, 'status': status,
        'sequence': sequence, 'previousReceiptDigest': previous_digest,
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
            receipt['monitorDigest'], receipt['archiveDigest'],
            sequence=receipt['sequence'],
            previous_digest=receipt['previousReceiptDigest'])
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
            receipt['monitorDigest'], receipt['archiveDigest'],
            sequence=receipt['sequence'],
            previous_digest=receipt['previousReceiptDigest'])
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


def frozen_start(campaign, source_tree, tracked_byte_digest,
                 remote_known_hosts_digest, first_suite_number,
                 mac_available_at_start_bytes):
    """Pin the host-owned campaign launch before allocating any guest."""
    if (not isinstance(campaign, dict) or campaign.get('kind') != CAMPAIGN
            or _HEX40.fullmatch(str(source_tree)) is None
            or source_tree != campaign['identity']['helperSourceTree']
            or any(_HEX64.fullmatch(str(value)) is None for value in
                   (tracked_byte_digest, remote_known_hosts_digest))
            or type(first_suite_number) is not int
            or not 1 <= first_suite_number <= 999999
            or type(mac_available_at_start_bytes) is not int
            or mac_available_at_start_bytes < 224 * 1024**3):
        raise ValueError('pr315-campaign-start-input-invalid')
    return {'schemaVersion': 1, 'kind': START_KIND,
        'planDigest': campaign['planDigest'],
        'sourceCommit': campaign['identity']['helperSourceCommit'],
        'sourceTree': source_tree,
        'trackedByteDigest': tracked_byte_digest,
        'hostKeyFingerprint': campaign['hostKeyFingerprint'],
        'fixtureManifestDigest': campaign['identity']['fixtureManifestDigest'],
        'productSelectionDigest': campaign['identity']['productSelectionDigest'],
        'hostAdmissionPolicy': campaign['hostAdmissionPolicy'],
        'remoteKnownHostsDigest': remote_known_hosts_digest,
        'groupCount': len(historical.GROUPS),
        'firstSuiteNumber': first_suite_number,
        'macAvailableAtStartBytes': mac_available_at_start_bytes}


def _verified_start_shape(campaign, value):
    if not isinstance(value, dict):
        raise ValueError('pr315-campaign-start-invalid')
    try:
        expected = frozen_start(campaign, value['sourceTree'],
            value['trackedByteDigest'], value['remoteKnownHostsDigest'],
            value['firstSuiteNumber'], value['macAvailableAtStartBytes'])
    except KeyError as error:
        raise ValueError('pr315-campaign-start-invalid') from error
    if value != expected:
        raise ValueError('pr315-campaign-start-changed')
    return value


def sign_start(root, campaign, start):
    """Seal the frozen launch identity using the Mac-only campaign key."""
    root = _private_directory(root)
    _check_plan(campaign, campaign['identity']['helperSourceCommit'],
                campaign['hostKeyFingerprint'])
    _verified_start_shape(campaign, start)
    key = root / KEY_NAME
    info = key.lstat()
    public = _public_key((root / (KEY_NAME + '.pub')).read_bytes())
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or hashlib.sha256(public).hexdigest() !=
                campaign['hostKeyFingerprint']):
        raise ValueError('pr315-campaign-start-key-invalid')
    signed = subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'sign',
        '-f', str(key), '-n', START_DOMAIN], input=_canonical(start),
        capture_output=True, timeout=15, check=True)
    signature = signed.stdout.decode('ascii')
    if (not signature.startswith('-----BEGIN SSH SIGNATURE-----\n')
            or not signature.endswith('-----END SSH SIGNATURE-----\n')
            or len(signature) > 4096):
        raise ValueError('pr315-campaign-start-signature-invalid')
    envelope = {'start': start, 'signature': signature}
    verify_start(root, campaign, envelope)
    return envelope


def verify_start(root, campaign, envelope):
    """Authenticate frozen start bytes before resume or resource allocation."""
    root = _private_directory(root)
    _check_plan(campaign, campaign['identity']['helperSourceCommit'],
                campaign['hostKeyFingerprint'])
    if (not isinstance(envelope, dict)
            or set(envelope) != {'start', 'signature'}):
        raise ValueError('pr315-campaign-start-envelope-invalid')
    start = _verified_start_shape(campaign, envelope['start'])
    signature = envelope['signature']
    public = _public_key((root / (KEY_NAME + '.pub')).read_bytes())
    if (not isinstance(signature, str) or len(signature) > 4096
            or not signature.startswith('-----BEGIN SSH SIGNATURE-----\n')
            or hashlib.sha256(public).hexdigest() !=
                campaign['hostKeyFingerprint']):
        raise ValueError('pr315-campaign-start-signature-invalid')
    with tempfile.TemporaryDirectory(prefix='pr315-start-verify-') as temporary:
        directory = Path(temporary)
        allowed = directory / 'allowed'
        sig = directory / 'signature'
        allowed.write_bytes(b'pr315-campaign ' + public + b'\n')
        sig.write_text(signature, encoding='ascii')
        checked = subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'verify',
            '-f', str(allowed), '-I', 'pr315-campaign', '-n', START_DOMAIN,
            '-s', str(sig)], input=_canonical(start), capture_output=True,
            timeout=15)
    if checked.returncode:
        raise ValueError('pr315-campaign-start-signature-mismatch')
    return start


def authority_handoff(campaign, preparation_id, provenance,
                      stop_digest, archive_digest):
    """Commit a retired guest's private input without exporting its raw handle."""
    if (not isinstance(campaign, dict) or campaign.get('kind') != CAMPAIGN
            or not isinstance(preparation_id, str)
            or _ATTEMPT_ID.fullmatch(preparation_id) is None
            or not isinstance(provenance, dict)
            or set(provenance) != {'schemaVersion', 'kind', 'sourceCommit',
                'bootId', 'campaignGeneration', 'senderHandleDigest',
                'inputDigest', 'guestStopped'}
            or provenance['schemaVersion'] != 1
            or provenance['kind'] != 'pr315-retired-authority-host-provenance'
            or provenance['sourceCommit'] !=
                campaign['identity']['helperSourceCommit']
            or provenance['guestStopped'] is not True
            or not isinstance(provenance['bootId'], str)
            or re.fullmatch('[0-9a-f-]{36}', provenance['bootId']) is None
            or any(_HEX64.fullmatch(str(provenance[key])) is None for key in
                ('campaignGeneration', 'senderHandleDigest', 'inputDigest'))
            or any(_HEX64.fullmatch(str(value)) is None
                   for value in (stop_digest, archive_digest))):
        raise ValueError('pr315-retired-authority-handoff-invalid')
    return {'schemaVersion': 1, 'kind': AUTHORITY_HANDOFF,
        'planDigest': campaign['planDigest'],
        'campaignNonce': campaign['campaignNonce'],
        'sourceCommit': provenance['sourceCommit'],
        'preparationAttemptId': preparation_id,
        'retiredBootId': provenance['bootId'],
        'retiredGeneration': provenance['campaignGeneration'],
        'senderHandleDigest': provenance['senderHandleDigest'],
        'privateInputDigest': provenance['inputDigest'],
        'stopDigest': stop_digest,
        'archiveDigest': archive_digest, 'guestStopped': True}


def sign_authority_handoff(root, campaign, handoff):
    """Seal the host-verified old authority after its guest is stopped."""
    root = _private_directory(root)
    _check_plan(campaign, campaign['identity']['helperSourceCommit'],
                campaign['hostKeyFingerprint'])
    if not isinstance(handoff, dict):
        raise ValueError('pr315-retired-authority-handoff-invalid')
    provenance = {'schemaVersion': 1,
        'kind': 'pr315-retired-authority-host-provenance',
        'sourceCommit': handoff.get('sourceCommit'),
        'bootId': handoff.get('retiredBootId'),
        'campaignGeneration': handoff.get('retiredGeneration'),
        'senderHandleDigest': handoff.get('senderHandleDigest'),
        'inputDigest': handoff.get('privateInputDigest'),
        'guestStopped': handoff.get('guestStopped')}
    expected = authority_handoff(campaign, handoff.get('preparationAttemptId'),
        provenance, handoff.get('stopDigest'), handoff.get('archiveDigest'))
    if handoff != expected:
        raise ValueError('pr315-retired-authority-handoff-changed')
    key = root / KEY_NAME
    info = key.lstat()
    public = _public_key((root / (KEY_NAME + '.pub')).read_bytes())
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or hashlib.sha256(public).hexdigest() !=
                campaign['hostKeyFingerprint']):
        raise ValueError('pr315-retired-authority-key-invalid')
    signed = subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'sign', '-f',
        str(key), '-n', AUTHORITY_DOMAIN], input=_canonical(handoff),
        capture_output=True, timeout=15, check=True)
    signature = signed.stdout.decode('ascii')
    if (not signature.startswith('-----BEGIN SSH SIGNATURE-----\n')
            or not signature.endswith('-----END SSH SIGNATURE-----\n')
            or len(signature) > 4096):
        raise ValueError('pr315-retired-authority-signature-invalid')
    envelope = {'handoff': handoff, 'signature': signature}
    verify_authority_handoff(campaign, envelope, public)
    return envelope


def verify_authority_handoff(campaign, envelope, public_key):
    """Authenticate a handoff with only the frozen public key, including on CT102."""
    public = _public_key(public_key)
    fingerprint = hashlib.sha256(public).hexdigest()
    _check_plan(campaign, campaign['identity']['helperSourceCommit'], fingerprint)
    if (not isinstance(envelope, dict)
            or set(envelope) != {'handoff', 'signature'}
            or not isinstance(envelope['handoff'], dict)):
        raise ValueError('pr315-retired-authority-envelope-invalid')
    handoff = envelope['handoff']
    provenance = {'schemaVersion': 1,
        'kind': 'pr315-retired-authority-host-provenance',
        'sourceCommit': handoff.get('sourceCommit'),
        'bootId': handoff.get('retiredBootId'),
        'campaignGeneration': handoff.get('retiredGeneration'),
        'senderHandleDigest': handoff.get('senderHandleDigest'),
        'inputDigest': handoff.get('privateInputDigest'),
        'guestStopped': handoff.get('guestStopped')}
    expected = authority_handoff(campaign, handoff.get('preparationAttemptId'),
        provenance, handoff.get('stopDigest'), handoff.get('archiveDigest'))
    signature = envelope['signature']
    if (handoff != expected or not isinstance(signature, str)
            or len(signature) > 4096
            or not signature.startswith('-----BEGIN SSH SIGNATURE-----\n')):
        raise ValueError('pr315-retired-authority-envelope-invalid')
    with tempfile.TemporaryDirectory(prefix='pr315-authority-verify-') as temporary:
        directory = Path(temporary)
        allowed = directory / 'allowed'
        sig = directory / 'signature'
        allowed.write_bytes(b'pr315-authority ' + public + b'\n')
        sig.write_text(signature, encoding='ascii')
        checked = subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'verify',
            '-f', str(allowed), '-I', 'pr315-authority',
            '-n', AUTHORITY_DOMAIN, '-s', str(sig)],
            input=_canonical(handoff), capture_output=True, timeout=15)
    if checked.returncode != 0:
        raise ValueError('pr315-retired-authority-signature-mismatch')
    return handoff


def verify_history(root, campaign, ledger, *, pinned_source_commit,
                   pinned_fingerprint):
    """Verify an append-only signed chain; do not infer installed success."""
    _check_plan(campaign, pinned_source_commit, pinned_fingerprint)
    public = _public_key((_private_directory(root) / (KEY_NAME + '.pub')).read_bytes())
    if hashlib.sha256(public).hexdigest() != pinned_fingerprint:
        raise ValueError('pr315-campaign-public-key-changed')
    if (not isinstance(ledger, dict) or set(ledger) != {
            'schemaVersion', 'kind', 'planDigest', 'headReceiptDigest', 'envelopes'}
            or ledger['schemaVersion'] != 2
            or ledger['kind'] != 'pr315-host-sealed-ledger-v2'
            or ledger['planDigest'] != campaign.get('planDigest')
            or not isinstance(ledger['envelopes'], list)
            or len(ledger['envelopes']) > 3 * len(historical.GROUPS)):
        raise ValueError('pr315-campaign-ledger-invalid')
    previous = '0' * 64
    receipts = []
    last_group_index = -1
    attempts_in_group = 0
    seen = set()
    ordering = {group: index for index, (group, _) in enumerate(historical.GROUPS)}
    for envelope in ledger['envelopes']:
        receipt = verify(root, campaign, envelope,
            pinned_source_commit=pinned_source_commit,
            pinned_fingerprint=pinned_fingerprint)
        index = ordering[receipt['groupId']]
        if (receipt['sequence'] != len(receipts) + 1
                or receipt['previousReceiptDigest'] != previous
                or receipt['attemptId'] in seen or index < last_group_index):
            raise ValueError('pr315-campaign-ledger-chain-invalid')
        if (receipt['status'] == 'preparation-completed'
                and (receipt['groupId'] != 'authority'
                     or any(row['groupId'] == 'authority'
                            and row['status'] == 'preparation-completed'
                            for row in receipts))):
            raise ValueError('pr315-campaign-retired-preparation-duplicate')
        if index != last_group_index:
            if receipts and receipts[-1]['status'] != 'completed':
                raise ValueError('pr315-campaign-ledger-unfinished-group')
            attempts_in_group = 0
        elif receipts and receipts[-1]['status'] not in (
                'setup-failed', 'preparation-completed'):
            raise ValueError('pr315-campaign-post-probe-retry')
        attempts_in_group += 1
        if attempts_in_group > 3:
            raise ValueError('pr315-campaign-retry-limit')
        previous = _digest(receipt)
        seen.add(receipt['attemptId'])
        last_group_index = index
        receipts.append(receipt)
    if ledger['headReceiptDigest'] != previous:
        raise ValueError('pr315-campaign-ledger-head-changed')
    return receipts


def _load_ledger(root, campaign):
    path = root / LEDGER_NAME
    if (root / ('.' + LEDGER_NAME + '.pending')).exists():
        raise ValueError('pr315-campaign-ledger-reconciliation-required')
    if not path.exists():
        return {'schemaVersion': 2, 'kind': 'pr315-host-sealed-ledger-v2',
            'planDigest': campaign['planDigest'],
            'headReceiptDigest': '0' * 64, 'envelopes': []}
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1
                or not 0 < info.st_size <= 512 * 1024):
            raise ValueError('pr315-campaign-ledger-file-invalid')
        raw = os.read(descriptor, 512 * 1024 + 1)
        if len(raw) != info.st_size or os.fstat(descriptor).st_size != info.st_size:
            raise ValueError('pr315-campaign-ledger-file-changed')
        value = json.loads(raw)
        if raw != _canonical(value):
            raise ValueError('pr315-campaign-ledger-bytes-changed')
        return value
    finally:
        os.close(descriptor)


def append_verified_attempt(root, campaign, *, pinned_source_commit,
                            pinned_fingerprint, group_id, attempt_id, status,
                            probe_started, case_digests, evidence_digest,
                            stop_digest, monitor_digest, archive_digest):
    """Atomically append a signed receipt after the caller verified live inputs."""
    root = _private_directory(root)
    lock = os.open(root / 'campaign-ledger.lock',
        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('pr315-campaign-ledger-lock-invalid')
        fcntl.flock(lock, fcntl.LOCK_EX)
        ledger = _load_ledger(root, campaign)
        receipts = verify_history(root, campaign, ledger,
            pinned_source_commit=pinned_source_commit,
            pinned_fingerprint=pinned_fingerprint)
        receipt = attempt_receipt(campaign, group_id, attempt_id,
            pinned_source_commit, status, probe_started, case_digests,
            evidence_digest, stop_digest, monitor_digest, archive_digest,
            sequence=len(receipts) + 1,
            previous_digest=ledger['headReceiptDigest'])
        envelope = sign(root, campaign, receipt,
            pinned_source_commit=pinned_source_commit,
            pinned_fingerprint=pinned_fingerprint)
        updated = {**ledger, 'headReceiptDigest': _digest(receipt),
                   'envelopes': [*ledger['envelopes'], envelope]}
        verify_history(root, campaign, updated,
            pinned_source_commit=pinned_source_commit,
            pinned_fingerprint=pinned_fingerprint)
        raw = _canonical(updated)
        if len(raw) > 512 * 1024:
            raise ValueError('pr315-campaign-ledger-limit')
        pending = root / ('.' + LEDGER_NAME + '.pending')
        descriptor = os.open(pending,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600)
        try:
            if os.write(descriptor, raw) != len(raw):
                raise ValueError('pr315-campaign-ledger-short-write')
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(pending, root / LEDGER_NAME)
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return receipt
    finally:
        os.close(lock)


def load_verified_history(root, campaign, *, pinned_source_commit,
                          pinned_fingerprint):
    """Recover authenticated attempts; caller still rechecks their raw evidence."""
    root = _private_directory(root)
    return verify_history(root, campaign, _load_ledger(root, campaign),
        pinned_source_commit=pinned_source_commit,
        pinned_fingerprint=pinned_fingerprint)

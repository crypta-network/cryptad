"""Finite CMS transport for maintenance runtime evidence.

Opening proves transport integrity only. The owning protected resolver must authenticate the
original freeze and ciphertext before calling this module and perform native admission afterward.
Neither this API nor its returned private directory confers producer or selection authority.
"""
from contextlib import contextmanager
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import uuid

from bounded_process import run

DESCRIPTOR = 'runtime-companion.json'
CIPHERTEXT = 'runtime-companion.cms'
PURPOSE = 'stable-maintenance-runtime'
POLICY_ID = 'maintenance-runtime-v1'
POLICY = Path('/etc/cryptad-certification/maintenance-runtime-recipient.json')
RECIPIENT = Path('/etc/cryptad-certification/maintenance-runtime-recipient.pem')
RECIPIENT_KEY = Path('/etc/cryptad-certification/maintenance-runtime-recipient.key')
MEMBERS = frozenset(('runtime-subjects.json', 'snapshot.json', 'baseline-registry.json',
                     'projection-inventory.json', 'native-admissions.json'))
MAX_MEMBER = 2 * 1024 * 1024
MAX_BYTES = 16 * 1024 * 1024
ENVIRONMENT = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'OPENSSL_CONF': '/dev/null'}
CONTEXT = ('releaseId', 'buildVersion', 'assetSetDigest', 'checksumsDigest', 'producer')


class CompanionError(ValueError):
    """Fixed diagnostics, containing no supplied material."""


def _fail():
    raise CompanionError('runtime-companion-rejected')


def _digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _json(raw):
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_BYTES:
        _fail()
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                _fail()
            value[key] = item
        return value
    value = json.loads(raw, object_pairs_hook=pairs,
                       parse_constant=lambda _: _fail())
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if count > 32768 or depth > 32:
            _fail()
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return value


def _read(path, maximum=MAX_BYTES, *, protected=False, key=False):
    path = Path(path)
    if any(parent.is_symlink() for parent in path.parents):
        _fail()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or not 1 <= before.st_size <= maximum
                or protected and (before.st_uid != 0 or before.st_mode & 0o022)
                or key and before.st_mode & 0o077):
            _fail()
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(fd)
        current = path.lstat()
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if len(raw) != before.st_size or any(getattr(before, f) != getattr(after, f)
                or getattr(before, f) != getattr(current, f) for f in fields):
            _fail()
        return raw
    finally:
        os.close(fd)


def _write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)


def _policy():
    try:
        policy_bytes = _read(POLICY, 16384, protected=True)
    except FileNotFoundError:
        raise CompanionError('runtime-companion-recipient-policy-missing') from None
    policy = _json(policy_bytes)
    if (set(policy) != {'schemaVersion', 'purpose', 'policy', 'epoch', 'certificateDigest',
                        'notBefore', 'notAfter', 'status'}
            or type(policy['schemaVersion']) is not int or policy['schemaVersion'] != 1
            or policy['purpose'] != PURPOSE or policy['policy'] != POLICY_ID
            or type(policy['epoch']) is not int or policy['epoch'] < 1
            or policy['status'] != 'active'):
        _fail()
    now = dt.datetime.now(dt.timezone.utc)
    start = dt.datetime.fromisoformat(policy['notBefore'].replace('Z', '+00:00'))
    end = dt.datetime.fromisoformat(policy['notAfter'].replace('Z', '+00:00'))
    if start.tzinfo is None or end.tzinfo is None or not start <= now < end:
        _fail()
    try:
        certificate = _read(RECIPIENT, 16384, protected=True)
    except FileNotFoundError:
        raise CompanionError('runtime-companion-recipient-certificate-missing') from None
    if _digest(certificate) != policy['certificateDigest']:
        _fail()
    return policy, certificate


def _openssl(arguments, *, output_limit=4096):
    # Limit output files and virtual address space in addition to bounded pipes/deadline.
    if not os.access('/usr/bin/openssl', os.X_OK):
        raise CompanionError('runtime-companion-openssl-unavailable')
    if not os.access('/usr/bin/prlimit', os.X_OK):
        raise CompanionError('runtime-companion-resource-limiter-unavailable')
    return run(['/usr/bin/prlimit', '--as=268435456', '--fsize=16777216', '--',
                '/usr/bin/openssl', *arguments], environment=ENVIRONMENT,
               timeout=60, output_limit=output_limit)


def _shape(source, root):
    normalized = root / 'normalized'
    _openssl(['cms', '-cmsout', '-inform', 'DER', '-in', str(source),
              '-outform', 'DER', '-out', str(normalized)])
    if _read(source) != _read(normalized):
        _fail()  # Includes trailing data and BER/noncanonical encodings.
    # OpenSSL owns ASN.1 parsing; cap its entire diagnostic output and never emit it.
    report = _openssl(['cms', '-cmsout', '-inform', 'DER', '-in', str(source), '-print'],
                      output_limit=128 * 1024 * 1024).decode('ascii')
    if (not re.search(r'^  contentType: id-smime-ct-authEnvelopedData ', report, re.M)
            or len(re.findall(r'^      d.ktri:', report, re.M)) != 1
            or not re.search(r'^        algorithm: aes-256-gcm ', report, re.M)
            or not re.search(r'^          algorithm: rsaEncryption ', report, re.M)
            or 'd.kari:' in report or 'd.kekri:' in report or 'd.pwri:' in report
            or not re.search(r'^    originatorInfo: <ABSENT>$', report, re.M)
            or not re.search(r'^      contentType: pkcs7-data ', report, re.M)
            or not re.search(r'    authAttrs:\s+<ABSENT>\s+mac:', report)
            or not re.search(r'    unauthAttrs:\s+<ABSENT>\s*$', report)):
        _fail()


def _cms(raw, root, certificate, *, decrypt=False):
    from federation_selection import _cms_arguments
    with tempfile.TemporaryDirectory(prefix='runtime-cms-', dir=root) as temporary:
        private = Path(temporary)
        source, target = private / 'input', private / 'output'
        _write(source, raw)
        cert = private / 'recipient.pem'
        _write(cert, certificate)
        key = None
        if decrypt:
            _shape(source, private)
            key = private / 'recipient.key'
            try:
                key_bytes = _read(RECIPIENT_KEY, 16384, protected=True, key=True)
            except FileNotFoundError:
                raise CompanionError('runtime-companion-recipient-key-missing') from None
            _write(key, key_bytes)
        _openssl(_cms_arguments(source, target, cert, key=key))
        if not decrypt:
            _shape(target, private)
        return _read(target)


def _context(freeze):
    return {**{field: freeze[field] for field in CONTEXT}, 'sourceCommit': freeze['source']['commit']}


def _identity(name, raw):
    return {'fileName': name, 'digest': _digest(raw), 'sizeBytes': len(raw)}


def _inspect(freeze, transfer_root):
    root = Path(transfer_root)
    if freeze.get('schemaVersion') != 3 or {p.name for p in root.iterdir()} != {DESCRIPTOR, CIPHERTEXT}:
        _fail()
    raw = _read(root / DESCRIPTOR, 16384)
    if freeze['runtimeMetadata'] != _identity(DESCRIPTOR, raw):
        _fail()
    value = _json(raw)
    if (set(value) != {'schemaVersion', 'kind', 'mode', 'purpose', 'recipientPolicy',
                       'recipientEpoch', 'ciphertext'}
            or type(value['schemaVersion']) is not int or value['schemaVersion'] != 1
            or value['kind'] != 'maintenance-runtime-companion'
            or value['mode'] != 'selected-federation' or value['purpose'] != PURPOSE
            or value['recipientPolicy'] != POLICY_ID or type(value['recipientEpoch']) is not int
            or value['recipientEpoch'] < 1
            or value['ciphertext'] != _identity(CIPHERTEXT, _read(root / CIPHERTEXT))):
        _fail()
    return value


def inspect(freeze, transfer_root):
    """Offline outer integrity only; no local keys, network, or private identities."""
    try:
        return _inspect(freeze, transfer_root)
    except CompanionError:
        raise
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        raise CompanionError('runtime-companion-rejected') from None


def seal(runtime_root, transfer_root, freeze):
    """Seal exactly five previously authenticated/validated private members once."""
    try:
        source, target = Path(runtime_root), Path(transfer_root)
        if source.resolve() == target.resolve() or source.resolve() in target.resolve().parents or target.resolve() in source.resolve().parents:
            _fail()
        if target.exists() or target.is_symlink() or any(p.is_symlink() for p in target.parents):
            _fail()
        if {p.name for p in source.iterdir()} != MEMBERS:
            _fail()
        policy, certificate = _policy()
        files = {name: _read(source / name, MAX_MEMBER) for name in MEMBERS}
        for raw in files.values():
            _json(raw)
        inner = {'schemaVersion': 1, 'kind': 'maintenance-runtime-private-set', 'purpose': PURPOSE,
                 'mode': 'selected-federation', 'context': _context(freeze),
                 'operationId': str(uuid.uuid4()), 'preparedAt': dt.datetime.now(dt.timezone.utc).isoformat(),
                 'recipientPolicy': POLICY_ID, 'recipientEpoch': policy['epoch'],
                 'members': {name: {'digest': _digest(raw), 'sizeBytes': len(raw),
                              'content': base64.b64encode(raw).decode('ascii')} for name, raw in files.items()}}
        encrypted = _cms(_bytes(inner), source.parent, certificate)
        descriptor = {'schemaVersion': 1, 'kind': 'maintenance-runtime-companion',
                      'mode': 'selected-federation', 'purpose': PURPOSE, 'recipientPolicy': POLICY_ID,
                      'recipientEpoch': policy['epoch'], 'ciphertext': _identity(CIPHERTEXT, encrypted)}
        raw = _bytes(descriptor)
        with tempfile.TemporaryDirectory(prefix='runtime-transfer-', dir=target.parent) as temporary:
            staged = Path(temporary) / 'runtime'
            staged.mkdir(mode=0o700)
            _write(staged / CIPHERTEXT, encrypted)
            _write(staged / DESCRIPTOR, raw)
            inspect({**freeze, 'schemaVersion': 3, 'runtimeMetadata': _identity(DESCRIPTOR, raw)}, staged)
            staged.rename(target)
        return _identity(DESCRIPTOR, raw)
    except CompanionError:
        raise
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        raise CompanionError('runtime-companion-rejected') from None


@contextmanager
def open_companion(freeze, transfer_root, private_parent):
    """Own a short-lived private materialization; caller must first prove original authority."""
    try:
        descriptor = inspect(freeze, transfer_root)
        policy, certificate = _policy()
        if descriptor['recipientEpoch'] != policy['epoch']:
            _fail()
        parent = Path(private_parent)
        if any(p.is_symlink() for p in (parent, *parent.parents)) or parent.stat().st_mode & 0o077:
            _fail()
        with tempfile.TemporaryDirectory(prefix='runtime-open-', dir=parent) as temporary:
            root = Path(temporary)
            encrypted = _read(Path(transfer_root) / CIPHERTEXT)
            if descriptor['ciphertext'] != _identity(CIPHERTEXT, encrypted):
                _fail()
            inner = _json(_cms(encrypted, root, certificate, decrypt=True))
            if (set(inner) != {'schemaVersion', 'kind', 'purpose', 'mode', 'context', 'operationId',
                              'preparedAt', 'recipientPolicy', 'recipientEpoch', 'members'}
                    or type(inner['schemaVersion']) is not int or inner['schemaVersion'] != 1
                    or inner['kind'] != 'maintenance-runtime-private-set' or inner['purpose'] != PURPOSE
                    or inner['mode'] != 'selected-federation' or inner['context'] != _context(freeze)
                    or inner['recipientPolicy'] != POLICY_ID or inner['recipientEpoch'] != policy['epoch']
                    or str(uuid.UUID(inner['operationId'])) != inner['operationId']
                    or set(inner['members']) != MEMBERS):
                _fail()
            prepared = dt.datetime.fromisoformat(inner['preparedAt'].replace('Z', '+00:00'))
            frozen = dt.datetime.fromisoformat(freeze['frozenAt'].replace('Z', '+00:00'))
            if (prepared.tzinfo is None or frozen.tzinfo is None or prepared > frozen
                    or prepared > dt.datetime.now(dt.timezone.utc)):
                _fail()
            files = {}
            for name, row in inner['members'].items():
                if set(row) != {'digest', 'sizeBytes', 'content'}:
                    _fail()
                raw = base64.b64decode(row['content'], validate=True)
                if (not 1 <= len(raw) <= MAX_MEMBER or type(row['sizeBytes']) is not int
                        or row['sizeBytes'] != len(raw) or row['digest'] != _digest(raw)):
                    _fail()
                _json(raw)
                files[name] = raw
            materialized = root / 'runtime'
            materialized.mkdir(mode=0o700)
            for name, raw in files.items():
                _write(materialized / name, raw)
            yield materialized
    except CompanionError:
        raise
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        raise CompanionError('runtime-companion-rejected') from None

"""Prepare a bounded private original-input capsule after the installed host owner passes.

Preparation carries no protected authority. A separately owned root collector must reverify
these native originals, bind the original journal, and retain the opaque supervisor receipt.
"""
from __future__ import annotations

import base64
import hashlib
import importlib
import json
import os
import pwd
import stat
from pathlib import Path

import pr318_storage_runtime_runner as host
from cryptad_certification import composed_budget_journal_member as journal

FILE = 'pr320-campaign-original-inputs.private.json'
ROOT_FILE = 'pr320-campaign-root-originals.private.json'
LIMIT = 16 * 1024 * 1024
OWNERS = {'pr320_route_runtime_evidence': 'route-component',
          'pr320_storage_runtime_evidence': 'storage-component',
          'pr320_owner_runtime_evidence': 'legacy-attachment',
          'pr320_restart_runtime_evidence': 'legacy-attachment',
          'pr320_privacy_runtime_evidence': 'installed-privacy'}


def _need(condition):
    if not condition: raise ValueError('pr320-original-capture-invalid')


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _read_owned(path, maximum, uid):
    """Read a fixed actor/root member through stable descriptors, never following links."""
    from cryptad_certification.certification_public_export import _open_directory
    path = Path(path)
    parent = _open_directory(path.parent)
    try:
        directory = os.fstat(parent)
        _need(directory.st_uid == uid and directory.st_mode & 0o077 == 0)
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(descriptor)
            _need(stat.S_ISREG(before.st_mode) and before.st_uid == uid and before.st_nlink == 1
                  and before.st_mode & 0o077 == 0 and 0 < before.st_size <= maximum)
            raw = os.read(descriptor, maximum + 1)
            after = os.fstat(descriptor)
            fields = lambda value: (value.st_dev, value.st_ino, value.st_uid, value.st_mode,
                                    value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
            _need(len(raw) == before.st_size and fields(before) == fields(after))
            return raw
        finally: os.close(descriptor)
    finally: os.close(parent)


def decode_root_capsule(raw):
    """Bound the root precursor; the absent host clock report grants no assessment."""
    _need(isinstance(raw, bytes) and 0 < len(raw) <= LIMIT)
    from cryptad_certification.composed_budget_campaign_evidence import _decode
    value = _decode(raw)
    _need(isinstance(value, dict) and set(value) == {'schemaVersion', 'kind', 'planDigest', 'originals'}
          and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
          and value['kind'] == 'pr320-root-original-input-capture')
    originals = value['originals']
    _need(isinstance(originals, dict) and set(originals) == {'owner', 'private', 'selected', 'diagnostics',
        'terminal', 'report', 'checkpoints', 'native', 'privacyOriginals', 'browser', 'artifact'}
        and originals['owner'] in OWNERS and originals['report'] is None)
    selected = originals['selected']
    _need(journal.legacy.pressure.baseline.digest(selected['plan']) == value['planDigest'])
    journal.validate_selected_sources(selected['plan'], selected['authorization']['budgetSelection']['toolIdentities'])
    module = importlib.import_module(originals['owner'])
    _need(Path(module.__file__).resolve() == Path(__file__).resolve().parent / (originals['owner'] + '.py'))
    _need(module.contract.verify_selection_contract(**selected))
    def raw_field(name, maximum):
        encoded = originals[name]
        _need(isinstance(encoded, str) and len(encoded) <= 4 * ((maximum + 2) // 3))
        data = base64.b64decode(encoded, validate=True)
        _need(0 < len(data) <= maximum and base64.b64encode(data).decode() == encoded)
        return data
    private = module.decode_private(raw_field('private', module.MAX_PRIVATE_BYTES))
    _need(private['selectionDigest'] == selected['authorization']['selectionDigest'])
    module.decode_checkpoints(raw_field('checkpoints', module.MAX_PRIVATE_BYTES))
    if hasattr(module, 'ROOT_NATIVE_FILE'):
        native = raw_field('native', module.MAX_PRIVATE_BYTES)
        module.decode_root_native(native)
    else: _need(originals['native'] is None)
    if hasattr(module, 'ORIGINALS_FILE'):
        module.decode_originals(raw_field('privacyOriginals', module.MAX_ORIGINAL_BYTES))
        module.decode_browser(raw_field('browser', 4 * 1024 * 1024))
        from pr320_privacy_artifact_producer import decode_artifact, LIMIT as artifact_limit
        artifact_raw=raw_field('artifact',artifact_limit)
        artifact=decode_artifact(artifact_raw)
        module.privacy.verify_artifacts(artifact,private['component'],
            native_digest='sha256:'+hashlib.sha256(raw_field('private',module.MAX_PRIVATE_BYTES)).hexdigest(),
            source_commit=next(row['sourceCommit'] for row in selected['plan']['nodes'] if row['role']=='candidate-sender'))
    else: _need(originals['privacyOriginals'] is None and originals['browser'] is None and originals['artifact'] is None)
    return value


def prepare_root(workload, selected, diagnostics, volatile):
    """Capture root originals while owned role tmpfs and volatile records still exist.

    Host UTC brackets are unavailable in the guest and remain null. The host reader adds
    its measured report separately; it cannot replace any root-captured original bytes.
    """
    _need(os.geteuid() == 0 and 'budgetCampaignInputs' in selected['plan'])
    journal.validate_inputs(selected['plan'])
    execution = selected['authorization']['executionClass']
    import pr320_route_contract as route_contract
    import pr320_storage_contract as storage_contract
    if execution in route_contract.EXECUTION_CLASSES:
        owner_name = 'pr320_route_runtime_evidence'
    elif execution in storage_contract.EXECUTION_CLASSES:
        owner_name = 'pr320_storage_runtime_evidence'
    elif execution == 'pr320-installed-owner-cancellation-v1':
        owner_name = 'pr320_owner_runtime_evidence'
    elif execution == 'pr320-installed-budget-privacy-v1':
        owner_name = 'pr320_privacy_runtime_evidence'
    elif execution == 'pr320-installed-restart-diagnostics-v1':
        owner_name = 'pr320_restart_runtime_evidence'
    else: raise ValueError('pr320-original-capture-unselected')
    module = importlib.import_module(owner_name)
    root = Path(selected['private']['root'])
    actor_uid = pwd.getpwnam('cryptad-soak').pw_uid
    _need(actor_uid > 0 and root == Path('/var/lib/cryptad-cross-version/experiments') / selected['plan']['experimentId'])
    def b64(name, maximum):
        return base64.b64encode(_read_owned(root / name, maximum, actor_uid)).decode()
    authority = workload.ROOT / 'authority'
    def original(name, maximum):
        return base64.b64encode(_read_owned(authority / name, maximum, 0)).decode()
    native_names = {'pr320_owner_runtime_evidence': 'pr320-owner-original-native.json',
                    'pr320_route_runtime_evidence': 'pr320-route-original-native.json'}
    originals = dict(owner=owner_name, private=b64(module.PRIVATE_FILE, module.MAX_PRIVATE_BYTES),
        selected=selected, diagnostics=diagnostics, terminal=volatile, report=None,
        checkpoints=b64('pr318-storage-attempts.private.jsonl' if owner_name == 'pr320_storage_runtime_evidence'
                        else module.CHECKPOINT_FILE, module.MAX_PRIVATE_BYTES),
        native=original(native_names[owner_name], module.MAX_PRIVATE_BYTES) if owner_name in native_names else None,
        privacyOriginals=original('pr320-privacy-originals.private.json', module.MAX_ORIGINAL_BYTES)
            if hasattr(module, 'ORIGINALS_FILE') else None,
        browser=b64(module.BROWSER_FILE, 4 * 1024 * 1024) if hasattr(module, 'BROWSER_FILE') else None,
        artifact=b64('pr320-public-artifact.private.json',2*1024*1024) if hasattr(module,'BROWSER_FILE') else None)
    value = dict(schemaVersion=1, kind='pr320-root-original-input-capture',
        planDigest=journal.legacy.pressure.baseline.digest(selected['plan']), originals=originals)
    raw = _encode(value)
    _need(0 < len(raw) <= LIMIT)
    decode_root_capsule(raw)
    destination = workload.ROOT / 'authority' / FILE
    workload.secured(destination.parent, directory=True)
    from cryptad_certification.certification_public_export import _open_directory
    parent = _open_directory(destination.parent)
    try:
        fd = os.open(destination.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(raw); handle.flush(); os.fsync(handle.fileno())
        os.fsync(parent)
    finally: os.close(parent)
    return {'file': FILE, 'bytes': len(raw), 'digest': 'sha256:' + hashlib.sha256(raw).hexdigest()}


def prepare(attempt, report, owner_name):
    """Read the exact already-verified roster, retain private bytes, and grant no admission."""
    _need(owner_name in OWNERS)
    module = importlib.import_module(owner_name)
    _need(Path(module.__file__).resolve() == Path(__file__).resolve().parent / (owner_name + '.py'))
    attempt = Path(attempt)
    selected = host.shared._private_json(attempt / 'pr320-selection.private.json', 262144)
    metadata = journal.validate_inputs(selected['plan'])
    journal.validate_selected_sources(selected['plan'], selected['authorization']['budgetSelection']['toolIdentities'])
    private_raw = host.shared._private_bytes(attempt / module.PRIVATE_FILE, module.MAX_PRIVATE_BYTES)
    private = module.decode_private(private_raw)
    def b64_file(name, maximum):
        return base64.b64encode(host.shared._private_bytes(attempt / name, maximum)).decode()
    originals = dict(owner=owner_name, private=base64.b64encode(private_raw).decode(), selected=selected,
        diagnostics=host.shared._private_json(attempt / 'pr315-workload-memory.private.json', 262144),
        terminal=host.shared._private_json(attempt / 'pr315-workload-volatile.private.json', 262144),
        report=report, checkpoints=b64_file(module.CHECKPOINT_FILE, module.MAX_PRIVATE_BYTES),
        native=b64_file(module.ROOT_NATIVE_FILE, module.MAX_PRIVATE_BYTES) if hasattr(module, 'ROOT_NATIVE_FILE') else None,
        privacyOriginals=b64_file(module.ORIGINALS_FILE, module.MAX_ORIGINAL_BYTES) if hasattr(module, 'ORIGINALS_FILE') else None,
        browser=b64_file(module.BROWSER_FILE, 4 * 1024 * 1024) if hasattr(module, 'BROWSER_FILE') else None,
        artifact=b64_file('pr320-public-artifact.private.json',2*1024*1024) if hasattr(module,'BROWSER_FILE') else None)
    root_capture = attempt / ROOT_FILE
    if root_capture.exists() or root_capture.is_symlink():
        rooted = decode_root_capsule(host.shared._private_bytes(root_capture, LIMIT))['originals']
        _need(rooted == {**originals, 'report': None})
        originals = {**rooted, 'report': report}
    else:
        raise ValueError('pr320-original-root-capture-required')
    raws = {}
    if owner_name == 'pr320_privacy_runtime_evidence':
        raws = {'installed-privacy': private_raw,
                'installed-browser-privacy': base64.b64decode(originals['browser'], validate=True)}
        raws['artifact-privacy'] = base64.b64decode(originals['artifact'],validate=True)
    else:
        component = (private['component'] if owner_name == 'pr320_route_runtime_evidence' else
                     private['storageComponent'] if owner_name == 'pr320_storage_runtime_evidence' else
                     private['composedBudgetEvidence'])
        raws[OWNERS[owner_name]] = _encode(component)
    entries = []
    for row in metadata:
        if row['kind'] not in raws: continue
        raw = raws[row['kind']]
        entries.append(dict(member=row['member'], kind=row['kind'], size=len(raw),
            digest='sha256:' + hashlib.sha256(raw).hexdigest(), rawBase64=base64.b64encode(raw).decode(),
            originals=originals))
    value = dict(schemaVersion=1, kind='pr320-private-original-input-capsule',
                 planDigest=journal.legacy.pressure.baseline.digest(selected['plan']), entries=entries)
    raw = _encode(value)
    _need(0 < len(raw) <= LIMIT)
    path = attempt / FILE
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    return path


def decode_capsule(raw):
    """Exact private retention reader; no copied coverage or public upload is accepted."""
    _need(isinstance(raw, bytes) and 0 < len(raw) <= LIMIT)
    from cryptad_certification.composed_budget_campaign_evidence import _decode
    value = _decode(raw)
    _need(isinstance(value, dict) and set(value) == {'schemaVersion', 'kind', 'planDigest', 'entries'}
          and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
          and value['kind'] == 'pr320-private-original-input-capsule'
          and isinstance(value['entries'], list) and 1 <= len(value['entries']) <= 3)
    names = set()
    from composed_budget_campaign_admission import verify_original_member
    for entry in value['entries']:
        _need(isinstance(entry, dict) and set(entry) == {'member', 'kind', 'size', 'digest', 'rawBase64', 'originals'}
              and entry['member'] not in names)
        names.add(entry['member'])
        member = base64.b64decode(entry['rawBase64'], validate=True)
        _need(type(entry['size']) is int and entry['size'] == len(member)
              and entry['digest'] == 'sha256:' + hashlib.sha256(member).hexdigest())
        selected = verify_original_member(entry['kind'], member, entry['originals'])
        _need(journal.legacy.pressure.baseline.digest(selected['plan']) == value['planDigest'])
        _need(any(row['member'] == entry['member'] and row['kind'] == entry['kind']
                  for row in journal.validate_inputs(selected['plan'])))
    return value

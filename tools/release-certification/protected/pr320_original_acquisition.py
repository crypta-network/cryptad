#!/usr/bin/python3
"""Acquire prospective budget originals inside the protected host's root domain.

This finite service runs the existing four-role kit on a qualified disposable host.
The requester cannot supply a plan, report, capture, executable, path, or originals.
Beginning work is short; the fixed systemd unit owns the long run and cleanup.
Source-build observations retain their original provenance and grant no release credit.
"""
from __future__ import annotations

import base64
import calendar
import datetime as dt
import fcntl
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import signal
import stat
import subprocess
import sys
import time
import uuid

CHECKOUT = Path('/opt/cryptad-cross-version/current')
KIT = Path('/opt/cryptad-restricted-test-kit')
ROOT = Path('/var/lib/cryptad-cross-version-authority/pr320-original-acquisition')
CONFIG = Path('/etc/cryptad-certification/pr320-original-acquisition.json')
ACTIVATION = Path('/var/lib/cryptad-cross-version-authority/activation.json')
SELECTION = ROOT / 'selection.json'
DRIVER_SELECTION = Path('/root/pr314-workload-selection.json')
WORKLOAD = Path('/var/lib/cryptad-restricted-workload')
STATE = Path('/var/lib/cryptad-cross-version')
BUDGET_UNIT = 'cryptad-pr320-original-acquisition.service'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8',
       'PYTHONDONTWRITEBYTECODE': '1'}
MAX_CAPTURE = 16 * 1024 * 1024
MAX_JOURNAL = 16 * 1024 * 1024
MAX_TOTAL = 40 * 1024 * 1024
_SEAL = object()
_KIT_VERIFIED = None


class AcquisitionError(ValueError):
    """Fixed diagnostic; private payloads never enter an error message."""


def _need(value):
    if not value:
        raise AcquisitionError('pr320-root-original-acquisition-unavailable')


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _json(raw):
    def unique(pairs):
        result = {}
        for name, value in pairs:
            _need(name not in result)
            result[name] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: _need(False))


def _trusted(path, *, private=True):
    path = Path(path)
    for entry in (path, *path.parents):
        info = entry.lstat()
        _need(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0
              and not info.st_mode & 0o022)
    if private:
        _need(not path.stat().st_mode & 0o077)
    return path


def _read(path, maximum, *, private=True):
    _trusted(path, private=private)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        _need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
              and 0 <= before.st_size <= maximum)
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after, current = os.fstat(descriptor), Path(path).lstat()
        fields = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink',
                  'st_size', 'st_mtime_ns', 'st_ctime_ns')
        _need(len(raw) == before.st_size and all(getattr(before, field) ==
              getattr(after, field) == getattr(current, field) for field in fields))
        return raw
    finally:
        os.close(descriptor)


def _write(path, raw, *, maximum=MAX_TOTAL):
    _trusted(Path(path).parent)
    _need(isinstance(raw, bytes) and 0 <= len(raw) <= maximum)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(descriptor, 'wb', closefd=False) as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    descriptor = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _immutable(path, maximum):
    _need(stat.S_IMODE(Path(path).lstat().st_mode) == 0o400)
    return _read(path, maximum)


def _boot():
    value = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    _need(str(uuid.UUID(value)) == value)
    return value


def _installed():
    _need(os.geteuid() == 0 and sys.flags.isolated and sys.flags.no_site
          and Path(__file__).resolve() == CHECKOUT.resolve(strict=True) /
          'tools/release-certification/protected/pr320_original_acquisition.py')
    sys.dont_write_bytecode = True
    for relative in ('tools/interop', 'tools/release-certification',
                     'tools/release-certification/restricted',
                     'tools/release-certification/protected'):
        sys.path.insert(0, str(CHECKOUT / relative))
    from restricted_registration import installed_verifier
    _installation, identity = installed_verifier()
    _verified_kit(identity['sourceCommit'], force=True)
    return identity


def _manager(action='show'):
    arguments = ['/usr/bin/systemctl', action, BUDGET_UNIT]
    if action == 'show':
        arguments += ['--property=ActiveState,SubState,InvocationID,MainPID,ControlGroup,Result,ExecMainStatus,ExecMainCode']
    else:
        _need(action == 'start')
        arguments += ['--no-block']
    result = subprocess.run(arguments, capture_output=True, timeout=20, env=ENV)
    _need(result.returncode == 0 and len(result.stdout) <= 4096 and len(result.stderr) <= 4096)
    if action != 'show':
        return None
    rows = dict(row.split('=', 1) for row in result.stdout.decode('ascii').splitlines())
    _need(set(rows) == {'ActiveState', 'SubState', 'InvocationID', 'MainPID', 'ControlGroup',
                       'Result', 'ExecMainStatus', 'ExecMainCode'})
    return rows


def _verify_unit():
    """Require the reviewed literal unit and reject every loaded override."""
    target = Path('/etc/systemd/system') / BUDGET_UNIT
    source = CHECKOUT / 'tools/release-certification/restricted/systemd' / BUDGET_UNIT
    _need(_read(target, 65536, private=False) == _read(source, 65536, private=False))
    result = subprocess.run(['/usr/bin/systemctl', 'show', BUDGET_UNIT,
        '--property=FragmentPath,DropInPaths', '--no-pager'], capture_output=True, timeout=20, env=ENV)
    _need(result.returncode == 0 and len(result.stdout) <= 4096)
    fields = dict(row.split('=', 1) for row in result.stdout.decode('ascii').splitlines())
    _need(fields == {'FragmentPath': str(target), 'DropInPaths': ''})
    for base in ('/etc/systemd/system', '/run/systemd/system', '/usr/lib/systemd/system',
                 '/etc/systemd/system.control', '/run/systemd/system.control'):
        for name in (BUDGET_UNIT + '.d', 'cryptad-pr320-original-.service.d',
                     'cryptad-pr320-.service.d', 'cryptad-.service.d', 'service.d'):
            path = Path(base) / name
            _need(not path.exists() and not path.is_symlink())


def _verified_kit(source_commit, *, force=False):
    """Verify every file of the fixed separate kit before adding its import directory."""
    global _KIT_VERIFIED
    import installation
    raw = _read(KIT / '.test-kit.json', 1024 * 1024, private=False)
    kit = _json(raw)
    _need(isinstance(kit, dict) and set(kit) == {'schemaVersion', 'kind', 'sourceCommit',
        'productionEligible', 'files'} and type(kit['schemaVersion']) is int and kit['schemaVersion'] == 1
        and kit['kind'] == 'synthetic-disposable-test-kit' and kit['productionEligible'] is False
        and kit['sourceCommit'] == source_commit and isinstance(kit['files'], dict)
        and 0 < len(kit['files']) <= 10000)
    stamp = (source_commit, _digest(raw))
    if force or _KIT_VERIFIED != stamp:
        names, total = set(), 0
        for directory, directories, files in os.walk(KIT, followlinks=False):
            _trusted(directory, private=False)
            _need(all(not (Path(directory) / name).is_symlink() for name in directories))
            for name in files:
                path = Path(directory) / name
                relative = path.relative_to(KIT).as_posix()
                if relative == '.test-kit.json': continue
                _need(relative in kit['files'] and not installation.production_member(relative)
                      and re.fullmatch('[0-9a-f]{64}', str(kit['files'][relative])) is not None)
                data = _read(path, 4 * 1024 * 1024, private=False)
                total += len(data); names.add(relative)
                _need(total <= 256 * 1024 * 1024 and hashlib.sha256(data).hexdigest() == kit['files'][relative])
        _need(names == set(kit['files']))
        _KIT_VERIFIED = stamp
    directory = str(KIT / 'tools/release-certification/restricted')
    if directory not in sys.path: sys.path.insert(0, directory)
    return kit


def _tool_path(relative, identity):
    """Resolve only the approved product export or its exact separate kit member."""
    import installation
    _need(isinstance(relative, str) and not Path(relative).is_absolute()
          and '..' not in Path(relative).parts and Path(relative).as_posix() == relative)
    manifest_raw = _read(CHECKOUT / '.restricted-manifest.json', 16 * 1024 * 1024, private=False)
    _need(hashlib.sha256(manifest_raw).hexdigest() == identity['bundleIdentity'])
    manifest = _json(manifest_raw)
    _need(manifest['sourceCommit'] == identity['sourceCommit'])
    if installation.production_member(relative):
        _need(relative in manifest['files'])
        path, expected = CHECKOUT / relative, manifest['files'][relative]['sha256']
    else:
        kit = _verified_kit(identity['sourceCommit'])
        _need(relative in kit['files'])
        path, expected = KIT / relative, kit['files'][relative]
    _need(hashlib.sha256(_read(path, 4 * 1024 * 1024, private=False)).hexdigest() == expected)
    return path


def validate_selected_contract(plan, private, authorization):
    """Root supervisor entry for the exact prospective contract under verified kit imports."""
    _installed()
    import pr320_installed_dispatch as dispatch
    _need(Path(dispatch.__file__).resolve() == KIT / 'tools/release-certification/restricted/pr320_installed_dispatch.py')
    profile = dispatch.common.prospective_profile(authorization.get('executionClass'))
    module = importlib.import_module({'pr320-installed-owner-cancellation-v1': 'pr320_cancellation_contract',
        'pr320-installed-restart-diagnostics-v1': 'pr320_restart_contract',
        'pr320-installed-budget-privacy-v1': 'pr320_privacy_contract'}.get(authorization.get('executionClass'),
        'pr320_route_contract' if authorization.get('executionClass') in dispatch.common.ROUTE_EXECUTION_CLASSES
        else 'pr320_storage_contract'))
    _need(profile['executionClass'] == authorization.get('executionClass')
          and module.verify_selection_contract(plan, private, authorization))
    return True


def verified_owner(name):
    """Resolve only one of the five measured original consumers in the separate kit."""
    _need(name in {'pr320_route_runtime_evidence', 'pr320_storage_runtime_evidence',
        'pr320_owner_runtime_evidence', 'pr320_restart_runtime_evidence', 'pr320_privacy_runtime_evidence'})
    identity = _installed()
    path = _tool_path('tools/release-certification/restricted/' + name + '.py', identity)
    module = importlib.import_module(name)
    _need(Path(module.__file__).resolve() == path)
    return module


def verified_privacy_observer():
    """Load the read-only privacy verifier for the unprivileged installed actor.

    Public source/dependency verification supplies no original custody or root capability.
    Root terminal admission continues to use ``verified_owner`` and its owning checks.
    """
    _need(Path(__file__).resolve() == CHECKOUT.resolve(strict=True) /
          'tools/release-certification/protected/pr320_original_acquisition.py')
    from cross_version_runtime import installed_snapshot_identity
    identity = installed_snapshot_identity(CHECKOUT)
    _need(isinstance(identity, dict))
    _verified_kit(identity['sourceCommit'], force=True)
    name = 'pr320_privacy_runtime_evidence'
    path = _tool_path('tools/release-certification/restricted/' + name + '.py', identity)
    module = importlib.import_module(name)
    _need(Path(module.__file__).resolve() == path)
    return module


def _kit_driver(source_commit):
    """Load the fixed measured kit driver without changing fixture factory import paths."""
    import installation
    identity = installation.verify_execution()
    _need(identity['sourceCommit'] == source_commit)
    kit = _verified_kit(source_commit)
    relative = 'tools/release-certification/restricted/pr314_workload_driver.py'
    path = KIT / relative
    raw = _read(path, 1024 * 1024, private=False)
    _need(kit['sourceCommit'] == source_commit
          and kit['files'].get(relative) == hashlib.sha256(raw).hexdigest())
    spec = importlib.util.spec_from_file_location('_pr320_fixed_kit_driver', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _need(not module.prerequisites())
    return module


def _boundary():
    import restricted_native as native
    import restricted_worker as worker
    current = native._ACTIVE.get()
    _need(isinstance(current, tuple) and len(current) == 2)
    context, check = current
    _need(isinstance(context, dict) and set(context) == {'operationId',
          'registrationDigest', 'bundleIdentity', 'deadlineMonotonic'}
          and callable(check) and type(context['deadlineMonotonic']) in (int, float)
          and time.monotonic() < context['deadlineMonotonic'])
    _need(re.fullmatch('[0-9a-f]{64}', str(context['operationId'])) is not None)
    check()
    operation = worker.OPERATIONS / context['operationId']
    raw = worker.read(operation / 'registration.json')
    record = worker.validate_record(worker.decode(raw, worker.MAX_RECORD))
    _need(record['method'] in {'budget-acquisition-prepare', 'supervisor-start',
                              'budget-acquisition-begin', 'budget-acquisition-collect'}
          and record['handle'] == context['operationId']
          and record['bundleIdentity'] == context['bundleIdentity']
          and worker.digest(raw) == context['registrationDigest'])
    worker.require_not_revoked(operation, record)
    worker.check_inputs(record, operation)
    return context, record, operation


def _configuration(record):
    raw = _read(CONFIG, 65536)
    _need(record['configurationFiles'].get(str(CONFIG)) ==
          {'digest': _digest(raw), 'size': len(raw)})
    value = _json(raw)
    fields = {'schemaVersion', 'kind', 'executionClass', 'fixtureManifestDigest',
              'candidateCommit', 'planDigest', 'verifierDigest'}
    _need(isinstance(value, dict) and set(value) == fields
          and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
          and value['kind'] == 'pr320-original-acquisition-selection')
    import pr320_budget_contract as common
    _need(value['executionClass'] in common.PROSPECTIVE_EXECUTION_CLASSES
          and re.fullmatch('[0-9a-f]{64}', str(value['fixtureManifestDigest'])) is not None
          and re.fullmatch('[0-9a-f]{40}', str(value['candidateCommit'])) is not None
          and re.fullmatch('sha256:[0-9a-f]{64}', str(value['planDigest'])) is not None
          and re.fullmatch('sha256:[0-9a-f]{64}', str(value['verifierDigest'])) is not None)
    return value


class InstalledFixtureSource:
    """Root-only installed source/verifier identity for the prospective factory seam."""
    __slots__ = ('_source_commit', '_bundle', '_verifier', '_verifier_digest')

    def __init__(self, seal, identity, verifier, verifier_digest):
        _need(seal is _SEAL and os.geteuid() == 0)
        object.__setattr__(self, '_source_commit', identity['sourceCommit'])
        object.__setattr__(self, '_bundle', identity['bundleIdentity'])
        object.__setattr__(self, '_verifier', str(verifier))
        object.__setattr__(self, '_verifier_digest', verifier_digest)

    def __setattr__(self, _name, _value):
        raise AcquisitionError('pr320-installed-fixture-source-frozen')

    def tool_path(self, relative):
        _need(os.geteuid() == 0)
        return _tool_path(relative, {'sourceCommit': self._source_commit, 'bundleIdentity': self._bundle})

    def require(self, source, fixture_root, fixture_verifier_digest):
        import cross_version_runtime as runtime
        identity = _installed()
        verifier = Path(self._verifier)
        _need(Path(source) == CHECKOUT and identity['sourceCommit'] == self._source_commit
              and identity['bundleIdentity'] == self._bundle
              and verifier == Path(fixture_root).parent / 'verifier'
              and verifier.is_relative_to('/root/cryptad/build')
              and fixture_verifier_digest == self._verifier_digest)
        _trusted(verifier)
        _need(runtime.tree_digest(verifier, require_java=False) == self._verifier_digest)
        return self._source_commit, verifier


def _fixture_factory(configuration, record, operation):
    """Stage only the registered fixture tree into the class's fixed existing root."""
    import pr320_installed_dispatch as dispatch
    module, _source_root = dispatch.fixture(configuration['executionClass'], CHECKOUT)
    _need(Path(module.__file__).resolve().parent == KIT / 'tools/release-certification/restricted')
    fixed = getattr(module, 'FIXED_ROOT', getattr(module, 'FIXED_GUEST_ROOT', None))
    _need(isinstance(fixed, Path) and fixed.is_relative_to('/root/cryptad/build'))
    profile = dispatch.common.prospective_profile(configuration['executionClass'])
    if configuration['executionClass'] in (*dispatch.common.ROUTE_EXECUTION_CLASSES,
                                           *dispatch.contract.EXECUTION_CLASSES):
        fixed = fixed / profile['experiment']
    mode_name = 'fixture-modes.private.json'
    fixture_names = {name for name in record['inputFiles'] if name.startswith('fixture/')}
    verifier_names = {name for name in record['inputFiles'] if name.startswith('verifier/')}
    member_names = fixture_names | verifier_names
    _need(mode_name in record['inputFiles'] and fixture_names and verifier_names
          and set(record['inputFiles']) == member_names | {mode_name})
    modes = _json(_read(operation / 'inputs' / mode_name, 262144))
    _need(isinstance(modes, dict) and set(modes) == member_names
          and all(type(mode) is int and mode in ((0o600, 0o700) if name in fixture_names
              else (0o600, 0o700, 0o644, 0o755)) for name, mode in modes.items()))
    _need(not fixed.exists() and not fixed.is_symlink())
    fixed.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _trusted(fixed.parent)
    fixed.mkdir(mode=0o700)
    # The registration owns the complete bounded tree. No caller-selected source paths.
    for name in sorted(member_names):
        identity = record['inputFiles'][name]
        relative = Path(name).relative_to('fixture') if name in fixture_names else Path(name)
        _need(relative.parts and '..' not in relative.parts)
        destination = fixed / relative
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        raw = _read(operation / 'inputs' / name, identity['size'])
        _need(len(raw) == identity['size'] and _digest(raw) == identity['digest'])
        _write(destination, raw, maximum=1024**3)
        # The normal fixture verifier authenticates the resulting runtime modes/digest.
        destination.chmod(modes[name])
    _write(fixed / mode_name, _read(operation / 'inputs' / mode_name, 262144))
    identity = _installed()
    _need(identity['sourceCommit'] == record['context']['sourceCommit'])
    source = InstalledFixtureSource(_SEAL, identity, fixed / 'verifier', configuration['verifierDigest'])
    return module.materialize_selection(fixed, CHECKOUT,
        configuration['fixtureManifestDigest'], configuration['candidateCommit'], installed_source=source)


def _activation(selected, *, terminal=None):
    raw = _read(ACTIVATION, 1024 * 1024, private=False)
    value = _json(raw)
    # Activation is public root-owned metadata in the historical supervisor.
    _need(value.get('planDigest') == _digest(_encode(selected['plan']))
          and value.get('bootId') == _boot()
          and type(value.get('deadlineMonotonicNs')) is int)
    if terminal is None: _need(time.monotonic_ns() < value['deadlineMonotonicNs'])
    if value.get('schemaVersion') == 1:
        _need(value.get('privateConfigDigest') == _digest(_encode(selected['private']))
              and value.get('authorizationDigest') == _digest(_encode(selected['authorization'])))
    else:
        from cross_version_supervisor_authority import _private_product_record
        products = _private_product_record(value, terminal=terminal)
        _need(products['privateConfigDigest'] == _digest(_encode(selected['private']))
              and products['authorizationDigest'] == _digest(_encode(selected['authorization'])))
    return value


def _active():
    pointer = _json(_immutable(ROOT / 'active.json', 65536))
    _need(isinstance(pointer, dict) and set(pointer) == {'acquisitionId', 'startDigest'}
          and str(uuid.UUID(pointer['acquisitionId'])) == pointer['acquisitionId'])
    directory = ROOT / pointer['acquisitionId']
    raw = _immutable(directory / 'start.json', 1024 * 1024)
    _need(_digest(raw) == pointer['startDigest'])
    start = _json(raw)
    _need(isinstance(start, dict) and set(start) == {'schemaVersion', 'kind', 'acquisitionId',
        'operationId', 'registrationDigest', 'bundleIdentity', 'job', 'sourceCommit',
        'activationDigest', 'planDigest', 'configurationDigest', 'selectionDigest',
        'helperIdentities', 'productsDigest', 'bootId', 'startedMonotonicNs',
        'deadlineMonotonicNs', 'executionClass'}
        and type(start['schemaVersion']) is int and start['schemaVersion'] == 1
        and start['kind'] == 'pr320-root-original-acquisition-start'
        and start['acquisitionId'] == pointer['acquisitionId']
        and type(start['startedMonotonicNs']) is int and type(start['deadlineMonotonicNs']) is int
        and 0 < start['startedMonotonicNs'] < start['deadlineMonotonicNs'])
    return directory, start


def _root_directory():
    if not ROOT.parent.exists():
        _trusted(ROOT.parent.parent, private=False)
        ROOT.parent.mkdir(mode=0o755)
        ROOT.parent.chmod(0o755)
    if not ROOT.exists(): ROOT.mkdir(mode=0o700)
    _trusted(ROOT)


def _state_selection(selected):
    observer = pwd.getpwnam('cryptad-soak')
    _need(observer.pw_uid > 0 and observer.pw_gid > 0)
    if not STATE.exists():
        _trusted(STATE.parent, private=False)
        STATE.mkdir(mode=0o700)
        os.chown(STATE, observer.pw_uid, observer.pw_gid)
    for entry in (STATE, *STATE.parents): _need(not entry.is_symlink())
    info = STATE.stat()
    _need(info.st_uid == observer.pw_uid and stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o077)
    destination = STATE / 'selected'
    _need(not destination.exists() and not destination.is_symlink())
    destination.mkdir(mode=0o700)
    values = {'plan': selected['plan'], 'private-config': selected['private'],
              'authorization': selected['authorization']}
    bindings = {name: _digest(_encode(value)) for name, value in values.items()}
    values['service-selection'] = {'schemaVersion': 1,
        'serviceDigest': _digest(_read(CHECKOUT / 'tools/release-certification/protected/pr320_original_acquisition.py',
                                     1024 * 1024, private=False)),
        'planDigest': bindings['plan'], 'privateConfigDigest': bindings['private-config'],
        'authorizationDigest': bindings['authorization']}
    directory = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name, value in values.items():
            descriptor = os.open(name + '.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 os.O_NOFOLLOW, 0o400, dir_fd=directory)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(_encode(value)); stream.flush(); os.fsync(stream.fileno())
                os.fchown(stream.fileno(), observer.pw_uid, observer.pw_gid)
        os.fsync(directory)
    finally: os.close(directory)
    os.chown(destination, observer.pw_uid, observer.pw_gid)


def prepare_owned():
    """Request fixed root preparation without changing the hardened worker's namespace."""
    identity = _installed()
    _verify_unit()
    _context, record, operation = _boundary()
    _need(record['method'] == 'budget-acquisition-prepare')
    configuration = _configuration(record)
    _root_directory()
    lock = os.open(ROOT / '.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _need(not (ROOT / 'prepare-request.json').exists() and not (ROOT / 'prepared.json').exists()
              and not (ROOT / 'active.json').exists() and not SELECTION.exists()
              and _manager()['ActiveState'] in {'inactive', 'failed'})
        context, _record, _operation = _boundary()
        import restricted_worker as worker
        remaining = (worker.utc(record['expiresAt']) - worker.now()).total_seconds()
        _need(remaining > 0)
        preparation_deadline = min(context['deadlineMonotonic'], time.monotonic() + remaining)
        preparation = str(uuid.uuid4())
        _write(ROOT / 'prepare-request.json', _encode({'schemaVersion': 1,
            'kind': 'pr320-root-original-preparation-request', 'preparationId': preparation,
            'operationId': context['operationId'], 'registrationDigest': context['registrationDigest'],
            'job': record['context'], 'sourceCommit': identity['sourceCommit'],
            'bundleIdentity': identity['bundleIdentity'], 'configuration': configuration,
            'inputFiles': record['inputFiles'], 'bootId': _boot(),
            'deadlineMonotonicNs': int(preparation_deadline * 10**9)}))
        _manager('start')
        return {'status': 'started', 'acquisitionId': preparation}
    finally:
        os.close(lock)


def _preparation_request():
    request = _json(_immutable(ROOT / 'prepare-request.json', 1024 * 1024))
    _need(isinstance(request, dict) and set(request) == {'schemaVersion', 'kind', 'preparationId',
        'operationId', 'registrationDigest', 'job', 'sourceCommit', 'bundleIdentity',
        'configuration', 'inputFiles', 'bootId', 'deadlineMonotonicNs'}
        and type(request['schemaVersion']) is int and request['schemaVersion'] == 1
        and request['kind'] == 'pr320-root-original-preparation-request'
        and request['bootId'] == _boot() and type(request['deadlineMonotonicNs']) is int
        and re.fullmatch('[0-9a-f]{64}', str(request['operationId'])) is not None
        and str(uuid.UUID(request['preparationId'])) == request['preparationId'])
    import restricted_worker as worker
    operation = worker.OPERATIONS / request['operationId']
    raw = worker.read(operation / 'registration.json')
    record = worker.validate_record(worker.decode(raw, worker.MAX_RECORD))
    _need(record['method'] == 'budget-acquisition-prepare'
          and record['handle'] == request['operationId']
          and _digest(raw) == request['registrationDigest']
          and record['context'] == request['job'] and record['inputFiles'] == request['inputFiles']
          and record['bundleIdentity'] == request['bundleIdentity'])
    worker.require_not_revoked(operation, record)
    worker.check_inputs(record, operation)
    _need(_configuration(record) == request['configuration'])
    return request, record, operation


def _prepared_selection(configuration, record, *, staged=False):
    prepared = _json(_immutable(ROOT / 'prepared.json', 1024 * 1024))
    selected = _json(_immutable(SELECTION, 262144))
    identity = _installed()
    _need(isinstance(prepared, dict) and set(prepared) == {'schemaVersion', 'kind',
        'preparationId', 'job', 'sourceCommit', 'bundleIdentity', 'configuration',
        'inputFiles', 'selectionDigest', 'invocationId', 'preparedMonotonicNs', 'requestDigest'}
        and type(prepared['schemaVersion']) is int and prepared['schemaVersion'] == 1
        and prepared['kind'] == 'pr320-root-original-acquisition-prepared'
        and prepared['configuration'] == configuration and prepared['inputFiles'] == record['inputFiles']
        and prepared['sourceCommit'] == identity['sourceCommit']
        and prepared['bundleIdentity'] == identity['bundleIdentity']
        and prepared['selectionDigest'] == _digest(_encode(selected))
        and configuration['planDigest'] == _digest(_encode(selected['plan'])))
    request, _original_record, _operation = _preparation_request()
    _need(prepared['job'] == request['job'] and prepared['inputFiles'] == request['inputFiles']
          and prepared['configuration'] == request['configuration']
          and prepared['preparationId'] == request['preparationId']
          and prepared['requestDigest'] == _digest(_immutable(ROOT / 'prepare-request.json', 1024 * 1024))
          and type(prepared['preparedMonotonicNs']) is int
          and 0 < prepared['preparedMonotonicNs'] <= request['deadlineMonotonicNs']
          and re.fullmatch('[0-9a-f]{32}', str(prepared['invocationId'])) is not None)
    if not staged: return selected
    import pr320_installed_dispatch as dispatch
    module, _ = dispatch.fixture(configuration['executionClass'], CHECKOUT)
    fixed = getattr(module, 'FIXED_ROOT', getattr(module, 'FIXED_GUEST_ROOT', None))
    profile = dispatch.common.prospective_profile(configuration['executionClass'])
    if configuration['executionClass'] in (*dispatch.common.ROUTE_EXECUTION_CLASSES, *dispatch.contract.EXECUTION_CLASSES):
        fixed = fixed / profile['experiment']
    raw_modes = _immutable(fixed / 'fixture-modes.private.json', 262144)
    _need(record['inputFiles']['fixture-modes.private.json'] == {'digest': _digest(raw_modes), 'size': len(raw_modes)})
    modes = _json(raw_modes)
    # The original root registration retains the immutable mode declaration; staged
    # byte inventory is independently compared to every frozen registered member.
    for name, value in record['inputFiles'].items():
        if name == 'fixture-modes.private.json': continue
        relative = Path(name).relative_to('fixture') if name.startswith('fixture/') else Path(name)
        path = fixed / relative
        raw = _read(path, value['size'], private=name.startswith('fixture/'))
        _need(value == {'digest': _digest(raw), 'size': len(raw)} and stat.S_IMODE(path.stat().st_mode) == modes[name])
    return selected


def verify_prepared_selection(plan, private, authorization):
    """Bind supervisor-selected JSON to root's own frozen selection, never requester copies."""
    _installed()
    request, record, _operation = _preparation_request()
    selected = _prepared_selection(request['configuration'], record)
    _need((ROOT / 'active.json').exists() or _stopped(_manager()))
    _need(selected == {'plan': plan, 'private': private, 'authorization': authorization})
    return True


def begin_owned():
    """Revalidate the prepared selection and start the fixed asynchronous acquisition unit."""
    identity = _installed()
    _verify_unit()
    context, record, operation = _boundary()
    _need(record['method'] in {'budget-acquisition-begin', 'supervisor-start'})
    configuration = _configuration(record)
    _root_directory()
    lock = os.open(ROOT / '.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _need(not (ROOT / 'active.json').exists()
              and not WORKLOAD.exists() and _stopped(_manager()))
        selected = _prepared_selection(configuration, record)
        _need(_digest(_encode(selected['plan'])) == configuration['planDigest'])
        activation = _activation(selected)
        _need(identity['sourceCommit'] == record['context']['sourceCommit'])
        import pr320_budget_contract as common
        maximum = 7200 if configuration['executionClass'] == common.PRIVACY_EXECUTION_CLASS else 3600
        _need(type(selected['authorization']['maxSeconds']) is int
              and 60 <= selected['authorization']['maxSeconds'] <= maximum)
        budget = selected['authorization']['maxSeconds'] + 600
        deadline = activation['deadlineMonotonicNs']
        import restricted_worker as worker
        _need(time.monotonic_ns() + budget * 10**9 <= deadline
              and (worker.utc(record['expiresAt']) - worker.now()).total_seconds() >= budget)
        acquisition = str(uuid.uuid4())
        directory = ROOT / acquisition
        directory.mkdir(mode=0o700)
        start = {'schemaVersion': 1, 'kind': 'pr320-root-original-acquisition-start',
            'acquisitionId': acquisition, 'operationId': context['operationId'],
            'registrationDigest': context['registrationDigest'], 'bundleIdentity': context['bundleIdentity'],
            'job': record['context'], 'sourceCommit': identity['sourceCommit'],
            'activationDigest': _digest(_encode(activation)), 'planDigest': configuration['planDigest'],
            'configurationDigest': _digest(_encode(configuration)), 'selectionDigest': _digest(_encode(selected)),
            'helperIdentities': selected['authorization']['budgetSelection']['toolIdentities'],
            'productsDigest': _digest(_encode(selected['plan']['nodes'])),
            'bootId': _boot(), 'startedMonotonicNs': time.monotonic_ns(),
            'deadlineMonotonicNs': deadline, 'executionClass': configuration['executionClass']}
        raw = _encode(start)
        _write(directory / 'start.json', raw)
        _write(ROOT / 'active.json', _encode({'acquisitionId': acquisition, 'startDigest': _digest(raw)}))
        _manager('start')
        return {'status': 'started', 'acquisitionId': acquisition}
    finally:
        os.close(lock)


def _revalidate(start, selected, *, terminal=None):
    import restricted_worker as worker
    _need(start['bootId'] == _boot() and start['selectionDigest'] == _digest(_encode(selected))
          and start['planDigest'] == _digest(_encode(selected['plan']))
          and start['productsDigest'] == _digest(_encode(selected['plan']['nodes']))
          and start['helperIdentities'] == selected['authorization']['budgetSelection']['toolIdentities'])
    if terminal is None: _need(time.monotonic_ns() < start['deadlineMonotonicNs'])
    operation = worker.OPERATIONS / start['operationId']
    raw = worker.read(operation / 'registration.json')
    record = worker.validate_record(worker.decode(raw, worker.MAX_RECORD))
    _need(_digest(raw) == start['registrationDigest'] and record['context'] == start['job']
          and record['bundleIdentity'] == start['bundleIdentity'])
    worker.require_not_revoked(operation, record)
    worker.check_inputs(record, operation)
    config = _configuration(record)
    _need(_digest(_encode(config)) == start['configurationDigest'])
    import pr320_storage_selection
    profile = importlib.import_module('pr320_budget_contract').prospective_profile(start['executionClass'])
    source = InstalledFixtureSource(_SEAL, _installed(), Path('/root/cryptad/build') / profile['experiment'] / 'verifier', config['verifierDigest'])
    _need(pr320_storage_selection.tool_identities(CHECKOUT, profile['toolPaths'], installed_source=source)
          == start['helperIdentities'])
    _need(_digest(_encode(_activation(selected, terminal=terminal))) == start['activationDigest'])


def _clock():
    """Actual common-kernel UTC samples; names retain the owning clock oracle shape."""
    before_mono, before_wall = time.monotonic_ns(), time.time_ns()
    role_wall = time.time_ns()
    after_wall, after_mono = time.time_ns(), time.monotonic_ns()
    return {'hostEpochBeforeNanos': before_wall, 'hostMonotonicBeforeNanos': before_mono,
            'guestEpochNanos': role_wall, 'hostMonotonicAfterNanos': after_mono,
            'hostEpochAfterNanos': after_wall}


def _run_child(service_pid):
    """Execute the kit in the fixed unit's verified, newly forked root child."""
    _installed()
    _verify_unit()
    directory, start = _active()
    selected = _json(_read(SELECTION, 262144))
    _revalidate(start, selected)
    request, _record, _operation = _preparation_request()
    _prepared_selection(request['configuration'], _record, staged=True)
    _need(_immutable(DRIVER_SELECTION, 262144) == _immutable(SELECTION, 262144))
    manager = _manager()
    _need(manager['MainPID'] == str(service_pid) and os.getppid() == service_pid and manager['ControlGroup'] ==
          '/system.slice/' + BUDGET_UNIT and re.fullmatch('[0-9a-f]{32}', manager['InvocationID']))
    _need(Path('/proc/self/cgroup').read_text().strip() == '0::' + manager['ControlGroup'])
    own_mount, manager_mount = Path('/proc/self/ns/mnt').stat(), Path('/proc/1/ns/mnt').stat()
    _need((own_mount.st_dev, own_mount.st_ino) == (manager_mount.st_dev, manager_mount.st_ino))
    _need(not (directory / 'running.json').exists())
    _write(directory / 'running.json', _encode({'invocationId': manager['InvocationID'],
        'pid': os.getpid(), 'supervisorPid': service_pid, 'startTicks': _process_start(os.getpid()),
        'bootId': _boot(), 'startedMonotonicNs': time.monotonic_ns()}))
    # The driver authenticates its separate installed kit and native closure again.
    driver = _kit_driver(start['sourceCommit'])
    before = _clock()
    def interrupted(_signum, _frame):
        raise AcquisitionError('pr320-root-original-acquisition-interrupted')
    previous = {number: signal.signal(number, interrupted)
                for number in (signal.SIGTERM, signal.SIGINT)}
    try:
        driver.execute(lifecycle_scenario='none', execution_class=start['executionClass'])
        after = _clock()
        _revalidate(start, selected)
        from pr320_campaign_capture import decode_root_capsule, _read_owned, FILE
        root_raw = _read_owned(WORKLOAD / 'authority' / FILE, MAX_CAPTURE, 0)
        capsule = decode_root_capsule(root_raw)
        _need(capsule['originals']['selected'] == selected and capsule['planDigest'] == start['planDigest'])
        observation = _read_owned(driver.REPORT, 262144, 0)
        _need(_json(observation).get('cleanupState') == 'completed')
        originals = capsule['originals']
        _need(originals['diagnostics'].get('cleanup') == 'completed')
        from pr316_mail_runtime_runner import _terminal_cleanup_verified
        _need(_terminal_cleanup_verified(originals['terminal']))
        actor = Path(selected['private']['root'])
        uid = pwd.getpwnam('cryptad-soak').pw_uid
        journal = _read_owned(actor / 'journal.jsonl', MAX_JOURNAL, uid)
        checkpoint = _read_owned(actor / 'checkpoint.json', 65536, uid)
        _verify_journal(selected['plan'], journal, checkpoint)
        report = {'schemaVersion': 1, 'kind': 'pr320-root-native-original-report',
            'clockDomain': 'protected-host-and-role-common-kernel-utc', 'bootId': _boot(),
            'unit': BUDGET_UNIT, 'invocationId': manager['InvocationID'],
            'storageClock': {'before': before, 'after': after},
            'planDigest': start['planDigest'], 'activationDigest': start['activationDigest'],
            'observationDigest': _digest(observation), 'checkpointDigest': _digest(checkpoint),
            'roleCleanup': 'completed', 'roleKernelEpochs': {
                role: {key: originals['terminal']['controllerRecords'][role]['record'][key]
                       for key in ('bootId', 'generation', 'managerInvocation', 'roleEpochDigest')}
                for role in ('candidate-sender', 'candidate-recipient', 'previous', 'relay-no-apps')}}
        for name, raw in (('root-capture.json', root_raw), ('observation.json', observation),
                          ('journal.jsonl', journal), ('checkpoint.json', checkpoint),
                          ('native-report.json', _encode(report))):
            _write(directory / name, raw)
        complete = {'schemaVersion': 1, 'kind': 'pr320-root-original-acquisition-complete',
            'startDigest': _digest(_read(directory / 'start.json', 1024 * 1024)),
            'bootId': _boot(), 'finishedMonotonicNs': time.monotonic_ns(),
            'invocationId': manager['InvocationID'], 'files': {name: {'digest': _digest(raw), 'size': len(raw)}
                for name, raw in (('root-capture.json', root_raw), ('observation.json', observation),
                    ('journal.jsonl', journal), ('checkpoint.json', checkpoint), ('native-report.json', _encode(report)))}}
        _need(sum(row['size'] for row in complete['files'].values()) <= MAX_TOTAL)
        _write(directory / 'complete.json', _encode(complete))
    except BaseException:
        if not (directory / 'failed.json').exists():
            _write(directory / 'failed.json', _encode({'schemaVersion': 1,
                'kind': 'pr320-root-original-acquisition-failed', 'bootId': _boot(),
                'finishedMonotonicNs': time.monotonic_ns(), 'reconciliationRequired': True}))
        raise
    finally:
        for number, handler in previous.items(): signal.signal(number, handler)


def _process_start(pid):
    raw = Path('/proc/' + str(pid) + '/stat').read_text()
    fields = raw[raw.rfind(')') + 2:].split()
    ticks = int(fields[19])
    _need(ticks > 0)
    return ticks


def _stop_fixed_roles():
    arguments = ['/usr/bin/systemctl', 'stop', 'cryptad-workload-controller.service',
        *('cryptad-workload@' + role + '.service' for role in
          ('candidate-sender', 'candidate-recipient', 'previous', 'relay-no-apps'))]
    result = subprocess.run(arguments, capture_output=True, timeout=120, env=ENV)
    _need(result.returncode == 0)


def _run_preparation_child(service_pid):
    identity = _installed()
    _verify_unit()
    manager = _manager()
    _need(manager['MainPID'] == str(service_pid) and os.getppid() == service_pid
          and manager['ControlGroup'] == '/system.slice/' + BUDGET_UNIT
          and re.fullmatch('[0-9a-f]{32}', manager['InvocationID']) is not None
          and Path('/proc/self/cgroup').read_text().strip() == '0::' + manager['ControlGroup'])
    own_mount, manager_mount = Path('/proc/self/ns/mnt').stat(), Path('/proc/1/ns/mnt').stat()
    _need((own_mount.st_dev, own_mount.st_ino) == (manager_mount.st_dev, manager_mount.st_ino))
    request, record, operation = _preparation_request()
    import restricted_worker as worker
    _need(time.monotonic_ns() < request['deadlineMonotonicNs'] and not SELECTION.exists()
          and not DRIVER_SELECTION.exists() and not WORKLOAD.exists()
          and not (ROOT / 'prepared.json').exists()
          and identity['sourceCommit'] == request['sourceCommit']
          and identity['bundleIdentity'] == request['bundleIdentity']
          and worker.now() < worker.utc(record['expiresAt']))
    _kit_driver(identity['sourceCommit'])
    selected = _fixture_factory(request['configuration'], record, operation)
    _need(_digest(_encode(selected['plan'])) == request['configuration']['planDigest'])
    _preparation_request()
    _write(SELECTION, _encode(selected))
    _write(DRIVER_SELECTION, _encode(selected))
    _state_selection(selected)
    _need(time.monotonic_ns() < request['deadlineMonotonicNs'] and worker.now() < worker.utc(record['expiresAt']))
    _write(ROOT / 'prepared.json', _encode({'schemaVersion': 1,
        'kind': 'pr320-root-original-acquisition-prepared', 'preparationId': request['preparationId'],
        'job': request['job'], 'sourceCommit': identity['sourceCommit'],
        'bundleIdentity': identity['bundleIdentity'], 'configuration': request['configuration'],
        'inputFiles': record['inputFiles'], 'selectionDigest': _digest(_encode(selected)),
        'requestDigest': _digest(_immutable(ROOT / 'prepare-request.json', 1024 * 1024)),
        'preparedMonotonicNs': time.monotonic_ns(), 'invocationId': manager['InvocationID']}))


def run_service():
    """Poll one fixed root child without interfering with the kit's own SIGALRM timers."""
    _installed()
    _verify_unit()
    preparation = not (ROOT / 'active.json').exists()
    if preparation:
        start, _record, _operation = _preparation_request()
        directory, completion_file, failure_file = ROOT, 'prepared.json', 'preparation-failed.json'
    else:
        directory, start = _active()
        completion_file, failure_file = 'complete.json', 'failed.json'
    manager = _manager()
    _need(manager['MainPID'] == str(os.getpid())
          and manager['ControlGroup'] == '/system.slice/' + BUDGET_UNIT
          and (preparation or not (directory / 'running.json').exists())
          and not (directory / completion_file).exists() and not (directory / failure_file).exists())
    service_pid = os.getpid()
    child = os.fork()
    if child == 0:
        try:
            _run_preparation_child(service_pid) if preparation else _run_child(service_pid)
        except BaseException:
            os._exit(1)
        os._exit(0)
    interrupted = [False]
    def terminate(_signum, _frame): interrupted[0] = True
    previous = {number: signal.signal(number, terminate) for number in (signal.SIGTERM, signal.SIGINT)}
    status, stopped = None, False
    try:
        while time.monotonic_ns() < start['deadlineMonotonicNs'] and not interrupted[0]:
            observed, status = os.waitpid(child, os.WNOHANG)
            if observed == child:
                stopped = True
                break
            time.sleep(0.25)
        if not stopped:
            os.kill(child, signal.SIGTERM)
            cleanup_deadline = time.monotonic() + 180
            while time.monotonic() < cleanup_deadline:
                observed, status = os.waitpid(child, os.WNOHANG)
                if observed == child:
                    stopped = True
                    break
                time.sleep(0.25)
        if not stopped:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
            stopped = True
        _need(not interrupted[0] and status is not None and os.waitstatus_to_exitcode(status) == 0
              and (directory / completion_file).exists() and not (directory / failure_file).exists())
    except BaseException:
        if not stopped:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
        # The fallback addresses only these task-owned role/controller units. A failure
        # never creates acquisition completion or deletes the retained workload mounts.
        try:
            if not preparation: _stop_fixed_roles()
        finally:
            if not (directory / failure_file).exists():
                _write(directory / failure_file, _encode({'schemaVersion': 1,
                    'kind': 'pr320-root-original-acquisition-failed', 'bootId': _boot(),
                    'finishedMonotonicNs': time.monotonic_ns(), 'reconciliationRequired': True}))
        raise
    finally:
        for number, handler in previous.items(): signal.signal(number, handler)


def _verify_journal(plan, raw, checkpoint_raw):
    from cryptad_certification import cross_version_evidence as evidence
    events, checkpoint = [_json(row) for row in raw.splitlines()], _json(checkpoint_raw)
    _need(0 < len(events) <= plan['policy']['maxEvents'] and checkpoint['status'] in {'partial', 'complete'})
    assessment = evidence.verify(plan, events, checkpoint)
    invalid = {'journal-lineage-invalid', 'checkpoint-substitution-or-truncation',
        'continuation-lineage-invalid', 'operation-replayed', 'journal-wall-clock-invalid',
        'clock-discontinuity', 'runtime-epoch-mismatch', 'peer-runtime-epoch-mismatch',
        'operation-on-stopped-node', 'observed-failure'}
    _need(not invalid.intersection(assessment['findings']))
    return events, checkpoint


def collect_owned():
    """Return only an opaque handle and current state under a fresh registered call."""
    _installed()
    _verify_unit()
    _context, record, _operation = _boundary()
    _need(record['method'] == 'budget-acquisition-collect')
    if not (ROOT / 'active.json').exists():
        request, _original_record, _operation = _preparation_request()
        _need(_configuration(record) == request['configuration']
              and record['inputFiles'] == request['inputFiles']
              and record['context']['sourceCommit'] == request['sourceCommit']
              and record['bundleIdentity'] == request['bundleIdentity'])
        manager = _manager()
        status = ('failed' if ((ROOT / 'preparation-failed.json').exists() or manager['ActiveState'] == 'failed'
                              or manager['ActiveState'] == 'inactive' and manager['Result'] != 'success')
                  else 'prepared' if (ROOT / 'prepared.json').exists() and _stopped(manager) else 'running')
        return {'status': status, 'acquisitionId': request['preparationId']}
    directory, start = _active()
    request, _original_record, _operation = _preparation_request()
    configuration = _configuration(record)
    _need(record['context']['sourceCommit'] == start['sourceCommit']
          and record['bundleIdentity'] == start['bundleIdentity']
          and _digest(_encode(configuration)) == start['configurationDigest']
          and record['inputFiles'] == request['inputFiles'])
    manager = _manager()
    status = 'failed' if ((directory / 'failed.json').exists() or manager['ActiveState'] == 'failed'
        or manager['ActiveState'] == 'inactive' and manager['Result'] != 'success') else (
        'complete' if (directory / 'complete.json').exists() and
        manager['ActiveState'] == 'inactive' else 'running')
    return {'status': status, 'acquisitionId': start['acquisitionId']}


class OwnedAcquisitionCapture:
    """Sealed root custody; private bytes are usable only with real terminal authority."""
    __slots__ = ('_raw', '_activation', '_plan', '_start')

    def __init__(self, seal, raw, activation, plan, start):
        _need(seal is _SEAL and os.geteuid() == 0)
        object.__setattr__(self, '_raw', tuple(sorted(raw.items())))
        object.__setattr__(self, '_activation', activation)
        object.__setattr__(self, '_plan', plan)
        object.__setattr__(self, '_start', _encode(start))

    def __setattr__(self, _name, _value):
        raise AcquisitionError('pr320-root-original-acquisition-frozen')

    def members(self, activation, plan, terminal):
        from cross_version_supervisor_authority import TerminalEvidence
        _need(os.geteuid() == 0 and isinstance(terminal, TerminalEvidence)
              and _digest(_encode(activation)) == self._activation
              and _digest(_encode(plan)) == self._plan)
        terminal.require(activation)
        start, raws = _json(self._start), dict(self._raw)
        _need(start['bootId'] == _boot() and _stopped(_manager()))
        from pr320_campaign_capture import decode_root_capsule, OWNERS
        capsule = decode_root_capsule(raws['root-capture.json'])
        _revalidate(start, capsule['originals']['selected'], terminal=terminal)
        originals = {**capsule['originals'], 'report': _json(raws['native-report.json'])}
        private_raw = base64.b64decode(originals['private'], validate=True)
        owner = importlib.import_module(originals['owner'])
        private = owner.decode_private(private_raw)
        kind = OWNERS[originals['owner']]
        if kind == 'installed-privacy':
            member_raws = {'installed-privacy': private_raw,
                    'installed-browser-privacy': base64.b64decode(originals['browser'], validate=True),
                    'artifact-privacy': base64.b64decode(originals['artifact'], validate=True)}
        else:
            component = private['component'] if kind == 'route-component' else (
                private['storageComponent'] if kind == 'storage-component' else private['composedBudgetEvidence'])
            member_raws = {kind: _encode(component)}
        events, _checkpoint = _verify_journal(plan, raws['journal.jsonl'], raws['checkpoint.json'])
        from composed_budget_campaign_admission import verify_original_member
        from cryptad_certification.composed_budget_journal_member import validate_reference
        members = []
        for event in events:
            if 'composedBudgetCampaignMember' not in event: continue
            descriptor = validate_reference(plan, event)
            reference = event['composedBudgetCampaignMember']
            raw = member_raws.get(descriptor['kind'])
            # Artifact exports have a separate owning reader; never invent their originals.
            if raw is None: continue
            _need(_digest(raw) == reference['digest'] and len(raw) == reference['size'])
            verify_original_member(descriptor['kind'], raw, originals)
            members.append({'member': descriptor['member'], 'kind': descriptor['kind'],
                            'raw': raw, 'originals': originals})
        _need(members and len({row['member'] for row in members}) == len(members))
        return members


def _stopped(manager):
    return (manager['ActiveState'] == 'inactive' and manager['MainPID'] == '0'
            and manager['ControlGroup'] in {'', '/system.slice/' + BUDGET_UNIT}
            and manager['Result'] == 'success' and manager['ExecMainStatus'] == '0'
            and manager['ExecMainCode'] == '1')


def _validate_completed_raws(raws, start, complete):
    """Bind the typed kernel report and actual root capture to the frozen service run."""
    from pr320_campaign_capture import decode_root_capsule
    from pr316_mail_runtime_runner import _terminal_cleanup_verified
    from pr318_storage_runtime_runner import _clock_sample
    capsule = decode_root_capsule(raws['root-capture.json'])
    originals = capsule['originals']
    selected = originals['selected']
    _need(_terminal_cleanup_verified(originals['terminal'])
          and originals['diagnostics'].get('cleanup') == 'completed')
    observation, report = _json(raws['observation.json']), _json(raws['native-report.json'])
    _need(observation.get('executionClass') == start['executionClass']
          and observation.get('selectionDigest') == selected['authorization']['selectionDigest']
          and observation.get('privateEvidenceDigest') == _digest(base64.b64decode(originals['private'], validate=True))
          and observation.get('cleanupState') == 'completed'
          and observation.get('identity', {}).get('sourceCommit') == start['sourceCommit']
          and observation.get('identity', {}).get('bundleIdentity') == start['bundleIdentity'])
    _need(isinstance(report, dict) and set(report) == {'schemaVersion', 'kind', 'clockDomain',
        'bootId', 'unit', 'invocationId', 'storageClock', 'planDigest', 'activationDigest',
        'observationDigest', 'checkpointDigest', 'roleCleanup', 'roleKernelEpochs'}
        and type(report['schemaVersion']) is int and report['schemaVersion'] == 1
        and report['kind'] == 'pr320-root-native-original-report'
        and report['clockDomain'] == 'protected-host-and-role-common-kernel-utc'
        and report['bootId'] == start['bootId'] == _boot()
        and report['unit'] == BUDGET_UNIT and report['invocationId'] == complete['invocationId']
        and report['planDigest'] == start['planDigest']
        and report['activationDigest'] == start['activationDigest']
        and report['observationDigest'] == _digest(raws['observation.json'])
        and report['checkpointDigest'] == _digest(raws['checkpoint.json'])
        and report['roleCleanup'] == 'completed'
        and isinstance(report['storageClock'], dict) and set(report['storageClock']) == {'before', 'after'})
    before, after = (_clock_sample(report['storageClock'][name]) for name in ('before', 'after'))
    _need(start['startedMonotonicNs'] <= before['hostMonotonicBeforeNanos']
          <= before['hostMonotonicAfterNanos'] < after['hostMonotonicBeforeNanos']
          <= after['hostMonotonicAfterNanos'] <= complete['finishedMonotonicNs'])
    expected = {role: {key: originals['terminal']['controllerRecords'][role]['record'][key]
                for key in ('bootId', 'generation', 'managerInvocation', 'roleEpochDigest')}
                for role in ('candidate-sender', 'candidate-recipient', 'previous', 'relay-no-apps')}
    _need(report['roleKernelEpochs'] == expected and all(row['bootId'] == start['bootId'] for row in expected.values()))
    if originals['owner'] == 'pr320_privacy_runtime_evidence':
        owner = importlib.import_module(originals['owner'])
        privacy_originals = owner.decode_originals(base64.b64decode(originals['privacyOriginals'], validate=True))
        component = owner.decode_private(base64.b64decode(originals['private'], validate=True))['component']
        _privacy_clock_binding(privacy_originals, before, after, component=component)
    return capsule


def _privacy_clock_binding(originals, before, after, *, component=None):
    """Every independent privacy observation belongs to this real kernel acquisition."""
    mono_start, mono_end = before['hostMonotonicAfterNanos'], after['hostMonotonicBeforeNanos']
    wall_start, wall_end = before['hostEpochAfterNanos'], after['hostEpochBeforeNanos']
    def monotonic(value):
        _need(type(value) is int and mono_start <= value <= mono_end)
    def epoch(value):
        _need(type(value) is int and wall_start <= value <= wall_end)
    _need(mono_start < mono_end and wall_start < wall_end)
    for receipt in originals['receipts']:
        if receipt['kind'] == 'pr320-original-privacy-readback':
            monotonic(receipt['capturedMonotonicNs'])
            monotonic(receipt['observedMonotonicNs'])
            for row in receipt['boundaryEvidence'].values():
                monotonic(row['observedMonotonicNs'])
                epoch(row['observedEpochNs'])
        elif receipt['kind'] == 'pr320-original-browser-observation':
            monotonic(receipt['startedMonotonicNs'])
            monotonic(receipt['finishedMonotonicNs'])
            _need(receipt['startedMonotonicNs'] <= receipt['finishedMonotonicNs'])
            if 'capturedMonotonicNs' in receipt: monotonic(receipt['capturedMonotonicNs'])
        else:
            _need(False)
    if component is not None:
        events = component['surfaces']['workSnapshot']['events']
        _need(isinstance(events, list) and events)
        for row in events:
            stamp = row['observedAt']
            _need(isinstance(stamp, str))
            match = re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(?:Z|\+00:00)', stamp)
            _need(match is not None)
            parsed = dt.datetime.fromisoformat(match[1] + '+00:00')
            nanos = calendar.timegm(parsed.utctimetuple()) * 10**9 + int((match[2] or '').ljust(9, '0'))
            epoch(nanos)


def completed_owned(activation, plan, *, terminal):
    """Independently read stopped service originals; caller copies cannot mint custody."""
    _installed()
    _verify_unit()
    from cross_version_supervisor_authority import TerminalEvidence
    _need(isinstance(terminal, TerminalEvidence))
    terminal.require(activation)
    directory, start = _active()
    _need(not (directory / 'failed.json').exists() and _stopped(_manager())
          and start['activationDigest'] == _digest(_encode(activation))
          and start['planDigest'] == _digest(_encode(plan)))
    complete = _json(_immutable(directory / 'complete.json', 65536))
    running = _json(_immutable(directory / 'running.json', 65536))
    _need(set(complete) == {'schemaVersion', 'kind', 'startDigest', 'bootId',
          'finishedMonotonicNs', 'invocationId', 'files'}
          and type(complete['schemaVersion']) is int and complete['schemaVersion'] == 1
          and complete['kind'] == 'pr320-root-original-acquisition-complete'
          and complete['startDigest'] == _digest(_read(directory / 'start.json', 1024 * 1024))
          and complete['bootId'] == _boot() == running['bootId']
          and complete['invocationId'] == running['invocationId']
          and type(running['pid']) is int and running['pid'] > 0
          and type(running['supervisorPid']) is int and running['supervisorPid'] > 0
          and running['pid'] != running['supervisorPid']
          and type(running['startTicks']) is int and running['startTicks'] > 0
          and running['startedMonotonicNs'] <= complete['finishedMonotonicNs'] <= start['deadlineMonotonicNs']
          and set(complete['files']) == {'root-capture.json', 'observation.json', 'journal.jsonl',
                                       'checkpoint.json', 'native-report.json'})
    limits = {'root-capture.json': MAX_CAPTURE, 'observation.json': 262144,
              'journal.jsonl': MAX_JOURNAL, 'checkpoint.json': 65536, 'native-report.json': 65536}
    raws = {name: _immutable(directory / name, limits[name]) for name in limits}
    _need(sum(len(raw) for raw in raws.values()) <= MAX_TOTAL
          and all(complete['files'][name] == {'digest': _digest(raw), 'size': len(raw)} for name, raw in raws.items()))
    capsule = _validate_completed_raws(raws, start, complete)
    selected = capsule['originals']['selected']
    _need(selected['plan'] == plan and capsule['planDigest'] == start['planDigest'])
    _revalidate(start, selected, terminal=terminal)
    _verify_journal(plan, raws['journal.jsonl'], raws['checkpoint.json'])
    cap = OwnedAcquisitionCapture(_SEAL, raws, start['activationDigest'], start['planDigest'], start)
    cap.members(activation, plan, terminal)
    return cap


if __name__ == '__main__':
    try:
        _need(len(sys.argv) == 1)
        run_service()
    except BaseException:
        raise SystemExit(1) from None

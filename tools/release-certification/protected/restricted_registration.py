#!/usr/bin/python3
"""Explicit administrator registration of fixed restricted operations.

This installed CLI is never exposed on the worker socket and never accepts runner authority.
Input paths belong exclusively to the out-of-band administrator. Registration pins claims;
the worker still authenticates the original job, artifacts and human decisions at execution.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
try:
    import fcntl
    import pwd
except ImportError:
    fcntl = pwd = None
import re
import secrets
import shutil
import stat
import sys

CHECKOUT = Path('/opt/cryptad-cross-version/current')
APPROVAL = Path('/etc/cryptad-certification/restricted-installation.json')
OPERATIONS = Path('/var/lib/cryptad-restricted/operations')
RESERVATIONS = Path('/var/lib/cryptad-restricted/reservations')
MAX_HANDLES = 1024


class RegistrationError(ValueError):
    """Closed administrator diagnostic without private payload contents."""


def trusted(path, *, private=False):
    for entry in (path, *path.parents):
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RegistrationError('restricted-registration-root-trust-required')
    if private and path.stat().st_mode & 0o077:
        raise RegistrationError('restricted-registration-private-input-required')
    return path


def installed_verifier():
    """Authenticate the verifier before importing any sensitive owner module."""
    if (pwd is None or fcntl is None or os.geteuid() != 0 or not sys.flags.isolated or not sys.flags.no_site
            or Path(__file__).resolve() != CHECKOUT / 'tools/release-certification/protected/restricted_registration.py'):
        raise RegistrationError('restricted-registration-installed-root-cli-required')
    approval = json.loads(trusted(APPROVAL, private=True).read_bytes())
    raw = trusted(CHECKOUT / '.restricted-manifest.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != approval['bundleIdentity']:
        raise RegistrationError('restricted-registration-bundle-mismatch')
    manifest = json.loads(raw)
    relative = 'tools/release-certification/restricted/installation.py'
    path = trusted(CHECKOUT / relative)
    if hashlib.sha256(path.read_bytes()).hexdigest() != manifest['files'][relative]['sha256']:
        raise RegistrationError('restricted-registration-verifier-mismatch')
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location('restricted_installation', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, module.verify()


def copy_file(source, destination, *, maximum):
    """Snapshot one root-owned regular input without aliases or race substitution."""
    trusted(source)
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size > maximum or before.st_uid != 0 or before.st_mode & 0o022):
            raise RegistrationError('restricted-registration-input-invalid')
        result = hashlib.sha256()
        count = 0
        output = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(output, 'wb') as stream:
            while block := os.read(descriptor, 1024 * 1024):
                count += len(block)
                if count > maximum:
                    raise RegistrationError('restricted-registration-input-limit')
                stream.write(block)
                result.update(block)
            stream.flush()
            os.fsync(stream.fileno())
        after, current = os.fstat(descriptor), source.lstat()
        fields = ('st_dev', 'st_ino', 'st_nlink', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if count != before.st_size or any(getattr(before, field) != getattr(after, field)
                or getattr(before, field) != getattr(current, field) for field in fields):
            raise RegistrationError('restricted-registration-input-changed')
        return {'digest': 'sha256:' + result.hexdigest(), 'size': count}
    finally:
        os.close(descriptor)


def snapshot(source, target):
    trusted(source)
    if not source.is_dir():
        raise RegistrationError('restricted-registration-input-directory-required')
    target.mkdir(mode=0o700)
    records, total, directory_count = {}, 0, 0
    for directory, directories, files in os.walk(source, followlinks=False):
        directory = Path(directory)
        trusted(directory)
        relative = directory.relative_to(source)
        directory_count += 1
        if len(relative.parts) > 32 or directory_count > 2048:
            raise RegistrationError('restricted-registration-depth-limit')
        for name in directories:
            trusted(directory / name)
            (target / relative / name).mkdir(mode=0o700)
        for name in sorted(files):
            if len(records) >= 1024:
                raise RegistrationError('restricted-registration-file-limit')
            key = (relative / name).as_posix()
            row = copy_file(directory / name, target / key, maximum=min(1024**3, 2 * 1024**3 - total))
            records[key] = row
            total += row['size']
    # Directory metadata must be durable as well as individual input bytes.
    for directory, _, _ in os.walk(target, topdown=False):
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return records


@contextmanager
def registration_lock():
    trusted(OPERATIONS, private=True)
    trusted(RESERVATIONS, private=True)
    descriptor = os.open(OPERATIONS.parent / 'registration.lock',
                         os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def handle_inventory():
    handles = set()
    for root in OPERATIONS.iterdir():
        if re.fullmatch('[0-9a-f]{64}', root.name):
            handles.add(root.name)
    for path in RESERVATIONS.iterdir():
        if re.fullmatch('[0-9a-f]{64}\\.json', path.name):
            handles.add(path.stem)
    return handles


def reserve(method):
    _installation, identity = installed_verifier()
    sys.path.insert(0, str(CHECKOUT / 'tools/release-certification/protected'))
    import restricted_worker as worker
    if method not in worker.METHODS:
        raise RegistrationError('restricted-registration-method-invalid')
    with registration_lock():
        if len(handle_inventory()) >= MAX_HANDLES:
            raise RegistrationError('restricted-registration-history-limit')
        handle = secrets.token_hex(32)
        worker.persist(RESERVATIONS / (handle + '.json'), {
            'schemaVersion': 1, 'handle': handle, 'method': method,
            'bundleIdentity': identity['bundleIdentity'], 'reservedAt': worker.now().isoformat()})
    return {'handle': handle, 'method': method, 'status': 'reserved-not-registered'}


def register(context_path, input_root, handle=None):
    installation, identity = installed_verifier()
    # Only after full immutable source/dependency/profile verification may owner code import.
    sys.path.insert(0, str(CHECKOUT / 'tools/release-certification/protected'))
    import restricted_worker as worker
    from restricted_protocol import decode, encode
    config = decode(worker.read(context_path), worker.MAX_RECORD)
    expected = {'method', 'context', 'notBefore', 'expiresAt', 'collectUntil', 'configurationFiles'}
    if (not isinstance(config, dict) or set(config) != expected
            or not isinstance(config['configurationFiles'], list)
            or len(config['configurationFiles']) > 1024
            or len(set(config['configurationFiles'])) != len(config['configurationFiles'])):
        raise RegistrationError('restricted-registration-context-invalid')
    from restricted_configuration import require_roster
    require_roster(config['method'], config['configurationFiles'], worker.read)
    caller = pwd.getpwnam('cryptad-runner').pw_uid
    reserved = handle is not None
    if reserved and re.fullmatch('[0-9a-f]{64}', handle) is None:
        raise RegistrationError('restricted-registration-handle-invalid')
    handle = handle or secrets.token_hex(32)
    record = {'schemaVersion': 1, 'method': config['method'], 'handle': handle,
              'bundleIdentity': identity['bundleIdentity'], 'callerUid': caller,
              'context': config['context'], 'notBefore': config['notBefore'],
              'expiresAt': config['expiresAt'], 'collectUntil': config['collectUntil'],
              'inputFiles': {}, 'configurationFiles': {}}
    for name in config['configurationFiles']:
        path = Path(name)
        if (not path.is_absolute() or '..' in path.parts
                or not path.is_relative_to('/etc/cryptad-certification')
                or path == worker.CREDENTIAL):
            raise RegistrationError('restricted-registration-configuration-path-invalid')
        raw = worker.read(path, 16 * 1024 * 1024)
        record['configurationFiles'][name] = {'digest': worker.digest(raw), 'size': len(raw)}
    worker.validate_record(record)
    with registration_lock():
        if reserved:
            reservation = decode(worker.read(RESERVATIONS / (handle + '.json')), worker.MAX_RECORD)
            if (set(reservation) != {'schemaVersion', 'handle', 'method', 'bundleIdentity', 'reservedAt'}
                    or reservation['schemaVersion'] != 1 or reservation['handle'] != handle
                    or reservation['method'] != record['method']
                    or reservation['bundleIdentity'] != identity['bundleIdentity']):
                raise RegistrationError('restricted-registration-reservation-mismatch')
        elif len(handle_inventory()) >= MAX_HANDLES:
            raise RegistrationError('restricted-registration-history-limit')
        if (OPERATIONS / handle).exists():
            raise RegistrationError('restricted-registration-already-bound')
        stage = OPERATIONS / ('.registration-' + handle)
        stage.mkdir(mode=0o700)
        try:
            record['inputFiles'] = snapshot(input_root, stage / 'inputs')
            worker.validate_record(record)
            if len(encode(record)) > worker.MAX_RECORD:
                raise RegistrationError('restricted-registration-record-limit')
            worker.check_inputs(record, stage)
            worker.persist(stage / 'registration.json', record)
            # The root-owned handle directory appears only after all snapshot bytes are durable.
            os.rename(stage, OPERATIONS / handle)
            descriptor = os.open(OPERATIONS, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except BaseException:
            # Only this unexposed, never-executed staging tree is removed. Existing operations,
            # interrupted intents and security history are never touched by registration cleanup.
            if stage.exists():
                shutil.rmtree(stage)
            raise
    return {'handle': handle, 'method': record['method'], 'status': 'registered-not-executed'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reserve', metavar='METHOD')
    parser.add_argument('--handle')
    parser.add_argument('--context', type=Path)
    parser.add_argument('--inputs', type=Path)
    args = parser.parse_args()
    try:
        if args.reserve is not None:
            if args.handle is not None or args.context is not None or args.inputs is not None:
                raise RegistrationError('restricted-registration-arguments-invalid')
            result = reserve(args.reserve)
        else:
            if args.context is None or args.inputs is None:
                raise RegistrationError('restricted-registration-arguments-invalid')
            result = register(args.context.absolute(), args.inputs.absolute(), args.handle)
        print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    except (ValueError, OSError, KeyError, TypeError, RuntimeError):
        raise SystemExit('restricted-registration-rejected') from None


if __name__ == '__main__':
    main()

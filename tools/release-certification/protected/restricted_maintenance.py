"""Fixed installed maintenance owner operations over administrator-registered input snapshots.

The controller authenticates the original operation and pins its immutable bundle before invoking
this module. Input filenames are fixed; callers cannot provide paths, policy, tools or environment.
Result files remain private to the controller and are never admitted from runner-uploaded JSON.
"""
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import hashlib
import json
import os
import shutil
from pathlib import Path
import stat

from restricted_native import owning_boundary


class MaintenanceOperationError(ValueError):
    """Closed failure reason without supplied paths, values or native diagnostics."""


def _read(path, maximum=16 * 1024 * 1024):
    from maintenance_runtime_companion import _read as protected_read
    return protected_read(path, maximum, protected=True, key=True)


def _json(path):
    from maintenance_runtime_companion import _json as strict_json
    return strict_json(_read(path))


def _write(path, value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


@contextmanager
def _workspace(root):
    previous = Path.cwd()
    os.chdir(root)
    try:
        # Certification diagnostics remain within the owning context. Native dispatch separately
        # bounds its pipes and does not expose stdout or exceptions through the client protocol.
        with open(os.devnull, 'w') as sink, redirect_stdout(sink), redirect_stderr(sink):
            yield
    finally:
        os.chdir(previous)


def _package(root, freeze):
    package = root / 'inputs/package.tar.gz'
    _read(package, 1024 ** 3)
    # The owner capability includes the public product filename as well as digest/size. Retain
    # the fixed input filename at the boundary, then map the authenticated freeze's simple
    # public asset name privately so the normal engine's exact identity comparison still holds.
    products = [row for row in freeze['assets'] if row['role'] == 'product']
    if len(products) != 1:
        raise MaintenanceOperationError('restricted-maintenance-product-rejected')
    product = products[0]
    name = product['fileName']
    if (not isinstance(name, str) or not name or Path(name).name != name
            or name in ('.', '..') or '\\' in name):
        raise MaintenanceOperationError('restricted-maintenance-product-name-rejected')
    product_root = root / 'selected-product'
    product_root.mkdir(mode=0o700)
    selected_package = product_root / name
    with package.open('rb') as source, selected_package.open('xb') as target:
        shutil.copyfileobj(source, target, 1024 * 1024)
    selected_package.chmod(0o600)
    return selected_package


def _prepare(root):
    import maintenance_runtime_metadata as metadata
    from maintenance_runtime_companion import inspect
    inputs = root / 'inputs'
    freeze = _json(inputs / 'freeze.json')
    projection_origin = _json(inputs / 'projection-origin.json')
    package = _package(root, freeze)
    private = root / 'resolver'
    private.mkdir(mode=0o700, exist_ok=True)
    # The controller journals intent before calling us. Any interrupted preparation is incomplete
    # and requires controlled reconciliation; it must never call seal again under the same ID.
    if (root / 'runtime').exists() or (root / 'freeze.json').exists():
        raise MaintenanceOperationError('restricted-maintenance-reconciliation-required')
    sealed = metadata.seal_private_freeze(freeze, package, root / 'runtime',
        projection_origin=projection_origin, private_root=private)
    _write(root / 'freeze.json', sealed)
    descriptor = inspect(sealed, root / 'runtime')
    return {'schemaVersion': 1, 'kind': 'restricted-maintenance-result',
            'operation': 'maintenance-prepare', 'status': 'prepared',
            'freezeDigest': metadata.identity(root / 'freeze.json')['digest'],
            'descriptor': sealed['runtimeMetadata'], 'ciphertext': descriptor['ciphertext']}


def _validate(root):
    import maintenance_runtime_metadata as metadata
    from maintenance_runtime_validation import original_context, require_context
    from cryptad_certification.cli import main as certify
    from cryptad_certification.manifest import load_manifest
    from cryptad_certification.models import RunContext
    from cryptad_certification.engines import stable_1_0_maintenance_core as owner
    inputs = root / 'inputs'
    freeze_bytes = _read(inputs / 'freeze.json')
    freeze = _json(inputs / 'freeze.json')
    package = _package(root, freeze)
    manifest_path = inputs / 'manifest.json'
    _read(manifest_path)
    manifest = load_manifest(manifest_path, inputs)
    # All engine writes must stay in this operation's private owning root. Complete input
    # snapshot verification is controller-owned; candidate input cannot replace the manifest.
    output = manifest.output.root.absolute()
    if not output.is_relative_to(root) or output.is_relative_to(inputs):
        raise MaintenanceOperationError('restricted-maintenance-output-rejected')
    context = RunContext(inputs, manifest.output.root / manifest.release.release_id,
                         'stable-maintenance', manifest)
    loaded = owner.load_json_input(context, 'maintenanceCandidateFreeze')
    if loaded is None or metadata.semantic_digest(loaded.value) != metadata.semantic_digest(freeze):
        raise MaintenanceOperationError('restricted-maintenance-freeze-substituted')
    freeze_digest = 'sha256:' + hashlib.sha256(freeze_bytes).hexdigest()
    with original_context(freeze, package, freeze_digest=freeze_digest):
        require_context(freeze, inputs / 'runtime', package)
        with _workspace(inputs):
            status = certify(['stable-maintenance', '--manifest', str(manifest_path)])
        if status != 0:
            raise MaintenanceOperationError('restricted-maintenance-consumer-rejected')
    result = {'schemaVersion': 1, 'kind': 'restricted-maintenance-result',
              'operation': 'maintenance-validate', 'status': 'validated',
              'freezeDigest': freeze_digest}
    _write(root / 'maintenance-validation.json', result)
    return result


def dispatch(method, operation_root):
    """Invoke a fixed owner; the authenticated controller supplies the retained root."""
    root = Path(operation_root).absolute()
    try:
        if os.geteuid() != 0:
            raise MaintenanceOperationError('restricted-maintenance-owner-required')
        for path in (root, *root.parents):
            info = path.lstat()
            if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or info.st_uid != 0 or info.st_mode & 0o022):
                raise MaintenanceOperationError('restricted-maintenance-root-rejected')
        if root.stat().st_mode & 0o077:
            raise MaintenanceOperationError('restricted-maintenance-root-rejected')
        with owning_boundary():
            if method == 'maintenance-prepare':
                return _prepare(root)
            if method == 'maintenance-validate':
                return _validate(root)
            raise MaintenanceOperationError('restricted-maintenance-method-rejected')
    except (ValueError, OSError, KeyError, TypeError):
        raise MaintenanceOperationError('restricted-maintenance-operation-failed') from None

"""Explicit protected maintenance validation with a lifetime-bound original runtime context.

The ordinary offline engine only consults an already installed in-process capability. This
entry point is the separate owning network/key operation; it never publishes and never loads
the publication backend. Retained JSON cannot install the capability.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
import argparse
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import maintenance_runtime_metadata as metadata

SOURCE = Path('/etc/cryptad-certification/maintenance-runtime-source.json')
_ACTIVE = ContextVar('maintenance_runtime_original_context', default=None)
_SEAL = object()


class RuntimeValidationError(ValueError):
    """Private authority failures expose only fixed diagnostics."""


class _OriginalContext:
    def __init__(self, seal, freeze, package, row):
        if seal is not _SEAL:
            raise RuntimeValidationError('maintenance-runtime-original-context-required')
        original = row.get('_freeze')
        binding = row.get('sealedRuntimeBinding')
        if (not isinstance(original, dict) or original.get('schemaVersion') != 3
                or metadata.semantic_digest(freeze) != metadata.semantic_digest(original)
                or not isinstance(binding, dict)
                or binding.get('descriptor') != original.get('runtimeMetadata')
                or row.get('_runtimeContext') is None):
            raise RuntimeValidationError('maintenance-runtime-original-freeze-substituted')
        self.freeze = metadata.semantic_digest(original)
        self.sealed_binding = metadata.semantic_digest(binding)
        self.package = metadata.identity(package, 1024 ** 3)
        if (row.get('artifactDigest') != self.package['digest']
                or row.get('artifactSize') != self.package['sizeBytes']):
            raise RuntimeValidationError('maintenance-runtime-original-product-substituted')
        self.row = row
        self.active = True

    def check(self, freeze, package, sealed_binding):
        if (not self.active or self.freeze != metadata.semantic_digest(freeze)
                or self.sealed_binding != metadata.semantic_digest(sealed_binding)
                or self.package != metadata.identity(package, 1024 ** 3)
                or self.row.get('_runtimeContext') is None):
            raise RuntimeValidationError('maintenance-runtime-original-context-substituted')


def require_context(freeze, runtime_root, package):
    """Check outer bytes and an existing original capability, without I/O authority escalation."""
    from maintenance_runtime_companion import inspect
    descriptor = inspect(freeze, runtime_root)
    context = _ACTIVE.get()
    if not isinstance(context, _OriginalContext):
        raise RuntimeValidationError('maintenance-runtime-original-private-context-required')
    context.check(freeze, package, {'descriptor': freeze['runtimeMetadata'],
                                   'ciphertextDigest': descriptor['ciphertext']['digest']})


@contextmanager
def original_context(freeze, package, *, freeze_digest):
    """Authenticate fixed provisioned original coordinates, then decrypt and verify natively."""
    from maintenance_runtime_companion import _read
    import app_subject_projection as projection
    import cross_version_product_admission as products
    row = None
    token = None
    context = None
    try:
        selected = metadata.read_json(_read(SOURCE, 16384, protected=True, key=True))
        if (set(selected) != {'coordinates', 'freezeDigest'}
                or selected['freezeDigest'] != freeze_digest):
            raise RuntimeValidationError('maintenance-runtime-original-selection-mismatch')
        cohort = projection._cohort()
        if cohort['schemaVersion'] != 2:
            raise RuntimeValidationError('maintenance-runtime-private-cohort-required')
        contract = metadata.read_json(metadata._regular(Path(cohort['admissionContract']['snapshotPath'])))
        portable = next(row for row in freeze['assets'] if row['role'] == 'product')
        node = {'role': 'relay-no-apps', 'product': 'cryptad', 'packageTarget': 'linux-x64',
                'artifactDigest': portable['digest'], 'artifactSize': portable['sizeBytes'],
                'sourceCommit': freeze['source']['commit'], 'appDigests': [],
                'contractVersion': contract['contract']['contractVersion']}
        with tempfile.TemporaryDirectory(prefix='maintenance-original-') as directory:
            row = products.authenticate_maintenance_product(selected, node, Path(directory) / 'original')
            if row['maintenanceFreezeDigest'] != selected['freezeDigest']:
                raise RuntimeValidationError('maintenance-runtime-original-selection-mismatch')
            context = _OriginalContext(_SEAL, freeze, package, row)
            token = _ACTIVE.set(context)
            try:
                yield context
            finally:
                context.active = False
                _ACTIVE.reset(token)
                token = None
                products.close_runtime_context(row)
                row = None
    except (ValueError, OSError, KeyError, TypeError):
        raise RuntimeValidationError('maintenance-runtime-original-private-validation-failed') from None
    finally:
        if context is not None:
            context.active = False
        if token is not None:
            _ACTIVE.reset(token)
        if row is not None:
            products.close_runtime_context(row)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True, type=Path)
    args = parser.parse_args(argv)
    from cryptad_certification.cli import main as certify
    from cryptad_certification.manifest import load_manifest
    from cryptad_certification.models import RunContext
    workspace = Path.cwd().resolve()
    manifest = load_manifest(args.manifest.resolve(), workspace)
    # Inspect confined inputs without creating/resetting output. The delegated normal CLI
    # owns prepare_run_root exactly once, followed by prepare_context, for this invocation.
    context = RunContext(workspace, manifest.output.root / manifest.release.release_id,
                         'stable-maintenance', manifest)
    from cryptad_certification.engines import stable_1_0_maintenance_core as owner
    loaded = owner.load_json_input(context, 'maintenanceCandidateFreeze')
    if loaded is None:
        raise RuntimeValidationError('maintenance-runtime-freeze-required')
    arguments = ['stable-maintenance', '--manifest', str(args.manifest)]
    if loaded.value.get('schemaVersion') != 3:
        return certify(arguments)
    # This CLI is called by the hosted job, whose account has unrestricted sudo. The
    # explicit original_context API belongs only to a separately isolated owning caller.
    raise RuntimeValidationError('maintenance-runtime-isolated-worker-required')


if __name__ == '__main__':
    try:
        # The engine imports this canonical module name. Keep its ContextVar and capability
        # type identical to the CLI's, rather than creating authority in a second __main__ copy.
        from maintenance_runtime_validation import main as protected_main
        raise SystemExit(protected_main())
    except (ValueError, OSError, KeyError, TypeError):
        print('maintenance-runtime-protected-validation-failed', file=sys.stderr)
        raise SystemExit(2) from None

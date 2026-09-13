"""Fail closed at the hosted maintenance job's unavailable private-worker boundary.

The job account has unrestricted sudo and a writable checkout. Root-only files and a sudo Python
wrapper cannot isolate original selection keys from that caller. Never provision private runtime
material on that worker. The private metadata APIs remain available to isolated owning contexts;
a hosted bridge requires a separately provisioned immutable resolver and restricted worker.
"""
import maintenance_runtime_metadata as metadata


def seal_with_authority(freeze, package, runtime_root, inputs):
    """Reject hosted private production before any original selection or key is opened."""
    raise metadata.RuntimeMetadataError('runtime-metadata-isolated-worker-required')

"""Authenticated Stable 1.0 maintenance publication provider."""

from .provider import StableMaintenanceBackend, create_backend, factory
from .lifecycle import StableLifecycleBackend, lifecycle_factory
from .supply_chain import (
    AuthenticatedObserver,
    AuthenticatedProducer,
    SupplyChainPublicationBackend,
    supply_chain_factory,
)
from .dependency_vulnerability import (
    AuthenticatedDependencyPublisher,
    DependencyVulnerabilityPublicationBackend,
    dependency_vulnerability_factory,
)

__all__ = [
    "AuthenticatedObserver",
    "AuthenticatedProducer",
    "AuthenticatedDependencyPublisher",
    "DependencyVulnerabilityPublicationBackend",
    "StableLifecycleBackend",
    "StableMaintenanceBackend",
    "SupplyChainPublicationBackend",
    "create_backend",
    "factory",
    "dependency_vulnerability_factory",
    "lifecycle_factory",
    "supply_chain_factory",
]

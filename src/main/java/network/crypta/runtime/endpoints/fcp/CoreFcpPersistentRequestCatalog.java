package network.crypta.runtime.endpoints.fcp;

import java.util.Objects;
import network.crypta.client.async.persistence.PersistentRequestCatalog;
import network.crypta.client.async.persistence.PersistentRequestHandle;
import network.crypta.client.async.persistence.PersistentRequestIdentifier;
import network.crypta.clients.fcp.PersistentRequestRoot;
import network.crypta.clients.fcp.RequestIdentifier;

/**
 * Runtime-owned adapter that exposes FCP persistent requests through the client-owned catalog seam.
 *
 * <p>This adapter keeps durable-request enumeration and duplicate detection under runtime ownership
 * while exposing only the narrow client-owned catalog contract. It reuses the existing {@link
 * PersistentRequestRoot} registry and FCP request-identifier semantics, so the client-layer
 * persister can checkpoint and skip duplicates without importing FCP types directly.
 *
 * <p>The implementation is intentionally thin. It delegates snapshot creation to the live FCP
 * registry and converts client-owned identifiers back into legacy FCP identifiers only for lookup.
 * That preserves the existing queue and request-name semantics during the first phase of the
 * decoupling work.
 */
public final class CoreFcpPersistentRequestCatalog implements PersistentRequestCatalog {
  private final PersistentRequestRoot persistentRoot;

  /**
   * Creates a catalog adapter backed by the shared FCP persistent-request registry.
   *
   * @param persistentRoot shared FCP request root used for enumeration and duplicate lookups
   */
  public CoreFcpPersistentRequestCatalog(PersistentRequestRoot persistentRoot) {
    this.persistentRoot = Objects.requireNonNull(persistentRoot);
  }

  /** {@inheritDoc} */
  @Override
  public PersistentRequestHandle[] getPersistentRequests() {
    return persistentRoot.getPersistentRequests();
  }

  /** {@inheritDoc} */
  @Override
  public boolean hasRequest(PersistentRequestIdentifier identifier) {
    return persistentRoot.hasRequest(
        RequestIdentifier.fromPersistentRequestIdentifier(Objects.requireNonNull(identifier)));
  }
}

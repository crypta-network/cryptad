package network.crypta.clients.fcp;

import network.crypta.client.async.persistence.PersistentRequestRuntimeContext;
import network.crypta.support.api.ResumeContext;

/**
 * Detached FCP runtime context for request resume paths that also need bucket reattachment.
 *
 * <p>The FCP adapter uses this seam where a lifecycle path needs both the persistent-request
 * runtime token and the narrower resume helpers required by buckets and other persisted storage
 * objects. Implementations may wrap another {@link PersistentRequestRuntimeContext}; bridge-owned
 * code can recover that underlying token through {@link #persistentRequestRuntimeContext()} when it
 * needs to narrow back to a live runtime type.
 *
 * <p>The interface is intentionally small and asymmetric. Adapter-owned code should depend on this
 * detached view when it needs restart-safe bucket or metadata reattachment, while bridge-owned code
 * remains responsible for any narrowing back to live runtime classes such as the daemon's {@code
 * ClientContext}. That keeps the adapter-side lifecycle logic independent of the live runtime
 * implementation without weakening the resume contract needed by persistent storage.
 */
public interface FcpRequestRuntimeContext extends PersistentRequestRuntimeContext, ResumeContext {

  /**
   * Returns the underlying persistent-request runtime token that backs this detached view.
   *
   * <p>Implementations that are already the original runtime token can return {@code this}. Wrapper
   * implementations should return the wrapped token so bridge-owned code can narrow there without
   * leaking the live runtime type into {@code :adapter-fcp}. Callers should treat the returned
   * value as the persistence/runtime identity for the current resume pass, not as permission to
   * reach through to unrelated runtime services.
   *
   * @return underlying persistent-request runtime token for this detached context
   */
  default PersistentRequestRuntimeContext persistentRequestRuntimeContext() {
    return this;
  }
}

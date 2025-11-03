package network.crypta.client.async;

import java.io.Serial;

/**
 * Signals that an operation requiring on-disk persistence is unavailable because persistence is
 * disabled by configuration or current runtime policy.
 *
 * <p>This exception is used to fail fast when a caller attempts to schedule, persist, or resume a
 * client operation that relies on durable storage (for example, queuing requests for recovery
 * across restarts) while the node or client API is running in a non-persistent mode. Library users
 * should treat this as a non-retryable condition unless they can enable persistence and
 * reinitialize the relevant components. Typical call patterns are:
 *
 * <ul>
 *   <li>Validate capability before enqueueing asynchronous requests that need persistence.
 *   <li>Catching this exception at API boundaries to present a clear user-facing error message and
 *       an optional remediation hint (enable persistence, restart, or downgrade functionality).
 *   <li>Falling back to ephemeral/in-memory flows when durable behavior is not essential.
 * </ul>
 *
 * <p>The type is immutable and carries no additional state beyond the standard exception message
 * and cause. It is safe to instantiate and throw from any thread. There are no side effects other
 * than control flow; the presence of this exception does not change the persistence setting—it only
 * reports it.
 *
 * @see Exception
 */
public class PersistenceDisabledException extends Exception {
  @Serial private static final long serialVersionUID = -992316133570818146L;

  /**
   * Creates an exception indicating that persistence is disabled.
   *
   * <p>Use this constructor when no additional context is required beyond the fact that the
   * attempted operation depends on persistence. The detail message is {@code null} and no cause is
   * set, which is appropriate for simple guard checks where the failure reason is self‑evident from
   * the call site and surrounding logs. Callers typically throw this directly from capability
   * checks or translate it into a user‑facing message at API boundaries.
   *
   * <p>Example usage:
   *
   * <pre>{@code
   * if (!persistenceEnabled) {
   *     throw new PersistenceDisabledException();
   * }
   * }</pre>
   */
  public PersistenceDisabledException() {
    super();
  }
}

package network.crypta.runtime.admin.queue.page;

import network.crypta.runtime.spi.RequestQueueUnavailableException;

/**
 * Defines the runtime-owned backend seam for legacy queue-page reads.
 *
 * <p>Implementations expose the current global queue as narrow runtime-owned views. The seam keeps
 * protocol-specific lookup rules, status adaptation, and availability checks out of {@code
 * network.crypta.runtime.admin}. That lets the legacy queue-page renderer keep its existing sorting
 * and HTML behavior while depending only on stable runtime-owned types.
 *
 * <p>Callers should treat each invocation as consulting live daemon state rather than a cached
 * snapshot. Returning an empty array is the normal way to represent a queue backend that is absent,
 * disabled, or currently has no visible requests.
 */
public interface QueuePageBackend {
  /**
   * Returns the current global queue snapshot as runtime-owned request views.
   *
   * <p>The returned array is a point-in-time view of whatever queue state the implementation can
   * currently observe. Implementations may return an empty array when the backing queue is missing
   * or has nothing visible to expose, but they should raise an exception when the queue exists and
   * an operational failure prevents the read from completing.
   *
   * @return point-in-time queue request views, or an empty array when nothing can be shown
   * @throws RequestQueueUnavailableException if a live queue exists but cannot be queried safely
   */
  QueuePageRequestView[] getGlobalRequests() throws RequestQueueUnavailableException;
}

package network.crypta.support;

import network.crypta.client.async.ClientContext;
import network.crypta.client.async.RequestSelectionTreeNode;

/**
 * Contract for items stored in a {@link RandomGrabArray} and selected by the request scheduler.
 *
 * <p>Implementations represent a single schedulable unit (for example, a request with one or more
 * keys to fetch). They participate in the request-selection tree via {@link
 * RequestSelectionTreeNode} and expose readiness through {@link #getWakeupTime(ClientContext,
 * long)}. Some implementations also keep a back-reference to their current {@link RandomGrabArray}
 * to support fast removal and wakeup propagation.
 *
 * <p>Thread-safety: Methods are typically invoked while the caller holds the selection tree's root
 * lock (see {@code ClientRequestSelector}). Implementations should minimize additional locking and
 * avoid blocking operations in these callbacks.
 */
public interface RandomGrabArrayItem extends RequestSelectionTreeNode {

  /**
   * Returns when this item next becomes eligible, or a sentinel for ready/cancelled.
   *
   * <p>Return values have the following meaning:
   *
   * <ul>
   *   <li>{@code -1}: The item is finished (cancelled or completed) and should be removed from its
   *       container.
   *   <li>{@code 0}: The item is ready now (has requests to send immediately).
   *   <li>{@code > 0}: Absolute time when the item may become ready again. Implementations and
   *       callers treat this as a future timestamp; {@link Long#MAX_VALUE} may be used to represent
   *       "no earlier than the distant future" when all sub-requests are in flight.
   * </ul>
   *
   * <p>Threading: This method is called while the selection root's lock is held. Keep the time
   * spent inside minimal and avoid acquiring other locks when possible to reduce contention.
   *
   * @param context client execution context used for randomness or state;
   * @param now the current time in milliseconds since the epoch
   * @return a sentinel ({@code -1} or {@code 0}) or a future timestamp as described above
   */
  @Override
  long getWakeupTime(ClientContext context, long now);

  /**
   * Returns whether this item tracks the {@link RandomGrabArray} it is currently registered on.
   *
   * <p>Items that return {@code true} are expected to store a back-reference provided via {@link
   * #setParentGrabArray(RandomGrabArray)} and expose it through {@link #getParentGrabArray()}.
   * Returning {@code false} indicates the item does not maintain such a reference.
   *
   * @return {@code true} if a parent back-reference is supported; otherwise {@code false}
   */
  boolean knowsParentGrabArray();

  /**
   * Informs the item of the {@link RandomGrabArray} on which it is registered.
   *
   * <p>Called by the container when an item is added or removed (passing {@code null} on detach).
   * Implementations that support back-references should store the value for later retrieval and for
   * wakeup propagation.
   *
   * @param parent the parent array, or {@code null} if the item is being detached
   */
  void setParentGrabArray(RandomGrabArray parent);

  /**
   * Returns the current {@link RandomGrabArray} parent if this item tracks it.
   *
   * <p>If {@link #knowsParentGrabArray()} is {@code false}, implementations should return {@code
   * null}.
   *
   * @return the parent array, or {@code null} if none is tracked
   */
  @Override
  RandomGrabArray getParentGrabArray();
}

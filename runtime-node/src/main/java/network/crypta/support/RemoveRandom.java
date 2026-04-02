package network.crypta.support;

import network.crypta.client.async.ClientContext;
import network.crypta.client.async.RequestSelectionTreeNode;

/**
 * Contract for nodes that can remove and return a random eligible item.
 *
 * <p>Implementations select a random {@link RandomGrabArrayItem} that is ready to be processed. If
 * no item is immediately eligible, they return the earliest absolute time (in epoch milliseconds)
 * at which an item may become available. If the structure becomes empty, callers may remove it from
 * its parent via {@link RemoveRandomParent#maybeRemove(RemoveRandom, ClientContext)}.
 *
 * <p>Thread-safety: Implementations are typically used under a single tree-wide lock held by the
 * request selector (see {@link network.crypta.client.async.ClientRequestSelector}). Callers should
 * acquire the appropriate lock before invoking methods on an implementation.
 */
public interface RemoveRandom extends RequestSelectionTreeNode {

  /**
   * Result of an attempt to remove a random item.
   *
   * <p>Exactly one of {@link #item} or {@link #wakeupTime} is meaningful at a time:
   *
   * <ul>
   *   <li>If {@link #item} is non-{@code null}, an item is ready now. In this case {@link
   *       #wakeupTime} is {@code -1}.
   *   <li>If {@link #item} is {@code null}, no item is ready right now. {@link #wakeupTime} then
   *       holds the earliest absolute time (epoch millis) at which an item may become ready.
   * </ul>
   *
   * <p>Null is not used to signal an empty structure here; a {@code null} return from {@link
   * #removeRandom(RandomGrabArrayItemExclusionList, ClientContext, long)} indicates the entire
   * container is empty and should be removed by the parent.
   */
  final class RemoveRandomReturn {
    /**
     * The item to process immediately, or {@code null} when nothing is ready at the current time.
     */
    public final RandomGrabArrayItem item;

    /**
     * Absolute time (epoch milliseconds) when an item may become available, or {@code -1} when an
     * item is ready now.
     */
    public final long wakeupTime;

    /**
     * Constructs a result representing an item that is ready now.
     *
     * @param item the selected item; must not be {@code null}.
     */
    RemoveRandomReturn(RandomGrabArrayItem item) {
      this.item = item;
      this.wakeupTime = -1;
    }

    /**
     * Constructs a result representing the earliest time to try again.
     *
     * @param wakeupTime absolute time in milliseconds since the epoch ({@link
     *     System#currentTimeMillis()}) when an item may become available; must be {@code > 0}.
     */
    RemoveRandomReturn(long wakeupTime) {
      this.item = null;
      this.wakeupTime = wakeupTime;
    }
  }

  /**
   * Attempts to remove and return a random eligible item.
   *
   * <p>If an item is available now, the result contains that item. If not, the result contains the
   * earliest absolute time (epoch millis) at which an item may become available, taking into
   * account the provided exclusion list. If the underlying container has no items left, this method
   * returns {@code null} to signal that the caller should remove this node from its parent.
   *
   * <p>Threading: Callers should invoke this method while holding the tree-wide selection lock (see
   * {@link network.crypta.client.async.ClientRequestSelector}) to ensure consistent state.
   *
   * @param excluding optional exclusion list used to temporarily skip items and compute a wakeup
   *     time; may be {@code null} if no exclusions apply.
   * @param context client execution context used for randomness and shared state; must not be
   *     {@code null}.
   * @param now the current time in milliseconds since the epoch (typically {@link
   *     System#currentTimeMillis()}).
   * @return a {@link RemoveRandomReturn} containing either an item or a wakeup time; or {@code
   *     null} if the container is empty and should be removed by the parent.
   */
  RemoveRandomReturn removeRandom(
      RandomGrabArrayItemExclusionList excluding, ClientContext context, long now);

  /**
   * Sets or updates the parent in the selection tree.
   *
   * <p>The parent is used to propagate state changes (for example, wakeup-time reductions or
   * structural removal when empty). This method does not perform any synchronization by itself; the
   * caller should hold the appropriate selection lock when required by the implementation.
   *
   * @param newTopLevel the parent node to associate with this instance; may be {@code null} to
   *     detach from the tree.
   */
  void setParent(RemoveRandomParent newTopLevel);
}

package network.crypta.client.async;

/**
 * A node in the client request-selection tree that participates in cooldown and wakeup scheduling.
 *
 * <p>Implementations represent either an internal aggregation node (e.g., a grouping by priority or
 * policy) or a leaf that corresponds to an individual request. The tree is consulted by the
 * scheduler to decide when subtrees and leaves next become eligible for work. Each node exposes a
 * wakeup time and utilities to reduce or clear this value as descendant state changes.
 *
 * <p><strong>Usage and lifecycle:</strong> nodes are typically created and wired by a higher-level
 * selector component and remain attached to a single logical tree. A node may be detached or have a
 * {@code null} parent when it is not yet inserted or after removal. Callers should treat the API as
 * stateful and invoke it from the component that owns the scheduling tree.
 *
 * <p><strong>Threading:</strong> unless otherwise documented by an implementation, instances are
 * not inherently thread-safe. Access should be serialized by the request scheduler or owning
 * subsystem. Methods do not guarantee idempotency: reducing or clearing wakeup mutates state and
 * can propagate upward to parent nodes.
 *
 * <ul>
 *   <li>Represents position and ancestry within the selection tree.
 *   <li>Tracks a subtree wakeup time and exposes it to the scheduler.
 *   <li>Propagates changes upward so parent nodes reflect earlier eligibility.
 * </ul>
 *
 * (but ClientRequestSelector isn't a RequestSelectionTreeNode at the moment, the root is the
 * priorities in the array on ClientRequestSelector; consistency with RGA.root etc.)
 */
public interface RequestSelectionTreeNode {

  /**
   * Returns the parent node or {@code null} when not attached or when this node is the logical root
   * of the selection structure.
   *
   * <p>The parent reference is used to propagate wakeup changes upward so aggregate nodes can
   * reflect earlier eligibility. Implementations may transiently return {@code null} while a node
   * is being inserted or removed from the tree.
   *
   * @return the parent tree node, or {@code null} when this node has no parent or is considered the
   *     root in the current arrangement
   */
  RequestSelectionTreeNode getParentGrabArray();

  /**
   * Returns the next wakeup time for this node.
   *
   * <p>For aggregation nodes this is the wakeup time for the entire subtree rooted at this node.
   * For a leaf (for example, a {@code RandomGrabArrayItem}), this is the wakeup time for the single
   * request represented by the leaf. The time base and units are implementation-defined; callers
   * should pass a {@code now} value from the same source they use to interpret the return value.
   *
   * @param context context object providing scheduler- and node-related state; callers should pass
   *     the currently active client context used for selection and not retain it
   * @param now the current time from the caller’s chosen time source; use the same source and units
   *     expected by the implementation for consistent comparisons
   * @return the absolute time at which this node or its subtree next becomes eligible, expressed in
   *     the same time base as {@code now}; may be equal to or earlier than {@code now} when ready
   */
  long getWakeupTime(ClientContext context, long now);

  /**
   * Lowers the current wakeup time if it is later than the provided value and propagates the change
   * toward the root.
   *
   * <p>This method is used when an earlier eligibility is discovered within the subtree. If the
   * change reaches the root and causes it to become earlier than previously recorded, the
   * implementation should notify the owning scheduler. The operation is stateful and may alter the
   * effective scheduling of ancestor nodes.
   *
   * @param wakeupTime a candidate earlier wakeup time, expressed in the time base used by the
   *     implementation; values not earlier than the current value are ignored
   * @param context context object providing access to selection state and callbacks; not stored by
   *     the node and only consulted during the call
   * @return {@code true} if the node or any ancestor updated its wakeup time as a result of this
   *     call; {@code false} if no change was necessary
   */
  boolean reduceWakeupTime(long wakeupTime, ClientContext context);

  /**
   * Clears the wakeup state for this node and propagates the effect toward the root.
   *
   * <p>Call when a request becomes immediately eligible so that parent nodes reflect readiness as
   * soon as possible. Implementations typically set the effective wakeup to the earliest value
   * representable by their time base.
   *
   * @param context context object used to coordinate with the selection system during propagation;
   *     the reference is used only for the duration of the call
   */
  void clearWakeupTime(ClientContext context);
}

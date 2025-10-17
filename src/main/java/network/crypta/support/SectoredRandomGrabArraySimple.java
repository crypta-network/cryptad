package network.crypta.support;

import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientRequestSelector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Sectorized selector that maps client objects to per-client random grab arrays.
 *
 * <p>This “simple” variant stores {@link RandomGrabArrayWithObject} children directly beneath this
 * node (two-tier tree: SRGA → RGA). It is used when a single level of grouping by client is
 * sufficient; deeper trees use {@link SectoredRandomGrabArrayWithObject} of SRGAs instead.
 *
 * <p>Identity semantics: client keys are compared by reference equality ({@code ==}), not by {@link
 * Object#equals(Object)}. Two distinct objects that are {@code equals()} but not {@code ==} are
 * treated as different clients. See {@link SectoredRandomGrabArray#haveClient(Object)}.
 *
 * <p>Threading: All public methods synchronize on the shared {@link ClientRequestSelector} instance
 * (the {@code root} monitor). Calls are reentrant if the caller already holds the same monitor.
 * Avoid holding other locks while entering these APIs to prevent deadlocks.
 *
 * <p>Wakeup propagation: Operations that add work call {@link #clearWakeupTime(ClientContext)} via
 * the parent chain when a non-{@code null} {@link ClientContext} is provided. This prompts the
 * scheduler to reevaluate readiness.
 *
 * <p>Nullability: {@code client} and {@code item} parameters must be non-null. {@code context} may
 * be {@code null} when wakeup propagation is not required.
 *
 * <p>Complexity: Looking up an existing client is {@code O(n)} over the number of children. Adding
 * a new child appends to dense arrays and is {@code O(n)} due to array copy.
 */
public class SectoredRandomGrabArraySimple<M, C>
    extends SectoredRandomGrabArrayWithObject<M, C, RandomGrabArrayWithObject<C>> {

  private static final Logger LOG = LoggerFactory.getLogger(SectoredRandomGrabArraySimple.class);

  /**
   * Creates a sectorized selector that groups requests by client and stores one {@link
   * RandomGrabArrayWithObject} per client.
   *
   * <p>Threading: The provided {@code root} instance is used as the monitor for internal
   * synchronization across this node and its children; the same instance must be shared with peers
   * in the selection tree.
   *
   * @param object the owner object associated with this node; returned by {@link #getObject()}
   * @param parent the parent used for wakeup propagation and pruning; may be {@code null}
   * @param root the shared selector root used as the synchronization monitor; must not be {@code
   *     null}
   */
  public SectoredRandomGrabArraySimple(
      M object, RemoveRandomParent parent, ClientRequestSelector root) {
    super(object, parent, root);
  }

  /**
   * Adds an item to the per-client {@link RandomGrabArrayWithObject} under this node.
   *
   * <p>Behavior:
   *
   * <ul>
   *   <li>If a child grab array already exists for {@code client} (compared by identity), the item
   *       is appended to that child.
   *   <li>Otherwise, a new child is created and associated with {@code client}, and the item is
   *       added to it.
   *   <li>When {@code context} is non-{@code null}, this method clears stored wakeup time via the
   *       parent chain to prompt scheduling reevaluation.
   * </ul>
   *
   * <p>Threading: Synchronizes on the shared {@code root} monitor for the entire operation. Safe to
   * call reentrantly when the caller already holds the same monitor.
   *
   * <p>Nullability: {@code client} and {@code item} must be non-null. {@code context} may be {@code
   * null}.
   *
   * <p>Complexity: {@code O(n)} to locate an existing client and append; {@code O(n)} when creating
   * a new child due to array copy.
   *
   * @param client grouping key; compared by identity ({@code ==}) within this data structure
   * @param item work item to add to the client's grab array
   * @param context execution context used for randomness and wakeup propagation; may be {@code
   *     null}
   */
  public void add(C client, RandomGrabArrayItem item, ClientContext context) {
    synchronized (root) {
      RandomGrabArrayWithObject<C> rga = getGrabber(client);
      if (rga == null) {
        if (LOG.isDebugEnabled())
          LOG.debug("Adding new RGAWithClient for {} on {} for {}", client, this, item);
        rga = new RandomGrabArrayWithObject<>(client, this, root);
        addElement(client, rga);
      }
      if (LOG.isDebugEnabled()) LOG.debug("Adding {} to RGA {} for {}", item, rga, client);
      rga.add(item, context);
      if (context != null) {
        clearWakeupTime(context);
      }
      if (LOG.isDebugEnabled()) LOG.debug("Size now {} on {}", size(), this);
    }
  }
}

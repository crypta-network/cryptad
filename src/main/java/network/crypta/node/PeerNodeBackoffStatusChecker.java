package network.crypta.node;

import java.lang.ref.WeakReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Periodically validates a {@link PeerNode}'s presence in the peers table and updates its cached
 * status after a routing backoff period.
 *
 * <p>This checker holds a {@link WeakReference} to the {@code PeerNode} to avoid prolonging its
 * lifetime. If the reference is cleared, the task becomes a no-op. When the peer is still present
 * in the peers table, it calls {@link PeerNode#setPeerNodeStatus(long, boolean)} with the current
 * time to refresh status and counters.
 *
 * <p>Thread-safety: invoked by the node's scheduled executor. Performs only reads on {@code
 * PeerManager} and delegates synchronization to {@link PeerNode} internals.
 */
class PeerNodeBackoffStatusChecker implements Runnable {
  private static final Logger LOG = LoggerFactory.getLogger(PeerNodeBackoffStatusChecker.class);

  /** Weak reference to the target peer; prevents retaining peers past their lifecycle. */
  final WeakReference<PeerNode> ref;

  /**
   * Creates a new checker bound to a peer reference.
   *
   * @param ref weak reference to the target peer; may be cleared at execution time
   */
  public PeerNodeBackoffStatusChecker(WeakReference<PeerNode> ref) {
    this.ref = ref;
  }

  /**
   * Refreshes the peer's cached status if it is still present in the peers table.
   *
   * <p>Behavior: - If the peer reference has been cleared, returns immediately. - If the peer is
   * flagged as removed and is not in the peers table, returns. - If the peer is flagged as removed
   * but still present, logs the inconsistency. - If the peer is missing from the table but not
   * flagged as removed, logs the inconsistency and returns. - Otherwise, updates the peer status
   * with the current time.
   */
  @Override
  public void run() {
    PeerNode pn = ref.get();
    // Reference may be cleared at execution time.
    if (pn == null) return;
    // If marked removed, only proceed when also still present (inconsistent state).
    if (pn.cachedRemoved()) {
      if (LOG.isDebugEnabled() && pn.node.network().peers().havePeer(pn)) {
        LOG.error("Peer marked removed but present in peers table: {}", pn);
      } else {
        return;
      }
    }
    // If not present, and not flagged removed, log inconsistency and stop.
    if (!pn.node.network().peers().havePeer(pn)) {
      if (!pn.cachedRemoved()) LOG.error("Peer not in peers table and not marked removed: {}", pn);
      return;
    }
    // Happy path: peer is present and not flagged removed; refresh status.
    pn.setPeerNodeStatus(System.currentTimeMillis(), true);
  }
}

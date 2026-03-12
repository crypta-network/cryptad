package network.crypta.node;

import java.util.HashMap;
import java.util.List;
import network.crypta.support.WeakHashSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Maintains the set of {@link PeerNode} instances for each status key.
 *
 * <p>The map values are weak sets; a peer may be removed automatically when it becomes only weakly
 * reachable. All methods are synchronized on the instance. While holding this monitor, the
 * implementation does not call back into {@link PeerNode} to avoid lock-order inversions. Acquire
 * this lock last when composing with other locks.
 *
 * @param <K> application-defined status key used to group peers
 */
class PeerStatusTracker<K> {
  private static final Logger LOG = LoggerFactory.getLogger(PeerStatusTracker.class);

  /**
   * Map from status key to the weak set of peers that currently have that status.
   *
   * <p>Guarded by {@code this}. Do not invoke {@link PeerNode} methods while holding this lock; see
   * the class-level locking note above.
   */
  private final HashMap<K, WeakHashSet<PeerNode>> statuses;

  PeerStatusTracker() {
    statuses = new HashMap<>();
  }

  /**
   * Adds the given peer to the set for the provided status.
   *
   * <p>If the set already contains the peer, the operation is a no-op. When {@code noLog} is {@code
   * false}, a duplicate membership triggers an {@code ERROR}-level log (with a short debug stack
   * trace).
   *
   * <p>Thread safety: synchronized; does not call into {@link PeerNode}.
   *
   * @param peerNodeStatus status key that the peer should be associated with
   * @param peerNode peer to add
   * @param noLog when {@code true}, suppresses the duplicate-membership error log
   */
  public synchronized void addStatus(K peerNodeStatus, PeerNode peerNode, boolean noLog) {
    WeakHashSet<PeerNode> statusSet = statuses.get(peerNodeStatus);
    if (statusSet != null) {
      if (statusSet.contains(peerNode)) {
        if (!noLog)
          LOG.error(
              "addPeerNodeStatus(): node already in peerNodeStatuses: {} status {}",
              peerNode,
              peerNodeStatus,
              new Exception("debug"));
        return;
      }
      // Reinsert the entry after mutation. Functionally equivalent for HashMap, but keeps the
      // write path consistent and ensures the map records the latest set reference.
      statuses.remove(peerNodeStatus);
    } else statusSet = new WeakHashSet<>();
    if (LOG.isDebugEnabled())
      LOG.debug(
          "addPeerNodeStatus(): adding PeerNode for '{}' with status '{}'",
          peerNode.getIdentityString(),
          peerNodeStatus);
    statusSet.add(peerNode);
    statuses.put(peerNodeStatus, statusSet);
  }

  /**
   * Returns the number of peers currently recorded with the given status.
   *
   * <p>Returns {@code 0} if the status key is not present. Because the underlying set is weak,
   * entries may disappear when peers are only weakly reachable.
   *
   * @param pnStatus status key
   * @return number of peers associated with the status
   */
  public synchronized int statusSize(K pnStatus) {
    WeakHashSet<PeerNode> statusSet = statuses.get(pnStatus);
    if (statusSet != null) return statusSet.size();
    else return 0;
  }

  /**
   * Removes the given peer from the set for the provided status, if present.
   *
   * <p>If the peer is not a member and {@code noLog} is {@code false}, the method logs an {@code
   * ERROR}-level message (with a short debug stack trace). When the set becomes empty, the status
   * key is removed from the map to keep the keys compact.
   *
   * @param peerNodeStatus status key from which the peer should be removed
   * @param peerNode peer to remove
   * @param noLog when {@code true}, suppresses the absent-membership error log
   */
  public synchronized void removeStatus(K peerNodeStatus, PeerNode peerNode, boolean noLog) {
    WeakHashSet<PeerNode> statusSet = statuses.get(peerNodeStatus);
    if (statusSet != null) {
      if (!statusSet.remove(peerNode)) {
        if (!noLog)
          LOG.error(
              "removePeerNodeStatus(): identity '{} for {}' not in peerNodeStatuses with status"
                  + " '{}'",
              peerNode.getIdentityString(),
              peerNode.shortToString(),
              peerNodeStatus,
              new Exception("debug"));
        return;
      }
      // Drop the key entirely when the associated set is empty to avoid stale status entries.
      if (statusSet.isEmpty()) statuses.remove(peerNodeStatus);
    }
    if (LOG.isDebugEnabled())
      LOG.debug(
          "removePeerNodeStatus(): removing PeerNode for '{}' with status '{}'",
          peerNode.getIdentityString(),
          peerNodeStatus);
  }

  /**
   * Moves the peer from {@code oldPeerNodeStatus} to {@code peerNodeStatus} atomically with respect
   * to this tracker.
   *
   * <p>The method performs a removal followed by an addition while holding the monitor, so callers
   * observe a single, consistent transition. The {@code noLog} flag is forwarded to both operations
   * to control duplicate/absent error logs.
   *
   * @param peerNode peer whose status changes
   * @param oldPeerNodeStatus previous status key
   * @param peerNodeStatus new status key
   * @param noLog when {@code true}, suppresses duplicate/absent error logs
   */
  public synchronized void changePeerNodeStatus(
      PeerNode peerNode, K oldPeerNodeStatus, K peerNodeStatus, boolean noLog) {
    if (LOG.isDebugEnabled())
      LOG.debug("Peer status change: {} -> {} on {}", oldPeerNodeStatus, peerNodeStatus, peerNode);
    removeStatus(oldPeerNodeStatus, peerNode, noLog);
    addStatus(peerNodeStatus, peerNode, noLog);
  }

  /**
   * Appends the currently known status keys to the provided list.
   *
   * <p>The list is not cleared. The snapshot is taken under lock; keys may change after the call
   * completes.
   *
   * @param list destination list that receives the keys
   */
  public synchronized void addStatusList(List<K> list) {
    list.addAll(statuses.keySet());
  }
}

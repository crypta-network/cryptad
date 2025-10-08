package network.crypta.node;

import java.util.HashMap;
import java.util.List;
import network.crypta.support.WeakHashSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Track a collection of PeerNode's for each status. */
class PeerStatusTracker<K extends Object> {
  private static final Logger LOG = LoggerFactory.getLogger(PeerStatusTracker.class);

  static {
  }

  /**
   * PeerNode statuses, by status. WARNING: LOCK THIS LAST. Must NOT call PeerNode inside this lock.
   */
  private final HashMap<K, WeakHashSet<PeerNode>> statuses;

  PeerStatusTracker() {
    statuses = new HashMap<>();
  }

  public synchronized void addStatus(K peerNodeStatus, PeerNode peerNode, boolean noLog) {
    WeakHashSet<PeerNode> statusSet = statuses.get(peerNodeStatus);
    if (statusSet != null) {
      if (statusSet.contains(peerNode)) {
        if (!noLog)
          LOG.error(
              "addPeerNodeStatus(): node already in peerNodeStatuses: "
                  + peerNode
                  + " status "
                  + peerNodeStatus,
              new Exception("debug"));
        return;
      }
      statuses.remove(peerNodeStatus);
    } else statusSet = new WeakHashSet<>();
    if (LOG.isDebugEnabled())
      LOG.debug(
          "addPeerNodeStatus(): adding PeerNode for '"
              + peerNode.getIdentityString()
              + "' with status '"
              + peerNodeStatus
              + "'");
    statusSet.add(peerNode);
    statuses.put(peerNodeStatus, statusSet);
  }

  public synchronized int statusSize(K pnStatus) {
    WeakHashSet<PeerNode> statusSet = statuses.get(pnStatus);
    if (statusSet != null) return statusSet.size();
    else return 0;
  }

  public synchronized void removeStatus(K peerNodeStatus, PeerNode peerNode, boolean noLog) {
    WeakHashSet<PeerNode> statusSet = statuses.get(peerNodeStatus);
    if (statusSet != null) {
      if (!statusSet.remove(peerNode)) {
        if (!noLog)
          LOG.error(
              "removePeerNodeStatus(): identity '"
                  + peerNode.getIdentityString()
                  + " for "
                  + peerNode.shortToString()
                  + "' not in peerNodeStatuses with status '"
                  + peerNodeStatus
                  + "'",
              new Exception("debug"));
        return;
      }
      if (statusSet.isEmpty()) statuses.remove(peerNodeStatus);
    }
    if (LOG.isDebugEnabled())
      LOG.debug(
          "removePeerNodeStatus(): removing PeerNode for '"
              + peerNode.getIdentityString()
              + "' with status '"
              + peerNodeStatus
              + "'");
  }

  public synchronized void changePeerNodeStatus(
      PeerNode peerNode, K oldPeerNodeStatus, K peerNodeStatus, boolean noLog) {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Peer status change: " + oldPeerNodeStatus + " -> " + peerNodeStatus + " on " + peerNode);
    removeStatus(oldPeerNodeStatus, peerNode, noLog);
    addStatus(peerNodeStatus, peerNode, noLog);
  }

  public synchronized void addStatusList(List<K> list) {
    list.addAll(statuses.keySet());
  }
}

package network.crypta.node;

import java.lang.ref.WeakReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class PeerNodeBackoffStatusChecker implements Runnable {
  private static final Logger LOG = LoggerFactory.getLogger(PeerNodeBackoffStatusChecker.class);

  final WeakReference<PeerNode> ref;

  static {
  }

  public PeerNodeBackoffStatusChecker(WeakReference<PeerNode> ref) {
    this.ref = ref;
  }

  @Override
  public void run() {
    PeerNode pn = ref.get();
    if (pn == null) return;
    if (pn.cachedRemoved()) {
      if (LOG.isDebugEnabled() && pn.node.getPeers().havePeer(pn)) {
        LOG.error("Removed flag is set yet is in peers table?!: " + pn);
      } else {
        return;
      }
    }
    if (!pn.node.getPeers().havePeer(pn)) {
      if (!pn.cachedRemoved()) LOG.error("Not in peers table but not flagged as removed: " + pn);
      return;
    }
    pn.setPeerNodeStatus(System.currentTimeMillis(), true);
  }
}

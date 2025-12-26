package network.crypta.node;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import network.crypta.support.ByteArrayWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Provides seed-server peer queries derived from the current peer snapshot. */
public class SeedPeerQueries {
  private static final Logger LOG = LoggerFactory.getLogger(SeedPeerQueries.class);

  private final PeerManager peerManager;

  SeedPeerQueries(PeerManager peerManager) {
    this.peerManager = peerManager;
  }

  /**
   * Returns connected seed-server peers, excluding specified public key hashes.
   *
   * @param exclude Set of public key hashes to exclude (optional; may be {@code null}).
   * @return List of connected seed-server peers.
   */
  public List<SeedServerPeerNode> getConnectedSeedServerPeersVector(Set<ByteArrayWrapper> exclude) {
    PeerNode[] peers = peerManager.myPeers();
    List<SeedServerPeerNode> result = new ArrayList<>(peers.length);
    for (PeerNode peer : peers) {
      if (peer instanceof SeedServerPeerNode sspn && !shouldSkipSeedServerPeer(sspn, exclude)) {
        result.add(sspn);
      }
    }
    return result;
  }

  /**
   * Returns a snapshot of all seed-server peers (copy), connected or not.
   *
   * @return List of seed-server peers.
   */
  public List<SeedServerPeerNode> getSeedServerPeersVector() {
    PeerNode[] peers = peerManager.myPeers();
    // Note: consider optimizing by maintaining a separate list
    List<SeedServerPeerNode> result = new ArrayList<>(peers.length);
    for (PeerNode peer : peers) {
      if (peer instanceof SeedServerPeerNode peerNode) result.add(peerNode);
    }
    return result;
  }

  private boolean shouldSkipSeedServerPeer(SeedServerPeerNode sspn, Set<ByteArrayWrapper> exclude) {
    if (exclude != null && exclude.contains(new ByteArrayWrapper(sspn.getPubKeyHash()))) {
      if (LOG.isDebugEnabled())
        LOG.debug("Excluded by filter (exclude set): {}", sspn.userToString());
      return true;
    }
    if (!sspn.isConnected()) {
      if (LOG.isDebugEnabled()) LOG.debug("Excluded; disconnected: {}", sspn.userToString());
      return true;
    }
    return false;
  }
}

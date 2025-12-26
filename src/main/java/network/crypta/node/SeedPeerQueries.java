package network.crypta.node;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import network.crypta.support.ByteArrayWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides read-only queries for seed-server peers derived from the current peer snapshot.
 *
 * <p>This helper wraps a {@link PeerManager} snapshot lookup and filters for {@link
 * SeedServerPeerNode} instances. It is intended for callers that need a consistent, short-lived
 * view of seed peers without mutating the underlying peer roster. Typical usage is to fetch a list,
 * iterate immediately, and then discard it; the results should not be cached across network events
 * because the peer roster may change concurrently.
 *
 * <p>All methods return new {@link java.util.ArrayList} instances that contain the matching peers
 * in the order provided by the manager snapshot. The class itself is stateless aside from its
 * reference to the manager and therefore is safe for concurrent use as long as the underlying
 * manager provides a safe snapshot. Filtering is conservative: peers are excluded if they are not
 * currently connected or if their public key hash is explicitly filtered by the caller.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Filtering connected seed peers while honoring an optional exclude set.
 *   <li>Returning a complete seed-peer snapshot without connection filtering.
 * </ul>
 *
 * @see PeerManager
 * @see SeedServerPeerNode
 */
public class SeedPeerQueries {
  private static final Logger LOG = LoggerFactory.getLogger(SeedPeerQueries.class);

  private final PeerManager peerManager;

  /**
   * Creates query helpers bound to the provided peer manager snapshot API.
   *
   * <p>The manager reference is stored and used for subsequent snapshot reads. Callers typically
   * obtain this instance via {@link PeerManager#seedPeers()} rather than constructing it directly.
   * This constructor performs no I/O and does not copy peer state; all data is read on demand from
   * the manager.
   *
   * @param peerManager manager that supplies the current peer snapshot; must not be {@code null}
   */
  SeedPeerQueries(PeerManager peerManager) {
    this.peerManager = peerManager;
  }

  /**
   * Returns connected seed-server peers, excluding specified public key hashes.
   *
   * <p>The method walks the current peer snapshot returned by the manager and retains only {@link
   * SeedServerPeerNode} instances that are connected at the time of evaluation. If an {@code
   * exclude} set is provided, any seed peer whose public key hash matches a member of the set is
   * filtered out. The returned list is a new mutable list that reflects the snapshot order; later
   * changes to connectivity or peer membership are not reflected in the list.
   *
   * <p>Edge cases: a {@code null} exclude set is treated as empty; disconnected peers are always
   * omitted; non-seed peers are ignored. This operation is read-only and safe to call repeatedly.
   *
   * <pre>{@code
   * List<SeedServerPeerNode> seeds = peerManager.seedPeers()
   *     .getConnectedSeedServerPeersVector(null);
   * }</pre>
   *
   * @param exclude set of public key hashes to exclude; {@code null} means no exclusions apply
   * @return mutable snapshot list of connected seed peers, never {@code null} and possibly empty
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
   * Returns a snapshot list of all seed-server peers, connected or not.
   *
   * <p>This method filters the current peer snapshot for {@link SeedServerPeerNode} instances only,
   * without applying any connection checks. The returned list is a new mutable list, ordered to
   * match the manager snapshot at the time of the call. The list does not update if the peer roster
   * changes later.
   *
   * <p>Edge cases: if there are no seed peers, the returned list is empty; non-seed peers are
   * ignored. This is a read-only operation intended for quick iteration.
   *
   * <pre>{@code
   * List<SeedServerPeerNode> allSeeds = peerManager.seedPeers().getSeedServerPeersVector();
   * }</pre>
   *
   * @return mutable snapshot list of seed peers, never {@code null} and possibly empty
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

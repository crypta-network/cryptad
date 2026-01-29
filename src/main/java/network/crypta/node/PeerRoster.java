package network.crypta.node;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.Peer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Maintains the active peer roster and connected peer snapshots for a node.
 *
 * <p>The roster is a small, synchronized registry that tracks known peers, their connected view,
 * and a set of common queries used by routing and status reporting. It is intentionally narrow in
 * scope: the class focuses on array-backed storage, identity checks, and lightweight lookups,
 * leaving higher-level coordination (alerts, routing policy, persistence) to {@link PeerManager}
 * and {@link Node}. Arrays are replaced atomically under a shared manager lock, so callers should
 * treat returned arrays as snapshots that can become stale immediately after the lock is released.
 *
 * <p>This design favors low-overhead reads and predictable allocation patterns, but it means
 * multistep operations must re-check state under the same lock if consistency is required.
 * Thread-safety is provided by synchronizing on the supplied lock; the returned arrays are mutable
 * and must not be modified by callers.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> add/remove peers, track connected peers, and answer
 *       summary queries.
 *   <li><strong>Notable behavior:</strong> connected snapshots are rebuilt from roster state and
 *       routability checks.
 * </ul>
 *
 * @see PeerManager
 * @see PeerNode
 */
@SuppressWarnings("ReferenceEquality")
public class PeerRoster {
  private static final Logger LOG = LoggerFactory.getLogger(PeerRoster.class);

  private final Node node;
  private final Object lock;

  private PeerNode[] myPeers = new PeerNode[0];
  private PeerNode[] connectedPeers = new PeerNode[0];

  /**
   * Creates a roster bound to the owning node and its shared synchronization lock.
   *
   * <p>The roster stores references to the supplied node and lock; it does not take ownership of
   * either object and does not perform any synchronization during construction. Callers should
   * provide the same lock that guards peer management in {@link PeerManager} so that roster updates
   * remain consistent with other peer-related state transitions.
   *
   * @param node the owning node instance used for random selection and policy checks.
   * @param lock the shared manager lock guarding all roster mutations and snapshots.
   */
  public PeerRoster(Node node, Object lock) {
    this.node = node;
    this.lock = lock;
  }

  /**
   * Returns the current roster snapshot without making a defensive copy.
   *
   * <p>The returned array is the internal snapshot captured under the shared lock. Its contents
   * represent the roster state at the time of the call, but the array may be replaced immediately
   * afterward by later mutations. Callers must not modify the array and should copy it if they
   * require a stable, caller-owned view.
   *
   * @return the internal array snapshot of all known peers, potentially empty.
   */
  public PeerNode[] myPeers() {
    synchronized (lock) {
      return myPeers;
    }
  }

  /**
   * Returns the last known connected-peer snapshot without a defensive copy.
   *
   * <p>The returned array is the internal connected-peers snapshot captured under the shared lock.
   * It may include only peers that were connected and routable when the snapshot was built, and it
   * can become stale as soon as the lock is released. Callers must not mutate the array and should
   * copy it for long-lived iteration.
   *
   * @return the internal array snapshot of connected peers, possibly empty.
   */
  public PeerNode[] connectedPeers() {
    synchronized (lock) {
      return connectedPeers;
    }
  }

  /**
   * Returns whether the given peer instance is present in the roster by identity.
   *
   * <p>This method performs a reference-equality check against the current roster snapshot. It does
   * not consult peer identity fields or keys, and it does not modify any roster state. The check is
   * performed under the shared lock to provide a consistent view of the array.
   *
   * @param peer the peer instance to test for presence; if {@code null} this returns {@code false}.
   * @return {@code true} if the exact instance is present, otherwise {@code false}.
   */
  public boolean havePeer(PeerNode peer) {
    synchronized (lock) {
      for (PeerNode existing : myPeers) {
        if (existing == peer) return true;
      }
      return false;
    }
  }

  /**
   * Adds a peer to the roster if it is not already present.
   *
   * <p>This method performs an equality-based check under the shared lock. When {@code reactivate}
   * is {@code true}, it first cancels any disconnecting state on the peer before acquiring the
   * lock. Adding a peer only updates the roster snapshot; it does not implicitly mark the peer as
   * connected or modify the connected-peers snapshot.
   *
   * @param peer the peer instance to add to the roster snapshot.
   * @param reactivate whether to cancel disconnecting state before the adding attempt.
   * @return {@code true} if the peer was newly added; {@code false} if already present.
   */
  public boolean addPeer(PeerNode peer, boolean reactivate) {
    if (reactivate) peer.forceCancelDisconnecting();
    synchronized (lock) {
      for (PeerNode existing : myPeers) {
        if (existing.equals(peer)) {
          if (LOG.isDebugEnabled()) {
            LOG.debug(
                "Can't add peer {} because already have {}",
                peer,
                existing,
                new Exception("debug"));
          }
          return false;
        }
      }
      myPeers = Arrays.copyOf(myPeers, myPeers.length + 1);
      myPeers[myPeers.length - 1] = peer;
      LOG.info("Added {}", peer);
    }
    return true;
  }

  /**
   * Removes the given peer from the roster by identity.
   *
   * <p>The method checks whether the exact peer instance is present, updates the roster snapshot,
   * and rebuilds the connected-peers snapshot from the remaining routable real connections. If the
   * peer is a {@link DarknetPeerNode}, its extra peer data directory is removed as part of the
   * cleanup. The method does not attempt to close network connections; it only updates local
   * snapshots.
   *
   * @param peer the peer instance to remove from the roster snapshot.
   * @return {@code true} if the peer was present and removed; {@code false} otherwise.
   */
  public boolean removePeer(PeerNode peer) {
    if (LOG.isDebugEnabled()) LOG.debug("Removing {}", peer);
    synchronized (lock) {
      boolean isInPeers = false;
      for (PeerNode existing : myPeers) {
        if (existing == peer) {
          isInPeers = true;
          break;
        }
      }
      if (peer instanceof DarknetPeerNode darknetPeer) {
        darknetPeer.removeExtraPeerDataDir();
      }
      if (isInPeers) {
        rebuildPeerArraysOnRemove(peer);
        LOG.info("Removed {}", peer);
        return true;
      }
    }
    return false;
  }

  /**
   * Removes all peers and returns the previous roster snapshot for cleanup.
   *
   * <p>Both the roster and connected-peers snapshots are cleared under the shared lock. The method
   * does not close network connections or alter peer state; it simply drops the local references so
   * the caller can perform any necessary cleanup with the returned array.
   *
   * @return the previous roster snapshot that was cleared from this roster.
   */
  public PeerNode[] removeAllPeers() {
    synchronized (lock) {
      PeerNode[] oldPeers = myPeers;
      myPeers = new PeerNode[0];
      connectedPeers = new PeerNode[0];
      return oldPeers;
    }
  }

  private void rebuildPeerArraysOnRemove(PeerNode peer) {
    ArrayList<PeerNode> connected = new ArrayList<>();
    for (PeerNode mp : myPeers) {
      if (mp != peer && mp.isConnected() && mp.isRealConnection()) connected.add(mp);
    }
    connectedPeers = connected.toArray(new PeerNode[0]);

    PeerNode[] newMyPeers = new PeerNode[myPeers.length - 1];
    int position = 0;
    for (PeerNode mp : myPeers) {
      if (mp != peer) {
        newMyPeers[position++] = mp;
      }
    }
    myPeers = newMyPeers;
  }

  /**
   * Updates the connected-peers snapshot when a peer disconnects.
   *
   * <p>If the peer is present in the connected snapshot, this method rebuilds the connected list by
   * scanning the roster and retaining only peers that are currently routable. The roster itself is
   * not modified. The update is performed under the shared lock to avoid races with other snapshot
   * updates.
   *
   * @param peer the peer instance that is transitioning to a disconnected state.
   * @return {@code true} if the peer was found in the connected snapshot; {@code false} otherwise.
   */
  public boolean disconnected(PeerNode peer) {
    synchronized (lock) {
      boolean isInPeers = false;
      for (PeerNode connectedPeer : connectedPeers) {
        if (connectedPeer == peer) {
          isInPeers = true;
          break;
        }
      }
      if (!isInPeers) return false;
      ArrayList<PeerNode> peers = new ArrayList<>();
      for (PeerNode mp : myPeers) {
        if (mp != peer && mp.isRoutable()) peers.add(mp);
      }
      connectedPeers = peers.toArray(new PeerNode[0]);
    }
    return true;
  }

  /**
   * Adds a peer to the connected snapshot when it is real and already connected.
   *
   * <p>The method rejects non-real or disconnected peers early and returns {@code false} without
   * modifying any state. When the peer is eligible, it verifies that the peer exists in the roster;
   * if not, it logs a diagnostic and invokes the provided {@link PeerAdder} to add it. The
   * connected snapshot is then updated under the shared lock using identity equality.
   *
   * @param peer the peer to consider for inclusion in the connected snapshot.
   * @param peerAdder callback used to insert the peer if missing from the roster.
   * @return {@code true} if the connected snapshot changed; {@code false} otherwise.
   */
  public boolean addConnectedPeer(PeerNode peer, PeerAdder peerAdder) {
    if (!peer.isRealConnection()) {
      if (LOG.isDebugEnabled()) LOG.debug("Not a real connection: {}", peer);
      return false;
    }
    if (!peer.isConnected()) {
      if (LOG.isDebugEnabled()) LOG.debug("Not connected: {}", peer);
      return false;
    }
    synchronized (lock) {
      for (PeerNode connectedPeer : connectedPeers) {
        if (connectedPeer == peer) {
          if (LOG.isDebugEnabled()) LOG.debug("Already connected: {}", peer);
          return false;
        }
      }
      ensurePeerPresent(peer, peerAdder);
      if (LOG.isDebugEnabled()) LOG.debug("Connecting: {}", peer);
      connectedPeers = Arrays.copyOf(connectedPeers, connectedPeers.length + 1);
      connectedPeers[connectedPeers.length - 1] = peer;
      if (LOG.isDebugEnabled()) LOG.debug("Connected peers: {}", connectedPeers.length);
    }
    return true;
  }

  private void ensurePeerPresent(PeerNode peer, PeerAdder peerAdder) {
    boolean inMyPeers = false;
    for (PeerNode mp : myPeers) {
      if (mp == peer) {
        inMyPeers = true;
        break;
      }
    }
    if (!inMyPeers) {
      LOG.error("Connecting to {} but not in peers", peer);
      peerAdder.add(peer);
    }
  }

  /**
   * Finds a peer by transport address, falling back to IP-only matches.
   *
   * <p>The roster is scanned twice: first for peers whose transport address and port match the
   * supplied {@link Peer}, and then for peers whose IP matches the same address regardless of port.
   * Disabled peers are skipped. The method returns the first matching peer and does not modify the
   * roster state.
   *
   * @param peer the transport address descriptor to match against the roster.
   * @return the first matching peer, or {@code null} if no match is found.
   */
  public PeerNode getByPeer(Peer peer) {
    PeerNode[] peerList = myPeers();
    for (PeerNode pn : peerList) {
      if (pn.isDisabled()) continue;
      if (pn.matchesPeerAndPort(peer)) return pn;
    }
    FreenetInetAddress addr = peer.getFreenetAddress();
    for (PeerNode pn : peerList) {
      if (pn.isDisabled()) continue;
      if (PeerNodeAddressManager.matchesIP(pn, addr, false)) return pn;
    }
    return null;
  }

  /**
   * Finds a peer by transport address and outgoing mangler, with an IP-only fallback.
   *
   * <p>This method mirrors {@link #getByPeer(Peer)} but additionally requires the peer's outgoing
   * {@link FNPPacketMangler} to match the supplied {@code mangler}. Disabled peers are skipped. The
   * method returns the first matching peer and does not modify the roster state.
   *
   * @param peer the transport address descriptor to match against the roster.
   * @param mangler the outgoing mangler instance that must match the peer configuration.
   * @return the first matching peer, or {@code null} if no match is found.
   */
  public PeerNode getByPeer(Peer peer, FNPPacketMangler mangler) {
    PeerNode[] peerList = myPeers();
    for (PeerNode pn : peerList) {
      if (pn.isDisabled()) continue;
      if (pn.matchesPeerAndPort(peer) && pn.getOutgoingMangler() == mangler) return pn;
    }
    FreenetInetAddress addr = peer.getFreenetAddress();
    for (PeerNode pn : peerList) {
      if (pn.isDisabled()) continue;
      if (PeerNodeAddressManager.matchesIP(pn, addr, false) && pn.getOutgoingMangler() == mangler)
        return pn;
    }
    return null;
  }

  /**
   * Finds connected, routable peers that match the given address.
   *
   * <p>The roster snapshot is scanned for peers that are connected, routable, and whose IP matches
   * the provided address using the {@code strict} flag. The method returns {@code null} when no
   * peers match to avoid allocating an empty list. When matches exist, the returned list preserves
   * the roster iteration order and is owned by the caller.
   *
   * @param addr the address to match against each peer's IP.
   * @param strict whether to request strict matching semantics from {@code matchesIP}.
   * @return a list of matching peers, or {@code null} if no peers match.
   */
  public List<PeerNode> getAllConnectedByAddress(FreenetInetAddress addr, boolean strict) {
    List<PeerNode> found = null;
    PeerNode[] peerList = myPeers();
    for (PeerNode pn : peerList) {
      boolean eligible =
          pn.isConnected() && pn.isRoutable() && PeerNodeAddressManager.matchesIP(pn, addr, strict);
      if (eligible) {
        if (found == null) found = new ArrayList<>();
        found.add(pn);
      }
    }
    return found;
  }

  /**
   * Returns the peer with the given public key hash, if present.
   *
   * <p>The roster is scanned linearly and each peer's public key hash is compared using {@link
   * Arrays#equals(byte[], byte[])}. The method returns the first matching peer or {@code null} if
   * none are present. The provided hash array is not copied or stored, and the comparison is a raw
   * byte match without normalization or decoding.
   *
   * @param pkHash the peer public-key hash bytes to match against roster entries.
   * @return the first peer with a matching hash, or {@code null} when absent.
   */
  public PeerNode getByPubKeyHash(byte[] pkHash) {
    PeerNode[] peers = myPeers();
    for (PeerNode peer : peers) {
      if (Arrays.equals(peer.peerECDSAPubKeyHash, pkHash)) return peer;
    }
    return null;
  }

  /**
   * Returns a random routable connected peer, or {@code null} if none exist.
   *
   * <p>This is a convenience wrapper around {@link #getRandomPeer(PeerNode)} with no exclusion. The
   * selection is based on the connected snapshot and may rebuild that snapshot if needed to ensure
   * routability. The method does not guarantee stable distribution across calls.
   *
   * @return a random routable connected peer, or {@code null} if none are available.
   */
  public PeerNode getRandomPeer() {
    return getRandomPeer(null);
  }

  /**
   * Returns a random routable connected peer, optionally excluding one peer.
   *
   * <p>The method first tries a small number of random selections from the current connected
   * snapshot, skipping the excluded peer and any unroutable entries. If those attempts fail, it
   * rebuilds the connected snapshot from the roster, optionally excluding the provided peer from
   * selection, and then chooses uniformly from the rebuilt list. The connected snapshot may be
   * modified as a side effect.
   *
   * @param exclude a peer instance to avoid returning; {@code null} allows any.
   * @return a routable connected peer, or {@code null} when none are eligible.
   */
  public PeerNode getRandomPeer(PeerNode exclude) {
    synchronized (lock) {
      if (connectedPeers.length == 0) return null;
      PeerNode candidate = attemptRandomRoutable(exclude);
      if (candidate != null) return candidate;
      int lengthWithoutExcluded = rebuildConnectedPeersExcluding(exclude);
      if (lengthWithoutExcluded == 0) return null;
      return connectedPeers[node.bootstrap().random().nextInt(lengthWithoutExcluded)];
    }
  }

  private PeerNode attemptRandomRoutable(PeerNode exclude) {
    for (int i = 0; i < 5; i++) {
      PeerNode pn = connectedPeers[node.bootstrap().random().nextInt(connectedPeers.length)];
      if (pn == exclude) continue;
      if (pn.isRoutable()) return pn;
    }
    return null;
  }

  private int rebuildConnectedPeersExcluding(PeerNode exclude) {
    ArrayList<PeerNode> v = new ArrayList<>(connectedPeers.length);
    for (PeerNode pn : myPeers) {
      if (pn == exclude) continue;
      if (pn.isRoutable()) v.add(pn);
      else if (LOG.isDebugEnabled()) LOG.debug("Excluding {}; disconnected", pn);
    }
    int lengthWithoutExcluded = v.size();
    if (exclude != null && exclude.isRoutable()) v.add(exclude);
    PeerNode[] newConnectedPeers = v.toArray(new PeerNode[0]);
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Connected peers in getRandomPeer: {} was {}",
          newConnectedPeers.length,
          connectedPeers.length);
    }
    connectedPeers = newConnectedPeers;
    return lengthWithoutExcluded;
  }

  /**
   * Returns the current locations of connected peers as doubles in {@code [0.0, 1.0)}.
   *
   * <p>If the node is not configured to publish its peers' locations, this method returns an empty
   * array. Otherwise, it collects locations from connected, routable peers, optionally pruning
   * peers that should be excluded from published lists, and sorts the resulting values in ascending
   * order. The returned array is a new allocation owned by the caller.
   *
   * @param pruneBackedOffPeers whether to exclude peers that should be pruned from peer lists.
   * @return a sorted array of peer locations or an empty array when publishing is disabled.
   */
  public double[] getPeerLocationDoubles(boolean pruneBackedOffPeers) {
    if (!node.shallWePublishOurPeersLocation()) return new double[0];
    PeerNode[] conns = connectedPeers();
    double[] locs = collectPeerLocations(conns, pruneBackedOffPeers);
    Arrays.sort(locs);
    return locs;
  }

  private double[] collectPeerLocations(PeerNode[] peers, boolean pruneBackedOffPeers) {
    ArrayList<Double> tmp = new ArrayList<>();
    for (PeerNode peer : peers) {
      if (peer.isRoutable() && (!pruneBackedOffPeers || !peer.shouldBeExcludedFromPeerList())) {
        tmp.add(peer.getLocation());
      }
    }
    double[] locs = new double[tmp.size()];
    for (int i = 0; i < tmp.size(); i++) {
      locs[i] = tmp.get(i);
    }
    return locs;
  }

  /**
   * Returns whether any connected peer is currently routable.
   *
   * <p>This method scans the connected snapshot and checks routability on each peer. It does not
   * alter the roster state and returns immediately on the first routable peer found. The snapshot
   * used for scanning is retrieved atomically but can become stale once the method returns. It is a
   * lightweight read-only query intended for fast status checks.
   *
   * @return {@code true} if any connected peer is routable; {@code false} otherwise.
   */
  public boolean anyConnectedPeers() {
    PeerNode[] conns = connectedPeers();
    for (PeerNode conn : conns) {
      if (conn.isRoutable()) return true;
    }
    return false;
  }

  /**
   * Returns whether any connected peer is a darknet peer.
   *
   * <p>The check is performed against the current connected snapshot and does not modify any roster
   * state. It returns as soon as a connected darknet peer is found and does not attempt to
   * revalidate connectivity or routability beyond what the snapshot already captured. Use this for
   * quick UI or reporting decisions rather than authoritative membership checks.
   *
   * @return {@code true} if any connected peer is a darknet peer; {@code false} otherwise.
   */
  public boolean anyDarknetPeers() {
    PeerNode[] conns = connectedPeers();
    for (PeerNode peer : conns) {
      if (peer.isDarknet()) return true;
    }
    return false;
  }

  /**
   * Returns the current list of darknet peers in the roster.
   *
   * <p>The method builds a new array containing only {@link DarknetPeerNode} instances found in the
   * roster snapshot. The snapshot is not filtered by connectivity, routability, or disabled state,
   * so the caller should apply additional checks if needed. The iteration order matches the roster
   * snapshot order, and the returned array is owned by the caller and can be modified safely.
   *
   * @return an array of darknet peers for callers, possibly empty.
   */
  public DarknetPeerNode[] getDarknetPeers() {
    PeerNode[] peers = myPeers();
    ArrayList<DarknetPeerNode> v = new ArrayList<>(peers.length);
    for (PeerNode peer : peers) {
      if (peer instanceof DarknetPeerNode darknetPeer) v.add(darknetPeer);
    }
    return v.toArray(new DarknetPeerNode[0]);
  }

  /**
   * Returns the current list of opennet peers in the roster.
   *
   * <p>The method builds a new array containing only {@link OpennetPeerNode} instances found in the
   * roster snapshot. The snapshot is not filtered by connectivity, routability, or disabled state,
   * so the caller should apply additional checks if needed. The iteration order matches the roster
   * snapshot order, and the returned array is owned by the caller and can be modified safely.
   *
   * @return an array of opennet peers, possibly empty.
   */
  public OpennetPeerNode[] getOpennetPeers() {
    PeerNode[] peers = myPeers();
    ArrayList<OpennetPeerNode> v = new ArrayList<>(peers.length);
    for (PeerNode peer : peers) {
      if (peer instanceof OpennetPeerNode opennetPeer) v.add(opennetPeer);
    }
    return v.toArray(new OpennetPeerNode[0]);
  }

  /**
   * Returns opennet peers and seed-server peers from the roster.
   *
   * <p>The method scans the roster snapshot and collects peers that are either {@link
   * OpennetPeerNode} instances or {@link SeedServerPeerNode} instances. The snapshot is not
   * filtered by a connection state or disabled flag, so the result is purely type-based. The
   * returned array is a new allocation owned by the caller and ordered by the roster iteration
   * order.
   *
   * @return an array of opennet and seed-server peers, possibly empty.
   */
  public PeerNode[] getOpennetAndSeedServerPeers() {
    PeerNode[] peers = myPeers();
    ArrayList<PeerNode> v = new ArrayList<>(peers.length);
    for (PeerNode peer : peers) {
      if (peer instanceof OpennetPeerNode || peer instanceof SeedServerPeerNode) v.add(peer);
    }
    return v.toArray(new PeerNode[0]);
  }

  /**
   * Removes all opennet peers from the roster.
   *
   * <p>The method rebuilds both the roster snapshot and the connected snapshot under the shared
   * lock, keeping only non-opennet peers. Connected peers are retained only if they remain
   * connected after the filtering. The method is idempotent and does not otherwise modify peer
   * state or attempt to close connections. Callers should expect the connected snapshot to shrink
   * as a result of removing opennet entries.
   */
  public void removeOpennetPeers() {
    synchronized (lock) {
      ArrayList<PeerNode> keep = new ArrayList<>();
      ArrayList<PeerNode> conn = new ArrayList<>();
      for (PeerNode pn : myPeers) {
        if (pn instanceof OpennetPeerNode) continue;
        keep.add(pn);
        if (pn.isConnected()) conn.add(pn);
      }
      myPeers = keep.toArray(new PeerNode[0]);
      connectedPeers = conn.toArray(new PeerNode[0]);
    }
  }

  /**
   * Finds a peer by public key hash within the relevant peer set.
   *
   * <p>The search scope depends on the supplied peer's network type: opennet peers are matched
   * against opennet and seed-server peers, while darknet peers are matched against the darknet
   * roster. Peers are compared by their public-key hash bytes, so the result may be a different
   * instance than the one supplied if another peer shares the same hash. The method performs a
   * linear scan and returns the first match in snapshot order.
   *
   * @param peer the peer whose network type and hash define the search scope.
   * @return the matching peer instance, or {@code null} if no match is found.
   */
  public PeerNode containsPeer(PeerNode peer) {
    PeerNode[] peers = peer.isOpennet() ? getOpennetAndSeedServerPeers() : getDarknetPeers();
    for (PeerNode candidate : peers) {
      if (Arrays.equals(peer.peerECDSAPubKeyHash, candidate.peerECDSAPubKeyHash)) return candidate;
    }
    return null;
  }

  /**
   * Checks whether any other connected real peer has the given address.
   *
   * <p>The scan ignores the provided peer instance, peers that are not connected, and peers that
   * are not real connections. Additionally, darknet peers are skipped when the reference peer is
   * not a darknet peer, preventing cross-network address comparisons. Address equality uses {@link
   * FreenetInetAddress#equals(Object)} for comparison, and the method returns immediately on the
   * first match found.
   *
   * @param addr the address to match against other connected peers.
   * @param peer the peer to exclude from matching and to infer network scope.
   * @return {@code true} if another connected real peer shares the address; {@code false}
   *     otherwise.
   */
  public boolean anyConnectedPeerHasAddress(FreenetInetAddress addr, PeerNode peer) {
    PeerNode[] peers = myPeers();
    for (PeerNode p : peers) {
      boolean skip =
          p == peer
              || !p.isConnected()
              || !p.isRealConnection()
              || (p.isDarknet() && !peer.isDarknet());
      if (skip) continue;
      if (p.getPeer().getFreenetAddress().equals(addr)) return true;
    }
    return false;
  }

  /**
   * Counts connected peers that are routable and not in routing backoff.
   *
   * <p>The method scans the connected snapshot and counts peers that are routable and not backed
   * off for the requested traffic class. It does not modify the roster state and performs no
   * allocations other than local counters. The result is a snapshot and should not be treated as a
   * stable capacity guarantee.
   *
   * @param realTime whether to apply the real-time traffic backoff classification.
   * @return the number of connected peers that are routable and not backed off.
   */
  public int countNonBackedOffPeers(boolean realTime) {
    PeerNode[] peers = connectedPeers();
    int count = 0;
    for (PeerNode peer : peers) {
      if (peer.isRoutable() && !peer.isRoutingBackedOff(realTime)) count++;
    }
    return count;
  }

  /**
   * Counts connected darknet peers that are routable and not opennet.
   *
   * <p>The roster snapshot is scanned for {@link DarknetPeerNode} instances that are not opennet
   * and are currently routable. This count is independent of the connected snapshot and reflects
   * the roster's current view at the time of the scan. It does not inspect backoff status.
   *
   * @return the number of connected, routable darknet peers that are not opennet.
   */
  public int countConnectedDarknetPeers() {
    int count = 0;
    PeerNode[] peers = myPeers();
    for (PeerNode peer : peers) {
      if (peer instanceof DarknetPeerNode && !peer.isOpennet() && peer.isRoutable()) count++;
    }
    if (LOG.isDebugEnabled()) LOG.debug("countConnectedDarknetPeers() returning {}", count);
    return count;
  }

  /**
   * Counts all routable peers in the roster snapshot.
   *
   * <p>This method counts routable peers from the roster snapshot rather than the connected
   * snapshot, mirroring historical behavior and allowing the roster to include peers that are
   * considered routable even if not currently in the connected list. The count is a best-effort
   * snapshot and may change immediately after the call returns. No allocations are performed beyond
   * a counter.
   *
   * @return the number of routable peers present in the roster snapshot.
   */
  public int countConnectedPeers() {
    return countConnectedPeers(myPeers());
  }

  private int countConnectedPeers(PeerNode[] peers) {
    int count = 0;
    for (PeerNode peer : peers) {
      if (peer.isRoutable()) count++;
    }
    return count;
  }

  /**
   * Counts darknet peers that are connected, regardless of routability.
   *
   * <p>The roster snapshot is scanned for {@link DarknetPeerNode} instances that are not opennet
   * and that report themselves as connected. Routability is not considered in this count, so peers
   * in backoff may still be included. The count is a transient view of roster state.
   *
   * @return the number of connected darknet peers, regardless of routability.
   */
  public int countAlmostConnectedDarknetPeers() {
    int count = 0;
    PeerNode[] peers = myPeers();
    for (PeerNode peer : peers) {
      if (peer instanceof DarknetPeerNode && !peer.isOpennet() && peer.isConnected()) count++;
    }
    return count;
  }

  /**
   * Counts darknet peers that are connected and routing-compatible.
   *
   * <p>The roster snapshot is scanned for {@link DarknetPeerNode} instances that are connected, not
   * opennet, and routing-compatible. This is a stricter filter than simply checking connectivity or
   * routability alone and is often used for eligibility gating. The count is based solely on
   * current peer-reported flags.
   *
   * @return the number of connected darknet peers that are routing-compatible.
   */
  public int countCompatibleDarknetPeers() {
    int count = 0;
    PeerNode[] peers = myPeers();
    for (PeerNode peer : peers) {
      if (peer instanceof DarknetPeerNode
          && !peer.isOpennet()
          && peer.isConnected()
          && peer.isRoutingCompatible()) {
        count++;
      }
    }
    return count;
  }

  /**
   * Counts peers with a real connection that are connected and routing-compatible.
   *
   * <p>The roster snapshot is scanned for peers that report a real connection, are connected, and
   * are routing-compatible. This count includes both darknet and opennet peers that satisfy the
   * criteria and do not distinguish between them. The result is a snapshot and may change as peers
   * connect or disconnect.
   *
   * @return the number of real, connected peers that are routing-compatible.
   */
  public int countCompatibleRealPeers() {
    int count = 0;
    PeerNode[] peers = myPeers();
    for (PeerNode peer : peers) {
      if (peer.isRealConnection() && peer.isConnected() && peer.isRoutingCompatible()) {
        count++;
      }
    }
    return count;
  }

  /**
   * Counts connected opennet peers that are routable.
   *
   * <p>The connected snapshot is scanned for {@link OpennetPeerNode} instances that are routable.
   * This uses the connected snapshot rather than the roster snapshot and therefore reflects the
   * last connection update rather than a live connection probe. The count is best-effort.
   *
   * @return the number of connected opennet peers that are routable.
   */
  public int countConnectedOpennetPeers() {
    int count = 0;
    PeerNode[] peers = connectedPeers();
    for (PeerNode peer : peers) {
      if (peer instanceof OpennetPeerNode && peer.isRoutable()) count++;
    }
    return count;
  }

  /**
   * Counts peers that may connect, excluding disabled peers and non-real connections.
   *
   * <p>The roster snapshot is scanned for peers that represent real connections and are not
   * disabled. Seed nodes are excluded implicitly because they do not qualify as real connections.
   * The count is a snapshot and may change as peers are added or removed. This method does not
   * attempt any network operations.
   *
   * @return the number of peers that may connect based on the current roster state.
   */
  public int countValidPeers() {
    int count = 0;
    PeerNode[] peers = myPeers();
    for (PeerNode peer : peers) {
      if (peer.isRealConnection() && !peer.isDisabled()) count++;
    }
    return count;
  }

  /**
   * Counts peers that may connect, excluding listen-only darknet peers.
   *
   * <p>The roster snapshot is scanned for peers that are not disabled and are not listen-only
   * darknet peers. This provides a count of peers that can actively participate in connections and
   * does not require any connectivity checks. The count treats opennet peers uniformly.
   *
   * @return the number of peers that may connect under current roster conditions.
   */
  public int countConnectiblePeers() {
    int count = 0;
    PeerNode[] peers = myPeers();
    for (PeerNode peer : peers) {
      boolean isListenOnlyDarknet =
          (peer instanceof DarknetPeerNode darknetPeer) && darknetPeer.isListenOnly();
      if (!peer.isDisabled() && !isListenOnlyDarknet) count++;
    }
    return count;
  }

  /**
   * Counts peers that are seed servers or seed clients.
   *
   * <p>The roster snapshot is scanned for {@link SeedServerPeerNode} and {@link SeedClientPeerNode}
   * instances. This count does not inspect connectivity or routability, so it remains stable even
   * when peer connection states fluctuate. The scan is linear in roster size.
   *
   * @return the number of seed server or seed client peers in the roster.
   */
  public int countSeednodes() {
    int count = 0;
    for (PeerNode peer : myPeers()) {
      if (peer instanceof SeedServerPeerNode || peer instanceof SeedClientPeerNode) count++;
    }
    return count;
  }

  /**
   * Counts peers currently in routing backoff.
   *
   * <p>The roster snapshot is scanned for peers that represent real connections, are not disabled,
   * and are currently backed off for the given traffic class. This count helps to route policy
   * assess available capacity without triggering any network operations. The result is a snapshot
   * and may change as backoff timers expire.
   *
   * @param realTime whether to apply the real-time traffic backoff classification.
   * @return the number of peers in routing backoff for the requested traffic class.
   */
  public int countBackedOffPeers(boolean realTime) {
    int count = 0;
    PeerNode[] peers = myPeers();
    for (PeerNode peer : peers) {
      if (peer.isRealConnection() && !peer.isDisabled() && peer.isRoutingBackedOff(realTime)) {
        count++;
      }
    }
    return count;
  }

  /**
   * Counts peers by their current status value.
   *
   * <p>The roster snapshot is scanned, and each peer's status is compared to the supplied status
   * code. No normalization or translation is performed; the integer is compared directly, so the
   * caller should use the exact status constants expected by {@link PeerNode#getPeerNodeStatus()}.
   * The scan is linear and does not allocate.
   *
   * @param status the raw status value to match against each peer's status code.
   * @return the number of peers whose status matches the supplied value.
   */
  public int countByStatus(int status) {
    int count = 0;
    PeerNode[] peers = myPeers();
    for (PeerNode peer : peers) {
      if (peer.getPeerNodeStatus() == status) count++;
    }
    return count;
  }

  /**
   * Returns a textual status list for all peers.
   *
   * <p>The method collects each peer's status string with verbose detail, sorts the resulting
   * entries, and joins them with newline separators. The returned string ends with a trailing
   * newline if at least one entry is present. When there are no peers, the method returns an empty
   * string without a trailing newline. The ordering is purely lexical after sorting.
   *
   * @return a sorted, newline-delimited list of peer status entries.
   */
  public String getStatus() {
    StringBuilder sb = new StringBuilder();
    PeerNode[] peers = myPeers();
    String[] status = new String[peers.length];
    for (int i = 0; i < peers.length; i++) {
      status[i] = peers[i].getStatus(true).toString();
    }
    Arrays.sort(status);
    for (String s : status) {
      sb.append(s).append('\n');
    }
    return sb.toString();
  }

  /**
   * Returns a textual list of TMCI peers.
   *
   * <p>The method collects each peer's TMCI information string, sorts the resulting entries, and
   * joins them with newline separators. The returned string ends with a trailing newline if at
   * least one entry is present. When there are no peers, the method returns an empty string. The
   * list is intended for display and is not a structured serialization format.
   *
   * @return a sorted, newline-delimited list of TMCI peer entries.
   */
  public String getTMCIPeerList() {
    StringBuilder sb = new StringBuilder();
    PeerNode[] peers = myPeers();
    String[] peerList = new String[peers.length];
    for (int i = 0; i < peers.length; i++) {
      peerList[i] = peers[i].getTMCIPeerInfo();
    }
    Arrays.sort(peerList);
    for (String p : peerList) {
      sb.append(p).append('\n');
    }
    return sb.toString();
  }

  /**
   * Asks each darknet peer to read and process its extra peer data.
   *
   * <p>The method iterates over the current darknet peers and invokes their extra data reader.
   * Exceptions are caught and logged so that a failure on one peer does not block processing of
   * others. A completion message is logged after the scan finishes, and no exceptions are
   * propagated to callers.
   */
  public void readExtraPeerData() {
    DarknetPeerNode[] peers = getDarknetPeers();
    for (DarknetPeerNode peer : peers) {
      try {
        peer.readExtraPeerData();
      } catch (Exception e) {
        LOG.error("Error reading extra peer data", e);
      }
    }
    LOG.info("Extra peer data reading and processing completed");
  }

  /**
   * Increments the selection sample counter for a peer.
   *
   * <p>This is a thin delegation to the peer's selection counter used for sampling and weighting.
   * The roster itself does not maintain any additional state for this operation, and the method
   * does not acquire the roster lock because it does not modify roster snapshots. Callers should
   * ensure the peer reference is valid for the current roster lifecycle.
   *
   * @param peer the peer whose selection counter should be incremented.
   */
  public void incrementSelectionSamples(PeerNode peer) {
    peer.incrementNumberOfSelections();
  }

  /**
   * Callback for inserting a peer into the roster when a connection is observed first.
   *
   * <p>This interface is used by {@link #addConnectedPeer(PeerNode, PeerAdder)} to ensure that
   * connected peers are also present in the roster. Implementations should perform the minimal
   * roster mutation and avoid blocking operations, because the call may occur while holding the
   * shared manager lock.
   */
  @FunctionalInterface
  public interface PeerAdder {
    /**
     * Adds the given peer to the roster.
     *
     * <p>The implementation is expected to register the peer with the roster and any surrounding
     * peer-management infrastructure without performing long-running work.
     *
     * @param peer the peer instance to add to the roster.
     */
    void add(PeerNode peer);
  }
}

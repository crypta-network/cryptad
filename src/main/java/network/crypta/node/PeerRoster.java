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
 * <p>This class encapsulates peer list mutations, lookups, and related counts while delegating
 * higher-level coordination (alerts, routing, persistence) to the owning {@link PeerManager}.
 */
public class PeerRoster {
  private static final Logger LOG = LoggerFactory.getLogger(PeerRoster.class);

  private final Node node;
  private final Object lock;

  private PeerNode[] myPeers = new PeerNode[0];
  private PeerNode[] connectedPeers = new PeerNode[0];

  public PeerRoster(Node node, Object lock) {
    this.node = node;
    this.lock = lock;
  }

  /** Returns a non-copied snapshot of all peers (synchronized on the manager lock). */
  public PeerNode[] myPeers() {
    synchronized (lock) {
      return myPeers;
    }
  }

  /** Returns the last known connected-peer snapshot (synchronized on the manager lock). */
  public PeerNode[] connectedPeers() {
    synchronized (lock) {
      return connectedPeers;
    }
  }

  /** Returns whether the given peer instance is present in the roster (identity check). */
  public boolean havePeer(PeerNode peer) {
    synchronized (lock) {
      for (PeerNode existing : myPeers) {
        if (existing == peer) return true;
      }
      return false;
    }
  }

  /**
   * Adds a peer to the roster if absent.
   *
   * @param peer the peer to add.
   * @param reactivate if true, cancel any disconnecting state before adding.
   * @return true if the peer was added, false if it was already present.
   */
  public boolean addPeer(PeerNode peer, boolean reactivate) {
    if (reactivate) peer.forceCancelDisconnecting();
    synchronized (lock) {
      for (PeerNode existing : myPeers) {
        if (existing == peer) {
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
   * Removes the given peer from the roster.
   *
   * @return true if the peer was present and removed, false otherwise.
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
      if (peer instanceof DarknetPeerNode) {
        ((DarknetPeerNode) peer).removeExtraPeerDataDir();
      }
      if (isInPeers) {
        rebuildPeerArraysOnRemove(peer);
        LOG.info("Removed {}", peer);
        return true;
      }
    }
    return false;
  }

  /** Removes all peers and returns the previous peer snapshot for cleanup. */
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
   * Updates the connected peers list when a peer disconnects.
   *
   * @return true if the peer was present in the connected set; false otherwise.
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
   * Adds a peer to the connected set if it is a real, connected peer.
   *
   * @param peerAdder callback used when the peer is not present in the roster.
   * @return true if the connected set changed, false otherwise.
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

  /** Finds a peer by transport address, falling back to IP-only matches. */
  public PeerNode getByPeer(Peer peer) {
    PeerNode[] peerList = myPeers();
    for (PeerNode pn : peerList) {
      if (pn.isDisabled()) continue;
      if (pn.matchesPeerAndPort(peer)) return pn;
    }
    FreenetInetAddress addr = peer.getFreenetAddress();
    for (PeerNode pn : peerList) {
      if (pn.isDisabled()) continue;
      if (pn.matchesIP(addr, false)) return pn;
    }
    return null;
  }

  /** Finds a peer by transport address and outgoing mangler, falling back to IP-only matches. */
  public PeerNode getByPeer(Peer peer, FNPPacketMangler mangler) {
    PeerNode[] peerList = myPeers();
    for (PeerNode pn : peerList) {
      if (pn.isDisabled()) continue;
      if (pn.matchesPeerAndPort(peer) && pn.getOutgoingMangler() == mangler) return pn;
    }
    FreenetInetAddress addr = peer.getFreenetAddress();
    for (PeerNode pn : peerList) {
      if (pn.isDisabled()) continue;
      if (pn.matchesIP(addr, false) && pn.getOutgoingMangler() == mangler) return pn;
    }
    return null;
  }

  /** Finds connected, routable peers that match the given address. */
  public List<PeerNode> getAllConnectedByAddress(FreenetInetAddress addr, boolean strict) {
    List<PeerNode> found = null;
    PeerNode[] peerList = myPeers();
    for (PeerNode pn : peerList) {
      boolean eligible = pn.isConnected() && pn.isRoutable() && pn.matchesIP(addr, strict);
      if (eligible) {
        if (found == null) found = new ArrayList<>();
        found.add(pn);
      }
    }
    return found;
  }

  /** Returns the peer with the given public key hash, if present. */
  public PeerNode getByPubKeyHash(byte[] pkHash) {
    PeerNode[] peers = myPeers();
    for (PeerNode peer : peers) {
      if (Arrays.equals(peer.peerECDSAPubKeyHash, pkHash)) return peer;
    }
    return null;
  }

  /** Returns a random routable connected peer, or null if none. */
  public PeerNode getRandomPeer() {
    return getRandomPeer(null);
  }

  /** Returns a random routable connected peer, or null if none. */
  public PeerNode getRandomPeer(PeerNode exclude) {
    synchronized (lock) {
      if (connectedPeers.length == 0) return null;
      PeerNode candidate = attemptRandomRoutable(exclude);
      if (candidate != null) return candidate;
      int lengthWithoutExcluded = rebuildConnectedPeersExcluding(exclude);
      if (lengthWithoutExcluded == 0) return null;
      return connectedPeers[node.getRandom().nextInt(lengthWithoutExcluded)];
    }
  }

  private PeerNode attemptRandomRoutable(PeerNode exclude) {
    for (int i = 0; i < 5; i++) {
      PeerNode pn = connectedPeers[node.getRandom().nextInt(connectedPeers.length)];
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

  /** Returns the current locations of connected peers as doubles in [0.0, 1.0). */
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

  /** Returns whether any peer is currently routable. */
  public boolean anyConnectedPeers() {
    PeerNode[] conns = connectedPeers();
    for (PeerNode conn : conns) {
      if (conn.isRoutable()) return true;
    }
    return false;
  }

  /** Returns whether any connected peer is a darknet peer. */
  public boolean anyDarknetPeers() {
    PeerNode[] conns = connectedPeers();
    for (PeerNode peer : conns) {
      if (peer.isDarknet()) return true;
    }
    return false;
  }

  /** Returns the current list of darknet peers. */
  public DarknetPeerNode[] getDarknetPeers() {
    PeerNode[] peers = myPeers();
    ArrayList<DarknetPeerNode> v = new ArrayList<>(peers.length);
    for (PeerNode peer : peers) {
      if (peer instanceof DarknetPeerNode) v.add((DarknetPeerNode) peer);
    }
    return v.toArray(new DarknetPeerNode[0]);
  }

  /** Returns the current list of opennet peers. */
  public OpennetPeerNode[] getOpennetPeers() {
    PeerNode[] peers = myPeers();
    ArrayList<OpennetPeerNode> v = new ArrayList<>(peers.length);
    for (PeerNode peer : peers) {
      if (peer instanceof OpennetPeerNode) v.add((OpennetPeerNode) peer);
    }
    return v.toArray(new OpennetPeerNode[0]);
  }

  /** Returns opennet and seed-server peers. */
  public PeerNode[] getOpennetAndSeedServerPeers() {
    PeerNode[] peers = myPeers();
    ArrayList<PeerNode> v = new ArrayList<>(peers.length);
    for (PeerNode peer : peers) {
      if (peer instanceof OpennetPeerNode || peer instanceof SeedServerPeerNode) v.add(peer);
    }
    return v.toArray(new PeerNode[0]);
  }

  /** Removes all opennet peers from the roster. */
  public void removeOpennetPeers() {
    synchronized (lock) {
      ArrayList<PeerNode> keep = new ArrayList<>();
      ArrayList<PeerNode> conn = new ArrayList<>();
      for (PeerNode pn : myPeers) {
        if (pn instanceof OpennetPeerNode) continue;
        keep.add(pn);
        if (pn.isConnected()) conn.add(pn);
      }
      PeerNode[] keepArray = keep.toArray(new PeerNode[0]);
      myPeers = keepArray;
      connectedPeers = Arrays.copyOf(keepArray, conn.size());
    }
  }

  /** Finds a peer by public key hash within the relevant peer set. */
  public PeerNode containsPeer(PeerNode peer) {
    PeerNode[] peers = peer.isOpennet() ? getOpennetAndSeedServerPeers() : getDarknetPeers();
    for (PeerNode candidate : peers) {
      if (Arrays.equals(peer.peerECDSAPubKeyHash, candidate.peerECDSAPubKeyHash)) return candidate;
    }
    return null;
  }

  /** Checks whether any other connected real peer has the given address. */
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

  /** Counts peers that are routable and not in backoff for the given traffic class. */
  public int countNonBackedOffPeers(boolean realTime) {
    PeerNode[] peers = connectedPeers();
    int count = 0;
    for (PeerNode peer : peers) {
      if (peer.isRoutable() && !peer.isRoutingBackedOff(realTime)) count++;
    }
    return count;
  }

  /** Counts connected darknet peers that are routable and not opennet. */
  public int countConnectedDarknetPeers() {
    int count = 0;
    PeerNode[] peers = myPeers();
    for (PeerNode peer : peers) {
      if (peer instanceof DarknetPeerNode && !peer.isOpennet() && peer.isRoutable()) count++;
    }
    if (LOG.isDebugEnabled()) LOG.debug("countConnectedDarknetPeers() returning {}", count);
    return count;
  }

  /** Counts all connected and routable peers. */
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

  /** Counts darknet peers that are connected (regardless of routability). */
  public int countAlmostConnectedDarknetPeers() {
    int count = 0;
    PeerNode[] peers = myPeers();
    for (PeerNode peer : peers) {
      if (peer instanceof DarknetPeerNode && !peer.isOpennet() && peer.isConnected()) count++;
    }
    return count;
  }

  /** Counts darknet peers that are connected and routing-compatible. */
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

  /** Counts peers with a real connection that are connected and routing-compatible. */
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

  /** Counts connected opennet peers that are routable. */
  public int countConnectedOpennetPeers() {
    int count = 0;
    PeerNode[] peers = connectedPeers();
    for (PeerNode peer : peers) {
      if (peer instanceof OpennetPeerNode && peer.isRoutable()) count++;
    }
    return count;
  }

  /** Counts peers that actually may connect (excluding seednodes and disabled peers). */
  public int countValidPeers() {
    int count = 0;
    PeerNode[] peers = myPeers();
    for (PeerNode peer : peers) {
      if (peer.isRealConnection() && !peer.isDisabled()) count++;
    }
    return count;
  }

  /** Counts peers that may connect, excluding listen-only darknet peers. */
  public int countConnectiblePeers() {
    int count = 0;
    PeerNode[] peers = myPeers();
    for (PeerNode peer : peers) {
      boolean isListenOnlyDarknet =
          (peer instanceof DarknetPeerNode) && ((DarknetPeerNode) peer).isListenOnly();
      if (!peer.isDisabled() && !isListenOnlyDarknet) count++;
    }
    return count;
  }

  /** Counts peers that are seed servers or seed clients. */
  public int countSeednodes() {
    int count = 0;
    for (PeerNode peer : myPeers()) {
      if (peer instanceof SeedServerPeerNode || peer instanceof SeedClientPeerNode) count++;
    }
    return count;
  }

  /** Counts peers currently in routing backoff. */
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

  /** Count peers by current status value. */
  public int countByStatus(int status) {
    int count = 0;
    PeerNode[] peers = myPeers();
    for (PeerNode peer : peers) {
      if (peer.getPeerNodeStatus() == status) count++;
    }
    return count;
  }

  /** Returns a textual status list for all peers. */
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

  /** Returns a textual list of TMCI peers. */
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

  /** Ask each DarknetPeerNode to read in its extra peer data. */
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

  /** Increments the selection sample counter for a peer. */
  public void incrementSelectionSamples(PeerNode peer) {
    peer.incrementNumberOfSelections();
  }

  @FunctionalInterface
  public interface PeerAdder {
    void add(PeerNode peer);
  }
}

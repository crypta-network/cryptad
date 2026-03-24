package network.crypta.node;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates darknet and opennet peers for the local node.
 *
 * <p>Responsibilities include maintaining the desired peer set (configured and discovered),
 * tracking currently connected peers, recording per-peer status, selecting routing targets, and
 * persisting peer references to disk. The manager also exposes helper queries for counts, lookups,
 * and status summaries, and emits user alerts summarizing connectivity.
 *
 * <p>Threading: most public methods briefly synchronize on the manager when reading/writing the
 * peer arrays. Callers should avoid holding unrelated locks when invoking selection or mutation
 * operations to limit contention.
 *
 * @author amphibian
 */
public class PeerManager {
  private static final Logger LOG = LoggerFactory.getLogger(PeerManager.class);

  /** Our Node */
  final Node node;

  /** First time we've got any connections since startup. */
  long timeFirstAnyConnections = 0;

  /** Handles peer reference persistence and scheduling. */
  private final PeerPersistence peerPersistence;

  /** Handles outbound peer connection requests. */
  private final PeerConnector peerConnector;

  /** Handles peer messaging and disconnect workflows. */
  private final PeerMessenger peerMessenger;

  /** Handles queries for seed-server peers. */
  private final SeedPeerQueries seedPeerQueries;

  /** Maintains peer lists and connected snapshots. */
  private final PeerRoster roster;

  /** Tracks peer status counts and backoff reasons. */
  private final PeerStatusBook statusBook;

  /** Validates opennet admission rules for newly added peers. */
  private final PeerOpennetGate opennetGate;

  /** Performs routing peer selection. */
  private final PeerRoutingSelector routingSelector;

  /** Coordinates PeerManagerUserAlert updates. */
  private final PeerAlertCoordinator alertCoordinator;

  public static final int PEER_NODE_STATUS_CONNECTED = 1;
  public static final int PEER_NODE_STATUS_ROUTING_BACKED_OFF = 2;
  public static final int PEER_NODE_STATUS_TOO_NEW = 3;
  public static final int PEER_NODE_STATUS_TOO_OLD = 4;
  public static final int PEER_NODE_STATUS_DISCONNECTED = 5;
  public static final int PEER_NODE_STATUS_NEVER_CONNECTED = 6;
  public static final int PEER_NODE_STATUS_DISABLED = 7;
  public static final int PEER_NODE_STATUS_BURSTING = 8;
  public static final int PEER_NODE_STATUS_LISTENING = 9;
  public static final int PEER_NODE_STATUS_LISTEN_ONLY = 10;
  public static final int PEER_NODE_STATUS_CLOCK_PROBLEM = 11;
  public static final int PEER_NODE_STATUS_CONN_ERROR = 12;
  public static final int PEER_NODE_STATUS_DISCONNECTING = 13;
  public static final int PEER_NODE_STATUS_ROUTING_DISABLED = 14;
  public static final int PEER_NODE_STATUS_NO_LOAD_STATS = 15;

  /**
   * The list of listeners that needs to be notified when peers' statuses changed. Note: Consider
   * using this for PeerManagerUserAlert and centralizing registration rather than registering with
   * each PeerNode separately (potentially excluding seed server/client changes).
   */
  private final List<PeerStatusChangeListener> listeners = new CopyOnWriteArrayList<>();

  /**
   * Constructs a manager for darknet/opennet peers and schedules periodic persistence.
   *
   * <p>The manager starts empty; peers are added by higher-level components or by reading persisted
   * files during startup. The supplied shutdown hook flushes peer lists on early shutdown.
   *
   * @param node The owning node instance. Must be fully constructed before invoking methods that
   *     call back into {@code node}.
   * @param shutdownHook Hook used to register an early job that writes peers to disk on shutdown.
   */
  public PeerManager(Node node, SemiOrderedShutdownHook shutdownHook) {
    LOG.info("PeerManager initialization start");
    this.node = node;
    roster = new PeerRoster(node, this);
    statusBook = new PeerStatusBook(roster, this);
    opennetGate = new PeerOpennetGate(node);
    peerPersistence = new PeerPersistence(node, this);
    peerConnector = new PeerConnector(node, this);
    peerMessenger = new PeerMessenger(node, this);
    seedPeerQueries = new SeedPeerQueries(this);
    routingSelector = new PeerRoutingSelector(node, roster, statusBook);
    alertCoordinator = new PeerAlertCoordinator(node, roster, statusBook);
    LOG.info("PeerManager initialized");
    shutdownHook.addEarlyJob(new Thread(peerPersistence::flushOnShutdown));
  }

  /** Returns the helper responsible for outbound peer connection requests. */
  public PeerConnector connector() {
    return peerConnector;
  }

  /** Returns the helper responsible for peer messaging and disconnect workflows. */
  public PeerMessenger messenger() {
    return peerMessenger;
  }

  /** Returns the helper that provides seed-server peer queries. */
  public SeedPeerQueries seedPeers() {
    return seedPeerQueries;
  }

  /** Returns the peer roster for direct queries and snapshots. */
  public PeerRoster roster() {
    return roster;
  }

  /** Returns the peer status tracker for status snapshots and backoff reasons. */
  public PeerStatusBook statusBook() {
    return statusBook;
  }

  /** Returns the routing selector used for peer routing decisions. */
  public PeerRoutingSelector routingSelector() {
    return routingSelector;
  }

  /** Reads peers from the disk using the configured persistence helper. */
  public void tryReadPeers(
      String filename,
      NodeCrypto crypto,
      OpennetManager opennet,
      boolean isOpennet,
      boolean oldOpennetPeers) {
    peerPersistence.tryReadPeers(filename, crypto, opennet, isOpennet, oldOpennetPeers);
  }

  public boolean addPeer(PeerNode pn) {
    return addPeer(pn, false, false);
  }

  /**
   * Add a peer.
   *
   * @param pn The node to add to the routing table.
   * @param ignoreOpennet If true, don't check for opennet peers. If false, check for opennet peers,
   *     and if so, if opennet is enabled, auto-add them to the opennet LRU, otherwise fail.
   * @param reactivate If true, re-enable the peer if it is in state DISCONNECTING before re-adding
   *     it.
   * @return True if the node was successfully added. False if it was already present, or if we
   *     tried to add an opennet peer when opennet was disabled.
   */
  public boolean addPeer(PeerNode pn, boolean ignoreOpennet, boolean reactivate) {
    Objects.requireNonNull(pn, "pn");
    boolean added = roster.addPeer(pn, reactivate);
    if (!added) return false;
    statusBook.onPeerAdded(pn);
    pn.setPeerNodeStatus(System.currentTimeMillis());
    if (!opennetGate.allowPeer(pn, ignoreOpennet)) {
      removePeer(pn);
      return false;
    }
    notifyPeerStatusChangeListeners();
    if (!pn.isSeed()) {
      // LOCKING: addPeer() can be called inside PM lock, so must do this on a separate thread.
      node.network().executor().execute(this::updatePMUserAlert);
    }
    return true;
  }

  synchronized boolean havePeer(PeerNode pn) {
    return roster.havePeer(pn);
  }

  /** Remove a PeerNode. LOCKING: Caller should not hold locks on any PeerNode. */
  @SuppressWarnings("UnusedReturnValue")
  boolean removePeer(PeerNode pn) {
    boolean isInPeers;
    synchronized (this) {
      isInPeers = roster.havePeer(pn);
      if (isInPeers) {
        statusBook.onPeerRemoved(pn);
        roster.removePeer(pn);
      }
    }
    pn.onRemove();
    if (isInPeers && !pn.isSeed()) updatePMUserAlert();
    notifyPeerStatusChangeListeners();
    updatePMUserAlert();
    return true;
  }

  @SuppressWarnings("UnusedReturnValue")
  public boolean removeAllPeers() {
    LOG.info("Removing all peers");
    PeerNode[] oldPeers = roster.removeAllPeers();
    for (PeerNode oldPeer : oldPeers) oldPeer.onRemove();
    notifyPeerStatusChangeListeners();
    return true;
  }

  /**
   * Handles post-disconnect bookkeeping for a peer.
   *
   * @param pn Peer that transitioned to disconnected.
   * @return {@code true} if the peer was present in the connected set; otherwise {@code false}.
   */
  public boolean disconnected(PeerNode pn) {
    boolean changed = roster.disconnected(pn);
    if (!changed) return false;
    if (!pn.isSeed()) updatePMUserAlert();
    node.network().locationManager().announceLocChange();
    return true;
  }

  /**
   * Returns the timestamp of the first successful connection since startup.
   *
   * @return Epoch milliseconds of the first connection, or 0 if none yet.
   */
  public synchronized long getTimeFirstAnyConnections() {
    return timeFirstAnyConnections;
  }

  /**
   * Adds a peer to the connected set if it is a real, connected peer.
   *
   * @param pn Peer that has just connected.
   */
  public void addConnectedPeer(PeerNode pn) {
    if (!pn.isRealConnection()) {
      if (LOG.isDebugEnabled()) LOG.debug("Not a real connection: {}", pn);
      return;
    }
    if (!pn.isConnected()) {
      if (LOG.isDebugEnabled()) LOG.debug("Not connected: {}", pn);
      return;
    }
    long now = System.currentTimeMillis();
    synchronized (this) {
      if (timeFirstAnyConnections == 0) timeFirstAnyConnections = now;
    }
    boolean added = roster.addConnectedPeer(pn, this::addPeer);
    if (!added) return;
    if (!pn.isSeed()) updatePMUserAlert();
    node.network().locationManager().announceLocChange();
  }

  /**
   * Returns the current locations of connected peers as doubles in [0.0, 1.0).
   *
   * @param pruneBackedOffPeers When true, omit peers excluded from lists due to backoff.
   * @return A sorted array of peer locations or an empty array when publishing is disabled.
   */
  public double[] getPeerLocationDoubles(boolean pruneBackedOffPeers) {
    return roster.getPeerLocationDoubles(pruneBackedOffPeers);
  }

  /**
   * Returns a random routable connected peer.
   *
   * <p>Note: consider taking performance into account. DO NOT remove the "synchronized". See below
   * for why.
   *
   * @return A random routable connected peer.
   */
  public synchronized PeerNode getRandomPeer(PeerNode exclude) {
    return roster.getRandomPeer(exclude);
  }

  /** Returns a random routable connected peer, or {@code null} if none. */
  public PeerNode getRandomPeer() {
    return getRandomPeer(null);
  }

  /**
   * Builds a human-readable status summary of all peers.
   *
   * @return Multiline string, one line per peer status, sorted lexicographically.
   */
  public String getStatus() {
    return roster.getStatus();
  }

  /**
   * Returns a textual list of peers for TMCI consumers.
   *
   * @return Multiline string with TMCI peer info, sorted.
   */
  public String getTMCIPeerList() {
    return roster.getTMCIPeerList();
  }

  void writePeers(boolean opennet) {
    peerPersistence.writePeers(opennet);
  }

  public void writePeersUrgent(boolean opennet) {
    peerPersistence.writePeersUrgent(opennet);
  }

  void writePeersDarknet() {
    peerPersistence.writePeers(false);
  }

  /**
   * Forces an urgent write of darknet peer state to disk.
   *
   * <p>This preserves the historical TMCI behavior of flushing peer list mutations immediately
   * after add/remove operations.
   */
  public void writePeersDarknetUrgent() {
    peerPersistence.writePeersUrgent(false);
  }

  /**
   * Update the numbers needed by our PeerManagerUserAlert on the UAM. Also, run the node's
   * onConnectedPeers() method if applicable. LOCKING: Do not call inside PeerNode lock.
   */
  public void updatePMUserAlert() {
    alertCoordinator.update();
  }

  /**
   * Returns whether any peer is currently routable.
   *
   * @return {@code true} if at least one connected peer is routable; otherwise {@code false}.
   */
  public boolean anyConnectedPeers() {
    return roster.anyConnectedPeers();
  }

  /**
   * Returns whether any connected peer is a darknet peer.
   *
   * @return {@code true} when a darknet peer is connected; otherwise {@code false}.
   */
  public boolean anyDarknetPeers() {
    return roster.anyDarknetPeers();
  }

  /** Ask each PeerNode to read in its extra peer data */
  public void readExtraPeerData() {
    roster.readExtraPeerData();
  }

  /** Initializes user alerts and schedules the first peer persistence writing. */
  public void start() {
    alertCoordinator.start();
    peerPersistence.scheduleInitialWrite();
  }

  /**
   * Counts peers that are routable and not in backoff for the given traffic class.
   *
   * @param realTime If true, evaluate realtime backoff; otherwise evaluate bulk backoff.
   * @return Number of connected peers not backed off.
   */
  public int countNonBackedOffPeers(boolean realTime) {
    return roster.countNonBackedOffPeers(realTime);
  }

  // Stats stuff
  /** Update oldestNeverConnectedPeerAge if the timer has expired */
  public void maybeUpdateOldestNeverConnectedDarknetPeerAge(long now) {
    statusBook.maybeUpdateOldestNeverConnectedDarknetPeerAge(now);
  }

  public long getOldestNeverConnectedDarknetPeerAge() {
    return statusBook.getOldestNeverConnectedDarknetPeerAge();
  }

  /** Log the current PeerNode status summary if the timer has expired */
  public void maybeLogPeerNodeStatusSummary(long now) {
    statusBook.maybeLogPeerNodeStatusSummary(now);
  }

  public void changePeerNodeStatus(
      PeerNode peerNode, int oldPeerNodeStatus, int peerNodeStatus, boolean noLog) {
    statusBook.changePeerNodeStatus(peerNode, oldPeerNodeStatus, peerNodeStatus, noLog);
    node.network().executor().execute(this::updatePMUserAlert);
  }

  /**
   * How many PeerNodes have a particular status?
   *
   * @param darknet If true, only count darknet nodes, if false, count all nodes.
   */
  public int getPeerNodeStatusSize(int pnStatus, boolean darknet) {
    return statusBook.getPeerNodeStatusSize(pnStatus, darknet);
  }

  /** Add a PeerNode routing backoff reason to the map */
  public void addPeerNodeRoutingBackoffReason(
      String peerNodeRoutingBackoffReason, PeerNode peerNode, boolean realTime) {
    if (peerNodeRoutingBackoffReason == null) {
      LOG.error(
          "Impossible backoff reason null on {} realtime={}",
          peerNode,
          realTime,
          new Exception("error"));
      return;
    }
    statusBook.addPeerNodeRoutingBackoffReason(peerNodeRoutingBackoffReason, peerNode, realTime);
  }

  /** What are the currently tracked PeerNode routing backoff reasons? */
  public String[] getPeerNodeRoutingBackoffReasons(boolean realTime) {
    return statusBook.getPeerNodeRoutingBackoffReasons(realTime);
  }

  /** How many PeerNodes have a particular routing backoff reason? */
  public int getPeerNodeRoutingBackoffReasonSize(
      String peerNodeRoutingBackoffReason, boolean realTime) {
    return statusBook.getPeerNodeRoutingBackoffReasonSize(peerNodeRoutingBackoffReason, realTime);
  }

  /** Remove a PeerNode routing backoff reason from the map */
  public void removePeerNodeRoutingBackoffReason(
      String peerNodeRoutingBackoffReason, PeerNode peerNode, boolean realTime) {
    statusBook.removePeerNodeRoutingBackoffReason(peerNodeRoutingBackoffReason, peerNode, realTime);
  }

  /**
   * Updates per-peer routable-connection counters when the timer elapses.
   *
   * <p>Increments sampling counters that feed routing-health statistics.
   */
  public void maybeUpdatePeerNodeRoutableConnectionStats(long now) {
    statusBook.maybeUpdatePeerNodeRoutableConnectionStats(now);
  }

  /** Removes all opennet peers from the manager and updates alerts/listeners. */
  public void removeOpennetPeers() {
    roster.removeOpennetPeers();
    updatePMUserAlert();
    notifyPeerStatusChangeListeners();
  }

  @SuppressWarnings("unused")
  public PeerNode containsPeer(PeerNode pn) {
    return roster.containsPeer(pn);
  }

  /**
   * Counts connected darknet peers that are routable and not opennet.
   *
   * @return Number of connected darknet peers.
   */
  public int countConnectedDarknetPeers() {
    return roster.countConnectedDarknetPeers();
  }

  /**
   * Counts all connected and routable peers.
   *
   * @return Number of connected routable peers.
   */
  public int countConnectedPeers() {
    return roster.countConnectedPeers();
  }

  /**
   * Counts darknet peers that are connected (regardless of routability).
   *
   * @return Number of connected darknet peers.
   */
  public int countAlmostConnectedDarknetPeers() {
    return roster.countAlmostConnectedDarknetPeers();
  }

  /**
   * Counts darknet peers that are connected and routing-compatible.
   *
   * @return Number of compatible darknet peers.
   */
  public int countCompatibleDarknetPeers() {
    return roster.countCompatibleDarknetPeers();
  }

  /**
   * Counts peers with a real connection that are connected and routing-compatible.
   *
   * @return Number of compatible real peers.
   */
  public int countCompatibleRealPeers() {
    return roster.countCompatibleRealPeers();
  }

  /**
   * Counts connected opennet peers that are routable.
   *
   * @return Number of connected opennet peers.
   */
  public int countConnectedOpennetPeers() {
    return roster.countConnectedOpennetPeers();
  }

  /**
   * How many peers do we have that actually may connect? Don't include seednodes, disabled nodes,
   * etc.
   */
  public int countValidPeers() {
    return roster.countValidPeers();
  }

  /**
   * How many peers do we have that actually may connect? Don't include seednodes, disabled nodes,
   * etc.
   */
  public int countConnectiblePeers() {
    return roster.countConnectiblePeers();
  }

  /**
   * Counts peers that are seed servers or seed clients.
   *
   * @return Number of seed nodes.
   */
  public int countSeednodes() {
    return roster.countSeednodes();
  }

  /**
   * Counts peers currently in routing backoff.
   *
   * @param realTime If true, consider realtime backoff; otherwise bulk backoff.
   * @return Number of peers in backoff.
   */
  public int countBackedOffPeers(boolean realTime) {
    return roster.countBackedOffPeers(realTime);
  }

  /**
   * Returns the peer with the given public key hash, if present.
   *
   * @param pkHash ECDSA public key hash.
   * @return Matching peer or {@code null}.
   */
  public PeerNode getByPubKeyHash(byte[] pkHash) {
    return roster.getByPubKeyHash(pkHash);
  }

  void incrementSelectionSamples(PeerNode pn) {
    roster.incrementSelectionSamples(pn);
  }

  /** Notifies the listeners about the status change */
  private void notifyPeerStatusChangeListeners() {
    for (PeerStatusChangeListener l : listeners) {
      l.onPeerStatusChange();
      for (PeerNode pn : roster.myPeers()) {
        pn.registerPeerNodeStatusChangeListener(l);
      }
    }
  }

  /**
   * Registers a listener to be notified when peers' statuses change
   *
   * @param listener - the listener to be registered
   */
  public void addPeerStatusChangeListener(PeerStatusChangeListener listener) {
    listeners.add(listener);
    for (PeerNode pn : roster.myPeers()) {
      pn.registerPeerNodeStatusChangeListener(listener);
    }
  }

  /**
   * Removes a listener
   *
   * @param listener - The listener to be removed
   */
  @SuppressWarnings("unused")
  public void removePeerStatusChangeListener(PeerStatusChangeListener listener) {
    listeners.remove(listener);
  }

  /** A listener interface that can be used to be notified about peer status change events */
  public interface PeerStatusChangeListener {
    /** Peers status has changed */
    void onPeerStatusChange();
  }

  /**
   * Get a non-copied snapshot of the peers list. NOTE: LOW LEVEL: Should be up to date (but not
   * guaranteed when exit lock), DO NOT MODIFY THE RETURNED DATA! Package-local - stuff outside
   * node/ should use the copying getters (which are a little more expensive).
   *
   * @return peer array snapshot
   */
  public synchronized PeerNode[] myPeers() {
    return roster.myPeers();
  }

  /**
   * Get the last snapshot of the connected peers list. NOTE: This is not as reliable as using the
   * copying getters (or even using myPeers() and then checking each peer). But it is fast.
   *
   * <p>Note: Check all callers. Should they use myPeers and check for connectedness, and/or should
   * they use a copying method? I'm not sure how reliable updating of connectedPeers is ...
   *
   * @return connected peer array snapshot
   */
  public synchronized PeerNode[] connectedPeers() {
    return roster.connectedPeers();
  }

  /**
   * Count the number of PeerNode's with a given status (right now, not based on a snapshot). Note
   * you should not call this if holding lots of locks!
   */
  public int countByStatus(int status) {
    return roster.countByStatus(status);
  }

  // We can't trust our strangers, so need a consensus.
  public static final int OUTDATED_MIN_TOO_NEW_TOTAL = 5;
  // We can trust our friends, so only 1 is needed.
  public static final int OUTDATED_MIN_TOO_NEW_DARKNET = 1;
  public static final int OUTDATED_MAX_CONNS = 5;

  /**
   * Heuristically determines whether this node is likely outdated.
   *
   * <p>Uses counts of peers reporting "too new" status and current connections to infer whether an
   * upgrade is likely required. Intended for UI hints, not a strict protocol check.
   *
   * @return {@code true} if heuristics indicate the node is outdated; otherwise {@code false}.
   */
  public boolean isOutdated() {

    int tooNewDarknet = getPeerNodeStatusSize(PEER_NODE_STATUS_TOO_NEW, true);

    if (tooNewDarknet >= OUTDATED_MIN_TOO_NEW_DARKNET) return true;

    int tooNewOpennet = getPeerNodeStatusSize(PEER_NODE_STATUS_TOO_NEW, false);

    // Note: the constants below are heuristics and may require tuning.
    // We cannot count on the version announcements.
    // Until we actually get a validated update jar, it's all potentially bogus.

    int connections =
        getPeerNodeStatusSize(PEER_NODE_STATUS_CONNECTED, false)
            + getPeerNodeStatusSize(PEER_NODE_STATUS_ROUTING_BACKED_OFF, false);

    if (tooNewOpennet >= OUTDATED_MIN_TOO_NEW_TOTAL) {
      return connections < OUTDATED_MAX_CONNS;
    } else return false;
  }
}

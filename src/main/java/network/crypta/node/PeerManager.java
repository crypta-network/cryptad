package network.crypta.node;

import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.BufferedReader;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.Peer;
import network.crypta.io.comm.PeerParseException;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.keys.Key;
import network.crypta.node.DarknetPeerNode.FRIEND_TRUST;
import network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY;
import network.crypta.node.useralerts.DroppedOldPeersUserAlert;
import network.crypta.node.useralerts.PeerManagerUserAlert;
import network.crypta.support.ByteArrayWrapper;
import network.crypta.support.ShortBuffer;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.TimeUtil;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.NativeThread;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates darknet and opennet peers for the local node.
 *
 * <p>Responsibilities include maintaining the desired peer set (configured + discovered), tracking
 * currently connected peers, recording per-peer status, selecting routing targets, and persisting
 * peer references to disk. The manager also exposes helper queries for counts, lookups, and status
 * summaries, and emits user alerts summarizing connectivity.
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

  /** All the peers we want to connect to */
  private PeerNode[] myPeers;

  /** All the peers we are actually connected to */
  private PeerNode[] connectedPeers;

  private String darkFilename;
  private String openFilename;
  private String oldOpennetPeersFilename;
  // Note: Potential improvement: use a dedicated stable hash (not hashCode()).
  // Note: Potential improvement: strip non-essential metadata; keep peer locations only.
  private String darknetPeersStringCache = null;
  private String opennetPeersStringCache = null;
  private String oldOpennetPeersStringCache = null;
  private PeerManagerUserAlert ua; // Peers stuff
  private final Object uaLock = new Object();

  /** age of oldest never connected peer (milliseconds) */
  private long oldestNeverConnectedDarknetPeerAge;

  /** Next time to update oldestNeverConnectedPeerAge */
  private long nextOldestNeverConnectedDarknetPeerAgeUpdateTime = -1;

  /** oldestNeverConnectedPeerAge update interval (milliseconds) */
  private static final long OLDEST_NEVER_CONNECTED_DARKNET_PEER_AGE_UPDATE_INTERVAL = 5000;

  /** Next time to log the PeerNode status summary */
  private long nextPeerNodeStatusLogTime = -1;

  /** PeerNode status summary log interval (milliseconds) */
  private static final long PEER_NODE_STATUS_LOG_INTERVAL = 5000;

  /** Statuses for all PeerNode's */
  private final PeerStatusTracker<Integer> allPeersStatuses;

  /** Statuses for darknet PeerNode's */
  private final PeerStatusTracker<Integer> darknetPeersStatuses;

  /** PeerNode routing backoff reasons, by reason (realtime) */
  private final PeerStatusTracker<String> peerNodeRoutingBackoffReasonsRT;

  /** PeerNode routing backoff reasons, by reason (bulk) */
  private final PeerStatusTracker<String> peerNodeRoutingBackoffReasonsBulk;

  /** Next time to update routableConnectionStats */
  private long nextRoutableConnectionStatsUpdateTime = -1;

  /** routableConnectionStats update interval (milliseconds) */
  private static final long ROUTABLE_CONNECTION_STATS_UPDATE_INTERVAL = SECONDS.toMillis(7);

  /** Should update the peer-file ? */
  private volatile boolean shouldWritePeersDarknet = false;

  private volatile boolean shouldWritePeersOpennet = false;
  private static final long MIN_WRITEPEERS_DELAY =
      MINUTES.toMillis(5); // Urgent stuff calls write*PeersUrgent.
  private final Runnable writePeersRunnable =
      () -> {
        try {
          writePeersNow();
        } finally {
          scheduleWritePeersNextRun();
        }
      };

  private void scheduleWritePeersNextRun() {
    node.getTicker().queueTimedJob(writePeersRunnable, MIN_WRITEPEERS_DELAY);
  }

  protected void writePeersNow() {
    // Non-urgent periodic write does not rotate backups.
    writePeersDarknetNow(false);
    writePeersOpennetNow(false);
  }

  private void writePeersDarknetNow(boolean rotateBackups) {
    if (shouldWritePeersDarknet) {
      shouldWritePeersDarknet = false;
      writePeersInnerDarknet(rotateBackups);
    }
  }

  private void writePeersOpennetNow(boolean rotateBackups) {
    if (shouldWritePeersOpennet) {
      shouldWritePeersOpennet = false;
      writePeersInnerOpennet(rotateBackups);
    }
  }

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
   * @param node Owning node instance. Must be fully constructed before invoking methods that call
   *     back into {@code node}.
   * @param shutdownHook Hook used to register an early job that writes peers to disk on shutdown.
   */
  public PeerManager(Node node, SemiOrderedShutdownHook shutdownHook) {
    LOG.info("PeerManager initialization start");
    peerNodeRoutingBackoffReasonsRT = new PeerStatusTracker<>();
    peerNodeRoutingBackoffReasonsBulk = new PeerStatusTracker<>();
    allPeersStatuses = new PeerStatusTracker<>();
    darknetPeersStatuses = new PeerStatusTracker<>();
    LOG.info("PeerManager initialized");
    myPeers = new PeerNode[0];
    connectedPeers = new PeerNode[0];
    this.node = node;
    shutdownHook.addEarlyJob(
        new Thread(
            () -> {
              // Ensure we're not waiting 5mins here
              writePeersDarknet();
              writePeersOpennet();
              writePeersNow();
            }));
  }

  private static final String READ_PREFIX = "Read ";

  /**
   * Attempt to read a file full of noderefs. Try the file as named first, then the .bak if it is
   * empty or otherwise doesn't work. WARNING: Only call this AFTER the Node constructor has
   * completed! Methods may be called on Node!
   *
   * @param filename The filename to read from. If this doesn't work, we try the .bak file.
   * @param crypto The cryptographic identity which these nodes are connected to.
   * @param opennet The opennet manager for the nodes. Only needed (for constructing the nodes) if
   *     isOpennet.
   * @param isOpennet Whether the file contains opennet peers.
   * @param oldOpennetPeers If true, don't add the nodes to the routing table, pass them to the
   *     opennet manager as "old peers" i.e. inactive nodes which may try to reconnect.
   */
  void tryReadPeers(
      String filename,
      NodeCrypto crypto,
      OpennetManager opennet,
      boolean isOpennet,
      boolean oldOpennetPeers) {
    synchronized (writePeersSync) {
      if (!oldOpennetPeers) {
        if (isOpennet) {
          openFilename = filename;
        } else {
          darkFilename = filename;
        }
      }
    }
    int maxBackups = isOpennet ? BACKUPS_OPENNET : BACKUPS_DARKNET;
    for (int i = 0; i <= maxBackups; i++) {
      File peersFile = this.getBackupFilename(filename, i);
      // Try to read the node list from disk
      if (peersFile.exists() && readPeers(peersFile, crypto, opennet, oldOpennetPeers)) {
        String msg;
        if (oldOpennetPeers) {
          msg =
              READ_PREFIX + opennet.countOldOpennetPeers() + " old-opennet-peers from " + peersFile;
        } else if (isOpennet) {
          msg = READ_PREFIX + getOpennetPeers().length + " opennet peers from " + peersFile;
        } else {
          msg = READ_PREFIX + getDarknetPeers().length + " darknet peers from " + peersFile;
        }
        LOG.info(msg);
        return;
      }
    }
    if (!isOpennet) {
      LOG.info("No darknet peers file found.");
    }
    // The other cases are less important.
  }

  @SuppressWarnings("java:S1181")
  private boolean readPeers(
      File peersFile, NodeCrypto crypto, OpennetManager opennet, boolean oldOpennetPeers) {
    boolean someBroken;
    File brokenPeersFile = new File(peersFile.getPath() + ".broken");
    DroppedOldPeersUserAlert droppedOldPeers = new DroppedOldPeersUserAlert(brokenPeersFile);
    List<SimpleFieldSet> peerEntries = new ArrayList<>();
    // read the peers file
    try (FileInputStream fis = new FileInputStream(peersFile);
        InputStreamReader ris = new InputStreamReader(fis, StandardCharsets.UTF_8);
        BufferedReader br = new BufferedReader(ris)) {
      readPeerFieldSets(br, peerEntries);
    } catch (FileNotFoundException e4) {
      LOG.info("Peers file not found: {}", peersFile);
      return false;
    } catch (IOException e3) {
      LOG.error("Read error {} on {}", e3, peersFile, e3);
    }

    List<PeerNode> createdNodes =
        createPeerNodesFromEntries(peerEntries, crypto, opennet, droppedOldPeers);
    // Consider the file "broken" if we could not create all peers (parse errors or too-old entries)
    someBroken = (createdNodes.size() != peerEntries.size());
    applyCreatedNodes(createdNodes, opennet, oldOpennetPeers);
    if (someBroken) {
      try {
        safeDeleteIfExists(brokenPeersFile);
        try (FileOutputStream fos = new FileOutputStream(brokenPeersFile);
            FileInputStream fis = new FileInputStream(peersFile)) {
          FileUtil.copy(fis, fos, -1);
        }
        LOG.warn("Broken peers file copied to {}", brokenPeersFile);
      } catch (IOException e) {
        LOG.warn("Unable to copy broken peers file");
      }
    }
    if (!droppedOldPeers.isEmpty()) {
      try {
        node.getClientCore().getAlerts().register(droppedOldPeers);
        LOG.error(droppedOldPeers.getText());
      } catch (Throwable t) {
        // Startup MUST complete, don't let client layer problems kill it.
        LOG.error("Caught error telling user about dropped peers", t);
      }
    }
    return !someBroken;
  }

  private List<PeerNode> createPeerNodesFromEntries(
      List<SimpleFieldSet> peerEntries,
      NodeCrypto crypto,
      OpennetManager opennet,
      DroppedOldPeersUserAlert droppedOldPeers) {
    List<PeerNode> created = new ArrayList<>();
    for (SimpleFieldSet fs : peerEntries) {
      try {
        created.add(PeerNode.create(fs, node, crypto, opennet, this));
      } catch (FSParseException
          | PeerParseException
          | ReferenceSignatureVerificationException
          | RuntimeException e2) {
        handlePeerCreationException(e2, fs);
      } catch (PeerTooOldException e) {
        if (crypto.isOpennet()) {
          LOG.error("Dropping too-old opennet peer");
        } else {
          droppedOldPeers.add(e, fs.get("myName"));
        }
      }
    }
    // Always return successfully parsed peers; callers decide whether some entries were broken.
    return created;
  }

  private void applyCreatedNodes(
      List<PeerNode> createdNodes, OpennetManager opennet, boolean oldOpennetPeers) {
    for (PeerNode pn : createdNodes) {
      if (oldOpennetPeers) {
        if (pn instanceof OpennetPeerNode opennetpeernode) {
          opennet.addOldOpennetNode(opennetpeernode);
        } else {
          LOG.error("Darknet node in old opennet peers: {}", pn);
        }
      } else {
        addPeer(pn, true, false);
      }
    }
  }

  private void handlePeerCreationException(Exception e2, SimpleFieldSet fs) {
    LOG.error("Peer parse error {} for {}", e2, fs, e2);
    LOG.warn("Cannot parse friend from peers file: {}", e2, e2);
  }

  private static void readPeerFieldSets(BufferedReader br, List<SimpleFieldSet> out)
      throws IOException {
    for (SimpleFieldSet sfs = readNextPeerFieldSet(br);
        sfs != null;
        sfs = readNextPeerFieldSet(br)) {
      out.add(sfs);
    }
  }

  private static SimpleFieldSet readNextPeerFieldSet(BufferedReader br) throws IOException {
    try {
      return new SimpleFieldSet(br, false, true);
    } catch (EOFException eof) {
      return null; // end-of-file reached
    }
  }

  private static void safeDeleteIfExists(File file) {
    try {
      java.nio.file.Files.deleteIfExists(file.toPath());
    } catch (IOException ignore) {
      // best-effort
    }
  }

  public boolean addPeer(PeerNode pn) {
    return addPeer(pn, false, false);
  }

  /**
   * Add a peer.
   *
   * @param pn The node to add to the routing table.
   * @param ignoreOpennet If true, don't check for opennet peers. If false, check for opennet peers
   *     and if so, if opennet is enabled auto-add them to the opennet LRU, otherwise fail.
   * @param reactivate If true, re-enable the peer if it is in state DISCONNECTING before re-adding
   *     it.
   * @return True if the node was successfully added. False if it was already present, or if we
   *     tried to add an opennet peer when opennet was disabled.
   */
  boolean addPeer(PeerNode pn, boolean ignoreOpennet, boolean reactivate) {
    assert (pn != null);
    if (reactivate) pn.forceCancelDisconnecting();
    synchronized (this) {
      for (PeerNode myPeer : myPeers) {
        if (myPeer.equals(pn)) {
          if (LOG.isDebugEnabled())
            LOG.debug(
                "Can't add peer {} because already have {}", pn, myPeer, new Exception("debug"));
          return false;
        }
      }
      myPeers = Arrays.copyOf(myPeers, myPeers.length + 1);
      myPeers[myPeers.length - 1] = pn;
      LOG.info("Added {}", pn);
    }
    if (pn.recordStatus()) addPeerNodeStatus(pn.getPeerNodeStatus(), pn);
    pn.setPeerNodeStatus(System.currentTimeMillis());
    if ((!ignoreOpennet) && pn instanceof OpennetPeerNode peerNode) {
      OpennetManager opennet = node.getOpennet();
      if (opennet != null) opennet.forceAddPeer(peerNode, true);
      else {
        LOG.error("Adding opennet peer when opennet is disabled: {} - removing", pn);
        removePeer(pn);
        return false;
      }
    }
    notifyPeerStatusChangeListeners();
    if (!pn.isSeed()) {
      // LOCKING: addPeer() can be called inside PM lock, so must do this on a separate thread.
      node.getExecutor().execute(this::updatePMUserAlert);
    }
    return true;
  }

  synchronized boolean havePeer(PeerNode pn) {
    for (PeerNode myPeer : myPeers) {
      if (myPeer == pn) return true;
    }
    return false;
  }

  /** Remove a PeerNode. LOCKING: Caller should not hold locks on any PeerNode. */
  @SuppressWarnings("UnusedReturnValue")
  private boolean removePeer(PeerNode pn) {
    if (LOG.isDebugEnabled()) LOG.debug("Removing {}", pn);
    boolean isInPeers;
    synchronized (this) {
      isInPeers = isPeerPresent(pn);
      if (pn instanceof DarknetPeerNode peerNode) peerNode.removeExtraPeerDataDir();
      if (isInPeers) {
        updateTrackersOnRemove(pn);
        rebuildPeerArraysOnRemove(pn);
        LOG.info("Removed {}", pn);
      }
    }
    pn.onRemove();
    if (isInPeers && !pn.isSeed()) updatePMUserAlert();
    notifyPeerStatusChangeListeners();
    updatePMUserAlert();
    return true;
  }

  private boolean isPeerPresent(PeerNode pn) {
    // Delegate to the synchronized variant to avoid duplicate implementations.
    return havePeer(pn);
  }

  private void updateTrackersOnRemove(PeerNode pn) {
    int peerNodeStatus = pn.getPeerNodeStatus();
    if (pn.recordStatus()) removePeerNodeStatus(peerNodeStatus, pn);
    String prevReason = pn.getPreviousBackoffReason(true);
    if (prevReason != null) removePeerNodeRoutingBackoffReason(prevReason, pn, true);
    prevReason = pn.getPreviousBackoffReason(false);
    if (prevReason != null) removePeerNodeRoutingBackoffReason(prevReason, pn, false);
  }

  private void rebuildPeerArraysOnRemove(PeerNode pn) {
    ArrayList<PeerNode> a = new ArrayList<>();
    for (PeerNode mp : myPeers) {
      if ((mp != pn) && mp.isConnected() && mp.isRealConnection()) a.add(mp);
    }
    connectedPeers = a.toArray(new PeerNode[0]);

    PeerNode[] newMyPeers = new PeerNode[myPeers.length - 1];
    int positionInNewArray = 0;
    for (PeerNode mp : myPeers) {
      if (mp != pn) newMyPeers[positionInNewArray++] = mp;
    }
    myPeers = newMyPeers;
  }

  @SuppressWarnings("UnusedReturnValue")
  public boolean removeAllPeers() {
    LOG.info("Removing all peers");
    PeerNode[] oldPeers;
    synchronized (this) {
      oldPeers = myPeers;
      myPeers = new PeerNode[0];
      connectedPeers = new PeerNode[0];
    }
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
    synchronized (this) {
      boolean isInPeers = false;
      for (PeerNode connectedPeer : connectedPeers) {
        if (connectedPeer == pn) {
          isInPeers = true;
          break;
        }
      }
      if (!isInPeers) return false;
      // removing from connectedPeers
      ArrayList<PeerNode> a = new ArrayList<>();
      for (PeerNode mp : myPeers) {
        if ((mp != pn) && mp.isRoutable()) a.add(mp);
      }
      PeerNode[] newConnectedPeers = new PeerNode[a.size()];
      newConnectedPeers = a.toArray(newConnectedPeers);
      connectedPeers = newConnectedPeers;
    }
    if (!pn.isSeed()) updatePMUserAlert();
    node.getLocationManager().announceLocChange();
    return true;
  }

  long timeFirstAnyConnections = 0;

  /**
   * Returns the timestamp of the first successful connection since startup.
   *
   * @return Epoch milliseconds of first connection, or 0 if none yet.
   */
  public long getTimeFirstAnyConnections() {
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
      if (isAlreadyConnected(pn)) return;
      ensurePeerPresent(pn);
      addToConnectedPeers(pn);
    }
    if (!pn.isSeed()) updatePMUserAlert();
    node.getLocationManager().announceLocChange();
  }

  private boolean isAlreadyConnected(PeerNode pn) {
    for (PeerNode connectedPeer : connectedPeers) {
      if (connectedPeer == pn) {
        if (LOG.isDebugEnabled()) LOG.debug("Already connected: {}", pn);
        return true;
      }
    }
    return false;
  }

  private void ensurePeerPresent(PeerNode pn) {
    boolean inMyPeers = false;
    for (PeerNode mp : myPeers) {
      if (mp == pn) {
        inMyPeers = true;
        break;
      }
    }
    if (!inMyPeers) {
      LOG.error("Connecting to {} but not in peers", pn);
      // Note: addPeer() called while holding PM lock; this mirrors historical behavior.
      addPeer(pn);
    }
  }

  private void addToConnectedPeers(PeerNode pn) {
    if (LOG.isDebugEnabled()) LOG.debug("Connecting: {}", pn);
    connectedPeers = Arrays.copyOf(connectedPeers, connectedPeers.length + 1);
    connectedPeers[connectedPeers.length - 1] = pn;
    if (LOG.isDebugEnabled()) LOG.debug("Connected peers: {}", connectedPeers.length);
  }

  /**
   * Returns the peer matching the given {@code Peer} address (IP and port).
   *
   * <p>Used by {@link FNPPacketMangler} to quickly identify an incoming connection. Includes peers
   * that are not real connections because they may still be connected.
   *
   * @param peer The transport-layer peer descriptor (contains IP and port).
   * @return The matching {@link PeerNode}, or {@code null} if not found.
   */
  public PeerNode getByPeer(Peer peer) {
    PeerNode[] peerList = myPeers();
    for (PeerNode pn : peerList) {
      if (pn.isDisabled()) continue;
      if (pn.matchesPeerAndPort(peer)) return pn;
    }
    // Try a match by IP address if we can't match exactly by IP:port.
    FreenetInetAddress addr = peer.getFreenetAddress();
    for (PeerNode pn : peerList) {
      if (pn.isDisabled()) continue;
      if (pn.matchesIP(addr, false)) return pn;
    }
    return null;
  }

  /**
   * Returns the peer that matches the given {@code Peer} address and outgoing mangler.
   *
   * <p>If an exact IP:port match is not found, falls back to an IP-only match. Only peers using the
   * provided outgoing mangler are considered.
   *
   * @param peer The transport-layer peer descriptor (contains IP and port).
   * @param mangler The expected outgoing packet mangler instance.
   * @return The matching {@link PeerNode}, or {@code null} if not found.
   */
  public PeerNode getByPeer(Peer peer, FNPPacketMangler mangler) {
    PeerNode[] peerList = myPeers();
    for (PeerNode pn : peerList) {
      if (pn.isDisabled()) continue;
      if (pn.matchesPeerAndPort(peer) && pn.getOutgoingMangler() == mangler) return pn;
    }
    // Try a match by IP address if we can't match exactly by IP:port.
    FreenetInetAddress addr = peer.getFreenetAddress();
    for (PeerNode pn : peerList) {
      if (pn.isDisabled()) continue;
      if (pn.matchesIP(addr, false) && pn.getOutgoingMangler() == mangler) return pn;
    }
    return null;
  }

  /**
   * Finds connected, routable peers with a given IP address.
   *
   * @param a IP address to match.
   * @param strict When true, require an exact match; otherwise allow non-strict matches as defined
   *     by {@link PeerNode#matchesIP(FreenetInetAddress, boolean)}.
   * @return A list of matching peers (may be empty), or {@code null} if none found.
   */
  public List<PeerNode> getAllConnectedByAddress(FreenetInetAddress a, boolean strict) {
    List<PeerNode> found = null;

    PeerNode[] peerList = myPeers();
    // Try a match by IP address if we can't match exactly by IP:port.
    for (PeerNode pn : peerList) {
      boolean eligible = pn.isConnected() && pn.isRoutable() && pn.matchesIP(a, strict);
      if (eligible) {
        if (found == null) found = new ArrayList<>();
        found.add(pn);
      }
    }
    return found;
  }

  /**
   * Connects to a darknet peer from its serialized reference.
   *
   * <p>Creates a new {@link DarknetPeerNode} from the provided field set and adds it if a peer with
   * the same public key hash is not already present.
   *
   * @param noderef Serialized darknet peer reference.
   * @param trust Initial friend trust.
   * @param visibility Initial friend visibility.
   * @throws FSParseException If the field set cannot be parsed.
   * @throws PeerParseException If the noderef is syntactically invalid.
   * @throws ReferenceSignatureVerificationException If the reference signature fails verification.
   * @throws PeerTooOldException If the peer is older than the supported minimum.
   */
  public void connect(SimpleFieldSet noderef, FRIEND_TRUST trust, FRIEND_VISIBILITY visibility)
      throws FSParseException,
          PeerParseException,
          ReferenceSignatureVerificationException,
          PeerTooOldException {
    PeerNode pn = node.createNewDarknetNode(noderef, trust, visibility);
    PeerNode[] peerList = myPeers();
    for (PeerNode mp : peerList) {
      if (Arrays.equals(mp.peerECDSAPubKeyHash, pn.peerECDSAPubKeyHash)) return;
    }
    addPeer(pn);
  }

  /**
   * Disconnects a peer and removes it from the routing table.
   *
   * @param pn Peer to disconnect.
   * @param sendDisconnectMessage If true, send a protocol disconnect message.
   * @param waitForAck If true, wait for the disconnect acknowledgment before removal.
   * @param purge If true, request the remote to purge this node from old-peer state.
   */
  public void disconnectAndRemove(
      final PeerNode pn, boolean sendDisconnectMessage, final boolean waitForAck, boolean purge) {
    disconnect(pn, sendDisconnectMessage, waitForAck, purge, false, true, Node.MAX_PEER_INACTIVITY);
  }

  /**
   * Disconnects from a specified node.
   *
   * @param pn Peer to disconnect.
   * @param sendDisconnectMessage If false, do not send the protocol disconnect message.
   * @param waitForAck If false, do not wait for the disconnect acknowledgment.
   * @param purge If true, request the remote to purge this node from old-peer lists.
   * @param dumpMessagesNow If true, drop queued messages immediately before completing disconnect.
   * @param remove If true, remove the peer locally after disconnect.
   * @param timeout Timeout in milliseconds to wait before completing removal if still
   *     disconnecting.
   */
  public void disconnect(
      final PeerNode pn,
      boolean sendDisconnectMessage,
      final boolean waitForAck,
      boolean purge,
      boolean dumpMessagesNow,
      final boolean remove,
      long timeout) {
    if (LOG.isDebugEnabled()) LOG.debug("Disconnecting {}", pn.shortToString());
    if (!shouldProceedWithDisconnect(pn, dumpMessagesNow)) return;
    if (sendDisconnectMessage) {
      Message msg = createDisconnectMessage(remove, purge);
      try {
        pn.sendAsync(msg, createDisconnectCallback(pn, remove, waitForAck), ctrDisconn);
      } catch (NotConnectedException e) {
        removePeerIfRequested(pn, remove);
        return;
      }
      scheduleDisconnectTimeoutHandling(pn, remove, timeout);
    } else {
      if (remove) {
        removePeer(pn);
        if (!pn.isSeed()) writePeersUrgent(pn.isOpennet());
      }
    }
  }

  private AsyncMessageCallback createDisconnectCallback(
      final PeerNode pn, final boolean remove, final boolean waitForAck) {
    return new AsyncMessageCallback() {
      boolean done = false;

      @Override
      public void acknowledged() {
        markDone();
      }

      @Override
      public void disconnected() {
        markDone();
      }

      @Override
      public void fatalError() {
        markDone();
      }

      @Override
      public void sent() {
        if (!waitForAck) markDone();
      }

      void markDone() {
        synchronized (this) {
          if (done) return;
          done = true;
        }
        if (remove) {
          removePeer(pn);
          if (!pn.isSeed()) writePeersUrgent(pn.isOpennet());
        }
      }
    };
  }

  private boolean shouldProceedWithDisconnect(PeerNode pn, boolean dumpMessagesNow) {
    synchronized (this) {
      if (!havePeer(pn)) return false;
    }
    if (pn.notifyDisconnecting(dumpMessagesNow)) {
      if (LOG.isDebugEnabled()) LOG.debug("Already disconnecting {}", pn.shortToString());
      return false;
    }
    return true;
  }

  private static Message createDisconnectMessage(boolean remove, boolean purge) {
    return DMT.createFNPDisconnect(remove, purge, -1, new ShortBuffer(new byte[0]));
  }

  private void removePeerIfRequested(PeerNode pn, boolean remove) {
    if (remove && pn.isDisconnecting()) {
      removePeer(pn);
      if (!pn.isSeed()) {
        writePeersUrgent(pn.isOpennet());
      }
    }
  }

  private void scheduleDisconnectTimeoutHandling(PeerNode pn, boolean remove, long timeout) {
    if (pn.isSeed()) return;
    node.getTicker()
        .queueTimedJob(
            () -> {
              if (pn.isDisconnecting()) {
                if (remove) {
                  removePeer(pn);
                  if (!pn.isSeed()) {
                    writePeersUrgent(pn.isOpennet());
                  }
                }
                pn.disconnected(true, true);
              }
            },
            timeout);
  }

  final ByteCounter ctrDisconn =
      new ByteCounter() {

        @Override
        public void receivedBytes(int x) {
          node.getNodeStats().disconnBytesReceived(x);
        }

        @Override
        public void sentBytes(int x) {
          node.getNodeStats().disconnBytesSent(x);
        }

        @Override
        public void sentPayload(int x) {
          // Ignore
        }
      };

  /**
   * Returns the current locations of connected peers as doubles in [0.0, 1.0).
   *
   * @param pruneBackedOffPeers When true, omit peers excluded from lists due to backoff.
   * @return A sorted array of peer locations, or an empty array when publishing is disabled.
   */
  public double[] getPeerLocationDoubles(boolean pruneBackedOffPeers) {
    if (!node.shallWePublishOurPeersLocation()) return new double[0];
    PeerNode[] conns = connectedPeers();
    double[] locs = collectPeerLocations(conns, pruneBackedOffPeers);
    Arrays.sort(locs);
    return locs;
  }

  private static double[] collectPeerLocations(PeerNode[] peers, boolean pruneBackedOffPeers) {
    java.util.ArrayList<Double> tmp = new java.util.ArrayList<>();
    for (PeerNode conn : peers) {
      if (conn.isRoutable() && (!pruneBackedOffPeers || !conn.shouldBeExcludedFromPeerList())) {
        tmp.add(conn.getLocation());
      }
    }
    double[] locs = new double[tmp.size()];
    for (int i = 0; i < tmp.size(); i++) locs[i] = tmp.get(i);
    return locs;
  }

  /**
   * @return A random routable connected peer. Note: consider taking performance into account. DO
   *     NOT remove the "synchronized". See below for why.
   */
  public synchronized PeerNode getRandomPeer(PeerNode exclude) {
    if (connectedPeers.length == 0) return null;
    PeerNode candidate = attemptRandomRoutable(exclude);
    if (candidate != null) return candidate;
    int lengthWithoutExcluded = rebuildConnectedPeersExcluding(exclude);
    if (lengthWithoutExcluded == 0) return null;
    return connectedPeers[node.getRandom().nextInt(lengthWithoutExcluded)];
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
    if ((exclude != null) && exclude.isRoutable()) v.add(exclude);
    PeerNode[] newConnectedPeers = v.toArray(new PeerNode[0]);
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Connected peers in getRandomPeer: {} was {}",
          newConnectedPeers.length,
          connectedPeers.length);
    connectedPeers = newConnectedPeers;
    return lengthWithoutExcluded;
  }

  public void localBroadcast(
      Message msg, boolean ignoreRoutability, boolean onlyRealConnections, ByteCounter ctr) {
    localBroadcast(
        msg, ignoreRoutability, onlyRealConnections, ctr, Integer.MIN_VALUE, Integer.MAX_VALUE);
  }

  /**
   * Asynchronously sends a message to all eligible peers.
   *
   * @param msg Message to send.
   * @param ignoreRoutability When true, send to connected peers even if not routable.
   * @param onlyRealConnections When true, exclude non-real connections.
   * @param ctr Counter to attribute bytes to.
   * @param minVersion Minimum accepted build number (inclusive).
   * @param maxVersion Maximum accepted build number (inclusive).
   */
  public void localBroadcast(
      Message msg,
      boolean ignoreRoutability,
      boolean onlyRealConnections,
      ByteCounter ctr,
      int minVersion,
      int maxVersion) {
    // myPeers not connectedPeers as connectedPeers only contains
    // ROUTABLE peers, and we may want to send to non-routable peers
    PeerNode[] peers = myPeers();
    for (PeerNode peer : peers) {
      if (!shouldSendLocal(peer, ignoreRoutability, onlyRealConnections, minVersion, maxVersion))
        continue;
      try {
        peer.sendAsync(msg, null, ctr);
      } catch (NotConnectedException e) {
        // Ignore
      }
    }
  }

  private static boolean shouldSendLocal(
      PeerNode peer,
      boolean ignoreRoutability,
      boolean onlyRealConnections,
      int minVersion,
      int maxVersion) {
    int version = peer.getBuildNumber();
    boolean routableOrConnected = ignoreRoutability ? peer.isConnected() : peer.isRoutable();
    return routableOrConnected
        && (!onlyRealConnections || peer.isRealConnection())
        && version >= minVersion
        && version <= maxVersion;
  }

  /** Asynchronously sends a differential node reference to every connected peer. */
  public void locallyBroadcastDiffNodeRef(
      SimpleFieldSet fs, boolean toDarknetOnly, boolean toOpennetOnly) {
    // myPeers not connectedPeers as connectedPeers only contains
    // ROUTABLE peers, and we want to also send to non-routable peers
    PeerNode[] peers = myPeers();
    for (PeerNode peer : peers) {
      boolean okDarknet = !toDarknetOnly || peer.isDarknet();
      boolean okOpennet = !toOpennetOnly || peer.isOpennet();
      if (peer.isConnected() && okDarknet && okOpennet) {
        peer.sendNodeToNodeMessage(fs, Node.N2N_MESSAGE_TYPE_DIFFNODEREF, false, 0, false);
      }
    }
  }

  /** Returns a random routable connected peer, or {@code null} if none. */
  public PeerNode getRandomPeer() {
    return getRandomPeer(null);
  }

  public PeerNode closerPeer(
      PeerNode pn,
      Set<PeerNode> routedTo,
      double loc,
      boolean ignoreSelf,
      boolean calculateMisrouting,
      int minVersion,
      List<Double> addUnpickedLocsTo,
      Key key,
      short outgoingHTL,
      long ignoreBackoffUnder,
      boolean isLocal,
      boolean realTime,
      boolean excludeMandatoryBackoff) {
    return closerPeer(
        pn,
        routedTo,
        loc,
        ignoreSelf,
        calculateMisrouting,
        minVersion,
        addUnpickedLocsTo,
        2.0,
        key,
        outgoingHTL,
        ignoreBackoffUnder,
        isLocal,
        realTime,
        null,
        false,
        System.currentTimeMillis(),
        excludeMandatoryBackoff);
  }

  /**
   * Find the peer, if any, which is closer to the target location than we are, and is not included
   * in the provided set. If ignoreSelf==false, and we are closer to the target than any peers, this
   * function returns null. This function returns two values, the closest such peer which is backed
   * off, and the same which is not backed off. It is possible for either to be null independent of
   * the other, 'closest' is the closer of the two in either case, and will not be null if any of
   * the other two return values is not null. LOCKING: This will briefly take various locks, try to
   * avoid calling it with lots of locks held.
   *
   * @param addUnpickedLocsTo Add all locations we didn't choose which we could have routed to to
   *     this array. Remove the location of the peer we pick from it.
   * @param maxDistance If a node is further away from the target than this distance, ignore it.
   * @param key The original key, if we have it, and if we want to consult with the FailureTable to
   *     avoid routing to nodes which have recently failed for the same key.
   * @param isLocal We don't just check pn == null because in some cases pn can be null here: If an
   *     insert is forked, for a remote requests, we can route back to the originator, so we set pn
   *     to null. Whereas for stats we want to know accurately whether this was originated remotely.
   * @param recentlyFailed If non-null, we should check for recently failed: If we have routed to,
   *     and got a failed response from, and are still connected to and within the timeout for, our
   *     top two routing choices, *and* the same is true of at least 3 nodes, we fill in this object
   *     and return null. This will cause a RecentlyFailed message to be returned to the originator,
   *     allowing them to retry in a little while. Note: the scheduler is currently not designed to
   *     retry immediately when that timeout elapses; re-evaluating this behavior may be beneficial
   *     to avoid introducing a round-trip to the request originator.
   */
  public PeerNode closerPeer(
      PeerNode pn,
      Set<PeerNode> routedTo,
      double target,
      boolean ignoreSelf,
      boolean calculateMisrouting,
      int minVersion,
      List<Double> addUnpickedLocsTo,
      double maxDistance,
      Key key,
      short outgoingHTL,
      long ignoreBackoffUnder,
      boolean isLocal,
      boolean realTime,
      RecentlyFailedReturn recentlyFailed,
      boolean ignoreTimeout,
      long now,
      boolean newLoadManagement) {
    CloserPeerContext ctx = initCloserPeerContext(pn, routedTo, target, ignoreSelf, key);
    evaluateCandidatesInContext(
        ctx,
        pn,
        routedTo,
        minVersion,
        now,
        realTime,
        ignoreTimeout,
        outgoingHTL,
        target,
        maxDistance,
        ignoreSelf,
        addUnpickedLocsTo,
        ignoreBackoffUnder,
        newLoadManagement);

    BestCandidate bestCand = selectBestCandidate(ctx.st, ctx.key);
    if (recentlyFailed != null && LOG.isDebugEnabled())
      LOG.debug("Count waiting: {}", ctx.st.countWaiting);

    PeerNode best =
        handleRecentlyFailedIfNeeded(
            bestCand.best,
            bestCand.bestDistance,
            recentlyFailed,
            ctx,
            pn,
            routedTo,
            target,
            ignoreSelf,
            minVersion,
            maxDistance,
            outgoingHTL,
            ignoreBackoffUnder,
            isLocal,
            realTime,
            now,
            newLoadManagement);
    if (best == null) return null;

    reportBackoffPercentIfNeeded(calculateMisrouting);
    postSelectionUpdate(best, calculateMisrouting, addUnpickedLocsTo, ctx.st);
    return best;
  }

  private void reportBackoffPercentIfNeeded(boolean calculateMisrouting) {
    if (!calculateMisrouting) return;
    int connected = getPeerNodeStatusSize(PEER_NODE_STATUS_CONNECTED, false);
    int backedOff = getPeerNodeStatusSize(PEER_NODE_STATUS_ROUTING_BACKED_OFF, false);
    if (backedOff + connected > 0)
      node.getNodeStats()
          .backedOffPercent
          .report((double) backedOff / (double) (backedOff + connected));
  }

  private record SelectionRates(double[] rates, double total) {
    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (!(o instanceof SelectionRates(double[] rates1, double total1))) return false;
      return Double.compare(total1, total) == 0 && java.util.Arrays.equals(rates, rates1);
    }

    @Override
    public int hashCode() {
      int result = java.util.Arrays.hashCode(rates);
      result = 31 * result + Double.hashCode(total);
      return result;
    }

    @Override
    public @NotNull String toString() {
      return "SelectionRates[rates=" + java.util.Arrays.toString(rates) + ", total=" + total + "]";
    }
  }

  private static final class CloserPeerContext {
    final PeerNode[] peers;
    final Key key;
    final double myLoc;
    final double maxDiff;
    final double prevLoc;
    final TimedOutNodesList entry;
    final SelectionRates selection;
    final boolean enableFOAFMitigationHack;
    final Set<Double> excludeLocations;
    final PeerSelectionState st = new PeerSelectionState();

    CloserPeerContext(
        PeerNode[] peers,
        Key key,
        double myLoc,
        double maxDiff,
        double prevLoc,
        TimedOutNodesList entry,
        SelectionRates selection,
        boolean enableFOAFMitigationHack,
        Set<Double> excludeLocations) {
      this.peers = peers;
      this.key = key;
      this.myLoc = myLoc;
      this.maxDiff = maxDiff;
      this.prevLoc = prevLoc;
      this.entry = entry;
      this.selection = selection;
      this.enableFOAFMitigationHack = enableFOAFMitigationHack;
      this.excludeLocations = excludeLocations;
    }
  }

  private CloserPeerContext initCloserPeerContext(
      PeerNode pn, Set<PeerNode> routedTo, double target, boolean ignoreSelf, Key key) {
    PeerNode[] peers = connectedPeers();
    Key effectiveKey = node.isEnablePerNodeFailureTables() ? key : null;
    if (LOG.isDebugEnabled())
      LOG.debug("Choosing closest peer (connectedPeers={}, key={})", peers.length, effectiveKey);

    double myLoc = node.getLocation();
    double maxDiff = ignoreSelf ? Double.MAX_VALUE : Location.distance(myLoc, target);
    double prevLoc = (pn != null) ? pn.getLocation() : -1.0;
    TimedOutNodesList entry =
        (effectiveKey != null) ? node.getFailureTable().getTimedOutNodesList(effectiveKey) : null;
    SelectionRates selection = computeSelectionRates(peers);
    boolean enableFOAF = (peers.length >= PeerNode.SELECTION_MIN_PEERS) && (selection.total > 0.0);
    Set<Double> exclude = buildExcludeLocations(myLoc, prevLoc, routedTo);
    return new CloserPeerContext(
        peers, effectiveKey, myLoc, maxDiff, prevLoc, entry, selection, enableFOAF, exclude);
  }

  private SelectionRates computeSelectionRates(PeerNode[] peers) {
    double[] rates = new double[peers.length];
    double total = 0.0;
    for (int i = 0; i < peers.length; i++) {
      rates[i] = peers[i].selectionRate();
      total += rates[i];
    }
    return new SelectionRates(rates, total);
  }

  private void evaluateCandidatesInContext(
      CloserPeerContext ctx,
      PeerNode pn,
      Set<PeerNode> routedTo,
      int minVersion,
      long now,
      boolean realTime,
      boolean ignoreTimeout,
      short outgoingHTL,
      double target,
      double maxDistance,
      boolean ignoreSelf,
      List<Double> addUnpickedLocsTo,
      long ignoreBackoffUnder,
      boolean newLoadManagement) {
    for (int i = 0; i < ctx.peers.length; i++) {
      evaluateCandidate(
          ctx.st,
          ctx.peers[i],
          i,
          pn,
          routedTo,
          minVersion,
          ctx.enableFOAFMitigationHack,
          ctx.selection.rates,
          ctx.selection.total,
          now,
          realTime,
          ctx.entry,
          ignoreTimeout,
          outgoingHTL,
          target,
          ctx.excludeLocations,
          maxDistance,
          ignoreSelf,
          ctx.maxDiff,
          addUnpickedLocsTo,
          ignoreBackoffUnder,
          newLoadManagement);
    }
  }

  private PeerNode handleRecentlyFailedIfNeeded(
      PeerNode best,
      double bestDistance,
      RecentlyFailedReturn recentlyFailed,
      CloserPeerContext ctx,
      PeerNode pn,
      Set<PeerNode> routedTo,
      double target,
      boolean ignoreSelf,
      int minVersion,
      double maxDistance,
      short outgoingHTL,
      long ignoreBackoffUnder,
      boolean isLocal,
      boolean realTime,
      long now,
      boolean newLoadManagement) {
    if (recentlyFailed == null) return best;
    if (ctx.st.countWaiting < maxCountWaiting(ctx.peers)) return best;
    if (!node.isEnableULPRDataPropagation()) return best;
    return maybeHandleRecentlyFailed(
        pn,
        routedTo,
        target,
        ignoreSelf,
        minVersion,
        maxDistance,
        ctx.key,
        outgoingHTL,
        ignoreBackoffUnder,
        isLocal,
        realTime,
        now,
        newLoadManagement,
        ctx.entry,
        ctx.st,
        best,
        bestDistance,
        ctx.myLoc,
        ctx.prevLoc,
        recentlyFailed);
  }

  private static final class PeerSelectionState {
    int countWaiting = 0;
    long soonestTimeoutWakeup = Long.MAX_VALUE;
    double closestDistance = Double.MAX_VALUE;
    double closestRealDistance = Double.MAX_VALUE;
    PeerNode closestBackedOff = null;
    double closestBackedOffDistance = Double.MAX_VALUE;
    double closestRealBackedOffDistance = Double.MAX_VALUE;
    PeerNode closestNotBackedOff = null;
    double closestNotBackedOffDistance = Double.MAX_VALUE;
    double closestRealNotBackedOffDistance = Double.MAX_VALUE;
    PeerNode leastRecentlyTimedOut = null;
    long timeLeastRecentlyTimedOut = Long.MAX_VALUE;
    double leastRecentlyTimedOutDistance = Double.MAX_VALUE;
    PeerNode leastRecentlyTimedOutBackedOff = null;
    long timeLeastRecentlyTimedOutBackedOff = Long.MAX_VALUE;
    double leastRecentlyTimedOutBackedOffDistance = Double.MAX_VALUE;
  }

  private record BestCandidate(PeerNode best, double bestDistance) {}

  private Set<Double> buildExcludeLocations(double myLoc, double prevLoc, Set<PeerNode> routedTo) {
    Set<Double> excludeLocations = new HashSet<>();
    excludeLocations.add(myLoc);
    excludeLocations.add(prevLoc);
    for (PeerNode routedToNode : routedTo) {
      excludeLocations.add(routedToNode.getLocation());
    }
    return excludeLocations;
  }

  private void evaluateCandidate(
      PeerSelectionState st,
      PeerNode p,
      int index,
      PeerNode origin,
      Set<PeerNode> routedTo,
      int minVersion,
      boolean enableFOAFMitigationHack,
      double[] selectionRates,
      double totalSelectionRate,
      long now,
      boolean realTime,
      TimedOutNodesList entry,
      boolean ignoreTimeout,
      short outgoingHTL,
      double target,
      Set<Double> excludeLocations,
      double maxDistance,
      boolean ignoreSelf,
      double maxDiff,
      List<Double> addUnpickedLocsTo,
      long ignoreBackoffUnder,
      boolean newLoadManagement) {
    if (shouldSkipCandidate(
        p,
        origin,
        routedTo,
        newLoadManagement,
        realTime,
        minVersion,
        enableFOAFMitigationHack,
        selectionRates,
        totalSelectionRate,
        index,
        now)) return;

    TimeoutInfo t = computeTimeoutInfo(st, entry, ignoreTimeout, now, outgoingHTL, p);
    DiffInfo d = computeDiffInfo(p, target, outgoingHTL, excludeLocations);

    if (d.diff > maxDistance) return;
    if ((!ignoreSelf) && (d.diff > maxDiff)) {
      if (LOG.isDebugEnabled()) LOG.debug("Ignore; farther than self; maxDiff={}", maxDiff);
      return;
    }
    if (LOG.isDebugEnabled())
      LOG.debug(
          "p.loc={}, target={}, d={} usedD={} timedOut={} for {}",
          d.loc,
          target,
          Location.distance(d.loc, target),
          d.diff,
          t.timedOut,
          p.getPeer());

    boolean chosen =
        updateBestTracking(st, p, d, t.timedOut, t.timeoutFT, ignoreBackoffUnder, realTime);
    if (addUnpickedLocsTo != null && !chosen) {
      Double locD = d.loc;
      if (!addUnpickedLocsTo.contains(locD)) addUnpickedLocsTo.add(locD);
    }
  }

  private boolean shouldSkipCandidate(
      PeerNode p,
      PeerNode origin,
      Set<PeerNode> routedTo,
      boolean newLoadManagement,
      boolean realTime,
      int minVersion,
      boolean enableFOAFMitigationHack,
      double[] selectionRates,
      double totalSelectionRate,
      int index,
      long now) {
    boolean skip = false;
    skip |= isAlreadyRoutedTo(p, routedTo);
    skip |= isOrigin(p, origin);
    skip |= isNotRoutable(p);
    skip |= isDisconnecting(p);
    skip |= lacksLoadStats(p, newLoadManagement, realTime);
    skip |= isOldVersion(p, minVersion);
    skip |=
        isOverSelectedPeer(enableFOAFMitigationHack, selectionRates, totalSelectionRate, index, p);
    skip |= isInMandatoryBackoff(p, newLoadManagement, realTime, now);
    return skip;
  }

  private boolean isAlreadyRoutedTo(PeerNode p, Set<PeerNode> routedTo) {
    if (routedTo.contains(p)) {
      if (LOG.isDebugEnabled()) LOG.debug("Skipping (already routed to): {}", p.getPeer());
      return true;
    }
    return false;
  }

  private boolean isOrigin(PeerNode p, PeerNode origin) {
    if (p == origin) {
      if (LOG.isDebugEnabled()) LOG.debug("Skipping (req came from): {}", p.getPeer());
      return true;
    }
    return false;
  }

  private boolean isNotRoutable(PeerNode p) {
    if (!p.isRoutable()) {
      if (LOG.isDebugEnabled()) LOG.debug("Skipping (not connected): {}", p.getPeer());
      return true;
    }
    return false;
  }

  private boolean isDisconnecting(PeerNode p) {
    if (p.isDisconnecting()) {
      if (LOG.isDebugEnabled()) LOG.debug("Skipping (disconnecting): {}", p.getPeer());
      return true;
    }
    return false;
  }

  private boolean lacksLoadStats(PeerNode p, boolean newLoadManagement, boolean realTime) {
    if (newLoadManagement && p.outputLoadTracker(realTime).getLastIncomingLoadStats() == null) {
      if (LOG.isDebugEnabled()) LOG.debug("Skipping (no load stats): {}", p.getPeer());
      return true;
    }
    return false;
  }

  private boolean isOldVersion(PeerNode p, int minVersion) {
    if (minVersion > 0
        && !Version.isBuildAtLeast(
            p.getNodeName(),
            Version.parseBuildNumberFromVersionStr(p.getVersion(), -1),
            minVersion)) {
      if (LOG.isDebugEnabled()) LOG.debug("Skipping old version: {}", p.getPeer());
      return true;
    }
    return false;
  }

  private boolean isOverSelectedPeer(
      boolean enableFOAFMitigationHack,
      double[] selectionRates,
      double totalSelectionRate,
      int index,
      PeerNode p) {
    if (enableFOAFMitigationHack) {
      double selectionPercentage = 100.0 * selectionRates[index] / totalSelectionRate;
      if (selectionPercentage > PeerNode.SELECTION_PERCENTAGE_WARNING) {
        if (LOG.isDebugEnabled())
          LOG.debug("Skipping over-selected peer({}%): {}", selectionPercentage, p.getPeer());
        return true;
      }
    }
    return false;
  }

  private boolean isInMandatoryBackoff(
      PeerNode p, boolean newLoadManagement, boolean realTime, long now) {
    if (newLoadManagement && p.isInMandatoryBackoff(now, realTime)) {
      if (LOG.isDebugEnabled()) LOG.debug("Skipping (mandatory backoff): {}", p.getPeer());
      return true;
    }
    return false;
  }

  private record TimeoutInfo(boolean timedOut, long timeoutFT) {}

  private TimeoutInfo computeTimeoutInfo(
      PeerSelectionState st,
      TimedOutNodesList entry,
      boolean ignoreTimeout,
      long now,
      short outgoingHTL,
      PeerNode p) {
    long timeoutRF;
    long timeoutFT = -1;
    if (entry != null && !ignoreTimeout) {
      timeoutFT = entry.getTimeoutTime(p, outgoingHTL, now, true);
      timeoutRF = entry.getTimeoutTime(p, outgoingHTL, now, false);
      if (timeoutRF > now) {
        st.soonestTimeoutWakeup = Math.min(st.soonestTimeoutWakeup, timeoutRF);
        st.countWaiting++;
      }
    }
    boolean timedOut = timeoutFT > now;
    return new TimeoutInfo(timedOut, timeoutFT);
  }

  private record DiffInfo(double loc, double diff, double realDiff, boolean direct) {}

  private DiffInfo computeDiffInfo(
      PeerNode p, double target, short outgoingHTL, Set<Double> excludeLocations) {
    double loc = p.getLocation();
    boolean direct = true;
    double realDiff = Location.distance(loc, target);
    double diff = realDiff;
    if (p.shallWeRouteAccordingToOurPeersLocation(outgoingHTL)) {
      double l = p.getClosestPeerLocation(target, excludeLocations);
      if (!Double.isNaN(l)) {
        double newDiff = Location.distance(l, target);
        if (newDiff < diff) {
          loc = l;
          diff = newDiff;
          direct = false;
        }
      }
      if (LOG.isDebugEnabled())
        LOG.debug("Peer {} publishes peer locations; closest candidate distance={}", p, diff);
    }
    return new DiffInfo(loc, diff, realDiff, direct);
  }

  private boolean updateBestTracking(
      PeerSelectionState st,
      PeerNode p,
      DiffInfo d,
      boolean timedOut,
      long timeoutFT,
      long ignoreBackoffUnder,
      boolean realTime) {
    boolean chosen = updateOverallBest(st, p, d);
    boolean backedOff = p.isRoutingBackedOff(ignoreBackoffUnder, realTime);
    chosen |= updateBestBackedOff(st, p, d, timedOut, backedOff);
    chosen |= updateBestNotBackedOff(st, p, d, timedOut, backedOff);
    updateTimedOutOrdering(st, p, d.diff, timeoutFT, timedOut, backedOff);
    return chosen;
  }

  private boolean updateOverallBest(PeerSelectionState st, PeerNode p, DiffInfo d) {
    if (d.diff < st.closestDistance
        || (Math.abs(d.diff - st.closestDistance) < Double.MIN_VALUE * 2
            && (d.direct || d.realDiff < st.closestRealDistance))) {
      st.closestDistance = d.diff;
      st.closestRealDistance = d.realDiff;
      if (LOG.isDebugEnabled())
        LOG.debug("New best distance={} at {} for {}", d.diff, d.loc, p.getPeer());
      return true;
    }
    return false;
  }

  private boolean updateBestBackedOff(
      PeerSelectionState st, PeerNode p, DiffInfo d, boolean timedOut, boolean backedOff) {
    if (backedOff
        && (d.diff < st.closestBackedOffDistance
            || (Math.abs(d.diff - st.closestBackedOffDistance) < Double.MIN_VALUE * 2
                && (d.direct || d.realDiff < st.closestRealBackedOffDistance)))
        && !timedOut) {
      st.closestBackedOffDistance = d.diff;
      st.closestBackedOff = p;
      st.closestRealBackedOffDistance = d.realDiff;
      if (LOG.isDebugEnabled())
        LOG.debug("New best-backed-off distance={} at {} for {}", d.diff, d.loc, p.getPeer());
      return true;
    }
    return false;
  }

  private boolean updateBestNotBackedOff(
      PeerSelectionState st, PeerNode p, DiffInfo d, boolean timedOut, boolean backedOff) {
    if (!backedOff
        && (d.diff < st.closestNotBackedOffDistance
            || (Math.abs(d.diff - st.closestNotBackedOffDistance) < Double.MIN_VALUE * 2
                && (d.direct || d.realDiff < st.closestRealNotBackedOffDistance)))
        && !timedOut) {
      st.closestNotBackedOffDistance = d.diff;
      st.closestNotBackedOff = p;
      st.closestRealNotBackedOffDistance = d.realDiff;
      if (LOG.isDebugEnabled())
        LOG.debug("New best-not-backed-off distance={} at {} for {}", d.diff, d.loc, p.getPeer());
      return true;
    }
    return false;
  }

  private void updateTimedOutOrdering(
      PeerSelectionState st,
      PeerNode p,
      double diff,
      long timeoutFT,
      boolean timedOut,
      boolean backedOff) {
    if (!timedOut) return;
    if (!backedOff) {
      if (timeoutFT < st.timeLeastRecentlyTimedOut) {
        st.timeLeastRecentlyTimedOut = timeoutFT;
        st.leastRecentlyTimedOut = p;
        st.leastRecentlyTimedOutDistance = diff;
      }
    } else if (timeoutFT < st.timeLeastRecentlyTimedOutBackedOff) {
      st.timeLeastRecentlyTimedOutBackedOff = timeoutFT;
      st.leastRecentlyTimedOutBackedOff = p;
      st.leastRecentlyTimedOutBackedOffDistance = diff;
    }
  }

  private BestCandidate selectBestCandidate(PeerSelectionState st, Key key) {
    PeerNode best = st.closestNotBackedOff;
    double bestDistance = st.closestNotBackedOffDistance;
    if (best == null) {
      if (st.leastRecentlyTimedOut != null) {
        best = st.leastRecentlyTimedOut;
        bestDistance = st.leastRecentlyTimedOutDistance;
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Using least recently failed in-timeout-period peer for key: {} for {}",
              best.shortToString(),
              key);
      } else if (st.closestBackedOff != null) {
        best = st.closestBackedOff;
        bestDistance = st.closestBackedOffDistance;
        if (LOG.isDebugEnabled())
          LOG.debug("Using best backed-off peer for key: {}", best.shortToString());
      } else if (st.leastRecentlyTimedOutBackedOff != null) {
        best = st.leastRecentlyTimedOutBackedOff;
        bestDistance = st.leastRecentlyTimedOutBackedOffDistance;
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Using least recently failed in-timeout-period backed-off peer for key: {} for {}",
              best.shortToString(),
              key);
      }
    }
    return new BestCandidate(best, bestDistance);
  }

  private PeerNode maybeHandleRecentlyFailed(
      PeerNode pn,
      Set<PeerNode> routedTo,
      double target,
      boolean ignoreSelf,
      int minVersion,
      double maxDistance,
      Key key,
      short outgoingHTL,
      long ignoreBackoffUnder,
      boolean isLocal,
      boolean realTime,
      long now,
      boolean newLoadManagement,
      TimedOutNodesList entry,
      PeerSelectionState st,
      PeerNode best,
      double bestDistance,
      double myLoc,
      double prevLoc,
      RecentlyFailedReturn recentlyFailed) {
    FirstSecondChoice choice =
        computeFirstSecondChoice(
            pn,
            routedTo,
            target,
            ignoreSelf,
            minVersion,
            maxDistance,
            key,
            outgoingHTL,
            ignoreBackoffUnder,
            isLocal,
            realTime,
            now,
            newLoadManagement,
            entry);
    if (choice == null) return best;
    long until = computeUntil(choice.firstTime, choice.secondTime, st, now);
    long check =
        (best == st.closestNotBackedOff)
            ? Long.MAX_VALUE
            : checkBackoffsForRecentlyFailed(
                connectedPeers(),
                best,
                target,
                bestDistance,
                myLoc,
                prevLoc,
                now,
                entry,
                outgoingHTL);
    if (check < until) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Reducing RecentlyFailed from {} ms to {} ms due to wake-up check",
            until - now,
            check - now);
      until = check;
    }
    long decidedUntil = decideRecentlyFailedUntil(until, now, key);
    if (decidedUntil >= 0) {
      recentlyFailed.fail(decidedUntil);
      return null;
    } else {
      if (LOG.isDebugEnabled())
        LOG.debug("Not sending RecentlyFailed because will wake up in {}ms", check - now);
      return best;
    }
  }

  private long computeUntil(long firstTime, long secondTime, PeerSelectionState st, long now) {
    long until = Math.min(secondTime, firstTime);
    if (st.countWaiting == maxCountWaiting(connectedPeers())) {
      until = Math.min(until, st.soonestTimeoutWakeup);
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Recently failed: {}ms",
            (int) Math.min(Integer.MAX_VALUE, (st.soonestTimeoutWakeup - now)));
    }
    return until;
  }

  private long decideRecentlyFailedUntil(long until, long now, Key key) {
    if (until <= now + MIN_DELTA) return -1L;
    if (until > now + FailureTable.RECENTLY_FAILED_TIME) {
      final long delay = until - now;
      LOG.atError().addArgument(() -> TimeUtil.formatTime(delay)).log("Wake-up time too long: {}");
      until = now + FailureTable.RECENTLY_FAILED_TIME;
    }
    return node.getFailureTable().hadAnyOffers(key) ? -1L : until;
  }

  private record FirstSecondChoice(
      PeerNode first, long firstTime, PeerNode second, long secondTime) {}

  private FirstSecondChoice computeFirstSecondChoice(
      PeerNode pn,
      Set<PeerNode> routedTo,
      double target,
      boolean ignoreSelf,
      int minVersion,
      double maxDistance,
      Key key,
      short outgoingHTL,
      long ignoreBackoffUnder,
      boolean isLocal,
      boolean realTime,
      long now,
      boolean newLoadManagement,
      TimedOutNodesList entry) {
    PeerNode first =
        closerPeer(
            pn,
            routedTo,
            target,
            ignoreSelf,
            false,
            minVersion,
            null,
            maxDistance,
            key,
            outgoingHTL,
            ignoreBackoffUnder,
            isLocal,
            realTime,
            null,
            true,
            now,
            newLoadManagement);
    if (first == null) return null;
    long firstTime = entry.getTimeoutTime(first, outgoingHTL, now, false);
    if (firstTime <= now) return null;
    if (LOG.isDebugEnabled()) LOG.debug("First choice timeout already passed");

    HashSet<PeerNode> newRoutedTo = new HashSet<>(routedTo);
    newRoutedTo.add(first);
    PeerNode second =
        closerPeer(
            pn,
            newRoutedTo,
            target,
            ignoreSelf,
            false,
            minVersion,
            null,
            maxDistance,
            key,
            outgoingHTL,
            ignoreBackoffUnder,
            isLocal,
            realTime,
            null,
            true,
            now,
            newLoadManagement);
    if (second == null) return null;
    long secondTime = entry.getTimeoutTime(first, outgoingHTL, now, false);
    if (secondTime <= now) return null;
    return new FirstSecondChoice(first, firstTime, second, secondTime);
  }

  private void postSelectionUpdate(
      PeerNode best,
      boolean calculateMisrouting,
      List<Double> addUnpickedLocsTo,
      PeerSelectionState st) {
    if (best == null) return;
    if (calculateMisrouting) {
      int numberOfConnected = getPeerNodeStatusSize(PEER_NODE_STATUS_CONNECTED, false);
      int numberOfRoutingBackedOff =
          getPeerNodeStatusSize(PEER_NODE_STATUS_ROUTING_BACKED_OFF, false);
      if (numberOfRoutingBackedOff + numberOfConnected > 0)
        node.getNodeStats()
            .backedOffPercent
            .report(
                (double) numberOfRoutingBackedOff
                    / (double) (numberOfRoutingBackedOff + numberOfConnected));
    }
    if (addUnpickedLocsTo != null
        && st.closestNotBackedOff != null
        && st.closestBackedOff != null) {
      addUnpickedLocsTo.add(st.closestBackedOff.getLocation());
    }
  }

  /**
   * Computes the threshold count of peers waiting due to timeouts.
   *
   * @param peers Snapshot of peers to consider when computing the threshold.
   * @return The minimum number of peers which are waiting for timeouts due to RecentlyFailed or
   *     DNF's for which we will terminate the request with a RecentlyFailed of our own.
   */
  private int maxCountWaiting(PeerNode[] peers) {
    int count = countConnectedPeers(peers);
    return Math.clamp(count / 4, 3, 10);
  }

  static final int MIN_DELTA = 2000;

  /**
   * Check whether the routing situation will change soon because of a node coming out of backoff or
   * of a FailureTable timeout.
   *
   * <p>If we have routed to a backed off node, or a node due to a failure-table timeout, there is a
   * good chance that the ideal node will change shortly.
   *
   * @return The time at which there will be a different best location to route to for this key, or
   *     Long.MAX_VALUE if we cannot predict a better peer after any amount of time.
   */
  private long checkBackoffsForRecentlyFailed(
      PeerNode[] peers,
      PeerNode best,
      double target,
      double bestDistance,
      double myLoc,
      double prevLoc,
      long now,
      TimedOutNodesList entry,
      short outgoingHTL) {
    long overallWakeup = Long.MAX_VALUE;
    Set<Double> excludeLocations =
        buildExcludeLocations(myLoc, prevLoc, java.util.Collections.emptySet());
    for (PeerNode p : peers) {
      long wake =
          wakeupTimeIfBetterAlternative(
              p, best, target, bestDistance, outgoingHTL, excludeLocations, now, entry);
      if (wake == Long.MIN_VALUE) continue; // not eligible / no improvement
      if (wake > now && wake < overallWakeup) overallWakeup = wake;
    }
    return overallWakeup;
  }

  private long wakeupTimeIfBetterAlternative(
      PeerNode p,
      PeerNode best,
      double target,
      double bestDistance,
      short outgoingHTL,
      Set<Double> excludeLocations,
      long now,
      TimedOutNodesList entry) {
    if (p == best || !p.isRoutable()) return Long.MIN_VALUE;
    DiffInfo d = computeDiffInfo(p, target, outgoingHTL, excludeLocations);
    if (d.diff >= bestDistance) return Long.MIN_VALUE;
    long wakeup = computeWakeupDeadline(entry, outgoingHTL, now, p);
    if (wakeup <= now) {
      if (LOG.isDebugEnabled())
        LOG.debug("Better node available during RecentlyFailed check: {}", p);
      return Long.MIN_VALUE;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Peer {} exits backoff/timeout in {} ms", p, wakeup - now);
    return wakeup;
  }

  private long computeWakeupDeadline(
      TimedOutNodesList entry, short outgoingHTL, long now, PeerNode p) {
    long wakeup = 0L;
    long timeoutFT = entry.getTimeoutTime(p, outgoingHTL, now, true);
    long timeoutRF = entry.getTimeoutTime(p, outgoingHTL, now, false);
    if (timeoutFT > now) wakeup = Math.max(wakeup, timeoutFT);
    if (timeoutRF > now) wakeup = Math.max(wakeup, timeoutRF);
    long bulkBackoff = p.getRoutingBackedOffUntilBulk();
    long rtBackoff = p.getRoutingBackedOffUntilRT();
    long candidate = Long.MAX_VALUE;
    if (bulkBackoff > now) candidate = bulkBackoff;
    if (rtBackoff > now && rtBackoff < candidate) candidate = rtBackoff;
    if (candidate != Long.MAX_VALUE) wakeup = Math.max(wakeup, candidate);
    return wakeup;
  }

  /**
   * Builds a human-readable status summary of all peers.
   *
   * @return Multiline string, one line per peer status, sorted lexicographically.
   */
  public String getStatus() {
    StringBuilder sb = new StringBuilder();
    PeerNode[] peers = myPeers();
    String[] status = new String[peers.length];
    for (int i = 0; i < peers.length; i++) {
      PeerNode pn = peers[i];
      status[i] = pn.getStatus(true).toString();
    }
    Arrays.sort(status);
    for (String s : status) {
      sb.append(s);
      sb.append('\n');
    }
    return sb.toString();
  }

  /**
   * Returns a textual list of peers for TMCI consumers.
   *
   * @return Multiline string with TMCI peer info, sorted.
   */
  public String getTMCIPeerList() {
    StringBuilder sb = new StringBuilder();
    PeerNode[] peers = myPeers();
    String[] peerList = new String[peers.length];
    for (int i = 0; i < peers.length; i++) {
      PeerNode pn = peers[i];
      peerList[i] = pn.getTMCIPeerInfo();
    }
    Arrays.sort(peerList);
    for (String p : peerList) {
      sb.append(p);
      sb.append('\n');
    }
    return sb.toString();
  }

  private final Object writePeersSync = new Object();
  private final Object writePeerFileSync = new Object();

  void writePeers(boolean opennet) {
    if (opennet) writePeersOpennet();
    else writePeersDarknet();
  }

  void writePeersUrgent(boolean opennet) {
    if (opennet) writePeersOpennetUrgent();
    else writePeersDarknetUrgent();
  }

  void writePeersOpennetUrgent() {
    node.getExecutor()
        .execute(
            new PrioRunnable() {

              @Override
              public void run() {
                writePeersOpennetNow(true);
              }

              @Override
              public int getPriority() {
                return NativeThread.PriorityLevel.HIGH_PRIORITY.value;
              }
            });
  }

  void writePeersDarknetUrgent() {
    node.getExecutor()
        .execute(
            new PrioRunnable() {

              @Override
              public void run() {
                writePeersDarknetNow(true);
              }

              @Override
              public int getPriority() {
                return NativeThread.PriorityLevel.HIGH_PRIORITY.value;
              }
            });
  }

  void writePeersDarknet() {
    shouldWritePeersDarknet = true;
  }

  void writePeersOpennet() {
    shouldWritePeersOpennet = true;
  }

  protected String getDarknetPeersString() {
    StringBuilder sb = new StringBuilder();
    PeerNode[] peers = myPeers();
    for (PeerNode pn : peers) {
      if (pn instanceof DarknetPeerNode) sb.append(pn.exportDiskFieldSet().toOrderedString());
    }

    return sb.toString();
  }

  protected String getOpennetPeersString() {
    StringBuilder sb = new StringBuilder();
    PeerNode[] peers = myPeers();
    for (PeerNode pn : peers) {
      if (pn instanceof OpennetPeerNode) sb.append(pn.exportDiskFieldSet().toOrderedString());
    }

    return sb.toString();
  }

  protected String getOldOpennetPeersString(OpennetManager om) {
    StringBuilder sb = new StringBuilder();
    for (PeerNode pn : om.getOldPeers()) {
      if (pn instanceof OpennetPeerNode) sb.append(pn.exportDiskFieldSet().toOrderedString());
    }

    return sb.toString();
  }

  private static final int BACKUPS_OPENNET = 1;
  private static final int BACKUPS_DARKNET = 10;

  private void writePeersInnerDarknet(boolean rotateBackups) {
    String newDarknetPeersString = null;
    synchronized (writePeersSync) {
      if (darkFilename != null) newDarknetPeersString = getDarknetPeersString();
    }
    synchronized (writePeerFileSync) {
      if (newDarknetPeersString != null && !newDarknetPeersString.equals(darknetPeersStringCache)) {
        darknetPeersStringCache = newDarknetPeersString;
        writePeersInner(darkFilename, darknetPeersStringCache, BACKUPS_DARKNET, rotateBackups);
      }
    }
  }

  private void writePeersInnerOpennet(boolean rotateBackups) {
    String newOpennetPeersString = null;
    String newOldOpennetPeersString = null;
    synchronized (writePeersSync) {
      OpennetManager om = node.getOpennet();
      if (om != null) {
        if (openFilename != null) newOpennetPeersString = getOpennetPeersString();
        oldOpennetPeersFilename = om.getOldPeersFilename();
        newOldOpennetPeersString = getOldOpennetPeersString(om);
      }
    }
    synchronized (writePeerFileSync) {
      if (newOpennetPeersString != null && !newOpennetPeersString.equals(opennetPeersStringCache)) {
        opennetPeersStringCache = newOpennetPeersString;
        writePeersInner(openFilename, opennetPeersStringCache, BACKUPS_OPENNET, rotateBackups);
      }
      if (newOldOpennetPeersString != null
          && !newOldOpennetPeersString.equals(oldOpennetPeersStringCache)) {
        oldOpennetPeersStringCache = newOldOpennetPeersString;
        writePeersInner(
            oldOpennetPeersFilename, oldOpennetPeersStringCache, BACKUPS_OPENNET, rotateBackups);
      }
    }
  }

  /**
   * Write the peers file to disk
   *
   * @param rotateBackups If true, rotate backups. If false, just clobber the latest file.
   */
  private void writePeersInner(String filename, String sb, int maxBackups, boolean rotateBackups) {
    assert (maxBackups >= 1);
    synchronized (writePeerFileSync) {
      File f;
      File full = new File(filename).getAbsoluteFile();
      try {
        f = File.createTempFile(full.getName() + ".", ".tmp", full.getParentFile());
      } catch (IOException e2) {
        LOG.error("Cannot write peers to disk: temp file creation error={}", e2, e2);
        return;
      }

      try (FileOutputStream fos = new FileOutputStream(f);
          OutputStreamWriter w = new OutputStreamWriter(fos, StandardCharsets.UTF_8)) {

        w.write(sb);
        w.flush();
        fos.getFD().sync();

        if (rotateBackups) {
          rotateBackupFiles(filename, maxBackups, f);
        } else {
          FileUtil.moveTo(f, getBackupFilename(filename, 0));
        }
      } catch (FileNotFoundException e2) {
        LOG.error("Cannot write peers to disk: cannot create {} (error={})", f, e2, e2);
        try {
          java.nio.file.Files.deleteIfExists(f.toPath());
        } catch (IOException ignore) {
          // best-effort
        }
      } catch (IOException e) {
        LOG.error("I/O error writing peers file: {}", e, e);
        try {
          java.nio.file.Files.deleteIfExists(f.toPath());
        } catch (IOException ignore) {
          // best-effort
        }
        // don't overwrite old file!
      } finally {
        // Try-with-resources handles the stream cleanup
        try {
          java.nio.file.Files.deleteIfExists(f.toPath());
        } catch (IOException ignore) {
          // best-effort
        }
      }
    }
  }

  private void rotateBackupFiles(String filename, int maxBackups, File newFile) {
    File prevFile = null;
    for (int i = maxBackups; i >= 0; i--) {
      File thisFile = getBackupFilename(filename, i);
      if (prevFile == null) {
        try {
          java.nio.file.Files.deleteIfExists(thisFile.toPath());
        } catch (IOException ignore) {
          // best-effort
        }
      } else if (thisFile.exists()) {
        FileUtil.moveTo(thisFile, prevFile);
      }
      prevFile = thisFile;
    }
    if (prevFile == null) prevFile = getBackupFilename(filename, 0);
    FileUtil.moveTo(newFile, prevFile);
  }

  private File getBackupFilename(String filename, int i) {
    if (i == 0) return new File(filename);
    if (i == 1) return new File(filename + ".bak");
    return new File(filename + ".bak." + i);
  }

  /**
   * Update the numbers needed by our PeerManagerUserAlert on the UAM. Also run the node's
   * onConnectedPeers() method if applicable. LOCKING: Do not call inside PeerNode lock.
   */
  public void updatePMUserAlert() {
    if (ua == null) return;
    int peers;
    int darknetPeers;
    int opennetPeers;
    synchronized (this) {
      darknetPeers = this.getDarknetPeers().length;
      opennetPeers = this.getOpennetPeers().length;
      peers = darknetPeers + opennetPeers; // Seednodes don't count.
    }
    OpennetManager om = node.getOpennet();

    boolean opennetDefinitelyPortForwarded;
    boolean opennetEnabled;
    boolean opennetAssumeNAT;
    if (om != null) {
      opennetEnabled = true;
      opennetDefinitelyPortForwarded = om.getCrypto().definitelyPortForwarded();
      opennetAssumeNAT = om.getCrypto().getConfig().alwaysHandshakeAggressively();
    } else {
      opennetEnabled = false;
      opennetDefinitelyPortForwarded = false;
      opennetAssumeNAT = false;
    }
    boolean darknetDefinitelyPortForwarded = node.darknetDefinitelyPortForwarded();
    boolean darknetAssumeNAT = node.getDarknetCrypto().getConfig().alwaysHandshakeAggressively();
    synchronized (uaLock) {
      ua.setOpennetDefinitelyPortForwarded(opennetDefinitelyPortForwarded);
      ua.setDarknetDefinitelyPortForwarded(darknetDefinitelyPortForwarded);
      ua.setOpennetAssumeNAT(opennetAssumeNAT);
      ua.setDarknetAssumeNAT(darknetAssumeNAT);
      int darknetConnsVal =
          getPeerNodeStatusSize(PEER_NODE_STATUS_CONNECTED, true)
              + getPeerNodeStatusSize(PEER_NODE_STATUS_ROUTING_BACKED_OFF, true);
      ua.setDarknetConns(darknetConnsVal);
      ua.setConns(
          getPeerNodeStatusSize(PEER_NODE_STATUS_CONNECTED, false)
              + getPeerNodeStatusSize(PEER_NODE_STATUS_ROUTING_BACKED_OFF, false));
      ua.setDarknetPeers(darknetPeers);
      ua.setDisconnDarknetPeers(darknetPeers - darknetConnsVal);
      ua.setPeers(peers);
      ua.setNeverConn(getPeerNodeStatusSize(PEER_NODE_STATUS_NEVER_CONNECTED, true));
      ua.setClockProblem(getPeerNodeStatusSize(PEER_NODE_STATUS_CLOCK_PROBLEM, false));
      ua.setConnError(getPeerNodeStatusSize(PEER_NODE_STATUS_CONN_ERROR, true));
      ua.setOpennetEnabled(opennetEnabled);
      ua.setTooNewPeersDarknet(getPeerNodeStatusSize(PEER_NODE_STATUS_TOO_NEW, true));
      ua.setTooNewPeersTotal(getPeerNodeStatusSize(PEER_NODE_STATUS_TOO_NEW, false));
    }
    if (anyConnectedPeers()) node.onConnectedPeer();
  }

  /**
   * Returns whether any peer is currently routable.
   *
   * @return {@code true} if at least one connected peer is routable; otherwise {@code false}.
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
   * @return {@code true} when a darknet peer is connected; otherwise {@code false}.
   */
  public boolean anyDarknetPeers() {
    PeerNode[] conns = connectedPeers();
    for (PeerNode p : conns) if (p.isDarknet()) return true;
    return false;
  }

  /** Ask each PeerNode to read in its extra peer data */
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

  /** Initializes user alerts and schedules the first peer persistence write. */
  public void start() {
    ua = new PeerManagerUserAlert(node.getNodeStats(), node.getNodeUpdater());
    updatePMUserAlert();
    node.getClientCore().getAlerts().register(ua);
    node.getTicker().queueTimedJob(writePeersRunnable, 0);
  }

  /**
   * Counts peers that are routable and not in backoff for the given traffic class.
   *
   * @param realTime If true, evaluate realtime backoff; otherwise evaluate bulk backoff.
   * @return Number of connected peers not backed off.
   */
  public int countNonBackedOffPeers(boolean realTime) {
    PeerNode[] peers = connectedPeers();
    // even if myPeers peers are connected they won't be routed to
    int countNoBackoff = 0;
    for (PeerNode peer : peers) {
      if (peer.isRoutable() && !peer.isRoutingBackedOff(realTime)) countNoBackoff++;
    }
    return countNoBackoff;
  }

  // Stats stuff
  /** Update oldestNeverConnectedPeerAge if the timer has expired */
  public void maybeUpdateOldestNeverConnectedDarknetPeerAge(long now) {
    PeerNode[] peerList;
    synchronized (this) {
      if (now <= nextOldestNeverConnectedDarknetPeerAgeUpdateTime) return;
      nextOldestNeverConnectedDarknetPeerAgeUpdateTime =
          now + OLDEST_NEVER_CONNECTED_DARKNET_PEER_AGE_UPDATE_INTERVAL;
      peerList = myPeers;
    }
    oldestNeverConnectedDarknetPeerAge = 0;
    for (PeerNode pn : peerList) {
      if (!pn.isDarknet()) continue;
      if (pn.getPeerNodeStatus() == PEER_NODE_STATUS_NEVER_CONNECTED
          && (now - pn.getPeerAddedTime()) > oldestNeverConnectedDarknetPeerAge) {
        oldestNeverConnectedDarknetPeerAge = now - pn.getPeerAddedTime();
      }
    }
    if (oldestNeverConnectedDarknetPeerAge > 0 && LOG.isDebugEnabled())
      LOG.debug("Oldest never connected peer is {}ms old", oldestNeverConnectedDarknetPeerAge);
    nextOldestNeverConnectedDarknetPeerAgeUpdateTime =
        now + OLDEST_NEVER_CONNECTED_DARKNET_PEER_AGE_UPDATE_INTERVAL;
  }

  public long getOldestNeverConnectedDarknetPeerAge() {
    return oldestNeverConnectedDarknetPeerAge;
  }

  /** Log the current PeerNode status summary if the timer has expired */
  public void maybeLogPeerNodeStatusSummary(long now) {
    if (!shouldLogPeerStatus(now)) return;
    PeerNode[] peers = this.myPeers();
    PeerStatusSummary s = computePeerStatusSummary(peers);
    logPeerStatusSummary(s);
    nextPeerNodeStatusLogTime = now + PEER_NODE_STATUS_LOG_INTERVAL;
  }

  private boolean shouldLogPeerStatus(long now) {
    if (now <= nextPeerNodeStatusLogTime) return false;
    if ((now - nextPeerNodeStatusLogTime) > SECONDS.toMillis(10) && nextPeerNodeStatusLogTime > 0)
      LOG.error(
          "PeerNode status summary late by {} ms; PacketSender may be congested",
          now - nextPeerNodeStatusLogTime);
    return true;
  }

  private record PeerStatusSummary(
      int connected,
      int routingBackedOff,
      int tooNew,
      int tooOld,
      int disconnected,
      int neverConnected,
      int disabled,
      int bursting,
      int listening,
      int listenOnly,
      int clockProblem,
      int connError,
      int disconnecting,
      int routingDisabled,
      int noLoadStats) {}

  private PeerStatusSummary computePeerStatusSummary(PeerNode[] peers) {
    int numberOfConnected = 0;
    int numberOfRoutingBackedOff = 0;
    int numberOfTooNew = 0;
    int numberOfTooOld = 0;
    int numberOfDisconnected = 0;
    int numberOfNeverConnected = 0;
    int numberOfDisabled = 0;
    int numberOfListenOnly = 0;
    int numberOfListening = 0;
    int numberOfBursting = 0;
    int numberOfClockProblem = 0;
    int numberOfConnError = 0;
    int numberOfDisconnecting = 0;
    int numberOfRoutingDisabled = 0;
    int numberOfNoLoadStats = 0;

    for (PeerNode peer : peers) {
      if (peer == null) {
        LOG.error("Peer status list contains null entry");
        continue;
      }
      int status = peer.getPeerNodeStatus();
      switch (status) {
        case PEER_NODE_STATUS_CONNECTED:
          numberOfConnected++;
          break;
        case PEER_NODE_STATUS_ROUTING_BACKED_OFF:
          numberOfRoutingBackedOff++;
          break;
        case PEER_NODE_STATUS_TOO_NEW:
          numberOfTooNew++;
          break;
        case PEER_NODE_STATUS_TOO_OLD:
          numberOfTooOld++;
          break;
        case PEER_NODE_STATUS_DISCONNECTED:
          numberOfDisconnected++;
          break;
        case PEER_NODE_STATUS_NEVER_CONNECTED:
          numberOfNeverConnected++;
          break;
        case PEER_NODE_STATUS_DISABLED:
          numberOfDisabled++;
          break;
        case PEER_NODE_STATUS_LISTEN_ONLY:
          numberOfListenOnly++;
          break;
        case PEER_NODE_STATUS_LISTENING:
          numberOfListening++;
          break;
        case PEER_NODE_STATUS_BURSTING:
          numberOfBursting++;
          break;
        case PEER_NODE_STATUS_CLOCK_PROBLEM:
          numberOfClockProblem++;
          break;
        case PEER_NODE_STATUS_CONN_ERROR:
          numberOfConnError++;
          break;
        case PEER_NODE_STATUS_DISCONNECTING:
          numberOfDisconnecting++;
          break;
        case PEER_NODE_STATUS_ROUTING_DISABLED:
          numberOfRoutingDisabled++;
          break;
        case PEER_NODE_STATUS_NO_LOAD_STATS:
          numberOfNoLoadStats++;
          break;
        default:
          LOG.error("Unknown peer status value: {}", status);
          break;
      }
    }
    return new PeerStatusSummary(
        numberOfConnected,
        numberOfRoutingBackedOff,
        numberOfTooNew,
        numberOfTooOld,
        numberOfDisconnected,
        numberOfNeverConnected,
        numberOfDisabled,
        numberOfBursting,
        numberOfListening,
        numberOfListenOnly,
        numberOfClockProblem,
        numberOfConnError,
        numberOfDisconnecting,
        numberOfRoutingDisabled,
        numberOfNoLoadStats);
  }

  private void logPeerStatusSummary(PeerStatusSummary s) {
    LOG.info(
        "Connected={} RoutingBackedOff={} TooNew={} TooOld={} Disconnected={} NeverConnected={}"
            + " Disabled={} Bursting={} Listening={} ListenOnly={} ClockProblem={}"
            + " ConnectionProblem={} Disconnecting={} RoutingDisabled={} NoLoadStats={}",
        s.connected,
        s.routingBackedOff,
        s.tooNew,
        s.tooOld,
        s.disconnected,
        s.neverConnected,
        s.disabled,
        s.bursting,
        s.listening,
        s.listenOnly,
        s.clockProblem,
        s.connError,
        s.disconnecting,
        s.routingDisabled,
        s.noLoadStats);
  }

  public void changePeerNodeStatus(
      PeerNode peerNode, int oldPeerNodeStatus, int peerNodeStatus, boolean noLog) {
    this.allPeersStatuses.changePeerNodeStatus(peerNode, oldPeerNodeStatus, peerNodeStatus, noLog);
    if (!peerNode.isOpennet())
      this.darknetPeersStatuses.changePeerNodeStatus(
          peerNode, oldPeerNodeStatus, peerNodeStatus, noLog);
    node.getExecutor().execute(this::updatePMUserAlert);
  }

  /** Add a PeerNode status to the map. Used internally when a peer is added. */
  private void addPeerNodeStatus(int pnStatus, PeerNode peerNode) {
    this.allPeersStatuses.addStatus(pnStatus, peerNode, false);
    if (!peerNode.isOpennet()) this.darknetPeersStatuses.addStatus(pnStatus, peerNode, false);
  }

  /**
   * How many PeerNodes have a particular status?
   *
   * @param darknet If true, only count darknet nodes, if false, count all nodes.
   */
  public int getPeerNodeStatusSize(int pnStatus, boolean darknet) {
    if (darknet) return darknetPeersStatuses.statusSize(pnStatus);
    else return allPeersStatuses.statusSize(pnStatus);
  }

  /**
   * Removes a PeerNode status from the map when a peer is removed.
   *
   * @param pnStatus Status code being removed.
   * @param peerNode Peer whose status is being removed.
   */
  private void removePeerNodeStatus(int pnStatus, PeerNode peerNode) {
    this.allPeersStatuses.removeStatus(pnStatus, peerNode, false);
    if (!peerNode.isOpennet()) this.darknetPeersStatuses.removeStatus(pnStatus, peerNode, false);
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
    PeerStatusTracker<String> peerNodeRoutingBackoffReasons =
        realTime ? peerNodeRoutingBackoffReasonsRT : peerNodeRoutingBackoffReasonsBulk;
    peerNodeRoutingBackoffReasons.addStatus(peerNodeRoutingBackoffReason, peerNode, false);
  }

  /** What are the currently tracked PeerNode routing backoff reasons? */
  public String[] getPeerNodeRoutingBackoffReasons(boolean realTime) {
    ArrayList<String> list = new ArrayList<>();
    PeerStatusTracker<String> peerNodeRoutingBackoffReasons =
        realTime ? peerNodeRoutingBackoffReasonsRT : peerNodeRoutingBackoffReasonsBulk;
    peerNodeRoutingBackoffReasons.addStatusList(list);
    return list.toArray(new String[0]);
  }

  /** How many PeerNodes have a particular routing backoff reason? */
  public int getPeerNodeRoutingBackoffReasonSize(
      String peerNodeRoutingBackoffReason, boolean realTime) {
    PeerStatusTracker<String> peerNodeRoutingBackoffReasons =
        realTime ? peerNodeRoutingBackoffReasonsRT : peerNodeRoutingBackoffReasonsBulk;
    return peerNodeRoutingBackoffReasons.statusSize(peerNodeRoutingBackoffReason);
  }

  /** Remove a PeerNode routing backoff reason from the map */
  public void removePeerNodeRoutingBackoffReason(
      String peerNodeRoutingBackoffReason, PeerNode peerNode, boolean realTime) {
    PeerStatusTracker<String> peerNodeRoutingBackoffReasons =
        realTime ? peerNodeRoutingBackoffReasonsRT : peerNodeRoutingBackoffReasonsBulk;
    peerNodeRoutingBackoffReasons.removeStatus(peerNodeRoutingBackoffReason, peerNode, false);
  }

  /**
   * Returns a snapshot of statuses for all peers.
   *
   * @param noHeavy If true, skip expensive computations.
   * @return Array of peer statuses.
   */
  public PeerNodeStatus[] getPeerNodeStatuses(boolean noHeavy) {
    PeerNode[] peers = myPeers();
    PeerNodeStatus[] peerNodeStatuses = new PeerNodeStatus[peers.length];
    for (int peerIndex = 0, peerCount = peers.length; peerIndex < peerCount; peerIndex++) {
      peerNodeStatuses[peerIndex] = peers[peerIndex].getStatus(noHeavy);
    }
    return peerNodeStatuses;
  }

  /**
   * Returns a snapshot of statuses for darknet peers.
   *
   * @param noHeavy If true, skip expensive computations.
   * @return Array of darknet peer statuses.
   */
  public DarknetPeerNodeStatus[] getDarknetPeerNodeStatuses(boolean noHeavy) {
    DarknetPeerNode[] peers = getDarknetPeers();
    DarknetPeerNodeStatus[] peerNodeStatuses = new DarknetPeerNodeStatus[peers.length];
    for (int peerIndex = 0, peerCount = peers.length; peerIndex < peerCount; peerIndex++) {
      peerNodeStatuses[peerIndex] = (DarknetPeerNodeStatus) peers[peerIndex].getStatus(noHeavy);
    }
    return peerNodeStatuses;
  }

  /**
   * Returns a snapshot of statuses for opennet peers.
   *
   * @param noHeavy If true, skip expensive computations.
   * @return Array of opennet peer statuses.
   */
  public OpennetPeerNodeStatus[] getOpennetPeerNodeStatuses(boolean noHeavy) {
    OpennetPeerNode[] peers = getOpennetPeers();
    OpennetPeerNodeStatus[] peerNodeStatuses = new OpennetPeerNodeStatus[peers.length];
    for (int peerIndex = 0, peerCount = peers.length; peerIndex < peerCount; peerIndex++) {
      peerNodeStatuses[peerIndex] = (OpennetPeerNodeStatus) peers[peerIndex].getStatus(noHeavy);
    }
    return peerNodeStatuses;
  }

  /**
   * Updates per-peer routable-connection counters when the timer elapses.
   *
   * <p>Increments sampling counters that feed routing-health statistics.
   */
  public void maybeUpdatePeerNodeRoutableConnectionStats(long now) {
    PeerNode[] peersToUpdate = prepareRoutableStatsUpdate(now);
    if (peersToUpdate.length == 0) return;
    updatePeerNodeRoutableConnectionStats(peersToUpdate);
  }

  private void updatePeerNodeRoutableConnectionStats(PeerNode[] peerList) {
    for (PeerNode pn : peerList) {
      pn.checkRoutableConnectionStatus();
    }
  }

  private PeerNode[] prepareRoutableStatsUpdate(long now) {
    synchronized (this) {
      if (now <= nextRoutableConnectionStatsUpdateTime) return new PeerNode[0];
      nextRoutableConnectionStatsUpdateTime = now + ROUTABLE_CONNECTION_STATS_UPDATE_INTERVAL;
      return myPeers;
    }
  }

  /** Get the darknet peers list. Note: consider optimizing */
  public DarknetPeerNode[] getDarknetPeers() {
    PeerNode[] peers = myPeers();
    // Note: consider optimizing by maintaining a separate list
    List<DarknetPeerNode> v = new ArrayList<>(peers.length);
    for (PeerNode peer : peers) {
      if (peer instanceof DarknetPeerNode dnp) v.add(dnp);
    }
    return v.toArray(new DarknetPeerNode[0]);
  }

  /**
   * Returns connected seed-server peers, excluding specified public key hashes.
   *
   * @param exclude Set of public key hashes to exclude (optional; may be {@code null}).
   * @return List of connected seed-server peers.
   */
  public List<SeedServerPeerNode> getConnectedSeedServerPeersVector(Set<ByteArrayWrapper> exclude) {
    PeerNode[] peers = myPeers();
    ArrayList<SeedServerPeerNode> v = new ArrayList<>(peers.length);
    for (PeerNode p : peers) {
      if (p instanceof SeedServerPeerNode sspn && !shouldSkipSeedServerPeer(sspn, exclude)) {
        v.add(sspn);
      }
    }
    return v;
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

  /**
   * Returns a snapshot of all seed-server peers (copy), connected or not.
   *
   * @return List of seed-server peers.
   */
  public List<SeedServerPeerNode> getSeedServerPeersVector() {
    PeerNode[] peers = myPeers();
    // Note: consider optimizing by maintaining a separate list
    List<SeedServerPeerNode> v = new ArrayList<>(peers.length);
    for (PeerNode peer : peers) {
      if (peer instanceof SeedServerPeerNode peerNode) v.add(peerNode);
    }
    return v;
  }

  /** Get the opennet peers list. */
  public OpennetPeerNode[] getOpennetPeers() {
    PeerNode[] peers = myPeers();
    // Note: consider optimizing by maintaining a separate list
    List<OpennetPeerNode> v = new ArrayList<>(peers.length);
    for (PeerNode peer : peers) {
      if (peer instanceof OpennetPeerNode onp) v.add(onp);
    }
    return v.toArray(new OpennetPeerNode[0]);
  }

  /**
   * Returns a snapshot of opennet and seed-server peers (copy).
   *
   * @return Array containing both opennet and seed-server peers.
   */
  public PeerNode[] getOpennetAndSeedServerPeers() {
    PeerNode[] peers = myPeers();
    // Note: consider optimizing by maintaining a separate list
    ArrayList<PeerNode> v = new ArrayList<>(peers.length);
    for (PeerNode peer : peers) {
      if (peer instanceof OpennetPeerNode || peer instanceof SeedServerPeerNode) v.add(peer);
    }
    return v.toArray(new PeerNode[0]);
  }

  /**
   * Checks whether any other connected real peer has the given address.
   *
   * @param addr Address to match.
   * @param pn Peer to exclude from the check.
   * @return {@code true} if a matching peer exists; otherwise {@code false}.
   */
  public boolean anyConnectedPeerHasAddress(FreenetInetAddress addr, PeerNode pn) {
    PeerNode[] peers = myPeers();
    for (PeerNode p : peers) {
      boolean skip =
          (p == pn)
              || !p.isConnected()
              || !p.isRealConnection()
              || (p.isDarknet() && !pn.isDarknet());
      if (skip) continue;
      // If getPeer() is null then presumably !isConnected().
      if (p.getPeer().getFreenetAddress().equals(addr)) return true;
    }
    return false;
  }

  /** Removes all opennet peers from the manager and updates alerts/listeners. */
  public void removeOpennetPeers() {
    synchronized (this) {
      ArrayList<PeerNode> keep = new ArrayList<>();
      ArrayList<PeerNode> conn = new ArrayList<>();
      for (PeerNode pn : myPeers) {
        if (pn instanceof OpennetPeerNode) continue;
        keep.add(pn);
        if (pn.isConnected()) conn.add(pn);
      }
      myPeers = keep.toArray(new PeerNode[0]);
      connectedPeers = keep.toArray(new PeerNode[conn.size()]);
    }
    updatePMUserAlert();
    notifyPeerStatusChangeListeners();
  }

  @SuppressWarnings("unused")
  public PeerNode containsPeer(PeerNode pn) {
    PeerNode[] peers = pn.isOpennet() ? getOpennetAndSeedServerPeers() : getDarknetPeers();

    for (PeerNode peer : peers)
      if (Arrays.equals(pn.getPubKeyHash(), peer.getPubKeyHash())) return peer;

    return null;
  }

  /**
   * Counts connected darknet peers that are routable and not opennet.
   *
   * @return Number of connected darknet peers.
   */
  public int countConnectedDarknetPeers() {
    int count = 0;
    PeerNode[] peers = myPeers();
    for (PeerNode peer : peers) {
      if ((peer instanceof DarknetPeerNode) && !peer.isOpennet() && peer.isRoutable()) {
        count++;
      }
    }
    if (LOG.isDebugEnabled()) LOG.debug("countConnectedDarknetPeers() returning {}", count);
    return count;
  }

  /**
   * Counts all connected and routable peers.
   *
   * @return Number of connected routable peers.
   */
  public int countConnectedPeers() {
    return countConnectedPeers(myPeers());
  }

  private int countConnectedPeers(PeerNode[] peers) {
    int count = 0;
    for (PeerNode peer : peers) {
      if (peer != null && peer.isRoutable()) count++;
    }
    return count;
  }

  /**
   * Counts darknet peers that are connected (regardless of routability).
   *
   * @return Number of connected darknet peers.
   */
  public int countAlmostConnectedDarknetPeers() {
    int count = 0;
    PeerNode[] peers = myPeers();
    for (PeerNode peer : peers) {
      if ((peer instanceof DarknetPeerNode) && !peer.isOpennet() && peer.isConnected()) {
        count++;
      }
    }
    return count;
  }

  /**
   * Counts darknet peers that are connected and routing-compatible.
   *
   * @return Number of compatible darknet peers.
   */
  public int countCompatibleDarknetPeers() {
    int count = 0;
    PeerNode[] peers = myPeers();
    for (PeerNode peer : peers) {
      if ((peer instanceof DarknetPeerNode)
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
   * @return Number of compatible real peers.
   */
  public int countCompatibleRealPeers() {
    int count = 0;
    PeerNode[] peers = myPeers();
    for (PeerNode peer : peers) {
      if (peer != null
          && peer.isRealConnection()
          && peer.isConnected()
          && peer.isRoutingCompatible()) {
        count++;
      }
    }
    return count;
  }

  /**
   * Counts connected opennet peers that are routable.
   *
   * @return Number of connected opennet peers.
   */
  public int countConnectedOpennetPeers() {
    int count = 0;
    PeerNode[] peers = connectedPeers();
    for (PeerNode peer : peers) {
      if ((peer instanceof OpennetPeerNode) && peer.isRoutable()) {
        count++;
      }
    }
    return count;
  }

  /**
   * How many peers do we have that actually may connect? Don't include seednodes, disabled nodes,
   * etc.
   */
  public int countValidPeers() {
    PeerNode[] peers = myPeers();
    int count = 0;
    for (PeerNode peer : peers) {
      if (peer.isRealConnection() && !peer.isDisabled()) count++;
    }
    return count;
  }

  /**
   * How many peers do we have that actually may connect? Don't include seednodes, disabled nodes,
   * etc.
   */
  public int countConnectiblePeers() {
    PeerNode[] peers = myPeers();
    int count = 0;
    for (PeerNode peer : peers) {
      boolean isListenOnlyDarknet =
          (peer instanceof DarknetPeerNode peerNode) && peerNode.isListenOnly();
      if (!peer.isDisabled() && !isListenOnlyDarknet) count++;
    }
    return count;
  }

  /**
   * Counts peers that are seed servers or seed clients.
   *
   * @return Number of seed nodes.
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
   * @param realTime If true, consider realtime backoff; otherwise bulk backoff.
   * @return Number of peers in backoff.
   */
  public int countBackedOffPeers(boolean realTime) {
    PeerNode[] peers = myPeers();
    int count = 0;
    for (PeerNode peer : peers) {
      if (peer.isRealConnection() && !peer.isDisabled() && peer.isRoutingBackedOff(realTime))
        count++;
    }
    return count;
  }

  /**
   * Returns the peer with the given public key hash, if present.
   *
   * @param pkHash ECDSA public key hash.
   * @return Matching peer or {@code null}.
   */
  public PeerNode getByPubKeyHash(byte[] pkHash) {
    PeerNode[] peers = myPeers();
    for (PeerNode peer : peers) {
      if (Arrays.equals(peer.peerECDSAPubKeyHash, pkHash)) return peer;
    }
    return null;
  }

  void incrementSelectionSamples(PeerNode pn) {
    // Note: consider reimplementing with a bit field to reduce memory usage
    pn.incrementNumberOfSelections();
  }

  /** Notifies the listeners about status change */
  private void notifyPeerStatusChangeListeners() {
    for (PeerStatusChangeListener l : listeners) {
      l.onPeerStatusChange();
      for (PeerNode pn : myPeers()) {
        pn.registerPeerNodeStatusChangeListener(l);
      }
    }
  }

  /**
   * Registers a listener to be notified when peers' statuses changes
   *
   * @param listener - the listener to be registered
   */
  public void addPeerStatusChangeListener(PeerStatusChangeListener listener) {
    listeners.add(listener);
    for (PeerNode pn : myPeers()) {
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
    /** Peers status have changed */
    void onPeerStatusChange();
  }

  /**
   * Get a non-copied snapshot of the peers list. NOTE: LOW LEVEL: Should be up to date (but not
   * guaranteed when exit lock), DO NOT MODIFY THE RETURNED DATA! Package-local - stuff outside
   * node/ should use the copying getters (which are a little more expensive).
   */
  synchronized PeerNode[] myPeers() {
    return myPeers;
  }

  /**
   * Get the last snapshot of the connected peers list. NOTE: This is not as reliable as using the
   * copying getters (or even using myPeers() and then checking each peer). But it is fast.
   *
   * <p>Note: Check all callers. Should they use myPeers and check for connectedness, and/or should
   * they use a copying method? I'm not sure how reliable updating of connectedPeers is ...
   */
  synchronized PeerNode[] connectedPeers() {
    return connectedPeers;
  }

  /**
   * Count the number of PeerNode's with a given status (right now, not based on a snapshot). Note
   * you should not call this if holding lots of locks!
   */
  public int countByStatus(int status) {
    int count = 0;
    PeerNode[] peers = myPeers();
    for (PeerNode peer : peers) {
      if (peer.getPeerNodeStatus() == status) count++;
    }
    return count;
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

    // Note: constants below are heuristics and may require tuning.
    // We cannot count on the version announcements.
    // Until we actually get a validated update jar it's all potentially bogus.

    int connections =
        getPeerNodeStatusSize(PEER_NODE_STATUS_CONNECTED, false)
            + getPeerNodeStatusSize(PEER_NODE_STATUS_ROUTING_BACKED_OFF, false);

    if (tooNewOpennet >= OUTDATED_MIN_TOO_NEW_TOTAL) {
      return connections < OUTDATED_MAX_CONNS;
    } else return false;
  }
}

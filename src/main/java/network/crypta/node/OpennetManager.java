package network.crypta.node;

import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import network.crypta.crypt.Util;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.DisconnectedException;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.OpennetAnnounceRequest;
import network.crypta.io.comm.Peer;
import network.crypta.io.comm.PeerParseException;
import network.crypta.io.xfer.BulkTransmitter;
import network.crypta.io.xfer.PartiallyReceivedBulk;
import network.crypta.node.OpennetPeerNode.NOT_DROP_REASON;
import network.crypta.support.Fields;
import network.crypta.support.LRUQueue;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.TimeSortedHashtable;
import network.crypta.support.io.ByteArrayRandomAccessBuffer;
import network.crypta.support.io.FileUtil;
import network.crypta.support.transport.ip.HostnameSyntaxException;
import network.crypta.support.transport.ip.IPUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages opennet peer lifecycle, cryptographic state, and announcement workflows for a node.
 *
 * <p>This component loads and persists opennet crypto material, maintains separate LRU queues for
 * short and long links, and applies admission/drop heuristics when peers connect, disconnect, or
 * are offered. It also drives opennet announcement and noderef exchange flows, including padded
 * transfers and bulk-send callbacks. Typical usage is to construct it during node initialization,
 * call {@link #start()} after the network layer is ready, and invoke {@link #stop(boolean)} during
 * shutdown.
 *
 * <p>State is mutable and shared across networking and scheduler threads; most LRU mutations and
 * counters are synchronized on {@code this}. Drop decisions balance grace-period protections,
 * bandwidth-based scaling, and protection against overfilling with outdated peers.
 *
 * <ul>
 *   <li>Manages per-distance LRU queues and old-peer tracking.
 *   <li>Coordinates noderef send/receive and announcement initiation.
 *   <li>Persists opennet crypto state to per-port files.
 * </ul>
 *
 * @author toad
 */
public class OpennetManager {
  private static final Logger LOG = LoggerFactory.getLogger(OpennetManager.class);
  private static final String OPENNET_FILE_PREFIX = "opennet-";

  private static final Comparator<OpennetPeerNode> PEER_COMPARATOR =
      (pn1, pn2) -> {
        if (pn1 == pn2) {
          return 0;
        }
        long lastSuccess1 = pn1.timeLastSuccess();
        long lastSuccess2 = pn2.timeLastSuccess();

        if (lastSuccess1 > lastSuccess2) {
          return 1;
        }
        if (lastSuccess2 > lastSuccess1) {
          return -1;
        }

        boolean neverConnected1 = pn1.neverConnected();
        boolean neverConnected2 = pn2.neverConnected();
        if (neverConnected1 && !neverConnected2) {
          return -1;
        }
        if (!neverConnected1 && neverConnected2) {
          return 1;
        }
        // a-b not the opposite sign to b-a possible in a corner case (a=0 b=Integer.MIN_VALUE).
        if (pn1.hashCode > pn2.hashCode) {
          return 1;
        } else if (pn1.hashCode < pn2.hashCode) {
          return -1;
        }
        LOG.error("Duplicate OpennetPeerNode hashCode for {} vs {}", pn1, pn2);
        return Fields.compareObjectID(pn1, pn2);
      };

  private final Node node;

  private final NodeCrypto crypto;

  private final Announcer announcer;

  private final SeedAnnounceTracker seedTracker = new SeedAnnounceTracker();

  /* The routing table is split into "buckets" by distance, each of which has a separate LRU
   * list. For now there are only 2 buckets; the PETS paper suggested many buckets, but this
   * would have larger overhead, more dependence on the network size, and it is not clear that
   * it is necessary at the moment.
   *
   * The measured global link length distribution showed a good (1/d) length distribution below
   * 0.01 (but nowhere near enough nodes) and a flat distribution above 0.01. Hence, the choice of
   * LONG_DISTANCE as 0.01. It appeared that there were very few short links (~ 15% less than
   * 0.01 distance) and a lot of random long links, which is the opposite of what we need for
   * good routing, so requests would mostly bounce around randomly on the long links.
   *
   * LONG_PROPORTION is chosen as 30% for two reasons: (a) It is close to the Kleinberg optimum
   * (around 20%), and (b) it ensures that nodes with 10 connections still have 3 long links, so
   * long links cannot form chains and the routing still scales if the short routing is broken.
   *
   * See USK@ZLwcSLwqpM1527Tw1YmnSiXgzITU0neHQ11Cyl0iLmk,f6FLo3TvsEijIcJq-X3BTjjtm0ErVZwAPO7AUd9V7lY,AQACAAE/fix-link-length/22/
   * Note: move to wiki or other permanent storage.
   */
  /** Peers with more than this distance are considered "long links". */
  static final double LONG_DISTANCE = 0.01;

  /** This proportion of the routing table consists of "long links". */
  static final double LONG_PROPORTION = 0.3;

  /**
   * Proportion of the routing table assigned to short links.
   *
   * <p>This is computed as {@code 1.0 - LONG_PROPORTION} and is used to size the short-link LRU
   * relative to the overall target peer count.
   */
  public static final double SHORT_PROPORTION = 1.0 - LONG_PROPORTION;

  /**
   * Assumed proportion of slow peers when scaling the target peer count.
   *
   * <p>The model inflates the target to compensate for peers that cannot supply full bandwidth per
   * connection, keeping fast nodes from underutilizing available capacity.
   */
  public static final double ASSUMPTION_50_PERCENT_SLOW_PEERS = 0.5;

  /**
   * Classifies peers by link distance for separate LRU management and capacity targeting.
   *
   * <p>Each class derives its target count from the overall opennet peer target so the manager can
   * enforce a stable long/short split as the node's capacity changes. The classification informs
   * drop decisions and offers behavior.
   */
  public enum LinkLengthClass {
    /**
     * Peers shorter than {@link #LONG_DISTANCE}, favoring locality and routing efficiency.
     *
     * <p>The target count is the overall target minus the long-link allocation, so it scales as the
     * opennet target changes while preserving the configured split.
     */
    SHORT {
      @Override
      public int getTargetPeers(int target) {
        int longPeers = (int) (target * LONG_PROPORTION);
        return target - longPeers;
      }
    },
    /**
     * Peers longer than {@link #LONG_DISTANCE}, providing random long-distance shortcuts.
     *
     * <p>The target count is a proportional slice of the overall target and grows as total peer
     * capacity increases, preserving long-link availability for routing.
     */
    LONG {
      @Override
      public int getTargetPeers(int target) {
        return (int) (target * LONG_PROPORTION);
      }
    };

    /**
     * Return the target number of peers for this class, given the overall target.
     *
     * <p>The target is derived from the current overall peer target and preserves the configured
     * long/short split.
     *
     * @param target the overall peer target count used as the allocation base
     * @return the target peer count for this class
     */
    public abstract int getTargetPeers(int target);
  }

  /**
   * Peers LRUs by LinkLengthClass. PeerNodes are promoted within their LRU when they successfully
   * fetch a key. Normally we take the bottom peer, but if that isn't eligible to be dropped, we
   * iterate up the list.
   */
  private final EnumMap<LinkLengthClass, LRUQueue<OpennetPeerNode>> peersLRUByDistance;

  /**
   * Old peers. Opennet peers which we dropped but would still like to talk to if we have no other
   * option.
   */
  private final LRUQueue<OpennetPeerNode> oldPeers;

  /** Maximum number of old peers */
  static final int MAX_OLD_PEERS = 25;

  /** Time at which last dropped a peer due to an incoming connection of each type. */
  private final EnumMap<ConnectionType, Long> timeLastDropped;

  // These only count stuff where we actually have a node to add.
  private final EnumMap<ConnectionType, Long> connectionAttempts;
  private final EnumMap<ConnectionType, Long> connectionAttemptsAdded;
  private final EnumMap<ConnectionType, Long> connectionAttemptsAddedPlentySpace;
  private final EnumMap<ConnectionType, Long> connectionAttemptsRejectedByPerTypeEnforcement;
  private final EnumMap<ConnectionType, Long> connectionAttemptsRejectedNoPeersDroppable;

  /**
   * Number of successful CHK requests since last added a node. All values are incremented on a
   * successful request, but when we add a node, we reset the value for that type of node.
   */
  private final EnumMap<ConnectionType, Long> successCount;

  /**
   * Minimum successful requests required before dropping a connection of a given type.
   *
   * <p>This guards against churn by ensuring a peer participates in a modest number of successful
   * requests before it becomes eligible for drop decisions within its connection class.
   */
  // Consider whether this should be a function of the number of opennet peers or the maximum
  // number of opennet peers.
  public static final int MIN_SUCCESS_BETWEEN_DROP_CONNS = 10;

  /**
   * Inverse probability of resetting path folding for plausible deniability.
   *
   * <p>A value of {@code 20} means a one-in-twenty chance to reset the path folding state when the
   * relevant logic triggers.
   */
  public static final int RESET_PATH_FOLDING_PROB = 20;

  /**
   * The minimum age a connected peer must reach before it becomes droppable.
   *
   * <p>This delay gives newly connected peers time to participate in traffic before they are
   * considered for removal.
   */
  public static final long DROP_MIN_AGE = MINUTES.toMillis(5);

  /**
   * The minimum age a disconnected peer must reach before it becomes droppable.
   *
   * <p>This applies when the peer has not yet connected; after one successful connection, {@link
   * #DROP_DISCONNECT_DELAY} governs disconnect-based drop timing. The value must remain shorter
   * than {@link #DROP_MIN_AGE} and is intentionally generous to accommodate slow noderef transfers.
   */
  public static final long DROP_MIN_AGE_DISCONNECTED = MINUTES.toMillis(5);

  /**
   * Startup grace period before any peer drops are permitted.
   *
   * <p>This reduces early churn while the node is still establishing its initial set of peers.
   */
  public static final long DROP_STARTUP_DELAY = MINUTES.toMillis(2);

  /**
   * Grace period after a disconnect before the peer becomes droppable.
   *
   * <p>The intent is to cover a typical reboot while avoiding an accumulation of disconnected
   * strangers. This should generally not exceed {@link #DROP_MIN_AGE}.
   */
  public static final long DROP_DISCONNECT_DELAY = MINUTES.toMillis(5);

  /**
   * Cooldown window for repeated disconnects.
   *
   * <p>If a peer disconnects more than once inside this interval, it may be dropped even if the
   * usual disconnect grace period otherwise protects it.
   */
  public static final long DROP_DISCONNECT_DELAY_COOLDOWN = MINUTES.toMillis(60);

  /**
   * Interval that permits dropping a connected peer to refresh the LRU.
   *
   * <p>This is tracked per connection type and allows periodic replacement even when peers remain
   * connected, preventing the table from becoming overly static.
   */
  public static final long DROP_CONNECTED_TIME = MINUTES.toMillis(5);

  /**
   * Minimum interval between opennet offers while at maximum capacity.
   *
   * <p>Offers may be rejected, so this is shorter than drop-related limits to avoid stalling
   * acquisition when the table is full.
   */
  public static final long MIN_TIME_BETWEEN_OFFERS = SECONDS.toMillis(30);

  /**
   * Padded size in bytes for opennet noderef transfers.
   *
   * <p>Noderefs smaller than this are padded up to this size for privacy. If a noderef exceeds this
   * size, the sending path rejects it rather than truncating.
   */
  public static final int PADDED_NODEREF_SIZE = 3072;

  /**
   * Maximum permitted opennet noderef length in bytes.
   *
   * <p>This allows for future expansion. At any given time, noderefs are expected to be not larger
   * than {@link #PADDED_NODEREF_SIZE}, and larger values are rejected before transfer.
   */
  public static final int MAX_OPENNET_NODEREF_LENGTH = 32768;

  /**
   * Whether bandwidth-based scaling is enabled when computing target peers.
   *
   * <p>When enabled, the target peer count is derived from output bandwidth and then capped by
   * network heuristics and user limits.
   */
  public static final boolean ENABLE_PEERS_PER_KB_OUTPUT = true;

  /**
   * Constant for scaling peers: we multiply bandwidth in kB/sec by this and then take the square
   * root. Minimum is MIN_PEERs_FOR_SCALING.
   *
   * <p>(define (peers kbps) (sqrt (* kbps scaling)))
   *
   * <p>Scaling at 3 gives 4 peers at 5K (min peers), 5 at 7K, 5 at 10K, 8 at 20K, 9 at 30K, 13 at
   * 60K, 17 at 100K, 20 at 140K, 87 at 2500K. 106 at 30mbit/s (the mean upload in Japan in 2014)
   * and 180 at 88mbit/s (the mean upload in Hong Kong in 2014).
   */
  public static final double SCALING_CONSTANT = 3;

  /**
   * Minimum number of peers. As an estimate, because the vast majority of requests that are
   * completed in 5 hops and 10 peers give just one binary decision per hop. However, the
   * distribution of peers before the link length fix showed that having 3 short distance peers
   * still worked, since requests preferentially go through higher capacity nodes with more FOAFs.
   */
  public static final int MIN_PEERS_FOR_SCALING = 4;

  /**
   * Maximum possible distance between two nodes in wrapping {@code [0,1)} location space.
   *
   * <p>Distances larger than this are equivalent under wrap-around and therefore do not appear in
   * the routing model.
   */
  public static final double MAX_DISTANCE = 0.5;

  /**
   * Estimated fraction of nodes that are a short distance away.
   *
   * <p>This is derived from {@link #LONG_DISTANCE} and {@link #MAX_DISTANCE} and is used in
   * heuristic peer-cap calculations.
   */
  public static final double SHORT_NODES_FRACTION = LONG_DISTANCE / MAX_DISTANCE;

  /**
   * Estimated average number of active nodes in the network.
   *
   * <p>This heuristic feeds into calculations for the available short-distance peer pool.
   */
  public static final int LAST_NETWORK_SIZE_ESTIMATE = 3000;

  /**
   * Estimated number of nodes within the short-distance region.
   *
   * <p>This is a derived heuristic used to bound how many short links a node can reasonably
   * maintain.
   */
  public static final int AVAILABLE_SHORT_DISTANCE_NODES =
      (int) (LAST_NETWORK_SIZE_ESTIMATE * SHORT_NODES_FRACTION);

  /**
   * Maximum number of peers allowed by short-link availability heuristics.
   *
   * <p>This cap is based on the expected number of short-distance nodes. Above this value, fast
   * nodes are unlikely to find enough suitable short links for efficient routing.
   *
   * @see OpennetManager.LinkLengthClass
   */
  public static final int MAX_PEERS_FOR_SCALING =
      (int) (AVAILABLE_SHORT_DISTANCE_NODES / SHORT_PROPORTION);

  /**
   * Absolute maximum peer count used for FOAF attack/sanity checks.
   *
   * <p>This is a small buffer above {@link #MAX_PEERS_FOR_SCALING} to detect abnormal peer counts
   * without immediately capping normal scaling.
   */
  public static final int PANIC_MAX_PEERS = MAX_PEERS_FOR_SCALING + 10;

  /**
   * Time limit for attempting reconnections to old opennet peers.
   *
   * <p>After this interval the old-peer record is considered too stale to retry.
   */
  public static final long MAX_TIME_ON_OLD_OPENNET_PEERS = DAYS.toMillis(31);

  // This is only relevant while the connection is in the grace period.
  // Null means none of the above e.g., not in the grace period.
  /**
   * Categorizes the reason a peer is being connected for grace-period enforcement and counters.
   *
   * <p>Each type influences per-type limits and drop timing. The categories are used to separate
   * path folding, announcements, and reconnection attempts so that one flow cannot consume all
   * grace-period slots.
   */
  public enum ConnectionType {
    /**
     * Connection established as part of a path-folding exchange.
     *
     * <p>These peers are acquired opportunistically to improve routing locality. They are tracked
     * separately so path folding cannot exhaust the grace-period budget.
     */
    PATH_FOLDING(0),
    /**
     * Connection established to support an announcement exchange.
     *
     * <p>Announcement-driven peers are tracked separately to avoid crowding out other types. This
     * category helps keep announcement bursts from displacing routine connections.
     */
    ANNOUNCE(1),
    /**
     * Connection created to re-establish contact with a previously known peer.
     *
     * <p>This is used for reconnecting peers from old-peer tracking or recent successes. It is also
     * used when a successful peer is re-added after falling out of the LRU.
     */
    RECONNECT(2);

    private final int code;

    ConnectionType(int code) {
      this.code = code;
    }

    int code() {
      return code;
    }
  }

  private final long creationTime;

  private boolean stopping;

  /**
   * Create an {@code OpennetManager} and initialize opennet crypto from disk if available.
   *
   * <p>Crypto state is loaded from files named {@code opennet-<port>} (and {@code .bak}) under the
   * node directory. If neither file can be read, a new crypto state is generated. The constructor
   * also initializes per-type counters and LRU containers but does not start network activity; call
   * {@link #start()} once the {@link Node} has completed construction. This keeps construction
   * lightweight and avoids callbacks while the node is still initializing.
   *
   * @param node owning {@link Node} instance; must not be {@code null}
   * @param opennetConfig opennet crypto configuration defining ports and keys
   * @param startupTime node startup epoch in milliseconds for crypto seeding
   * @param enableAnnouncement whether to enable the announcer component on the start
   * @throws NodeInitException if crypto initialization fails or files are unreadable
   */
  public OpennetManager(
      Node node, NodeCryptoConfig opennetConfig, long startupTime, boolean enableAnnouncement)
      throws NodeInitException {
    this.creationTime = System.currentTimeMillis();
    this.node = node;
    crypto = new NodeCrypto(node, true, opennetConfig, startupTime, node.isEnableARKs());

    timeLastDropped = new EnumMap<>(ConnectionType.class);
    connectionAttempts = new EnumMap<>(ConnectionType.class);
    connectionAttemptsAdded = new EnumMap<>(ConnectionType.class);
    connectionAttemptsAddedPlentySpace = new EnumMap<>(ConnectionType.class);
    connectionAttemptsRejectedByPerTypeEnforcement = new EnumMap<>(ConnectionType.class);
    connectionAttemptsRejectedNoPeersDroppable = new EnumMap<>(ConnectionType.class);
    successCount = new EnumMap<>(ConnectionType.class);
    for (ConnectionType c : ConnectionType.values()) {
      timeLastDropped.put(c, 0L);
      connectionAttempts.put(c, 0L);
      connectionAttemptsAdded.put(c, 0L);
      connectionAttemptsAddedPlentySpace.put(c, 0L);
      connectionAttemptsRejectedByPerTypeEnforcement.put(c, 0L);
      connectionAttemptsRejectedNoPeersDroppable.put(c, 0L);
      successCount.put(c, 0L);
    }

    File nodeFile = node.nodeDir().file(OPENNET_FILE_PREFIX + crypto.getPortNumber());
    File backupNodeFile =
        node.nodeDir().file(OPENNET_FILE_PREFIX + crypto.getPortNumber() + ".bak");

    // Keep opennet crypto details in a separate file
    try {
      readFile(nodeFile);
    } catch (IOException _) {
      try {
        readFile(backupNodeFile);
      } catch (IOException _) {
        crypto.initCrypto();
      }
    }
    peersLRUByDistance = new EnumMap<>(LinkLengthClass.class);
    for (LinkLengthClass l : LinkLengthClass.values()) peersLRUByDistance.put(l, new LRUQueue<>());
    oldPeers = new LRUQueue<>();
    announcer = (enableAnnouncement ? new Announcer(this) : null);
  }

  /**
   * Persist current opennet crypto state to disk.
   *
   * <p>The state is written to {@code opennet-<port>} using a temporary backup file. Failures are
   * intentionally swallowed to preserve runtime behavior, so callers should treat persistence as
   * best-effort. This method does not synchronize on the manager; invoke it from safe contexts that
   * do not race with crypto replacement or concurrent file writes.
   */
  public void writeFile() {
    File nodeFile = node.nodeDir().file(OPENNET_FILE_PREFIX + crypto.getPortNumber());
    File backupNodeFile =
        node.nodeDir().file(OPENNET_FILE_PREFIX + crypto.getPortNumber() + ".bak");
    writeFile(nodeFile, backupNodeFile);
  }

  private void writeFile(File orig, File backup) {
    SimpleFieldSet fs = crypto.exportPrivateFieldSet();

    if (orig.exists()) {
      try {
        Files.deleteIfExists(backup.toPath());
      } catch (IOException _) {
        // Keep behavior: ignore delete failures
      }
    }

    try (FileOutputStream fos = new FileOutputStream(backup);
        OutputStreamWriter osr = new OutputStreamWriter(fos, StandardCharsets.UTF_8);
        BufferedWriter bw = new BufferedWriter(osr)) {
      fs.writeTo(bw);
      bw.flush(); // Ensure data is written before moving the file
      FileUtil.moveTo(backup, orig);
    } catch (IOException _) {
      // Resources are automatically closed by try-with-resources
    }
  }

  private void readFile(File filename) throws IOException {
    // REDFLAG: Any way to share this code with Node and NodePeer?
    try (FileInputStream fis = new FileInputStream(filename);
        InputStreamReader isr = new InputStreamReader(fis, StandardCharsets.UTF_8);
        BufferedReader br = new BufferedReader(isr)) {
      SimpleFieldSet fs = new SimpleFieldSet(br, false, true);
      // Read contents
      String[] udp = fs.getAll("physical.udp");
      if (udp != null) {
        for (String u : udp) {
          // Just keep the first one with the correct port number.
          Peer p = parseUdpPeerOrThrow(u);
          if (p != null && p.getPort() == crypto.getPortNumber()) {
            // DNSRequester doesn't deal with our own node
            node.network().ipDetector().setOldIPAddress(p.getFreenetAddress());
            break;
          }
        }
      }

      crypto.readCrypto(fs);
    } // end try-with-resources
  }

  private Peer parseUdpPeerOrThrow(String u) throws IOException {
    try {
      return new Peer(u, false, true);
    } catch (HostnameSyntaxException _) {
      LOG.error("Invalid hostname or IP address in opennet peer reference: {}", u);
      return null; // skip invalid
    } catch (PeerParseException e) {
      throw new IOException(e);
    }
  }

  /**
   * Start opennet subsystems.
   *
   * <p>This loads known opennet peers, initializes LRUs, drops excess peers, and loads old peers
   * for opportunistic reconnection. It then starts the crypto engine and, if enabled, the
   * announcer. Call this after the network stack is constructed; it is safe to call only once per
   * instance and is not idempotent across multiple invocations.
   */
  public void start() {
    synchronized (this) {
      stopping = false;
    }
    // Do this outside the constructor, since the constructor is called by the Node constructor, and
    // callbacks may make assumptions about data structures being ready.
    node.network()
        .peers()
        .tryReadPeers(
            node.nodeDir().file("openpeers-" + crypto.getPortNumber()).toString(),
            crypto,
            this,
            true,
            false);
    OpennetPeerNode[] nodes = node.network().peers().roster().getOpennetPeers();
    Arrays.sort(nodes, PEER_COMPARATOR);
    initLRUsFromExisting(nodes);
    if (LOG.isDebugEnabled()) {
      LOG.debug("Local compressed full reference length={}", crypto.myCompressedFullRef().length);
      LOG.debug("Local compressed setup reference length={}", crypto.myCompressedSetupRef().length);
      LOG.debug(
          "Local compressed heavy-setup reference length={}",
          crypto.myCompressedHeavySetupRef().length);
    }
    dropAllExcessPeers();
    writeFile();
    // Read old peers
    node.network()
        .peers()
        .tryReadPeers(
            node.nodeDir().file("openpeers-old-" + crypto.getPortNumber()).toString(),
            crypto,
            this,
            true,
            true);
    crypto.start();
    if (announcer != null) announcer.start();
  }

  /**
   * Stop opennet subsystems and optionally purge opennet peers.
   *
   * <p>This marks the manager as stopping, halts the announcer (if present), stops opennet crypto,
   * and resets the address tracker to a presumed-innocent state. When {@code purge} is {@code
   * true}, opennet peers are also removed from the global peer list. The method does not persist
   * state; callers should invoke {@link #writeFile()} if persistence is needed.
   *
   * @param purge whether to remove opennet peers from the global peer list
   */
  public void stop(boolean purge) {
    synchronized (this) {
      stopping = true;
    }
    if (announcer != null) announcer.stop();
    crypto.stop();
    if (purge) node.network().peers().removeOpennetPeers();
    crypto.getSocket().getAddressTracker().setPresumedInnocent();
  }

  synchronized boolean stopping() {
    return stopping;
  }

  private void initLRUsFromExisting(OpennetPeerNode[] nodes) {
    for (OpennetPeerNode opn : nodes) {
      // Drop any peers that don't have a location yet. That means we haven't connected to
      // them yet, and we need the location to decide which LRU to put them in ...
      // This should only be a problem with old nodes; we will include the location in new
      // path folding noderefs...
      if (Location.isValid(opn.getLocation())) {
        lruQueue(opn).push(opn);
      } else {
        node.network().peers().messenger().disconnectAndRemove(opn, false, false, false);
      }
    }
  }

  private LRUQueue<OpennetPeerNode> lruQueue(LinkLengthClass distance) {
    return peersLRUByDistance.get(distance);
  }

  private LRUQueue<OpennetPeerNode> lruQueue(OpennetPeerNode pn) {
    return lruQueue(pn.linkLengthClass());
  }

  private record WantPeerContext(
      LRUQueue<OpennetPeerNode> peersLRU,
      LinkLengthClass distance,
      OpennetPeerNode nodeToAddNow,
      ConnectionType connectionType,
      boolean oldOpennetPeer,
      boolean outdated,
      long now) {}

  private static final class WantPeerSyncState {
    boolean notMany;
    boolean noDisconnect;
    boolean earlyReturn;
    boolean earlyReturnValue;
  }

  private boolean checkOutdatedRejection(
      boolean outdated, ConnectionType connectionType, OpennetPeerNode nodeToAddNow) {
    if (outdated && tooManyOutdatedPeers()) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Reject peer from {} due to too many outdated peers: {}", connectionType, nodeToAddNow);
      return true;
    }
    return false;
  }

  private boolean violatesAddressPolicy(
      OpennetPeerNode nodeToAddNow, ConnectionType connectionType) {
    if (!crypto.getConfig().oneConnectionPerAddress()) return false;

    Peer[] handshakeIPs = nodeToAddNow.getHandshakeIPs();
    if (handshakeIPs == null) {
      LOG.debug(
          "No handshake IPs for {}; skip oneConnectionPerAddress check (type={})",
          nodeToAddNow,
          connectionType);
      return false;
    }

    AddressPolicyState st = checkHandshakeAddresses(handshakeIPs, nodeToAddNow);
    if (st.anyValid && !st.allAllowed) {
      LOG.info("Reject peer; already connected to same IP address");
      return true;
    }
    return false;
  }

  private record AddressPolicyState(boolean anyValid, boolean allAllowed) {}

  private AddressPolicyState checkHandshakeAddresses(
      Peer[] handshakeIPs, OpennetPeerNode nodeToAddNow) {
    boolean any = false;
    for (Peer p : handshakeIPs) {
      if (p != null) {
        FreenetInetAddress addr = p.getFreenetAddress();
        InetAddress a = (addr == null) ? null : addr.getAddress(false);
        boolean invalid =
            (a == null)
                || a.isAnyLocalAddress()
                || a.isLinkLocalAddress()
                || IPUtil.isSiteLocalAddress(a);
        if (!invalid) {
          any = true;
          if (!crypto.allowConnection(nodeToAddNow, addr)) {
            // NodeCrypto rejected an address; reject the peer per policy
            return new AddressPolicyState(true, false);
          }
        }
      }
    }
    return new AddressPolicyState(any, true);
  }

  private WantPeerSyncState decideInitialSync(
      WantPeerContext ctx, int maxPeers, boolean addAtLRU, boolean justChecking) {
    WantPeerSyncState state = new WantPeerSyncState();
    synchronized (this) {
      if (isAlreadyPresentInLRU(ctx)) {
        state.earlyReturn = true;
        state.earlyReturnValue = true;
        return state;
      }

      incrementConnectionAttemptIfAdding(ctx);

      if (hasCapacityOrOutdated(ctx, maxPeers)) {
        handleAddWhenNotFull(ctx, addAtLRU);
        updateOfferTimestampIfNeeded(ctx, justChecking);
        state.notMany = true;
      }

      state.noDisconnect = shouldAvoidDisconnect(ctx);
    }
    return state;
  }

  private boolean isAlreadyPresentInLRU(WantPeerContext ctx) {
    if (ctx.nodeToAddNow != null && ctx.peersLRU.contains(ctx.nodeToAddNow)) {
      if (LOG.isDebugEnabled()) LOG.debug("Opennet peer already in LRU: {}", ctx.nodeToAddNow);
      return true;
    }
    return false;
  }

  private void incrementConnectionAttemptIfAdding(WantPeerContext ctx) {
    if (ctx.nodeToAddNow != null) {
      connectionAttempts.put(ctx.connectionType, connectionAttempts.get(ctx.connectionType) + 1);
    }
  }

  private boolean hasCapacityOrOutdated(WantPeerContext ctx, int maxPeers) {
    return getSize(ctx.distance) < maxPeers || ctx.outdated;
  }

  private void handleAddWhenNotFull(WantPeerContext ctx, boolean addAtLRU) {
    if (ctx.nodeToAddNow != null) {
      if (LOG.isDebugEnabled())
        LOG.debug("Add opennet peer {}; peers list has capacity", ctx.nodeToAddNow);
      if (addAtLRU) ctx.peersLRU.pushLeast(ctx.nodeToAddNow);
      else ctx.peersLRU.push(ctx.nodeToAddNow);
      oldPeers.remove(ctx.nodeToAddNow);
      connectionAttemptsAddedPlentySpace.put(
          ctx.connectionType, connectionAttemptsAddedPlentySpace.get(ctx.connectionType) + 1);
    } else {
      if (LOG.isDebugEnabled()) LOG.debug("Request opennet peer; insufficient peers");
    }
  }

  private void updateOfferTimestampIfNeeded(WantPeerContext ctx, boolean justChecking) {
    if (ctx.nodeToAddNow == null && !justChecking) {
      timeLastOffered = System.currentTimeMillis();
    }
  }

  private boolean shouldAvoidDisconnect(WantPeerContext ctx) {
    return successCount.get(ctx.connectionType) < MIN_SUCCESS_BETWEEN_DROP_CONNS
        || ctx.oldOpennetPeer
        || (ctx.nodeToAddNow == null && ctx.now - timeLastOffered <= MIN_TIME_BETWEEN_OFFERS)
        || ctx.now - timeLastDropped.get(ctx.connectionType) < DROP_CONNECTED_TIME;
  }

  private record DropResult(boolean canAdd, List<OpennetPeerNode> dropList) {}

  private DropResult computeDropAndMaybeAdd(
      WantPeerContext ctx, boolean addAtLRU, boolean justChecking, boolean noDisconnect) {
    ArrayList<OpennetPeerNode> dropList = new ArrayList<>();
    int targetPeers = getNumberOfConnectedPeersToAim(ctx.distance);
    boolean canAdd;
    synchronized (this) {
      int size = getSize(ctx.distance);
      DropDecision decision = decideDropPath(ctx, targetPeers, noDisconnect, dropList, size);
      if (decision == DropDecision.REJECT_BY_PER_TYPE) {
        return new DropResult(false, dropList);
      }
      canAdd = (decision != DropDecision.CANNOT_ADD);
      if (canAdd && !justChecking) {
        finalizeAddOrOffer(ctx, addAtLRU, dropList);
      }
    }
    return new DropResult(canAdd, dropList);
  }

  private enum DropDecision {
    PROCEED,
    CANNOT_ADD,
    REJECT_BY_PER_TYPE
  }

  private DropDecision handleFullSizeNoOffer(
      WantPeerContext ctx, int maxPeers, boolean noDisconnect) {
    OpennetPeerNode toDrop =
        peerToDrop(
            noDisconnect,
            false,
            ctx.nodeToAddNow != null,
            ctx.connectionType,
            maxPeers,
            ctx.distance,
            ctx.peersLRU);
    if (toDrop == null) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "No droppable peers at capacity; current={} cannot accept peer{}",
            ctx.peersLRU.size(),
            ctx.nodeToAddNow == null ? "" : ctx.nodeToAddNow.toString());
      if (ctx.nodeToAddNow != null)
        connectionAttemptsRejectedNoPeersDroppable.put(
            ctx.connectionType,
            connectionAttemptsRejectedNoPeersDroppable.get(ctx.connectionType) + 1);
      return DropDecision.CANNOT_ADD;
    }
    if (toDrop.isConnected()
        && enforcePerTypeGracePeriodLimits(
            maxPeers, ctx.connectionType, ctx.nodeToAddNow != null, ctx.peersLRU)) {
      if (ctx.nodeToAddNow != null)
        connectionAttemptsRejectedByPerTypeEnforcement.put(
            ctx.connectionType,
            connectionAttemptsRejectedByPerTypeEnforcement.get(ctx.connectionType) + 1);
      return DropDecision.REJECT_BY_PER_TYPE;
    }
    return DropDecision.PROCEED;
  }

  private DropDecision decideDropPath(
      WantPeerContext ctx,
      int maxPeers,
      boolean noDisconnect,
      List<OpennetPeerNode> dropList,
      int currentSize) {
    if (currentSize == maxPeers && ctx.nodeToAddNow == null) {
      return handleFullSizeNoOffer(ctx, maxPeers, noDisconnect);
    }
    return dropWhileOverLimit(ctx, maxPeers, noDisconnect, dropList);
  }

  private void finalizeAddOrOffer(
      WantPeerContext ctx, boolean addAtLRU, List<OpennetPeerNode> dropList) {
    if (ctx.nodeToAddNow != null) {
      successCount.put(ctx.connectionType, 0L);
      if (addAtLRU) ctx.peersLRU.pushLeast(ctx.nodeToAddNow);
      else ctx.peersLRU.push(ctx.nodeToAddNow);
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Added opennet peer {} after clearing {} items - now have {} opennet peers",
            ctx.nodeToAddNow,
            dropList.size(),
            ctx.peersLRU.size());
      oldPeers.remove(ctx.nodeToAddNow);
      if (!dropList.isEmpty()) {
        if (LOG.isDebugEnabled())
          LOG.debug("Drop opennet peer after add; first in drop list: {}", dropList.getFirst());
        timeLastDropped.put(ctx.connectionType, ctx.now);
      }
      connectionAttemptsAdded.put(
          ctx.connectionType, connectionAttemptsAdded.get(ctx.connectionType) + 1);
    } else {
      timeLastOffered = ctx.now;
      if (LOG.isDebugEnabled()) LOG.debug("Send opennet offer");
    }
  }

  private DropDecision dropWhileOverLimit(
      WantPeerContext ctx, int maxPeers, boolean noDisconnect, List<OpennetPeerNode> dropList) {
    while (true) {
      int size = getSize(ctx.distance);
      if (!isOverLimitForNextIteration(ctx, maxPeers, size)) {
        return DropDecision.PROCEED;
      }

      DropCandidateResult candidate = pickDropCandidate(ctx, maxPeers, noDisconnect);
      if (candidate.decision == DropDecision.CANNOT_ADD) {
        return DropDecision.CANNOT_ADD;
      }
      if (candidate.decision == DropDecision.REJECT_BY_PER_TYPE) {
        return DropDecision.REJECT_BY_PER_TYPE;
      }

      OpennetPeerNode toDrop = candidate.toDrop;
      if (ctx.nodeToAddNow != null || size > maxPeers) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Drop opennet peer {} (connected={}) of {}:{}",
              toDrop,
              toDrop.isConnected(),
              ctx.peersLRU.size(),
              getSize(ctx.distance));
        ctx.peersLRU.remove(toDrop);
        dropList.add(toDrop);
      }
    }
  }

  private boolean isOverLimitForNextIteration(WantPeerContext ctx, int maxPeers, int currentSize) {
    int allowance = (ctx.nodeToAddNow == null || ctx.outdated) ? 0 : 1;
    return currentSize > (maxPeers - allowance);
  }

  private record DropCandidateResult(DropDecision decision, OpennetPeerNode toDrop) {}

  private DropCandidateResult pickDropCandidate(
      WantPeerContext ctx, int maxPeers, boolean noDisconnect) {
    OpennetPeerNode toDrop =
        peerToDrop(
            noDisconnect,
            false,
            ctx.nodeToAddNow != null,
            ctx.connectionType,
            maxPeers,
            ctx.distance,
            ctx.peersLRU);
    if (toDrop == null) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "No droppable peers while dropping; current={} cannot accept peer{}",
            ctx.peersLRU.size(),
            ctx.nodeToAddNow == null ? "" : ctx.nodeToAddNow.toString());
      if (ctx.nodeToAddNow != null)
        connectionAttemptsRejectedNoPeersDroppable.put(
            ctx.connectionType,
            connectionAttemptsRejectedNoPeersDroppable.get(ctx.connectionType) + 1);
      return new DropCandidateResult(DropDecision.CANNOT_ADD, null);
    }
    if (toDrop.isConnected()
        && enforcePerTypeGracePeriodLimits(
            maxPeers, ctx.connectionType, ctx.nodeToAddNow != null, ctx.peersLRU)) {
      if (ctx.nodeToAddNow != null)
        connectionAttemptsRejectedByPerTypeEnforcement.put(
            ctx.connectionType,
            connectionAttemptsRejectedByPerTypeEnforcement.get(ctx.connectionType) + 1);
      return new DropCandidateResult(DropDecision.REJECT_BY_PER_TYPE, null);
    }
    return new DropCandidateResult(DropDecision.PROCEED, toDrop);
  }

  /**
   * Check whether a provided opennet reference is already present.
   *
   * <p>The reference is parsed into an {@link OpennetPeerNode} and compared against the LRU for its
   * link-length class. Parsing errors are logged and treated as "not present" so callers do not
   * have to handle exceptions during request processing. The method does not mutate the LRU and is
   * safe to call from request paths.
   *
   * @param fs field set containing the serialized noderef payload
   * @return {@code true} if an equal opennet peer is already known; {@code false} otherwise
   */
  @SuppressWarnings("java:S1181")
  public boolean alreadyHaveOpennetNode(SimpleFieldSet fs) {
    try {
      // Consider optimizing: parse only the pubkey and compare against existing peers.
      OpennetPeerNode pn =
          new OpennetPeerNode(fs, node, crypto, this, false, node.network().peers());
      if (lruQueue(pn).contains(pn)) {
        if (LOG.isDebugEnabled())
          LOG.debug("Opennet ref already known; {} already in opennet list", pn.userToString());
        return true;
      }
      // Don't check for self. That should be passed through too.
      return false;
    } catch (Throwable t) {
      // Don't break the code flow in the caller, which is normally a request.
      LOG.error("Error parsing opennet node from fieldset: {}", t, t);
      return false;
    }
  }

  /**
   * Add a new opennet peer from a serialized noderef.
   *
   * <p>This validates the reference, filters out self, checks update compatibility, and applies
   * per-type and drop heuristics. If the peer is already present and {@code allowExisting} is
   * {@code true}, the existing instance is returned so callers can reconnect. Errors are logged and
   * treated as a rejection rather than propagating exceptions. On acceptance, the method may update
   * internal LRUs and counters but does not alter the provided field set.
   *
   * @param fs field set representation of the serialized noderef
   * @param connectionType reason/category for the adding, affecting grace limits
   * @param allowExisting whether to return the current instance if already present
   * @return new or existing {@link OpennetPeerNode}, or {@code null} when rejected
   */
  @SuppressWarnings("java:S1181")
  public OpennetPeerNode addNewOpennetNode(
      SimpleFieldSet fs, ConnectionType connectionType, boolean allowExisting) {
    try {
      OpennetPeerNode pn =
          new OpennetPeerNode(fs, node, crypto, this, false, node.network().peers());
      if (Arrays.equals(pn.peerECDSAPubKeyHash, crypto.getEcdsaPubKeyHash())) {
        if (LOG.isDebugEnabled()) LOG.debug("Skip adding self as opennet peer");
        return null; // Equal to myself
      }
      LinkLengthClass distance = pn.linkLengthClass();
      LRUQueue<OpennetPeerNode> peersLRU = lruQueue(distance);
      if (peersLRU.contains(pn)) {
        if (LOG.isDebugEnabled())
          LOG.debug("Opennet add skipped; {} already in opennet list", pn.userToString());
        if (allowExisting) {
          // However, we can reconnect.
          return peersLRU.get(pn);
        } else {
          return null;
        }
      }
      if (pn.isUnroutableOlderVersion()
          && node.services().nodeUpdater() != null
          && node.services().nodeUpdater().dontAllowUOM()) {
        // We can't send the UOM to it, so we should not accept it.
        // Plus, some versions around 1320 had big problems with being connected both as a seednode
        // and as an opennet peer.
        return null;
      }
      if (wantPeer(pn, true, false, false, connectionType, distance)) return pn;
      else return null;
      // Start at the bottom. Node must prove itself.
    } catch (Throwable t) {
      // Don't break the code flow in the caller, which is normally a request.
      LOG.error("Error adding opennet node from fieldset: {}", t, t);
      return null;
    }
  }

  /** When did we last offer our noderef to some other node? */
  private long timeLastOffered;

  @SuppressWarnings("SameParameterValue")
  void forceAddPeer(OpennetPeerNode nodeToAddNow, boolean addAtLRU) {
    LinkLengthClass distance = nodeToAddNow.linkLengthClass();
    LRUQueue<OpennetPeerNode> peersLRU = lruQueue(distance);
    synchronized (this) {
      if (addAtLRU) peersLRU.pushLeast(nodeToAddNow);
      else peersLRU.push(nodeToAddNow);
      oldPeers.remove(nodeToAddNow);
    }
    dropExcessPeers(distance);
  }

  /**
   * Evaluate whether we want a peer and optionally add it.
   *
   * <p>When {@code nodeToAddNow} is {@code null}, this method decides whether to offer our noderef
   * to acquire a peer, attempting both short and long link classes. When non-null, it validates the
   * peer's location, selects its link class, applies admission heuristics, and performs the adding
   * when appropriate. Calls with {@code justChecking} avoid mutating counters or LRUs.
   *
   * <pre>{@code
   * // Example: decide whether to send an offer when at capacity.
   * boolean shouldOffer = manager.wantPeer(null, true, true, false, null);
   * }</pre>
   *
   * @param nodeToAddNow peer to add, or {@code null} to decide on offering
   * @param addAtLRU whether to place at LRU tail instead of head
   * @param justChecking whether to compute eligibility without mutating state
   * @param oldOpennetPeer whether this is a reconnection of an old peer
   * @param connectionType reason/category for the connection attempt
   * @return {@code true} if capacity exists or the peer was accepted
   */
  public boolean wantPeer(
      OpennetPeerNode nodeToAddNow,
      boolean addAtLRU,
      boolean justChecking,
      boolean oldOpennetPeer,
      ConnectionType connectionType) {
    if (nodeToAddNow != null) {
      if (!Location.isValid(nodeToAddNow.getLocation())) {
        LOG.error("Opennet node reference must include a valid location", new Exception("error"));
        return false;
      }
      // We have received a node reference, so we know whether it is long or short.
      LinkLengthClass distance = nodeToAddNow.linkLengthClass();
      return wantPeer(
          nodeToAddNow, addAtLRU, justChecking, oldOpennetPeer, connectionType, distance);
    } else {
      // Initiate path folding if we want a long link or a short link.
      // Note: ideally we would indicate whether we want long links or short links.
      return wantPeer(
              null, addAtLRU, justChecking, oldOpennetPeer, connectionType, LinkLengthClass.SHORT)
          || wantPeer(
              null, addAtLRU, justChecking, oldOpennetPeer, connectionType, LinkLengthClass.LONG);
    }
  }

  /**
   * Evaluate whether to add or offer an opennet peer for a specific link-length class.
   *
   * <p>When {@code nodeToAddNow} is {@code null}, this method decides whether to send an offer for
   * the given {@code distance} class, rate-limited by {@link #MIN_TIME_BETWEEN_OFFERS}. When a node
   * is provided, it applies per-type grace limits, outdated-peer thresholds, and capacity checks,
   * then adds and/or drops peers as needed. Calls with {@code justChecking} read state without
   * mutating counters or LRU membership.
   *
   * @param nodeToAddNow peer to add, or {@code null} to determine offer eligibility
   * @param addAtLRU whether to place at the LRU tail instead of head
   * @param justChecking whether to compute eligibility without mutating state
   * @param oldOpennetPeer whether this is a reconnecting old peer to be throttled
   * @param connectionType reason/category for the connection attempt
   * @param distance link-length class for the peer or offer decision
   * @return {@code true} if we can accept or should offer; {@code false} otherwise
   */
  public boolean wantPeer(
      OpennetPeerNode nodeToAddNow,
      boolean addAtLRU,
      boolean justChecking,
      boolean oldOpennetPeer,
      ConnectionType connectionType,
      LinkLengthClass distance) {
    LRUQueue<OpennetPeerNode> peersLRU = lruQueue(distance);
    long now = System.currentTimeMillis();
    if (LOG.isDebugEnabled())
      LOG.debug(
          "wantPeer({},{},{},{},{},{})",
          nodeToAddNow != null,
          addAtLRU,
          justChecking,
          oldOpennetPeer,
          connectionType,
          distance);
    boolean outdated = nodeToAddNow != null && nodeToAddNow.isUnroutableOlderVersion();
    if (shouldReject(nodeToAddNow, connectionType, outdated)) return false;

    int maxPeers = getNumberOfConnectedPeersToAim(distance);
    if (LOG.isDebugEnabled()) LOG.debug("Target peers={}", maxPeers);

    WantPeerContext ctx =
        new WantPeerContext(
            peersLRU, distance, nodeToAddNow, connectionType, oldOpennetPeer, outdated, now);
    WantPeerSyncState state = decideInitialSync(ctx, maxPeers, addAtLRU, justChecking);
    if (state.earlyReturn) return state.earlyReturnValue;

    if (nodeToAddNow != null) {
      nodeToAddNow.setAddedReason(
          connectionType == null ? PeerNode.ADDED_REASON_UNKNOWN : connectionType.code());
    }
    if (state.notMany) return addPeerIfPresent(nodeToAddNow);

    DropResult result = computeDropAndMaybeAdd(ctx, addAtLRU, justChecking, state.noDisconnect);
    finalizeGlobalPeerAddAndDrops(nodeToAddNow, result);
    return result.canAdd;
  }

  private boolean shouldReject(
      OpennetPeerNode nodeToAddNow, ConnectionType connectionType, boolean outdated) {
    if (outdated && LOG.isDebugEnabled())
      LOG.debug(
          "Peer is outdated: {} for {}",
          nodeToAddNow == null ? null : nodeToAddNow.getBuildNumber(),
          connectionType);
    if (checkOutdatedRejection(outdated, connectionType, nodeToAddNow)) return true;
    return nodeToAddNow != null && violatesAddressPolicy(nodeToAddNow, connectionType);
  }

  private boolean addPeerIfPresent(OpennetPeerNode nodeToAddNow) {
    if (nodeToAddNow != null) {
      node.network().peers().addPeer(nodeToAddNow, true, true);
    }
    return true;
  }

  private void finalizeGlobalPeerAddAndDrops(OpennetPeerNode nodeToAddNow, DropResult result) {
    if (nodeToAddNow != null
        && result.canAdd
        && !node.network().peers().addPeer(nodeToAddNow, true, true)) {
      LOG.debug("Already present in global peers list: {}", nodeToAddNow);
    }
    for (OpennetPeerNode pn : result.dropList) {
      if (LOG.isDebugEnabled()) LOG.debug("Drop LRU peer during global sync: {}", pn);
      pn.setAddedReason(PeerNode.ADDED_REASON_UNKNOWN);
      node.network().peers().messenger().disconnectAndRemove(pn, true, true, true);
    }
  }

  private int maxOutdatedPeers() {
    return Math.max(5, getNumberOfConnectedPeersToAimIncludingDarknet() / 4);
  }

  private boolean tooManyOutdatedPeers() {
    // This does not check whether they are short or long as it is irrelevant for outdated peers.
    int maxTooOldPeers = maxOutdatedPeers();
    int count = 0;
    OpennetPeerNode[] peers = node.network().peers().roster().getOpennetPeers();
    for (OpennetPeerNode pn : peers) {
      if (pn.isUnroutableOlderVersion()) {
        count++;
        if (count >= maxTooOldPeers) return true;
      }
    }
    return false;
  }

  private synchronized boolean enforcePerTypeGracePeriodLimits(
      int maxPeers, ConnectionType type, boolean addingPeer, LRUQueue<OpennetPeerNode> peersLRU) {
    if (type == null && LOG.isDebugEnabled()) LOG.debug("No type set; skip per-type limits");

    // We do NOT want to have all our peers in grace periods!
    // For opennet to work, we need LRU. For LRU to work, it needs a choice.
    // If everything is in a grace period, then we have no choice - we replace the one node that
    // comes out of its grace period as soon as it does.
    // So first calculate an overall limit on the number of peers in grace periods.

    // Heuristic: Half rounded down.
    int maxGracePeriodPeers = maxPeers / 2;

    int announceMax;
    int reconnectMax;
    int pathFoldingMax;
    // Same total global number of slots as 1242/1243.
    announceMax = reconnectMax = (maxGracePeriodPeers / 5) + 1;
    pathFoldingMax = maxGracePeriodPeers - announceMax - reconnectMax;
    if (pathFoldingMax < 2) return false;
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Per-type grace period limits: total={} announce={} reconnect={} pathFolding={}",
          maxPeers,
          announceMax,
          reconnectMax,
          pathFoldingMax);
    int myLimit =
        (type == null)
            ? reconnectMax
            : switch (type) {
              case PATH_FOLDING -> pathFoldingMax;
              case ANNOUNCE -> announceMax;
              case RECONNECT -> reconnectMax;
            };

    if (exceedsTypeLimit(peersLRU, type, myLimit)) {
      return true;
    }
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Per-type grace period allows type={} count={} limit={} addingPeer={}",
          type,
          countActivePeersOfType(peersLRU, type),
          myLimit,
          addingPeer);
    return false;
  }

  private int countActivePeersOfType(LRUQueue<OpennetPeerNode> peersLRU, ConnectionType type) {
    int count = 0;
    int typeCode = type == null ? PeerNode.ADDED_REASON_UNKNOWN : type.code();
    OpennetPeerNode[] peers = peersLRU.toArray(new OpennetPeerNode[peersLRU.size()]);
    for (OpennetPeerNode pn : peers) {
      if (pn.getAddedReason() == typeCode && pn.isConnected() && !pn.isDroppable(false)) {
        count++;
      }
    }
    return count;
  }

  private boolean exceedsTypeLimit(
      LRUQueue<OpennetPeerNode> peersLRU, ConnectionType type, int myLimit) {
    int count = 0;
    int typeCode = type == null ? PeerNode.ADDED_REASON_UNKNOWN : type.code();
    OpennetPeerNode[] peers = peersLRU.toArray(new OpennetPeerNode[peersLRU.size()]);
    for (OpennetPeerNode pn : peers) {
      if (pn.getAddedReason() == typeCode && pn.isConnected() && !pn.isDroppable(false)) {
        count++;
        if (count >= myLimit) {
          if (LOG.isDebugEnabled())
            LOG.debug(
                "Per-type grace period rejects type={} count={} limit={}", type, count, myLimit);
          return true;
        }
      }
    }
    return false;
  }

  void dropAllExcessPeers() {
    for (LinkLengthClass l : LinkLengthClass.values()) dropExcessPeers(l);
  }

  void dropExcessPeers(LinkLengthClass distance) {
    LRUQueue<OpennetPeerNode> peersLRU = lruQueue(distance);
    int maxPeers = getNumberOfConnectedPeersToAim(distance);
    while (peersLRU.size() > maxPeers) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Drop opennet peers: current={} target={} class={}",
            peersLRU.size(),
            maxPeers,
            distance);
      OpennetPeerNode toDrop;
      toDrop = peerToDrop(false, false, false, null, maxPeers, distance, peersLRU);
      if (toDrop == null)
        toDrop = peerToDrop(false, true, false, null, maxPeers, distance, peersLRU);
      if (toDrop == null) return;
      synchronized (this) {
        peersLRU.remove(toDrop);
      }
      if (LOG.isDebugEnabled()) LOG.debug("Drop excess opennet peer: {}", toDrop);
      node.network().peers().messenger().disconnectAndRemove(toDrop, true, true, true);
    }
  }

  // A TOO OLD peer does not count towards the limit, even if it is not connected.
  // It can, however, be dumped if it doesn't connect in a reasonable time, and if
  // it upgrades, it may not have the usual grace period.

  /**
   * Return the count of opennet peers for the given distance class.
   *
   * <p>Connected peers that are marked as too old do not count toward the limit; they are allowed
   * to connect long enough to update and will be disconnected later.
   *
   * @param distance link-length class whose peers should be counted
   * @return number of counted peers for the specified class
   * @see OpennetPeerNode#shouldDisconnectAndRemoveNow()
   */
  public synchronized int getSize(LinkLengthClass distance) {
    int x = 0;
    for (Iterator<OpennetPeerNode> e = lruQueue(distance).elements(); e.hasNext(); ) {
      OpennetPeerNode pn = e.next();
      if (!pn.isUnroutableOlderVersion()) x++;
    }
    return x;
  }

  private OpennetPeerNode peerToDrop(
      boolean noDisconnect,
      boolean force,
      boolean addingNode,
      ConnectionType connectionType,
      int maxPeers,
      LinkLengthClass distance,
      LRUQueue<OpennetPeerNode> peersLRU) {
    if (getSize(distance) < maxPeers) {
      if (LOG.isDebugEnabled())
        LOG.debug("Skip drop (force={} addingNode={}); under limit", force, addingNode);
      return null;
    }
    synchronized (this) {
      EnumMap<NOT_DROP_REASON, Integer> map =
          addingNode ? new EnumMap<>(NOT_DROP_REASON.class) : null;
      OpennetPeerNode[] peers = peersLRU.toArrayOrdered(new OpennetPeerNode[peersLRU.size()]);

      OpennetPeerNode candidate = pickDroppableDisconnected(peers, force, map);
      if (candidate != null) return candidate;

      if (noDisconnect) {
        logNotDropReasons("Skip disconnect", map, addingNode);
        return null;
      }

      if (map != null) map.clear();
      OpennetPeerNode connectedCandidate =
          pickDroppableConnected(peers, force, connectionType, map);
      if (connectedCandidate != null) return connectedCandidate;

      logNotDropReasons("No drop candidate", map, addingNode);
    }
    return null;
  }

  private void logNotDropReasons(
      String header, EnumMap<NOT_DROP_REASON, Integer> map, boolean addingNode) {
    if (!(addingNode && LOG.isDebugEnabled())) return;
    LOG.debug(header);
    if (map == null) return;
    for (Map.Entry<NOT_DROP_REASON, Integer> entry : map.entrySet()) {
      LOG.debug("{} : {}", entry.getKey(), entry.getValue());
    }
  }

  private void increment(EnumMap<NOT_DROP_REASON, Integer> map, NOT_DROP_REASON reason) {
    if (map == null) return;
    map.compute(reason, (_, x) -> x == null ? 1 : x + 1);
  }

  private OpennetPeerNode pickDroppableDisconnected(
      OpennetPeerNode[] peers, boolean force, EnumMap<NOT_DROP_REASON, Integer> map) {
    for (OpennetPeerNode pn : peers) {
      if (pn == null) continue; // single continue in this loop
      if (isAllowedDropCandidateDisconnected(pn, force, map)) {
        boolean tooOld = pn.isUnroutableOlderVersion();
        NOT_DROP_REASON reason = pn.isDroppableWithReason(false);
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Select drop candidate {} (disconnected, reason={} force={} tooOld={})",
              pn,
              reason,
              force,
              tooOld);
        pn.setWasDropped();
        return pn;
      }
    }
    return null;
  }

  private boolean isAllowedDropCandidateDisconnected(
      OpennetPeerNode pn, boolean force, EnumMap<NOT_DROP_REASON, Integer> map) {
    boolean tooOld = pn.isUnroutableOlderVersion();
    if (pn.isConnected() && tooOld) return false; // Doesn't count towards the limit.
    NOT_DROP_REASON reason = pn.isDroppableWithReason(false);
    increment(map, reason);
    boolean allowed = (reason == NOT_DROP_REASON.DROPPABLE) || (force && !tooOld);
    return allowed && !pn.isConnected();
  }

  private OpennetPeerNode pickDroppableConnected(
      OpennetPeerNode[] peers,
      boolean force,
      ConnectionType connectionType,
      EnumMap<NOT_DROP_REASON, Integer> map) {
    for (OpennetPeerNode pn : peers) {
      if (pn == null) continue; // single continue in this loop
      if (isAllowedDropCandidate(pn, force, map)) {
        logDropCandidate(connectionType, pn);
        pn.setWasDropped();
        return pn;
      }
    }
    return null;
  }

  private boolean isAllowedDropCandidate(
      OpennetPeerNode pn, boolean force, EnumMap<NOT_DROP_REASON, Integer> map) {
    boolean tooOld = pn.isUnroutableOlderVersion();
    if (pn.isConnected() && tooOld) return false; // Doesn't count anyway.
    NOT_DROP_REASON reason = pn.isDroppableWithReason(false);
    increment(map, reason);
    return (reason == NOT_DROP_REASON.DROPPABLE) || (force && !tooOld);
  }

  private void logDropCandidate(ConnectionType connectionType, OpennetPeerNode pn) {
    if (!LOG.isDebugEnabled()) return;
    LOG.debug(
        "Select drop candidate {} {}",
        pn,
        (connectionType == null)
            ? ""
            : ((System.currentTimeMillis() - timeLastDropped.get(connectionType))
                + " ms since last dropped peer of type "
                + connectionType));
  }

  /**
   * Record a successful request via the given peer and update its LRU position.
   *
   * <p>This increments success counters for all connection types and promotes the peer to the LRU
   * head when present. If the peer is no longer tracked, it is treated as a reconnection candidate;
   * failure to re-add triggers a disconnect/remove to keep the table consistent. Calls from network
   * threads are expected; the method synchronizes with the manager for LRU updates.
   *
   * @param pn peer that successfully handled a request
   */
  public void onSuccess(OpennetPeerNode pn) {
    LinkLengthClass distance = pn.linkLengthClass();
    LRUQueue<OpennetPeerNode> peersLRU = lruQueue(distance);
    synchronized (this) {
      for (ConnectionType type : ConnectionType.values())
        successCount.put(type, successCount.get(type) + 1);
      if (peersLRU.contains(pn)) {
        peersLRU.push(pn);
        if (LOG.isDebugEnabled())
          LOG.debug("Promote opennet peer {} to LRU head after successful request", pn);
        return;
      } else {
        if (LOG.isDebugEnabled())
          LOG.debug("Success on opennet peer not in LRU: {}", pn, new Exception("debug"));
        // Re-add it: nasty race condition when we have few peers
      }
    }
    if (!wantPeer(
        pn,
        false,
        false,
        false,
        ConnectionType.RECONNECT,
        distance)) { // Start at the top as it just succeeded
      node.network().peers().messenger().disconnectAndRemove(pn, true, false, true);
    }
  }

  /**
   * Notification that a peer was removed.
   *
   * <p>This removes the peer from the LRU and, when eligible, tracks it as an old opennet peer so
   * that future reconnection attempts can be accepted under scarcity conditions. Peers that never
   * connected are not added to the old-peer list. The old-peer list is bounded by {@link
   * #MAX_OLD_PEERS} to avoid unbounded growth.
   *
   * @param pn peer that was removed from the opennet set
   */
  public void onRemove(OpennetPeerNode pn) {
    long now = System.currentTimeMillis();
    LRUQueue<OpennetPeerNode> peersLRU = lruQueue(pn);
    synchronized (this) {
      peersLRU.remove(pn);
      if (pn.isDroppable(true) && !pn.grabWasDropped()) {
        if (LOG.isDebugEnabled()) LOG.debug("onRemove for {}", pn);
        if (pn.timeLastConnected(now) > 0) {
          // Don't even add it if it never connected.
          oldPeers.push(pn);
          while (oldPeers.size() > MAX_OLD_PEERS) oldPeers.pop();
        }
      }
    }
  }

  synchronized OpennetPeerNode[] getOldPeers() {
    return oldPeers.toArrayOrdered(new OpennetPeerNode[oldPeers.size()]);
  }

  @SuppressWarnings("unused")
  synchronized OpennetPeerNode[] getUnsortedOldPeers() {
    return oldPeers.toArray(new OpennetPeerNode[oldPeers.size()]);
  }

  /**
   * Add an old opennet node - a node which might try to reconnect, and which we should accept if we
   * are desperate.
   *
   * @param pn The node to add to the old opennet nodes LRU.
   */
  synchronized void addOldOpennetNode(OpennetPeerNode pn) {
    oldPeers.push(pn);
  }

  final String getOldPeersFilename() {
    return node.nodeDir().file("openpeers-old-" + crypto.getPortNumber()).toString();
  }

  synchronized int countOldOpennetPeers() {
    return oldPeers.size();
  }

  /**
   * Remove a peer from the old-opennet tracking LRU.
   *
   * <p>This is used to forget a peer that should no longer be considered for opportunistic
   * reconnection, for example, after a definitive failure or manual removal. The removal is
   * idempotent and safe to call even if the peer is not present.
   *
   * @param source old peer entry to remove from tracking
   */
  public synchronized void purgeOldOpennetPeer(OpennetPeerNode source) {
    oldPeers.remove(source);
  }

  /**
   * Compute the target total number of peers, including darknet peers.
   *
   * <p>This uses bandwidth-based scaling when enabled and then caps the result by network
   * heuristics and user-specified limits. The returned value represents the overall target before
   * subtracting connected darknet peers. It is a planning value only and does not force immediate
   * connection or disconnection actions by itself. The computation reads current network settings
   * without additional synchronization.
   *
   * @return target peer count, including darknet peers, subject to limits
   */
  public int getNumberOfConnectedPeersToAimIncludingDarknet() {
    int max = node.network().maxOpennetPeers();
    if (ENABLE_PEERS_PER_KB_OUTPUT) {
      int obwLimit = node.network().outputBandwidthLimit();
      int targetPeers = (int) Math.round(Math.sqrt(obwLimit * SCALING_CONSTANT / 1000.0));
      if (targetPeers < MIN_PEERS_FOR_SCALING) targetPeers = MIN_PEERS_FOR_SCALING;
      targetPeers = addMorePeersIfSlowPeersCannotSupplyEnoughBandwidthPerConnection(targetPeers);
      // limit to max peers
      targetPeers = Math.min(MAX_PEERS_FOR_SCALING, targetPeers);
      if (max > targetPeers) {
        max = targetPeers; // Allow user to reduce it.
      }
    }
    return max;
  }

  /**
   * A fast peer requires inbound bandwidth per connection proportional to the number of target
   * peers. But a peer with fewer than sqrt(targetPeers) connections does not have enough bandwidth
   * to support a connection to such a fast peer.
   *
   * <p>Therefore, a fast peer needs more peers than given by the square-root scaling.
   *
   * <p>To calculate the missing bandwidth, we have to make an assumption: How many peers are too
   * slow? We assume that 50% of the peers have the lowest possible peer count.
   *
   * <p>We need targetPeers packets per peer. We assume that half the peers have the minimum peer
   * count. To stay in the 50% slow nodes model, we assume that half the peers of the slow peer are
   * slow, the other half are as fast as we are. We receive targetPeers / (minPeers + targetPeers)
   * of the packages the slow peer receives.
   *
   * <p>For each additional peer, we receive one additional packet from fast peers and
   * receivedFraction * MIN_PEERS_FOR_SCALING * MIN_PEERS_FOR_SCALING from slow peers.
   *
   * @param targetPeers the target peers from square root scaling
   * @return increased estimate to provide enough bandwidth for the fast peer.
   */
  private int addMorePeersIfSlowPeersCannotSupplyEnoughBandwidthPerConnection(int targetPeers) {
    double receivedFraction = ((double) targetPeers) / (MIN_PEERS_FOR_SCALING + targetPeers);
    double packetsFromSlowPeer = receivedFraction * MIN_PEERS_FOR_SCALING * MIN_PEERS_FOR_SCALING;
    if (targetPeers <= packetsFromSlowPeer) {
      return targetPeers;
    }
    double missingPacketsPerSlowPeer = targetPeers - packetsFromSlowPeer;
    double missingPackets =
        ASSUMPTION_50_PERCENT_SLOW_PEERS * targetPeers * missingPacketsPerSlowPeer;
    double additionalPacketsPerAddedPeer =
        ASSUMPTION_50_PERCENT_SLOW_PEERS * targetPeers + packetsFromSlowPeer;
    // always compensate for the missing packets. The worst nodes to be underused are the fast ones.
    return targetPeers + 1 + (int) (missingPackets / additionalPacketsPerAddedPeer);
  }

  /**
   * Return the target number of opennet peers for a specific distance class.
   *
   * <p>This delegates to {@link #getNumberOfConnectedPeersToAim()} and then applies the per-class
   * allocation logic. Do not call while holding locks that might be acquired during peer
   * accounting. The result is a target used by LRU trimming and admission decisions, not an
   * immediate enforcement guarantee.
   *
   * @param distance link-length class whose target should be computed
   * @return target number of opennet peers for the given class
   */
  public int getNumberOfConnectedPeersToAim(LinkLengthClass distance) {
    if (distance == null) throw new IllegalArgumentException();
    int target = getNumberOfConnectedPeersToAim();
    return distance.getTargetPeers(target);
  }

  /**
   * Compute the target number of opennet peers.
   *
   * <p>This subtracts the number of connected darknet peers from the overall target to determine
   * how many opennet peers to aim for. The result can be negative if the darknet peer count exceeds
   * the total target, in which case callers should treat it as zero. No side effects occur; it is a
   * pure calculation based on current counters and limits.
   *
   * @return target opennet peer count after darknet subtraction
   */
  public int getNumberOfConnectedPeersToAim() {
    int max = getNumberOfConnectedPeersToAimIncludingDarknet();
    return max - node.network().peers().countConnectedDarknetPeers();
  }

  /**
   * Callback invoked when all packets of an opennet noderef transfer have been queued and observed
   * as sent.
   *
   * <p>This is intentionally narrower than {@link
   * network.crypta.io.xfer.BulkTransmitter.AllSentCallback} so callers do not need to depend on
   * bulk transfer internals.
   */
  @FunctionalInterface
  public interface NoderefAllSentCallback {
    /**
     * Called asynchronously once all packets have been queued and their sending callbacks have
     * fired.
     *
     * <p>The callback is best-effort and does not imply delivery by the remote peer; it only
     * reflects local queuing and send completion. Implementations should be fast and avoid blocking
     * since they may run on network executor threads.
     *
     * @param anyFailed {@code true} if any packet failed to send; {@code false} otherwise
     */
    void allSent(boolean anyFailed);
  }

  /**
   * Send our opennet noderef to a node without an explicit send-completion callback.
   *
   * <p>The noderef is padded to a fixed size for privacy before the bulk transfer begins. A
   * lightweight control message is sent first, followed by the bulk transfer. The return value
   * indicates whether the bulk transfer was initiated, not whether the remote side accepted it.
   * Oversized noderefs are logged and rejected before any transfer is queued.
   *
   * @param isReply whether to send a reply ({@code true}) or destination message
   * @param uid unique ID of the request chain involved
   * @param peer destination peer; may be darknet or opennet
   * @param noderef full compressed noderef payload to send
   * @param ctr byte counter used for bandwidth accounting
   * @return {@code true} if the bulk transfer was started successfully
   * @throws NotConnectedException if the peer disconnects during sending setup
   */
  @SuppressWarnings("UnusedReturnValue")
  public boolean sendOpennetRef(
      boolean isReply, long uid, PeerNode peer, byte[] noderef, ByteCounter ctr)
      throws NotConnectedException {
    return sendOpennetRef(isReply, uid, peer, noderef, ctr, null);
  }

  /**
   * Send our opennet noderef to a node, with an optional completion callback.
   *
   * <p>The noderef is padded to a fixed size for privacy before transfer. A control message is
   * queued first, then the bulk transfer is sent. When provided, {@code cb} is invoked once all
   * packets are queued and their sending callbacks have fired; it does not indicate remote receipt.
   * Oversized noderefs are logged and rejected before any bulk transfer is queued.
   *
   * @param isReply whether to send a reply ({@code true}) or destination message
   * @param uid unique ID of the request chain involved
   * @param peer destination peer; may be darknet or opennet
   * @param noderef full compressed noderef payload to send
   * @param ctr byte counter used for bandwidth accounting
   * @param cb optional callback invoked when all packets are queued and sent
   * @return {@code true} if the bulk transfer was started successfully
   * @throws NotConnectedException if the peer disconnects during sending setup
   */
  @SuppressWarnings("UnusedReturnValue")
  public boolean sendOpennetRef(
      boolean isReply,
      long uid,
      PeerNode peer,
      byte[] noderef,
      ByteCounter ctr,
      NoderefAllSentCallback cb)
      throws NotConnectedException {
    byte[] padded = new byte[paddedSize(noderef.length)];
    if (noderef.length > padded.length) {
      LOG.error("Opennet ref send rejected; noderef too big: {} bytes", noderef.length);
      return false;
    }
    System.arraycopy(noderef, 0, padded, 0, noderef.length);
    Util.randomBytes(
        node.bootstrap().fastWeakRandom(), padded, noderef.length, padded.length - noderef.length);
    long xferUID = node.bootstrap().random().nextLong();
    Message msg2 =
        isReply
            ? DMT.createFNPOpennetConnectReplyNew(uid, xferUID, noderef.length, padded.length)
            : DMT.createFNPOpennetConnectDestinationNew(
                uid, xferUID, noderef.length, padded.length);
    peer.transport().sendAsync(msg2, null, ctr);
    return innerSendOpennetRef(xferUID, padded, peer, ctr, cb);
  }

  /**
   * Just the actual transfer.
   *
   * @param xferUID The transfer UID
   * @param padded The length of the data to transfer.
   * @param peer The peer to send it to.
   * @param cb Optional callback invoked when all packets have been queued and observed as sent.
   * @throws NotConnectedException If the peer is not connected, or we lose the connection to the
   *     peer, or it restarts.
   */
  private boolean innerSendOpennetRef(
      long xferUID, byte[] padded, PeerNode peer, ByteCounter ctr, NoderefAllSentCallback cb)
      throws NotConnectedException {
    ByteArrayRandomAccessBuffer raf = new ByteArrayRandomAccessBuffer(padded);
    raf.setReadOnly();
    PartiallyReceivedBulk prb =
        new PartiallyReceivedBulk(node.network().usm(), padded.length, Node.PACKET_SIZE, raf, true);
    try {
      BulkTransmitter.AllSentCallback bulkCb = null;
      if (cb != null) {
        bulkCb = (_, anyFailed) -> cb.allSent(anyFailed);
      }
      BulkTransmitter bt = new BulkTransmitter(prb, peer, xferUID, true, ctr, true, bulkCb);
      return bt.send();
    } catch (DisconnectedException e) {
      throw new NotConnectedException(e);
    }
  }

  /**
   * Start an announcement noderef transfer.
   *
   * <p>This sends the announcement request control message and returns the bulk transfer UID that
   * must be used when sending the padded payload. The actual payload transfer is completed by
   * {@link #finishSentAnnouncementRequest(PeerNode, byte[], ByteCounter, long)}. The returned UID
   * is unique for this transfer and should not be reused for another sending.
   *
   * @param uid request chain UID for correlating the announcement
   * @param peer destination peer for the announcement request
   * @param noderef compressed noderef payload to announce
   * @param ctr byte counter used for bandwidth accounting
   * @param target target location in {@code [0,1)}
   * @param htl HTL value carried by the announcement request
   * @return transfer UID used for the later bulk send
   * @throws NotConnectedException if the peer is not connected
   */
  public long startSendAnnouncementRequest(
      long uid, PeerNode peer, byte[] noderef, ByteCounter ctr, double target, short htl)
      throws NotConnectedException {
    long xferUID = node.bootstrap().random().nextLong();
    OpennetAnnounceRequest request =
        new OpennetAnnounceRequest(
            uid, xferUID, noderef.length, paddedSize(noderef.length), target, htl);
    Message msg = DMT.createFNPOpennetAnnounceRequest(request);
    peer.transport().sendAsync(msg, null, ctr);
    return xferUID;
  }

  /**
   * Complete an announcement noderef transfer after the request message was sent.
   *
   * <p>The payload is padded to a fixed size and sent as a bulk transfer using the provided {@code
   * xferUID}. This method should only be called after {@link #startSendAnnouncementRequest(long,
   * PeerNode, byte[], ByteCounter, double, short)} has successfully queued the request message. It
   * does not return a status; errors are surfaced via {@link NotConnectedException}.
   *
   * @param peer destination peer for the bulk transfer
   * @param noderef compressed noderef payload to send
   * @param ctr byte counter used for bandwidth accounting
   * @param xferUID transfer UID returned by {@link #startSendAnnouncementRequest}
   * @throws NotConnectedException if the peer is not connected
   */
  public void finishSentAnnouncementRequest(
      PeerNode peer, byte[] noderef, ByteCounter ctr, long xferUID) throws NotConnectedException {
    byte[] padded = new byte[paddedSize(noderef.length)];
    System.arraycopy(noderef, 0, padded, 0, noderef.length);
    Util.randomBytes(
        node.bootstrap().fastWeakRandom(), padded, noderef.length, padded.length - noderef.length);
    innerSendOpennetRef(xferUID, padded, peer, ctr, null);
  }

  private int paddedSize(int length) {
    if (length < PADDED_NODEREF_SIZE) return PADDED_NODEREF_SIZE;
    LOG.info("Large noderef: {} bytes", length);
    if (length > MAX_OPENNET_NODEREF_LENGTH)
      throw new IllegalArgumentException(
          "Too big noderef: " + length + " limit is " + MAX_OPENNET_NODEREF_LENGTH);
    return ((length >>> 10) + ((length & 1023) == 0 ? 0 : 1)) << 10;
  }

  /**
   * Send an announcement reply containing our noderef.
   *
   * <p>The reply uses a fixed padded size and sends a control message followed by a bulk transfer.
   * Oversized noderefs are rejected and logged. The method returns only after the bulk transfer has
   * been queued, not after remote receipt. Use this for reply-only flows, not for offers.
   *
   * @param uid request chain UID associated with the announcement
   * @param peer destination peer that requested the announcement
   * @param noderef compressed noderef payload to include in the reply
   * @param ctr byte counter used for bandwidth accounting
   * @throws NotConnectedException if the peer is not connected
   */
  public void sendAnnouncementReply(long uid, PeerNode peer, byte[] noderef, ByteCounter ctr)
      throws NotConnectedException {
    byte[] padded = new byte[PADDED_NODEREF_SIZE];
    if (noderef.length > padded.length) {
      LOG.error("Announcement reply noderef too big: {} bytes", noderef.length);
      return;
    }
    System.arraycopy(noderef, 0, padded, 0, noderef.length);
    long xferUID = node.bootstrap().random().nextLong();
    Message msg = DMT.createFNPOpennetAnnounceReply(uid, xferUID, noderef.length, padded.length);
    peer.transport().sendAsync(msg, null, ctr);
    innerSendOpennetRef(xferUID, padded, peer, ctr, null);
  }

  /**
   * Send a noderef rejection to the given peer.
   *
   * <p>This emits a small control message and ignores disconnect errors because the rejection is a
   * best-effort notification. Callers do not need to coordinate with the transfer state, and
   * failures do not affect local peer accounting.
   *
   * @param uid parent request UID for correlation
   * @param source peer to notify about the rejection
   * @param reason DMT reason code to include in the message
   * @param ctr byte counter used for bandwidth accounting
   */
  public static void rejectRef(long uid, PeerNode source, int reason, ByteCounter ctr) {
    Message msg = DMT.createFNPOpennetNoderefRejected(uid, reason);
    try {
      source.transport().sendAsync(msg, null, ctr);
    } catch (NotConnectedException _) {
      // Ignore
    }
  }

  /**
   * Start an opennet announcement to a target location.
   *
   * <p>This schedules an {@link AnnounceSender} on the network executor and returns immediately.
   * The announcement proceeds asynchronously and reports status through the provided callback.
   * Callers should assume the callback may be invoked from executor threads and may be invoked
   * multiple times as the announcement progresses.
   *
   * @param target target location in {@code [0,1)}
   * @param cb callback for announcement status updates
   */
  public void announce(double target, AnnouncementCallback cb) {
    AnnounceSender sender = new AnnounceSender(target, this, node, cb, null);
    node.network().executor().execute(sender, "Announcement to " + target);
  }

  /**
   * Return the creation time of this manager instance.
   *
   * <p>The value is captured at construction and is useful for relative age calculations. It does
   * not change even if the manager is restarted, making it a stable anchor for uptime metrics. The
   * timestamp is in the same epoch units used elsewhere in the node.
   *
   * @return epoch time in milliseconds when the manager was created
   */
  public long getCreationTime() {
    return creationTime;
  }

  private static final long MAX_AGE = DAYS.toMillis(7);
  private static final TimeSortedHashtable<String> knownIds = new TimeSortedHashtable<>();

  static void registerKnownIdentity(String d) {
    if (LOG.isDebugEnabled()) LOG.debug("Known identity: {}", d);
    long now = System.currentTimeMillis();

    synchronized (knownIds) {
      if (LOG.isDebugEnabled())
        LOG.debug("knownIds add start; identity={} size={}", d, knownIds.size());
      knownIds.push(d, now);
      if (LOG.isDebugEnabled())
        LOG.debug("knownIds add done; identity={} size={}", d, knownIds.size());
      knownIds.removeBefore(now - MAX_AGE);
      if (LOG.isDebugEnabled())
        LOG.debug("knownIds add+prune; identity={} size={}", d, knownIds.size());
    }
    if (LOG.isDebugEnabled()) LOG.debug("Estimated opennet size (session)={}", knownIds.size());
  }

  // Return the estimated network size based on locations seen after timestamp or for the whole
  // session if -1
  /**
   * Return the estimated opennet size based on distinct identities observed.
   *
   * <p>The estimate is derived from an in-memory, time-bounded set of identities. Passing {@code
   * -1} returns a session-wide estimate; otherwise, only identities seen after the given epoch are
   * counted. The value is approximate and intended for heuristics, not precise census.
   *
   * @param timestamp count only identities seen after this epoch in milliseconds, or {@code -1} for
   *     session scope
   * @return estimated distinct opennet size for the chosen window
   */
  public int getNetworkSizeEstimate(long timestamp) {
    return knownIds.countValuesAfter(timestamp);
  }

  /**
   * Threshold for triggering an announcement, as determined by the {@link Announcer}.
   *
   * <p>This value reflects the current announcer policy and may change as network conditions or
   * configuration change. It is read directly from the announcer without additional caching and
   * should be treated as an instantaneous snapshot. Use it for diagnostics rather than control
   * flow.
   *
   * @return current announcement threshold value
   */
  public int getAnnouncementThreshold() {
    return announcer.getAnnouncementThreshold();
  }

  /**
   * Notification that a peer was disconnected.
   *
   * <p>This asks the announcer to re-evaluate whether an announcement should run. The call is
   * non-blocking and only schedules work if needed. It is typically invoked after a disconnect so
   * the announcer can respond to changed connectivity. No guarantees are made about immediate
   * announcement dispatch.
   */
  public void onDisconnect() {
    if (announcer != null) announcer.maybeSendAnnouncementOffThread();
  }

  /**
   * Return the count of connection attempts for the given {@link ConnectionType}.
   *
   * <p>This counter is incremented whenever a peer is considered for addition and provides a simple
   * visibility metric for admission pressure by connection type. Reads are synchronized to avoid
   * races with concurrent bookkeeping updates in the networking threads. The counter is monotonic
   * for the lifetime of the manager.
   *
   * @param type connection type whose attempt count should be read
   * @return number of attempts recorded for the specified type
   */
  public synchronized long getConnectionAttempts(ConnectionType type) {
    return connectionAttempts.get(type);
  }

  /**
   * Return the count of accepted connection attempts for the given {@link ConnectionType}.
   *
   * <p>This counter increments when a peer is accepted and added, and it can be compared against
   * {@link #getConnectionAttempts(ConnectionType)} to gauge acceptance rate. Reads are synchronized
   * to keep the snapshot consistent. It only changes when a peer is accepted, so it is a strict
   * subset of attempts.
   *
   * @param type connection type whose accepted count should be read
   * @return number of accepted attempts for the specified type
   */
  public synchronized long getConnectionAttemptsAdded(ConnectionType type) {
    return connectionAttemptsAdded.get(type);
  }

  /**
   * Return the count of accepted connection attempts where free slots were available.
   *
   * <p>This counter reflects cases where the LRU had capacity and no drops were required. It helps
   * distinguish between routine acceptance and cases that required replacement or rejection.
   * Compare with {@link #getConnectionAttemptsAdded(ConnectionType)} for drop frequency. A low
   * ratio indicates frequent replacements.
   *
   * @param type connection type whose free-slot accepts should be read
   * @return number of accepted attempts with free slots available
   */
  public synchronized long getConnectionAttemptsAddedPlentySpace(ConnectionType type) {
    return connectionAttemptsAddedPlentySpace.get(type);
  }

  /**
   * Return the count of connection attempts rejected by per-type grace period enforcement.
   *
   * <p>This counter increments when a candidate is rejected because its connection type has reached
   * its grace-period quota. It provides visibility into admission throttling. Large values indicate
   * sustained pressure for that connection type and may imply biased workloads.
   *
   * @param type connection type whose grace-period rejects should be read
   * @return number of rejected attempts due to per-type enforcement
   */
  public synchronized long getConnectionAttemptsRejectedByPerTypeEnforcement(ConnectionType type) {
    return connectionAttemptsRejectedByPerTypeEnforcement.get(type);
  }

  /**
   * Return the count of connection attempts rejected because no peers were droppable.
   *
   * <p>This counter records cases where the LRU is full and no eligible peers could be dropped to
   * make room. It can signal overly conservative drop policies or high peer churn. Sustained
   * increases may warrant tuning drop thresholds or investigating stuck peers.
   *
   * @param type connection type whose no-drop rejects should be read
   * @return number of rejected attempts due to lack of droppable peers
   */
  public synchronized long getConnectionAttemptsRejectedNoPeersDroppable(ConnectionType type) {
    return connectionAttemptsRejectedNoPeersDroppable.get(type);
  }

  /**
   * Whether the announcer is waiting for an updater condition before proceeding.
   *
   * <p>The announcer can pause when updates are pending or other preconditions are unmet. This
   * method exposes that state so callers can decide whether to trigger or defer related actions. It
   * reads the current state without side effects. Use it for diagnostics and UI hints.
   *
   * @return {@code true} if waiting; otherwise {@code false}
   */
  @SuppressWarnings("unused")
  public boolean waitingForUpdater() {
    return announcer.isWaitingForUpdater();
  }

  /**
   * Request the announcer to run again.
   *
   * <p>This is a lightweight signal that re-evaluates announcement conditions; it does not force a
   * sending if thresholds are not met. The call is safe to invoke from UI or admin paths and may
   * result in no action if the announcer is still waiting.
   */
  @SuppressWarnings("unused")
  public void reannounce() {
    announcer.reannounce();
  }

  /**
   * Called when a connection completes to re-evaluate opennet capacity.
   *
   * <p>If the peer is an opennet peer, the manager may need to drop another peer to keep within the
   * per-class target. If the peer is darknet, the opennet target may shrink, requiring excess
   * opennet peers to be dropped to maintain the overall limit. This method performs only drop
   * evaluation and does not add new peers. It is safe to call from connection completion handlers.
   *
   * @param pn the peer that just completed its connection handshake
   */
  public void onConnectedPeer(PeerNode pn) {
    if (pn instanceof OpennetPeerNode peerNode) {
      dropExcessPeers(peerNode.linkLengthClass());
    } else {
      // The peer count target may have decreased, so we may need to drop an opennet peer.
      dropAllExcessPeers();
    }
  }

  /**
   * Return the owning {@link Node} instance.
   *
   * <p>This reference is stable for the lifetime of the manager and provides access to network,
   * configuration, and execution services. Callers should treat the returned node as a shared state
   * and avoid mutating it without appropriate synchronization. It is provided for integration and
   * monitoring rather than for ownership transfer.
   *
   * @return owning node instance
   */
  public Node getNode() {
    return node;
  }

  /**
   * Return the opennet {@link NodeCrypto} component.
   *
   * <p>The crypto instance manages opennet keys, sockets, and protocol state and is shared with
   * other opennet operations. It is long-lived and should not be replaced by callers. Treat the
   * returned instance as a shared subsystem and avoid mutating configuration at runtime.
   *
   * @return opennet crypto component
   */
  public NodeCrypto getCrypto() {
    return crypto;
  }

  /**
   * Return the announcer component, or {@code null} when disabled.
   *
   * <p>The announcer orchestrates opennet announcements and may be inactive if announcements are
   * configured off. Callers should guard against {@code null} before invoking it. The announcer's
   * lifecycle is tied to this manager, and it shares its threading model. Treat it as nullable at
   * all times.
   *
   * @return announcer component, or {@code null} when disabled
   */
  public Announcer getAnnouncer() {
    return announcer;
  }

  /**
   * Return the seed announcement tracker.
   *
   * <p>This tracker maintains the state about recent seed announcements to avoid redundant
   * activity. It is safe to cache the reference, but its internal state changes over time. The
   * tracker is shared across announcement flows and is updated by announcer activity. It is
   * non-null for the life of the manager.
   *
   * @return seed announcement tracker instance
   */
  public SeedAnnounceTracker getSeedTracker() {
    return seedTracker;
  }
}

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
import java.util.Enumeration;
import java.util.Map;
import network.crypta.crypt.Util;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.DisconnectedException;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.NotConnectedException;
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
 * Manages opennet state for the node.
 *
 * <p>This class coordinates opennet cryptographic state, peer selection, and LRU-based peer
 * management. It is the central integration point for: - Opennet cryptographic initialization,
 * persistence, and export - Maintaining separate LRUs for short and long links and applying
 * drop/add heuristics - Announcements and noderef send/receive flows
 *
 * <p>Concurrency: most mutations to LRUs and counters are synchronized on {@code this}. External
 * components call into this class from networking threads and scheduled tasks.
 *
 * <p>Persistence: opennet crypto state is stored in per-port files with an optional backup.
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
        if (neverConnected1 && (!neverConnected2)) {
          return -1;
        }
        if ((!neverConnected1) && neverConnected2) {
          return 1;
        }
        // a-b not opposite sign to b-a possible in a corner case (a=0 b=Integer.MIN_VALUE).
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

  /** The proportion of the routing table which consists of "short links". */
  public static final double SHORT_PROPORTION = 1.0 - LONG_PROPORTION;

  /**
   * Assumed proportion of slow peers for scaling up the peer count to take limited capacity of slow
   * peers into account.
   */
  public static final double ASSUMPTION_50_PERCENT_SLOW_PEERS = 0.5;

  public enum LinkLengthClass {
    /** Shorter than LONG_DISTANCE */
    SHORT {
      @Override
      public int getTargetPeers(int target) {
        int longPeers = (int) (target * LONG_PROPORTION);
        return target - longPeers;
      }
    },
    /** Longer than LONG_DISTANCE */
    LONG {
      @Override
      public int getTargetPeers(int target) {
        return (int) (target * LONG_PROPORTION);
      }
    };

    /** Get the target number of peers for this class, given the overall target number of peers */
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
   * Only drop a connection after at least this many successful requests. This is per connection
   * type.
   */
  // Consider whether this should be a function of the number of opennet peers or the maximum
  // number of opennet peers.
  public static final int MIN_SUCCESS_BETWEEN_DROP_CONNS = 10;

  /** Chance of resetting path folding (for plausible deniability) is 1 in this number. */
  public static final int RESET_PATH_FOLDING_PROB = 20;

  /** Don't drop a node until it's at least this old, if it's connected. */
  public static final long DROP_MIN_AGE = MINUTES.toMillis(5);

  /**
   * Don't drop a node until it's at least this old, if it's not connected (if it has connected once
   * then DROP_DISCONNECT_DELAY applies, but only once an hour as below). Must be less than
   * DROP_MIN_AGE. Relatively generous because noderef transfers e.g. for announcement can be slow
   * (Note that announcements actually wait for previous transfers!).
   */
  public static final long DROP_MIN_AGE_DISCONNECTED = MINUTES.toMillis(5);

  /** Don't drop a node until this long after startup */
  public static final long DROP_STARTUP_DELAY = MINUTES.toMillis(2);

  /**
   * Don't drop a node until this long after losing connection to it. This should be long enough to
   * cover a typical reboot, but not so long as to result in a lot of disconnected nodes in the
   * Strangers list. Also, it should probably not be longer than DROP_MIN_AGE!
   */
  public static final long DROP_DISCONNECT_DELAY = MINUTES.toMillis(5);

  /** But if it has disconnected more than once in this period, allow it to be dropped anyway */
  public static final long DROP_DISCONNECT_DELAY_COOLDOWN = MINUTES.toMillis(60);

  /**
   * Every DROP_CONNECTED_TIME, we may drop a peer even though it is connected. This is per
   * connection type, we should consider whether to reduce it further.
   */
  public static final long DROP_CONNECTED_TIME = MINUTES.toMillis(5);

  /**
   * Minimum time between offers, if we have maximum peers. Less than the above limits, since an
   * offer may not be accepted.
   */
  public static final long MIN_TIME_BETWEEN_OFFERS = SECONDS.toMillis(30);

  /** How big to pad opennet noderefs to? If they are bigger than this then we won't send them. */
  public static final int PADDED_NODEREF_SIZE = 3072;

  /**
   * Allow for future expansion. However, at any given time all noderefs should be
   * PADDED_NODEREF_SIZE
   */
  public static final int MAX_OPENNET_NODEREF_LENGTH = 32768;

  /** Enable scaling of peers with bandwidth? */
  public static final boolean ENABLE_PEERS_PER_KB_OUTPUT = true;

  /**
   * Constant for scaling peers: we multiply bandwidth in kB/sec by this and then take the square
   * root. Minimum is MIN_PEERs_FOR_SCALING.
   *
   * <p>(define (peers kBps) (sqrt (* kBps scaling)))
   *
   * <p>Scaling at 3 gives 4 peers at 5K (min peers), 5 at 7K, 5 at 10K, 8 at 20K, 9 at 30K, 13 at
   * 60K, 17 at 100K, 20 at 140K, 87 at 2500K. 106 at 30mbit/s (the mean upload in Japan in 2014)
   * and 180 at 88mbit/s (the mean upload in Hong Kong in 2014).
   */
  public static final double SCALING_CONSTANT = 3;

  /**
   * Minimum number of peers. As a rough estimate, because the vast majority of requests complete in
   * 5 hops, 10 peers give just one binary decision per hop. However, the distribution of peers
   * before the link length fix showed that having 3 short distance peers still worked, since
   * requests preferentially go through higher capacity nodes with more FOAFs.
   */
  public static final int MIN_PEERS_FOR_SCALING = 4;

  /** The maximum possible distance between two nodes in the wrapping [0,1) location space. */
  public static final double MAX_DISTANCE = 0.5;

  /** The fraction of nodes which are only a short distance away. */
  public static final double SHORT_NODES_FRACTION = LONG_DISTANCE / MAX_DISTANCE;

  /** The estimated average number of nodes which are active at any given time. */
  public static final int LAST_NETWORK_SIZE_ESTIMATE = 3000;

  /** The estimated number of nodes which are a short distance away. */
  public static final int AVAILABLE_SHORT_DISTANCE_NODES =
      (int) (LAST_NETWORK_SIZE_ESTIMATE * SHORT_NODES_FRACTION);

  /**
   * Maximum number of peers.
   *
   * <p>This is limited by the expected availability of nodes with short links to a given location.
   * Above that number of peers, fast nodes will not be able to find enough peers with short links.
   *
   * @see OpennetManager.LinkLengthClass
   */
  public static final int MAX_PEERS_FOR_SCALING =
      (int) (AVAILABLE_SHORT_DISTANCE_NODES / SHORT_PROPORTION);

  /** Maximum number of peers for purposes of FOAF attack/sanity check */
  public static final int PANIC_MAX_PEERS = MAX_PEERS_FOR_SCALING + 10;

  /** Stop trying to reconnect to an old-opennet-peer after a month. */
  public static final long MAX_TIME_ON_OLD_OPENNET_PEERS = DAYS.toMillis(31);

  // This is only relevant while the connection is in the grace period.
  // Null means none of the above e.g. not in grace period.
  public enum ConnectionType {
    PATH_FOLDING,
    ANNOUNCE,
    RECONNECT
  }

  private final long creationTime;

  private boolean stopping;

  /**
   * Create an {@code OpennetManager} and initialize opennet crypto from disk if available.
   *
   * <p>Crypto state is loaded from files named {@code opennet-<port>} (and {@code .bak}) under the
   * node directory. If neither file can be read, new crypto state is generated.
   *
   * @param node The owning {@link Node} instance. Must not be {@code null}.
   * @param opennetConfig The opennet crypto configuration.
   * @param startupTime Node startup epoch (ms) used for crypto initialization.
   * @param enableAnnouncement Whether to enable the opennet announcer component.
   * @throws NodeInitException If crypto initialization fails.
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
   * <p>Writes to {@code opennet-<port>} with a temporary backup file. IO errors are swallowed to
   * preserve runtime behavior.
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
      bw.flush(); // Ensure data is written before moving file
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
   * <p>Loads known opennet peers, initializes LRUs, drops excess peers, loads old peers, starts
   * crypto, and starts the announcer if enabled.
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
   * Stop opennet subsystems.
   *
   * @param purge If {@code true}, remove opennet peers from the global peers list.
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
      // Drop any peers which don't have a location yet. That means we haven't connected to
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

  private record DropResult(boolean canAdd, ArrayList<OpennetPeerNode> dropList) {}

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
            "No droppable peers; current={} cannot accept peer{}",
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
      ArrayList<OpennetPeerNode> dropList,
      int currentSize) {
    if (currentSize == maxPeers && ctx.nodeToAddNow == null) {
      return handleFullSizeNoOffer(ctx, maxPeers, noDisconnect);
    }
    return dropWhileOverLimit(ctx, maxPeers, noDisconnect, dropList);
  }

  private void finalizeAddOrOffer(
      WantPeerContext ctx, boolean addAtLRU, ArrayList<OpennetPeerNode> dropList) {
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
        if (LOG.isDebugEnabled()) LOG.debug("Drop opennet peer: {}", dropList.getFirst());
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
      WantPeerContext ctx,
      int maxPeers,
      boolean noDisconnect,
      ArrayList<OpennetPeerNode> dropList) {
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
            "No droppable peers; current={} cannot accept peer{}",
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
   * <p>Parses the reference and compares against the current LRU for its link class.
   *
   * @param fs The field set containing the serialized noderef.
   * @return {@code true} when an equal opennet peer is already known; {@code false} otherwise.
   */
  @SuppressWarnings("java:S1181")
  public boolean alreadyHaveOpennetNode(SimpleFieldSet fs) {
    try {
      // Consider optimizing: parse only the pubkey and compare against existing peers.
      OpennetPeerNode pn =
          new OpennetPeerNode(fs, node, crypto, this, false, node.network().peers());
      if (lruQueue(pn).contains(pn)) {
        if (LOG.isDebugEnabled())
          LOG.debug("Skip add; {} already in opennet list", pn.userToString());
        return true;
      }
      // Don't check for self. That should be passed through too.
      return false;
    } catch (Throwable t) {
      // Don't break the code flow in the caller which is normally a request.
      LOG.error("Error parsing opennet node from fieldset: {}", t, t);
      return false;
    }
  }

  /**
   * Add a new opennet peer from a serialized noderef.
   *
   * <p>Validates the reference, filters out self, and applies per-type/drop heuristics. May return
   * an existing instance when {@code allowExisting} is {@code true}.
   *
   * @param fs The field set representation of the noderef.
   * @param connectionType The reason/category for the add (affects grace limits).
   * @param allowExisting If {@code true}, return the current instance when already present.
   * @return The new or existing {@link OpennetPeerNode}, or {@code null} when not accepted.
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
          LOG.debug("Skip add; {} already in opennet list", pn.userToString());
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
      // Start at bottom. Node must prove itself.
    } catch (Throwable t) {
      // Don't break the code flow in the caller which is normally a request.
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
   * to acquire a peer. When non-null, it decides whether to add the specific node and performs the
   * add when appropriate.
   *
   * @param nodeToAddNow The peer to add, or {@code null} to only decide on offering.
   * @param addAtLRU If {@code true}, place the peer at the LRU tail; otherwise at the head.
   * @param justChecking If {@code true}, compute availability without mutating state.
   * @param oldOpennetPeer Whether this is a reconnection of an old opennet peer.
   * @param connectionType The reason/category for the connection.
   * @return {@code true} if we have capacity or the peer was accepted; {@code false} otherwise.
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
   * <p>When {@code nodeToAddNow} is {@code null}, this method decides whether to send an offer.
   * Offers are rate-limited by {@link #MIN_TIME_BETWEEN_OFFERS}. When a node is provided, the
   * method applies grace-period and capacity heuristics and may add the node to the appropriate
   * LRU.
   *
   * @param nodeToAddNow The peer to add, or {@code null} to determine if we should offer.
   * @param addAtLRU Place the peer at the LRU tail (trial placement) when {@code true}; otherwise
   *     place at the head.
   * @param justChecking If {@code true}, only compute capacity/eligibility without mutating state.
   * @param oldOpennetPeer Whether this is a reconnecting old opennet peer (throttled acceptance).
   * @param connectionType The reason/category for the connection.
   * @param distance The link-length class for the peer or offer decision.
   * @return {@code true} if we can accept or should offer; {@code false} otherwise.
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
          connectionType == null ? PeerNode.ADDED_REASON_UNKNOWN : connectionType.ordinal());
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
      if (LOG.isDebugEnabled()) LOG.debug("Drop LRU opennet peer: {}", pn);
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
    // For opennet to work, we need LRU. For LRU to work it needs a choice.
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
    int typeCode = type == null ? PeerNode.ADDED_REASON_UNKNOWN : type.ordinal();
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
    int typeCode = type == null ? PeerNode.ADDED_REASON_UNKNOWN : type.ordinal();
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
      if (LOG.isDebugEnabled()) LOG.debug("Drop {}", toDrop);
      node.network().peers().messenger().disconnectAndRemove(toDrop, true, true, true);
    }
  }

  // A TOO OLD peer does not count towards the limit, even if it is not connected.
  // It can however be dumped if it doesn't connect in a reasonable time, and if
  // it upgrades, it may not have the usual grace period.

  /**
   * How many opennet peers do we have? Connected but out of date nodes don't count towards the
   * connection limit. Let them connect for long enough to auto-update. They will be disconnected
   * eventually, and then removed:
   *
   * @see OpennetPeerNode#shouldDisconnectAndRemoveNow()
   */
  public synchronized int getSize(LinkLengthClass distance) {
    int x = 0;
    for (Enumeration<OpennetPeerNode> e = lruQueue(distance).elements(); e.hasMoreElements(); ) {
      OpennetPeerNode pn = e.nextElement();
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
    map.compute(reason, (k, x) -> x == null ? 1 : x + 1);
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
   * <p>Increments success counters and promotes the peer to the LRU head when present. If the peer
   * is no longer tracked, attempts to re-add it as a reconnect.
   *
   * @param pn The peer that successfully handled a request.
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
        distance)) { // Start at top as it just succeeded
      node.network().peers().messenger().disconnectAndRemove(pn, true, false, true);
    }
  }

  /**
   * Notification that a peer was removed.
   *
   * <p>Removes it from the LRU and, when eligible, tracks it as an old-opennet-peer to allow
   * opportunistic reconnection.
   *
   * @param pn The removed peer.
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

  public synchronized void purgeOldOpennetPeer(OpennetPeerNode source) {
    oldPeers.remove(source);
  }

  /**
   * Compute the target total number of peers including darknet peers.
   *
   * <p>Uses bandwidth-based scaling when enabled and caps by network heuristics and user limits.
   *
   * @return Target count including darknet peers.
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
   * <p>Therefore a fast peer needs more peers than given by the square-root scaling.
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

  /** Get the target number of opennet peers. Do not call while holding locks. */
  public int getNumberOfConnectedPeersToAim(LinkLengthClass distance) {
    if (distance == null) throw new IllegalArgumentException();
    int target = getNumberOfConnectedPeersToAim();
    return distance.getTargetPeers(target);
  }

  /**
   * Compute the target number of opennet peers.
   *
   * <p>This subtracts the number of connected darknet peers from the overall target to determine
   * how many opennet peers to aim for.
   *
   * @return Target opennet peer count.
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
     * Called asynchronously once all packets have been queued and their send callbacks have fired.
     *
     * @param anyFailed {@code true} if any packet failed to send; {@code false} otherwise
     */
    void allSent(boolean anyFailed);
  }

  /**
   * Send our opennet noderef to a node.
   *
   * @param isReply If true, send an FNPOpennetConnectReply, else send an
   *     FNPOpennetConnectDestination.
   * @param uid The unique ID of the request chain involved.
   * @param peer The node to send the noderef to. Not necessarily an OpennetPeerNode, as path
   *     folding and possibly announcement can pass through darknet.
   * @param noderef The full compressed noderef to send.
   * @throws NotConnectedException If the peer becomes disconnected while we are trying to send the
   *     noderef.
   */
  @SuppressWarnings("UnusedReturnValue")
  public boolean sendOpennetRef(
      boolean isReply, long uid, PeerNode peer, byte[] noderef, ByteCounter ctr)
      throws NotConnectedException {
    return sendOpennetRef(isReply, uid, peer, noderef, ctr, null);
  }

  /**
   * Send our opennet noderef to a node, with an optional callback invoked when all packets have
   * been queued and observed as sent.
   *
   * @param isReply If true, send an FNPOpennetConnectReply, else send an
   *     FNPOpennetConnectDestination.
   * @param uid The unique ID of the request chain involved.
   * @param peer The node to send the noderef to. Not necessarily an OpennetPeerNode, as path
   *     folding and possibly announcement can pass through darknet.
   * @param noderef The full compressed noderef to send.
   * @param cb Optional callback invoked when all packets have been queued and sent.
   * @throws NotConnectedException If the peer becomes disconnected while we are trying to send the
   *     noderef.
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
      LOG.error("Noderef too big: {} bytes", noderef.length);
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
        bulkCb = (bulkTransmitter, anyFailed) -> cb.allSent(anyFailed);
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
   * @param uid Request chain UID.
   * @param peer Destination peer.
   * @param noderef Compressed noderef to send.
   * @param ctr Byte counter for accounting.
   * @param target Target location in [0,1).
   * @param htl HTL value for the announcement.
   * @return Transfer UID for the bulk send.
   * @throws NotConnectedException If the peer is not connected.
   */
  public long startSendAnnouncementRequest(
      long uid, PeerNode peer, byte[] noderef, ByteCounter ctr, double target, short htl)
      throws NotConnectedException {
    long xferUID = node.bootstrap().random().nextLong();
    Message msg =
        DMT.createFNPOpennetAnnounceRequest(
            uid, xferUID, noderef.length, paddedSize(noderef.length), target, htl);
    peer.transport().sendAsync(msg, null, ctr);
    return xferUID;
  }

  /**
   * Complete an announcement noderef transfer after the request message was sent.
   *
   * @param peer Destination peer.
   * @param noderef Compressed noderef payload.
   * @param ctr Byte counter for accounting.
   * @param xferUID Transfer UID returned by {@link #startSendAnnouncementRequest}.
   * @throws NotConnectedException If the peer is not connected.
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
   * @param uid The request chain UID.
   * @param peer Destination peer.
   * @param noderef Compressed noderef payload.
   * @param ctr Byte counter for accounting.
   * @throws NotConnectedException If the peer is not connected.
   */
  public void sendAnnouncementReply(long uid, PeerNode peer, byte[] noderef, ByteCounter ctr)
      throws NotConnectedException {
    byte[] padded = new byte[PADDED_NODEREF_SIZE];
    if (noderef.length > padded.length) {
      LOG.error("Noderef too big: {} bytes", noderef.length);
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
   * @param uid Parent request UID.
   * @param source Peer to notify.
   * @param reason DMT reason code.
   * @param ctr Byte counter for accounting.
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
   * @param target The target location in [0,1).
   * @param cb Callback for announcement status updates.
   */
  public void announce(double target, AnnouncementCallback cb) {
    AnnounceSender sender = new AnnounceSender(target, this, node, cb, null);
    node.network().executor().execute(sender, "Announcement to " + target);
  }

  /**
   * Get the creation time of this manager.
   *
   * @return Epoch time in milliseconds.
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
      if (LOG.isDebugEnabled()) LOG.debug("Add identity {} knownIds size {}", d, knownIds.size());
      knownIds.push(d, now);
      if (LOG.isDebugEnabled()) LOG.debug("Added identity {} knownIds size {}", d, knownIds.size());
      knownIds.removeBefore(now - MAX_AGE);
      if (LOG.isDebugEnabled())
        LOG.debug("Add and prune identity {} knownIds size {}", d, knownIds.size());
    }
    if (LOG.isDebugEnabled()) LOG.debug("Estimated opennet size (session)={}", knownIds.size());
  }

  // Return the estimated network size based on locations seen after timestamp or for the whole
  // session if -1
  /**
   * Return the estimated opennet size based on distinct identities observed.
   *
   * @param timestamp Count only identities seen after this epoch (ms), or {@code -1} for session
   *     scope.
   * @return Estimated size.
   */
  public int getNetworkSizeEstimate(long timestamp) {
    return knownIds.countValuesAfter(timestamp);
  }

  /**
   * Threshold for triggering an announcement, as determined by the {@link Announcer}.
   *
   * @return Current announcement threshold.
   */
  public int getAnnouncementThreshold() {
    return announcer.getAnnouncementThreshold();
  }

  /** Notification that a peer was disconnected. Query the Announcer, it may need to rerun. */
  public void onDisconnect() {
    if (announcer != null) announcer.maybeSendAnnouncementOffThread();
  }

  /**
   * Return the count of connection attempts for the given {@link ConnectionType}.
   *
   * <p>Thread safety: reads are synchronized to avoid races with opennet connection bookkeeping.
   *
   * @param type the connection type to read
   * @return number of attempts
   */
  public synchronized long getConnectionAttempts(ConnectionType type) {
    return connectionAttempts.get(type);
  }

  /**
   * Return the count of accepted connection attempts for the given {@link ConnectionType}.
   *
   * @param type the connection type to read
   * @return number of accepted attempts
   */
  public synchronized long getConnectionAttemptsAdded(ConnectionType type) {
    return connectionAttemptsAdded.get(type);
  }

  /**
   * Return the count of accepted connection attempts where free slots were available.
   *
   * @param type the connection type to read
   * @return number of accepted attempts with free slots
   */
  public synchronized long getConnectionAttemptsAddedPlentySpace(ConnectionType type) {
    return connectionAttemptsAddedPlentySpace.get(type);
  }

  /**
   * Return the count of connection attempts rejected by per-type grace period enforcement.
   *
   * @param type the connection type to read
   * @return number of rejected attempts
   */
  public synchronized long getConnectionAttemptsRejectedByPerTypeEnforcement(ConnectionType type) {
    return connectionAttemptsRejectedByPerTypeEnforcement.get(type);
  }

  /**
   * Return the count of connection attempts rejected because no peers were droppable.
   *
   * @param type the connection type to read
   * @return number of rejected attempts
   */
  public synchronized long getConnectionAttemptsRejectedNoPeersDroppable(ConnectionType type) {
    return connectionAttemptsRejectedNoPeersDroppable.get(type);
  }

  /**
   * Whether the announcer is waiting for an updater condition before proceeding.
   *
   * @return {@code true} if waiting; otherwise {@code false}.
   */
  @SuppressWarnings("unused")
  public boolean waitingForUpdater() {
    return announcer.isWaitingForUpdater();
  }

  /** Request the announcer to run again. */
  @SuppressWarnings("unused")
  public void reannounce() {
    announcer.reannounce();
  }

  /**
   * Called when a connection completes. If it's an opennet peer, we may need to drop a peer to make
   * space. If it's a darknet peer, the connection limit for opennet peers may have decreased so
   * again we may need to drop a peer.
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
   * @return The owning node.
   */
  public Node getNode() {
    return node;
  }

  /**
   * @return The opennet crypto component.
   */
  public NodeCrypto getCrypto() {
    return crypto;
  }

  /**
   * @return The announcer component, or {@code null} when disabled.
   */
  public Announcer getAnnouncer() {
    return announcer;
  }

  /**
   * @return The seed announcement tracker.
   */
  public SeedAnnounceTracker getSeedTracker() {
    return seedTracker;
  }
}

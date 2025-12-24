package network.crypta.io;

import static java.util.concurrent.TimeUnit.HOURS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
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
import java.util.HashMap;
import java.util.Iterator;
import network.crypta.io.comm.Peer;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.FSParseException;
import network.crypta.node.ProgramDirectory;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tracks packet traffic to and from peers and raw IP addresses to infer whether the local node is
 * reachable from the public internet (e.g., port forwarded) or likely behind NAT/stateful
 * filtering.
 *
 * <p>One instance typically exists per listening port (for example, per UDP socket handler). This
 * class maintains lightweight per-peer and per-IP counters and timestamps and persists them
 * periodically. Public methods are safe to call from multiple threads; state mutations are
 * synchronized, and read methods return snapshots that may be slightly stale under concurrent
 * updates.
 *
 * @author toad
 */
public class AddressTracker {
  private static final Logger LOG = LoggerFactory.getLogger(AddressTracker.class);

  /** Per-peer tracker items keyed by {@link Peer}. */
  private final HashMap<Peer, PeerAddressTrackerItem> peerTrackers;

  /** Per-address tracker items keyed by {@link InetAddress}. */
  private final HashMap<InetAddress, InetAddressAddressTrackerItem> ipTrackers;

  /** Maximum number of tracker items for either map before a reset/eviction occurs. */
  private int maxItems = DEFAULT_MAX_ITEMS;

  static final int DEFAULT_MAX_ITEMS = 1000;
  static final int SEED_MAX_ITEMS = 10000;
  private static final String PACKETS_PREFIX = "packets-";

  private long timeDefinitelyNoPacketsReceivedIP;
  private long timeDefinitelyNoPacketsSentIP;

  private long timeDefinitelyNoPacketsReceivedPeer;
  private long timeDefinitelyNoPacketsSentPeer;

  private long brokenTime;

  /**
   * Creates a tracker, restoring previously persisted state for the given port when available and
   * consistent.
   *
   * <p>The table is loaded from {@code packets-<port>.dat} under {@code runDir}. A backup file
   * {@code packets-<port>.bak} is cleaned before load. If the on-disk data is missing, corrupt, or
   * associated with a different boot ID, a fresh tracker is returned.
   *
   * @param lastBootID identifier of the last clean boot used to validate persisted state
   * @param runDir program directory where tracker files reside
   * @param port local UDP/TCP port whose traffic this instance observes
   * @return a new {@link AddressTracker}, possibly populated from disk
   */
  public static AddressTracker create(long lastBootID, ProgramDirectory runDir, int port) {
    File data = runDir.file(PACKETS_PREFIX + port + ".dat");
    File dataBak = runDir.file(PACKETS_PREFIX + port + ".bak");
    try {
      // Ensure a clean backup slot before any subsequent write/rotate.
      Files.deleteIfExists(dataBak.toPath());
    } catch (IOException e) {
      LOG.debug("Failed to delete backup file {} before load: {}", dataBak, e.toString());
    }
    try (FileInputStream fis = new FileInputStream(data);
        BufferedInputStream bis = new BufferedInputStream(fis);
        InputStreamReader ir = new InputStreamReader(bis, StandardCharsets.UTF_8);
        BufferedReader br = new BufferedReader(ir)) {
      SimpleFieldSet fs = new SimpleFieldSet(br, false, true);
      return new AddressTracker(fs, lastBootID);
    } catch (IOException _) {
      // Fall through
    } catch (FSParseException e) {
      LOG.warn("Failed to load from disk for port {}: {}", port, e, e);
      // Fall through
    }
    return new AddressTracker();
  }

  private AddressTracker() {
    timeDefinitelyNoPacketsReceivedIP = System.currentTimeMillis();
    timeDefinitelyNoPacketsSentIP = System.currentTimeMillis();
    timeDefinitelyNoPacketsReceivedPeer = System.currentTimeMillis();
    timeDefinitelyNoPacketsSentPeer = System.currentTimeMillis();
    peerTrackers = new HashMap<>();
    ipTrackers = new HashMap<>();
  }

  private AddressTracker(SimpleFieldSet fs, long lastBootID) throws FSParseException {
    int version = fs.getInt("Version");
    if (version != 2) throw new FSParseException("Unknown Version " + version);
    long savedBootID = fs.getLong("BootID");
    if (savedBootID != lastBootID)
      throw new FSParseException(
          "Unable to load address tracker table, assuming an unclean shutdown: Last ID was "
              + lastBootID
              + " but stored "
              + savedBootID);
    // We do not know whether packets arrived during any downtime. Some stateful devices keep
    // pinholes open on incoming traffic alone; treat receive timestamps as unknown since restart.
    timeDefinitelyNoPacketsReceivedPeer = System.currentTimeMillis();
    timeDefinitelyNoPacketsReceivedIP = System.currentTimeMillis();
    timeDefinitelyNoPacketsSentPeer = fs.getLong("TimeDefinitelyNoPacketsSentPeer");
    timeDefinitelyNoPacketsSentIP = fs.getLong("TimeDefinitelyNoPacketsSentIP");
    peerTrackers = new HashMap<>();
    SimpleFieldSet peers = fs.subset("Peers");
    if (peers != null) {
      Iterator<String> i = peers.directSubsetNameIterator();
      if (i != null) {
        while (i.hasNext()) {
          SimpleFieldSet peer = peers.subset(i.next());
          PeerAddressTrackerItem item = new PeerAddressTrackerItem(peer);
          peerTrackers.put(item.peer, item);
        }
      }
    }
    ipTrackers = new HashMap<>();
    SimpleFieldSet ips = fs.subset("IPs");
    if (ips != null) {
      Iterator<String> i = ips.directSubsetNameIterator();
      if (i != null) {
        while (i.hasNext()) {
          SimpleFieldSet peer = ips.subset(i.next());
          InetAddressAddressTrackerItem item = new InetAddressAddressTrackerItem(peer);
          ipTrackers.put(item.addr, item);
        }
      }
    }
  }

  /**
   * Records that a packet was sent to the given peer.
   *
   * @param peer destination peer; host names are dropped so tracking is keyed by resolved address
   */
  public void sentPacketTo(Peer peer) {
    packetTo(peer, true);
  }

  /**
   * Records that a packet was received from the given peer.
   *
   * @param peer source peer; host names are dropped so tracking is keyed by resolved address
   */
  public void receivedPacketFrom(Peer peer) {
    packetTo(peer, false);
  }

  private void packetTo(Peer peer, boolean sent) {
    Peer peer2 = peer.dropHostName();
    if (peer2 == null) {
      LOG.error("Impossible: No host name in AddressTracker.packetTo for {}", peer);
      return;
    }
    peer = peer2;

    InetAddress ip = peer.getAddress();
    long now = System.currentTimeMillis();
    synchronized (this) {
      PeerAddressTrackerItem peerItem = peerTrackers.get(peer);
      if (peerItem == null) {
        peerItem =
            new PeerAddressTrackerItem(
                timeDefinitelyNoPacketsReceivedPeer, timeDefinitelyNoPacketsSentPeer, peer);
        if (peerTrackers.size() > maxItems) {
          // Hard reset if the map would grow too large: this bounds memory and resets baselines.
          LOG.error("Clearing peer trackers on {}", this);
          peerTrackers.clear();
          ipTrackers.clear();
          timeDefinitelyNoPacketsReceivedPeer = now;
          timeDefinitelyNoPacketsSentPeer = now;
        }
        peerTrackers.put(peer, peerItem);
      }
      if (sent) peerItem.sentPacket(now);
      else peerItem.receivedPacket(now);
      InetAddressAddressTrackerItem ipItem = ipTrackers.get(ip);
      if (ipItem == null) {
        ipItem =
            new InetAddressAddressTrackerItem(
                timeDefinitelyNoPacketsReceivedIP, timeDefinitelyNoPacketsSentIP, ip);
        if (ipTrackers.size() > maxItems) {
          // Same reset strategy for the per-IP map.
          LOG.error("Clearing IP trackers on {}", this);
          peerTrackers.clear();
          ipTrackers.clear();
          timeDefinitelyNoPacketsReceivedIP = now;
          timeDefinitelyNoPacketsSentIP = now;
        }
        ipTrackers.put(ip, ipItem);
      }
      if (sent) ipItem.sentPacket(now);
      else ipItem.receivedPacket(now);
    }
  }

  /**
   * Declares that the system has started receiving packets at the given time; used to set the
   * baseline for the "no packets received since" timers.
   *
   * @param now wall-clock time in milliseconds since the epoch
   */
  public synchronized void startReceive(long now) {
    timeDefinitelyNoPacketsReceivedIP = now;
    timeDefinitelyNoPacketsReceivedPeer = now;
  }

  /**
   * Declares that the system has started sending packets at the given time; used to set the
   * baseline for the "no packets sent since" timers.
   *
   * @param now wall-clock time in milliseconds since the epoch
   */
  public synchronized void startSend(long now) {
    timeDefinitelyNoPacketsSentIP = now;
    timeDefinitelyNoPacketsSentPeer = now;
  }

  /**
   * Returns a snapshot of per-peer tracker items at the time of the call.
   *
   * @return array of items; never {@code null}
   */
  public synchronized PeerAddressTrackerItem[] getPeerAddressTrackerItems() {
    PeerAddressTrackerItem[] items = new PeerAddressTrackerItem[peerTrackers.size()];
    return peerTrackers.values().toArray(items);
  }

  /**
   * Returns a snapshot of per-peer tracker items at the time of the call.
   *
   * @return array of items; never {@code null}
   */
  public synchronized InetAddressAddressTrackerItem[] getInetAddressTrackerItems() {
    InetAddressAddressTrackerItem[] items = new InetAddressAddressTrackerItem[ipTrackers.size()];
    return ipTrackers.values().toArray(items);
  }

  public enum Status {
    /**
     * Note: the ordinal order is used elsewhere. Do not reorder without auditing consumers relying
     * on {@code ordinal()} comparisons.
     */
    DEFINITELY_NATED,
    MAYBE_NATED,
    DONT_KNOW,
    MAYBE_PORT_FORWARDED,
    DEFINITELY_PORT_FORWARDED
  }

  /**
   * Threshold (milliseconds): if the longest observed gap is at least this value, the node may be
   * port forwarded. RFC 4787 requires at least 2 minutes, but many NATs use shorter timeouts.
   */
  public static final long MAYBE_TUNNEL_LENGTH = MINUTES.toMillis(5) + SECONDS.toMillis(1);

  /**
   * Threshold (milliseconds): if the longest observed gap is at least this value, the node is very
   * likely port forwarded. Some stateful firewalls use timeouts of 30 minutes or more; this value
   * intends to exceed such behavior comfortably.
   */
  public static final long DEFINITELY_TUNNEL_LENGTH = HOURS.toMillis(12) + MINUTES.toMillis(1);

  /**
   * Time horizon (milliseconds) after which old evidence is ignored for port-forwarding assessment.
   */
  public static final long HORIZON = HOURS.toMillis(24);

  /**
   * Computes the longest observed gap (in milliseconds) between a time we were known not to have
   * sent any packets and a subsequent receive from an internet-reachable peer, using the default
   * {@link #HORIZON}.
   *
   * @return longest gap in milliseconds, or {@code -1} if insufficient evidence exists
   */
  public long getLongestSendReceiveGap() {
    return getLongestSendReceiveGap(HORIZON);
  }

  /**
   * Finds the longest send/known-no-packets-sent → receive gap within the given horizon. It is
   * unlikely that we are behind NAT/stateful filtering with a timeout shorter than the returned
   * length.
   *
   * @param horizon maximum age of evidence to consider, in milliseconds
   * @return longest gap in milliseconds, or {@code -1} if no qualifying peers are observed
   */
  public long getLongestSendReceiveGap(long horizon) {
    long longestGap = -1;
    long now = System.currentTimeMillis();
    PeerAddressTrackerItem[] items = getPeerAddressTrackerItems();
    for (PeerAddressTrackerItem item : items) {
      if (item.packetsReceived() <= 0 || !item.peer.isRealInternetAddress(false, false, false)) {
        continue;
      }
      longestGap = Math.max(longestGap, item.longestGap(horizon, now));
    }
    return longestGap;
  }

  /**
   * Derives the current connectivity status using observed gaps and internal flags.
   *
   * <p>If the longest gap exceeds {@link #DEFINITELY_TUNNEL_LENGTH}, the node is treated as
   * definitely port forwarded. Values above {@link #MAYBE_TUNNEL_LENGTH} but below the definite
   * threshold yield a "maybe" result. When gaps are inconclusive, the method considers
   * implementation safeguards: {@link #setBroken()} forces {@link Status#DEFINITELY_NATED} within
   * the {@link #HORIZON}, and an active presumption (see {@link #setPresumedGuiltyAt(long)}) may
   * return {@link Status#MAYBE_NATED}.
   *
   * @return connectivity status
   */
  public Status getPortForwardStatus() {
    long minGap = getLongestSendReceiveGap(HORIZON);

    if (minGap > DEFINITELY_TUNNEL_LENGTH) return Status.DEFINITELY_PORT_FORWARDED;
    if (minGap > MAYBE_TUNNEL_LENGTH) return Status.MAYBE_PORT_FORWARDED;
    // Consider failure/suspicion flags only when gaps are inconclusive. A hostile peer could
    // attempt to influence inputs (e.g., bogus sent-packet signals), so we bias toward caution.
    synchronized (this) {
      if (isBroken()) return Status.DEFINITELY_NATED;
      if (minGap == 0 && timePresumeGuilty > 0 && System.currentTimeMillis() > timePresumeGuilty)
        return Status.MAYBE_NATED;
    }
    return Status.DONT_KNOW;
  }

  private boolean isBroken() {
    return System.currentTimeMillis() - brokenTime < HORIZON;
  }

  /**
   * Returns a localized, human-readable label for the given status.
   *
   * @param status connectivity status
   * @return localized text suitable for UI display
   */
  public static String statusString(Status status) {
    return NodeL10n.getBase().getString("ConnectivityToadlet.status." + status);
  }

  /**
   * Persists the current table to disk under {@code packets-<port>.dat} in {@code runDir} using a
   * write-then-rotate strategy via {@code .bak}.
   *
   * <p>When the tracker is marked broken (see {@link #setBroken()}), writing is skipped to avoid
   * persisting misleading evidence. Errors are logged and do not throw.
   *
   * @param bootID boot identifier paired with this snapshot
   * @param runDir target directory for persistence
   * @param port associated local port
   */
  public void storeData(long bootID, ProgramDirectory runDir, int port) {
    // Don't write to disk if we know we're NATed anyway!
    if (isBroken()) return;
    File data = runDir.file(PACKETS_PREFIX + port + ".dat");
    File dataBak = runDir.file(PACKETS_PREFIX + port + ".bak");
    try {
      Files.deleteIfExists(dataBak.toPath());
    } catch (IOException e) {
      LOG.debug("Failed to delete backup file {} before store: {}", dataBak, e.toString());
    }
    try (FileOutputStream fos = new FileOutputStream(dataBak);
        BufferedOutputStream bos = new BufferedOutputStream(fos);
        OutputStreamWriter osw = new OutputStreamWriter(bos, StandardCharsets.UTF_8);
        BufferedWriter bw = new BufferedWriter(osw)) {
      SimpleFieldSet fs = getFieldset(bootID);
      fs.writeTo(bw);
      bw.flush();
    } catch (IOException _) {
      LOG.error("Cannot store packet tracker to disk");
      return;
    }
    FileUtil.moveTo(dataBak, data);
  }

  private synchronized SimpleFieldSet getFieldset(long bootID) {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.put("Version", 2);
    sfs.put("BootID", bootID);
    sfs.put("TimeDefinitelyNoPacketsReceivedPeer", timeDefinitelyNoPacketsReceivedPeer);
    sfs.put("TimeDefinitelyNoPacketsReceivedIP", timeDefinitelyNoPacketsReceivedIP);
    sfs.put("TimeDefinitelyNoPacketsSentPeer", timeDefinitelyNoPacketsSentPeer);
    sfs.put("TimeDefinitelyNoPacketsSentIP", timeDefinitelyNoPacketsSentIP);
    PeerAddressTrackerItem[] peerItems = getPeerAddressTrackerItems();
    SimpleFieldSet items = new SimpleFieldSet(true);
    if (peerItems.length > 0) {
      for (int i = 0; i < peerItems.length; i++)
        items.put(Integer.toString(i), peerItems[i].toFieldSet());
      sfs.put("Peers", items);
    }
    InetAddressAddressTrackerItem[] inetItems = getInetAddressTrackerItems();
    items = new SimpleFieldSet(true);
    if (inetItems.length > 0) {
      for (int i = 0; i < inetItems.length; i++)
        items.put(Integer.toString(i), inetItems[i].toFieldSet());
      sfs.put("IPs", items);
    }
    return sfs;
  }

  /**
   * Hook invoked when higher-level state changes may invalidate previous inferences. Currently, a
   * no-op; kept for future integration.
   */
  public void rescan() {
    // Do nothing for now, as we don't maintain any final state yet.
  }

  /**
   * Marks the tracker as broken at the current time. For the next {@link #HORIZON}, {@link
   * #getPortForwardStatus()} will bias toward {@link Status#DEFINITELY_NATED}.
   */
  public synchronized void setBroken() {
    brokenTime = System.currentTimeMillis();
  }

  private long timePresumeGuilty = -1;

  /**
   * Sets a future timestamp after which, in the absence of other evidence, the node may be treated
   * as {@link Status#MAYBE_NATED}. Has effect only if not already set.
   *
   * @param l wall-clock time in milliseconds since the epoch
   */
  public synchronized void setPresumedGuiltyAt(long l) {
    if (timePresumeGuilty <= 0) timePresumeGuilty = l;
  }

  /** Clears any prior presumption set by {@link #setPresumedGuiltyAt(long)}. */
  public synchronized void setPresumedInnocent() {
    timePresumeGuilty = -1;
  }

  /**
   * Increases the maximum tracker size to accommodate seed-like workloads with many observed
   * peers/addresses.
   */
  public synchronized void setHugeTracker() {
    maxItems = SEED_MAX_ITEMS;
  }
}

package network.crypta.node;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicIntegerArray;
import java.util.concurrent.atomic.AtomicLong;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.xfer.BlockTransmitter.BlockTimeCallback;
import network.crypta.node.SecurityLevels.NETWORK_THREAT_LEVEL;
import network.crypta.runtime.bootstrap.NodeStarter;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.math.BootstrappingDecayingRunningAverage;
import network.crypta.support.math.DecayingKeyspaceAverage;
import network.crypta.support.math.RunningAverage;
import network.crypta.support.math.RunningAverageBounds;
import network.crypta.support.math.TimeDecayingRunningAverage;
import network.crypta.support.math.TrivialRunningAverage;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * Collects and reports node-wide runtime statistics and load-admission decisions.
 *
 * <p>This class centralizes counters and decaying averages for networking, request scheduling,
 * block transfers, and datastore interactions. Hot-path components report events (bytes sent,
 * request outcomes, backoff delays), while diagnostics and admission control query aggregated
 * snapshots. Typical usage is "report as events occur" and "poll periodically," supporting UI
 * panels, peer exchanges, and policies such as {@link
 * #shouldRejectRequest(RequestAdmissionContext)}.
 *
 * <p>Invariants and trade-offs: counters are monotonic within a process, averages are time-decayed
 * views of recent behavior, and several thresholds are intentionally conservative to avoid
 * overload. The implementation favors short synchronized sections and atomic arrays to keep
 * contention low; callers should avoid expensive work while holding NodeStats locks.
 *
 * <ul>
 *   <li>Compute admission inputs from ping, bandwidth liability, and request outcomes.
 *   <li>Track per-type byte costs, success rates, and request locations.
 *   <li>Expose snapshot data for UI panels and persistence.
 * </ul>
 *
 * <p>Thread-safety: methods that read or update shared counters are synchronized or use atomic
 * structures. Callers should avoid long-running work while holding NodeStats locks.
 *
 * <p>Units: unless stated otherwise, byte counters are in bytes, times are in milliseconds, and
 * probabilities are in the {@code [0.0, 1.0]} range.
 *
 * @see Node
 * @see NodeStatsFieldSetExporter
 */
public final class NodeStats implements Persistable, BlockTimeCallback {
  private static final Logger LOG = LoggerFactory.getLogger(NodeStats.class);

  /** Kinds of requests and inserts tracked by NodeStats. */
  public enum RequestType {
    /**
     * CHK fetch request traffic recorded for admission and accounting decisions.
     *
     * <p>Represents a retrieval request (not an insert) and is tracked separately from SSK to keep
     * byte-cost and rejection statistics accurate.
     */
    CHK_REQUEST,

    /**
     * SSK fetch request traffic recorded separately from CHK for accounting.
     *
     * <p>Represents a retrieval request (not an insert) whose byte costs and rejection rates are
     * tracked independently for policy decisions.
     */
    SSK_REQUEST,

    /**
     * CHK insert traffic, tracked separately from fetches for overhead estimation.
     *
     * <p>Inserts affect stored data placement and use distinct admission assumptions compared with
     * retrieval requests.
     */
    CHK_INSERT,

    /**
     * SSK insert traffic, tracked separately from fetches for overhead estimation.
     *
     * <p>Inserts affect stored data placement and use distinct admission assumptions compared with
     * retrieval requests.
     */
    SSK_INSERT,

    /**
     * Offered-key CHK fetches, handled outside normal routing and tracked independently.
     *
     * <p>These direct retrievals from recent offers are counted separately to avoid skewing
     * standard fetch success metrics.
     */
    CHK_OFFER_FETCH,

    /**
     * Offered-key SSK fetches, handled outside normal routing and tracked independently.
     *
     * <p>These direct retrievals from recent offers are counted separately to avoid skewing
     * standard fetch success metrics.
     */
    SSK_OFFER_FETCH
  }

  /** Histogram for request locations. */
  private record RequestsByLocation(AtomicIntegerArray bins) {

    /** Constructs a request location histogram with the given number of bins. */
    RequestsByLocation(int numBins) {
      this(new AtomicIntegerArray(numBins));
    }

    /** Update the request counts with a request for the given location. */
    void report(final double loc) {
      assert loc >= 0 && loc < 1.0;
      int bin = (int) Math.floor(loc * bins.length());
      bins.incrementAndGet(bin);
    }

    /** Get the request count bins. */
    int[] getCounts() {
      int[] counts = new int[bins.length()];
      for (int i = 0; i < counts.length; i++) {
        counts[i] = bins.get(i);
      }
      return counts;
    }
  }

  /**
   * Lightweight histogram of per-location success rates.
   *
   * <p>Each bucket maintains a running average of reported values.
   */
  @SuppressWarnings("ClassCanBeRecord")
  private static class SuccessRateHistogram {
    private final double max;
    private final RunningAverage[] bars;

    SuccessRateHistogram(int numBars, double maxValue) {
      this.max = maxValue;
      this.bars = new RunningAverage[numBars];
      for (int i = 0; i < numBars; i++) {
        this.bars[i] = new TrivialRunningAverage();
      }
    }

    void report(double key, double value) {
      if (key < 0.0 || key >= max) return;
      int n = (int) (bars.length * key / max);
      bars[n].report(value);
    }

    int[] getPercentageArray(int localMax) {
      int[] retval = new int[bars.length];
      for (int i = 0; i < retval.length; i++) {
        int val = (int) (bars[i].currentValue() * localMax / max);
        retval[i] = val;
      }
      return retval;
    }
  }

  /** Sub-max ping time. If ping is greater than this, we reject some requests. */
  public static final long DEFAULT_SUB_MAX_PING_TIME = 700L;

  /** Maximum overall average ping time. If ping is greater than this, we reject all requests. */
  public static final long DEFAULT_MAX_PING_TIME = 1500L;

  /**
   * Maximum throttled packet delay for bulk transfers used by alerting logic. If the throttled
   * packet delay is greater than this, all packets would be rejected by legacy logic.
   */
  public static final long MAX_THROTTLE_DELAY_BULK = SECONDS.toMillis(10);

  /** How high can bwlimitDelayTime be before we alert (in milliseconds) */
  public static final long MAX_BWLIMIT_DELAY_TIME_ALERT_THRESHOLD = MAX_THROTTLE_DELAY_BULK;

  /** How high can nodeAveragePingTime be before we alert (in milliseconds) */
  public static final long MAX_NODE_AVERAGE_PING_TIME_ALERT_THRESHOLD = DEFAULT_MAX_PING_TIME;

  /** How long we're over the bwlimitDelayTime threshold before we alert (in milliseconds) */
  public static final long MAX_BWLIMIT_DELAY_TIME_ALERT_DELAY = MINUTES.toMillis(10);

  /** How long we're over the nodeAveragePingTime threshold before we alert (in milliseconds) */
  public static final long MAX_NODE_AVERAGE_PING_TIME_ALERT_DELAY = MINUTES.toMillis(10);

  /** Accept one request every 10 seconds regardless, to ensure we update the block send time. */
  public static final long MAX_INTERREQUEST_TIME = SECONDS.toMillis(10);

  /** Number of outbound transfers per insert assumed for admission logic. */
  private static final int OUTWARD_TRANSFERS_PER_INSERT = 1;

  /** Locations of incoming requests */
  private final RequestsByLocation incomingRequests = new RequestsByLocation(10);

  /** Locations of outgoing requests */
  private final RequestsByLocation outgoingLocalRequests = new RequestsByLocation(10);

  private final RequestsByLocation outgoingRequests = new RequestsByLocation(10);

  private volatile long subMaxPingTime;
  private volatile long maxPingTime;

  final Node node;

  /**
   * Peer manager associated with this node for connection and peer-count statistics.
   *
   * <p>This reference is final and non-null, while the manager itself maintains a mutable peer
   * state updated concurrently by networking components.
   */
  public final PeerManager peers;

  // static initializer intentionally removed (no-op)

  /** the first time bwlimitDelay was over PeerManagerUserAlert threshold */
  private volatile long firstBwlimitDelayTimeThresholdBreak;

  /** the first time nodeAveragePing was over PeerManagerUserAlert threshold */
  private volatile long firstNodeAveragePingTimeThresholdBreak;

  /** bwlimitDelay PeerManagerUserAlert should happen if true */
  private volatile boolean bwlimitDelayAlertRelevant;

  /** nodeAveragePing PeerManagerUserAlert should happen if true */
  private volatile boolean nodeAveragePingAlertRelevant;

  /**
   * Decaying average fraction of incoming requests rejected immediately due to overload.
   *
   * <p>Values are in {@code [0.0, 1.0]} and updated on admission decisions to provide a
   * coarse-grained signal for UI and diagnostics.
   */
  public final BootstrappingDecayingRunningAverage pInstantRejectIncomingOverall;

  /**
   * Decaying probability that an incoming realtime CHK request is rejected immediately.
   *
   * <p>Updated for each admission decision; used for realtime request diagnostics and load
   * reporting.
   */
  public final BootstrappingDecayingRunningAverage pInstantRejectIncomingCHKRequestRT;

  /**
   * Decaying probability that an incoming realtime SSK request is rejected immediately.
   *
   * <p>Reported as a {@code [0.0, 1.0]} fraction for UI and load-tracking decisions.
   */
  public final BootstrappingDecayingRunningAverage pInstantRejectIncomingSSKRequestRT;

  /**
   * Decaying probability that an incoming realtime CHK insert is rejected immediately.
   *
   * <p>Helps distinguish insert pressure from fetch pressure in realtime mode.
   */
  public final BootstrappingDecayingRunningAverage pInstantRejectIncomingCHKInsertRT;

  /**
   * Decaying probability that an incoming realtime SSK insert is rejected immediately.
   *
   * <p>Used for tracking insert overload behavior in realtime traffic.
   */
  public final BootstrappingDecayingRunningAverage pInstantRejectIncomingSSKInsertRT;

  /**
   * Decaying probability that an incoming bulk CHK request is rejected immediately.
   *
   * <p>Used to characterize bulk-mode admission pressure for CHK fetches.
   */
  public final BootstrappingDecayingRunningAverage pInstantRejectIncomingCHKRequestBulk;

  /**
   * Decaying probability that an incoming bulk SSK request is rejected immediately.
   *
   * <p>Used to characterize bulk-mode admission pressure for SSK fetches.
   */
  public final BootstrappingDecayingRunningAverage pInstantRejectIncomingSSKRequestBulk;

  /**
   * Decaying probability that an incoming bulk CHK insert is rejected immediately.
   *
   * <p>Reflects the insert load in bulk mode, distinct from fetch rejection rates.
   */
  public final BootstrappingDecayingRunningAverage pInstantRejectIncomingCHKInsertBulk;

  /**
   * Decaying probability that an incoming bulk SSK insert is rejected immediately.
   *
   * <p>Reflects the insert load in bulk mode, distinct from fetch rejection rates.
   */
  public final BootstrappingDecayingRunningAverage pInstantRejectIncomingSSKInsertBulk;

  private boolean ignoreLocalVsRemoteBandwidthLiability;

  /** Average delay caused by throttling for sending a packet */
  private final RunningAverage throttledPacketSendAverage;

  private final RunningAverage throttledPacketSendAverageRT;
  private final RunningAverage throttledPacketSendAverageBulk;

  // Bytes used by each different type of local/remote chk/ssk request/insert
  final TimeDecayingRunningAverage remoteChkFetchBytesSentAverage;
  final TimeDecayingRunningAverage remoteSskFetchBytesSentAverage;
  final TimeDecayingRunningAverage remoteChkInsertBytesSentAverage;
  final TimeDecayingRunningAverage remoteSskInsertBytesSentAverage;
  final TimeDecayingRunningAverage remoteChkFetchBytesReceivedAverage;
  final TimeDecayingRunningAverage remoteSskFetchBytesReceivedAverage;
  final TimeDecayingRunningAverage remoteChkInsertBytesReceivedAverage;
  final TimeDecayingRunningAverage remoteSskInsertBytesReceivedAverage;
  final TimeDecayingRunningAverage localChkFetchBytesSentAverage;
  final TimeDecayingRunningAverage localSskFetchBytesSentAverage;
  final TimeDecayingRunningAverage localChkInsertBytesSentAverage;
  final TimeDecayingRunningAverage localSskInsertBytesSentAverage;
  final TimeDecayingRunningAverage localChkFetchBytesReceivedAverage;
  final TimeDecayingRunningAverage localSskFetchBytesReceivedAverage;
  final TimeDecayingRunningAverage localChkInsertBytesReceivedAverage;
  final TimeDecayingRunningAverage localSskInsertBytesReceivedAverage;

  // Bytes used by successful chk/ssk request/insert.
  // Note: These are used to determine whether to accept a request,
  // hence they should be roughly representative of incoming - NOT LOCAL -
  // requests. Therefore, while we DO report local successful requests,
  // we only report the portion which will be consistent with a remote
  // request. If there is both a Handler and a Sender, it's a remote
  // request, report both. If there is only a Sender, report only the
  // received bytes (for a request). Etc.

  // Note that these are always reported in the Handler or the NodeClientCore
  // call taking its place.
  final TimeDecayingRunningAverage successfulChkFetchBytesSentAverage;
  final TimeDecayingRunningAverage successfulSskFetchBytesSentAverage;
  final TimeDecayingRunningAverage successfulChkInsertBytesSentAverage;
  final TimeDecayingRunningAverage successfulSskInsertBytesSentAverage;
  final TimeDecayingRunningAverage successfulChkOfferReplyBytesSentAverage;
  final TimeDecayingRunningAverage successfulSskOfferReplyBytesSentAverage;
  final TimeDecayingRunningAverage successfulChkFetchBytesReceivedAverage;
  final TimeDecayingRunningAverage successfulSskFetchBytesReceivedAverage;
  final TimeDecayingRunningAverage successfulChkInsertBytesReceivedAverage;
  final TimeDecayingRunningAverage successfulSskInsertBytesReceivedAverage;
  final TimeDecayingRunningAverage successfulChkOfferReplyBytesReceivedAverage;
  final TimeDecayingRunningAverage successfulSskOfferReplyBytesReceivedAverage;

  final TrivialRunningAverage globalFetchPSuccess;
  final TrivialRunningAverage chkLocalFetchPSuccess;
  final TrivialRunningAverage chkRemoteFetchPSuccess;
  final TrivialRunningAverage sskLocalFetchPSuccess;
  final TrivialRunningAverage sskRemoteFetchPSuccess;
  final TrivialRunningAverage blockTransferPSuccessRT;
  final TrivialRunningAverage blockTransferPSuccessBulk;
  final TrivialRunningAverage blockTransferPSuccessLocal;
  final TrivialRunningAverage blockTransferFailTimeout;

  final TrivialRunningAverage successfulLocalCHKFetchTimeAverageRT;
  final TrivialRunningAverage unsuccessfulLocalCHKFetchTimeAverageRT;
  final TrivialRunningAverage localCHKFetchTimeAverageRT;
  final TrivialRunningAverage successfulLocalCHKFetchTimeAverageBulk;
  final TrivialRunningAverage unsuccessfulLocalCHKFetchTimeAverageBulk;
  final TrivialRunningAverage localCHKFetchTimeAverageBulk;

  final TrivialRunningAverage successfulLocalSSKFetchTimeAverageRT;
  final TrivialRunningAverage unsuccessfulLocalSSKFetchTimeAverageRT;
  final TrivialRunningAverage localSSKFetchTimeAverageRT;
  final TrivialRunningAverage successfulLocalSSKFetchTimeAverageBulk;
  final TrivialRunningAverage unsuccessfulLocalSSKFetchTimeAverageBulk;
  final TrivialRunningAverage localSSKFetchTimeAverageBulk;

  /** Success rates of CHK fetches bucketed by location (diagnostic histogram). */
  private final SuccessRateHistogram chkSuccessRatesByLocation;

  private long previousInputStat;
  private long previousOutputStat;
  private long previousIoStatTime;
  private long lastInputStat;
  private long lastOutputStat;
  private long lastIoStatTime;
  private final Object ioStatSync = new Object();

  /** Monitor used to coordinate overload waiters; signaled on configuration changes. */
  private final Object overloadSync = new Object();

  /** Next time to update the node I/O stats */
  private long nextNodeIOStatsUpdateTime = -1;

  /** Node I/O stats update interval (milliseconds) */
  private static final long NODE_IO_STATS_UPDATE_INTERVAL = 2000;

  // various metrics
  /** Time-decayed miss distance for local routing decisions. */
  public final RunningAverage routingMissDistanceLocal;

  /** Time-decayed miss distance for remote routing decisions. */
  public final RunningAverage routingMissDistanceRemote;

  /** Aggregate miss distance across all routing modes. */
  public final RunningAverage routingMissDistanceOverall;

  /** Miss distance observed in bulk mode. */
  public final RunningAverage routingMissDistanceBulk;

  /** Miss distance observed in realtime mode. */
  public final RunningAverage routingMissDistanceRT;

  /** A fraction of time requests were backed off (0.0–1.0). */
  public final RunningAverage backedOffPercent;

  /** Average keyspace location for CHK hits in the main cache. */
  public final DecayingKeyspaceAverage avgCacheCHKLocation;

  /** Average keyspace location for CHK hits in the Slashdot cache. */
  public final DecayingKeyspaceAverage avgSlashdotCacheCHKLocation;

  // Average Slashdot cache location (legacy metric kept elsewhere)
  /** Average keyspace location for CHK hits in the store. */
  public final DecayingKeyspaceAverage avgStoreCHKLocation;

  // Average store location (legacy metric kept elsewhere)
  /** Average success probability for CHK in the store. */
  public final DecayingKeyspaceAverage avgStoreCHKSuccess;

  // Review: does furthest{Store,Cache}Success need to be synchronized?
  double furthestCacheCHKSuccess = 0.0;
  double furthestClientCacheCHKSuccess = 0.0;
  double furthestSlashdotCacheCHKSuccess = 0.0;
  double furthestStoreCHKSuccess = 0.0;
  double furthestStoreSSKSuccess = 0.0;
  double furthestCacheSSKSuccess = 0.0;
  double furthestClientCacheSSKSuccess = 0.0;
  double furthestSlashdotCacheSSKSuccess = 0.0;
  private final Persister persister;

  /**
   * Decaying average of request locations across the keyspace.
   *
   * <p>Values are normalized to {@code [0.0, 1.0]} and persisted to capture recent request
   * distribution for diagnostics and trend reporting.
   */
  private final DecayingKeyspaceAverage avgRequestLocation;

  /**
   * Records a request location into the decaying average.
   *
   * @param location normalized keyspace location in {@code [0.0, 1.0]}
   */
  public void reportRequestLocation(double location) {
    avgRequestLocation.report(location);
  }

  /**
   * Updates the furthest observed SSK store success distance.
   *
   * @param distance the observed distance
   */
  public void updateFurthestStoreSSKSuccess(double distance) {
    if (distance > furthestStoreSSKSuccess) furthestStoreSSKSuccess = distance;
  }

  /**
   * Updates the furthest observed SSK cache success distance.
   *
   * @param distance the observed distance
   */
  public void updateFurthestCacheSSKSuccess(double distance) {
    if (distance > furthestCacheSSKSuccess) furthestCacheSSKSuccess = distance;
  }

  /**
   * Updates the furthest observed SSK client cache success distance.
   *
   * @param distance the observed distance
   */
  public void updateFurthestClientCacheSSKSuccess(double distance) {
    if (distance > furthestClientCacheSSKSuccess) furthestClientCacheSSKSuccess = distance;
  }

  /**
   * Updates the furthest observed SSK Slashdot cache success distance.
   *
   * @param distance the observed distance
   */
  public void updateFurthestSlashdotCacheSSKSuccess(double distance) {
    if (distance > furthestSlashdotCacheSSKSuccess) furthestSlashdotCacheSSKSuccess = distance;
  }

  /**
   * Updates the furthest observed CHK store success distance.
   *
   * @param distance the observed distance
   */
  public void updateFurthestStoreCHKSuccess(double distance) {
    if (distance > furthestStoreCHKSuccess) furthestStoreCHKSuccess = distance;
  }

  /**
   * Updates the furthest observed CHK cache success distance.
   *
   * @param distance the observed distance
   */
  public void updateFurthestCacheCHKSuccess(double distance) {
    if (distance > furthestCacheCHKSuccess) furthestCacheCHKSuccess = distance;
  }

  /**
   * Updates the furthest observed CHK client cache success distance.
   *
   * @param distance the observed distance
   */
  public void updateFurthestClientCacheCHKSuccess(double distance) {
    if (distance > furthestClientCacheCHKSuccess) furthestClientCacheCHKSuccess = distance;
  }

  /**
   * Updates the furthest observed CHK Slashdot cache success distance.
   *
   * @param distance the observed distance
   */
  public void updateFurthestSlashdotCacheCHKSuccess(double distance) {
    if (distance > furthestSlashdotCacheCHKSuccess) furthestSlashdotCacheCHKSuccess = distance;
  }

  // ThreadCounting stuffs
  private int threadLimit;

  final NodePinger nodePinger;

  final Map<String, Integer> preemptiveRejectReasons;
  final Map<String, Integer> localPreemptiveRejectReasons;

  // Peers stats
  /** Next time to update PeerManagerUserAlert stats */
  private long nextPeerManagerUserAlertStatsUpdateTime = -1;

  /** PeerManagerUserAlert stats update interval (milliseconds) */
  private static final long PEER_MANAGER_USER_ALERT_STATS_UPDATE_INTERVAL = 1000; // 1 second

  // Backoff stats
  private final BackoffStats mandatoryBackoffStats = new BackoffStats();
  private final BackoffStats routingBackoffStats = new BackoffStats();
  private final BackoffStats transferBackoffStats = new BackoffStats();

  // Database stats
  private final Map<String, TrivialRunningAverage> avgDatabaseJobExecutionTimes =
      new ConcurrentHashMap<>();

  /** Average CHK location for the client cache. */
  public final DecayingKeyspaceAverage avgClientCacheCHKLocation;

  /** Average CHK success for the main cache. */
  public final DecayingKeyspaceAverage avgCacheCHKSuccess;

  /** Average CHK success for the Slashdot cache. */
  public final DecayingKeyspaceAverage avgSlashdotCacheCHKSucess;

  /** Average CHK success for the client cache. */
  public final DecayingKeyspaceAverage avgClientCacheCHKSuccess;

  /** Average SSK location for the store. */
  public final DecayingKeyspaceAverage avgStoreSSKLocation;

  /** Average SSK location for the main cache. */
  public final DecayingKeyspaceAverage avgCacheSSKLocation;

  /** Average SSK location for the Slashdot cache. */
  public final DecayingKeyspaceAverage avgSlashdotCacheSSKLocation;

  /** Average SSK location for the client cache. */
  public final DecayingKeyspaceAverage avgClientCacheSSKLocation;

  /** Average SSK success for the main cache. */
  public final DecayingKeyspaceAverage avgCacheSSKSuccess;

  /** Average SSK success for the Slashdot cache. */
  public final DecayingKeyspaceAverage avgSlashdotCacheSSKSuccess;

  /** Average SSK success for the client cache. */
  public final DecayingKeyspaceAverage avgClientCacheSSKSuccess;

  /** Average SSK success for the store. */
  public final DecayingKeyspaceAverage avgStoreSSKSuccess;

  private static final String PAIR_FMT = "{}/{}";
  private static final String L_CHK_INSERT_BYTES_RECEIVED_AVG =
      "LocalChkInsertBytesReceivedAverage";
  private static final String TEXT_CHK_INSERT = " CHK insert ";
  private static final String TEXT_SSK_INSERT = " SSK insert ";
  private static final String TEXT_CHK_FETCH = " CHK fetch ";
  private static final String TEXT_SSK_FETCH = " SSK fetch ";

  // (helpers removed; assignments performed directly in constructor to satisfy final semantics)

  private void initIoStatsDefaults() {
    previousInputStat = 0;
    previousOutputStat = 0;
    previousIoStatTime = 1;
    lastInputStat = 0;
    lastOutputStat = 0;
    lastIoStatTime = 3;
  }

  /**
   * Creates node statistics with the provided configuration.
   *
   * @param node owning node instance
   * @param sortOrder base sort order for config registration
   * @param statsConfig stats configuration helper
   * @throws NodeInitException if initialization fails
   */
  public NodeStats(Node node, int sortOrder, NodeStatsConfig statsConfig) throws NodeInitException {
    this.node = node;
    this.peers = node.network().peers();
    this.routingMissDistanceLocal =
        new TimeDecayingRunningAverage(RunningAverageBounds.of(0.0, 0.0, 1.0), 180000, node);
    this.routingMissDistanceRemote =
        new TimeDecayingRunningAverage(RunningAverageBounds.of(0.0, 0.0, 1.0), 180000, node);
    this.routingMissDistanceOverall =
        new TimeDecayingRunningAverage(RunningAverageBounds.of(0.0, 0.0, 1.0), 180000, node);
    this.routingMissDistanceBulk =
        new TimeDecayingRunningAverage(RunningAverageBounds.of(0.0, 0.0, 1.0), 180000, node);
    this.routingMissDistanceRT =
        new TimeDecayingRunningAverage(RunningAverageBounds.of(0.0, 0.0, 1.0), 180000, node);
    this.backedOffPercent =
        new TimeDecayingRunningAverage(RunningAverageBounds.of(0.0, 0.0, 1.0), 180000, node);
    preemptiveRejectReasons = new ConcurrentHashMap<>();
    localPreemptiveRejectReasons = new ConcurrentHashMap<>();
    pInstantRejectIncomingOverall =
        new BootstrappingDecayingRunningAverage(0.0, 0.0, 1.0, 1000, null);
    pInstantRejectIncomingCHKRequestRT =
        new BootstrappingDecayingRunningAverage(0.0, 0.0, 1.0, 1000, null);
    pInstantRejectIncomingSSKRequestRT =
        new BootstrappingDecayingRunningAverage(0.0, 0.0, 1.0, 1000, null);
    pInstantRejectIncomingCHKInsertRT =
        new BootstrappingDecayingRunningAverage(0.0, 0.0, 1.0, 1000, null);
    pInstantRejectIncomingSSKInsertRT =
        new BootstrappingDecayingRunningAverage(0.0, 0.0, 1.0, 1000, null);
    pInstantRejectIncomingCHKRequestBulk =
        new BootstrappingDecayingRunningAverage(0.0, 0.0, 1.0, 1000, null);
    pInstantRejectIncomingSSKRequestBulk =
        new BootstrappingDecayingRunningAverage(0.0, 0.0, 1.0, 1000, null);
    pInstantRejectIncomingCHKInsertBulk =
        new BootstrappingDecayingRunningAverage(0.0, 0.0, 1.0, 1000, null);
    pInstantRejectIncomingSSKInsertBulk =
        new BootstrappingDecayingRunningAverage(0.0, 0.0, 1.0, 1000, null);
    rejectStatsAveragers =
        new RunningAverage[] {
          pInstantRejectIncomingCHKRequestBulk,
          pInstantRejectIncomingSSKRequestBulk,
          pInstantRejectIncomingCHKInsertBulk,
          pInstantRejectIncomingSSKInsertBulk
        };
    noisyRejectStats = new byte[4];
    throttledPacketSendAverage =
        new BootstrappingDecayingRunningAverage(0, 0, Long.MAX_VALUE, 100, null);
    throttledPacketSendAverageRT =
        new BootstrappingDecayingRunningAverage(0, 0, Long.MAX_VALUE, 100, null);
    throttledPacketSendAverageBulk =
        new BootstrappingDecayingRunningAverage(0, 0, Long.MAX_VALUE, 100, null);
    nodePinger = new NodePinger(node);
    initIoStatsDefaults();

    NodeStatsConfig.Result configResult = statsConfig.configure(this, node, sortOrder);

    // This is a *network* level setting because it affects the rate at which we initiate local
    // requests, which could be seen by distant nodes.
    registerSecurityListener();

    persister = configResult.persister();
    SimpleFieldSet throttleFS = configResult.throttleFS();

    // Guesstimates. Hopefully well over the reality.
    localChkFetchBytesSentAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(500, 0.0, 200.0 * 1024),
            180000,
            subset(throttleFS, "LocalChkFetchBytesSentAverage"),
            node);
    localSskFetchBytesSentAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(500, 0.0, 200.0 * 1024),
            180000,
            subset(throttleFS, "LocalSskFetchBytesSentAverage"),
            node);
    localChkInsertBytesSentAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(32768, 0.0, 200.0 * 1024),
            180000,
            subset(throttleFS, "LocalChkInsertBytesSentAverage"),
            node);
    localSskInsertBytesSentAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(2048, 0.0, 200.0 * 1024),
            180000,
            subset(throttleFS, "LocalSskInsertBytesSentAverage"),
            node);
    localChkFetchBytesReceivedAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(32768d + 2048d /*path folding*/, 0.0, 200.0 * 1024),
            180000,
            subset(throttleFS, "LocalChkFetchBytesReceivedAverage"),
            node);
    localSskFetchBytesReceivedAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(2048, 0.0, 200.0 * 1024),
            180000,
            subset(throttleFS, "LocalSskFetchBytesReceivedAverage"),
            node);
    localChkInsertBytesReceivedAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(1024, 0.0, 200.0 * 1024),
            180000,
            subset(throttleFS, L_CHK_INSERT_BYTES_RECEIVED_AVG),
            node);
    localSskInsertBytesReceivedAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(500, 0.0, 200.0 * 1024),
            180000,
            subset(throttleFS, L_CHK_INSERT_BYTES_RECEIVED_AVG),
            node);

    remoteChkFetchBytesSentAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(
                32768d + 1024d + 500d + 2048d /*path folding*/, 0.0, 200.0 * 1024),
            180000,
            subset(throttleFS, "RemoteChkFetchBytesSentAverage"),
            node);
    remoteSskFetchBytesSentAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(1024d + 1024d + 500d, 0.0, 200.0 * 1024),
            180000,
            subset(throttleFS, "RemoteSskFetchBytesSentAverage"),
            node);
    remoteChkInsertBytesSentAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(32768d + 32768d + 1024d, 0.0, 200.0 * 1024),
            180000,
            subset(throttleFS, "RemoteChkInsertBytesSentAverage"),
            node);
    remoteSskInsertBytesSentAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(1024d + 1024d + 500d, 0.0, 200.0 * 1024),
            180000,
            subset(throttleFS, "RemoteSskInsertBytesSentAverage"),
            node);
    remoteChkFetchBytesReceivedAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(
                32768d + 1024d + 500d + 2048d /*path folding*/, 0.0, 200.0 * 1024),
            180000,
            subset(throttleFS, "RemoteChkFetchBytesReceivedAverage"),
            node);
    remoteSskFetchBytesReceivedAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(2048d + 500d, 0.0, 200.0 * 1024),
            180000,
            subset(throttleFS, "RemoteSskFetchBytesReceivedAverage"),
            node);
    remoteChkInsertBytesReceivedAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(32768d + 1024d + 500d, 0.0, 200.0 * 1024),
            180000,
            subset(throttleFS, "RemoteChkInsertBytesReceivedAverage"),
            node);
    remoteSskInsertBytesReceivedAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(1024d + 1024d + 500d, 0.0, 200.0 * 1024),
            180000,
            subset(throttleFS, "RemoteSskInsertBytesReceivedAverage"),
            node);

    successfulChkFetchBytesSentAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(
                32768d + 1024d + 500d + 2048d /*path folding*/, 0.0, 200.0 * 1024),
            180000,
            subset(throttleFS, "SuccessfulChkFetchBytesSentAverage"),
            node);
    successfulSskFetchBytesSentAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(1024d + 1024d + 500d, 0.0, 200.0 * 1024),
            180000,
            subset(throttleFS, "SuccessfulSskFetchBytesSentAverage"),
            node);
    successfulChkInsertBytesSentAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(32768d + 32768d + 1024d, 0.0, 200.0 * 1024),
            180000,
            subset(throttleFS, "SuccessfulChkInsertBytesSentAverage"),
            node);
    successfulSskInsertBytesSentAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(1024d + 1024d + 500d, 0.0, 200.0 * 1024),
            180000,
            subset(throttleFS, "SuccessfulSskInsertBytesSentAverage"),
            node);
    successfulChkOfferReplyBytesSentAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(32768d + 500d, 0.0, 200.0 * 1024),
            180000,
            subset(throttleFS, "successfulChkOfferReplyBytesSentAverage"),
            node);
    successfulSskOfferReplyBytesSentAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(3072, 0.0, 200.0 * 1024),
            180000,
            subset(throttleFS, "successfulSskOfferReplyBytesSentAverage"),
            node);
    successfulChkFetchBytesReceivedAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(
                32768d + 1024d + 500d + 2048d /*path folding*/, 0.0, 200.0 * 1024),
            180000,
            subset(throttleFS, "SuccessfulChkFetchBytesReceivedAverage"),
            node);
    successfulSskFetchBytesReceivedAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(2048d + 500d, 0.0, 200.0 * 1024),
            180000,
            subset(throttleFS, "SuccessfulSskFetchBytesReceivedAverage"),
            node);
    successfulChkInsertBytesReceivedAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(32768d + 1024d + 500d, 0.0, 200.0 * 1024),
            180000,
            subset(throttleFS, "SuccessfulChkInsertBytesReceivedAverage"),
            node);
    successfulSskInsertBytesReceivedAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(1024d + 1024d + 500d, 0.0, 200.0 * 1024),
            180000,
            subset(throttleFS, "SuccessfulSskInsertBytesReceivedAverage"),
            node);
    successfulChkOfferReplyBytesReceivedAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(32768d + 500d, 0.0, 200.0 * 1024),
            180000,
            subset(throttleFS, "successfulChkOfferReplyBytesReceivedAverage"),
            node);
    successfulSskOfferReplyBytesReceivedAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(3072, 0.0, 200.0 * 1024),
            180000,
            subset(throttleFS, "successfulSskOfferReplyBytesReceivedAverage"),
            node);

    globalFetchPSuccess = new TrivialRunningAverage();
    chkLocalFetchPSuccess = new TrivialRunningAverage();
    chkRemoteFetchPSuccess = new TrivialRunningAverage();
    sskLocalFetchPSuccess = new TrivialRunningAverage();
    sskRemoteFetchPSuccess = new TrivialRunningAverage();
    blockTransferPSuccessRT = new TrivialRunningAverage();
    blockTransferPSuccessBulk = new TrivialRunningAverage();
    blockTransferPSuccessLocal = new TrivialRunningAverage();
    blockTransferFailTimeout = new TrivialRunningAverage();

    successfulLocalCHKFetchTimeAverageRT = new TrivialRunningAverage();
    unsuccessfulLocalCHKFetchTimeAverageRT = new TrivialRunningAverage();
    localCHKFetchTimeAverageRT = new TrivialRunningAverage();
    successfulLocalCHKFetchTimeAverageBulk = new TrivialRunningAverage();
    unsuccessfulLocalCHKFetchTimeAverageBulk = new TrivialRunningAverage();
    localCHKFetchTimeAverageBulk = new TrivialRunningAverage();

    successfulLocalSSKFetchTimeAverageRT = new TrivialRunningAverage();
    unsuccessfulLocalSSKFetchTimeAverageRT = new TrivialRunningAverage();
    localSSKFetchTimeAverageRT = new TrivialRunningAverage();
    successfulLocalSSKFetchTimeAverageBulk = new TrivialRunningAverage();
    unsuccessfulLocalSSKFetchTimeAverageBulk = new TrivialRunningAverage();
    localSSKFetchTimeAverageBulk = new TrivialRunningAverage();

    chkSuccessRatesByLocation = new SuccessRateHistogram(10, 1.0);

    double nodeLoc = node.network().locationManager().getLocation();
    this.avgCacheCHKLocation =
        new DecayingKeyspaceAverage(nodeLoc, 10000, subset(throttleFS, "AverageCacheCHKLocation"));
    this.avgStoreCHKLocation = dka(nodeLoc, "AverageStoreCHKLocation", throttleFS);
    this.avgSlashdotCacheCHKLocation = dka(nodeLoc, "AverageSlashdotCacheCHKLocation", throttleFS);
    this.avgClientCacheCHKLocation = dka(nodeLoc, "AverageClientCacheCHKLocation", throttleFS);

    this.avgCacheCHKSuccess = dka(nodeLoc, "AverageCacheCHKSuccessLocation", throttleFS);
    this.avgSlashdotCacheCHKSucess =
        dka(nodeLoc, "AverageSlashdotCacheCHKSuccessLocation", throttleFS);
    this.avgClientCacheCHKSuccess =
        dka(nodeLoc, "AverageClientCacheCHKSuccessLocation", throttleFS);
    this.avgStoreCHKSuccess = dka(nodeLoc, "AverageStoreCHKSuccessLocation", throttleFS);
    this.avgRequestLocation = dka(nodeLoc, "AverageRequestLocation", throttleFS);

    this.avgCacheSSKLocation = dka(nodeLoc, "AverageCacheSSKLocation", throttleFS);
    this.avgStoreSSKLocation = dka(nodeLoc, "AverageStoreSSKLocation", throttleFS);
    this.avgSlashdotCacheSSKLocation = dka(nodeLoc, "AverageSlashdotCacheSSKLocation", throttleFS);
    this.avgClientCacheSSKLocation = dka(nodeLoc, "AverageClientCacheSSKLocation", throttleFS);

    this.avgCacheSSKSuccess = dka(nodeLoc, "AverageCacheSSKSuccessLocation", throttleFS);
    this.avgSlashdotCacheSSKSuccess =
        dka(nodeLoc, "AverageSlashdotCacheSSKSuccessLocation", throttleFS);
    this.avgClientCacheSSKSuccess =
        dka(nodeLoc, "AverageClientCacheSSKSuccessLocation", throttleFS);
    this.avgStoreSSKSuccess = dka(nodeLoc, "AverageStoreSSKSuccessLocation", throttleFS);

    hourlyStatsRT = new HourlyStats(node);
    hourlyStatsBulk = new HourlyStats(node);
    if (!NodeStarter.isTestingVM()) {
      minReportsNoisyRejectStats = 200;
      rejectStatsUpdateInterval = MINUTES.toMillis(10);
      rejectStatsFuzz = 10.0;
    } else {
      minReportsNoisyRejectStats = 1;
      rejectStatsUpdateInterval = SECONDS.toMillis(10);
      rejectStatsFuzz = -1.0;
    }
  }

  private void registerSecurityListener() {
    node.services()
        .securityLevels()
        .addNetworkThreatLevelListener(
            (oldLevel, newLevel) -> {
              if (newLevel == NETWORK_THREAT_LEVEL.MAXIMUM) {
                ignoreLocalVsRemoteBandwidthLiability = true;
              }
              if (oldLevel == NETWORK_THREAT_LEVEL.MAXIMUM) {
                ignoreLocalVsRemoteBandwidthLiability = false;
              }
            });
  }

  /**
   * Starts background components used for live statistics.
   *
   * <p>Side effects: schedules {@code NodePinger}, starts the {@code Persister}, and kicks off the
   * periodic updater for noisy reject statistics. Safe to call once during node startup.
   */
  public void start() {
    node.network().executor().execute(nodePinger::start, "Starting NodePinger");
    persister.start();
    noisyRejectStatsUpdater.run();
  }

  /**
   * Absolute limit of 4MB queued to any given peer. Note: consider making this configurable. Note
   * that for many MessageItem's, the actual memory usage will be significantly more than this
   * figure.
   */
  private static final long MAX_PEER_QUEUE_BYTES = 4L * 1024 * 1024;

  /**
   * Don't accept requests if it'll take more than 1 minute to send the current message queue. On
   * the assumption that most of the message queue is block transfer data. Note that this only
   * applies to data on the queue before calling shouldRejectRequest(): we do *not* attempt to
   * include any estimate of how much the request will add to it. This is important because if we
   * did, the AIMD may not have reached enough speed to transfer it in 60 seconds yet, because it
   * hasn't had enough data in transit to need to increase its speed.
   *
   * <p>Interaction with output bandwidth liability: This must be slightly larger than the output
   * bandwidth liability time limit (combined for both types).
   *
   * <p>A fast peer can have slightly more than half our output limit queued in requests to run. If
   * they all complete, they will take half the time limit. If they are all served from the store,
   * this will be shown on the queue time. But the queue time is estimated based on using at most
   * half the limit, so the time will be slightly over the overall limit.
   */
  // Consider increasing to 4 minutes when the bulk/realtime flag merged.
  private static final long MAX_PEER_QUEUE_TIME = MINUTES.toMillis(2);

  private long lastAcceptedRequest = -1;

  static final double DEFAULT_OVERHEAD = 0.7;
  static final long DEFAULT_ONLY_PERIOD = MINUTES.toMillis(1);
  static final long DEFAULT_TRANSITION_PERIOD = MINUTES.toMillis(4);

  /**
   * Relatively high minimum overhead. A low overhead estimate becomes a self-fulfilling prophecy,
   * and it takes a long time to shake it off as the averages gradually increase. If we accept no
   * requests, then everything is overhead! Whereas with a high minimum overhead, the worst case is
   * that more stuff succeeds than expected. We have a few timeouts (because output bandwidth
   * liability was assuming a lower overhead than actually happens) - but this should be very rare.
   */
  static final double MIN_NON_OVERHEAD = 0.5;

  /**
   * All requests must be able to complete in this many seconds given the bandwidth available, even
   * if they all succeed. Bulk requests.
   */
  static final int BANDWIDTH_LIABILITY_LIMIT_SECONDS_BULK = 120;

  /**
   * All requests must be able to complete in this many seconds given the bandwidth available, even
   * if they all succeed. Realtime requests - separate from bulk requests, given higher priority but
   * expected to be bursty and lower capacity.
   */
  static final int BANDWIDTH_LIABILITY_LIMIT_SECONDS_REALTIME = 60;

  /**
   * @param soft If true, rejected because of preemptive bandwidth limiting, i.e. "soft", at least
   *     somewhat predictable, can be retried. If false, hard rejection should backoff and not
   *     retry.
   */
  record RejectReason(String name, boolean soft) {

    @Override
    public @NotNull String toString() {
      return (soft ? "SOFT" : "HARD") + ":" + name;
    }
  }

  private record TransferLimits(
      int maxOutputTransfers,
      int maxTransfersOutUpperLimit,
      int maxTransfersOutLowerLimit,
      int maxTransfersOutPeerLimit) {}

  private final Object serializeShouldRejectRequest = new Object();

  /**
   * Should a request be accepted by this node, based on its local capacity? This includes thread
   * limits and ping times, but more importantly, mechanisms based on predicting worst case
   * bandwidth usage for all running requests and fairly sharing that capacity between peers.
   * Currently, there is no mechanism for fairness between request types, this should be implemented
   * on the sender side and is with new load management. New load management has caused various
   * changes here, but that's probably sorted out now, i.e., changes involved in new load management
   * will probably be mainly in PeerNode and RequestSender now.
   *
   * @param context request admission inputs
   * @return The reason for rejecting it, or null to accept it.
   */
  RejectReason shouldRejectRequest(RequestAdmissionContext context) {
    // Serialise shouldRejectRequest.
    // It's not always called on the same thread, and things could be problematic if they interfere
    // with each other.
    synchronized (serializeShouldRejectRequest) {
      boolean isSSK = context.isSSK();
      boolean realTimeFlag = context.realTimeFlag();
      PeerNode source = context.source();
      boolean hasInStore = context.hasInStore();

      if (LOG.isDebugEnabled()) dumpByteCostAverages();

      RejectReason early = checkThreadsAndPing(context);
      if (early != null) return early;

      long now = System.currentTimeMillis();

      double nonOverheadFraction = getNonOverheadFraction(now);

      // Pre-emptive rejection based on avoiding timeouts, with fair sharing
      // between peers. We calculate the node's capacity for requests and then
      // decide whether we will exceed it or whether a particular peer will
      // exceed its slice of it. Peers are guaranteed a proportion of the
      // total ("peer limit"), but can opportunistically use a bit more,
      // provided the total is less than the "lower limit". The overall usage
      // should not go over the "upper limit".

      // This should normally account for the bulk of request rejections.

      int transfersPerInsert = OUTWARD_TRANSFERS_PER_INSERT;

      /* Requests running, globally */
      RunningRequestsSnapshot requestsSnapshot =
          new RunningRequestsSnapshot(
              node.routing().tracker(),
              ignoreLocalVsRemoteBandwidthLiability,
              transfersPerInsert,
              realTimeFlag);

      // Don't need to decrement because it won't be counted until setAccepted() below.

      if (LOG.isDebugEnabled()) requestsSnapshot.log();

      long limit = getLimitSeconds(realTimeFlag);
      limit = adjustLimitForDatastore(limit, hasInStore);

      int peerCount =
          node.network().peers().countConnectedPeers()
              + 2 * node.network().peers().countConnectedDarknetPeers();

      // These limits are by transfers.
      // We limit the total number of transfers running in parallel to ensure
      // that they don't get starved: The number of seconds a transfer has to
      // wait (for all the others) before it can send needs to be reasonable.

      // Whereas the bandwidth-based limit is by bytes, on the principle that
      // it must be possible to complete all transfers within a reasonable time.

      /*
       * Requests running for this specific peer (local counts as a peer). Note that this separately
       * counts requests which have sourceRestarted, which are not included in the count, and are
       * decremented from the peer limit before it is used and sent to the peer. This ensures that
       * the peer doesn't use more than it should after a restart.
       */
      RunningRequestsSnapshot peerRequestsSnapshot =
          new RunningRequestsSnapshot(
              node.routing().tracker(),
              source,
              false,
              ignoreLocalVsRemoteBandwidthLiability,
              transfersPerInsert,
              realTimeFlag);
      if (LOG.isDebugEnabled()) peerRequestsSnapshot.log(source);

      int maxTransfersOutUpperLimit = getMaxTransfersUpperLimit(realTimeFlag, nonOverheadFraction);
      int maxTransfersOutLowerLimit = (int) Math.max(1, getLowerLimit(maxTransfersOutUpperLimit));
      int maxTransfersOutPeerLimit =
          (int)
              Math.max(
                  1,
                  getPeerLimit(
                      source,
                      (double) maxTransfersOutUpperLimit - (double) maxTransfersOutLowerLimit,
                      peerCount,
                      (peerRequestsSnapshot.expectedTransfersOutCHKSR
                          + peerRequestsSnapshot.expectedTransfersOutSSKSR)));
      /* Per-peer limit based on the current state of the connection. */
      int maxOutputTransfers =
          this.calculateMaxTransfersOut(
              source, realTimeFlag, nonOverheadFraction, maxTransfersOutUpperLimit);
      TransferLimits transferLimits =
          new TransferLimits(
              maxOutputTransfers,
              maxTransfersOutUpperLimit,
              maxTransfersOutLowerLimit,
              maxTransfersOutPeerLimit);

      // Check bandwidth-based limits, with fair sharing.

      String ret =
          checkBandwidthLiability(
              getOutputBandwidthUpperLimit(limit, nonOverheadFraction),
              requestsSnapshot,
              peerRequestsSnapshot,
              false,
              context);
      if (ret != null) {
        return new RejectReason(ret, true);
      }

      ret =
          checkBandwidthLiability(
              getInputBandwidthUpperLimit(limit),
              requestsSnapshot,
              peerRequestsSnapshot,
              true,
              context);
      if (ret != null) {
        return new RejectReason(ret, true);
      }

      // Check transfer-based limits, with fair sharing.

      ret =
          checkMaxOutputTransfers(transferLimits, requestsSnapshot, peerRequestsSnapshot, context);
      if (ret != null) {
        return new RejectReason(ret, true);
      }

      // Message queues - when the link level has far more queued than it can transmit in a
      // reasonable time, don't accept requests.
      RejectReason qrr = checkPeerQueues(source, context);
      if (qrr != null) return qrr;

      synchronized (this) {
        if (LOG.isDebugEnabled()) LOG.debug("Accept request (isSSK={})", isSSK);
        lastAcceptedRequest = now;
      }

      accepted(context);

      context.markAccepted();

      // Accept
      return null;
    }
  }

  private RejectReason checkThreadsAndPing(RequestAdmissionContext context) {
    PeerNode source = context.source();
    boolean canAcceptAnyway = context.canAcceptAnyway();
    boolean preferInsert = context.preferInsert();
    if (source != null && source.isDisconnecting()) return new RejectReason("disconnecting", false);
    int threadCount = getActiveThreadCount();
    if (threadLimit < threadCount) {
      rejected(">threadLimit", context);
      return new RejectReason(">threadLimit (" + threadCount + '/' + threadLimit + ')', false);
    }
    long now = System.currentTimeMillis();
    double pingTime = nodePinger.averagePingTime();
    synchronized (this) {
      if (pingTime > maxPingTime) {
        if ((now - lastAcceptedRequest > MAX_INTERREQUEST_TIME) && canAcceptAnyway) {
          if (LOG.isDebugEnabled())
            LOG.debug("Accept request to refresh bwlimitDelayTime (every 10 s)");
        } else {
          rejected(">MAX_PING_TIME", context);
          return new RejectReason(">MAX_PING_TIME (" + formatPingTime(pingTime) + ')', false);
        }
      } else if (pingTime > subMaxPingTime) {
        double x = (pingTime - subMaxPingTime) / (maxPingTime - subMaxPingTime);
        if (randomLessThan(x, preferInsert)) {
          rejected(">SUB_MAX_PING_TIME", context);
          return new RejectReason(">SUB_MAX_PING_TIME (" + formatPingTime(pingTime) + ')', false);
        }
      }
    }
    return null;
  }

  private static String formatPingTime(double pingTimeMillis) {
    return String.format("%.3fs", pingTimeMillis / 1000.0);
  }

  private long adjustLimitForDatastore(long limit, boolean hasInStore) {
    if (hasInStore) {
      long newLimit = limit + 10;
      if (LOG.isDebugEnabled())
        LOG.debug("Allow extra request; block in datastore (limit {} s)", newLimit);
      return newLimit;
    }
    return limit;
  }

  private RejectReason checkPeerQueues(PeerNode source, RequestAdmissionContext context) {
    if (source == null) return null;
    if (source.getMessageQueueLengthBytes() > MAX_PEER_QUEUE_BYTES) {
      rejected(">MAX_PEER_QUEUE_BYTES", context);
      return new RejectReason("Too many message bytes queued for peer", false);
    }
    if (source.getProbableSendQueueTime() > MAX_PEER_QUEUE_TIME) {
      rejected(">MAX_PEER_QUEUE_TIME", context);
      return new RejectReason("Peer's queue will take too long to transfer", false);
    }
    return null;
  }

  private int getLimitSeconds(boolean realTimeFlag) {
    return realTimeFlag
        ? BANDWIDTH_LIABILITY_LIMIT_SECONDS_REALTIME
        : BANDWIDTH_LIABILITY_LIMIT_SECONDS_BULK;
  }

  /**
   * Calculates the per-peer maximum number of concurrent outbound transfers based on congestion
   * control and acceptable block times.
   *
   * @param peer target peer; when {@code null}, returns {@link Integer#MAX_VALUE}.
   * @param realTime whether the request is realtime.
   * @param nonOverheadFraction estimated fraction of output usable for payload.
   * @param maxTransfersOutUpperLimit global cap derived from bandwidth limits.
   * @return the per-peer cap, honoring both peer and global constraints.
   */
  public int calculateMaxTransfersOut(
      PeerNode peer, boolean realTime, double nonOverheadFraction, int maxTransfersOutUpperLimit) {
    if (peer == null) return Integer.MAX_VALUE;
    else
      return Math.min(
          maxTransfersOutUpperLimit,
          peer.calculateMaxTransfersOut(getAcceptableBlockTime(realTime), nonOverheadFraction));
  }

  private int getAcceptableBlockTime(boolean realTime) {
    return realTime ? 2 : 15;
  }

  /**
   * Returns the lower limit given an upper-limit capacity.
   *
   * <p>Fair sharing starts once total usage exceeds this value.
   *
   * @param upperLimit the computed upper-limit capacity for a peer or bucket.
   * @return the lower-limit capacity threshold that triggers fair sharing.
   */
  public double getLowerLimit(double upperLimit) {
    // Bandwidth scheduling is now unfair, based on deadlines.
    // Therefore, we can allocate a large chunk of our capacity to a single peer.
    return upperLimit / 2;
  }

  private double getInputBandwidthUpperLimit(long limit) {
    return node.network().inputBandwidthLimit() * (double) limit;
  }

  @SuppressWarnings("java:S1905")
  private double getNonOverheadFraction(long now) {

    long[] total = node.network().collector().getTotalIO();
    long totalSent = total[0];
    long totalOverhead = getSentOverhead();
    long uptime = node.network().uptime();

    /* The fraction of output bytes which are used for requests */
    // Consider using a shorter average; evaluate behavior when bwlimit changes

    double totalCouldSend =
        Math.max((double) totalSent, (node.network().outputBandwidthLimit() * uptime) / 1000.0);
    double nonOverheadFraction = (totalCouldSend - totalOverhead) / totalCouldSend;
    long timeFirstAnyConnections = peers.getTimeFirstAnyConnections();
    if (timeFirstAnyConnections > 0) {
      long time = now - timeFirstAnyConnections;
      if (time < DEFAULT_ONLY_PERIOD) {
        nonOverheadFraction = DEFAULT_OVERHEAD;
        if (LOG.isDebugEnabled())
          LOG.debug("Adjusted non-overhead fraction (startup only): {}", nonOverheadFraction);
      } else if (time < DEFAULT_ONLY_PERIOD + DEFAULT_TRANSITION_PERIOD) {
        time -= DEFAULT_ONLY_PERIOD;
        nonOverheadFraction =
            (time * nonOverheadFraction + (DEFAULT_TRANSITION_PERIOD - time) * DEFAULT_OVERHEAD)
                / DEFAULT_TRANSITION_PERIOD;
        if (LOG.isDebugEnabled())
          LOG.debug("Adjusted non-overhead fraction (startup transition): {}", nonOverheadFraction);
      }
    }
    if (nonOverheadFraction < MIN_NON_OVERHEAD) {
      // If there been an auto-update, we may have used a vast amount of bandwidth for it.
      // Also, if things have broken, our overhead might be above our bandwidth limit,
      // especially on a slow node.

      // So impose a minimum of 20% of the bandwidth limit.
      // This will ensure we don't get stuck in any situation where all our bandwidth is overhead,
      // and we don't accept any requests because of that, so it remains that way...
      LOG.warn(
          "Non-overhead fraction is {} - assuming this is self-inflicted and using default",
          nonOverheadFraction);
      nonOverheadFraction = MIN_NON_OVERHEAD;
    }
    if (nonOverheadFraction > 1.0) {
      LOG.error("Non-overhead fraction exceeds 1.0");
      return 1.0;
    }
    return nonOverheadFraction;
  }

  private double getOutputBandwidthUpperLimit(long limit, double nonOverheadFraction) {
    double outputAvailablePerSecond = node.network().outputBandwidthLimit() * nonOverheadFraction;
    return outputAvailablePerSecond * limit;
  }

  private int getMaxTransfersUpperLimit(boolean realTime, double nonOverheadFraction) {
    // Could refactor with getOutputBandwidthUpperLimit to avoid duplicate calculation
    double outputAvailablePerSecond = node.network().outputBandwidthLimit() * nonOverheadFraction;

    return (int)
        Math.max(1, (getAcceptableBlockTime(realTime) * outputAvailablePerSecond) / 1024.0);
  }

  /**
   * Should the request be rejected due to bandwidth liability? Enforces fair sharing between peers,
   * while allowing peers to opportunistically use a bit more than their fair share as long as the
   * total is below the lower limit. Used for both bandwidth-based limiting and transfer-count-based
   * limiting.
   *
   * @param bandwidthAvailableOutputUpperLimit The overall upper limit, already calculated.
   * @param requestsSnapshot The requests running.
   * @param peerRequestsSnapshot The requests running to this one peer.
   * @param input True if this is input bandwidth, false if it is output bandwidth.
   * @param context Admission context containing source and mode flags.
   * @return A string explaining why, or null if we can accept the request.
   */
  private String checkBandwidthLiability(
      double bandwidthAvailableOutputUpperLimit,
      RunningRequestsSnapshot requestsSnapshot,
      RunningRequestsSnapshot peerRequestsSnapshot,
      boolean input,
      RequestAdmissionContext context) {
    PeerNode source = context.source();
    String name = input ? "Input" : "Output";
    int peerCount =
        node.network().peers().countConnectedPeers()
            + 2 * node.network().peers().countConnectedDarknetPeers();

    double bandwidthAvailableOutputLowerLimit = getLowerLimit(bandwidthAvailableOutputUpperLimit);

    double bandwidthLiabilityOutput =
        requestsSnapshot.calculate(ignoreLocalVsRemoteBandwidthLiability, input);

    // Calculate the peer limit so the peer gets notified, even if we are going to ignore it.

    double thisAllocation =
        getPeerLimit(
            source,
            bandwidthAvailableOutputUpperLimit - bandwidthAvailableOutputLowerLimit,
            peerCount,
            peerRequestsSnapshot.calculateSR(ignoreLocalVsRemoteBandwidthLiability, input));

    // Ignore the upper limit.
    // Because we reassignToSelf() in various tricky timeout conditions, it is possible to exceed
    // it.
    // Even if we do, we still need to allow the guaranteed allocation for each peer.
    // Except when we do that, we have to offer it via ULPRs afterward ...
    //  Yes, but the GetOfferedKey's are subject to load management, so no problem.
    if (bandwidthLiabilityOutput > bandwidthAvailableOutputUpperLimit) {
      LOG.warn(
          "Usage over upper limit {} (usage={}); allow due to reassignment edge cases",
          bandwidthAvailableOutputUpperLimit,
          bandwidthLiabilityOutput);
    }

    if (bandwidthLiabilityOutput > bandwidthAvailableOutputLowerLimit) {

      // Bandwidth is scarce (we are over the lower limit i.e., more than half our capacity is
      // used).
      // Share available bandwidth fairly between peers.

      if (LOG.isDebugEnabled())
        LOG.debug(
            "Allocation ({}) for {} is {}; usage {} vs lower {}; upper {} for {}",
            name,
            source,
            thisAllocation,
            bandwidthLiabilityOutput,
            bandwidthAvailableOutputLowerLimit,
            bandwidthAvailableOutputUpperLimit,
            name);

      double peerUsedBytes = getPeerBandwidthLiability(peerRequestsSnapshot, input);
      if (peerUsedBytes > thisAllocation) {
        rejected(name + " bandwidth liability: fairness between peers", context);
        return name
            + " bandwidth liability: fairness between peers (peer "
            + source
            + " used "
            + peerUsedBytes
            + " allowed "
            + thisAllocation
            + ")";
      }

    } else {

      // Plenty of bandwidth available, allow one peer to use up to the lower limit (about half the
      // total).

      if (LOG.isDebugEnabled())
        LOG.debug(
            "Usage {} below lower {} for {}",
            bandwidthLiabilityOutput,
            bandwidthAvailableOutputLowerLimit,
            name);
    }
    return null;
  }

  private String checkMaxOutputTransfers(
      TransferLimits transferLimits,
      RunningRequestsSnapshot requestsSnapshot,
      RunningRequestsSnapshot peerRequestsSnapshot,
      RequestAdmissionContext context) {
    int maxOutputTransfers = transferLimits.maxOutputTransfers();
    int maxTransfersOutUpperLimit = transferLimits.maxTransfersOutUpperLimit();
    int maxTransfersOutLowerLimit = transferLimits.maxTransfersOutLowerLimit();
    int maxTransfersOutPeerLimit = transferLimits.maxTransfersOutPeerLimit();
    boolean isLocal = context.isLocal();
    boolean realTime = context.realTimeFlag();
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Max transfers: congestion control limit {} upper {} lower {} peer {} {}",
          maxOutputTransfers,
          maxTransfersOutUpperLimit,
          maxTransfersOutLowerLimit,
          maxTransfersOutPeerLimit,
          realTime ? "(rt)" : "(bulk)");
    int peerOutTransfers = peerRequestsSnapshot.totalOutTransfers();
    int totalOutTransfers = requestsSnapshot.totalOutTransfers();
    if (peerOutTransfers > maxOutputTransfers && !isLocal) {
      // Can't handle that many transfers with current bandwidth.
      rejected("TooManyTransfers: Congestion control", context);
      return "TooManyTransfers: Congestion control";
    }
    if (totalOutTransfers <= maxTransfersOutLowerLimit) {
      // If the total is below the lower limit, then fine, go for it.
      // We have plenty of spare bandwidth.
      return null;
    }
    if (peerOutTransfers <= maxTransfersOutPeerLimit) {
      // The total is above the lower limit, but the per-peer is below the peer limit.
      // It is within its guaranteed space, so we accept it.
      return null;
    }
    rejected("TooManyTransfers: Fair sharing between peers", context);
    return "TooManyTransfers: Fair sharing between peers";
  }

  /**
   * Computes the per-peer bandwidth share for fair allocation.
   *
   * @param source The peer for which the allocation is computed; {@code null} when computing the
   *     local share.
   * @param totalGuaranteedBandwidth The difference between the upper and lower overall bandwidth
   *     limits. If the total usage is less than the lower limit, we do not enforce fairness. Any
   *     node may therefore optimistically try to use up to the lower limit. However, the node is
   *     only guaranteed its fair share, which is defined as its fraction of the part of the total
   *     that is above the lower limit.
   * @param peers Number of peers among which the non-local share is divided.
   * @param sourceRestarted A small penalty to subtract for recently restarted peers (in bandwidth
   *     units); {@code 0} when not applicable.
   * @return The computed bandwidth share for the given peer.
   */
  private double getPeerLimit(
      PeerNode source, double totalGuaranteedBandwidth, int peers, double sourceRestarted) {

    double thisAllocation;
    double totalAllocation = totalGuaranteedBandwidth;
    // Could be made configurable and security-level dependent
    double localAllocation = totalAllocation * 0.5;
    if (source == null) thisAllocation = localAllocation;
    else {
      totalAllocation -= localAllocation;
      thisAllocation = totalAllocation / peers;
      if (source instanceof DarknetPeerNode) {
        thisAllocation *= 3;
      }
    }

    if (LOG.isDebugEnabled() && sourceRestarted != 0)
      LOG.debug("Allocation {} sourceRestarted={}", thisAllocation, sourceRestarted);
    return thisAllocation - sourceRestarted;
  }

  /**
   * Calculate the worst-case bytes used by a specific peer. This will be compared to its peer
   * limit, and if it is higher, the request may be rejected.
   *
   * @param requestsSnapshot Snapshot of requests running from the peer.
   * @param input If {@code true}, calculate input bytes; otherwise, calculate output bytes.
   * @return The peer's bandwidth liability in bytes for the chosen direction.
   */
  private double getPeerBandwidthLiability(
      RunningRequestsSnapshot requestsSnapshot, boolean input) {
    return requestsSnapshot.calculate(ignoreLocalVsRemoteBandwidthLiability, input);
  }

  /**
   * @return True if we should reject the request.
   * @param x The threshold. We should reject the request unless a random number is greater than
   *     this threshold.
   * @param preferInsert If true, we allow 3 chances to pass the threshold.
   */
  private boolean randomLessThan(double x, boolean preferInsert) {
    if (preferInsert) {
      // Three chances.
      for (int i = 0; i < 3; i++) if (node.bootstrap().random().nextDouble() >= x) return false;
      return true;
    }
    return node.bootstrap().random().nextDouble() < x;
  }

  private void rejected(String reason, RequestAdmissionContext context) {
    boolean isLocal = context.isLocal();
    boolean isSSK = context.isSSK();
    boolean isInsert = context.isInsert();
    boolean isOfferReply = context.isOfferReply();
    boolean isRealTime = context.realTimeFlag();
    reason += " " + (isRealTime ? " (rt)" : " (bulk)");
    if (LOG.isDebugEnabled())
      LOG.debug("Rejecting (local={}) isSSK={} isInsert={} : {}", isLocal, isSSK, isInsert, reason);
    if (!isLocal) incrementRejectReason(preemptiveRejectReasons, reason);
    else incrementRejectReason(localPreemptiveRejectReasons, reason);
    if (!isLocal && !isOfferReply) {
      this.pInstantRejectIncomingOverall.report(1.0);
      getRejectedTracker(context).report(1.0);
    }
  }

  private static void incrementRejectReason(Map<String, Integer> target, String reason) {
    target.merge(reason, 1, Integer::sum);
  }

  private void accepted(RequestAdmissionContext context) {
    if (!context.isLocal() && !context.isOfferReply()) {
      pInstantRejectIncomingOverall.report(0.0);
      getRejectedTracker(context).report(0.0);
    }
  }

  private BootstrappingDecayingRunningAverage getRejectedTracker(RequestAdmissionContext context) {
    boolean isRealTime = context.realTimeFlag();
    boolean isSSK = context.isSSK();
    boolean isInsert = context.isInsert();
    if (isRealTime) {
      if (isSSK) {
        return isInsert ? pInstantRejectIncomingSSKInsertRT : pInstantRejectIncomingSSKRequestRT;
      }
      return isInsert ? pInstantRejectIncomingCHKInsertRT : pInstantRejectIncomingCHKRequestRT;
    }
    if (isSSK) {
      return isInsert ? pInstantRejectIncomingSSKInsertBulk : pInstantRejectIncomingSSKRequestBulk;
    }
    return isInsert ? pInstantRejectIncomingCHKInsertBulk : pInstantRejectIncomingCHKRequestBulk;
  }

  private void dumpByteCostAverages() {
    LOG.debug(
        "Byte cost averages: REMOTE:"
            + TEXT_CHK_INSERT
            + PAIR_FMT
            + TEXT_SSK_INSERT
            + PAIR_FMT
            + TEXT_CHK_FETCH
            + PAIR_FMT
            + TEXT_SSK_FETCH
            + PAIR_FMT,
        remoteChkInsertBytesSentAverage.currentValue(),
        remoteChkInsertBytesReceivedAverage.currentValue(),
        remoteSskInsertBytesSentAverage.currentValue(),
        remoteSskInsertBytesReceivedAverage.currentValue(),
        remoteChkFetchBytesSentAverage.currentValue(),
        remoteChkFetchBytesReceivedAverage.currentValue(),
        remoteSskFetchBytesSentAverage.currentValue(),
        remoteSskFetchBytesReceivedAverage.currentValue());
    LOG.debug(
        "Byte cost averages: LOCAL:"
            + TEXT_CHK_INSERT
            + PAIR_FMT
            + TEXT_SSK_INSERT
            + PAIR_FMT
            + TEXT_CHK_FETCH
            + PAIR_FMT
            + TEXT_SSK_FETCH
            + PAIR_FMT,
        localChkInsertBytesSentAverage.currentValue(),
        localChkInsertBytesReceivedAverage.currentValue(),
        localSskInsertBytesSentAverage.currentValue(),
        localSskInsertBytesReceivedAverage.currentValue(),
        localChkFetchBytesSentAverage.currentValue(),
        localChkFetchBytesReceivedAverage.currentValue(),
        localSskFetchBytesSentAverage.currentValue(),
        localSskFetchBytesReceivedAverage.currentValue());
    LOG.debug(
        "Byte cost averages: SUCCESSFUL:"
            + TEXT_CHK_INSERT
            + PAIR_FMT
            + TEXT_SSK_INSERT
            + PAIR_FMT
            + TEXT_CHK_FETCH
            + PAIR_FMT
            + TEXT_SSK_FETCH
            + PAIR_FMT
            + " CHK offer reply "
            + PAIR_FMT
            + " SSK offer reply "
            + PAIR_FMT,
        successfulChkInsertBytesSentAverage.currentValue(),
        successfulChkInsertBytesReceivedAverage.currentValue(),
        successfulSskInsertBytesSentAverage.currentValue(),
        successfulSskInsertBytesReceivedAverage.currentValue(),
        successfulChkFetchBytesSentAverage.currentValue(),
        successfulChkFetchBytesReceivedAverage.currentValue(),
        successfulSskFetchBytesSentAverage.currentValue(),
        successfulSskFetchBytesReceivedAverage.currentValue(),
        successfulChkOfferReplyBytesSentAverage.currentValue(),
        successfulChkOfferReplyBytesReceivedAverage.currentValue(),
        successfulSskOfferReplyBytesSentAverage.currentValue(),
        successfulSskOfferReplyBytesReceivedAverage.currentValue());
  }

  /**
   * Returns the decaying average throttling delay for realtime packet sends.
   *
   * <p>The value represents the delay introduced by bandwidth throttling, measured in milliseconds.
   * It is derived from {@link #blockTime(long, boolean)} reports and reflects recent behavior
   * rather than a lifetime mean. It does not include additional scheduling or queueing time outside
   * the throttle.
   *
   * @return average realtime throttling delay in milliseconds.
   */
  public double getBwlimitDelayTimeRT() {
    return throttledPacketSendAverageRT.currentValue();
  }

  /**
   * Returns the decaying average throttling delay for bulk packet sends.
   *
   * <p>The value is measured in milliseconds and reflects recent bulk-channel behavior as reported
   * by {@link #blockTime(long, boolean)}. It is a throttling-only signal used by alerting and
   * admission logic, not a full end-to-end latency metric.
   *
   * @return average bulk throttling delay in milliseconds.
   */
  public double getBwlimitDelayTimeBulk() {
    return throttledPacketSendAverageBulk.currentValue();
  }

  /**
   * Returns the decaying average throttling delay across all packet sending.
   *
   * <p>This aggregate includes both realtime and bulk observations and is used by alerting logic
   * that does not distinguish channels. Values are in milliseconds and represent the throttle delay
   * only.
   *
   * @return average throttling delay across all channels in milliseconds.
   */
  public double getBwlimitDelayTime() {
    return throttledPacketSendAverage.currentValue();
  }

  /**
   * Returns the node-wide average ping time reported by the {@link NodePinger}.
   *
   * <p>The result is used for overload and alerting decisions and represents a recent average, not
   * an instantaneous sample. The time unit is milliseconds.
   *
   * @return average ping time in milliseconds.
   */
  public double getNodeAveragePingTime() {
    return nodePinger.averagePingTime();
  }

  /**
   * Returns the estimated opennet size at or before the given time.
   *
   * @param timestamp cutoff time in milliseconds since epoch; pass {@code -1} for the current
   *     session estimate.
   * @return estimated number of nodes, or {@code 0} if opennet is disabled.
   */
  public int getOpennetSizeEstimate(long timestamp) {
    if (node.network().opennet() == null) return 0;
    return node.network().opennet().getNetworkSizeEstimate(timestamp);
  }

  /**
   * Returns the estimated darknet size at or before the given time.
   *
   * @param timestamp cutoff time in milliseconds since epoch; pass {@code -1} for the current
   *     session estimate.
   * @return estimated number of peers.
   */
  public int getDarknetSizeEstimate(long timestamp) {
    return node.network().locationManager().getNetworkSizeEstimate(timestamp);
  }

  /**
   * Returns known peer locations for diagnostics at or before {@code timestamp}.
   *
   * @param timestamp cutoff time in milliseconds since epoch; pass {@code -1} for all cached
   *     entries.
   * @return array of serialized location entries; never {@code null}.
   */
  public Object[] getKnownLocations(long timestamp) {
    return node.network().locationManager().getKnownLocations(timestamp);
  }

  /**
   * Probability that an incoming request is immediately rejected (overall).
   *
   * @return the current instantaneous rejection probability across all traffic.
   */
  public double pRejectIncomingInstantly() {
    return pInstantRejectIncomingOverall.currentValue();
  }

  /**
   * Probability of instant rejection for realtime CHK requests.
   *
   * @return the current instantaneous rejection probability for realtime CHK requests.
   */
  public double pRejectIncomingInstantlyCHKRequestRT() {
    return pInstantRejectIncomingCHKRequestRT.currentValue();
  }

  /**
   * Probability of instant rejection for realtime CHK inserts.
   *
   * @return the current instantaneous rejection probability for realtime CHK inserts.
   */
  public double pRejectIncomingInstantlyCHKInsertRT() {
    return pInstantRejectIncomingCHKInsertRT.currentValue();
  }

  /**
   * Probability of instant rejection for realtime SSK requests.
   *
   * @return the current instantaneous rejection probability for realtime SSK requests.
   */
  public double pRejectIncomingInstantlySSKRequestRT() {
    return pInstantRejectIncomingSSKRequestRT.currentValue();
  }

  /**
   * Probability of instant rejection for realtime SSK inserts.
   *
   * @return the current instantaneous rejection probability for realtime SSK inserts.
   */
  public double pRejectIncomingInstantlySSKInsertRT() {
    return pInstantRejectIncomingSSKInsertRT.currentValue();
  }

  /**
   * Probability of instant rejection for bulk CHK requests.
   *
   * @return the current instantaneous rejection probability for bulk CHK requests.
   */
  public double pRejectIncomingInstantlyCHKRequestBulk() {
    return pInstantRejectIncomingCHKRequestBulk.currentValue();
  }

  /**
   * Probability of instant rejection for bulk CHK inserts.
   *
   * @return the current instantaneous rejection probability for bulk CHK inserts.
   */
  public double pRejectIncomingInstantlyCHKInsertBulk() {
    return pInstantRejectIncomingCHKInsertBulk.currentValue();
  }

  /**
   * Probability of instant rejection for bulk SSK requests.
   *
   * @return the current instantaneous rejection probability for bulk SSK requests.
   */
  public double pRejectIncomingInstantlySSKRequestBulk() {
    return pInstantRejectIncomingSSKRequestBulk.currentValue();
  }

  /**
   * Probability of instant rejection for bulk SSK inserts.
   *
   * @return the current instantaneous rejection probability for bulk SSK inserts.
   */
  public double pRejectIncomingInstantlySSKInsertBulk() {
    return pInstantRejectIncomingSSKInsertBulk.currentValue();
  }

  /**
   * Updates alert-related stats when the refresh interval elapses.
   *
   * <p>Inputs: {@code now} is the current wall clock in milliseconds. This method evaluates the
   * throttling delay and average ping against configured thresholds with a grace period to reduce
   * flapping.
   *
   * <p>Threading: called from packet-sender context; internal fields are plain {@code long}s and
   * booleans updated atomically.
   *
   * @param now current wall-clock time in milliseconds.
   */
  public void maybeUpdatePeerManagerUserAlertStats(long now) {
    if (now > nextPeerManagerUserAlertStatsUpdateTime) {
      updateBwlimitDelayAlert(now);
      updateNodeAveragePingAlert(now);
      if (LOG.isDebugEnabled())
        LOG.debug(
            "UserAlert update at {}: bwDelay {} >? {} since {} (relevant={}) avgPing {} >? {} since"
                + " {} (relevant={})",
            now,
            getBwlimitDelayTime(),
            MAX_BWLIMIT_DELAY_TIME_ALERT_THRESHOLD,
            firstBwlimitDelayTimeThresholdBreak,
            bwlimitDelayAlertRelevant,
            getNodeAveragePingTime(),
            MAX_NODE_AVERAGE_PING_TIME_ALERT_THRESHOLD,
            firstNodeAveragePingTimeThresholdBreak,
            nodeAveragePingAlertRelevant);
      nextPeerManagerUserAlertStatsUpdateTime = now + PEER_MANAGER_USER_ALERT_STATS_UPDATE_INTERVAL;
    }
  }

  private void updateBwlimitDelayAlert(long now) {
    if (getBwlimitDelayTime() > MAX_BWLIMIT_DELAY_TIME_ALERT_THRESHOLD) {
      if (firstBwlimitDelayTimeThresholdBreak == 0) {
        firstBwlimitDelayTimeThresholdBreak = now;
      }
    } else {
      firstBwlimitDelayTimeThresholdBreak = 0;
    }
    bwlimitDelayAlertRelevant =
        (firstBwlimitDelayTimeThresholdBreak != 0)
            && ((now - firstBwlimitDelayTimeThresholdBreak) >= MAX_BWLIMIT_DELAY_TIME_ALERT_DELAY);
  }

  private void updateNodeAveragePingAlert(long now) {
    if (getNodeAveragePingTime() > 2 * maxPingTime) {
      if (firstNodeAveragePingTimeThresholdBreak == 0) {
        firstNodeAveragePingTimeThresholdBreak = now;
      }
    } else {
      firstNodeAveragePingTimeThresholdBreak = 0;
    }
    nodeAveragePingAlertRelevant =
        (firstNodeAveragePingTimeThresholdBreak != 0)
            && ((now - firstNodeAveragePingTimeThresholdBreak)
                >= MAX_NODE_AVERAGE_PING_TIME_ALERT_DELAY);
  }

  /**
   * Persists throttle- and success-related decaying averages to a field set.
   *
   * <p>Outputs include local/remote byte costs for CHK/SSK fetch/insert, successful transfer byte
   * costs, and average store/cache locations and successes. Values are decayed running averages and
   * therefore represent recent behavior rather than lifetime totals.
   *
   * @return a {@link SimpleFieldSet} containing the persisted averages; never {@code null}.
   */
  @Override
  public SimpleFieldSet persistThrottlesToFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.put("RemoteChkFetchBytesSentAverage", remoteChkFetchBytesSentAverage.exportFieldSet(true));
    fs.put("RemoteSskFetchBytesSentAverage", remoteSskFetchBytesSentAverage.exportFieldSet(true));
    fs.put("RemoteChkInsertBytesSentAverage", remoteChkInsertBytesSentAverage.exportFieldSet(true));
    fs.put("RemoteSskInsertBytesSentAverage", remoteSskInsertBytesSentAverage.exportFieldSet(true));
    fs.put(
        "RemoteChkFetchBytesReceivedAverage",
        remoteChkFetchBytesReceivedAverage.exportFieldSet(true));
    fs.put(
        "RemoteSskFetchBytesReceivedAverage",
        remoteSskFetchBytesReceivedAverage.exportFieldSet(true));
    fs.put(
        "RemoteChkInsertBytesReceivedAverage",
        remoteChkInsertBytesReceivedAverage.exportFieldSet(true));
    fs.put(
        "RemoteSskInsertBytesReceivedAverage",
        remoteSskInsertBytesReceivedAverage.exportFieldSet(true));
    fs.put("LocalChkFetchBytesSentAverage", localChkFetchBytesSentAverage.exportFieldSet(true));
    fs.put("LocalSskFetchBytesSentAverage", localSskFetchBytesSentAverage.exportFieldSet(true));
    fs.put("LocalChkInsertBytesSentAverage", localChkInsertBytesSentAverage.exportFieldSet(true));
    fs.put("LocalSskInsertBytesSentAverage", localSskInsertBytesSentAverage.exportFieldSet(true));
    fs.put(
        "LocalChkFetchBytesReceivedAverage",
        localChkFetchBytesReceivedAverage.exportFieldSet(true));
    fs.put(
        "LocalSskFetchBytesReceivedAverage",
        localSskFetchBytesReceivedAverage.exportFieldSet(true));
    fs.put(
        L_CHK_INSERT_BYTES_RECEIVED_AVG, localChkInsertBytesReceivedAverage.exportFieldSet(true));
    fs.put(
        "LocalSskInsertBytesReceivedAverage",
        localSskInsertBytesReceivedAverage.exportFieldSet(true));
    fs.put(
        "SuccessfulChkFetchBytesSentAverage",
        successfulChkFetchBytesSentAverage.exportFieldSet(true));
    fs.put(
        "SuccessfulSskFetchBytesSentAverage",
        successfulSskFetchBytesSentAverage.exportFieldSet(true));
    fs.put(
        "SuccessfulChkInsertBytesSentAverage",
        successfulChkInsertBytesSentAverage.exportFieldSet(true));
    fs.put(
        "SuccessfulSskInsertBytesSentAverage",
        successfulSskInsertBytesSentAverage.exportFieldSet(true));
    fs.put(
        "SuccessfulChkOfferReplyBytesSentAverage",
        successfulChkOfferReplyBytesSentAverage.exportFieldSet(true));
    fs.put(
        "SuccessfulSskOfferReplyBytesSentAverage",
        successfulSskOfferReplyBytesSentAverage.exportFieldSet(true));
    fs.put(
        "SuccessfulChkFetchBytesReceivedAverage",
        successfulChkFetchBytesReceivedAverage.exportFieldSet(true));
    fs.put(
        "SuccessfulSskFetchBytesReceivedAverage",
        successfulSskFetchBytesReceivedAverage.exportFieldSet(true));
    fs.put(
        "SuccessfulChkInsertBytesReceivedAverage",
        successfulChkInsertBytesReceivedAverage.exportFieldSet(true));
    fs.put(
        "SuccessfulSskInsertBytesReceivedAverage",
        successfulSskInsertBytesReceivedAverage.exportFieldSet(true));
    fs.put(
        "SuccessfulChkOfferReplyBytesReceivedAverage",
        successfulChkOfferReplyBytesReceivedAverage.exportFieldSet(true));
    fs.put(
        "SuccessfulSskOfferReplyBytesReceivedAverage",
        successfulSskOfferReplyBytesReceivedAverage.exportFieldSet(true));

    // These are not really part of the 'throttling' data, but are also running averages which
    // should be persisted
    fs.put("AverageCacheCHKLocation", avgCacheCHKLocation.exportFieldSet(true));
    fs.put("AverageStoreCHKLocation", avgStoreCHKLocation.exportFieldSet(true));
    fs.put("AverageSlashdotCacheCHKLocation", avgSlashdotCacheCHKLocation.exportFieldSet(true));
    fs.put("AverageClientCacheCHKLocation", avgClientCacheCHKLocation.exportFieldSet(true));

    fs.put("AverageCacheCHKSuccessLocation", avgCacheCHKSuccess.exportFieldSet(true));
    fs.put(
        "AverageSlashdotCacheCHKSuccessLocation", avgSlashdotCacheCHKSucess.exportFieldSet(true));
    fs.put("AverageClientCacheCHKSuccessLocation", avgClientCacheCHKSuccess.exportFieldSet(true));
    fs.put("AverageStoreCHKSuccessLocation", avgStoreCHKSuccess.exportFieldSet(true));

    fs.put("AverageCacheSSKLocation", avgCacheSSKLocation.exportFieldSet(true));
    fs.put("AverageStoreSSKLocation", avgStoreSSKLocation.exportFieldSet(true));
    fs.put("AverageSlashdotCacheSSKLocation", avgSlashdotCacheSSKLocation.exportFieldSet(true));
    fs.put("AverageClientCacheSSKLocation", avgClientCacheSSKLocation.exportFieldSet(true));

    fs.put("AverageCacheSSKSuccessLocation", avgCacheSSKSuccess.exportFieldSet(true));
    fs.put(
        "AverageSlashdotCacheSSKSuccessLocation", avgSlashdotCacheSSKSuccess.exportFieldSet(true));
    fs.put("AverageClientCacheSSKSuccessLocation", avgClientCacheSSKSuccess.exportFieldSet(true));
    fs.put("AverageStoreSSKSuccessLocation", avgStoreSSKSuccess.exportFieldSet(true));

    fs.put("AverageRequestLocation", avgRequestLocation.exportFieldSet(true));

    return fs;
  }

  /**
   * Updates node-wide input/output deltas when the refresh timer expires.
   *
   * @param now current wall-clock time in milliseconds.
   */
  public void maybeUpdateNodeIOStats(long now) {
    if (now > nextNodeIOStatsUpdateTime) {
      long[] ioStats = node.network().collector().getTotalIO();
      long outdiff;
      long indiff;
      synchronized (ioStatSync) {
        previousOutputStat = lastOutputStat;
        previousInputStat = lastInputStat;
        previousIoStatTime = lastIoStatTime;
        lastOutputStat = ioStats[0];
        lastInputStat = ioStats[1];
        lastIoStatTime = now;
        outdiff = lastOutputStat - previousOutputStat;
        indiff = lastInputStat - previousInputStat;
      }
      if (LOG.isDebugEnabled()) LOG.debug("I/O over last 2 s: input={} output={}", indiff, outdiff);
      nextNodeIOStatsUpdateTime = now + NODE_IO_STATS_UPDATE_INTERVAL;
    }
  }

  /**
   * Returns the last two cumulative I/O samples and their timestamps.
   *
   * <p>Layout: {@code [prevOut, prevIn, prevTs, lastOut, lastIn, lastTs]}.
   *
   * @return six-element array with previous and current I/O counters and times.
   */
  public long[] getNodeIOStats() {
    long[] result = new long[6];
    synchronized (ioStatSync) {
      result[0] = previousOutputStat;
      result[1] = previousInputStat;
      result[2] = previousIoStatTime;
      result[3] = lastOutputStat;
      result[4] = lastInputStat;
      result[5] = lastIoStatTime;
    }
    return result;
  }

  /**
   * Blocks the caller until the node is no longer considered overloaded.
   *
   * <p>This method waits while the approximate active-thread count exceeds {@link
   * #getThreadLimit()} and wakes periodically to re-check, even if no notification arrives. It is
   * safe to call from worker threads that need backpressure. If interrupted, it restores the
   * interrupt flag and returns immediately.
   */
  public void waitUntilNotOverloaded() {
    // Wait with timeout so callers re-check periodically even if no signals arrive.
    synchronized (overloadSync) {
      while (threadLimit < getActiveThreadCount()) {
        try {
          overloadSync.wait(5000L);
        } catch (InterruptedException _) {
          // Preserve interrupt status and return to the caller.
          Thread.currentThread().interrupt();
          return;
        }
      }
    }
  }

  /**
   * Approximates the number of "active" threads for overload protection.
   *
   * <p>This method returns a process-wide estimate that includes non-executor threads (I/O, peer
   * connections, JVM helpers, etc.) so the {@code threadLimit} guard reflects real resource usage.
   * It uses the JVM's live thread count and subtracts idle worker threads from the node's executor.
   * As a safety floor, it is always at least the executor's currently running workers.
   *
   * <p>Implementation details: - Live thread count is read via {@code
   * ThreadMXBean.getThreadCount()} (O(1), lightweight). - Idle worker estimate prefers {@link
   * PriorityAwareExecutor#getWaitingThreadsCount()} and falls back to summing {@link
   * PriorityAwareExecutor#waitingThreads()}. - Running worker floor is computed from {@link
   * PriorityAwareExecutor#runningThreads()}.
   *
   * <p>Notes: - The result is an approximation and may lag actual changes due to races and platform
   * nuances. - We intentionally do not walk the entire thread list on the hot path.
   *
   * @return an approximate count of active threads used for overload decisions.
   */
  @SuppressWarnings("java:S1181")
  public int getActiveThreadCount() {
    final PriorityAwareExecutor exec = node.network().executor();

    // Executor running threads (floor)
    int runningWorkers = 0;
    try {
      int[] running = exec.runningThreads();
      for (int v : running) runningWorkers += v;
    } catch (Throwable _) {
      // Keep the floor at 0 if introspection is unavailable.
    }

    // Idle workers to subtract from process-wide live threads
    int idleWorkers = 0;
    try {
      idleWorkers = Math.max(exec.getWaitingThreadsCount(), 0);
    } catch (Throwable _) {
      try {
        int[] waiting = exec.waitingThreads();
        for (int v : waiting) idleWorkers += v;
      } catch (Throwable _) {
        // Leave at 0 if we cannot determine idle workers.
      }
    }

    // Process-wide live threads (includes daemons and non-executor threads)
    int live;
    try {
      live = java.lang.management.ManagementFactory.getThreadMXBean().getThreadCount();
    } catch (Throwable _) {
      // If MXBean is unavailable (very unlikely), fall back to the executor floor.
      return Math.max(runningWorkers, 0);
    }

    // Approximate "active" threads: live minus idle executor workers, floored at running workers.
    int approx = live - idleWorkers;
    if (approx < runningWorkers) approx = runningWorkers;
    if (approx > live) approx = live; // Bound to a sane range in case of races.
    return Math.max(approx, 0);
  }

  /**
   * Returns counts of actively running executor threads per priority bucket.
   *
   * @return array of counts indexed by scheduler priority; never {@code null}.
   */
  public int[] getActiveThreadsByPriority() {
    return node.network().executor().runningThreads();
  }

  /**
   * Returns counts of executor threads currently waiting for work per priority bucket.
   *
   * @return array of counts indexed by scheduler priority; never {@code null}.
   */
  public int[] getWaitingThreadsByPriority() {
    return node.network().executor().waitingThreads();
  }

  /**
   * Maximum allowed active thread estimate used for overload protection.
   *
   * @return the configured soft limit for active threads.
   */
  public int getThreadLimit() {
    return threadLimit;
  }

  void updateThreadLimit(int val) {
    synchronized (overloadSync) {
      threadLimit = val;
      overloadSync.notifyAll();
    }
  }

  boolean getIgnoreLocalVsRemoteBandwidthLiability() {
    synchronized (this) {
      return ignoreLocalVsRemoteBandwidthLiability;
    }
  }

  void setIgnoreLocalVsRemoteBandwidthLiability(boolean val) {
    synchronized (this) {
      ignoreLocalVsRemoteBandwidthLiability = val;
    }
  }

  long getMaxPingTime() {
    return maxPingTime;
  }

  void setMaxPingTime(long val) {
    maxPingTime = val;
  }

  long getSubMaxPingTime() {
    return subMaxPingTime;
  }

  void setSubMaxPingTime(long val) {
    subMaxPingTime = val;
  }

  /**
   * Gets a copy of the thread list by enumerating from the root {@link ThreadGroup}.
   *
   * <p>Why not {@code ThreadPoolExecutor}? Diagnostics need to list all JVM threads (GC, JIT,
   * third‑party pools, custom executors like {@code network.crypta.support.PooledExecutor}, and
   * various helpers), not only the workers owned by a single pool. Using the root {@link
   * ThreadGroup} provides a lightweight, VM‑wide enumeration without forcing stack capture.
   *
   * <p>This avoids the significant overhead of {@link Thread#getAllStackTraces()}, which collects a
   * full stack trace array for every live thread. The returned array is null-terminated to match
   * the historical contract: the end of the list is marked by a null entry.
   *
   * @return an array of threads followed by a trailing {@code null} element.
   */
  @SuppressWarnings(
      "java:S3014") // Intentional ThreadGroup use for inexpensive, VM‑wide enumeration
  public Thread[] getThreads() {
    // Find the root ThreadGroup.
    ThreadGroup group = Thread.currentThread().getThreadGroup();
    while (group != null && group.getParent() != null) group = group.getParent();

    // activeCount() is an estimate; oversize and retry if needed.
    int nAlloc = (group != null) ? group.activeCount() : Thread.activeCount();
    int n = nAlloc + (nAlloc / 2) + 16; // cushion for races
    Thread[] scratch;
    int count;
    do {
      scratch = new Thread[Math.max(n, 32)];
      count = (group != null) ? group.enumerate(scratch, true) : Thread.enumerate(scratch);
      if (count >= scratch.length) n = scratch.length * 2; // expand and retry
    } while (count >= scratch.length);

    Thread[] result = new Thread[count + 1];
    System.arraycopy(scratch, 0, result, 0, count);
    // Last element remains null by construction.
    return result;
  }

  /**
   * Exports a volatile snapshot of node statistics for UI and remote reporting.
   *
   * <p>The returned {@link SimpleFieldSet} captures dynamic, non-persisted values such as bandwidth
   * counters and current averages. The snapshot is a point-in-time view and may lag concurrent
   * updates by a small amount.
   *
   * @return a field set containing volatile statistics; never {@code null}.
   */
  public SimpleFieldSet exportVolatileFieldSet() {
    return NodeStatsFieldSetExporter.exportVolatileFieldSet(this);
  }

  /**
   * True when the throttled-packet delay has exceeded the alert threshold long enough to trigger.
   *
   * @return whether the bandwidth-delay alert condition is currently relevant.
   */
  public boolean isBwlimitDelayAlertRelevant() {
    return bwlimitDelayAlertRelevant;
  }

  /**
   * True, when average node ping has exceeded the alert threshold long enough to trigger.
   *
   * @return whether the average-ping alert condition is currently relevant.
   */
  public boolean isNodeAveragePingAlertRelevant() {
    return nodeAveragePingAlertRelevant;
  }

  private static SimpleFieldSet subset(SimpleFieldSet fs, String key) {
    return fs == null ? null : fs.subset(key);
  }

  private static DecayingKeyspaceAverage dka(double nodeLoc, String key, SimpleFieldSet sfs) {
    return new DecayingKeyspaceAverage(nodeLoc, 10000, subset(sfs, key));
  }

  /**
   * True when the node runs with testnet configuration.
   *
   * @return whether testnet mode is enabled.
   */
  @SuppressWarnings("unused")
  public boolean isTestnetEnabled() {
    return Node.isTestnetEnabled();
  }

  /**
   * Records the outcome of a completed fetch request for success-rate reporting.
   *
   * @param succeeded {@code true} for success, {@code false} otherwise.
   * @param isRemote {@code true} if the request originated from a remote peer.
   * @param isSSK {@code true} for SSK, {@code false} for CHK.
   */
  public synchronized void requestCompleted(boolean succeeded, boolean isRemote, boolean isSSK) {
    double v = succeeded ? 1.0 : 0.0;
    globalFetchPSuccess.report(v);
    if (isSSK) {
      (isRemote ? sskRemoteFetchPSuccess : sskLocalFetchPSuccess).report(v);
      return;
    }
    (isRemote ? chkRemoteFetchPSuccess : chkLocalFetchPSuccess).report(v);
  }

  /* Total bytes sent by requests and inserts, excluding payload */
  private long chkRequestSentBytes;
  private long sskRequestSentBytes;
  private long chkInsertSentBytes;
  private long sskInsertSentBytes;

  /**
   * Adds to the sent-byte counter for CHK/SSK requests (protocol overhead only).
   *
   * @param ssk {@code true} for SSK, {@code false} for CHK.
   * @param x bytes sent to add.
   */
  public synchronized void requestSentBytes(boolean ssk, int x) {
    if (ssk) sskRequestSentBytes += x;
    else chkRequestSentBytes += x;
  }

  /**
   * Records received bytes for CHK/SSK requests.
   *
   * <p>This implementation currently ignores the values because only sent overhead is tracked for
   * requests. The method is retained for symmetry with sending counters and to keep call sites
   * uniform.
   *
   * @param ssk {@code true} for SSK, {@code false} for CHK.
   * @param x number of bytes received (ignored).
   */
  @SuppressWarnings("unused")
  public synchronized void requestReceivedBytes(boolean ssk, int x) {
    // no-op: received request bytes are not tracked
  }

  /**
   * Adds to the sent-byte counter for CHK/SSK inserts (protocol overhead only).
   *
   * @param ssk {@code true} for SSK, {@code false} for CHK.
   * @param x bytes sent to add.
   */
  public synchronized void insertSentBytes(boolean ssk, int x) {
    if (LOG.isTraceEnabled()) LOG.trace("insertSentBytes({}, {})", ssk, x);
    if (ssk) sskInsertSentBytes += x;
    else chkInsertSentBytes += x;
  }

  /**
   * Records received bytes for CHK/SSK inserts.
   *
   * <p>This implementation currently ignores the values because only sent overhead is tracked for
   * inserts. The method is retained for symmetry with sending counters and to keep call sites
   * uniform.
   *
   * @param ssk {@code true} for SSK, {@code false} for CHK.
   * @param x number of bytes received (ignored).
   */
  @SuppressWarnings("unused")
  public synchronized void insertReceivedBytes(boolean ssk, int x) {
    // no-op: received insert bytes are not tracked
  }

  /**
   * Total sent bytes attributed to CHK requests (overhead only).
   *
   * @return cumulative CHK-request overhead bytes sent.
   */
  public synchronized long getCHKRequestTotalBytesSent() {
    return chkRequestSentBytes;
  }

  /**
   * Total sent bytes attributed to SSK requests (overhead only).
   *
   * @return cumulative SSK-request overhead bytes sent.
   */
  public synchronized long getSSKRequestTotalBytesSent() {
    return sskRequestSentBytes;
  }

  /**
   * Total sent bytes attributed to CHK inserts (overhead only).
   *
   * @return cumulative CHK-insert overhead bytes sent.
   */
  public synchronized long getCHKInsertTotalBytesSent() {
    return chkInsertSentBytes;
  }

  /**
   * Total sent bytes attributed to SSK inserts (overhead only).
   *
   * @return cumulative SSK-insert overhead bytes sent.
   */
  public synchronized long getSSKInsertTotalBytesSent() {
    return sskInsertSentBytes;
  }

  private long offeredKeysSenderRcvdBytes;
  private long offeredKeysSenderSentBytes;

  /**
   * Adds to the received-byte counter for replies to {@code FNPGetOfferedKey}.
   *
   * @param x number of bytes received for the reply.
   */
  public synchronized void offeredKeysSenderReceivedBytes(int x) {
    offeredKeysSenderRcvdBytes += x;
  }

  /**
   * Adds to the sent-byte counter for replies to {@code FNPGetOfferedKey}.
   *
   * @param x number of bytes sent for the reply.
   */
  public synchronized void offeredKeysSenderSentBytes(int x) {
    offeredKeysSenderSentBytes += x;
  }

  /**
   * Total received bytes for offered-key replies.
   *
   * @return cumulative bytes received for offered-key replies.
   */
  @SuppressWarnings("unused")
  public long getOfferedKeysTotalBytesReceived() {
    return offeredKeysSenderRcvdBytes;
  }

  /**
   * Total sent bytes for offered-key replies.
   *
   * @return cumulative bytes sent for offered-key replies.
   */
  public long getOfferedKeysTotalBytesSent() {
    return offeredKeysSenderSentBytes;
  }

  private long offerKeysSentBytes;

  ByteCounter sendOffersCtr =
      new ByteCounter() {

        @Override
        public void receivedBytes(int x) {
          // Intentionally empty: we do not track received bytes for offers
        }

        @Override
        public void sentBytes(int x) {
          synchronized (NodeStats.this) {
            offerKeysSentBytes += x;
          }
        }

        @Override
        public void sentPayload(int x) {
          // Ignore
        }
      };

  /**
   * Returns total bytes sent for offered-key replies.
   *
   * <p>This counter tracks protocol overhead for {@code FNPGetOfferedKey} responses and is
   * cumulative since process start. It does not include payload bytes recorded elsewhere.
   *
   * @return cumulative offered-key reply bytes sent.
   */
  public synchronized long getOffersSentBytesSent() {
    return offerKeysSentBytes;
  }

  private long swappingRcvdBytes;
  private long swappingSentBytes;

  /**
   * Records bytes received for key swapping traffic.
   *
   * <p>This method updates a cumulative counter used for overhead reporting. The value is measured
   * in bytes and is expected to be called on the networking hot path.
   *
   * @param x bytes received for swap messages.
   */
  public synchronized void swappingReceivedBytes(int x) {
    swappingRcvdBytes += x;
  }

  /**
   * Records bytes sent for key swapping traffic.
   *
   * <p>This method updates a cumulative counter used for overhead reporting. The value is measured
   * in bytes and is expected to be called on the networking hot path.
   *
   * @param x bytes sent for swap messages.
   */
  public synchronized void swappingSentBytes(int x) {
    swappingSentBytes += x;
  }

  /**
   * Returns total bytes received for key swapping traffic.
   *
   * <p>The value has been cumulative since process start and is intended for diagnostics and
   * bandwidth accounting. It does not include request payloads.
   *
   * @return cumulative swap bytes received.
   */
  @SuppressWarnings("unused")
  public synchronized long getSwappingTotalBytesReceived() {
    return swappingRcvdBytes;
  }

  /**
   * Returns total bytes sent for key swapping traffic.
   *
   * <p>The value has been cumulative since process start and is intended for diagnostics and
   * bandwidth accounting. It does not include request payloads.
   *
   * @return cumulative swap bytes sent.
   */
  public synchronized long getSwappingTotalBytesSent() {
    return swappingSentBytes;
  }

  private long totalAuthBytesSent;

  /**
   * Adds bytes sent for authentication and connection setup.
   *
   * <p>This counter tracks protocol overhead for link establishment and handshake traffic. It's
   * been cumulative since the process started and used in overhead summaries.
   *
   * @param x bytes sent for authentication/setup.
   */
  public synchronized void reportAuthBytes(int x) {
    totalAuthBytesSent += x;
  }

  /**
   * Returns cumulative bytes sent for authentication and connection setup.
   *
   * <p>This value is protocol overhead only and does not include request payloads.
   *
   * @return total authentication/setup bytes sent.
   */
  public synchronized long getTotalAuthBytesSent() {
    return totalAuthBytesSent;
  }

  private long resendBytesSent;

  /** Tracks bytes sent due to resends. */
  public final ByteCounter resendByteCounter =
      new ByteCounter() {

        @Override
        public void receivedBytes(int x) {
          // Ignore
        }

        @Override
        public void sentBytes(int x) {
          synchronized (NodeStats.this) {
            resendBytesSent += x;
          }
        }

        @Override
        public void sentPayload(int x) {
          LOG.warn("Unexpected payload in resendByteCounter");
        }
      };

  /**
   * Returns cumulative bytes sent due to resend activity.
   *
   * <p>This countermeasures protocol overhead associated with retransmissions and is used in
   * overhead summaries.
   *
   * @return total resend bytes sent.
   */
  public synchronized long getResendBytesSent() {
    return resendBytesSent;
  }

  private long uomBytesSent;

  /**
   * Adds bytes sent for update-over-mandatory (UOM) traffic.
   *
   * <p>This counter tracks protocol overhead for update mechanisms. It's been cumulative since the
   * process started and included in overhead summaries.
   *
   * @param x bytes sent for UOM traffic.
   */
  public synchronized void reportUOMBytesSent(int x) {
    uomBytesSent += x;
  }

  /**
   * Returns cumulative bytes sent for update-over-mandatory (UOM) traffic.
   *
   * <p>The value includes protocol overhead only and is used for bandwidth accounting.
   *
   * @return total UOM bytes sent.
   */
  public synchronized long getUOMBytesSent() {
    return uomBytesSent;
  }

  // Opennet-related bytes - *not* including bytes sent on requests, those are accounted towards
  // the requests' totals.

  private long announceBytesSent;
  private long announceBytesPayload;

  /** Tracks bytes and payload sent for opennet announcements. */
  public final ByteCounter announceByteCounter =
      new ByteCounter() {

        @Override
        public void receivedBytes(int x) {
          // Ignore
        }

        @Override
        public void sentBytes(int x) {
          synchronized (NodeStats.this) {
            announceBytesSent += x;
          }
        }

        @Override
        public void sentPayload(int x) {
          synchronized (NodeStats.this) {
            announceBytesPayload += x;
          }
        }
      };

  /**
   * Returns total bytes sent for opennet announcements.
   *
   * <p>This includes overhead and payload recorded by {@link #announceByteCounter}. Values have
   * been cumulative since the process started.
   *
   * @return total announcement bytes sent.
   */
  public synchronized long getAnnounceBytesSent() {
    return announceBytesSent;
  }

  /**
   * Returns payload bytes sent for opennet announcements.
   *
   * <p>This is the payload-only subset of {@link #getAnnounceBytesSent()} recorded by {@link
   * #announceByteCounter}.
   *
   * @return announcement payload bytes sent.
   */
  public synchronized long getAnnounceBytesPayloadSent() {
    return announceBytesPayload;
  }

  private long routingStatusBytesSent;

  ByteCounter setRoutingStatusCtr =
      new ByteCounter() {

        @Override
        public void receivedBytes(int x) {
          // Unexpected: setRoutingStatusCtr should not receive bytes for this flow
          LOG.error("Routing status sender received bytes {}; unexpected", x);
        }

        @Override
        public void sentBytes(int x) {
          synchronized (NodeStats.this) {
            routingStatusBytesSent += x;
          }
        }

        @Override
        public void sentPayload(int x) {
          // Ignore
        }
      };

  /**
   * Returns total bytes sent for routing status updates.
   *
   * <p>The counter has been cumulative since process start and is intended for overhead reporting.
   *
   * @return total routing-status bytes sent.
   */
  public synchronized long getRoutingStatusBytes() {
    return routingStatusBytesSent;
  }

  private long networkColoringSentBytesCounter;

  /**
   * Records the bytes received for network-coloring traffic.
   *
   * <p>This implementation currently ignores the value because only sent bytes are tracked for this
   * counter.
   *
   * @param x bytes received for network-coloring messages (ignored).
   */
  @SuppressWarnings("unused")
  public synchronized void networkColoringReceivedBytes(int x) {
    // Intentionally empty: received bytes are not tracked for this counter
  }

  /**
   * Records bytes sent for network-coloring traffic.
   *
   * <p>The counter is cumulative and contributes to overhead reporting.
   *
   * @param x bytes sent for network-coloring messages.
   */
  @SuppressWarnings("unused")
  public synchronized void networkColoringSentBytes(int x) {
    networkColoringSentBytesCounter += x;
  }

  /**
   * Returns total bytes sent for network-coloring traffic.
   *
   * <p>This has been a cumulative counter since process start.
   *
   * @return total network-coloring bytes sent.
   */
  public synchronized long getNetworkColoringSentBytes() {
    return networkColoringSentBytesCounter;
  }

  private long pingBytesSent;

  /**
   * Records bytes received for ping traffic.
   *
   * <p>This implementation ignores the value because only sent ping bytes are tracked.
   *
   * @param x bytes received for ping messages (ignored).
   */
  @SuppressWarnings("unused")
  public synchronized void pingCounterReceived(int x) {
    // Intentionally empty: received ping bytes are not tracked
  }

  /**
   * Records bytes sent for ping traffic.
   *
   * <p>The counter is cumulative and contributes to overhead reporting.
   *
   * @param x bytes sent for ping messages.
   */
  public synchronized void pingCounterSent(int x) {
    pingBytesSent += x;
  }

  /**
   * Returns total bytes sent for ping traffic.
   *
   * <p>This counter is cumulative since process start and is used in overhead summaries.
   *
   * @return total ping bytes sent.
   */
  public synchronized long getPingSentBytes() {
    return pingBytesSent;
  }

  /** Tracks overhead bytes sent for SSK requests. */
  public final ByteCounter sskRequestCtr =
      new ByteCounter() {

        @Override
        public void receivedBytes(int x) {
          // Intentionally empty: received bytes for SSK requests are not tracked
        }

        @Override
        public void sentBytes(int x) {
          synchronized (NodeStats.this) {
            sskRequestSentBytes += x;
          }
        }

        @Override
        public void sentPayload(int x) {
          // Ignore
        }
      };

  /** Tracks overhead bytes sent for CHK requests. */
  public final ByteCounter chkRequestCtr =
      new ByteCounter() {

        @Override
        public void receivedBytes(int x) {
          // Intentionally empty: received bytes for CHK requests are not tracked
        }

        @Override
        public void sentBytes(int x) {
          synchronized (NodeStats.this) {
            chkRequestSentBytes += x;
          }
        }

        @Override
        public void sentPayload(int x) {
          // Ignore
        }
      };

  /** Tracks overhead bytes sent for SSK inserts. */
  public final ByteCounter sskInsertCtr =
      new ByteCounter() {

        @Override
        public void receivedBytes(int x) {
          // Intentionally empty: received bytes for SSK inserts are not tracked
        }

        @Override
        public void sentBytes(int x) {
          synchronized (NodeStats.this) {
            sskInsertSentBytes += x;
          }
        }

        @Override
        public void sentPayload(int x) {
          // Ignore
        }
      };

  /** Tracks overhead bytes sent for CHK inserts. */
  public final ByteCounter chkInsertCtr =
      new ByteCounter() {

        @Override
        public void receivedBytes(int x) {
          // Intentionally empty: received bytes for CHK inserts are not tracked
        }

        @Override
        public void sentBytes(int x) {
          synchronized (NodeStats.this) {
            chkInsertSentBytes += x;
          }
        }

        @Override
        public void sentPayload(int x) {
          // Ignore
        }
      };

  private long probeRequestSentBytes;

  /** Tracks bytes sent for probe requests. */
  public final ByteCounter probeRequestCtr =
      new ByteCounter() {

        @Override
        public void receivedBytes(int x) {
          // Intentionally empty: received bytes for probe requests are not tracked
        }

        @Override
        public void sentBytes(int x) {
          synchronized (NodeStats.this) {
            probeRequestSentBytes += x;
          }
        }

        @Override
        public void sentPayload(int x) {
          // Ignore
        }
      };

  /**
   * Returns total bytes sent for probe requests.
   *
   * <p>This counter tracks protocol overhead for probe traffic and is cumulative since process
   * start.
   *
   * @return total probe-request bytes sent.
   */
  public synchronized long getProbeRequestSentBytes() {
    return probeRequestSentBytes;
  }

  private long routedMessageBytesSent;

  /** Tracks bytes sent for routed test messages. */
  public final ByteCounter routedMessageCtr =
      new ByteCounter() {

        @Override
        public void receivedBytes(int x) {
          // Intentionally empty: received bytes for routed messages are not tracked
        }

        @Override
        public void sentBytes(int x) {
          synchronized (NodeStats.this) {
            routedMessageBytesSent += x;
          }
        }

        @Override
        public void sentPayload(int x) {
          // Ignore
        }
      };

  /**
   * Returns total bytes sent for routed test messages.
   *
   * <p>The value has been cumulative since process start and contributes to overhead reporting.
   *
   * @return total routed-message bytes sent.
   */
  public synchronized long getRoutedMessageSentBytes() {
    return routedMessageBytesSent;
  }

  private final AtomicLong disconnBytesSent = new AtomicLong();

  @SuppressWarnings("unused")
  void disconnBytesReceived(int x) {
    // Intentionally empty: received disconnect bytes are not tracked
  }

  void disconnBytesSent(int x) {
    disconnBytesSent.addAndGet(x);
  }

  /**
   * Returns total bytes sent for disconnect-related traffic.
   *
   * <p>The counter has been cumulative since process start and is intended for overhead
   * diagnostics.
   *
   * @return total disconnect bytes sent.
   */
  public long getDisconnBytesSent() {
    return disconnBytesSent.get();
  }

  private long initialMessagesBytesSent;

  ByteCounter initialMessagesCtr =
      new ByteCounter() {

        @Override
        public void receivedBytes(int x) {
          // Intentionally empty: received bytes for initial messages are not tracked
        }

        @Override
        public void sentBytes(int x) {
          synchronized (NodeStats.this) {
            initialMessagesBytesSent += x;
          }
        }

        @Override
        public void sentPayload(int x) {
          // Ignore
        }
      };

  /**
   * Returns total bytes sent for initial peer messages.
   *
   * <p>The counter has been cumulative since process start and used for overhead reporting.
   *
   * @return total initial-message bytes sent.
   */
  public synchronized long getInitialMessagesBytesSent() {
    return initialMessagesBytesSent;
  }

  private long changedIPBytesSent;

  ByteCounter changedIPCtr =
      new ByteCounter() {

        @Override
        public void receivedBytes(int x) {
          // Intentionally empty: received bytes for changed IP are not tracked
        }

        @Override
        public void sentBytes(int x) {
          synchronized (NodeStats.this) {
            changedIPBytesSent += x;
          }
        }

        @Override
        public void sentPayload(int x) {
          // Ignore
        }
      };

  /**
   * Returns total bytes sent for IP-change notifications.
   *
   * <p>The counter has been cumulative since process start and contributes to overhead reporting.
   *
   * @return total changed-IP bytes sent.
   */
  public long getChangedIPBytesSent() {
    return changedIPBytesSent;
  }

  private long nodeToNodeSentBytes;

  final ByteCounter nodeToNodeCounter =
      new ByteCounter() {

        @Override
        public void receivedBytes(int x) {
          // Intentionally empty: received n2n bytes are not tracked
        }

        @Override
        public void sentBytes(int x) {
          synchronized (NodeStats.this) {
            nodeToNodeSentBytes += x;
          }
        }

        @Override
        public void sentPayload(int x) {
          // Ignore
        }
      };

  /**
   * Returns total bytes sent for node-to-node (n2n) messages.
   *
   * <p>This counter tracks protocol overhead for n2n traffic and is cumulative since process start.
   *
   * @return total node-to-node bytes sent.
   */
  public long getNodeToNodeBytesSent() {
    return nodeToNodeSentBytes;
  }

  private long allocationNoticesCounterBytesSent;

  @SuppressWarnings("unused")
  final ByteCounter allocationNoticesCounter =
      new ByteCounter() {

        @Override
        public void receivedBytes(int x) {
          // Intentionally empty: received bytes for allocation notices are not tracked
        }

        @Override
        public void sentBytes(int x) {
          synchronized (NodeStats.this) {
            allocationNoticesCounterBytesSent += x;
          }
        }

        @Override
        public void sentPayload(int x) {
          // Ignore
        }
      };

  /**
   * Returns total bytes sent for allocation notice traffic.
   *
   * <p>This counter has been cumulative since process start and contributes to overhead reporting.
   *
   * @return total allocation-notice bytes sent.
   */
  public long getAllocationNoticesBytesSent() {
    return allocationNoticesCounterBytesSent;
  }

  private long foafCounterBytesSent;

  final ByteCounter foafCounter =
      new ByteCounter() {

        @Override
        public void receivedBytes(int x) {
          // Intentionally empty: received bytes for FOAF traffic are not tracked
        }

        @Override
        public void sentBytes(int x) {
          synchronized (NodeStats.this) {
            foafCounterBytesSent += x;
          }
        }

        @Override
        public void sentPayload(int x) {
          // Ignore
        }
      };

  /**
   * Returns total bytes sent for FOAF traffic.
   *
   * <p>This counter tracks protocol overhead for friend-of-a-friend exchanges and is cumulative
   * since process start.
   *
   * @return total FOAF bytes sent.
   */
  public long getFOAFBytesSent() {
    return foafCounterBytesSent;
  }

  private long notificationOnlySentBytes;

  synchronized void reportNotificationOnlyPacketSent(int packetSize) {
    notificationOnlySentBytes += packetSize;
  }

  /**
   * Total bytes for notification-only (ACK-only) packets sent.
   *
   * @return cumulative bytes sent for notification-only packets.
   */
  public long getNotificationOnlyPacketsSentBytes() {
    return notificationOnlySentBytes;
  }

  /**
   * Returns total non-payload bytes sent (protocol overhead) since node start.
   *
   * @return total overhead bytes sent.
   */
  public synchronized long getSentOverhead() {
    return offerKeysSentBytes // offers we have sent
        + swappingSentBytes // swapping
        + totalAuthBytesSent // connection setup
        + resendBytesSent // resends - may be dependent on requests
        + uomBytesSent // update over mandatory
        + announceBytesSent // announcements, including payload
        + routingStatusBytesSent // routing status
        + networkColoringSentBytesCounter // network coloring
        + pingBytesSent // ping bytes
        + probeRequestSentBytes // probe requests
        + routedMessageBytesSent // routed test messages
        + disconnBytesSent.get() // disconnection related bytes
        + initialMessagesBytesSent // initial messages
        + changedIPBytesSent // changed IP
        + nodeToNodeSentBytes // n2n messages
        + notificationOnlySentBytes; // ack-only packets
  }

  /**
   * The average number of bytes sent per second for things other than requests, inserts, and offer
   * replies.
   *
   * @return current average overhead bytes per second.
   */
  public double getSentOverheadPerSecond() {
    long uptime = node.network().uptime();
    // Uptime is in milliseconds; multiply by 1000 to keep units as bytes/second without
    // truncating early.
    return (double) (getSentOverhead() * SECONDS.toMillis(1)) / uptime;
  }

  /**
   * Records a successful block receiving and updates success-rate averages.
   *
   * <p>This method updates the realtime or bulk success average and, when {@code isLocal} is {@code
   * true}, also updates the local-only success metric. It is safe to call frequently from transfer
   * paths and does not perform any I/O.
   *
   * @param realTimeFlag {@code true} for realtime transfers, {@code false} for bulk.
   * @param isLocal {@code true} if the transfer was for a local request.
   */
  public synchronized void successfulBlockReceive(boolean realTimeFlag, boolean isLocal) {
    RunningAverage blockTransferPSuccess =
        realTimeFlag ? blockTransferPSuccessRT : blockTransferPSuccessBulk;
    blockTransferPSuccess.report(1.0);
    if (isLocal) blockTransferPSuccessLocal.report(1.0);
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Block receive success: {} count={} realtime={}",
          blockTransferPSuccess.currentValue(),
          blockTransferPSuccess.countReports(),
          realTimeFlag);
  }

  /**
   * Records a failed block receiving and updates failure and success-rate averages.
   *
   * <p>When {@code normalFetch} is {@code true}, timeout information contributes to the timeout
   * failure metric. The per-channel success average is updated with a failure sample, and the
   * local-only metric is updated when {@code isLocal} is {@code true}.
   *
   * @param normalFetch {@code true} if the failure was for a normal fetch operation.
   * @param timeout {@code true} if the failure was due to a timeout.
   * @param realTimeFlag {@code true} for realtime transfers, {@code false} for bulk.
   * @param isLocal {@code true} if the transfer was for a local request.
   */
  public synchronized void failedBlockReceive(
      boolean normalFetch, boolean timeout, boolean realTimeFlag, boolean isLocal) {
    if (normalFetch) {
      blockTransferFailTimeout.report(timeout ? 1.0 : 0.0);
    }
    RunningAverage blockTransferPSuccess =
        realTimeFlag ? blockTransferPSuccessRT : blockTransferPSuccessBulk;
    blockTransferPSuccess.report(0.0);
    if (isLocal) blockTransferPSuccessLocal.report(0.0);
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Block receive failure: {} count={} realtime={}",
          blockTransferPSuccess.currentValue(),
          blockTransferPSuccess.countReports(),
          realTimeFlag);
  }

  /**
   * Records the location of an incoming request in the location histogram.
   *
   * <p>The location is expected to be in {@code [0.0, 1.0)}. The histogram is cumulative over the
   * process lifetime and is used for diagnostics and UI display.
   *
   * @param loc normalized request location in the keyspace.
   */
  public void reportIncomingRequestLocation(double loc) {
    incomingRequests.report(loc);
  }

  /**
   * Returns the histogram counts for incoming request locations.
   *
   * <p>The array length equals the configured number of bins. Counts are cumulative since the
   * process starts and are safe to read without external synchronization.
   *
   * @return histogram bin counts for incoming requests.
   */
  public int[] getIncomingRequestLocation() {
    return incomingRequests.getCounts();
  }

  /**
   * Records the location of an outgoing local request in the location histogram.
   *
   * <p>The location is expected to be in {@code [0.0, 1.0)}. The histogram is cumulative and used
   * for diagnostics and UI display.
   *
   * @param loc normalized request location in the keyspace.
   */
  public void reportOutgoingLocalRequestLocation(double loc) {
    outgoingLocalRequests.report(loc);
  }

  /**
   * Returns the histogram counts for outgoing local request locations.
   *
   * <p>The array length equals the configured number of bins. Counts are cumulative since the
   * process starts and are safe to read without external synchronization.
   *
   * @return histogram bin counts for outgoing local requests.
   */
  public int[] getOutgoingLocalRequestLocation() {
    return outgoingLocalRequests.getCounts();
  }

  /**
   * Records the location of an outgoing request in the location histogram.
   *
   * <p>The location is expected to be in {@code [0.0, 1.0)}. The histogram is cumulative and used
   * for diagnostics and UI display.
   *
   * @param loc normalized request location in the keyspace.
   */
  public void reportOutgoingRequestLocation(double loc) {
    outgoingRequests.report(loc);
  }

  /**
   * Returns the histogram counts for outgoing request locations.
   *
   * <p>The array length equals the configured number of bins. Counts are cumulative since the
   * process starts and are safe to read without external synchronization.
   *
   * @return histogram bin counts for outgoing requests.
   */
  public int[] getOutgoingRequestLocation() {
    return outgoingRequests.getCounts();
  }

  /**
   * Returns CHK success-rate buckets scaled to the provided maximum.
   *
   * <p>Each bucket contains a scaled percentage value representing the average success rate for
   * that location range. The caller chooses the scale (for example, {@code 100} for percentages).
   *
   * @param scale maximum value used for scaling the percentages.
   * @return scaled success-rate values per location bucket.
   */
  public int[] getChkSuccessRatesByLocationPercentages(int scale) {
    return chkSuccessRatesByLocation.getPercentageArray(scale);
  }

  /**
   * Records the outcome and timing for a local CHK fetch.
   *
   * <p>The method updates success and failure timing averages for the specified channel and records
   * a per-location success sample when a location is provided. Values are expected to be reported
   * in milliseconds and a normalized keyspace location.
   *
   * @param rtt round-trip time for the fetch in milliseconds.
   * @param successful {@code true} if the fetch succeeded.
   * @param location normalized keyspace location in {@code [0.0, 1.0)}.
   * @param isRealtime {@code true} for realtime fetches, {@code false} for bulk.
   */
  public void reportCHKOutcome(long rtt, boolean successful, double location, boolean isRealtime) {
    if (successful) {
      (isRealtime ? successfulLocalCHKFetchTimeAverageRT : successfulLocalCHKFetchTimeAverageBulk)
          .report(rtt);
      chkSuccessRatesByLocation.report(location, 1.0);
    } else {
      (isRealtime
              ? unsuccessfulLocalCHKFetchTimeAverageRT
              : unsuccessfulLocalCHKFetchTimeAverageBulk)
          .report(rtt);
      chkSuccessRatesByLocation.report(location, 0.0);
    }
    (isRealtime ? localCHKFetchTimeAverageRT : localCHKFetchTimeAverageBulk).report(rtt);
  }

  /**
   * Records the outcome and timing for a local SSK fetch.
   *
   * <p>The method updates success and failure timing averages for the specified channel. Values are
   * expected to be reported in milliseconds and are used for diagnostics and UI reporting.
   *
   * @param rtt round-trip time for the fetch in milliseconds.
   * @param successful {@code true} if the fetch succeeded.
   * @param isRealtime {@code true} for realtime fetches, {@code false} for bulk.
   */
  public void reportSSKOutcome(long rtt, boolean successful, boolean isRealtime) {
    if (successful) {
      (isRealtime ? successfulLocalSSKFetchTimeAverageRT : successfulLocalSSKFetchTimeAverageBulk)
          .report(rtt);
    } else {
      (isRealtime
              ? unsuccessfulLocalSSKFetchTimeAverageRT
              : unsuccessfulLocalSSKFetchTimeAverageBulk)
          .report(rtt);
    }
    (isRealtime ? localSSKFetchTimeAverageRT : localSSKFetchTimeAverageBulk).report(rtt);
  }

  private final HourlyStats hourlyStatsRT;
  private final HourlyStats hourlyStatsBulk;

  void remoteRequest(
      boolean ssk,
      boolean success,
      boolean local,
      short htl,
      double location,
      boolean realTime,
      boolean fromOfferedKey) {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Remote request: success={} htl={} answeredLocally={} location={} fromOfferedKey={}",
          success,
          htl,
          local,
          location,
          fromOfferedKey);
    if (!fromOfferedKey) {
      if (realTime) hourlyStatsRT.remoteRequest(ssk, success, local, htl, location);
      else hourlyStatsBulk.remoteRequest(ssk, success, local, htl, location);
    }
  }

  HourlyStats getHourlyStats(boolean realTime) {
    return realTime ? hourlyStatsRT : hourlyStatsBulk;
  }

  private String sanitizeDBJobType(String jobType) {
    int typeBeginIndex =
        jobType.lastIndexOf('.'); // Only use the actual class name, exclude the packages
    int typeEndIndex = jobType.indexOf('@');

    if (typeBeginIndex < 0)
      typeBeginIndex = jobType.lastIndexOf(':'); // Strip "DBJobWrapper:" prefix

    if (typeBeginIndex < 0) typeBeginIndex = 0;
    else ++typeBeginIndex;

    if (typeEndIndex < 0) typeEndIndex = jobType.length();

    return jobType.substring(typeBeginIndex, typeEndIndex);
  }

  /**
   * Records execution time for a database job type.
   *
   * <p>The job type is sanitized to a stable label (class name or wrapper prefix), and the timing
   * is recorded in a running average. These statistics are used for diagnostics and do not affect
   * admission decisions.
   *
   * @param jobType job type identifier or class name used for grouping.
   * @param executionTimeMiliSeconds duration in milliseconds for the job execution.
   */
  public void reportDatabaseJob(String jobType, long executionTimeMiliSeconds) {
    avgDatabaseJobExecutionTimes
        .computeIfAbsent(sanitizeDBJobType(jobType), _ -> new TrivialRunningAverage())
        .report(executionTimeMiliSeconds);
  }

  /**
   * Records a mandatory backoff event and its duration.
   *
   * <p>The event is grouped by the provided backoff type and by mode (realtime or bulk) for
   * aggregate reporting. Values are accumulated as running averages.
   *
   * @param backoffType stable label describing the mandatory backoff reason.
   * @param backoffTimeMilliSeconds duration of the backoff in milliseconds.
   * @param realtime {@code true} for realtime mode; {@code false} for bulk.
   */
  public void reportMandatoryBackoff(
      String backoffType, long backoffTimeMilliSeconds, boolean realtime) {
    mandatoryBackoffStats.report(backoffType, backoffTimeMilliSeconds, realtime);
  }

  /**
   * Records a routing backoff event and its duration.
   *
   * <p>The event is grouped by the provided backoff type and by mode (realtime or bulk) for
   * aggregate reporting. Values are accumulated as running averages.
   *
   * @param backoffType stable label describing the routing backoff reason.
   * @param backoffTimeMilliSeconds duration of the backoff in milliseconds.
   * @param realtime {@code true} for realtime mode; {@code false} for bulk.
   */
  public void reportRoutingBackoff(
      String backoffType, long backoffTimeMilliSeconds, boolean realtime) {
    routingBackoffStats.report(backoffType, backoffTimeMilliSeconds, realtime);
  }

  /**
   * Records a transfer backoff event and its duration.
   *
   * <p>The event is grouped by the provided backoff type and by mode (realtime or bulk) for
   * aggregate reporting. Values are accumulated as running averages.
   *
   * @param backoffType stable label describing the transfer backoff reason.
   * @param backoffTimeMilliSeconds duration of the backoff in milliseconds.
   * @param realtime {@code true} for realtime mode; {@code false} for bulk.
   */
  public void reportTransferBackoff(
      String backoffType, long backoffTimeMilliSeconds, boolean realtime) {
    transferBackoffStats.report(backoffType, backoffTimeMilliSeconds, realtime);
  }

  /**
   * Aggregated timing statistics for a labeled activity.
   *
   * <p>Fields are immutable snapshots: {@link #count()} (samples), {@link #avgTime()} (mean
   * duration in milliseconds), and {@link #totalTime()} (sum in milliseconds). Natural ordering
   * sorts descending by {@code totalTime}.
   *
   * @param keyStr stable label for the measured activity or job type.
   * @param count number of samples included in the statistics.
   * @param avgTime mean duration per sample, in milliseconds.
   * @param totalTime total duration across samples, in milliseconds.
   */
  public record TimedStats(String keyStr, long count, long avgTime, long totalTime)
      implements Comparable<TimedStats> {
    @Override
    public int compareTo(TimedStats o) {
      return Long.compare(o.totalTime, totalTime);
    }
  }

  /**
   * Returns timing stats for mandatory backoff events, partitioned by mode.
   *
   * @param realtime when {@code true}, returns realtime stats; otherwise bulk stats.
   * @return an array of timing statistics buckets.
   */
  public TimedStats[] getMandatoryBackoffStatistics(boolean realtime) {
    return mandatoryBackoffStats.getStatistics(realtime);
  }

  /**
   * Returns timing stats for routing backoff events, partitioned by mode.
   *
   * @param realtime when {@code true}, returns realtime stats; otherwise bulk stats.
   * @return an array of timing statistics buckets.
   */
  public TimedStats[] getRoutingBackoffStatistics(boolean realtime) {
    return routingBackoffStats.getStatistics(realtime);
  }

  /**
   * Returns timing stats for transfer backoff events, partitioned by mode.
   *
   * @param realtime when {@code true}, returns realtime stats; otherwise bulk stats.
   * @return an array of timing statistics buckets.
   */
  public TimedStats[] getTransferBackoffStatistics(boolean realtime) {
    return transferBackoffStats.getStatistics(realtime);
  }

  /**
   * Returns timing stats for database job execution, grouped by sanitized job type.
   *
   * <p>The job type labels are sanitized to a stable short name, and the results are sorted by
   * total time descending to highlight the heaviest contributors.
   *
   * @return array of timing statistics for database jobs.
   */
  @SuppressWarnings("unused")
  public TimedStats[] getDatabaseJobExecutionStatistics() {
    return getStatistics(avgDatabaseJobExecutionTimes);
  }

  RunningRequestsSnapshot getRunningRequestsTo(PeerNode peerNode, boolean realTimeFlag) {
    return new RunningRequestsSnapshot(
        node.routing().tracker(),
        peerNode,
        true,
        false,
        OUTWARD_TRANSFERS_PER_INSERT,
        realTimeFlag);
  }

  /**
   * Returns whether local requests are treated as remote for bandwidth liability.
   *
   * <p>When enabled, local traffic is accounted as if it were remote to reduce information leakage.
   * The flag is updated by security-level listeners and affects admission decisions.
   *
   * @return {@code true} if local requests are treated as remote.
   */
  public boolean ignoreLocalVsRemoteBandwidthLiability() {
    return ignoreLocalVsRemoteBandwidthLiability;
  }

  private int totalAnnouncements;
  private int totalAnnounceForwards;

  /**
   * Records the number of references forwarded during an opennet announcement from the given peer.
   *
   * @param forwardedRefs number of references forwarded.
   * @param source peer that originated the announcement; used for seed-tracker updates.
   */
  public void reportAnnounceForwarded(int forwardedRefs, PeerNode source) {
    synchronized (this) {
      totalAnnouncements++;
      totalAnnounceForwards += forwardedRefs;
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Announcements: {} average {}",
            totalAnnouncements,
            (totalAnnounceForwards * 1.0) / totalAnnouncements);
      // Could add to the stats page
    }
    OpennetManager om = node.network().opennet();
    if (om != null && source instanceof SeedClientPeerNode peerNode)
      om.getSeedTracker().completedAnnounce(peerNode, forwardedRefs);
  }

  /**
   * Returns the estimated transfers per announcement, rounded up to at least one.
   *
   * <p>The value is derived from recent announcement statistics and is used when computing
   * liability-style limits for concurrent announcements.
   *
   * @return estimated transfers per announcement, always {@code >= 1}.
   */
  public synchronized int getTransfersPerAnnounce() {
    if (totalAnnouncements == 0) return 1;
    return (int) Math.max(1, Math.ceil((totalAnnounceForwards * 1.0) / totalAnnouncements));
  }

  private final HashSet<Long> runningAnnouncements = new HashSet<>();

  // Could be made configurable and more sophisticated

  /** To prevent thread overflow */
  private static final int MAX_ANNOUNCEMENTS = 100;

  enum AnnouncementDecision {
    ACCEPT,
    OVERLOAD,
    LOOP
  }

  AnnouncementDecision shouldAcceptAnnouncement(long uid) {
    int outputPerSecond =
        node.network().outputBandwidthLimit() / 2; // Consider overhead; may include announcements
    // and that would cause problems!
    int inputPerSecond = node.network().inputBandwidthLimit() / 2;
    int limit = Math.min(inputPerSecond, outputPerSecond);
    synchronized (this) {
      int transfersPerAnnouncement = getTransfersPerAnnounce();
      int running = runningAnnouncements.size();
      if (running >= MAX_ANNOUNCEMENTS) {
        if (LOG.isDebugEnabled()) LOG.debug("Too many announcements running: {}", running);
        return AnnouncementDecision.OVERLOAD;
      }
      // Liability-style limiting as well.
      int perTransfer = OpennetManager.PADDED_NODEREF_SIZE;
      // Must all complete in 30 seconds. That is the timeout for one block.
      int bandwidthIn30Secs = limit * 30;
      if (perTransfer * transfersPerAnnouncement * running > bandwidthIn30Secs) {
        if (LOG.isDebugEnabled()) LOG.debug("Cannot complete {} announcements in 30 s", running);
        return AnnouncementDecision.OVERLOAD;
      }
      boolean ret = runningAnnouncements.add(uid);
      if (LOG.isDebugEnabled()) {
        if (ret) LOG.debug("Accepting announcement {}", uid);
        else LOG.debug("Rejecting (loop) announcement {}", uid);
      }
      return (ret ? AnnouncementDecision.ACCEPT : AnnouncementDecision.LOOP);
    }
  }

  /**
   * Marks an announcement as complete and releases its slot.
   *
   * <p>Call this after {@link #shouldAcceptAnnouncement(long)} returns {@code ACCEPT} to ensure the
   * running-announcement count is accurate.
   *
   * @param uid unique identifier for the announcement being finished.
   */
  public synchronized void endAnnouncement(long uid) {
    runningAnnouncements.remove(uid);
  }

  /**
   * Reports the throttled delay applied to an already sent packet.
   *
   * @param interval delay applied in milliseconds.
   * @param realtime {@code true} if on the realtime channel; {@code false} for bulk.
   */
  @Override
  public void blockTime(long interval, boolean realtime) {
    throttledPacketSendAverage.report(interval);
    if (realtime) throttledPacketSendAverageRT.report(interval);
    else throttledPacketSendAverageBulk.report(interval);
  }

  /**
   * Returns the ping threshold above which a peer is considered backed off.
   *
   * <p>The threshold is derived from the configured maximum ping time and is used by routing and
   * admission logic to apply backoff behavior.
   *
   * @return ping time threshold in milliseconds.
   */
  public synchronized long maxPeerPingTime() {
    return 2 * maxPingTime;
  }

  private final RunningAverage nlmDelayRTLocal = new TrivialRunningAverage();
  private final RunningAverage nlmDelayRTRemote = new TrivialRunningAverage();
  private final RunningAverage nlmDelayBulkLocal = new TrivialRunningAverage();
  private final RunningAverage nlmDelayBulkRemote = new TrivialRunningAverage();

  /**
   * Reports wait time for new-load-management slot allocation.
   *
   * @param waitTime time in milliseconds.
   * @param realTime {@code true} for realtime queue, {@code false} for bulk.
   * @param local {@code true} for local requests, {@code false} for remote.
   */
  public void reportNLMDelay(long waitTime, boolean realTime, boolean local) {
    if (realTime) {
      if (local) nlmDelayRTLocal.report(waitTime);
      else nlmDelayRTRemote.report(waitTime);
    } else {
      if (local) nlmDelayBulkLocal.report(waitTime);
      else nlmDelayBulkRemote.report(waitTime);
    }
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Delay times: realtime local={} remote={} bulk local={} remote={}",
          nlmDelayRTLocal.currentValue(),
          nlmDelayRTRemote.currentValue(),
          nlmDelayBulkLocal.currentValue(),
          nlmDelayBulkRemote.currentValue());
  }

  private final Object slotTimeoutsSync = new Object();
  private long fatalTimeoutsInWaitLocal;
  private long fatalTimeoutsInWaitRemote;
  private long allocatedSlotLocal;
  private long allocatedSlotRemote;

  double[] getNlmDelaySnapshot() {
    return new double[] {
      nlmDelayRTLocal.currentValue(),
      nlmDelayRTRemote.currentValue(),
      nlmDelayBulkLocal.currentValue(),
      nlmDelayBulkRemote.currentValue()
    };
  }

  long[] getSlotTimeoutSnapshot() {
    synchronized (slotTimeoutsSync) {
      return new long[] {
        fatalTimeoutsInWaitLocal, fatalTimeoutsInWaitRemote, allocatedSlotLocal, allocatedSlotRemote
      };
    }
  }

  /**
   * Records a fatal timeout while waiting for a new-load-management slot.
   *
   * <p>Counts are tracked separately for local and remote requests to aid diagnostics.
   *
   * @param local {@code true} for local requests, {@code false} for remote.
   */
  public void reportFatalTimeoutInWait(boolean local) {
    synchronized (slotTimeoutsSync) {
      if (local) fatalTimeoutsInWaitLocal++;
      else fatalTimeoutsInWaitRemote++;
    }
  }

  /**
   * Records a successful new-load-management slot allocation.
   *
   * <p>Counts are tracked separately for local and remote requests to aid diagnostics.
   *
   * @param local {@code true} for local requests, {@code false} for remote.
   */
  public void reportAllocatedSlot(boolean local) {
    synchronized (slotTimeoutsSync) {
      if (local) allocatedSlotLocal++;
      else allocatedSlotRemote++;
    }
  }

  /**
   * Indicates whether new-load-management is enabled for the given mode.
   *
   * <p>This method currently returns {@code false} for both realtime and bulk, preserving the call
   * site contract while the feature remains disabled.
   *
   * @param realTimeFlag {@code true} for realtime mode, {@code false} for bulk.
   * @return {@code true} if new-load-management is enabled for the mode.
   */
  public boolean enableNewLoadManagement(boolean realTimeFlag) {
    boolean enableNewLoadManagementBulk = false;
    boolean enableNewLoadManagementRT = false;
    return realTimeFlag ? enableNewLoadManagementRT : enableNewLoadManagementBulk;
  }

  final RunningAverage[] rejectStatsAveragers;

  private final Runnable noisyRejectStatsUpdater =
      new Runnable() {

        @Override
        public void run() {
          // SECURITY/TRIVIAL PERFORMANCE TRADEOFF: I don't think we want to run this lazily.
          // If we run it lazily, an attacker could trigger it, given that it's rarely triggered
          // in normal operation. Long term we probably want to get rid of this from the
          // production network and just surveil a few "special" nodes which volunteer to have
          // heavier stats inserted regularly.
          try {
            synchronized (noisyRejectStats) { // Only used for accessing the bytes.
              for (int i = 0; i < rejectStatsAveragers.length; i++) {
                byte result;
                RunningAverage r = rejectStatsAveragers[i];
                if (r.countReports() < minReportsNoisyRejectStats) {
                  // Do not return data until there are at least 200 results.
                  result = -1;
                } else {
                  double noisy = r.currentValue() * 100.0;
                  if (rejectStatsFuzz > 0) noisy = randomNoise(noisy, rejectStatsFuzz);
                  if (noisy < 0) result = 0;
                  else if (noisy > 100) result = 100;
                  else result = (byte) noisy;
                }
                noisyRejectStats[i] = result;
              }
            }
          } finally {
            node.network().ticker().queueTimedJob(this, rejectStatsUpdateInterval);
          }
        }
      };

  /** How many reports to require before returning a value for reject stats */
  private final int minReportsNoisyRejectStats;

  /** How often to update the reject stats */
  private final long rejectStatsUpdateInterval;

  /** If positive, the level of fuzz (size of 1 standard deviation for Gauss in percent) to use */
  private final double rejectStatsFuzz;

  private final byte[] noisyRejectStats;

  /**
   * Returns a noisy snapshot of bulk reject percentages.
   *
   * @return Array of 4 bytes, with the percentage rejections for (bulk only): CHK request, SSK
   *     request, CHK insert, SSK insert. Negative value = insufficient data. Positive value =
   *     percentage rejected. PRECAUTIONS: We update this statistic every 10 minutes. We don't
   *     return a value unless we have at least 200 samples. We add Gaussian noise. SECURITY NOTE We
   *     should remove this eventually.
   */
  public byte[] getNoisyRejectStats() {
    synchronized (noisyRejectStats) {
      return Arrays.copyOf(noisyRejectStats, noisyRejectStats.length);
    }
  }

  /**
   * Applies multiplicative Gaussian noise of mean 1.0 and the specified sigma to the input value.
   *
   * @param input Value to apply noise to.
   * @param sigma Proportion change at one standard deviation.
   * @return Value +/- Gaussian percentage.
   */
  public double randomNoise(final double input, final double sigma) {
    double multiplier = (node.bootstrap().random().nextGaussian() * sigma) + 1.0;

    /*
     * Cap noise to [0.5, 1.5]. Such amounts are very rare (5 sigma at 10%) and serve only to throw off the
     * statistics by including crazy things like negative values or impossibly huge limits.
     */
    if (multiplier < 0.5) multiplier = 0.5;
    else if (multiplier > 1.5) multiplier = 1.5;

    return input * multiplier;
  }

  /**
   * Returns the fraction of output bandwidth liability currently used relative to the upper limit.
   *
   * @return a ratio in {@code [0.0, +inf)}; values above 1.0 indicate temporary oversubscription.
   */
  public double getBandwidthLiabilityUsage() {
    long now = System.currentTimeMillis();
    long limit = getLimitSeconds(false);
    RunningRequestsSnapshot requestsSnapshot =
        new RunningRequestsSnapshot(
            node.routing().tracker(),
            ignoreLocalVsRemoteBandwidthLiability,
            OUTWARD_TRANSFERS_PER_INSERT,
            false);
    double usedBytes = requestsSnapshot.calculate(ignoreLocalVsRemoteBandwidthLiability, false);
    double nonOverheadFraction = getNonOverheadFraction(now);
    double upperLimit = getOutputBandwidthUpperLimit(limit, nonOverheadFraction);
    return usedBytes / upperLimit;
  }

  private static class BackoffStats {
    private final Map<String, TrivialRunningAverage> avgRealtimeBackoff = new ConcurrentHashMap<>();
    private final Map<String, TrivialRunningAverage> avgBulkBackoff = new ConcurrentHashMap<>();

    void report(String backoffType, long backoffTimeMilliSeconds, boolean realtime) {
      getMap(realtime)
          .computeIfAbsent(backoffType, _ -> new TrivialRunningAverage())
          .report(backoffTimeMilliSeconds);
    }

    TimedStats[] getStatistics(boolean realtime) {
      return NodeStats.getStatistics(getMap(realtime));
    }

    private Map<String, TrivialRunningAverage> getMap(boolean realtime) {
      return realtime ? avgRealtimeBackoff : avgBulkBackoff;
    }
  }

  private static TimedStats[] getStatistics(Map<String, TrivialRunningAverage> averages) {
    List<TimedStats> stats = new ArrayList<>();
    averages.forEach(
        (key, avg) ->
            stats.add(
                new TimedStats(
                    key, avg.countReports(), (long) avg.currentValue(), (long) avg.totalValue())));
    Collections.sort(stats);
    return stats.toArray(new TimedStats[0]);
  }
}

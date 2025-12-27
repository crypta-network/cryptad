package network.crypta.node;

import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicIntegerArray;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.SubConfig;
import network.crypta.crypt.RandomSource;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.xfer.BlockTransmitter.BlockTimeCallback;
import network.crypta.io.xfer.BulkTransmitter;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.RequestTracker.CountedRequests;
import network.crypta.node.RequestTracker.WaitingForSlots;
import network.crypta.node.SecurityLevels.NETWORK_THREAT_LEVEL;
import network.crypta.node.stats.StoreLocationStats;
import network.crypta.store.StoreCallback;
import network.crypta.support.HTMLNode;
import network.crypta.support.Histogram2;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.StringCounter;
import network.crypta.support.TimeUtil;
import network.crypta.support.api.BooleanCallback;
import network.crypta.support.api.IntCallback;
import network.crypta.support.api.LongCallback;
import network.crypta.support.math.BootstrappingDecayingRunningAverage;
import network.crypta.support.math.DecayingKeyspaceAverage;
import network.crypta.support.math.RunningAverage;
import network.crypta.support.math.TimeDecayingRunningAverage;
import network.crypta.support.math.TrivialRunningAverage;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Collects and reports node-wide runtime statistics and load-admission decisions.
 *
 * <p>This class aggregates metrics from networking, request scheduling, block transfers, and
 * datastore interactions to guide admission control (for example, {@link
 * #shouldRejectRequest(boolean, boolean, boolean, boolean, boolean, PeerNode, boolean, boolean,
 * boolean, UIDTag)}). It also exposes snapshots for UIs and remote peers, persists decaying
 * averages, and emits diagnostic counters used by bandwidth and fairness logic.
 *
 * <p>Thread-safety: methods that read or update shared counters are synchronized or use atomic
 * structures. Callers should avoid long-running work while holding NodeStats locks.
 *
 * <p>Units: unless stated otherwise, byte counters are in bytes, times are in milliseconds, and
 * probabilities are in the {@code [0.0, 1.0]} range.
 */
public class NodeStats implements Persistable, BlockTimeCallback {
  private static final Logger LOG = LoggerFactory.getLogger(NodeStats.class);

  /** Kinds of requests and inserts tracked by NodeStats. */
  public enum RequestType {
    CHK_REQUEST,
    SSK_REQUEST,
    CHK_INSERT,
    SSK_INSERT,
    CHK_OFFER_FETCH,
    SSK_OFFER_FETCH
  }

  /** Histogram for request locations. */
  private static class RequestsByLocation {
    private final AtomicIntegerArray bins;

    /** Constructs a request location histogram with the given number of bins. */
    RequestsByLocation(int numBins) {
      bins = new AtomicIntegerArray(numBins);
    }

    /** Update the request counts with a request for the given location. */
    final void report(final double loc) {
      assert loc >= 0 && loc < 1.0;
      int bin = (int) Math.floor(loc * bins.length());
      bins.incrementAndGet(bin);
    }

    /** Get the request count bins. */
    final int[] getCounts() {
      int[] counts = new int[bins.length()];
      for (int i = 0; i < counts.length; i++) {
        counts[i] = bins.get(i);
      }
      return counts;
    }
  }

  /** Sub-max ping time. If ping is greater than this, we reject some requests. */
  public static final long DEFAULT_SUB_MAX_PING_TIME = MILLISECONDS.toMillis(700);

  /** Maximum overall average ping time. If ping is greater than this, we reject all requests. */
  public static final long DEFAULT_MAX_PING_TIME = MILLISECONDS.toMillis(1500);

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

  /** Locations of incoming requests */
  private final RequestsByLocation incomingRequests = new RequestsByLocation(10);

  /** Locations of outgoing requests */
  private final RequestsByLocation outgoingLocalRequests = new RequestsByLocation(10);

  private final RequestsByLocation outgoingRequests = new RequestsByLocation(10);

  private volatile long subMaxPingTime;
  private volatile long maxPingTime;

  final Node node;
  public final PeerManager peers;

  final RandomSource hardRandom;

  // static initializer intentionally removed (no-op)

  /** first time bwlimitDelay was over PeerManagerUserAlert threshold */
  private long firstBwlimitDelayTimeThresholdBreak;

  /** first time nodeAveragePing was over PeerManagerUserAlert threshold */
  private long firstNodeAveragePingTimeThresholdBreak;

  /** bwlimitDelay PeerManagerUserAlert should happen if true */
  private boolean bwlimitDelayAlertRelevant;

  /** nodeAveragePing PeerManagerUserAlert should happen if true */
  private boolean nodeAveragePingAlertRelevant;

  /** Average proportion of requests rejected immediately due to overload */
  public final BootstrappingDecayingRunningAverage pInstantRejectIncomingOverall;

  public final BootstrappingDecayingRunningAverage pInstantRejectIncomingCHKRequestRT;
  public final BootstrappingDecayingRunningAverage pInstantRejectIncomingSSKRequestRT;
  public final BootstrappingDecayingRunningAverage pInstantRejectIncomingCHKInsertRT;
  public final BootstrappingDecayingRunningAverage pInstantRejectIncomingSSKInsertRT;
  public final BootstrappingDecayingRunningAverage pInstantRejectIncomingCHKRequestBulk;
  public final BootstrappingDecayingRunningAverage pInstantRejectIncomingSSKRequestBulk;
  public final BootstrappingDecayingRunningAverage pInstantRejectIncomingCHKInsertBulk;
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
  public final Histogram2 chkSuccessRatesByLocation;

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

  /** Fraction of time requests were backed off (0.0–1.0). */
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

  protected final DecayingKeyspaceAverage avgRequestLocation;

  // ThreadCounting stuffs
  private int threadLimit;

  final NodePinger nodePinger;

  final StringCounter preemptiveRejectReasons;
  final StringCounter localPreemptiveRejectReasons;

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

  private static final String TEXT_FOR = " for ";
  private static final String HTML_TABLE = "table";
  private static final String HTML_BORDER = "border";
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

  NodeStats(Node node, int sortOrder, SubConfig statsConfig) throws NodeInitException {
    this.node = node;
    this.peers = node.getPeers();
    this.hardRandom = node.getRandom();
    this.routingMissDistanceLocal = new TimeDecayingRunningAverage(0.0, 180000, 0.0, 1.0, node);
    this.routingMissDistanceRemote = new TimeDecayingRunningAverage(0.0, 180000, 0.0, 1.0, node);
    this.routingMissDistanceOverall = new TimeDecayingRunningAverage(0.0, 180000, 0.0, 1.0, node);
    this.routingMissDistanceBulk = new TimeDecayingRunningAverage(0.0, 180000, 0.0, 1.0, node);
    this.routingMissDistanceRT = new TimeDecayingRunningAverage(0.0, 180000, 0.0, 1.0, node);
    this.backedOffPercent = new TimeDecayingRunningAverage(0.0, 180000, 0.0, 1.0, node);
    preemptiveRejectReasons = new StringCounter();
    localPreemptiveRejectReasons = new StringCounter();
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

    sortOrder = configureThreadLimit(statsConfig, sortOrder);
    registerIgnoredOptions(statsConfig);
    sortOrder = configureBandwidthLiabilityOption(statsConfig, sortOrder);
    sortOrder = configurePingTimes(statsConfig, sortOrder);

    // This is a *network* level setting, because it affects the rate at which we initiate local
    // requests, which could be seen by distant nodes.

    registerSecurityListener();

    statsConfig.registerIgnoredOption("enableNewLoadManagementRT");
    statsConfig.registerIgnoredOption("enableNewLoadManagementBulk");

    persister = createPersister(statsConfig, sortOrder, node);
    SimpleFieldSet throttleFS = readThrottleFS();

    // Guesstimates. Hopefully well over the reality.
    localChkFetchBytesSentAverage =
        new TimeDecayingRunningAverage(
            500,
            180000,
            0.0,
            200.0 * 1024,
            subset(throttleFS, "LocalChkFetchBytesSentAverage"),
            node);
    localSskFetchBytesSentAverage =
        new TimeDecayingRunningAverage(
            500,
            180000,
            0.0,
            200.0 * 1024,
            subset(throttleFS, "LocalSskFetchBytesSentAverage"),
            node);
    localChkInsertBytesSentAverage =
        new TimeDecayingRunningAverage(
            32768,
            180000,
            0.0,
            200.0 * 1024,
            subset(throttleFS, "LocalChkInsertBytesSentAverage"),
            node);
    localSskInsertBytesSentAverage =
        new TimeDecayingRunningAverage(
            2048,
            180000,
            0.0,
            200.0 * 1024,
            subset(throttleFS, "LocalSskInsertBytesSentAverage"),
            node);
    localChkFetchBytesReceivedAverage =
        new TimeDecayingRunningAverage(
            32768d + 2048d /*path folding*/,
            180000,
            0.0,
            200.0 * 1024,
            subset(throttleFS, "LocalChkFetchBytesReceivedAverage"),
            node);
    localSskFetchBytesReceivedAverage =
        new TimeDecayingRunningAverage(
            2048,
            180000,
            0.0,
            200.0 * 1024,
            subset(throttleFS, "LocalSskFetchBytesReceivedAverage"),
            node);
    localChkInsertBytesReceivedAverage =
        new TimeDecayingRunningAverage(
            1024,
            180000,
            0.0,
            200.0 * 1024,
            subset(throttleFS, L_CHK_INSERT_BYTES_RECEIVED_AVG),
            node);
    localSskInsertBytesReceivedAverage =
        new TimeDecayingRunningAverage(
            500,
            180000,
            0.0,
            200.0 * 1024,
            subset(throttleFS, L_CHK_INSERT_BYTES_RECEIVED_AVG),
            node);

    remoteChkFetchBytesSentAverage =
        new TimeDecayingRunningAverage(
            32768d + 1024d + 500d + 2048d /*path folding*/,
            180000,
            0.0,
            200.0 * 1024,
            subset(throttleFS, "RemoteChkFetchBytesSentAverage"),
            node);
    remoteSskFetchBytesSentAverage =
        new TimeDecayingRunningAverage(
            1024d + 1024d + 500d,
            180000,
            0.0,
            200.0 * 1024,
            subset(throttleFS, "RemoteSskFetchBytesSentAverage"),
            node);
    remoteChkInsertBytesSentAverage =
        new TimeDecayingRunningAverage(
            32768d + 32768d + 1024d,
            180000,
            0.0,
            200.0 * 1024,
            subset(throttleFS, "RemoteChkInsertBytesSentAverage"),
            node);
    remoteSskInsertBytesSentAverage =
        new TimeDecayingRunningAverage(
            1024d + 1024d + 500d,
            180000,
            0.0,
            200.0 * 1024,
            subset(throttleFS, "RemoteSskInsertBytesSentAverage"),
            node);
    remoteChkFetchBytesReceivedAverage =
        new TimeDecayingRunningAverage(
            32768d + 1024d + 500d + 2048d /*path folding*/,
            180000,
            0.0,
            200.0 * 1024,
            subset(throttleFS, "RemoteChkFetchBytesReceivedAverage"),
            node);
    remoteSskFetchBytesReceivedAverage =
        new TimeDecayingRunningAverage(
            2048d + 500d,
            180000,
            0.0,
            200.0 * 1024,
            subset(throttleFS, "RemoteSskFetchBytesReceivedAverage"),
            node);
    remoteChkInsertBytesReceivedAverage =
        new TimeDecayingRunningAverage(
            32768d + 1024d + 500d,
            180000,
            0.0,
            200.0 * 1024,
            subset(throttleFS, "RemoteChkInsertBytesReceivedAverage"),
            node);
    remoteSskInsertBytesReceivedAverage =
        new TimeDecayingRunningAverage(
            1024d + 1024d + 500d,
            180000,
            0.0,
            200.0 * 1024,
            subset(throttleFS, "RemoteSskInsertBytesReceivedAverage"),
            node);

    successfulChkFetchBytesSentAverage =
        new TimeDecayingRunningAverage(
            32768d + 1024d + 500d + 2048d /*path folding*/,
            180000,
            0.0,
            200.0 * 1024,
            subset(throttleFS, "SuccessfulChkFetchBytesSentAverage"),
            node);
    successfulSskFetchBytesSentAverage =
        new TimeDecayingRunningAverage(
            1024d + 1024d + 500d,
            180000,
            0.0,
            200.0 * 1024,
            subset(throttleFS, "SuccessfulSskFetchBytesSentAverage"),
            node);
    successfulChkInsertBytesSentAverage =
        new TimeDecayingRunningAverage(
            32768d + 32768d + 1024d,
            180000,
            0.0,
            200.0 * 1024,
            subset(throttleFS, "SuccessfulChkInsertBytesSentAverage"),
            node);
    successfulSskInsertBytesSentAverage =
        new TimeDecayingRunningAverage(
            1024d + 1024d + 500d,
            180000,
            0.0,
            200.0 * 1024,
            subset(throttleFS, "SuccessfulSskInsertBytesSentAverage"),
            node);
    successfulChkOfferReplyBytesSentAverage =
        new TimeDecayingRunningAverage(
            32768d + 500d,
            180000,
            0.0,
            200.0 * 1024,
            subset(throttleFS, "successfulChkOfferReplyBytesSentAverage"),
            node);
    successfulSskOfferReplyBytesSentAverage =
        new TimeDecayingRunningAverage(
            3072,
            180000,
            0.0,
            200.0 * 1024,
            subset(throttleFS, "successfulSskOfferReplyBytesSentAverage"),
            node);
    successfulChkFetchBytesReceivedAverage =
        new TimeDecayingRunningAverage(
            32768d + 1024d + 500d + 2048d /*path folding*/,
            180000,
            0.0,
            200.0 * 1024,
            subset(throttleFS, "SuccessfulChkFetchBytesReceivedAverage"),
            node);
    successfulSskFetchBytesReceivedAverage =
        new TimeDecayingRunningAverage(
            2048d + 500d,
            180000,
            0.0,
            200.0 * 1024,
            subset(throttleFS, "SuccessfulSskFetchBytesReceivedAverage"),
            node);
    successfulChkInsertBytesReceivedAverage =
        new TimeDecayingRunningAverage(
            32768d + 1024d + 500d,
            180000,
            0.0,
            200.0 * 1024,
            subset(throttleFS, "SuccessfulChkInsertBytesReceivedAverage"),
            node);
    successfulSskInsertBytesReceivedAverage =
        new TimeDecayingRunningAverage(
            1024d + 1024d + 500d,
            180000,
            0.0,
            200.0 * 1024,
            subset(throttleFS, "SuccessfulSskInsertBytesReceivedAverage"),
            node);
    successfulChkOfferReplyBytesReceivedAverage =
        new TimeDecayingRunningAverage(
            32768d + 500d,
            180000,
            0.0,
            200.0 * 1024,
            subset(throttleFS, "successfulChkOfferReplyBytesReceivedAverage"),
            node);
    successfulSskOfferReplyBytesReceivedAverage =
        new TimeDecayingRunningAverage(
            3072,
            180000,
            0.0,
            200.0 * 1024,
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

    chkSuccessRatesByLocation = new Histogram2(10, 1.0);

    double nodeLoc = node.getLocationManager().getLocation();
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
    statsConfig.finishedInitialization();
  }

  private void registerSecurityListener() {
    node.getSecurityLevels()
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

  private ConfigurablePersister createPersister(SubConfig statsConfig, int sortOrder, Node node)
      throws NodeInitException {
    return new ConfigurablePersister(
        this,
        statsConfig,
        "nodeThrottleFile",
        "node-throttle.dat",
        sortOrder,
        true,
        false,
        "NodeStat.statsPersister",
        "NodeStat.statsPersisterLong",
        node.getTicker(),
        node.getRunDir());
  }

  private SimpleFieldSet readThrottleFS() {
    SimpleFieldSet throttleFS = persister.read();
    if (LOG.isDebugEnabled()) LOG.debug("Read throttleFS: {}", throttleFS);
    return throttleFS;
  }

  private int configureThreadLimit(SubConfig statsConfig, int sortOrder) {
    int defaultThreadLimit;
    long memoryLimit = NodeStarter.getMemoryLimitMB();
    LOG.debug("Detected memory limit {} MB", memoryLimit);
    if (memoryLimit > 0 && memoryLimit < 100) {
      defaultThreadLimit = 200;
      LOG.debug("Severe memory pressure; set thread limit to 200. Crypta may not work well.");
    } else if (memoryLimit > 0 && memoryLimit < 128) {
      defaultThreadLimit = 300;
      LOG.debug(
          "Moderate memory pressure; set thread limit to 300. Increase the limit in wrapper.conf if"
              + " possible.");
    } else if (memoryLimit > 0 && memoryLimit < 192) {
      defaultThreadLimit = 400;
      LOG.debug("Set thread limit to 400 due to <=192 MB memory limit. More memory is better.");
    } else if (memoryLimit > 0 && memoryLimit < 512) {
      defaultThreadLimit = 500;
      LOG.debug("Set thread limit to 500 due to <=512 MB memory limit. More memory is better.");
    } else {
      defaultThreadLimit = 1000;
      LOG.debug("Set standard thread limit to 1000. Suitable for most nodes.");
    }
    statsConfig.register(
        "threadLimit",
        defaultThreadLimit,
        sortOrder++,
        true,
        true,
        "NodeStat.threadLimit",
        "NodeStat.threadLimitLong",
        new IntCallback() {
          @Override
          public Integer get() {
            return threadLimit;
          }

          @Override
          public void set(Integer val) throws InvalidConfigValueException {
            if (get().equals(val)) return;
            if (val < 100) throw new InvalidConfigValueException(l10n("valueTooLow"));
            synchronized (overloadSync) {
              threadLimit = val;
              overloadSync.notifyAll();
            }
          }
        },
        false);
    threadLimit = statsConfig.getInt("threadLimit");
    return sortOrder;
  }

  private void registerIgnoredOptions(SubConfig statsConfig) {
    // Yes it could be in seconds instead of multiples of 0.12, but we don't want people to play
    // with it :)
    statsConfig.registerIgnoredOption("aggressiveGC");
    statsConfig.registerIgnoredOption("memoryChecker");
  }

  private int configureBandwidthLiabilityOption(SubConfig statsConfig, int sortOrder) {
    statsConfig.register(
        "ignoreLocalVsRemoteBandwidthLiability",
        false,
        sortOrder++,
        true,
        false,
        "NodeStat.ignoreLocalVsRemoteBandwidthLiability",
        "NodeStat.ignoreLocalVsRemoteBandwidthLiabilityLong",
        new BooleanCallback() {

          @Override
          public Boolean get() {
            synchronized (NodeStats.this) {
              return ignoreLocalVsRemoteBandwidthLiability;
            }
          }

          @Override
          public void set(Boolean val) {
            synchronized (NodeStats.this) {
              ignoreLocalVsRemoteBandwidthLiability = val;
            }
          }
        });
    ignoreLocalVsRemoteBandwidthLiability =
        statsConfig.getBoolean("ignoreLocalVsRemoteBandwidthLiability");
    return sortOrder;
  }

  private int configurePingTimes(SubConfig statsConfig, int sortOrder) {
    statsConfig.register(
        "maxPingTime",
        DEFAULT_MAX_PING_TIME,
        sortOrder++,
        true,
        true,
        "NodeStat.maxPingTime",
        "NodeStat.maxPingTimeLong",
        new LongCallback() {

          @Override
          public Long get() {
            return maxPingTime;
          }

          @Override
          public void set(Long val) {
            maxPingTime = val;
          }
        },
        false);
    maxPingTime = statsConfig.getLong("maxPingTime");

    statsConfig.register(
        "subMaxPingTime",
        DEFAULT_SUB_MAX_PING_TIME,
        sortOrder++,
        true,
        true,
        "NodeStat.subMaxPingTime",
        "NodeStat.subMaxPingTimeLong",
        new LongCallback() {

          @Override
          public Long get() {
            return subMaxPingTime;
          }

          @Override
          public void set(Long val) {
            subMaxPingTime = val;
          }
        },
        false);
    subMaxPingTime = statsConfig.getLong("subMaxPingTime");
    return sortOrder;
  }

  protected String l10n(String key) {
    return NodeL10n.getBase().getString("NodeStats." + key);
  }

  protected String l10n(String key, String[] patterns, String[] values) {
    return NodeL10n.getBase().getString("NodeStats." + key, patterns, values);
  }

  /**
   * Starts background components used for live statistics.
   *
   * <p>Side effects: schedules {@code NodePinger}, starts the {@code Persister}, and kicks off the
   * periodic updater for noisy reject statistics. Safe to call once during node startup.
   */
  public void start() {
    node.getExecutor().execute(nodePinger::start, "Starting NodePinger");
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
   * Don't accept requests if it'll take more than 1 minutes to send the current message queue. On
   * the assumption that most of the message queue is block transfer data. Note that this only
   * applies to data on the queue before calling shouldRejectRequest(): we do *not* attempt to
   * include any estimate of how much the request will add to it. This is important because if we
   * did, the AIMD may not have reached sufficient speed to transfer it in 60 seconds yet, because
   * it hasn't had enough data in transit to need to increase its speed.
   *
   * <p>Interaction with output bandwidth liability: This must be slightly larger than the output
   * bandwidth liability time limit (combined for both types).
   *
   * <p>A fast peer can have slightly more than half our output limit queued in requests to run. If
   * they all complete, they will take half the time limit. If they are all served from the store,
   * this will be shown on the queue time. But the queue time is estimated based on using at most
   * half the limit, so the time will be slightly over the overall limit.
   */

  // Consider increasing to 4 minutes when bulk/realtime flag merged.

  private static final long MAX_PEER_QUEUE_TIME = MINUTES.toMillis(2);

  private long lastAcceptedRequest = -1;

  static final double DEFAULT_OVERHEAD = 0.7;
  static final long DEFAULT_ONLY_PERIOD = MINUTES.toMillis(1);
  static final long DEFAULT_TRANSITION_PERIOD = MINUTES.toMillis(4);

  /**
   * Relatively high minimum overhead. A low overhead estimate becomes a self-fulfilling prophecy,
   * and it takes a long time to shake it off as the averages gradually increase. If we accept no
   * requests then everything is overhead! Whereas with a high minimum overhead the worst case is
   * that more stuff succeeds than expected, and we have a few timeouts (because output bandwidth
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
   * View of a peer's advertised load metrics used for fairness and liability checks.
   *
   * <p>Holds expected in/out transfers, per-peer and overall bandwidth limits, and derived caps for
   * concurrent transfers. Instances are immutable snapshots parsed from a {@link Message}.
   */
  public class PeerLoadStats {

    public final PeerNode peer;

    /** These do not include those from the peer */
    public final int expectedTransfersOutCHK;

    public final int expectedTransfersInCHK;
    public final int expectedTransfersOutSSK;
    public final int expectedTransfersInSSK;
    public final double outputBandwidthLowerLimit;
    public final double outputBandwidthUpperLimit;
    public final double outputBandwidthPeerLimit;
    public final double inputBandwidthLowerLimit;
    public final double inputBandwidthUpperLimit;
    public final double inputBandwidthPeerLimit;
    public final int totalRequests;
    public final int averageTransfersOutPerInsert;
    public final boolean realTime;

    /** Maximum transfers out - hard limit based on congestion control. */
    public final int maxTransfersOut;

    /**
     * Maximum transfers out - per-peer limit. If total is over the lower limit, we will be accepted
     * as long as we are below this limit.
     */
    public final int maxTransfersOutPeerLimit;

    /**
     * Maximum transfers out - lower overall limit. If total is over this limit, we will be accepted
     * as long as the per-peer usage is above the peer limit.
     */
    public final int maxTransfersOutLowerLimit;

    /** Maximum transfers out - upper overall limit. Nothing is accepted above this limit. */
    public final int maxTransfersOutUpperLimit;

    @Override
    public boolean equals(Object o) {
      if (!(o instanceof PeerLoadStats s)) return false;
      if (s.peer != peer) return false;
      if (s.expectedTransfersOutCHK != expectedTransfersOutCHK) return false;
      if (s.expectedTransfersInCHK != expectedTransfersInCHK) return false;
      if (s.expectedTransfersOutSSK != expectedTransfersOutSSK) return false;
      if (s.expectedTransfersInSSK != expectedTransfersInSSK) return false;
      if (s.totalRequests != totalRequests) return false;
      if (s.averageTransfersOutPerInsert != averageTransfersOutPerInsert) return false;
      if (s.outputBandwidthLowerLimit != outputBandwidthLowerLimit) return false;
      if (s.outputBandwidthUpperLimit != outputBandwidthUpperLimit) return false;
      if (s.outputBandwidthPeerLimit != outputBandwidthPeerLimit) return false;
      if (s.inputBandwidthLowerLimit != inputBandwidthLowerLimit) return false;
      if (s.inputBandwidthUpperLimit != inputBandwidthUpperLimit) return false;
      if (s.inputBandwidthPeerLimit != inputBandwidthPeerLimit) return false;
      if (s.maxTransfersOut != maxTransfersOut) return false;
      if (s.maxTransfersOutPeerLimit != maxTransfersOutPeerLimit) return false;
      if (s.maxTransfersOutLowerLimit != maxTransfersOutLowerLimit) return false;
      return s.maxTransfersOutUpperLimit == maxTransfersOutUpperLimit;
    }

    @Override
    public int hashCode() {
      return peer.hashCode();
    }

    @Override
    public String toString() {
      return peer.toString()
          + ":output:{lower="
          + outputBandwidthLowerLimit
          + ",upper="
          + outputBandwidthUpperLimit
          + ",this="
          + outputBandwidthPeerLimit
          + "},input:lower="
          + inputBandwidthLowerLimit
          + ",upper="
          + inputBandwidthUpperLimit
          + ",peer="
          + inputBandwidthPeerLimit
          + "},requests:"
          + "in:"
          + expectedTransfersInCHK
          + "chk/"
          + expectedTransfersInSSK
          + "ssk:out:"
          + expectedTransfersOutCHK
          + "chk/"
          + expectedTransfersOutSSK
          + "ssk transfers="
          + maxTransfersOut
          + "/"
          + maxTransfersOutPeerLimit
          + "/"
          + maxTransfersOutLowerLimit
          + "/"
          + maxTransfersOutUpperLimit;
    }

    public PeerLoadStats(PeerNode source, Message m) {
      peer = source;
      if (m.getSpec() == DMT.FNPPeerLoadStatusInt) {
        expectedTransfersInCHK = m.getInt(DMT.OTHER_TRANSFERS_IN_CHK);
        expectedTransfersInSSK = m.getInt(DMT.OTHER_TRANSFERS_IN_SSK);
        expectedTransfersOutCHK = m.getInt(DMT.OTHER_TRANSFERS_OUT_CHK);
        expectedTransfersOutSSK = m.getInt(DMT.OTHER_TRANSFERS_OUT_SSK);
        averageTransfersOutPerInsert = m.getInt(DMT.AVERAGE_TRANSFERS_OUT_PER_INSERT);
        maxTransfersOut = m.getInt(DMT.MAX_TRANSFERS_OUT);
        maxTransfersOutUpperLimit = m.getInt(DMT.MAX_TRANSFERS_OUT_UPPER_LIMIT);
        maxTransfersOutLowerLimit = m.getInt(DMT.MAX_TRANSFERS_OUT_LOWER_LIMIT);
        maxTransfersOutPeerLimit = m.getInt(DMT.MAX_TRANSFERS_OUT_PEER_LIMIT);
      } else if (m.getSpec() == DMT.FNPPeerLoadStatusShort) {
        expectedTransfersInCHK = m.getShort(DMT.OTHER_TRANSFERS_IN_CHK) & 0xFFFF;
        expectedTransfersInSSK = m.getShort(DMT.OTHER_TRANSFERS_IN_SSK) & 0xFFFF;
        expectedTransfersOutCHK = m.getShort(DMT.OTHER_TRANSFERS_OUT_CHK) & 0xFFFF;
        expectedTransfersOutSSK = m.getShort(DMT.OTHER_TRANSFERS_OUT_SSK) & 0xFFFF;
        averageTransfersOutPerInsert = m.getShort(DMT.AVERAGE_TRANSFERS_OUT_PER_INSERT) & 0xFFFF;
        maxTransfersOut = m.getShort(DMT.MAX_TRANSFERS_OUT) & 0xFFFF;
        maxTransfersOutUpperLimit = m.getShort(DMT.MAX_TRANSFERS_OUT_UPPER_LIMIT) & 0xFFFF;
        maxTransfersOutLowerLimit = m.getShort(DMT.MAX_TRANSFERS_OUT_LOWER_LIMIT) & 0xFFFF;
        maxTransfersOutPeerLimit = m.getShort(DMT.MAX_TRANSFERS_OUT_PEER_LIMIT) & 0xFFFF;
      } else if (m.getSpec() == DMT.FNPPeerLoadStatusByte) {
        expectedTransfersInCHK = m.getByte(DMT.OTHER_TRANSFERS_IN_CHK) & 0xFF;
        expectedTransfersInSSK = m.getByte(DMT.OTHER_TRANSFERS_IN_SSK) & 0xFF;
        expectedTransfersOutCHK = m.getByte(DMT.OTHER_TRANSFERS_OUT_CHK) & 0xFF;
        expectedTransfersOutSSK = m.getByte(DMT.OTHER_TRANSFERS_OUT_SSK) & 0xFF;
        averageTransfersOutPerInsert = m.getByte(DMT.AVERAGE_TRANSFERS_OUT_PER_INSERT) & 0xFF;
        maxTransfersOut = m.getByte(DMT.MAX_TRANSFERS_OUT) & 0xFF;
        maxTransfersOutUpperLimit = m.getByte(DMT.MAX_TRANSFERS_OUT_UPPER_LIMIT) & 0xFF;
        maxTransfersOutLowerLimit = m.getByte(DMT.MAX_TRANSFERS_OUT_LOWER_LIMIT) & 0xFF;
        maxTransfersOutPeerLimit = m.getByte(DMT.MAX_TRANSFERS_OUT_PEER_LIMIT) & 0xFF;
      } else throw new IllegalArgumentException();
      outputBandwidthLowerLimit = m.getInt(DMT.OUTPUT_BANDWIDTH_LOWER_LIMIT);
      outputBandwidthUpperLimit = m.getInt(DMT.OUTPUT_BANDWIDTH_UPPER_LIMIT);
      outputBandwidthPeerLimit = m.getInt(DMT.OUTPUT_BANDWIDTH_PEER_LIMIT);
      inputBandwidthLowerLimit = m.getInt(DMT.INPUT_BANDWIDTH_LOWER_LIMIT);
      inputBandwidthUpperLimit = m.getInt(DMT.INPUT_BANDWIDTH_UPPER_LIMIT);
      inputBandwidthPeerLimit = m.getInt(DMT.INPUT_BANDWIDTH_PEER_LIMIT);
      totalRequests = -1;
      realTime = m.getBoolean(DMT.REAL_TIME_FLAG);
    }

    RunningRequestsSnapshot getOtherRunningRequests() {
      return new RunningRequestsSnapshot(this);
    }

    public double peerLimit(boolean input) {
      if (input) return inputBandwidthPeerLimit;
      else return outputBandwidthPeerLimit;
    }

    public double lowerLimit(boolean input) {
      if (input) return inputBandwidthLowerLimit;
      else return outputBandwidthLowerLimit;
    }
  }

  class RunningRequestsSnapshot {

    final int expectedTransfersOutCHK;
    final int expectedTransfersInCHK;
    final int expectedTransfersOutSSK;
    final int expectedTransfersInSSK;
    final int totalRequests;
    final int expectedTransfersOutCHKSR;
    final int expectedTransfersInCHKSR;
    final int expectedTransfersOutSSKSR;
    final int expectedTransfersInSSKSR;
    final int totalRequestsSR;
    final int averageTransfersPerInsert;
    final boolean realTimeFlag;

    /**
     * Create a snapshot of all requests running. Because this isn't for any particular peer, it
     * includes all requests, even those which are SourceRestarted.
     *
     * @param tracker The RequestTracker for the Node.
     * @param ignoreLocalVsRemote If true, pretend that the request is remote even if it's local
     *     (that is, count imaginary onward transfers etc. depending on the request type).
     * @param transfersPerInsert Assume that any insert will cause this many outgoing transfers.
     *     This is not predictable, so we use an average.
     * @param realTimeFlag If true, count real-time requests, if false, count bulk requests.
     */
    RunningRequestsSnapshot(
        RequestTracker tracker,
        boolean ignoreLocalVsRemote,
        int transfersPerInsert,
        boolean realTimeFlag) {
      this.averageTransfersPerInsert = transfersPerInsert;
      this.realTimeFlag = realTimeFlag;
      CountedRequests countCHK = new CountedRequests();
      CountedRequests countSSK = new CountedRequests();
      CountedRequests countCHKSR = new CountedRequests();
      CountedRequests countSSKSR = new CountedRequests();
      tracker.countRequests(
          true,
          false,
          false,
          false,
          realTimeFlag,
          transfersPerInsert,
          ignoreLocalVsRemote,
          countCHK,
          countCHKSR);
      tracker.countRequests(
          true,
          true,
          false,
          false,
          realTimeFlag,
          transfersPerInsert,
          ignoreLocalVsRemote,
          countSSK,
          countSSKSR);
      tracker.countRequests(
          true,
          false,
          true,
          false,
          realTimeFlag,
          transfersPerInsert,
          ignoreLocalVsRemote,
          countCHK,
          countCHKSR);
      tracker.countRequests(
          true,
          true,
          true,
          false,
          realTimeFlag,
          transfersPerInsert,
          ignoreLocalVsRemote,
          countSSK,
          countSSKSR);
      tracker.countRequests(
          false,
          false,
          false,
          false,
          realTimeFlag,
          transfersPerInsert,
          ignoreLocalVsRemote,
          countCHK,
          countCHKSR);
      tracker.countRequests(
          false,
          true,
          false,
          false,
          realTimeFlag,
          transfersPerInsert,
          ignoreLocalVsRemote,
          countSSK,
          countSSKSR);
      tracker.countRequests(
          false,
          false,
          true,
          false,
          realTimeFlag,
          transfersPerInsert,
          ignoreLocalVsRemote,
          countCHK,
          countCHKSR);
      tracker.countRequests(
          false,
          true,
          true,
          false,
          realTimeFlag,
          transfersPerInsert,
          ignoreLocalVsRemote,
          countSSK,
          countSSKSR);
      tracker.countRequests(
          false,
          false,
          false,
          true,
          realTimeFlag,
          transfersPerInsert,
          ignoreLocalVsRemote,
          countCHK,
          countCHKSR);
      tracker.countRequests(
          false,
          true,
          false,
          true,
          realTimeFlag,
          transfersPerInsert,
          ignoreLocalVsRemote,
          countSSK,
          countSSKSR);
      this.expectedTransfersInCHK = countCHK.expectedTransfersIn();
      this.expectedTransfersInSSK = countSSK.expectedTransfersIn();
      this.expectedTransfersOutCHK = countCHK.expectedTransfersOut();
      this.expectedTransfersOutSSK = countSSK.expectedTransfersOut();
      this.totalRequests = countCHK.total() + countSSK.total();
      this.expectedTransfersInCHKSR = countCHKSR.expectedTransfersIn();
      this.expectedTransfersInSSKSR = countSSKSR.expectedTransfersIn();
      this.expectedTransfersOutCHKSR = countCHKSR.expectedTransfersOut();
      this.expectedTransfersOutSSKSR = countSSKSR.expectedTransfersOut();
      this.totalRequestsSR = countCHKSR.total() + countSSKSR.total();
    }

    /**
     * Create a snapshot of either the requests from a node, or the requests routed to a node. If we
     * are counting requests from a node, we also fill in the *SR counters with the counts for
     * requests which have sourceRestarted() i.e. the requests where the peer has reconnected after
     * a timeout but the requests are still running. These are only counted in the *SR totals, they
     * are not in the basic totals. The caller will reduce the limits according to the *SR totals,
     * and only consider the non-SR requests when deciding whether the peer is over the limit. The
     * updated limits are sent to the downstream node so that it can send the right number of
     * requests.
     *
     * @param tracker Request tracker used to count relevant requests.
     * @param source The peer we are interested in.
     * @param requestsToNode If true, count requests sent to the node and currently running. If
     *     false, count requests originated by the node.
     */
    RunningRequestsSnapshot(
        RequestTracker tracker,
        PeerNode source,
        boolean requestsToNode,
        boolean ignoreLocalVsRemote,
        int transfersPerInsert,
        boolean realTimeFlag) {
      this.averageTransfersPerInsert = transfersPerInsert;
      this.realTimeFlag = realTimeFlag;
      // We are calculating what part of their resources we use. Therefore, we have
      // to see it from their point of view - meaning all the requests are remote.
      if (requestsToNode) ignoreLocalVsRemote = true;
      CountedRequests countCHK = new CountedRequests();
      CountedRequests countSSK = new CountedRequests();
      CountedRequests countCHKSR = null;
      CountedRequests countSSKSR = null;
      if (!requestsToNode) {
        // No point counting if it's requests to the node.
        // Restarted only matters for requests from a node.
        countCHKSR = new CountedRequests();
        countSSKSR = new CountedRequests();
      }
      tracker.countRequests(
          source,
          requestsToNode,
          true,
          false,
          false,
          false,
          realTimeFlag,
          transfersPerInsert,
          ignoreLocalVsRemote,
          countCHK,
          countCHKSR);
      tracker.countRequests(
          source,
          requestsToNode,
          true,
          true,
          false,
          false,
          realTimeFlag,
          transfersPerInsert,
          ignoreLocalVsRemote,
          countSSK,
          countSSKSR);
      tracker.countRequests(
          source,
          requestsToNode,
          true,
          false,
          true,
          false,
          realTimeFlag,
          transfersPerInsert,
          ignoreLocalVsRemote,
          countCHK,
          countCHKSR);
      tracker.countRequests(
          source,
          requestsToNode,
          true,
          true,
          true,
          false,
          realTimeFlag,
          transfersPerInsert,
          ignoreLocalVsRemote,
          countSSK,
          countSSKSR);
      tracker.countRequests(
          source,
          requestsToNode,
          false,
          false,
          false,
          false,
          realTimeFlag,
          transfersPerInsert,
          ignoreLocalVsRemote,
          countCHK,
          countCHKSR);
      tracker.countRequests(
          source,
          requestsToNode,
          false,
          true,
          false,
          false,
          realTimeFlag,
          transfersPerInsert,
          ignoreLocalVsRemote,
          countSSK,
          countSSKSR);
      tracker.countRequests(
          source,
          requestsToNode,
          false,
          false,
          true,
          false,
          realTimeFlag,
          transfersPerInsert,
          ignoreLocalVsRemote,
          countCHK,
          countCHKSR);
      tracker.countRequests(
          source,
          requestsToNode,
          false,
          true,
          true,
          false,
          realTimeFlag,
          transfersPerInsert,
          ignoreLocalVsRemote,
          countSSK,
          countSSKSR);
      tracker.countRequests(
          source,
          requestsToNode,
          false,
          false,
          false,
          true,
          realTimeFlag,
          transfersPerInsert,
          ignoreLocalVsRemote,
          countCHK,
          countCHKSR);
      tracker.countRequests(
          source,
          requestsToNode,
          false,
          true,
          false,
          true,
          realTimeFlag,
          transfersPerInsert,
          ignoreLocalVsRemote,
          countSSK,
          countSSKSR);
      if (!requestsToNode) {
        this.expectedTransfersInCHKSR = countCHKSR.expectedTransfersIn();
        this.expectedTransfersInSSKSR = countSSKSR.expectedTransfersIn();
        this.expectedTransfersOutCHKSR = countCHKSR.expectedTransfersOut();
        this.expectedTransfersOutSSKSR = countSSKSR.expectedTransfersOut();
        this.totalRequestsSR = countCHKSR.total() + countSSKSR.total();
        this.expectedTransfersInCHK = countCHK.expectedTransfersIn() - expectedTransfersInCHKSR;
        this.expectedTransfersInSSK = countSSK.expectedTransfersIn() - expectedTransfersInSSKSR;
        this.expectedTransfersOutCHK = countCHK.expectedTransfersOut() - expectedTransfersOutCHKSR;
        this.expectedTransfersOutSSK = countSSK.expectedTransfersOut() - expectedTransfersOutSSKSR;
        this.totalRequests = (countCHK.total() + countSSK.total()) - totalRequestsSR;
      } else {
        this.expectedTransfersInCHK = countCHK.expectedTransfersIn();
        this.expectedTransfersInSSK = countSSK.expectedTransfersIn();
        this.expectedTransfersOutCHK = countCHK.expectedTransfersOut();
        this.expectedTransfersOutSSK = countSSK.expectedTransfersOut();
        this.totalRequests = countCHK.total() + countSSK.total();
        this.expectedTransfersInCHKSR = 0;
        this.expectedTransfersInSSKSR = 0;
        this.expectedTransfersOutCHKSR = 0;
        this.expectedTransfersOutSSKSR = 0;
        this.totalRequestsSR = 0;
      }
    }

    public RunningRequestsSnapshot(PeerLoadStats stats) {
      this.realTimeFlag = stats.realTime;
      // Assume they are all remote.
      this.expectedTransfersInCHK = stats.expectedTransfersInCHK;
      this.expectedTransfersInSSK = stats.expectedTransfersInSSK;
      this.expectedTransfersOutCHK = stats.expectedTransfersOutCHK;
      this.expectedTransfersOutSSK = stats.expectedTransfersOutSSK;
      this.totalRequests = stats.totalRequests;
      this.averageTransfersPerInsert = stats.averageTransfersOutPerInsert;
      this.expectedTransfersInCHKSR = 0;
      this.expectedTransfersInSSKSR = 0;
      this.expectedTransfersOutCHKSR = 0;
      this.expectedTransfersOutSSKSR = 0;
      this.totalRequestsSR = 0;
    }

    public void log() {
      log(null);
    }

    public void log(PeerNode source) {
      String message =
          "Running (adjusted): CHK in: "
              + expectedTransfersInCHK
              + " out: "
              + expectedTransfersOutCHK
              + " SSK in: "
              + expectedTransfersInSSK
              + " out: "
              + expectedTransfersOutSSK
              + " total="
              + totalRequests
              + (source == null ? "" : (TEXT_FOR + source))
              + (realTimeFlag ? " (realtime)" : " (bulk)");
      if (expectedTransfersInCHK < 0
          || expectedTransfersOutCHK < 0
          || expectedTransfersInSSK < 0
          || expectedTransfersOutSSK < 0) LOG.error(message);
      else if (LOG.isDebugEnabled()) LOG.debug(message);
    }

    public double calculate(boolean ignoreLocalVsRemoteBandwidthLiability, boolean input) {
      use(ignoreLocalVsRemoteBandwidthLiability);

      if (input)
        return this.expectedTransfersInCHK * (32768d + 256d)
            + this.expectedTransfersInSSK * (2048d + 256d)
            + this.expectedTransfersOutCHK * (double) TRANSFER_OUT_IN_OVERHEAD
            + this.expectedTransfersOutSSK * (double) TRANSFER_OUT_IN_OVERHEAD;
      else
        return this.expectedTransfersOutCHK * (32768d + 256d)
            + this.expectedTransfersOutSSK * (2048d + 256d)
            + expectedTransfersInCHK * (double) TRANSFER_IN_OUT_OVERHEAD
            + expectedTransfersInSSK * (double) TRANSFER_IN_OUT_OVERHEAD;
    }

    public double calculateSR(boolean ignoreLocalVsRemoteBandwidthLiability, boolean input) {
      use(ignoreLocalVsRemoteBandwidthLiability);

      if (input)
        return this.expectedTransfersInCHKSR * (32768d + 256d)
            + this.expectedTransfersInSSKSR * (2048d + 256d)
            + this.expectedTransfersOutCHKSR * (double) TRANSFER_OUT_IN_OVERHEAD
            + this.expectedTransfersOutSSKSR * (double) TRANSFER_OUT_IN_OVERHEAD;
      else
        return this.expectedTransfersOutCHKSR * (32768d + 256d)
            + this.expectedTransfersOutSSKSR * (2048d + 256d)
            + expectedTransfersInCHKSR * (double) TRANSFER_IN_OUT_OVERHEAD
            + expectedTransfersInSSKSR * (double) TRANSFER_IN_OUT_OVERHEAD;
    }

    /**
     * @return The number of requests running or -1 if not known (remote doesn't tell us).
     */
    public int totalRequests() {
      return totalRequests;
    }

    public int totalOutTransfers() {
      return expectedTransfersOutCHK + expectedTransfersOutSSK;
    }
  }

  // Look plausible from my node-throttle.dat stats as of 01/11/2010.
  /**
   * Output bytes required for an inbound transfer. Includes e.g. sending the request in the first
   * place.
   */
  static final int TRANSFER_IN_OUT_OVERHEAD = 256;

  /** Input bytes required for an outbound transfer. Includes e.g. sending the insert etc. */
  static final int TRANSFER_OUT_IN_OVERHEAD = 256;

  /**
   * @param soft If true, rejected because of preemptive bandwidth limiting, i.e. "soft", at least
   *     somewhat predictable, can be retried. If false, hard rejection, should backoff and not
   *     retry.
   */
  record RejectReason(String name, boolean soft) {

    @Override
    public @NotNull String toString() {
      return (soft ? "SOFT" : "HARD") + ":" + name;
    }
  }

  private final Object serializeShouldRejectRequest = new Object();

  /**
   * Should a request be accepted by this node, based on its local capacity? This includes thread
   * limits and ping times, but more importantly, mechanisms based on predicting worst case
   * bandwidth usage for all running requests, and fairly sharing that capacity between peers.
   * Currently, there is no mechanism for fairness between request types, this should be implemented
   * on the sender side, and is with new load management. New load management has caused various
   * changes here but that's probably sorted out now, i.e. changes involved in new load management
   * will probably be mainly in PeerNode and RequestSender now.
   *
   * @param canAcceptAnyway Periodically we ignore the ping time and accept a request anyway. This
   *     is because the ping time partly depends on whether we have accepted any requests... This
   *     behaviour may warrant reconsideration.
   * @param isInsert Whether this is an insert.
   * @param isSSK Whether this is a request/insert for an SSK.
   * @param isLocal Is this request originated locally? This can affect our estimate of likely
   *     bandwidth usage. Whether it should be used is unclear, since an attacker can observe
   *     bandwidth usage. It is configurable.
   * @param isOfferReply Is this request actually a GetOfferedKey? This is a non-relayed fetch of a
   *     block which we recently offered via ULPRs.
   * @param source The node that sent us this request. This should be null on local requests and
   *     non-null on remote requests, but in some parts of the code that doesn't always hold. It
   *     *should* hold here, but that needs more checking before we can remove isLocal.
   * @param hasInStore If this is a request, do we have the block in the datastore already? This
   *     affects whether we accept it, which gives a significant performance gain. Arguably there is
   *     a security issue, although timing attacks are pretty easy anyway, and making requests go
   *     further may give attackers more samples...
   * @param preferInsert If true, prefer inserts to requests (slightly). There is a flag for this on
   *     inserts. The idea is that when inserts are misrouted this causes long-term problems because
   *     the data is stored in the wrong place. New load management should avoid the need for this.
   * @param realTimeFlag Is this a realtime request (low latency, low capacity) or a bulk request
   *     (high latency, high capacity)? They are accounted for separately.
   * @return The reason for rejecting it, or null to accept it.
   */
  RejectReason shouldRejectRequest(
      boolean canAcceptAnyway,
      boolean isInsert,
      boolean isSSK,
      boolean isLocal,
      boolean isOfferReply,
      PeerNode source,
      boolean hasInStore,
      boolean preferInsert,
      boolean realTimeFlag,
      UIDTag tag) {
    // Serialise shouldRejectRequest.
    // It's not always called on the same thread, and things could be problematic if they interfere
    // with each other.
    synchronized (serializeShouldRejectRequest) {
      if (LOG.isDebugEnabled()) dumpByteCostAverages();

      RejectReason early =
          checkThreadsAndPing(
              canAcceptAnyway,
              isInsert,
              isSSK,
              isLocal,
              isOfferReply,
              realTimeFlag,
              source,
              preferInsert);
      if (early != null) return early;

      long now = System.currentTimeMillis();

      double nonOverheadFraction = getNonOverheadFraction(now);

      // Pre-emptive rejection based on avoiding timeouts, with fair sharing
      // between peers. We calculate the node's capacity for requests and then
      // decide whether we will exceed it, or whether a particular peer will
      // exceed its slice of it. Peers are guaranteed a proportion of the
      // total ("peer limit"), but can opportunistically use a bit more,
      // provided the total is less than the "lower limit". The overall usage
      // should not go over the "upper limit".

      // This should normally account for the bulk of request rejections.

      int transfersPerInsert = outwardTransfersPerInsert();

      /* Requests running, globally */
      RunningRequestsSnapshot requestsSnapshot =
          new RunningRequestsSnapshot(
              node.getTracker(),
              ignoreLocalVsRemoteBandwidthLiability,
              transfersPerInsert,
              realTimeFlag);

      // Don't need to decrement because it won't be counted until setAccepted() below.

      if (LOG.isDebugEnabled()) requestsSnapshot.log();

      long limit = getLimitSeconds(realTimeFlag);
      limit = adjustLimitForDatastore(limit, hasInStore);

      int peerCount =
          node.getPeers().countConnectedPeers() + 2 * node.getPeers().countConnectedDarknetPeers();

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
              node.getTracker(),
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
      /* Per-peer limit based on current state of the connection. */
      int maxOutputTransfers =
          this.calculateMaxTransfersOut(
              source, realTimeFlag, nonOverheadFraction, maxTransfersOutUpperLimit);

      // Check bandwidth-based limits, with fair sharing.

      String ret =
          checkBandwidthLiability(
              getOutputBandwidthUpperLimit(limit, nonOverheadFraction),
              requestsSnapshot,
              peerRequestsSnapshot,
              false,
              source,
              isLocal,
              isSSK,
              isInsert,
              isOfferReply,
              realTimeFlag);
      if (ret != null) {
        return new RejectReason(ret, true);
      }

      ret =
          checkBandwidthLiability(
              getInputBandwidthUpperLimit(limit),
              requestsSnapshot,
              peerRequestsSnapshot,
              true,
              source,
              isLocal,
              isSSK,
              isInsert,
              isOfferReply,
              realTimeFlag);
      if (ret != null) {
        return new RejectReason(ret, true);
      }

      // Check transfer-based limits, with fair sharing.

      ret =
          checkMaxOutputTransfers(
              maxOutputTransfers,
              maxTransfersOutUpperLimit,
              maxTransfersOutLowerLimit,
              maxTransfersOutPeerLimit,
              requestsSnapshot,
              peerRequestsSnapshot,
              isLocal,
              realTimeFlag,
              isInsert,
              isSSK,
              isOfferReply);
      if (ret != null) {
        return new RejectReason(ret, true);
      }

      // Message queues - when the link level has far more queued than it can transmit in a
      // reasonable time, don't accept requests.
      RejectReason qrr =
          checkPeerQueues(source, isLocal, isInsert, isSSK, isOfferReply, realTimeFlag);
      if (qrr != null) return qrr;

      synchronized (this) {
        if (LOG.isDebugEnabled()) LOG.debug("Accept request (isSSK={})", isSSK);
        lastAcceptedRequest = now;
      }

      accepted(isLocal, isInsert, isSSK, isOfferReply, realTimeFlag);

      if (tag != null) tag.setAccepted();

      // Accept
      return null;
    }
  }

  private RejectReason checkThreadsAndPing(
      boolean canAcceptAnyway,
      boolean isInsert,
      boolean isSSK,
      boolean isLocal,
      boolean isOfferReply,
      boolean realTimeFlag,
      PeerNode source,
      boolean preferInsert) {
    if (source != null && source.isDisconnecting()) return new RejectReason("disconnecting", false);
    int threadCount = getActiveThreadCount();
    if (threadLimit < threadCount) {
      rejected(">threadLimit", isLocal, isInsert, isSSK, isOfferReply, realTimeFlag);
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
          rejected(">MAX_PING_TIME", isLocal, isInsert, isSSK, isOfferReply, realTimeFlag);
          return new RejectReason(
              ">MAX_PING_TIME (" + TimeUtil.formatTime((long) pingTime, 2, true) + ')', false);
        }
      } else if (pingTime > subMaxPingTime) {
        double x = (pingTime - subMaxPingTime) / (maxPingTime - subMaxPingTime);
        if (randomLessThan(x, preferInsert)) {
          rejected(">SUB_MAX_PING_TIME", isLocal, isInsert, isSSK, isOfferReply, realTimeFlag);
          return new RejectReason(
              ">SUB_MAX_PING_TIME (" + TimeUtil.formatTime((long) pingTime, 2, true) + ')', false);
        }
      }
    }
    return null;
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

  private RejectReason checkPeerQueues(
      PeerNode source,
      boolean isLocal,
      boolean isInsert,
      boolean isSSK,
      boolean isOfferReply,
      boolean realTimeFlag) {
    if (source == null) return null;
    if (source.getMessageQueueLengthBytes() > MAX_PEER_QUEUE_BYTES) {
      rejected(">MAX_PEER_QUEUE_BYTES", isLocal, isInsert, isSSK, isOfferReply, realTimeFlag);
      return new RejectReason("Too many message bytes queued for peer", false);
    }
    if (source.getProbableSendQueueTime() > MAX_PEER_QUEUE_TIME) {
      rejected(">MAX_PEER_QUEUE_TIME", isLocal, isInsert, isSSK, isOfferReply, realTimeFlag);
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

  /**
   * Number of outbound transfers per insert assumed for admission logic.
   *
   * @return the assumed number of outbound transfers per insert.
   */
  public int outwardTransfersPerInsert() {
    // Consider computing a dynamic average in future revisions
    return 1;
  }

  private double getInputBandwidthUpperLimit(long limit) {
    return node.getInputBandwidthLimit() * (double) limit;
  }

  private double getNonOverheadFraction(long now) {

    long[] total = node.getCollector().getTotalIO();
    long totalSent = total[0];
    long totalOverhead = getSentOverhead();
    long uptime = node.getUptime();

    /* The fraction of output bytes which are used for requests */
    // Consider using a shorter average; evaluate behavior when bwlimit changes

    double totalCouldSend = Math.max(totalSent, (node.getOutputBandwidthLimit() * uptime) / 1000.0);
    double nonOverheadFraction = (totalCouldSend - totalOverhead) / totalCouldSend;
    long timeFirstAnyConnections = peers.timeFirstAnyConnections;
    if (timeFirstAnyConnections > 0) {
      long time = now - timeFirstAnyConnections;
      if (time < DEFAULT_ONLY_PERIOD) {
        nonOverheadFraction = DEFAULT_OVERHEAD;
        if (LOG.isDebugEnabled())
          LOG.debug("Adjusted non-overhead fraction: {}", nonOverheadFraction);
      } else if (time < DEFAULT_ONLY_PERIOD + DEFAULT_TRANSITION_PERIOD) {
        time -= DEFAULT_ONLY_PERIOD;
        nonOverheadFraction =
            (time * nonOverheadFraction + (DEFAULT_TRANSITION_PERIOD - time) * DEFAULT_OVERHEAD)
                / DEFAULT_TRANSITION_PERIOD;
        if (LOG.isDebugEnabled())
          LOG.debug("Adjusted non-overhead fraction: {}", nonOverheadFraction);
      }
    }
    if (nonOverheadFraction < MIN_NON_OVERHEAD) {
      // If there's been an auto-update, we may have used a vast amount of bandwidth for it.
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
    double outputAvailablePerSecond = node.getOutputBandwidthLimit() * nonOverheadFraction;
    return outputAvailablePerSecond * limit;
  }

  private int getMaxTransfersUpperLimit(boolean realTime, double nonOverheadFraction) {
    // Could refactor with getOutputBandwidthUpperLimit to avoid duplicate calculation
    double outputAvailablePerSecond = node.getOutputBandwidthLimit() * nonOverheadFraction;

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
   * @param source The source of the request.
   * @param isLocal True if the request is local.
   * @param isSSK True if it is an SSK request.
   * @param isInsert True if it is an insert.
   * @param isOfferReply True if it is a GetOfferedKey.
   * @param realTimeFlag True if this is a real-time request, false if it is a bulk request.
   * @return A string explaining why, or null if we can accept the request.
   */
  private String checkBandwidthLiability(
      double bandwidthAvailableOutputUpperLimit,
      RunningRequestsSnapshot requestsSnapshot,
      RunningRequestsSnapshot peerRequestsSnapshot,
      boolean input,
      PeerNode source,
      boolean isLocal,
      boolean isSSK,
      boolean isInsert,
      boolean isOfferReply,
      boolean realTimeFlag) {
    String name = input ? "Input" : "Output";
    int peerCount =
        node.getPeers().countConnectedPeers() + 2 * node.getPeers().countConnectedDarknetPeers();

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
    // Even if we do we still need to allow the guaranteed allocation for each peer.
    // Except when we do that, we have to offer it via ULPRs afterward ...
    // Yes but the GetOfferedKey's are subject to load management, so no problem.
    if (bandwidthLiabilityOutput > bandwidthAvailableOutputUpperLimit) {
      LOG.warn(
          "Usage over upper limit {} (usage={}); allow due to reassignment edge cases",
          bandwidthAvailableOutputUpperLimit,
          bandwidthLiabilityOutput);
    }

    if (bandwidthLiabilityOutput > bandwidthAvailableOutputLowerLimit) {

      // Bandwidth is scarce (we are over the lower limit i.e. more than half our capacity is used).
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
        rejected(
            name + " bandwidth liability: fairness between peers",
            isLocal,
            isInsert,
            isSSK,
            isOfferReply,
            realTimeFlag);
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
      int maxOutputTransfers,
      int maxTransfersOutUpperLimit,
      int maxTransfersOutLowerLimit,
      int maxTransfersOutPeerLimit,
      RunningRequestsSnapshot requestsSnapshot,
      RunningRequestsSnapshot peerRequestsSnapshot,
      boolean isLocal,
      boolean realTime,
      boolean isInsert,
      boolean isSSK,
      boolean isOfferReply) {
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
      rejected(
          "TooManyTransfers: Congestion control", isLocal, isInsert, isSSK, isOfferReply, realTime);
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
    rejected(
        "TooManyTransfers: Fair sharing between peers",
        isLocal,
        isInsert,
        isSSK,
        isOfferReply,
        realTime);
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
      for (int i = 0; i < 3; i++) if (hardRandom.nextDouble() >= x) return false;
      return true;
    }
    return hardRandom.nextDouble() < x;
  }

  private void rejected(
      String reason,
      boolean isLocal,
      boolean isInsert,
      boolean isSSK,
      boolean isOfferReply,
      boolean isRealTime) {
    reason += " " + (isRealTime ? " (rt)" : " (bulk)");
    if (LOG.isDebugEnabled())
      LOG.debug("Rejecting (local={}) isSSK={} isInsert={} : {}", isLocal, isSSK, isInsert, reason);
    if (!isLocal) preemptiveRejectReasons.inc(reason);
    else this.localPreemptiveRejectReasons.inc(reason);
    if (!isLocal && !isOfferReply) {
      this.pInstantRejectIncomingOverall.report(1.0);
      getRejectedTracker(isRealTime, isSSK, isInsert).report(1.0);
    }
  }

  private void accepted(
      boolean isLocal,
      boolean isInsert,
      boolean isSSK,
      boolean isOfferReply,
      boolean realTimeFlag) {
    if (!isLocal && !isOfferReply) {
      pInstantRejectIncomingOverall.report(0.0);
      getRejectedTracker(realTimeFlag, isSSK, isInsert).report(0.0);
    }
  }

  private BootstrappingDecayingRunningAverage getRejectedTracker(
      boolean isRealTime, boolean isSSK, boolean isInsert) {
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

  public double getBwlimitDelayTimeRT() {
    return throttledPacketSendAverageRT.currentValue();
  }

  public double getBwlimitDelayTimeBulk() {
    return throttledPacketSendAverageBulk.currentValue();
  }

  public double getBwlimitDelayTime() {
    return throttledPacketSendAverage.currentValue();
  }

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
    if (node.getOpennet() == null) return 0;
    return node.getOpennet().getNetworkSizeEstimate(timestamp);
  }

  /**
   * Returns the estimated darknet size at or before the given time.
   *
   * @param timestamp cutoff time in milliseconds since epoch; pass {@code -1} for the current
   *     session estimate.
   * @return estimated number of peers.
   */
  public int getDarknetSizeEstimate(long timestamp) {
    return node.getLocationManager().getNetworkSizeEstimate(timestamp);
  }

  /**
   * Returns known peer locations for diagnostics at or before {@code timestamp}.
   *
   * @param timestamp cutoff time in milliseconds since epoch; pass {@code -1} for all cached
   *     entries.
   * @return array of serialized location entries; never {@code null}.
   */
  public Object[] getKnownLocations(long timestamp) {
    return node.getLocationManager().getKnownLocations(timestamp);
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
      long[] ioStats = node.getCollector().getTotalIO();
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

  public void waitUntilNotOverloaded() {
    // Wait with timeout so callers re-check periodically even if no signals arrive.
    synchronized (overloadSync) {
      while (threadLimit < getActiveThreadCount()) {
        try {
          overloadSync.wait(5000L);
        } catch (InterruptedException _) {
          // Preserve interrupt status and return to caller.
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
    final PriorityAwareExecutor exec = node.getExecutor();

    // Executor running threads (floor)
    int runningWorkers = 0;
    try {
      int[] running = exec.runningThreads();
      for (int v : running) runningWorkers += v;
    } catch (Throwable _) {
      // Keep floor at 0 if introspection is unavailable.
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
    return node.getExecutor().runningThreads();
  }

  /**
   * Returns counts of executor threads currently waiting for work per priority bucket.
   *
   * @return array of counts indexed by scheduler priority; never {@code null}.
   */
  public int[] getWaitingThreadsByPriority() {
    return node.getExecutor().waitingThreads();
  }

  /**
   * Maximum allowed active thread estimate used for overload protection.
   *
   * @return the configured soft limit for active threads.
   */
  public int getThreadLimit() {
    return threadLimit;
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
  @SuppressWarnings("java:S3014") // Intentional ThreadGroup use for cheap, VM‑wide enumeration
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

  public SimpleFieldSet exportVolatileFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    long now = System.currentTimeMillis();
    fs.put("isUsingWrapper", node.isUsingWrapper());
    putUptime(fs, now);
    putPingAndDelays(fs);
    long nodeUptimeSecondsLocal = Math.max(1, (now - node.getStartupTime()) / 1000);
    putNetworkSizeEstimates(fs, now);
    putRoutingMissDistances(fs);

    fs.put("backedOffPercent", backedOffPercent.currentValue());
    fs.put("pInstantReject", pRejectIncomingInstantly());
    fs.put("unclaimedFIFOSize", node.getUSM().getUnclaimedFIFOSize());
    fs.put("RAMBucketPoolSize", node.getClientCore().getTempBucketFactory().getRamUsed());

    /* gather connection statistics */
    PeerNodeStatus[] peerNodeStatuses = peers.statusBook().getPeerNodeStatuses(true);
    int numberOfSeedServers = 0;
    int numberOfSeedClients = 0;

    for (PeerNodeStatus peerNodeStatus : peerNodeStatuses) {
      if (peerNodeStatus.isSeedServer()) numberOfSeedServers++;
      if (peerNodeStatus.isSeedClient()) numberOfSeedClients++;
    }

    int numberOfConnected =
        PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_CONNECTED);
    int numberOfRoutingBackedOff =
        PeerNodeStatus.getPeerStatusCount(
            peerNodeStatuses, PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF);
    int numberOfTooNew =
        PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_TOO_NEW);
    int numberOfTooOld =
        PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_TOO_OLD);
    int numberOfDisconnected =
        PeerNodeStatus.getPeerStatusCount(
            peerNodeStatuses, PeerManager.PEER_NODE_STATUS_DISCONNECTED);
    int numberOfNeverConnected =
        PeerNodeStatus.getPeerStatusCount(
            peerNodeStatuses, PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED);
    int numberOfDisabled =
        PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_DISABLED);
    int numberOfBursting =
        PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_BURSTING);
    int numberOfListening =
        PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_LISTENING);
    int numberOfListenOnly =
        PeerNodeStatus.getPeerStatusCount(
            peerNodeStatuses, PeerManager.PEER_NODE_STATUS_LISTEN_ONLY);

    int numberOfSimpleConnected = numberOfConnected + numberOfRoutingBackedOff;
    int numberOfNotConnected =
        numberOfTooNew
            + numberOfTooOld
            + numberOfDisconnected
            + numberOfNeverConnected
            + numberOfDisabled
            + numberOfBursting
            + numberOfListening
            + numberOfListenOnly;

    fs.put("numberOfSeedServers", numberOfSeedServers);
    fs.put("numberOfSeedClients", numberOfSeedClients);
    fs.put("numberOfConnected", numberOfConnected);
    fs.put("numberOfRoutingBackedOff", numberOfRoutingBackedOff);
    fs.put("numberOfTooNew", numberOfTooNew);
    fs.put("numberOfTooOld", numberOfTooOld);
    fs.put("numberOfDisconnected", numberOfDisconnected);
    fs.put("numberOfNeverConnected", numberOfNeverConnected);
    fs.put("numberOfDisabled", numberOfDisabled);
    fs.put("numberOfBursting", numberOfBursting);
    fs.put("numberOfListening", numberOfListening);
    fs.put("numberOfListenOnly", numberOfListenOnly);

    fs.put("numberOfSimpleConnected", numberOfSimpleConnected);
    fs.put("numberOfNotConnected", numberOfNotConnected);

    fs.put(
        "numberOfTransferringRequestSenders", node.getTracker().getNumTransferringRequestSenders());
    fs.put("numberOfARKFetchers", node.getNumARKFetchers());
    fs.put("bandwidthLiabilityUsageOutputBulk", node.getNodeStats().getBandwidthLiabilityUsage());

    RequestTracker tracker = node.getTracker();

    fs.put("numberOfLocalCHKInserts", tracker.getNumLocalCHKInserts());
    fs.put("numberOfRemoteCHKInserts", tracker.getNumRemoteCHKInserts());
    fs.put("numberOfLocalSSKInserts", tracker.getNumLocalSSKInserts());
    fs.put("numberOfRemoteSSKInserts", tracker.getNumRemoteSSKInserts());
    fs.put("numberOfLocalCHKRequests", tracker.getNumLocalCHKRequests());
    fs.put("numberOfRemoteCHKRequests", tracker.getNumRemoteCHKRequests());
    fs.put("numberOfLocalSSKRequests", tracker.getNumLocalSSKRequests());
    fs.put("numberOfRemoteSSKRequests", tracker.getNumRemoteSSKRequests());
    fs.put(
        "numberOfTransferringRequestHandlers",
        node.getTracker().getNumTransferringRequestHandlers());
    fs.put("numberOfCHKOfferReplys", tracker.getNumCHKOfferReplies());
    fs.put("numberOfSSKOfferReplys", tracker.getNumSSKOfferReplies());

    fs.put("delayTimeLocalRT", nlmDelayRTLocal.currentValue());
    fs.put("delayTimeRemoteRT", nlmDelayRTRemote.currentValue());
    fs.put("delayTimeLocalBulk", nlmDelayBulkLocal.currentValue());
    fs.put("delayTimeRemoteBulk", nlmDelayBulkRemote.currentValue());
    synchronized (slotTimeoutsSync) {
      // timeoutFractions = fatalTimeouts/(fatalTimeouts+allocatedSlot)
      fs.put("fatalTimeoutsLocal", fatalTimeoutsInWaitLocal);
      fs.put("fatalTimeoutsRemote", fatalTimeoutsInWaitRemote);
      fs.put("allocatedSlotLocal", allocatedSlotLocal);
      fs.put("allocatedSlotRemote", allocatedSlotRemote);
    }

    WaitingForSlots waitingSlots = tracker.countRequestsWaitingForSlots();
    fs.put("RequestsWaitingSlotsLocal", waitingSlots.local);
    fs.put("RequestsWaitingSlotsRemote", waitingSlots.remote);

    fs.put(
        "successfulLocalCHKFetchTimeBulk", successfulLocalCHKFetchTimeAverageBulk.currentValue());
    fs.put("successfulLocalCHKFetchTimeRT", successfulLocalCHKFetchTimeAverageRT.currentValue());
    fs.put(
        "unsuccessfulLocalCHKFetchTimeBulk",
        unsuccessfulLocalCHKFetchTimeAverageBulk.currentValue());
    fs.put(
        "unsuccessfulLocalCHKFetchTimeRT", unsuccessfulLocalCHKFetchTimeAverageRT.currentValue());

    fs.put(
        "successfulLocalSSKFetchTimeBulk", successfulLocalSSKFetchTimeAverageBulk.currentValue());
    fs.put("successfulLocalSSKFetchTimeRT", successfulLocalSSKFetchTimeAverageRT.currentValue());
    fs.put(
        "unsuccessfulLocalSSKFetchTimeBulk",
        unsuccessfulLocalSSKFetchTimeAverageBulk.currentValue());
    fs.put(
        "unsuccessfulLocalSSKFetchTimeRT", unsuccessfulLocalSSKFetchTimeAverageRT.currentValue());

    putTotalAndRecentIOMetrics(fs, nodeUptimeSecondsLocal);

    putRoutingBackoffCounters(fs);

    putSwapAndStoreMetrics(fs, nodeUptimeSecondsLocal);

    Runtime rt = Runtime.getRuntime();
    float freeMemory = rt.freeMemory();
    float totalMemory = rt.totalMemory();
    float maxMemory = rt.maxMemory();

    long usedJavaMem = (long) (totalMemory - freeMemory);
    long allocatedJavaMem = (long) totalMemory;
    long maxJavaMem = (long) maxMemory;
    int availableCpus = rt.availableProcessors();

    fs.put("freeJavaMemory", (long) freeMemory);
    fs.put("usedJavaMemory", usedJavaMem);
    fs.put("allocatedJavaMemory", allocatedJavaMem);
    fs.put("maximumJavaMemory", maxJavaMem);
    fs.put("availableCPUs", availableCpus);
    fs.put("runningThreadCount", getActiveThreadCount());

    fs.put("globalFetchPSuccess", globalFetchPSuccess.currentValue());
    fs.put("globalFetchCount", globalFetchPSuccess.countReports());
    fs.put("chkLocalFetchPSuccess", chkLocalFetchPSuccess.currentValue());
    fs.put("chkLocalFetchCount", chkLocalFetchPSuccess.countReports());
    fs.put("chkRemoteFetchPSuccess", chkRemoteFetchPSuccess.currentValue());
    fs.put("chkRemoteFetchCount", chkRemoteFetchPSuccess.countReports());
    fs.put("sskLocalFetchPSuccess", sskLocalFetchPSuccess.currentValue());
    fs.put("sskLocalFetchCount", sskLocalFetchPSuccess.countReports());
    fs.put("sskRemoteFetchPSuccess", sskRemoteFetchPSuccess.currentValue());
    fs.put("sskRemoteFetchCount", sskRemoteFetchPSuccess.countReports());
    fs.put("blockTransferPSuccessRT", blockTransferPSuccessRT.currentValue());
    fs.put("blockTransferCountRT", blockTransferPSuccessRT.countReports());
    fs.put("blockTransferPSuccessBulk", blockTransferPSuccessBulk.currentValue());
    fs.put("blockTransferCountBulk", blockTransferPSuccessBulk.countReports());
    fs.put("blockTransferFailTimeout", blockTransferFailTimeout.currentValue());

    return fs;
  }

  private void putUptime(SimpleFieldSet fs, long now) {
    long nodeUptimeSeconds;
    synchronized (this) {
      fs.put("startupTime", node.getStartupTime());
      nodeUptimeSeconds = (now - node.getStartupTime()) / 1000;
      if (nodeUptimeSeconds == 0) nodeUptimeSeconds = 1; // prevent division by zero
      fs.put("uptimeSeconds", nodeUptimeSeconds);
    }
  }

  private void putPingAndDelays(SimpleFieldSet fs) {
    fs.put("averagePingTime", getNodeAveragePingTime());
    fs.put("bwlimitDelayTime", getBwlimitDelayTime());
    fs.put("bwlimitDelayTimeRT", getBwlimitDelayTimeRT());
    fs.put("bwlimitDelayTimeBulk", getBwlimitDelayTimeBulk());
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
   * True when average node ping has exceeded the alert threshold long enough to trigger.
   *
   * @return whether the average-ping alert condition is currently relevant.
   */
  public boolean isNodeAveragePingAlertRelevant() {
    return nodeAveragePingAlertRelevant;
  }

  private void putNetworkSizeEstimates(SimpleFieldSet fs, long now) {
    fs.put("opennetSizeEstimateSession", getOpennetSizeEstimate(-1));
    fs.put("networkSizeEstimateSession", getDarknetSizeEstimate(-1));
    for (int t = 1; t < 7; t++) {
      int hour = t * 24;
      long limit = now - DAYS.toMillis(t);
      fs.put("opennetSizeEstimate" + hour + "hourRecent", getOpennetSizeEstimate(limit));
      fs.put("networkSizeEstimate" + hour + "hourRecent", getDarknetSizeEstimate(limit));
    }
  }

  private void putRoutingMissDistances(SimpleFieldSet fs) {
    fs.put("routingMissDistanceLocal", routingMissDistanceLocal.currentValue());
    fs.put("routingMissDistanceRemote", routingMissDistanceRemote.currentValue());
    fs.put("routingMissDistanceOverall", routingMissDistanceOverall.currentValue());
    fs.put("routingMissDistanceBulk", routingMissDistanceBulk.currentValue());
    fs.put("routingMissDistanceRT", routingMissDistanceRT.currentValue());
  }

  @SuppressWarnings("java:S1172")
  private static void use(boolean... ignored) {
    // Intentionally no-op: acknowledge parameter usage without jumps
  }

  private static SimpleFieldSet subset(SimpleFieldSet fs, String key) {
    return fs == null ? null : fs.subset(key);
  }

  private static DecayingKeyspaceAverage dka(double nodeLoc, String key, SimpleFieldSet sfs) {
    return new DecayingKeyspaceAverage(nodeLoc, 10000, subset(sfs, key));
  }

  private void putTotalAndRecentIOMetrics(SimpleFieldSet fs, long nodeUptimeSecondsLocal) {
    long[] total = node.getCollector().getTotalIO();
    long totalOutputRate = (total[0]) / nodeUptimeSecondsLocal;
    long totalInputRate = (total[1]) / nodeUptimeSecondsLocal;
    long totalPayloadOutput = node.getTotalPayloadSent();
    long totalPayloadOutputRate = totalPayloadOutput / nodeUptimeSecondsLocal;
    int totalPayloadOutputPercent =
        (total[0] == 0) ? -1 : (int) (100 * totalPayloadOutput / total[0]);
    fs.put("totalOutputBytes", total[0]);
    fs.put("totalOutputRate", totalOutputRate);
    fs.put("totalPayloadOutputBytes", totalPayloadOutput);
    fs.put("totalPayloadOutputRate", totalPayloadOutputRate);
    fs.put("totalPayloadOutputPercent", totalPayloadOutputPercent);
    fs.put("totalInputBytes", total[1]);
    fs.put("totalInputRate", totalInputRate);

    long[] rate = getNodeIOStats();
    long deltaMS = (rate[5] - rate[2]);
    double recentOutputRate = deltaMS == 0 ? 0 : (1000.0 * (rate[3] - rate[0]) / deltaMS);
    double recentInputRate = deltaMS == 0 ? 0 : (1000.0 * (rate[4] - rate[1]) / deltaMS);
    fs.put("recentOutputRate", recentOutputRate);
    fs.put("recentInputRate", recentInputRate);

    fs.put("ackOnlyBytes", getNotificationOnlyPacketsSentBytes());
    fs.put("resentBytes", getResendBytesSent());
    fs.put("updaterOutputBytes", getUOMBytesSent());
    fs.put("announcePayloadBytes", getAnnounceBytesPayloadSent());
    fs.put("announceSentBytes", getAnnounceBytesSent());
  }

  private void putRoutingBackoffCounters(SimpleFieldSet fs) {
    String[] routingBackoffReasons = peers.getPeerNodeRoutingBackoffReasons(true);
    for (String routingBackoffReason : routingBackoffReasons) {
      fs.put(
          "numberWithRoutingBackoffReasonsRT." + routingBackoffReason,
          peers.getPeerNodeRoutingBackoffReasonSize(routingBackoffReason, true));
    }

    routingBackoffReasons = peers.getPeerNodeRoutingBackoffReasons(false);
    for (String routingBackoffReason : routingBackoffReasons) {
      fs.put(
          "numberWithRoutingBackoffReasonsBulk." + routingBackoffReason,
          peers.getPeerNodeRoutingBackoffReasonSize(routingBackoffReason, false));
    }
  }

  private void putSwapAndStoreMetrics(SimpleFieldSet fs, long nodeUptimeSecondsLocal) {
    double swaps = node.getSwaps();
    double noSwaps = node.getNoSwaps();
    double numberOfRemotePeerLocationsSeenInSwaps =
        node.getNumberOfRemotePeerLocationsSeenInSwaps();
    fs.put("numberOfRemotePeerLocationsSeenInSwaps", numberOfRemotePeerLocationsSeenInSwaps);
    double avgConnectedPeersPerNode = 0.0;
    if ((numberOfRemotePeerLocationsSeenInSwaps > 0.0) && ((swaps > 0.0) || (noSwaps > 0.0))) {
      avgConnectedPeersPerNode = numberOfRemotePeerLocationsSeenInSwaps / (swaps + noSwaps);
    }
    fs.put("avgConnectedPeersPerNode", avgConnectedPeersPerNode);

    int startedSwaps = node.getStartedSwaps();
    int swapsRejectedAlreadyLocked = node.getSwapsRejectedAlreadyLocked();
    int swapsRejectedNowhereToGo = node.getSwapsRejectedNowhereToGo();
    int swapsRejectedRateLimit = node.getSwapsRejectedRateLimit();
    int swapsRejectedRecognizedID = node.getSwapsRejectedRecognizedID();
    double locationChangePerSession = node.getLocationChangeSession();
    double locationChangePerSwap = 0.0;
    double locationChangePerMinute = 0.0;
    double swapsPerMinute = 0.0;
    double noSwapsPerMinute = 0.0;
    double swapsPerNoSwaps = 0.0;
    if (swaps > 0) {
      locationChangePerSwap = locationChangePerSession / swaps;
    }
    if ((swaps > 0.0) && (nodeUptimeSecondsLocal >= 60)) {
      locationChangePerMinute = locationChangePerSession / (nodeUptimeSecondsLocal / 60.0);
    }
    if ((swaps > 0.0) && (nodeUptimeSecondsLocal >= 60)) {
      swapsPerMinute = swaps / (nodeUptimeSecondsLocal / 60.0);
    }
    if ((noSwaps > 0.0) && (nodeUptimeSecondsLocal >= 60)) {
      noSwapsPerMinute = noSwaps / (nodeUptimeSecondsLocal / 60.0);
    }
    if ((swaps > 0.0) && (noSwaps > 0.0)) {
      swapsPerNoSwaps = swaps / noSwaps;
    }
    fs.put("locationChangePerSession", locationChangePerSession);
    fs.put("locationChangePerSwap", locationChangePerSwap);
    fs.put("locationChangePerMinute", locationChangePerMinute);
    fs.put("swapsPerMinute", swapsPerMinute);
    fs.put("noSwapsPerMinute", noSwapsPerMinute);
    fs.put("swapsPerNoSwaps", swapsPerNoSwaps);
    fs.put("swaps", swaps);
    fs.put("noSwaps", noSwaps);
    fs.put("startedSwaps", startedSwaps);
    fs.put("swapsRejectedAlreadyLocked", swapsRejectedAlreadyLocked);
    fs.put("swapsRejectedNowhereToGo", swapsRejectedNowhereToGo);
    fs.put("swapsRejectedRateLimit", swapsRejectedRateLimit);
    fs.put("swapsRejectedRecognizedID", swapsRejectedRecognizedID);
    long fix32kb = 32L * 1024;
    long cachedKeys = node.getChkDatacache().keyCount();
    long cachedSize = cachedKeys * fix32kb;
    long storeKeys = node.getChkDatastore().keyCount();
    long storeSize = storeKeys * fix32kb;
    long overallKeys = cachedKeys + storeKeys;
    long overallSize = cachedSize + storeSize;

    long maxOverallKeys = node.getMaxTotalKeys();
    long maxOverallSize = maxOverallKeys * fix32kb;

    double percentOverallKeysOfMax = (double) (overallKeys * 100) / (double) maxOverallKeys;

    long cachedStoreHits = node.getChkDatacache().hits();
    long cachedStoreMisses = node.getChkDatacache().misses();
    long cachedStoreWrites = node.getChkDatacache().writes();
    long cacheAccesses = cachedStoreHits + cachedStoreMisses;
    long cachedStoreFalsePositives = node.getChkDatacache().getBloomFalsePositive();
    double percentCachedStoreHitsOfAccesses =
        (double) (cachedStoreHits * 100) / (double) cacheAccesses;
    long storeHits = node.getChkDatastore().hits();
    long storeMisses = node.getChkDatastore().misses();
    long storeWrites = node.getChkDatastore().writes();
    long storeFalsePositives = node.getChkDatastore().getBloomFalsePositive();
    long storeAccesses = storeHits + storeMisses;
    double percentStoreHitsOfAccesses = (double) (storeHits * 100) / (double) storeAccesses;
    long overallAccesses = storeAccesses + cacheAccesses;
    double avgStoreAccessRate = (double) overallAccesses / (double) nodeUptimeSecondsLocal;

    fs.put("cachedKeys", cachedKeys);
    fs.put("cachedSize", cachedSize);
    fs.put("storeKeys", storeKeys);
    fs.put("storeSize", storeSize);
    fs.put("overallKeys", overallKeys);
    fs.put("overallSize", overallSize);
    fs.put("maxOverallKeys", maxOverallKeys);
    fs.put("maxOverallSize", maxOverallSize);
    fs.put("percentOverallKeysOfMax", percentOverallKeysOfMax);
    fs.put("cachedStoreHits", cachedStoreHits);
    fs.put("cachedStoreMisses", cachedStoreMisses);
    fs.put("cachedStoreWrites", cachedStoreWrites);
    fs.put("cacheAccesses", cacheAccesses);
    fs.put("cachedStoreFalsePositives", cachedStoreFalsePositives);
    fs.put("percentCachedStoreHitsOfAccesses", percentCachedStoreHitsOfAccesses);
    fs.put("storeHits", storeHits);
    fs.put("storeMisses", storeMisses);
    fs.put("storeAccesses", storeAccesses);
    fs.put("storeWrites", storeWrites);
    fs.put("storeFalsePositives", storeFalsePositives);
    fs.put("percentStoreHitsOfAccesses", percentStoreHitsOfAccesses);
    fs.put("overallAccesses", overallAccesses);
    fs.put("avgStoreAccessRate", avgStoreAccessRate);
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
   * Appends rows describing remote preemptive-reject reasons.
   *
   * @param table an HTML table node to append rows to; must not be {@code null}.
   * @return {@code true} if any rows were added.
   */
  public boolean getRejectReasonsTable(HTMLNode table) {
    return preemptiveRejectReasons.toTableRows(table) > 0;
  }

  /**
   * Appends rows describing local preemptive-reject reasons.
   *
   * @param table an HTML table node to append rows to; must not be {@code null}.
   * @return {@code true} if any rows were added.
   */
  public boolean getLocalRejectReasonsTable(HTMLNode table) {
    return localPreemptiveRejectReasons.toTableRows(table) > 0;
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

  private final DecimalFormat fix3p3pct = new DecimalFormat("##0.000%");
  private final NumberFormat thousandPoint = NumberFormat.getInstance();

  /**
   * Renders high-level success-rate statistics into the given HTML container.
   *
   * @param parent container node to append a table to; must not be {@code null}.
   */
  public void fillSuccessRateBox(HTMLNode parent) {
    HTMLNode list = parent.addChild(HTML_TABLE, HTML_BORDER, "0");
    final RunningAverage[] averages =
        new RunningAverage[] {
          globalFetchPSuccess,
          chkLocalFetchPSuccess,
          chkRemoteFetchPSuccess,
          sskLocalFetchPSuccess,
          sskRemoteFetchPSuccess,
          blockTransferPSuccessBulk,
          blockTransferPSuccessRT,
          blockTransferPSuccessLocal,
          blockTransferFailTimeout
        };
    final String[] names =
        new String[] {
          l10n("allRequests"),
          l10n("localCHKs"),
          l10n("remoteCHKs"),
          l10n("localSSKs"),
          l10n("remoteSSKs"),
          l10n("blockTransfersBulk"),
          l10n("blockTransfersRT"),
          l10n("blockTransfersLocal"),
          l10n("transfersTimedOut")
        };
    addSuccessRateHeaderRow(list);
    addSuccessRateRows(list, averages, names);

    long[] bulkSuccess = BulkTransmitter.transferSuccess();
    HTMLNode row = list.addChild("tr");
    row.addChild("td", l10n("bulkSends"));
    row.addChild("td", fix3p3pct.format(((double) bulkSuccess[1]) / ((double) bulkSuccess[0])));
    row.addChild("td", Long.toString(bulkSuccess[0]));
  }

  private void addSuccessRateHeaderRow(HTMLNode list) {
    HTMLNode row = list.addChild("tr");
    row.addChild("th", l10n("group"));
    row.addChild("th", l10n("pSuccess"));
    row.addChild("th", l10n("count"));
  }

  private void addSuccessRateRows(HTMLNode list, RunningAverage[] averages, String[] names) {
    for (int i = 0; i < averages.length; i++) {
      HTMLNode row = list.addChild("tr");
      row.addChild("td", names[i]);
      if (averages[i].countReports() == 0) {
        row.addChild("td", "-");
        row.addChild("td", "0");
      } else {
        row.addChild("td", fix3p3pct.format(averages[i].currentValue()));
        row.addChild("td", thousandPoint.format(averages[i].countReports()));
      }
    }
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

  public synchronized long getOffersSentBytesSent() {
    return offerKeysSentBytes;
  }

  private long swappingRcvdBytes;
  private long swappingSentBytes;

  public synchronized void swappingReceivedBytes(int x) {
    swappingRcvdBytes += x;
  }

  public synchronized void swappingSentBytes(int x) {
    swappingSentBytes += x;
  }

  @SuppressWarnings("unused")
  public synchronized long getSwappingTotalBytesReceived() {
    return swappingRcvdBytes;
  }

  public synchronized long getSwappingTotalBytesSent() {
    return swappingSentBytes;
  }

  private long totalAuthBytesSent;

  public synchronized void reportAuthBytes(int x) {
    totalAuthBytesSent += x;
  }

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

  public synchronized long getResendBytesSent() {
    return resendBytesSent;
  }

  private long uomBytesSent;

  public synchronized void reportUOMBytesSent(int x) {
    uomBytesSent += x;
  }

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

  public synchronized long getAnnounceBytesSent() {
    return announceBytesSent;
  }

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

  public synchronized long getRoutingStatusBytes() {
    return routingStatusBytesSent;
  }

  private long networkColoringSentBytesCounter;

  @SuppressWarnings("unused")
  public synchronized void networkColoringReceivedBytes(int x) {
    // Intentionally empty: received bytes are not tracked for this counter
  }

  @SuppressWarnings("unused")
  public synchronized void networkColoringSentBytes(int x) {
    networkColoringSentBytesCounter += x;
  }

  public synchronized long getNetworkColoringSentBytes() {
    return networkColoringSentBytesCounter;
  }

  private long pingBytesSent;

  @SuppressWarnings("unused")
  public synchronized void pingCounterReceived(int x) {
    // Intentionally empty: received ping bytes are not tracked
  }

  public synchronized void pingCounterSent(int x) {
    pingBytesSent += x;
  }

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

  public synchronized long getRoutedMessageSentBytes() {
    return routedMessageBytesSent;
  }

  private long disconnBytesSent;

  @SuppressWarnings("unused")
  void disconnBytesReceived(int x) {
    // Intentionally empty: received disconnect bytes are not tracked
  }

  void disconnBytesSent(int x) {
    this.disconnBytesSent += x;
  }

  public long getDisconnBytesSent() {
    return disconnBytesSent;
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
        + disconnBytesSent // disconnection related bytes
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
    long uptime = node.getUptime();
    // Uptime is in milliseconds; multiply by 1000 to keep units as bytes/second without
    // truncating early.
    return (double) (getSentOverhead() * SECONDS.toMillis(1)) / uptime;
  }

  public synchronized void successfulBlockReceive(boolean realTimeFlag, boolean isLocal) {
    RunningAverage blockTransferPSuccess =
        realTimeFlag ? blockTransferPSuccessRT : blockTransferPSuccessBulk;
    blockTransferPSuccess.report(1.0);
    if (isLocal) blockTransferPSuccessLocal.report(1.0);
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Successful receives: {} count={} realtime={}",
          blockTransferPSuccess.currentValue(),
          blockTransferPSuccess.countReports(),
          realTimeFlag);
  }

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
          "Successful receives: {} count={} realtime={}",
          blockTransferPSuccess.currentValue(),
          blockTransferPSuccess.countReports(),
          realTimeFlag);
  }

  public void reportIncomingRequestLocation(double loc) {
    incomingRequests.report(loc);
  }

  public int[] getIncomingRequestLocation() {
    return incomingRequests.getCounts();
  }

  public void reportOutgoingLocalRequestLocation(double loc) {
    outgoingLocalRequests.report(loc);
  }

  public int[] getOutgoingLocalRequestLocation() {
    return outgoingLocalRequests.getCounts();
  }

  public void reportOutgoingRequestLocation(double loc) {
    outgoingRequests.report(loc);
  }

  public int[] getOutgoingRequestLocation() {
    return outgoingRequests.getCounts();
  }

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

  public void fillDetailedTimingsBox(HTMLNode html) {
    HTMLNode table = html.addChild(HTML_TABLE);
    HTMLNode row = table.addChild("tr");
    row.addChild("td");
    row.addChild("td", "colspan", "2", "CHK");
    row.addChild("td", "colspan", "2", "SSK");
    row = table.addChild("tr");
    row.addChild("td", l10n("successfulHeader"));
    row.addChild(
        "td",
        TimeUtil.formatTime((long) successfulLocalCHKFetchTimeAverageBulk.currentValue(), 2, true));
    row.addChild(
        "td",
        TimeUtil.formatTime((long) successfulLocalCHKFetchTimeAverageRT.currentValue(), 2, true));
    row.addChild(
        "td",
        TimeUtil.formatTime((long) successfulLocalSSKFetchTimeAverageBulk.currentValue(), 2, true));
    row.addChild(
        "td",
        TimeUtil.formatTime((long) successfulLocalSSKFetchTimeAverageRT.currentValue(), 2, true));
    row = table.addChild("tr");
    row.addChild("td", l10n("unsuccessfulHeader"));
    row.addChild(
        "td",
        TimeUtil.formatTime(
            (long) unsuccessfulLocalCHKFetchTimeAverageBulk.currentValue(), 2, true));
    row.addChild(
        "td",
        TimeUtil.formatTime((long) unsuccessfulLocalCHKFetchTimeAverageRT.currentValue(), 2, true));
    row.addChild(
        "td",
        TimeUtil.formatTime(
            (long) unsuccessfulLocalSSKFetchTimeAverageBulk.currentValue(), 2, true));
    row.addChild(
        "td",
        TimeUtil.formatTime((long) unsuccessfulLocalSSKFetchTimeAverageRT.currentValue(), 2, true));
    row = table.addChild("tr");
    row.addChild("td", l10n("averageHeader"));
    row.addChild(
        "td", TimeUtil.formatTime((long) localCHKFetchTimeAverageBulk.currentValue(), 2, true));
    row.addChild(
        "td", TimeUtil.formatTime((long) localCHKFetchTimeAverageRT.currentValue(), 2, true));
    row.addChild(
        "td", TimeUtil.formatTime((long) localSSKFetchTimeAverageBulk.currentValue(), 2, true));
    row.addChild(
        "td", TimeUtil.formatTime((long) localSSKFetchTimeAverageRT.currentValue(), 2, true));
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

  public void fillRemoteRequestHTLsBox(HTMLNode html, boolean realTime) {
    if (realTime) hourlyStatsRT.fillRemoteRequestHTLsBox(html);
    else hourlyStatsBulk.fillRemoteRequestHTLsBox(html);
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

  public void reportDatabaseJob(String jobType, long executionTimeMiliSeconds) {
    avgDatabaseJobExecutionTimes
        .computeIfAbsent(sanitizeDBJobType(jobType), k -> new TrivialRunningAverage())
        .report(executionTimeMiliSeconds);
  }

  public void reportMandatoryBackoff(
      String backoffType, long backoffTimeMilliSeconds, boolean realtime) {
    mandatoryBackoffStats.report(backoffType, backoffTimeMilliSeconds, realtime);
  }

  public void reportRoutingBackoff(
      String backoffType, long backoffTimeMilliSeconds, boolean realtime) {
    routingBackoffStats.report(backoffType, backoffTimeMilliSeconds, realtime);
  }

  public void reportTransferBackoff(
      String backoffType, long backoffTimeMilliSeconds, boolean realtime) {
    transferBackoffStats.report(backoffType, backoffTimeMilliSeconds, realtime);
  }

  /**
   * View of stats for CHK Store
   *
   * @return stats for CHK Store
   */
  public StoreLocationStats chkStoreStats() {
    return new StoreLocationStats() {
      @Override
      public double avgLocation() {
        return avgStoreCHKLocation.currentValue();
      }

      @Override
      public double avgSuccess() {
        return avgStoreCHKSuccess.currentValue();
      }

      @Override
      public double furthestSuccess() {
        return furthestStoreCHKSuccess;
      }

      @Override
      public double avgDist() {
        return Location.distance(node.getLocationManager().getLocation(), avgLocation());
      }

      @Override
      public double distanceStats() {
        return cappedDistance(avgStoreCHKLocation, node.getChkDatastore());
      }
    };
  }

  /**
   * View of stats for CHK Cache
   *
   * @return CHK cache stats
   */
  public StoreLocationStats chkCacheStats() {
    return new StoreLocationStats() {
      @Override
      public double avgLocation() {
        return avgCacheCHKLocation.currentValue();
      }

      @Override
      public double avgSuccess() {
        return avgCacheCHKSuccess.currentValue();
      }

      @Override
      public double furthestSuccess() {
        return furthestCacheCHKSuccess;
      }

      @Override
      public double avgDist() {
        return Location.distance(node.getLocationManager().getLocation(), avgLocation());
      }

      @Override
      public double distanceStats() {
        return cappedDistance(avgCacheCHKLocation, node.getChkDatacache());
      }
    };
  }

  /**
   * View of stats for CHK SlashdotCache
   *
   * @return CHK Slashdotcache stats
   */
  public StoreLocationStats chkSlashDotCacheStats() {
    return new StoreLocationStats() {
      @Override
      public double avgLocation() {
        return avgSlashdotCacheCHKLocation.currentValue();
      }

      @Override
      public double avgSuccess() {
        return avgSlashdotCacheCHKSucess.currentValue();
      }

      @Override
      public double furthestSuccess() {
        return furthestSlashdotCacheCHKSuccess;
      }

      @Override
      public double avgDist() {
        return Location.distance(node.getLocationManager().getLocation(), avgLocation());
      }

      @Override
      public double distanceStats() {
        return cappedDistance(avgSlashdotCacheCHKLocation, node.getChkSlashdotCache());
      }
    };
  }

  /**
   * View of stats for CHK ClientCache
   *
   * @return CHK ClientCache stats
   */
  public StoreLocationStats chkClientCacheStats() {
    return new StoreLocationStats() {
      @Override
      public double avgLocation() {
        return avgClientCacheCHKLocation.currentValue();
      }

      @Override
      public double avgSuccess() {
        return avgClientCacheCHKSuccess.currentValue();
      }

      @Override
      public double furthestSuccess() {
        return furthestClientCacheCHKSuccess;
      }

      @Override
      public double avgDist() {
        return Location.distance(node.getLocationManager().getLocation(), avgLocation());
      }

      @Override
      public double distanceStats() {
        return cappedDistance(avgClientCacheCHKLocation, node.getChkClientCache());
      }
    };
  }

  /**
   * View of stats for SSK Store
   *
   * @return stats for SSK Store
   */
  public StoreLocationStats sskStoreStats() {
    return new StoreLocationStats() {
      @Override
      public double avgLocation() {
        return avgStoreSSKLocation.currentValue();
      }

      @Override
      public double avgSuccess() {
        return avgStoreSSKSuccess.currentValue();
      }

      @Override
      public double furthestSuccess() {
        return furthestStoreSSKSuccess;
      }

      @Override
      public double avgDist() {
        return Location.distance(node.getLocationManager().getLocation(), avgLocation());
      }

      @Override
      public double distanceStats() {
        return cappedDistance(avgStoreSSKLocation, node.getSskDatastore());
      }
    };
  }

  /**
   * View of stats for SSK Cache
   *
   * @return SSK cache stats
   */
  public StoreLocationStats sskCacheStats() {
    return new StoreLocationStats() {
      @Override
      public double avgLocation() {
        return avgCacheSSKLocation.currentValue();
      }

      @Override
      public double avgSuccess() {
        return avgCacheSSKSuccess.currentValue();
      }

      @Override
      public double furthestSuccess() {
        return furthestCacheSSKSuccess;
      }

      @Override
      public double avgDist() {
        return Location.distance(node.getLocationManager().getLocation(), avgLocation());
      }

      @Override
      public double distanceStats() {
        return cappedDistance(avgCacheSSKLocation, node.getSskDatacache());
      }
    };
  }

  /**
   * View of stats for SSK SlashdotCache
   *
   * @return SSK Slashdotcache stats
   */
  public StoreLocationStats sskSlashDotCacheStats() {
    return new StoreLocationStats() {
      @Override
      public double avgLocation() {
        return avgSlashdotCacheSSKLocation.currentValue();
      }

      @Override
      public double avgSuccess() {
        return avgSlashdotCacheSSKSuccess.currentValue();
      }

      @Override
      public double furthestSuccess() {
        return furthestSlashdotCacheSSKSuccess;
      }

      @Override
      public double avgDist() {
        return Location.distance(node.getLocationManager().getLocation(), avgLocation());
      }

      @Override
      public double distanceStats() {
        return cappedDistance(avgSlashdotCacheSSKLocation, node.getSskSlashdotCache());
      }
    };
  }

  /**
   * View of stats for SSK ClientCache
   *
   * @return SSK ClientCache stats
   */
  public StoreLocationStats sskClientCacheStats() {
    return new StoreLocationStats() {
      @Override
      public double avgLocation() {
        return avgClientCacheSSKLocation.currentValue();
      }

      @Override
      public double avgSuccess() {
        return avgClientCacheSSKSuccess.currentValue();
      }

      @Override
      public double furthestSuccess() {
        return furthestClientCacheSSKSuccess;
      }

      @Override
      public double avgDist() {
        return Location.distance(node.getLocationManager().getLocation(), avgLocation());
      }

      @Override
      public double distanceStats() {
        return cappedDistance(avgClientCacheSSKLocation, node.getSskClientCache());
      }
    };
  }

  private double cappedDistance(DecayingKeyspaceAverage avgLocation, StoreCallback<?> store) {
    double cachePercent = 1.0 * avgLocation.countReports() / store.keyCount();
    // Cap the reported value at 100%, as the decaying average does not account beyond that anyway.
    if (cachePercent > 1.0) {
      cachePercent = 1.0;
    }
    return cachePercent;
  }

  /**
   * Aggregated timing statistics for a labeled activity.
   *
   * <p>Fields are immutable snapshots: {@link #count} (samples), {@link #avgTime} (mean duration in
   * milliseconds), and {@link #totalTime} (sum in milliseconds). Natural ordering sorts descending
   * by {@code totalTime}.
   */
  public static class TimedStats implements Comparable<TimedStats> {
    public final String keyStr;
    public final long count;
    public final long avgTime;
    public final long totalTime;

    public TimedStats(String myKeyStr, long myCount, long myAvgTime, long myTotalTime) {
      keyStr = myKeyStr;
      count = myCount;
      avgTime = myAvgTime;
      totalTime = myTotalTime;
    }

    @Override
    public int compareTo(TimedStats o) {
      return Long.compare(o.totalTime, totalTime);
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) return true;
      if (!(obj instanceof TimedStats other)) return false;
      return this.totalTime == other.totalTime;
    }

    @Override
    public int hashCode() {
      return Long.hashCode(totalTime);
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

  /** Returns timing stats for database job execution, grouped by sanitized job type. */
  @SuppressWarnings("unused")
  public TimedStats[] getDatabaseJobExecutionStatistics() {
    return getStatistics(avgDatabaseJobExecutionTimes);
  }

  /**
   * Parses a peer's load-stats message into a structured view.
   *
   * @param source the peer originating the message.
   * @param m the raw message to parse.
   * @return parsed peer load statistics.
   */
  public PeerLoadStats parseLoadStats(PeerNode source, Message m) {
    return new PeerLoadStats(source, m);
  }

  RunningRequestsSnapshot getRunningRequestsTo(PeerNode peerNode, boolean realTimeFlag) {
    return new RunningRequestsSnapshot(
        node.getTracker(), peerNode, true, false, outwardTransfersPerInsert(), realTimeFlag);
  }

  /**
   * Returns the current setting for treating local requests as remote when computing bandwidth
   * liability.
   */
  public boolean ignoreLocalVsRemoteBandwidthLiability() {
    return ignoreLocalVsRemoteBandwidthLiability;
  }

  private int totalAnnouncements;
  private int totalAnnounceForwards;

  /**
   * Records the number of references forwarded during an opennet announce from the given peer.
   *
   * @param forwardedRefs number of references forwarded.
   * @param source peer that originated the announce; used for seed-tracker updates.
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
      // Could add to stats page
    }
    OpennetManager om = node.getOpennet();
    if (om != null && source instanceof SeedClientPeerNode peerNode)
      om.getSeedTracker().completedAnnounce(peerNode, forwardedRefs);
  }

  /** Estimated transfers per announce, rounded up to at least 1. */
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
        node.getOutputBandwidthLimit() / 2; // Consider overhead; may include announcements
    // and that would cause problems!
    int inputPerSecond = node.getInputBandwidthLimit() / 2;
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

  public synchronized void endAnnouncement(long uid) {
    runningAnnouncements.remove(uid);
  }

  /**
   * Reports the throttled delay applied to a sent packet.
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

  /** If a peer's ping exceeds this threshold, consider it backed off. */
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

  /** Renders NLM delay and timeout fractions to HTML. */
  public void drawNewLoadManagementDelayTimes(HTMLNode content) {
    WaitingForSlots waitingSlots = node.getTracker().countRequestsWaitingForSlots();
    content
        .addChild("p")
        .addChild(
            "#",
            l10n(
                "slotsWaiting",
                new String[] {"local", "remote"},
                new String[] {
                  Integer.toString(waitingSlots.local), Integer.toString(waitingSlots.remote)
                }));
    HTMLNode table = content.addChild(HTML_TABLE, HTML_BORDER, "0");
    HTMLNode header = table.addChild("tr");
    header.addChild("th", l10n("delayTimes"));
    header.addChild("th", l10n("localHeader"));
    header.addChild("th", l10n("remoteHeader"));
    HTMLNode row = table.addChild("tr");
    row.addChild("th", l10n("realTimeHeader"));
    row.addChild("td", TimeUtil.formatTime((int) nlmDelayRTLocal.currentValue(), 2, true));
    row.addChild("td", TimeUtil.formatTime((int) nlmDelayRTRemote.currentValue(), 2, true));
    row = table.addChild("tr");
    row.addChild("th", l10n("bulkHeader"));
    row.addChild("td", TimeUtil.formatTime((int) nlmDelayBulkLocal.currentValue(), 2, true));
    row.addChild("td", TimeUtil.formatTime((int) nlmDelayBulkRemote.currentValue(), 2, true));

    synchronized (slotTimeoutsSync) {
      if (fatalTimeoutsInWaitLocal
              + fatalTimeoutsInWaitRemote
              + allocatedSlotLocal
              + allocatedSlotRemote
          > 0) {
        content.addChild("b", l10n("timeoutFractions"));
        table = content.addChild(HTML_TABLE, HTML_BORDER, "0");
        header = table.addChild("tr");
        header.addChild("th", l10n("localHeader"));
        header.addChild("th", l10n("remoteHeader"));
        row = table.addChild("tr");
        row.addChild(
            "td",
            this.fix3p3pct.format(
                ((double) fatalTimeoutsInWaitLocal)
                    / ((double) (fatalTimeoutsInWaitLocal + allocatedSlotLocal))));
        row.addChild(
            "td",
            this.fix3p3pct.format(
                ((double) fatalTimeoutsInWaitRemote)
                    / ((double) (fatalTimeoutsInWaitRemote + allocatedSlotRemote))));
      }
    }
  }

  private final Object slotTimeoutsSync = new Object();
  private long fatalTimeoutsInWaitLocal;
  private long fatalTimeoutsInWaitRemote;
  private long allocatedSlotLocal;
  private long allocatedSlotRemote;

  public void reportFatalTimeoutInWait(boolean local) {
    synchronized (slotTimeoutsSync) {
      if (local) fatalTimeoutsInWaitLocal++;
      else fatalTimeoutsInWaitRemote++;
    }
  }

  public void reportAllocatedSlot(boolean local) {
    synchronized (slotTimeoutsSync) {
      if (local) allocatedSlotLocal++;
      else allocatedSlotRemote++;
    }
  }

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
          // If we run it lazily, an attacker could trigger it, given that it's triggered rarely
          // in normal operation. Long term we probably want to get rid of this from the
          // production network, and just surveil a few "special" nodes which volunteer to have
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
            node.getTicker().queueTimedJob(this, rejectStatsUpdateInterval);
          }
        }
      };

  /** How many reports to require before returning a value for reject stats */
  private final int minReportsNoisyRejectStats;

  /** How often to update the reject stats */
  private final long rejectStatsUpdateInterval;

  /** If positive, the level of fuzz (size of 1 standard deviation for gauss in percent) to use */
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
  public final double randomNoise(final double input, final double sigma) {
    double multiplier = (node.getRandom().nextGaussian() * sigma) + 1.0;

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
  public final double getBandwidthLiabilityUsage() {
    long now = System.currentTimeMillis();
    long limit = getLimitSeconds(false);
    int transfersPerInsert = outwardTransfersPerInsert();
    RunningRequestsSnapshot requestsSnapshot =
        new RunningRequestsSnapshot(
            node.getTracker(), ignoreLocalVsRemoteBandwidthLiability, transfersPerInsert, false);
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
          .computeIfAbsent(backoffType, k -> new TrivialRunningAverage())
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

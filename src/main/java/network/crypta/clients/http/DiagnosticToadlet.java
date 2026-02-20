package network.crypta.clients.http;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.clients.fcp.DownloadRequestStatus;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.fcp.RequestStatus;
import network.crypta.clients.fcp.UploadDirRequestStatus;
import network.crypta.clients.fcp.UploadFileRequestStatus;
import network.crypta.config.SubConfig;
import network.crypta.fs.AppEnv;
import network.crypta.io.xfer.BlockReceiver;
import network.crypta.io.xfer.BlockTransmitter;
import network.crypta.l10n.BaseL10n;
import network.crypta.node.Node;
import network.crypta.node.NodeStats;
import network.crypta.node.OpennetManager;
import network.crypta.node.PeerManager;
import network.crypta.node.PeerNodeStatus;
import network.crypta.node.RequestTracker;
import network.crypta.node.Version;
import network.crypta.node.diagnostics.ThreadDiagnostics;
import network.crypta.node.diagnostics.threads.NodeThreadInfo;
import network.crypta.node.diagnostics.threads.NodeThreadSnapshot;
import network.crypta.node.stats.DataStoreInstanceType;
import network.crypta.node.stats.DataStoreStats;
import network.crypta.node.stats.StatsNotAvailableException;
import network.crypta.node.stats.StoreAccessStats;
import network.crypta.support.BandwidthStatsContainer;
import network.crypta.support.SizeUtil;
import network.crypta.support.api.HTTPRequest;

/**
 * Serves the `/diagnostic/` HTTP endpoint that aggregates runtime status for a running Crypta node.
 *
 * <p>This toadlet renders a plain-text snapshot that combines JVM resource details, datastore
 * sizes, success rates, bandwidth usage, peer health, update/runtime status, work queues, and
 * thread diagnostics into a single page intended for administrators. Callers typically access it
 * via the built-in web interface when troubleshooting connectivity, storage pressure, or
 * performance anomalies. The handler executes synchronously on the toadlet thread and consults live
 * {@link Node} services, so values reflect the moment of invocation rather than cached metrics.
 *
 * <p>The instance is tied to a specific node and reuses shared formatters to ensure stable numeric
 * output. No state is retained between requests beyond these formatters, making the class safe for
 * concurrent reads under the servlet-style contract imposed by {@link Toadlet}. Thread safety
 * relies on short synchronized sections around formatting to protect {@link DecimalFormat}
 * instances from concurrent use.
 *
 * <ul>
 *   <li>Gathers node, datastore, bandwidth, peer, queue, and thread information.
 *   <li>Requires full-access authentication before emitting diagnostics.
 *   <li>Designed for operational observability rather than end-user presentation.
 * </ul>
 *
 * @see network.crypta.clients.http.ToadletContext
 * @see Node
 */
public class DiagnosticToadlet extends Toadlet {

  /**
   * Relative path where this toadlet is mounted within the HTTP interface.
   *
   * <p>The value is shared with router configuration and should remain stable so bookmarked
   * diagnostic URLs and automated monitoring checks continue to resolve.
   */
  public static final String TOADLET_URL = "/diagnostic/";

  private static final String PATTERN_MEMORY = "memory";
  private static final String PATTERN_VERSION = "version";
  private static final String PATTERN_TOTAL = "total";
  private static final String PATTERN_PERCENT = "percent";
  private static final String STATISTICS_PREFIX = "StatisticsToadlet.";

  /**
   * Builds a diagnostic toadlet bound to the provided node and client plumbing.
   *
   * @param n live {@link Node} instance that exposes stats, peers, and diagnostics; must be
   *     non-null for correct operation.
   * @param fcp FCP server used to collect queue information and request statuses; expected to be
   *     initialized and running.
   * @param client HTTP client facade supplied to the superclass for response handling; reused for
   *     outbound interactions initiated by the toadlet.
   */
  protected DiagnosticToadlet(Node n, FCPServer fcp, HighLevelSimpleClient client) {
    super(client);
    this.node = n;
    this.fcp = fcp;
    stats = node.network().stats();
    peers = node.network().peers();
    /* copied from NodeL10n constructor. */
    baseL10n =
        new BaseL10n(
            "network/crypta/l10n/",
            "crypta.l10n.${lang}.properties",
            new File(".").getPath() + File.separator + "crypta.l10n.${lang}.override.properties",
            BaseL10n.LANGUAGE.ENGLISH);
  }

  /**
   * Handles authenticated GET requests for the diagnostic page and streams a textual snapshot of
   * node health.
   *
   * <p>The handler first enforces full-access permissions on the {@link ToadletContext}, then
   * refreshes bandwidth statistics and gathers a series of live metrics: version data, system
   * memory and CPU figures, datastore usage and success rates, activity counters, peer summaries,
   * bandwidth caps, queued requests, and thread diagnostics. Formatting occurs inside a
   * synchronized block to guard shared {@link DecimalFormat} instances. On success, it responds
   * with HTTP 200 and the assembled plaintext body; on failure it lets I/O and toadlet-specific
   * exceptions propagate to the caller for higher-level handling.
   *
   * @param uri request target; path should match {@link #path()} and query parameters are ignored.
   * @param request parsed HTTP request wrapper providing headers and authorization state; must not
   *     be {@code null}.
   * @param ctx toadlet context used for access control and writing the response; must be open for
   *     the duration of the call.
   * @throws ToadletContextClosedException if the client disconnects or the context closes before a
   *     response is written.
   * @throws IOException if reading from the request or writing the diagnostic output fails.
   * @throws RedirectException if the caller lacks permission and the framework triggers a redirect
   *     to the login or permissions page.
   */
  @Override
  public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    if (!ctx.checkFullAccess(this)) {
      return;
    }

    node.services()
        .clientCore()
        .getClientLayerPersister()
        .getBandwidthStatsPutter()
        .updateData(node);

    final SubConfig nodeConfig = node.getConfig().get("node");

    StringBuilder textBuilder = new StringBuilder();

    // Synchronize to avoid problems with DecimalFormat.
    synchronized (this) {
      appendNodeVersion(textBuilder);
      appendSystemInformation(textBuilder);
      appendStoreSize(textBuilder);
      appendActivity(textBuilder);
      appendPeerStatistics(textBuilder);
      appendBandwidth(textBuilder, nodeConfig);
      appendQueue(textBuilder);
      appendThreadDiagnostics(textBuilder);
    }

    this.writeTextReply(ctx, 200, "OK", textBuilder.toString());
  }

  private void appendNodeVersion(StringBuilder textBuilder) {
    textBuilder.append("Crypta Version:\n");
    textBuilder
        .append(
            baseL10n.getString(
                "WelcomeToadlet.version",
                new String[] {"fullVersion", "build", "rev"},
                new String[] {
                  Long.toString(Version.currentBuildNumber()),
                  Integer.toString(Version.currentBuildNumber()),
                  Version.gitRevision()
                }))
        .append("\n");
  }

  private void appendSystemInformation(StringBuilder textBuilder) {
    textBuilder.append("System Information:\n");
    Runtime runtime = Runtime.getRuntime();
    long freeMemory = runtime.freeMemory();
    long totalMemory = runtime.totalMemory();
    long maxMemory = runtime.maxMemory();
    long usedJavaMem = totalMemory - freeMemory;
    int availableCpus = runtime.availableProcessors();
    int threadCount = stats.getActiveThreadCount();
    textBuilder
        .append(
            statisticsL10n("usedMemory", PATTERN_MEMORY, SizeUtil.formatSize(usedJavaMem, true)))
        .append("\n");
    textBuilder
        .append(
            statisticsL10n("allocMemory", PATTERN_MEMORY, SizeUtil.formatSize(totalMemory, true)))
        .append("\n");
    textBuilder
        .append(statisticsL10n("maxMemory", PATTERN_MEMORY, SizeUtil.formatSize(maxMemory, true)))
        .append("\n");
    textBuilder
        .append(
            statisticsL10n(
                "threads",
                new String[] {"running", "max"},
                new String[] {
                  thousandPoint.format(threadCount), Integer.toString(stats.getThreadLimit())
                }))
        .append("\n");
    textBuilder
        .append(statisticsL10n("cpus", "count", Integer.toString(availableCpus)))
        .append("\n");
    textBuilder
        .append(statisticsL10n("javaVersion", PATTERN_VERSION, System.getProperty("java.version")))
        .append("\n");
    textBuilder
        .append(statisticsL10n("jvmVendor", "vendor", System.getProperty("java.vendor")))
        .append("\n");
    textBuilder
        .append(statisticsL10n("jvmName", "name", System.getProperty("java.vm.name")))
        .append("\n");
    textBuilder
        .append(
            statisticsL10n("jvmVersion", PATTERN_VERSION, System.getProperty("java.vm.version")))
        .append("\n");
    textBuilder.append(statisticsL10n("osName", "name", new AppEnv().osNameRaw())).append("\n");
    textBuilder
        .append(statisticsL10n("osVersion", PATTERN_VERSION, System.getProperty("os.version")))
        .append("\n");
    textBuilder
        .append(statisticsL10n("osArch", "arch", System.getProperty("os.arch")))
        .append("\n");
    textBuilder.append("\n");
  }

  private void appendStoreSize(StringBuilder textBuilder) {
    textBuilder.append("Store Size:\n");
    Map<DataStoreInstanceType, DataStoreStats> storeStats = node.storage().getDataStoreStats();
    for (Map.Entry<DataStoreInstanceType, DataStoreStats> entry : storeStats.entrySet()) {
      DataStoreInstanceType instance = entry.getKey();
      DataStoreStats storeStatsEntry = entry.getValue();
      StoreAccessStats sessionAccess = storeStatsEntry.getSessionAccessStats();
      StoreAccessStats totalAccess = getTotalAccessStats(storeStatsEntry);
      textBuilder
          .append(statisticsL10n(instance.store.name()))
          .append(": (")
          .append(statisticsL10n(instance.key.name()))
          .append(")\n");
      textBuilder
          .append("  ")
          .append(statisticsL10n("keys"))
          .append(": ")
          .append(thousandPoint.format(storeStatsEntry.keys()))
          .append("\n");
      textBuilder
          .append("  ")
          .append(statisticsL10n("capacity"))
          .append(": ")
          .append(thousandPoint.format(storeStatsEntry.capacity()))
          .append("\n");
      textBuilder
          .append("  ")
          .append(statisticsL10n("datasize"))
          .append(": ")
          .append(SizeUtil.formatSize(storeStatsEntry.dataSize()))
          .append("\n");
      textBuilder
          .append("  ")
          .append(statisticsL10n("utilization"))
          .append(": ")
          .append(fix3p1pct.format(storeStatsEntry.utilization()))
          .append("\n");
      textBuilder
          .append("  ")
          .append(statisticsL10n("readRequests"))
          .append(": ")
          .append(thousandPoint.format(sessionAccess.readRequests()))
          .append(
              totalAccess == null
                  ? ""
                  : (" (" + thousandPoint.format(totalAccess.readRequests()) + ")"))
          .append("\n");
      textBuilder
          .append("  ")
          .append(statisticsL10n("successfulReads"))
          .append(": ")
          .append(thousandPoint.format(sessionAccess.successfulReads()))
          .append(
              totalAccess == null
                  ? ""
                  : (" (" + thousandPoint.format(totalAccess.successfulReads()) + ")"))
          .append("\n");
      appendSuccessRates(textBuilder, sessionAccess, totalAccess);
    }
    textBuilder.append("\n");
  }

  private StoreAccessStats getTotalAccessStats(DataStoreStats storeStatsEntry) {
    try {
      return storeStatsEntry.getTotalAccessStats();
    } catch (StatsNotAvailableException _) {
      return null;
    }
  }

  private void appendSuccessRates(
      StringBuilder textBuilder, StoreAccessStats sessionAccess, StoreAccessStats totalAccess) {
    try {
      textBuilder.append(fix1p4.format(sessionAccess.successRate())).append("%");
    } catch (StatsNotAvailableException _) {
      textBuilder.append("\n");
      return;
    }
    try {
      appendTotalSuccessRate(textBuilder, totalAccess);
    } catch (StatsNotAvailableException _) {
      // Ignore failures from total stats so we still show the session success rate.
    }
    textBuilder.append("\n");
  }

  private void appendTotalSuccessRate(StringBuilder textBuilder, StoreAccessStats totalAccess)
      throws StatsNotAvailableException {
    if (totalAccess == null) {
      return;
    }
    textBuilder.append(" (").append(fix1p4.format(totalAccess.successRate())).append("%)");
  }

  private void appendActivity(StringBuilder textBuilder) {
    textBuilder.append("Activity:\n");
    RequestTracker tracker = node.routing().tracker();
    int numLocalCHKInserts = tracker.getNumLocalCHKInserts();
    int numRemoteCHKInserts = tracker.getNumRemoteCHKInserts();
    int numLocalSSKInserts = tracker.getNumLocalSSKInserts();
    int numRemoteSSKInserts = tracker.getNumRemoteSSKInserts();
    int numLocalCHKRequests = tracker.getNumLocalCHKRequests();
    int numRemoteCHKRequests = tracker.getNumRemoteCHKRequests();
    int numLocalSSKRequests = tracker.getNumLocalSSKRequests();
    int numRemoteSSKRequests = tracker.getNumRemoteSSKRequests();
    int numTransferringRequests = tracker.getNumTransferringRequestSenders();
    int numTransferringRequestHandlers = tracker.getNumTransferringRequestHandlers();
    int numCHKOfferReplies = tracker.getNumCHKOfferReplies();
    int numSSKOfferReplies = tracker.getNumSSKOfferReplies();
    int numCHKRequests = numLocalCHKRequests + numRemoteCHKRequests;
    int numSSKRequests = numLocalSSKRequests + numRemoteSSKRequests;
    int numCHKInserts = numLocalCHKInserts + numRemoteCHKInserts;
    int numSSKInserts = numLocalSSKInserts + numRemoteSSKInserts;
    if ((numTransferringRequests == 0)
        && (numCHKRequests == 0)
        && (numSSKRequests == 0)
        && (numCHKInserts == 0)
        && (numSSKInserts == 0)
        && (numTransferringRequestHandlers == 0)
        && (numCHKOfferReplies == 0)
        && (numSSKOfferReplies == 0)) {
      textBuilder.append(statisticsL10n("noRequests")).append("\n\n");
      return;
    }
    appendActivityLine(
        textBuilder,
        numCHKInserts > 0 || numSSKInserts > 0,
        "activityInserts",
        new String[] {"CHKhandlers", "SSKhandlers", "local"},
        new String[] {
          Integer.toString(numCHKInserts),
          Integer.toString(numSSKInserts),
          numLocalCHKInserts + "/" + numLocalSSKInserts
        });
    appendActivityLine(
        textBuilder,
        numCHKRequests > 0 || numSSKRequests > 0,
        "activityRequests",
        new String[] {"CHKhandlers", "SSKhandlers", "local"},
        new String[] {
          Integer.toString(numCHKRequests),
          Integer.toString(numSSKRequests),
          numLocalCHKRequests + "/" + numLocalSSKRequests
        });
    appendActivityLine(
        textBuilder,
        numTransferringRequests > 0 || numTransferringRequestHandlers > 0,
        "transferringRequests",
        new String[] {"senders", "receivers", "turtles"},
        new String[] {
          Integer.toString(numTransferringRequests),
          Integer.toString(numTransferringRequestHandlers),
          "0"
        });
    appendActivityLine(
        textBuilder,
        numCHKOfferReplies > 0 || numSSKOfferReplies > 0,
        "offerReplys",
        new String[] {"chk", "ssk"},
        new String[] {Integer.toString(numCHKOfferReplies), Integer.toString(numSSKOfferReplies)});
    textBuilder
        .append(
            statisticsL10n(
                "runningBlockTransfers",
                new String[] {"sends", "receives"},
                new String[] {
                  Integer.toString(BlockTransmitter.getRunningSends()),
                  Integer.toString(BlockReceiver.getRunningReceives())
                }))
        .append("\n\n");
  }

  private void appendActivityLine(
      StringBuilder textBuilder,
      boolean shouldAppend,
      String key,
      String[] patterns,
      String[] values) {
    if (shouldAppend) {
      textBuilder.append(statisticsL10n(key, patterns, values)).append("\n");
    }
  }

  private void appendPeerStatistics(StringBuilder textBuilder) {
    textBuilder.append("Peer Statistics:\n");
    PeerNodeStatus[] peerNodeStatuses = peers.statusBook().getPeerNodeStatuses(true);
    Arrays.sort(peerNodeStatuses, Comparator.comparingInt(PeerNodeStatus::getStatusValue));
    appendPeerCount(
        textBuilder, peerNodeStatuses, PeerManager.PEER_NODE_STATUS_CONNECTED, "connectedShort");
    appendPeerCount(
        textBuilder,
        peerNodeStatuses,
        PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF,
        "backedOffShort");
    appendPeerCount(
        textBuilder, peerNodeStatuses, PeerManager.PEER_NODE_STATUS_TOO_NEW, "tooNewShort");
    appendPeerCount(
        textBuilder, peerNodeStatuses, PeerManager.PEER_NODE_STATUS_TOO_OLD, "tooOldShort");
    appendPeerCount(
        textBuilder,
        peerNodeStatuses,
        PeerManager.PEER_NODE_STATUS_DISCONNECTED,
        "notConnectedShort");
    appendPeerCount(
        textBuilder,
        peerNodeStatuses,
        PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED,
        "neverConnectedShort");
    appendPeerCount(
        textBuilder, peerNodeStatuses, PeerManager.PEER_NODE_STATUS_DISABLED, "disabledShort");
    appendPeerCount(
        textBuilder, peerNodeStatuses, PeerManager.PEER_NODE_STATUS_BURSTING, "burstingShort");
    appendPeerCount(
        textBuilder, peerNodeStatuses, PeerManager.PEER_NODE_STATUS_LISTENING, "listeningShort");
    appendPeerCount(
        textBuilder, peerNodeStatuses, PeerManager.PEER_NODE_STATUS_LISTEN_ONLY, "listenOnlyShort");
    appendPeerCount(
        textBuilder,
        peerNodeStatuses,
        PeerManager.PEER_NODE_STATUS_CLOCK_PROBLEM,
        "clockProblemShort");
    appendPeerCount(
        textBuilder, peerNodeStatuses, PeerManager.PEER_NODE_STATUS_CONN_ERROR, "connErrorShort");
    appendPeerCount(
        textBuilder,
        peerNodeStatuses,
        PeerManager.PEER_NODE_STATUS_DISCONNECTING,
        "disconnectingShort");
    appendSeedCounts(textBuilder, peerNodeStatuses);
    appendPeerCount(
        textBuilder,
        peerNodeStatuses,
        PeerManager.PEER_NODE_STATUS_ROUTING_DISABLED,
        "routingDisabledShort");
    appendPeerCount(
        textBuilder,
        peerNodeStatuses,
        PeerManager.PEER_NODE_STATUS_NO_LOAD_STATS,
        "noLoadStatsShort");
    appendOpennetTargets(textBuilder);
    textBuilder.append("\n");
  }

  private void appendSeedCounts(StringBuilder textBuilder, PeerNodeStatus[] peerNodeStatuses) {
    int numberOfSeedServers = getCountSeedServers(peerNodeStatuses);
    int numberOfSeedClients = getCountSeedClients(peerNodeStatuses);
    if (numberOfSeedServers > 0) {
      textBuilder
          .append(darknetL10n("seedServersShort"))
          .append(": ")
          .append(numberOfSeedServers)
          .append("\n");
    }
    if (numberOfSeedClients > 0) {
      textBuilder
          .append(darknetL10n("seedClientsShort"))
          .append(": ")
          .append(numberOfSeedClients)
          .append("\n");
    }
  }

  private void appendPeerCount(
      StringBuilder textBuilder, PeerNodeStatus[] peerNodeStatuses, int status, String key) {
    int count = getPeerStatusCount(peerNodeStatuses, status);
    if (count > 0) {
      textBuilder.append(darknetL10n(key)).append(": ").append(count).append("\n");
    }
  }

  private void appendOpennetTargets(StringBuilder textBuilder) {
    OpennetManager opennetManager = node.network().opennet();
    if (opennetManager != null) {
      textBuilder
          .append(statisticsL10n("maxTotalPeers"))
          .append(": ")
          .append(opennetManager.getNumberOfConnectedPeersToAimIncludingDarknet())
          .append("\n");
      textBuilder
          .append(statisticsL10n("maxOpennetPeers"))
          .append(": ")
          .append(opennetManager.getNumberOfConnectedPeersToAim())
          .append("\n");
    }
  }

  private void appendBandwidth(StringBuilder textBuilder, SubConfig nodeConfig) {
    textBuilder.append("Bandwidth:\n");
    long[] total = node.network().collector().getTotalIO();
    if (total[0] == 0 || total[1] == 0) {
      textBuilder.append("bandwidth error\n\n");
      return;
    }
    long now = System.currentTimeMillis();
    long nodeUptimeSeconds = (now - node.getStartupTime()) / 1000;
    long totalOutputRate = total[0] / nodeUptimeSeconds;
    long totalInputRate = total[1] / nodeUptimeSeconds;
    long totalPayload = node.getTotalPayloadSent();
    long totalPayloadRate = totalPayload / nodeUptimeSeconds;
    if (node.services().clientCore() == null) {
      throw new NullPointerException();
    }
    BandwidthStatsContainer bandwidthStats =
        node.services()
            .clientCore()
            .getClientLayerPersister()
            .getBandwidthStatsPutter()
            .getLatestBWData();
    if (bandwidthStats == null) {
      throw new NullPointerException();
    }
    long overallTotalOut = bandwidthStats.getTotalBytesOut();
    long overallTotalIn = bandwidthStats.getTotalBytesIn();
    int payloadPercent = (int) (100 * totalPayload / total[0]);
    long[] rate = node.network().stats().getNodeIOStats();
    long delta = (rate[5] - rate[2]) / 1000;
    appendInstantaneousRates(textBuilder, nodeConfig, rate, delta);
    long[] sessionRates = new long[] {totalInputRate, totalOutputRate, totalPayloadRate};
    long[] overallTotals = new long[] {overallTotalIn, overallTotalOut};
    BandwidthSessionData sessionData =
        new BandwidthSessionData(total, totalPayload, sessionRates, payloadPercent, overallTotals);
    appendSessionTotals(textBuilder, sessionData);
    appendCategoryBreakdown(textBuilder, total, totalPayload);
    double sentOverheadPerSecond = node.network().stats().getSentOverheadPerSecond();
    textBuilder
        .append(
            statisticsL10n(
                "totalOverhead",
                new String[] {"rate", PATTERN_PERCENT},
                new String[] {
                  SizeUtil.formatSize((long) sentOverheadPerSecond),
                  Integer.toString((int) ((100 * sentOverheadPerSecond) / totalOutputRate))
                }))
        .append("\n\n");
  }

  private void appendInstantaneousRates(
      StringBuilder textBuilder, SubConfig nodeConfig, long[] rate, long delta) {
    if (delta <= 0) {
      return;
    }
    long outputRate = (rate[3] - rate[0]) / delta;
    long inputRate = (rate[4] - rate[1]) / delta;
    int outputBandwidthLimit = nodeConfig.getInt("outputBandwidthLimit");
    int inputBandwidthLimit = nodeConfig.getInt("inputBandwidthLimit");
    if (inputBandwidthLimit == -1) {
      inputBandwidthLimit = outputBandwidthLimit * 4;
    }
    textBuilder
        .append(
            statisticsL10n(
                "inputRate",
                new String[] {"rate", "max"},
                new String[] {
                  SizeUtil.formatSize(inputRate, true),
                  SizeUtil.formatSize(inputBandwidthLimit, true)
                }))
        .append("\n");
    textBuilder
        .append(
            statisticsL10n(
                "outputRate",
                new String[] {"rate", "max"},
                new String[] {
                  SizeUtil.formatSize(outputRate, true),
                  SizeUtil.formatSize(outputBandwidthLimit, true)
                }))
        .append("\n");
  }

  private void appendSessionTotals(StringBuilder textBuilder, BandwidthSessionData sessionData) {
    textBuilder
        .append(
            statisticsL10n(
                "totalInputSession",
                new String[] {PATTERN_TOTAL, "rate"},
                new String[] {
                  SizeUtil.formatSize(sessionData.total[1], true),
                  SizeUtil.formatSize(sessionData.sessionRates[0], true)
                }))
        .append("\n");
    textBuilder
        .append(
            statisticsL10n(
                "totalOutputSession",
                new String[] {PATTERN_TOTAL, "rate"},
                new String[] {
                  SizeUtil.formatSize(sessionData.total[0], true),
                  SizeUtil.formatSize(sessionData.sessionRates[1], true)
                }))
        .append("\n");
    textBuilder
        .append(
            statisticsL10n(
                "payloadOutput",
                new String[] {PATTERN_TOTAL, "rate", PATTERN_PERCENT},
                new String[] {
                  SizeUtil.formatSize(sessionData.totalPayload, true),
                  SizeUtil.formatSize(sessionData.sessionRates[2], true),
                  Integer.toString(sessionData.payloadPercent)
                }))
        .append("\n");
    textBuilder
        .append(
            statisticsL10n(
                "totalInput",
                new String[] {PATTERN_TOTAL},
                new String[] {SizeUtil.formatSize(sessionData.overallTotals[0], true)}))
        .append("\n");
    textBuilder
        .append(
            statisticsL10n(
                "totalOutput",
                new String[] {PATTERN_TOTAL},
                new String[] {SizeUtil.formatSize(sessionData.overallTotals[1], true)}))
        .append("\n");
  }

  private static final class BandwidthSessionData {
    private final long[] total;
    private final long totalPayload;
    private final long[] sessionRates;
    private final int payloadPercent;
    private final long[] overallTotals;

    BandwidthSessionData(
        long[] total,
        long totalPayload,
        long[] sessionRates,
        int payloadPercent,
        long[] overallTotals) {
      this.total = total;
      this.totalPayload = totalPayload;
      this.sessionRates = sessionRates;
      this.payloadPercent = payloadPercent;
      this.overallTotals = overallTotals;
    }
  }

  private void appendCategoryBreakdown(StringBuilder textBuilder, long[] total, long totalPayload) {
    long totalBytesSentCHKRequests = node.network().stats().getCHKRequestTotalBytesSent();
    long totalBytesSentSSKRequests = node.network().stats().getSSKRequestTotalBytesSent();
    long totalBytesSentCHKInserts = node.network().stats().getCHKInsertTotalBytesSent();
    long totalBytesSentSSKInserts = node.network().stats().getSSKInsertTotalBytesSent();
    long totalBytesSentOfferedKeys = node.network().stats().getOfferedKeysTotalBytesSent();
    long totalBytesSendOffers = node.network().stats().getOffersSentBytesSent();
    long totalBytesSentSwapOutput = node.network().stats().getSwappingTotalBytesSent();
    long totalBytesSentAuth = node.network().stats().getTotalAuthBytesSent();
    long totalBytesSentAckOnly = node.network().stats().getNotificationOnlyPacketsSentBytes();
    long totalBytesSentResends = node.network().stats().getResendBytesSent();
    long totalBytesSentUOM = node.network().stats().getUOMBytesSent();
    long totalBytesSentAnnounce = node.network().stats().getAnnounceBytesSent();
    long totalBytesSentAnnouncePayload = node.network().stats().getAnnounceBytesPayloadSent();
    long totalBytesSentRoutingStatus = node.network().stats().getRoutingStatusBytes();
    long totalBytesSentNetworkColoring = node.network().stats().getNetworkColoringSentBytes();
    long totalBytesSentPing = node.network().stats().getPingSentBytes();
    long totalBytesSentProbeRequest = node.network().stats().getProbeRequestSentBytes();
    long totalBytesSentRouted = node.network().stats().getRoutedMessageSentBytes();
    long totalBytesSentDisconn = node.network().stats().getDisconnBytesSent();
    long totalBytesSentInitial = node.network().stats().getInitialMessagesBytesSent();
    long totalBytesSentChangedIP = node.network().stats().getChangedIPBytesSent();
    long totalBytesSentNodeToNode = node.network().stats().getNodeToNodeBytesSent();
    long totalBytesSentAllocationNotices = node.network().stats().getAllocationNoticesBytesSent();
    long totalBytesSentFOAF = node.network().stats().getFOAFBytesSent();
    long totalBytesSentRemaining =
        total[0]
            - (totalPayload
                + totalBytesSentCHKRequests
                + totalBytesSentSSKRequests
                + totalBytesSentCHKInserts
                + totalBytesSentSSKInserts
                + totalBytesSentOfferedKeys
                + totalBytesSendOffers
                + totalBytesSentSwapOutput
                + totalBytesSentAuth
                + totalBytesSentAckOnly
                + totalBytesSentResends
                + totalBytesSentUOM
                + totalBytesSentAnnounce
                + totalBytesSentRoutingStatus
                + totalBytesSentNetworkColoring
                + totalBytesSentPing
                + totalBytesSentProbeRequest
                + totalBytesSentRouted
                + totalBytesSentDisconn
                + totalBytesSentInitial
                + totalBytesSentChangedIP
                + totalBytesSentNodeToNode
                + totalBytesSentAllocationNotices
                + totalBytesSentFOAF);
    textBuilder
        .append(
            statisticsL10n(
                "requestOutput",
                new String[] {"chk", "ssk"},
                new String[] {
                  SizeUtil.formatSize(totalBytesSentCHKRequests, true),
                  SizeUtil.formatSize(totalBytesSentSSKRequests, true)
                }))
        .append("\n");
    textBuilder
        .append(
            statisticsL10n(
                "insertOutput",
                new String[] {"chk", "ssk"},
                new String[] {
                  SizeUtil.formatSize(totalBytesSentCHKInserts, true),
                  SizeUtil.formatSize(totalBytesSentSSKInserts, true)
                }))
        .append("\n");
    textBuilder
        .append(
            statisticsL10n(
                "offeredKeyOutput",
                new String[] {PATTERN_TOTAL, "offered"},
                new String[] {
                  SizeUtil.formatSize(totalBytesSentOfferedKeys, true),
                  SizeUtil.formatSize(totalBytesSendOffers, true)
                }))
        .append("\n");
    textBuilder
        .append(
            statisticsL10n(
                "swapOutput", PATTERN_TOTAL, SizeUtil.formatSize(totalBytesSentSwapOutput, true)))
        .append("\n");
    textBuilder
        .append(
            statisticsL10n(
                "authBytes", PATTERN_TOTAL, SizeUtil.formatSize(totalBytesSentAuth, true)))
        .append("\n");
    textBuilder
        .append(
            statisticsL10n(
                "ackOnlyBytes", PATTERN_TOTAL, SizeUtil.formatSize(totalBytesSentAckOnly, true)))
        .append("\n");
    textBuilder
        .append(
            statisticsL10n(
                "resendBytes",
                new String[] {PATTERN_TOTAL, PATTERN_PERCENT},
                new String[] {
                  SizeUtil.formatSize(totalBytesSentResends, true),
                  Long.toString((100 * totalBytesSentResends) / Math.max(1, total[0]))
                }))
        .append("\n");
    textBuilder
        .append(
            statisticsL10n("uomBytes", PATTERN_TOTAL, SizeUtil.formatSize(totalBytesSentUOM, true)))
        .append("\n");
    textBuilder
        .append(
            statisticsL10n(
                "announceBytes",
                new String[] {PATTERN_TOTAL, "payload"},
                new String[] {
                  SizeUtil.formatSize(totalBytesSentAnnounce, true),
                  SizeUtil.formatSize(totalBytesSentAnnouncePayload, true)
                }))
        .append("\n");
    textBuilder
        .append(
            statisticsL10n(
                "adminBytes",
                new String[] {"routingStatus", "disconn", "initial", "changedIP"},
                new String[] {
                  SizeUtil.formatSize(totalBytesSentRoutingStatus, true),
                  SizeUtil.formatSize(totalBytesSentDisconn, true),
                  SizeUtil.formatSize(totalBytesSentInitial, true),
                  SizeUtil.formatSize(totalBytesSentChangedIP, true)
                }))
        .append("\n");
    textBuilder
        .append(
            statisticsL10n(
                "debuggingBytes",
                new String[] {"netColoring", "ping", "probe", "routed"},
                new String[] {
                  SizeUtil.formatSize(totalBytesSentNetworkColoring, true),
                  SizeUtil.formatSize(totalBytesSentPing, true),
                  SizeUtil.formatSize(totalBytesSentProbeRequest, true),
                  SizeUtil.formatSize(totalBytesSentRouted, true)
                }))
        .append("\n");
    textBuilder
        .append(
            statisticsL10n(
                "nodeToNodeBytes",
                PATTERN_TOTAL,
                SizeUtil.formatSize(totalBytesSentNodeToNode, true)))
        .append("\n");
    textBuilder
        .append(
            statisticsL10n(
                "loadAllocationNoticesBytes",
                PATTERN_TOTAL,
                SizeUtil.formatSize(totalBytesSentAllocationNotices, true)))
        .append("\n");
    textBuilder
        .append(
            statisticsL10n(
                "foafBytes", PATTERN_TOTAL, SizeUtil.formatSize(totalBytesSentFOAF, true)))
        .append("\n");
    textBuilder
        .append(
            statisticsL10n(
                "unaccountedBytes",
                new String[] {PATTERN_TOTAL, PATTERN_PERCENT},
                new String[] {
                  SizeUtil.formatSize(totalBytesSentRemaining, true),
                  Integer.toString((int) (totalBytesSentRemaining * 100 / total[0]))
                }))
        .append("\n");
  }

  private void appendQueue(StringBuilder textBuilder) {
    textBuilder.append("Queue:\n");
    try {
      RequestStatus[] reqs = fcp.getGlobalRequests();
      if (reqs.length < 1) {
        textBuilder.append(baseL10n.getString("QueueToadlet.globalQueueIsEmpty")).append("\n");
      } else {
        appendQueueCounts(textBuilder, reqs);
      }
    } catch (PersistenceDisabledException _) {
      textBuilder.append("DatabaseDisabledException\n");
    }
    textBuilder.append("\n");
  }

  private void appendQueueCounts(StringBuilder textBuilder, RequestStatus[] reqs) {
    long totalQueuedDownload = 0;
    long totalQueuedUpload = 0;
    for (RequestStatus req : reqs) {
      if (req instanceof DownloadRequestStatus) {
        totalQueuedDownload++;
      } else if (req instanceof UploadFileRequestStatus || req instanceof UploadDirRequestStatus) {
        totalQueuedUpload++;
      }
    }
    textBuilder
        .append("Downloads Queued: ")
        .append(totalQueuedDownload)
        .append(" (")
        .append(totalQueuedDownload)
        .append(")\n");
    textBuilder
        .append("Uploads Queued: ")
        .append(totalQueuedUpload)
        .append(" (")
        .append(totalQueuedUpload)
        .append(")\n");
  }

  private void appendThreadDiagnostics(StringBuilder textBuilder) {
    if (node.isNodeDiagnosticsEnabled()) {
      textBuilder.append(threadsStats());
      textBuilder.append("\n");
    }
  }

  /**
   * Returns the HTTP path that maps to this toadlet within the embedded server.
   *
   * @return immutable path string beginning with a slash; callers do not take ownership.
   */
  @Override
  public String path() {
    return TOADLET_URL;
  }

  /**
   * Retrieves ThreadDiagnostics (through NodeDiagnostics) to display thread information (id, name,
   * group, % cpu, etc.).
   *
   * @return Thread information in tab separated format.
   */
  private StringBuilder threadsStats() {
    StringBuilder sb = new StringBuilder();

    ThreadDiagnostics threadDiagnostics = node.services().nodeDiagnostics().getThreadDiagnostics();

    NodeThreadSnapshot threadSnapshot = threadDiagnostics.getThreadSnapshot();

    double wallTime = TimeUnit.MILLISECONDS.toNanos(threadSnapshot.getInterval());

    List<NodeThreadInfo> threads = threadSnapshot.getThreads();
    threads.sort(Comparator.comparing(NodeThreadInfo::getCpuTime).reversed());

    sb.append("Threads (%d):%n".formatted(threads.size()));

    // Thread ID, Job ID, Name, Priority, Group (system, main), Status, % CPU
    sb.append(
        "%10s %15s %-90s %5s %10s %-20s %-5s%n"
            .formatted("Thread ID", "Job ID", "Name", "Prio.", "Group", "Status", "% CPU"));

    for (NodeThreadInfo thread : threads) {
      String line =
          "%10s %15s %-90s %5s %10s %-20s %.2f%n"
              .formatted(
                  thread.getId(),
                  thread.getJobId(),
                  thread.getName().substring(0, Math.min(90, thread.getName().length())),
                  thread.getPrio(),
                  thread.getGroupName().substring(0, Math.min(10, thread.getGroupName().length())),
                  thread.getState(),
                  thread.getCpuTime() / wallTime * 100);
      sb.append(line);
    }

    return sb;
  }

  private int getPeerStatusCount(PeerNodeStatus[] peerNodeStatuses, int status) {
    int count = 0;
    for (PeerNodeStatus peerNodeStatus : peerNodeStatuses) {
      if (!peerNodeStatus.recordStatus()) {
        continue;
      }
      if (peerNodeStatus.getStatusValue() == status) {
        count++;
      }
    }
    return count;
  }

  private int getCountSeedServers(PeerNodeStatus[] peerNodeStatuses) {
    int count = 0;
    for (PeerNodeStatus peerNodeStatus : peerNodeStatuses) {
      if (peerNodeStatus.isSeedServer()) {
        count++;
      }
    }
    return count;
  }

  private int getCountSeedClients(PeerNodeStatus[] peerNodeStatuses) {
    int count = 0;
    for (PeerNodeStatus peerNodeStatus : peerNodeStatuses) {
      if (peerNodeStatus.isSeedClient()) {
        count++;
      }
    }
    return count;
  }

  private String statisticsL10n(String key) {
    return baseL10n.getString(STATISTICS_PREFIX + key);
  }

  private String darknetL10n(String key) {
    return baseL10n.getString("DarknetConnectionsToadlet." + key);
  }

  private String statisticsL10n(String key, String pattern, String value) {
    return baseL10n.getString(
        STATISTICS_PREFIX + key, new String[] {pattern}, new String[] {value});
  }

  private String statisticsL10n(String key, String[] patterns, String[] values) {
    return baseL10n.getString(STATISTICS_PREFIX + key, patterns, values);
  }

  private final Node node;
  private final NodeStats stats;
  private final PeerManager peers;
  private final NumberFormat thousandPoint = NumberFormat.getInstance();
  private final FCPServer fcp;
  private final DecimalFormat fix1p4 = new DecimalFormat("0.0000");
  private final DecimalFormat fix3p1pct = new DecimalFormat("##0.0%");
  private final BaseL10n baseL10n;
}

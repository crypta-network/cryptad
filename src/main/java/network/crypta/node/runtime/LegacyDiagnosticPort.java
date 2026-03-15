package network.crypta.node.runtime;

import java.io.File;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.PersistentStatsPutter;
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
import network.crypta.node.NodeClientCore;
import network.crypta.node.NodeStats;
import network.crypta.node.OpennetManager;
import network.crypta.node.PeerManager;
import network.crypta.node.PeerNodeStatus;
import network.crypta.node.RequestTracker;
import network.crypta.node.Version;
import network.crypta.node.diagnostics.NodeDiagnostics;
import network.crypta.node.diagnostics.ThreadDiagnostics;
import network.crypta.node.diagnostics.threads.NodeThreadInfo;
import network.crypta.node.diagnostics.threads.NodeThreadSnapshot;
import network.crypta.node.stats.DataStoreInstanceType;
import network.crypta.node.stats.DataStoreStats;
import network.crypta.node.stats.StatsNotAvailableException;
import network.crypta.node.stats.StoreAccessStats;
import network.crypta.runtime.spi.DiagnosticPort;
import network.crypta.runtime.spi.DiagnosticReportSnapshot;
import network.crypta.runtime.spi.DiagnosticSectionSnapshot;
import network.crypta.support.BandwidthStatsContainer;
import network.crypta.support.SizeUtil;

/**
 * Legacy daemon-backed implementation of the runtime diagnostic-report SPI.
 *
 * <p>This adapter keeps the existing diagnostic traversal inside the daemon root module while
 * exposing only detached line-oriented report sections to higher layers. It preserves the legacy
 * `/diagnostic/` page's plain-text structure, queue aggregation, peer counting, bandwidth summary,
 * and thread-diagnostics formatting without leaking {@link Node}, {@link FCPServer}, request
 * status, or thread snapshot types across the runtime boundary.
 *
 * <p>The adapter is intentionally report-oriented for this slice. It does not define a reusable
 * metrics schema, and it does not perform HTTP access control. Callers request one snapshot per
 * render and serialize the returned sections as needed.
 */
final class LegacyDiagnosticPort implements DiagnosticPort {
  /** Placeholder name used by localized memory-oriented statistics strings. */
  private static final String PATTERN_MEMORY = "memory";

  /** Placeholder name used by localized version-oriented statistics strings. */
  private static final String PATTERN_VERSION = "version";

  /** Placeholder name used by localized total-value statistics strings. */
  private static final String PATTERN_TOTAL = "total";

  /** Placeholder name used by localized percentage-oriented statistics strings. */
  private static final String PATTERN_PERCENT = "percent";

  /** Prefix for statistics localization keys reused from the legacy HTTP page. */
  private static final String STATISTICS_PREFIX = "StatisticsToadlet.";

  /** Section title emitted before the version summary line. */
  private static final String VERSION_TITLE = "Crypta Version:";

  /** Section title emitted before JVM and operating-system details. */
  private static final String SYSTEM_INFORMATION_TITLE = "System Information:";

  /** Section title emitted before per-store capacity and access metrics. */
  private static final String STORE_SIZE_TITLE = "Store Size:";

  /** Section title emitted before current request-activity counters. */
  private static final String ACTIVITY_TITLE = "Activity:";

  /** Section title emitted before peer status and opennet target counts. */
  private static final String PEER_STATISTICS_TITLE = "Peer Statistics:";

  /** Section title emitted before bandwidth rates and traffic totals. */
  private static final String BANDWIDTH_TITLE = "Bandwidth:";

  /** Fallback line used when bandwidth data cannot be assembled safely. */
  private static final String BANDWIDTH_ERROR = "bandwidth error";

  /** Section title emitted before queue summary lines. */
  private static final String QUEUE_TITLE = "Queue:";

  /** Header row format for the legacy thread diagnostics table. */
  private static final String THREAD_HEADER_FORMAT = "%10s %15s %-90s %5s %10s %-20s %-5s";

  /** Data row format for the legacy thread diagnostics table. */
  private static final String THREAD_ROW_FORMAT = "%10s %15s %-90s %5s %10s %-20s %.2f";

  /** Legacy sentinel text used when the persistence database is unavailable. */
  private static final String DATABASE_DISABLED = "DatabaseDisabledException";

  /** Live daemon node traversed while building one detached diagnostic snapshot. */
  private final Node node;

  /** Live client core used for bandwidth persistence and FCP queue access. */
  private final NodeClientCore core;

  /** Cached node statistics view used by several report sections. */
  private final NodeStats stats;

  /** Cached peer manager used for the peer statistics section. */
  private final PeerManager peers;

  /** Shared integer formatter matching the legacy plaintext output style. */
  private final NumberFormat thousandPoint = NumberFormat.getInstance();

  /** Fixed-point formatter used for success-rate values. */
  private final DecimalFormat fix1p4 = new DecimalFormat("0.0000");

  /** Percentage formatter used for datastore utilization values. */
  private final DecimalFormat fix3p1pct = new DecimalFormat("##0.0%");

  /** English localization bundle reused from the legacy diagnostic page. */
  private final BaseL10n baseL10n;

  /**
   * Creates a daemon-backed diagnostic-report adapter.
   *
   * <p>The adapter keeps direct references to the live node and client core because the legacy
   * diagnostic page still aggregates several subsystems that are not exposed through narrower SPI
   * ports. Construction is side-effect free: it only caches frequently used daemon views and the
   * localization bundle needed to preserve the existing plaintext wording.
   *
   * @param node live daemon node whose runtime state will be traversed during snapshot creation
   * @param core live client core that exposes persistence and FCP endpoint access
   */
  LegacyDiagnosticPort(Node node, NodeClientCore core) {
    this.node = Objects.requireNonNull(node);
    this.core = Objects.requireNonNull(core);
    this.stats = node.network().stats();
    this.peers = node.network().peers();
    this.baseL10n =
        new BaseL10n(
            "network/crypta/l10n/",
            "crypta.l10n.${lang}.properties",
            new File(".").getPath() + File.separator + "crypta.l10n.${lang}.override.properties",
            BaseL10n.LANGUAGE.ENGLISH);
  }

  @Override
  public synchronized DiagnosticReportSnapshot snapshot() {
    refreshBandwidthStats();

    List<DiagnosticSectionSnapshot> sections = new ArrayList<>(8);
    sections.add(nodeVersionSection());
    sections.add(systemInformationSection());
    sections.add(storeSizeSection());
    sections.add(activitySection());
    sections.add(peerStatisticsSection());
    sections.add(bandwidthSection(node.getConfig().get("node")));
    sections.add(queueSection());

    DiagnosticSectionSnapshot threadDiagnostics = threadDiagnosticsSection();
    if (threadDiagnostics != null) {
      sections.add(threadDiagnostics);
    }

    return new DiagnosticReportSnapshot(sections);
  }

  /**
   * Refreshes persisted bandwidth statistics before report generation.
   *
   * <p>The legacy HTTP page attempted this refresh on every request, so the persisted totals stayed
   * current before the bandwidth section was rendered. This adapter preserves that behavior while
   * keeping it the best effort: runtime failures are ignored so the rest of the report can still be
   * produced.
   */
  private void refreshBandwidthStats() {
    try {
      PersistentStatsPutter statsPutter = core.getClientLayerPersister().getBandwidthStatsPutter();
      if (statsPutter != null) {
        statsPutter.updateData(node);
      }
    } catch (RuntimeException _) {
      // Keep the diagnostic snapshot best-effort if bandwidth persistence is unavailable.
    }
  }

  /**
   * Builds the version section exactly as the legacy page rendered it.
   *
   * @return detached section containing the version header and one localized version line
   */
  private DiagnosticSectionSnapshot nodeVersionSection() {
    return new DiagnosticSectionSnapshot(
        VERSION_TITLE,
        List.of(
            baseL10n.getString(
                "WelcomeToadlet.version",
                new String[] {"fullVersion", "build", "rev"},
                new String[] {
                  Long.toString(Version.currentBuildNumber()),
                  Integer.toString(Version.currentBuildNumber()),
                  Version.gitRevision()
                })));
  }

  /**
   * Builds the JVM and operating-system summary section.
   *
   * <p>The section mixes live runtime values with a few localized labels and ends with an empty
   * line, so the caller can preserve the historical spacing between top-level sections.
   *
   * @return detached section containing memory, thread, JVM, and OS summary lines
   */
  private DiagnosticSectionSnapshot systemInformationSection() {
    Runtime runtime = Runtime.getRuntime();
    long freeMemory = runtime.freeMemory();
    long totalMemory = runtime.totalMemory();
    long maxMemory = runtime.maxMemory();
    long usedJavaMem = totalMemory - freeMemory;

    List<String> lines = new ArrayList<>(10);
    lines.add(statisticsL10n("usedMemory", PATTERN_MEMORY, SizeUtil.formatSize(usedJavaMem, true)));
    lines.add(
        statisticsL10n("allocMemory", PATTERN_MEMORY, SizeUtil.formatSize(totalMemory, true)));
    lines.add(statisticsL10n("maxMemory", PATTERN_MEMORY, SizeUtil.formatSize(maxMemory, true)));
    lines.add(
        statisticsL10n(
            "threads",
            new String[] {"running", "max"},
            new String[] {
              thousandPoint.format(stats.getActiveThreadCount()),
              Integer.toString(stats.getThreadLimit())
            }));
    lines.add(statisticsL10n("cpus", "count", Integer.toString(runtime.availableProcessors())));
    lines.add(statisticsL10n("javaVersion", PATTERN_VERSION, System.getProperty("java.version")));
    lines.add(statisticsL10n("jvmVendor", "vendor", System.getProperty("java.vendor")));
    lines.add(statisticsL10n("jvmName", "name", System.getProperty("java.vm.name")));
    lines.add(statisticsL10n("jvmVersion", PATTERN_VERSION, System.getProperty("java.vm.version")));
    lines.add(statisticsL10n("osName", "name", new AppEnv().osNameRaw()));
    lines.add(statisticsL10n("osVersion", PATTERN_VERSION, System.getProperty("os.version")));
    lines.add(statisticsL10n("osArch", "arch", System.getProperty("os.arch")));
    lines.add("");
    return new DiagnosticSectionSnapshot(SYSTEM_INFORMATION_TITLE, lines);
  }

  /**
   * Builds the datastore capacity and access the summary section.
   *
   * <p>Each datastore instance contributes a fixed block of lines covering keys, capacity, data
   * size, utilization, read activity, successful reads, and the legacy bare success-rate line. The
   * method keeps the section ordering and line shape aligned with the pre-SPI diagnostic page.
   *
   * @return detached section containing one block of lines per datastore instance
   */
  private DiagnosticSectionSnapshot storeSizeSection() {
    List<String> lines = new ArrayList<>();
    Map<DataStoreInstanceType, DataStoreStats> storeStats = node.storage().getDataStoreStats();
    for (Map.Entry<DataStoreInstanceType, DataStoreStats> entry : storeStats.entrySet()) {
      DataStoreInstanceType instance = entry.getKey();
      DataStoreStats storeStatsEntry = entry.getValue();
      StoreAccessStats sessionAccess = storeStatsEntry.getSessionAccessStats();
      StoreAccessStats totalAccess = getTotalAccessStats(storeStatsEntry);

      lines.add(
          statisticsL10n(instance.store.name())
              + ": ("
              + statisticsL10n(instance.key.name())
              + ")");
      lines.add(
          "  " + statisticsL10n("keys") + ": " + thousandPoint.format(storeStatsEntry.keys()));
      lines.add(
          "  "
              + statisticsL10n("capacity")
              + ": "
              + thousandPoint.format(storeStatsEntry.capacity()));
      lines.add(
          "  "
              + statisticsL10n("datasize")
              + ": "
              + SizeUtil.formatSize(storeStatsEntry.dataSize()));
      lines.add(
          "  "
              + statisticsL10n("utilization")
              + ": "
              + fix3p1pct.format(storeStatsEntry.utilization()));
      lines.add(
          "  "
              + statisticsL10n("readRequests")
              + ": "
              + thousandPoint.format(sessionAccess.readRequests())
              + totalValue(totalAccess == null ? null : totalAccess.readRequests()));
      lines.add(
          "  "
              + statisticsL10n("successfulReads")
              + ": "
              + thousandPoint.format(sessionAccess.successfulReads())
              + totalValue(totalAccess == null ? null : totalAccess.successfulReads()));
      lines.add(successRateText(sessionAccess, totalAccess));
    }
    lines.add("");
    return new DiagnosticSectionSnapshot(STORE_SIZE_TITLE, lines);
  }

  /**
   * Resolves total access statistics when the backing store exposes them.
   *
   * <p>Some datastore implementations do not retain total access history. Those cases are treated
   * as absent rather than as hard failures, so the report can continue with session-only values.
   *
   * @param storeStatsEntry datastore statistics view for one logical store instance
   * @return total access statistics, or {@code null} when unavailable
   */
  private StoreAccessStats getTotalAccessStats(DataStoreStats storeStatsEntry) {
    try {
      return storeStatsEntry.getTotalAccessStats();
    } catch (StatsNotAvailableException _) {
      return null;
    }
  }

  /**
   * Formats the legacy success-rate line for one datastore block.
   *
   * <p>The returned text intentionally contains only the percentage value, optionally followed by
   * the total-history percentage in parentheses, because the historical diagnostic page emitted a
   * bare line rather than a labeled field here.
   *
   * @param sessionAccess session-scoped access statistics used for the primary percentage
   * @param totalAccess total-history access statistics, or {@code null} when unavailable
   * @return formatted success-rate line, or an empty string when no session rate exists
   */
  private String successRateText(StoreAccessStats sessionAccess, StoreAccessStats totalAccess) {
    StringBuilder text = new StringBuilder();
    try {
      text.append(fix1p4.format(sessionAccess.successRate())).append('%');
    } catch (StatsNotAvailableException _) {
      return "";
    }

    if (totalAccess == null) {
      return text.toString();
    }

    try {
      text.append(" (").append(fix1p4.format(totalAccess.successRate())).append("%)");
    } catch (StatsNotAvailableException _) {
      // Keep the session success rate when total stats are unavailable.
    }
    return text.toString();
  }

  /**
   * Formats an optional total-history value using the legacy parenthesized shape.
   *
   * @param value total-history numeric value, or {@code null} when no total should be shown
   * @return empty text when absent, otherwise a parenthesized formatted number
   */
  private String totalValue(Number value) {
    return value == null ? "" : " (" + thousandPoint.format(value) + ")";
  }

  /**
   * Builds the current request-activity section.
   *
   * <p>The legacy page collapses several request-tracker counters into a small set of localized
   * lines and emits a special no-requests message when every tracked count is zero. The section
   * always ends with a blank line to preserve report spacing.
   *
   * @return detached section containing request and block-transfer activity lines
   */
  private DiagnosticSectionSnapshot activitySection() {
    List<String> lines = new ArrayList<>();
    RequestTracker tracker = node.routing().tracker();
    int numLocalChkInserts = tracker.getNumLocalCHKInserts();
    int numRemoteChkInserts = tracker.getNumRemoteCHKInserts();
    int numLocalSskInserts = tracker.getNumLocalSSKInserts();
    int numRemoteSskInserts = tracker.getNumRemoteSSKInserts();
    int numLocalChkRequests = tracker.getNumLocalCHKRequests();
    int numRemoteChkRequests = tracker.getNumRemoteCHKRequests();
    int numLocalSskRequests = tracker.getNumLocalSSKRequests();
    int numRemoteSskRequests = tracker.getNumRemoteSSKRequests();
    int numTransferringRequests = tracker.getNumTransferringRequestSenders();
    int numTransferringRequestHandlers = tracker.getNumTransferringRequestHandlers();
    int numChkOfferReplies = tracker.getNumCHKOfferReplies();
    int numSskOfferReplies = tracker.getNumSSKOfferReplies();
    int numChkRequests = numLocalChkRequests + numRemoteChkRequests;
    int numSskRequests = numLocalSskRequests + numRemoteSskRequests;
    int numChkInserts = numLocalChkInserts + numRemoteChkInserts;
    int numSskInserts = numLocalSskInserts + numRemoteSskInserts;

    if ((numTransferringRequests == 0)
        && (numChkRequests == 0)
        && (numSskRequests == 0)
        && (numChkInserts == 0)
        && (numSskInserts == 0)
        && (numTransferringRequestHandlers == 0)
        && (numChkOfferReplies == 0)
        && (numSskOfferReplies == 0)) {
      lines.add(statisticsL10n("noRequests"));
      lines.add("");
      return new DiagnosticSectionSnapshot(ACTIVITY_TITLE, lines);
    }

    addActivityLine(
        lines,
        numChkInserts > 0 || numSskInserts > 0,
        "activityInserts",
        new String[] {"CHKhandlers", "SSKhandlers", "local"},
        new String[] {
          Integer.toString(numChkInserts),
          Integer.toString(numSskInserts),
          numLocalChkInserts + "/" + numLocalSskInserts
        });
    addActivityLine(
        lines,
        numChkRequests > 0 || numSskRequests > 0,
        "activityRequests",
        new String[] {"CHKhandlers", "SSKhandlers", "local"},
        new String[] {
          Integer.toString(numChkRequests),
          Integer.toString(numSskRequests),
          numLocalChkRequests + "/" + numLocalSskRequests
        });
    addActivityLine(
        lines,
        numTransferringRequests > 0 || numTransferringRequestHandlers > 0,
        "transferringRequests",
        new String[] {"senders", "receivers", "turtles"},
        new String[] {
          Integer.toString(numTransferringRequests),
          Integer.toString(numTransferringRequestHandlers),
          "0"
        });
    addActivityLine(
        lines,
        numChkOfferReplies > 0 || numSskOfferReplies > 0,
        "offerReplys",
        new String[] {"chk", "ssk"},
        new String[] {Integer.toString(numChkOfferReplies), Integer.toString(numSskOfferReplies)});
    lines.add(
        statisticsL10n(
            "runningBlockTransfers",
            new String[] {"sends", "receives"},
            new String[] {
              Integer.toString(BlockTransmitter.getRunningSends()),
              Integer.toString(BlockReceiver.getRunningReceives())
            }));
    lines.add("");
    return new DiagnosticSectionSnapshot(ACTIVITY_TITLE, lines);
  }

  /**
   * Adds one localized activity line when the related counters are non-zero.
   *
   * @param lines destination list for the rendered activity line
   * @param shouldAppend whether the line should be emitted for the current counters
   * @param key localization suffix used for the legacy activity message
   * @param patterns placeholder names expected by the localized template
   * @param values placeholder values to interpolate into the localized template
   */
  private void addActivityLine(
      List<String> lines, boolean shouldAppend, String key, String[] patterns, String[] values) {
    if (shouldAppend) {
      lines.add(statisticsL10n(key, patterns, values));
    }
  }

  /**
   * Builds the peer statistics section.
   *
   * <p>The section preserves the historical status ordering from the old toadlet, including seed
   * server and seed client counts plus opennet peer targets when opennet is active.
   *
   * @return detached section containing peer state counts and optional opennet targets
   */
  private DiagnosticSectionSnapshot peerStatisticsSection() {
    List<String> lines = new ArrayList<>();
    PeerNodeStatus[] peerNodeStatuses = peers.statusBook().getPeerNodeStatuses(true);
    Arrays.sort(peerNodeStatuses, Comparator.comparingInt(PeerNodeStatus::getStatusValue));

    addPeerCount(lines, peerNodeStatuses, PeerManager.PEER_NODE_STATUS_CONNECTED, "connectedShort");
    addPeerCount(
        lines, peerNodeStatuses, PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF, "backedOffShort");
    addPeerCount(lines, peerNodeStatuses, PeerManager.PEER_NODE_STATUS_TOO_NEW, "tooNewShort");
    addPeerCount(lines, peerNodeStatuses, PeerManager.PEER_NODE_STATUS_TOO_OLD, "tooOldShort");
    addPeerCount(
        lines, peerNodeStatuses, PeerManager.PEER_NODE_STATUS_DISCONNECTED, "notConnectedShort");
    addPeerCount(
        lines,
        peerNodeStatuses,
        PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED,
        "neverConnectedShort");
    addPeerCount(lines, peerNodeStatuses, PeerManager.PEER_NODE_STATUS_DISABLED, "disabledShort");
    addPeerCount(lines, peerNodeStatuses, PeerManager.PEER_NODE_STATUS_BURSTING, "burstingShort");
    addPeerCount(lines, peerNodeStatuses, PeerManager.PEER_NODE_STATUS_LISTENING, "listeningShort");
    addPeerCount(
        lines, peerNodeStatuses, PeerManager.PEER_NODE_STATUS_LISTEN_ONLY, "listenOnlyShort");
    addPeerCount(
        lines, peerNodeStatuses, PeerManager.PEER_NODE_STATUS_CLOCK_PROBLEM, "clockProblemShort");
    addPeerCount(
        lines, peerNodeStatuses, PeerManager.PEER_NODE_STATUS_CONN_ERROR, "connErrorShort");
    addPeerCount(
        lines, peerNodeStatuses, PeerManager.PEER_NODE_STATUS_DISCONNECTING, "disconnectingShort");
    appendSeedCounts(lines, peerNodeStatuses);
    addPeerCount(
        lines,
        peerNodeStatuses,
        PeerManager.PEER_NODE_STATUS_ROUTING_DISABLED,
        "routingDisabledShort");
    addPeerCount(
        lines, peerNodeStatuses, PeerManager.PEER_NODE_STATUS_NO_LOAD_STATS, "noLoadStatsShort");
    appendOpennetTargets(lines);
    lines.add("");
    return new DiagnosticSectionSnapshot(PEER_STATISTICS_TITLE, lines);
  }

  /**
   * Appends the legacy seed peer counts when present.
   *
   * @param lines destination list for rendered peer statistics
   * @param peerNodeStatuses peer snapshots from the status book
   */
  private void appendSeedCounts(List<String> lines, PeerNodeStatus[] peerNodeStatuses) {
    int numberOfSeedServers = countSeedServers(peerNodeStatuses);
    int numberOfSeedClients = countSeedClients(peerNodeStatuses);
    if (numberOfSeedServers > 0) {
      lines.add(darknetL10n("seedServersShort") + ": " + numberOfSeedServers);
    }
    if (numberOfSeedClients > 0) {
      lines.add(darknetL10n("seedClientsShort") + ": " + numberOfSeedClients);
    }
  }

  /**
   * Appends one peer-status line when at least one peer matches the requested status.
   *
   * @param lines destination list for rendered peer statistics
   * @param peerNodeStatuses peer snapshots from the status book
   * @param status legacy peer status constant to count
   * @param key localization suffix for the rendered line label
   */
  private void addPeerCount(
      List<String> lines, PeerNodeStatus[] peerNodeStatuses, int status, String key) {
    int count = peerStatusCount(peerNodeStatuses, status);
    if (count > 0) {
      lines.add(darknetL10n(key) + ": " + count);
    }
  }

  /**
   * Appends opennet target lines when the node currently runs opennet.
   *
   * @param lines destination list for rendered peer statistics
   */
  private void appendOpennetTargets(List<String> lines) {
    OpennetManager opennetManager = node.network().opennet();
    if (opennetManager != null) {
      lines.add(
          statisticsL10n("maxTotalPeers")
              + ": "
              + opennetManager.getNumberOfConnectedPeersToAimIncludingDarknet());
      lines.add(
          statisticsL10n("maxOpennetPeers")
              + ": "
              + opennetManager.getNumberOfConnectedPeersToAim());
    }
  }

  /**
   * Builds the bandwidth section.
   *
   * <p>The section combines instantaneous rates, session totals, persisted overall totals, and the
   * existing category breakdown. When required bandwidth data is missing, the method returns the
   * legacy fallback line instead of throwing.
   *
   * @param nodeConfig node configuration subset that exposes bandwidth limit settings
   * @return detached section containing rendered bandwidth lines
   */
  private DiagnosticSectionSnapshot bandwidthSection(SubConfig nodeConfig) {
    List<String> lines = new ArrayList<>();
    long[] total = node.network().collector().getTotalIO();
    if (total == null || total.length < 2 || total[0] == 0 || total[1] == 0) {
      lines.add(BANDWIDTH_ERROR);
      lines.add("");
      return new DiagnosticSectionSnapshot(BANDWIDTH_TITLE, lines);
    }

    long nodeUptimeSeconds =
        Math.max(1, (System.currentTimeMillis() - node.getStartupTime()) / 1000);
    long totalOutputRate = total[0] / nodeUptimeSeconds;
    long totalInputRate = total[1] / nodeUptimeSeconds;
    long totalPayload = node.getTotalPayloadSent();
    long totalPayloadRate = totalPayload / nodeUptimeSeconds;
    BandwidthStatsContainer bandwidthStats = latestBandwidthStats();
    if (bandwidthStats == null) {
      lines.add(BANDWIDTH_ERROR);
      lines.add("");
      return new DiagnosticSectionSnapshot(BANDWIDTH_TITLE, lines);
    }

    long overallTotalOut = bandwidthStats.getTotalBytesOut();
    long overallTotalIn = bandwidthStats.getTotalBytesIn();
    int payloadPercent = (int) (100 * totalPayload / Math.max(1, total[0]));
    long[] rate = node.network().stats().getNodeIOStats();
    long delta = (rate[5] - rate[2]) / 1000;
    appendInstantaneousRates(lines, nodeConfig, rate, delta);
    BandwidthSessionData sessionData =
        new BandwidthSessionData(
            total,
            totalPayload,
            new long[] {totalInputRate, totalOutputRate, totalPayloadRate},
            payloadPercent,
            new long[] {overallTotalIn, overallTotalOut});
    appendSessionTotals(lines, sessionData);
    appendCategoryBreakdown(lines, total, totalPayload);
    double sentOverheadPerSecond = node.network().stats().getSentOverheadPerSecond();
    lines.add(
        statisticsL10n(
            "totalOverhead",
            new String[] {"rate", PATTERN_PERCENT},
            new String[] {
              SizeUtil.formatSize((long) sentOverheadPerSecond),
              Integer.toString(
                  totalOutputRate == 0
                      ? 0
                      : (int) ((100 * sentOverheadPerSecond) / totalOutputRate))
            }));
    lines.add("");
    return new DiagnosticSectionSnapshot(BANDWIDTH_TITLE, lines);
  }

  /**
   * Reads the most recently persisted bandwidth totals.
   *
   * @return latest persisted bandwidth totals, or {@code null} when unavailable
   */
  private BandwidthStatsContainer latestBandwidthStats() {
    PersistentStatsPutter statsPutter = core.getClientLayerPersister().getBandwidthStatsPutter();
    return statsPutter == null ? null : statsPutter.getLatestBWData();
  }

  /**
   * Appends instantaneous input and output rate lines when the required sample window is valid.
   *
   * @param lines destination list for rendered bandwidth lines
   * @param nodeConfig node configuration subset that supplies bandwidth limits
   * @param rate rolling bandwidth sample array from node statistics
   * @param delta sample interval in seconds derived from the rolling sample timestamps
   */
  private void appendInstantaneousRates(
      List<String> lines, SubConfig nodeConfig, long[] rate, long delta) {
    if (rate == null || rate.length < 6 || delta <= 0 || nodeConfig == null) {
      return;
    }

    long outputRate = (rate[3] - rate[0]) / delta;
    long inputRate = (rate[4] - rate[1]) / delta;
    int outputBandwidthLimit = nodeConfig.getInt("outputBandwidthLimit");
    int inputBandwidthLimit = nodeConfig.getInt("inputBandwidthLimit");
    if (inputBandwidthLimit == -1) {
      inputBandwidthLimit = outputBandwidthLimit * 4;
    }

    lines.add(
        statisticsL10n(
            "inputRate",
            new String[] {"rate", "max"},
            new String[] {
              SizeUtil.formatSize(inputRate, true), SizeUtil.formatSize(inputBandwidthLimit, true)
            }));
    lines.add(
        statisticsL10n(
            "outputRate",
            new String[] {"rate", "max"},
            new String[] {
              SizeUtil.formatSize(outputRate, true), SizeUtil.formatSize(outputBandwidthLimit, true)
            }));
  }

  /**
   * Appends session-scoped and persisted-total bandwidth summary lines.
   *
   * @param lines destination list for rendered bandwidth lines
   * @param sessionData precomputed session and total bandwidth values for this report
   */
  private void appendSessionTotals(List<String> lines, BandwidthSessionData sessionData) {
    lines.add(
        statisticsL10n(
            "totalInputSession",
            new String[] {PATTERN_TOTAL, "rate"},
            new String[] {
              SizeUtil.formatSize(sessionData.total()[1], true),
              SizeUtil.formatSize(sessionData.sessionRates()[0], true)
            }));
    lines.add(
        statisticsL10n(
            "totalOutputSession",
            new String[] {PATTERN_TOTAL, "rate"},
            new String[] {
              SizeUtil.formatSize(sessionData.total()[0], true),
              SizeUtil.formatSize(sessionData.sessionRates()[1], true)
            }));
    lines.add(
        statisticsL10n(
            "payloadOutput",
            new String[] {PATTERN_TOTAL, "rate", PATTERN_PERCENT},
            new String[] {
              SizeUtil.formatSize(sessionData.totalPayload(), true),
              SizeUtil.formatSize(sessionData.sessionRates()[2], true),
              Integer.toString(sessionData.payloadPercent())
            }));
    lines.add(
        statisticsL10n(
            "totalInput",
            new String[] {PATTERN_TOTAL},
            new String[] {SizeUtil.formatSize(sessionData.overallTotals()[0], true)}));
    lines.add(
        statisticsL10n(
            "totalOutput",
            new String[] {PATTERN_TOTAL},
            new String[] {SizeUtil.formatSize(sessionData.overallTotals()[1], true)}));
  }

  /**
   * Appends the detailed bandwidth category breakdown.
   *
   * <p>The calculation preserves the legacy accounting buckets, so the rendered text remains close
   * to the original diagnostic page, including the final unaccounted-bytes line.
   *
   * @param lines destination list for rendered bandwidth lines
   * @param total total sent and received bytes from the network collector
   * @param totalPayload total payload bytes sent during the current node lifetime
   */
  private void appendCategoryBreakdown(List<String> lines, long[] total, long totalPayload) {
    long totalBytesSentChkRequests = node.network().stats().getCHKRequestTotalBytesSent();
    long totalBytesSentSskRequests = node.network().stats().getSSKRequestTotalBytesSent();
    long totalBytesSentChkInserts = node.network().stats().getCHKInsertTotalBytesSent();
    long totalBytesSentSskInserts = node.network().stats().getSSKInsertTotalBytesSent();
    long totalBytesSentOfferedKeys = node.network().stats().getOfferedKeysTotalBytesSent();
    long totalBytesSendOffers = node.network().stats().getOffersSentBytesSent();
    long totalBytesSentSwapOutput = node.network().stats().getSwappingTotalBytesSent();
    long totalBytesSentAuth = node.network().stats().getTotalAuthBytesSent();
    long totalBytesSentAckOnly = node.network().stats().getNotificationOnlyPacketsSentBytes();
    long totalBytesSentResends = node.network().stats().getResendBytesSent();
    long totalBytesSentUom = node.network().stats().getUOMBytesSent();
    long totalBytesSentAnnounce = node.network().stats().getAnnounceBytesSent();
    long totalBytesSentAnnouncePayload = node.network().stats().getAnnounceBytesPayloadSent();
    long totalBytesSentRoutingStatus = node.network().stats().getRoutingStatusBytes();
    long totalBytesSentNetworkColoring = node.network().stats().getNetworkColoringSentBytes();
    long totalBytesSentPing = node.network().stats().getPingSentBytes();
    long totalBytesSentProbeRequest = node.network().stats().getProbeRequestSentBytes();
    long totalBytesSentRouted = node.network().stats().getRoutedMessageSentBytes();
    long totalBytesSentDisconn = node.network().stats().getDisconnBytesSent();
    long totalBytesSentInitial = node.network().stats().getInitialMessagesBytesSent();
    long totalBytesSentChangedIp = node.network().stats().getChangedIPBytesSent();
    long totalBytesSentNodeToNode = node.network().stats().getNodeToNodeBytesSent();
    long totalBytesSentAllocationNotices = node.network().stats().getAllocationNoticesBytesSent();
    long totalBytesSentFoaf = node.network().stats().getFOAFBytesSent();
    long totalBytesSentRemaining =
        total[0]
            - (totalPayload
                + totalBytesSentChkRequests
                + totalBytesSentSskRequests
                + totalBytesSentChkInserts
                + totalBytesSentSskInserts
                + totalBytesSentOfferedKeys
                + totalBytesSendOffers
                + totalBytesSentSwapOutput
                + totalBytesSentAuth
                + totalBytesSentAckOnly
                + totalBytesSentResends
                + totalBytesSentUom
                + totalBytesSentAnnounce
                + totalBytesSentRoutingStatus
                + totalBytesSentNetworkColoring
                + totalBytesSentPing
                + totalBytesSentProbeRequest
                + totalBytesSentRouted
                + totalBytesSentDisconn
                + totalBytesSentInitial
                + totalBytesSentChangedIp
                + totalBytesSentNodeToNode
                + totalBytesSentAllocationNotices
                + totalBytesSentFoaf);

    lines.add(
        statisticsL10n(
            "requestOutput",
            new String[] {"chk", "ssk"},
            new String[] {
              SizeUtil.formatSize(totalBytesSentChkRequests, true),
              SizeUtil.formatSize(totalBytesSentSskRequests, true)
            }));
    lines.add(
        statisticsL10n(
            "insertOutput",
            new String[] {"chk", "ssk"},
            new String[] {
              SizeUtil.formatSize(totalBytesSentChkInserts, true),
              SizeUtil.formatSize(totalBytesSentSskInserts, true)
            }));
    lines.add(
        statisticsL10n(
            "offeredKeyOutput",
            new String[] {PATTERN_TOTAL, "offered"},
            new String[] {
              SizeUtil.formatSize(totalBytesSentOfferedKeys, true),
              SizeUtil.formatSize(totalBytesSendOffers, true)
            }));
    lines.add(
        statisticsL10n(
            "swapOutput", PATTERN_TOTAL, SizeUtil.formatSize(totalBytesSentSwapOutput, true)));
    lines.add(
        statisticsL10n("authBytes", PATTERN_TOTAL, SizeUtil.formatSize(totalBytesSentAuth, true)));
    lines.add(
        statisticsL10n(
            "ackOnlyBytes", PATTERN_TOTAL, SizeUtil.formatSize(totalBytesSentAckOnly, true)));
    lines.add(
        statisticsL10n(
            "resendBytes",
            new String[] {PATTERN_TOTAL, PATTERN_PERCENT},
            new String[] {
              SizeUtil.formatSize(totalBytesSentResends, true),
              Long.toString((100 * totalBytesSentResends) / Math.max(1, total[0]))
            }));
    lines.add(
        statisticsL10n("uomBytes", PATTERN_TOTAL, SizeUtil.formatSize(totalBytesSentUom, true)));
    lines.add(
        statisticsL10n(
            "announceBytes",
            new String[] {PATTERN_TOTAL, "payload"},
            new String[] {
              SizeUtil.formatSize(totalBytesSentAnnounce, true),
              SizeUtil.formatSize(totalBytesSentAnnouncePayload, true)
            }));
    lines.add(
        statisticsL10n(
            "adminBytes",
            new String[] {"routingStatus", "disconn", "initial", "changedIP"},
            new String[] {
              SizeUtil.formatSize(totalBytesSentRoutingStatus, true),
              SizeUtil.formatSize(totalBytesSentDisconn, true),
              SizeUtil.formatSize(totalBytesSentInitial, true),
              SizeUtil.formatSize(totalBytesSentChangedIp, true)
            }));
    lines.add(
        statisticsL10n(
            "debuggingBytes",
            new String[] {"netColoring", "ping", "probe", "routed"},
            new String[] {
              SizeUtil.formatSize(totalBytesSentNetworkColoring, true),
              SizeUtil.formatSize(totalBytesSentPing, true),
              SizeUtil.formatSize(totalBytesSentProbeRequest, true),
              SizeUtil.formatSize(totalBytesSentRouted, true)
            }));
    lines.add(
        statisticsL10n(
            "nodeToNodeBytes", PATTERN_TOTAL, SizeUtil.formatSize(totalBytesSentNodeToNode, true)));
    lines.add(
        statisticsL10n(
            "loadAllocationNoticesBytes",
            PATTERN_TOTAL,
            SizeUtil.formatSize(totalBytesSentAllocationNotices, true)));
    lines.add(
        statisticsL10n("foafBytes", PATTERN_TOTAL, SizeUtil.formatSize(totalBytesSentFoaf, true)));
    lines.add(
        statisticsL10n(
            "unaccountedBytes",
            new String[] {PATTERN_TOTAL, PATTERN_PERCENT},
            new String[] {
              SizeUtil.formatSize(totalBytesSentRemaining, true),
              Integer.toString((int) (totalBytesSentRemaining * 100 / Math.max(1, total[0])))
            }));
  }

  /**
   * Builds the queue summary section.
   *
   * <p>The method preserves the legacy text for both the empty-queue case and the persistence
   * database failure case, then appends a blank trailing line for section spacing.
   *
   * @return detached section containing queue summary lines
   */
  private DiagnosticSectionSnapshot queueSection() {
    List<String> lines = new ArrayList<>();
    try {
      RequestStatus[] requests = globalRequests();
      if (requests.length < 1) {
        lines.add(baseL10n.getString("QueueToadlet.globalQueueIsEmpty"));
      } else {
        appendQueueCounts(lines, requests);
      }
    } catch (PersistenceDisabledException _) {
      lines.add(DATABASE_DISABLED);
    }
    lines.add("");
    return new DiagnosticSectionSnapshot(QUEUE_TITLE, lines);
  }

  /**
   * Reads the current global request list from the FCP server when present.
   *
   * @return current global request snapshots, or an empty array when no FCP server exists
   * @throws PersistenceDisabledException if the persistence layer rejects queue access
   */
  private RequestStatus[] globalRequests() throws PersistenceDisabledException {
    FCPServer fcpServer = core.getEndpoints().getFCPServer();
    return fcpServer == null ? new RequestStatus[0] : fcpServer.getGlobalRequests();
  }

  /**
   * Appends the legacy download and upload queue counts.
   *
   * @param lines destination list for rendered queue lines
   * @param requests global request snapshots returned by the FCP server
   */
  private void appendQueueCounts(List<String> lines, RequestStatus[] requests) {
    long totalQueuedDownload = 0;
    long totalQueuedUpload = 0;
    for (RequestStatus request : requests) {
      if (request instanceof DownloadRequestStatus) {
        totalQueuedDownload++;
      } else if (request instanceof UploadFileRequestStatus
          || request instanceof UploadDirRequestStatus) {
        totalQueuedUpload++;
      }
    }
    lines.add("Downloads Queued: " + totalQueuedDownload + " (" + totalQueuedDownload + ")");
    lines.add("Uploads Queued: " + totalQueuedUpload + " (" + totalQueuedUpload + ")");
  }

  /**
   * Builds the thread diagnostics section when node diagnostics are enabled.
   *
   * <p>The section keeps the historical sort order by descending CPU time, truncates long names and
   * group labels to the same widths used by the old plaintext page, and returns {@code null} when
   * diagnostics are disabled or unavailable so the caller can omit the section entirely.
   *
   * @return detached thread diagnostics section, or {@code null} when no thread section should be
   *     rendered
   */
  private DiagnosticSectionSnapshot threadDiagnosticsSection() {
    if (!node.isNodeDiagnosticsEnabled()) {
      return null;
    }

    NodeDiagnostics nodeDiagnostics = node.services().nodeDiagnostics();
    if (nodeDiagnostics == null) {
      return null;
    }

    ThreadDiagnostics threadDiagnostics = nodeDiagnostics.getThreadDiagnostics();
    if (threadDiagnostics == null) {
      return null;
    }

    NodeThreadSnapshot threadSnapshot = threadDiagnostics.getThreadSnapshot();
    List<NodeThreadInfo> threads =
        threadSnapshot == null ? new ArrayList<>() : threadSnapshot.getThreads();
    threads.sort(Comparator.comparing(NodeThreadInfo::getCpuTime).reversed());

    double wallTime =
        TimeUnit.MILLISECONDS.toNanos(
            threadSnapshot == null ? 1 : Math.max(1, threadSnapshot.getInterval()));

    List<String> lines = new ArrayList<>(threads.size() + 2);
    lines.add(
        THREAD_HEADER_FORMAT.formatted(
            "Thread ID", "Job ID", "Name", "Prio.", "Group", "Status", "% CPU"));
    for (NodeThreadInfo thread : threads) {
      lines.add(
          THREAD_ROW_FORMAT.formatted(
              thread.getId(),
              thread.getJobId(),
              truncate(thread.getName(), 90),
              thread.getPrio(),
              truncate(thread.getGroupName(), 10),
              safeText(thread.getState()),
              thread.getCpuTime() / wallTime * 100));
    }
    lines.add("");
    return new DiagnosticSectionSnapshot("Threads (%d):".formatted(threads.size()), lines);
  }

  /**
   * Counts peers that both record status and match the requested legacy status constant.
   *
   * @param peerNodeStatuses peer snapshots from the status book
   * @param status legacy peer status constant to count
   * @return number of peers whose recorded status matches {@code status}
   */
  private int peerStatusCount(PeerNodeStatus[] peerNodeStatuses, int status) {
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

  /**
   * Counts peers currently marked as seed servers.
   *
   * @param peerNodeStatuses peer snapshots from the status book
   * @return number of seed-server peers in the supplied array
   */
  private int countSeedServers(PeerNodeStatus[] peerNodeStatuses) {
    int count = 0;
    for (PeerNodeStatus peerNodeStatus : peerNodeStatuses) {
      if (peerNodeStatus.isSeedServer()) {
        count++;
      }
    }
    return count;
  }

  /**
   * Counts peers currently marked as seed clients.
   *
   * @param peerNodeStatuses peer snapshots from the status book
   * @return number of seed-client peers in the supplied array
   */
  private int countSeedClients(PeerNodeStatus[] peerNodeStatuses) {
    int count = 0;
    for (PeerNodeStatus peerNodeStatusesEntry : peerNodeStatuses) {
      if (peerNodeStatusesEntry.isSeedClient()) {
        count++;
      }
    }
    return count;
  }

  /**
   * Truncates text to the legacy column width while tolerating {@code null} input.
   *
   * @param value raw text value that may be {@code null}
   * @param maxLength maximum number of characters to retain
   * @return non-null text truncated to at most {@code maxLength} characters
   */
  private String truncate(String value, int maxLength) {
    String text = safeText(value);
    return text.substring(0, Math.min(maxLength, text.length()));
  }

  /**
   * Converts nullable text into the empty string for formatter safety.
   *
   * @param value raw text value that may be {@code null}
   * @return original text when present, otherwise the empty string
   */
  private String safeText(String value) {
    return value == null ? "" : value;
  }

  /**
   * Resolves a statistics localization key without placeholders.
   *
   * @param key suffix appended to the statistics localization prefix
   * @return localized message for the supplied statistics key
   */
  private String statisticsL10n(String key) {
    return baseL10n.getString(STATISTICS_PREFIX + key);
  }

  /**
   * Resolves a statistics localization key with one placeholder.
   *
   * @param key suffix appended to the statistics localization prefix
   * @param pattern placeholder name expected by the localized template
   * @param value placeholder value interpolated into the localized template
   * @return localized and formatted message for the supplied key
   */
  private String statisticsL10n(String key, String pattern, String value) {
    return baseL10n.getString(
        STATISTICS_PREFIX + key, new String[] {pattern}, new String[] {safeText(value)});
  }

  /**
   * Resolves a statistics localization key with multiple placeholders.
   *
   * @param key suffix appended to the statistics localization prefix
   * @param patterns placeholder names expected by the localized template
   * @param values placeholder values interpolated into the localized template
   * @return localized and formatted message for the supplied key
   */
  private String statisticsL10n(String key, String[] patterns, String[] values) {
    return baseL10n.getString(STATISTICS_PREFIX + key, patterns, values);
  }

  /**
   * Resolves a darknet-page localization key reused by the peer statistics section.
   *
   * @param key suffix appended to the darknet localization prefix
   * @return localized darknet message for the supplied key
   */
  private String darknetL10n(String key) {
    return baseL10n.getString("DarknetConnectionsToadlet." + key);
  }

  /**
   * Small immutable holder for precomputed bandwidth totals used during section rendering.
   *
   * <p>The adapter keeps these related values together so the section-building helpers can share a
   * single parameter without recomputing or re-reading the same totals.
   */
  @SuppressWarnings({"ClassCanBeRecord", "java:S6206"})
  private static final class BandwidthSessionData {
    /** Total sent and received bytes returned by the network collector. */
    private final long[] total;

    /** Total payload bytes sent during the current node lifetime. */
    private final long totalPayload;

    /** Derived per-second session rates for input, output, and payload traffic. */
    private final long[] sessionRates;

    /** Percentage of session output attributed to payload bytes. */
    private final int payloadPercent;

    /** Persisted overall input and output totals used for long-horizon lines. */
    private final long[] overallTotals;

    /**
     * Creates a bandwidth session data holder.
     *
     * @param total total sent and received byte counters
     * @param totalPayload total payload bytes sent during the current session
     * @param sessionRates per-second session rates for input, output, and payload traffic
     * @param payloadPercent percentage of output traffic attributed to payload bytes
     * @param overallTotals persisted overall input and output byte totals
     */
    private BandwidthSessionData(
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

    /**
     * Returns the raw collector totals.
     *
     * @return two-element array containing total sent and received bytes
     */
    private long[] total() {
      return total;
    }

    /**
     * Returns the total payload bytes sent for the current session.
     *
     * @return payload byte total for the current node lifetime
     */
    private long totalPayload() {
      return totalPayload;
    }

    /**
     * Returns the derived session rates.
     *
     * @return array containing input, output, and payload rates in bytes per second
     */
    private long[] sessionRates() {
      return sessionRates;
    }

    /**
     * Returns the payload share of session output traffic.
     *
     * @return integer percentage of output bytes attributed to payload traffic
     */
    private int payloadPercent() {
      return payloadPercent;
    }

    /**
     * Returns persisted overall totals.
     *
     * @return array containing persisted overall input and output totals
     */
    private long[] overallTotals() {
      return overallTotals;
    }
  }
}

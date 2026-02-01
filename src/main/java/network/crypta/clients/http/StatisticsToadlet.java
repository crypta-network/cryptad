package network.crypta.clients.http;

import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.concurrent.TimeUnit.HOURS;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.IOException;
import java.net.URI;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.text.NumberFormat;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.async.ClientRequester;
import network.crypta.config.SubConfig;
import network.crypta.crypt.ciphers.Rijndael;
import network.crypta.io.comm.IncomingPacketFilterImpl;
import network.crypta.io.xfer.BlockReceiver;
import network.crypta.io.xfer.BlockTransmitter;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Location;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.NodeStats;
import network.crypta.node.NodeStatsHtmlRenderer;
import network.crypta.node.OpennetManager;
import network.crypta.node.PeerManager;
import network.crypta.node.PeerNodeStatus;
import network.crypta.node.PeerStatusCounts;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestStarterGroup;
import network.crypta.node.RequestTracker;
import network.crypta.node.Version;
import network.crypta.node.stats.DataStoreInstanceType;
import network.crypta.node.stats.DataStoreStats;
import network.crypta.node.stats.StatsNotAvailableException;
import network.crypta.node.stats.StoreAccessStats;
import network.crypta.support.BandwidthStatsContainer;
import network.crypta.support.HTMLNode;
import network.crypta.support.SizeUtil;
import network.crypta.support.TimeUtil;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.io.NativeThread;
import org.jetbrains.annotations.NotNull;

/**
 * Serves the statistics page for Crypta's HTTP interface, aggregating peer, bandwidth, request, and
 * storage metrics into localized infoboxes. The toadlet lives at {@code /stats/} and targets node
 * operators who need a concise, browser-friendly overview of runtime health without attaching
 * external monitoring tools.
 *
 * <p>At request time the toadlet refreshes bandwidth counters, captures a {@link PeerStatusSummary}
 * snapshot, and renders multiple panels that cover peer connectivity, datastore sizing heuristics,
 * active requests, thread usage, swaps, and routing histograms. Advanced mode adjusts terminology
 * and exposes more granular peer-state wording while keeping the default view approachable.
 * Formatting is synchronized around shared {@link java.text.DecimalFormat} instances to remain
 * thread-safe when multiple HTTP workers render pages concurrently.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Handling HTTP GET requests and routing between the statistics overview and the requester
 *       subpage.
 *   <li>Transforming {@link network.crypta.node.NodeStats} and peer status data into HTML fragments
 *       with consistent CSS hooks.
 *   <li>Highlighting connection, routing back-off, and bandwidth states with styles understood by
 *       the bundled themes.
 * </ul>
 *
 * @see network.crypta.node.NodeStats
 * @see network.crypta.node.PeerManager
 * @see network.crypta.clients.http.ToadletContext
 */
public class StatisticsToadlet extends Toadlet {

  static final NumberFormat thousandPoint = NumberFormat.getInstance();

  private record STMessageCount(String messageName, int messageCount) {}

  private static class PeerStatusSummary {
    final PeerNodeStatus[] peerNodeStatuses;
    final PeerStatusCounts counts;

    PeerStatusSummary(PeerNodeStatus[] peerNodeStatuses, PeerStatusCounts counts) {
      this.peerNodeStatuses = peerNodeStatuses;
      this.counts = counts;
    }

    boolean hasConnectedOrBackedOffPeers() {
      return counts.connected() + counts.routingBackedOff() > 0;
    }
  }

  private final Node node;
  private final NodeClientCore core;
  private final NodeStats stats;
  private final PeerManager peers;
  private final DecimalFormat fix1p1 = new DecimalFormat("0.0");
  private final DecimalFormat fix1p2 = new DecimalFormat("0.00");
  private final DecimalFormat fix1p4 = new DecimalFormat("0.0000");
  private final DecimalFormat fix1p6sci = new DecimalFormat("0.######E0");
  private final DecimalFormat fix3p1pct = new DecimalFormat("##0.0%");
  private final DecimalFormat fix3p1US =
      new DecimalFormat("##0.0", new DecimalFormatSymbols(Locale.US));
  private final DecimalFormat fix3pctUS =
      new DecimalFormat("##0%", new DecimalFormatSymbols(Locale.US));
  private final DecimalFormat fix6p6 = new DecimalFormat("#####0.0#####");
  private static final String TAG_TABLE = "table";
  private static final String ATTR_CLASS = "class";
  private static final String ATTR_BORDER = "border";
  private static final String CLASS_FIRST = "first";
  private static final String CLASS_INFOBOX = "infobox";
  private static final String CLASS_INFOBOX_HEADER = "infobox-header";
  private static final String CLASS_INFOBOX_CONTENT = "infobox-content";
  private static final String CLASS_COLUMN = "column";
  private static final String BULK_LABEL_SUFFIX = " (bulk)";
  private static final String COUNT_LABEL = "count";
  private static final String AVG_TIME_KEY = "avgTime";
  private static final String TOTAL_TIME_KEY = "totalTime";
  private static final String REALTIME_SUFFIX = " (realtime)";
  private static final String NBSP = "\u00a0";
  private static final String ATTR_STYLE = "style";
  private static final String LABEL_LOCATION = "Location";
  private static final String LABEL_DISTRIBUTION = "Distribution";
  private static final String MEMORY_KEY = "memory";
  private static final String VERSION_KEY = "version";
  private static final String COLON_NBSP = ":" + NBSP;
  private static final String NBSP_OPEN_PAREN = NBSP + "(";
  private static final String TITLE_ATTR = "title";
  private static final String CLASS_CONNECTED = "connected";
  private static final String CLASS_DISCONNECTED = "disconnected";
  private static final String HOVER_STYLE = "border-bottom: 1px dotted; cursor: help;";
  private static final String PEER_LISTENING_CLASS = "peer_listening";
  private static final String PEER_LISTEN_ONLY_CLASS = "peer_listen_only";
  private static final String STATS_PREFIX = "StatisticsToadlet.";
  private static final String TOTAL_KEY = "total";
  private static final String PERCENT_KEY = "percent";
  private static final String NBSP_NODES = NBSP + "nodes";
  private static final String CHK_SUFFIX = " (CHK) ";
  private static final String SSK_SUFFIX = " (SSK)";
  private static final String POSITION_TOP = "position: absolute; top: ";
  private static final String PX_LEFT = "px; left: ";
  private static final String HEIGHT_100PX = "height: 100px;";
  private static final String HISTOGRAM_DISCONNECTED = "histogramDisconnected";
  private static final String HISTOGRAM_LABEL_CLASS = "histogramLabel";
  private static final String HISTOGRAM_CONNECTED_CLASS = "histogramConnected";
  private static final String HEIGHT_PREFIX = "height: ";
  private static final String WIDTH_100 = "; width: 100%;";

  /**
   * Builds a statistics toadlet tied to the supplied node state and client wiring so it can
   * assemble runtime metrics on demand. The constructor caches frequently used collaborators
   * (statistics snapshotter and peer manager), so individual requests avoid repeated lookups while
   * still reflecting the live node through fresh data pulls performed inside each handler.
   *
   * @param n node instance that owns the peer set, configuration, and counters displayed by the
   *     toadlet; expected to remain reachable for the lifetime of the toadlet.
   * @param core client core used for bandwidth statistics and requester views; must match the same
   *     node and stay initialized when the toadlet runs.
   * @param client HTTP client facade passed to the {@link Toadlet} base class for generating
   *     responses and accessing higher-level convenience helpers; reused per request lifecycle.
   */
  protected StatisticsToadlet(Node n, NodeClientCore core, HighLevelSimpleClient client) {
    super(client);
    this.node = n;
    this.core = core;
    stats = node.network().stats();
    peers = node.network().peers();
  }

  /**
   * Counts the peers in <code>peerNodes</code> that have the specified status.
   *
   * @param peerNodeStatuses The peer nodes' statuses
   * @param status The status to count
   * @return The number of peers that have the specified status.
   */
  private int getPeerStatusCount(PeerNodeStatus[] peerNodeStatuses, int status) {
    int count = 0;
    for (PeerNodeStatus peerNodeStatus : peerNodeStatuses) {
      if (!peerNodeStatus.recordStatus()) continue;
      if (peerNodeStatus.getStatusValue() == status) {
        count++;
      }
    }
    return count;
  }

  private int getCountSeedServers(PeerNodeStatus[] peerNodeStatuses) {
    int count = 0;
    for (PeerNodeStatus peerNodeStatus : peerNodeStatuses) {
      if (peerNodeStatus.isSeedServer()) count++;
    }
    return count;
  }

  private int getCountSeedClients(PeerNodeStatus[] peerNodeStatuses) {
    int count = 0;
    for (PeerNodeStatus peerNodeStatus : peerNodeStatuses) {
      if (peerNodeStatus.isSeedClient()) count++;
    }
    return count;
  }

  /**
   * Serves GET requests for the statistics toadlet, enforcing full-access checks, dispatching to
   * the requester subpage when requested, and rendering the main statistics page otherwise. The
   * method refreshes bandwidth counters before building a page, synchronizes on the toadlet while
   * formatting numbers, and writes the generated HTML with a standard 200 response.
   *
   * @param uri full request URI used mainly for consistency with the {@link Toadlet} contract; the
   *     path segment is inspected indirectly through {@code request}.
   * @param request the incoming HTTP request providing path, parameters, and user context for the
   *     statistics view; must already be parsed by the calling toadlet framework.
   * @param ctx toadlet context that supplies page construction helpers, localization, and access
   *     control flags such as advanced mode; also used to emit the final response.
   * @throws ToadletContextClosedException if the client disconnects or the context is no longer
   *     writable while the page is being generated or streamed.
   * @throws IOException if output cannot be written to the client or ancillary resources fail
   *     during rendering.
   * @throws RedirectException if a redirect is requested by the framework during handling (for
   *     example, when access control triggers a login flow).
   */
  @Override
  public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    if (!ctx.checkFullAccess(this)) return;

    final String requestPath = request.getPath().substring(path().length());

    if (isRequestersPath(requestPath)) {
      showRequesters(ctx);
      return;
    }

    node.services()
        .clientCore()
        .getClientLayerPersister()
        .getBandwidthStatsPutter()
        .updateData(node);

    PageNode page = ctx.getPageMaker().getPageNode(l10n("fullTitle"), ctx);

    // Synchronize to avoid problems with DecimalFormat.
    synchronized (this) {
      PeerStatusSummary peerStatusSummary = preparePeerStatusSummary();
      renderStatisticsPage(node.getConfig().get("node"), ctx, page, peerStatusSummary);
    }

    this.writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private boolean isRequestersPath(String requestPath) {
    return !requestPath.isEmpty()
        && (requestPath.equals("requesters.html") || requestPath.equals("/requesters.html"));
  }

  private PeerStatusSummary preparePeerStatusSummary() {
    PeerNodeStatus[] peerNodeStatuses = peers.statusBook().getPeerNodeStatuses(true);
    Arrays.sort(peerNodeStatuses, Comparator.comparingInt(PeerNodeStatus::getStatusValue));

    int numberOfConnected =
        getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_CONNECTED);
    int numberOfRoutingBackedOff =
        getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF);
    int numberOfTooNew = getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_TOO_NEW);
    int numberOfTooOld = getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_TOO_OLD);
    int numberOfDisconnected =
        getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_DISCONNECTED);
    int numberOfNeverConnected =
        getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED);
    int numberOfDisabled =
        getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_DISABLED);
    int numberOfBursting =
        getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_BURSTING);
    int numberOfListening =
        getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_LISTENING);
    int numberOfListenOnly =
        getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_LISTEN_ONLY);
    int numberOfSeedServers = getCountSeedServers(peerNodeStatuses);
    int numberOfSeedClients = getCountSeedClients(peerNodeStatuses);
    int numberOfRoutingDisabled =
        getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_ROUTING_DISABLED);
    int numberOfClockProblem =
        getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_CLOCK_PROBLEM);
    int numberOfConnError =
        getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_CONN_ERROR);
    int numberOfDisconnecting =
        PeerNodeStatus.getPeerStatusCount(
            peerNodeStatuses, PeerManager.PEER_NODE_STATUS_DISCONNECTING);
    int numberOfNoLoadStats =
        PeerNodeStatus.getPeerStatusCount(
            peerNodeStatuses, PeerManager.PEER_NODE_STATUS_NO_LOAD_STATS);

    PeerStatusCounts counts =
        new PeerStatusCounts(
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
            numberOfSeedServers,
            numberOfSeedClients,
            numberOfRoutingDisabled,
            numberOfClockProblem,
            numberOfConnError,
            numberOfDisconnecting,
            numberOfNoLoadStats);
    return new PeerStatusSummary(peerNodeStatuses, counts);
  }

  private void renderStatisticsPage(
      SubConfig nodeConfig,
      ToadletContext ctx,
      PageNode page,
      PeerStatusSummary peerStatusSummary) {

    boolean advancedMode = ctx.isAdvancedModeEnabled();
    HTMLNode contentNode = page.getContentNode();

    final long now = System.currentTimeMillis();
    double myLocation = node.network().location();
    final long nodeUptimeSeconds = (now - node.getStartupTime()) / 1000;

    if (ctx.isAllowedFullAccess()) {
      contentNode.addChild(ctx.getAlertManager().createSummary());
    }

    double swaps = node.network().swaps();
    double noSwaps = node.network().noSwaps();

    HTMLNode overviewTable = contentNode.addChild(TAG_TABLE, ATTR_CLASS, CLASS_COLUMN);
    HTMLNode overviewTableRow = overviewTable.addChild("tr");
    HTMLNode leftColumn = overviewTableRow.addChild("td", ATTR_CLASS, CLASS_FIRST);

    addCoreInfoboxes(
        nodeConfig,
        ctx,
        advancedMode,
        nodeUptimeSeconds,
        leftColumn,
        peerStatusSummary,
        contentNode);

    if (advancedMode || peerStatusSummary.hasConnectedOrBackedOffPeers()) {
      HTMLNode rightColumn = overviewTableRow.addChild("td", ATTR_CLASS, "last");
      addActivityAndPeerBoxes(
          rightColumn, advancedMode, nodeUptimeSeconds, peerStatusSummary, swaps, noSwaps, now);

      if (advancedMode) {
        addAdvancedOnlyBoxes(rightColumn, nodeUptimeSeconds, swaps, noSwaps, myLocation);
      }

      addDistributionBoxes(overviewTable, peerStatusSummary.peerNodeStatuses, myLocation);
    }
  }

  private void addCoreInfoboxes(
      SubConfig nodeConfig,
      ToadletContext ctx,
      boolean advancedMode,
      long nodeUptimeSeconds,
      HTMLNode leftColumn,
      PeerStatusSummary peerStatusSummary,
      HTMLNode contentNode) {
    HTMLNode versionInfobox = leftColumn.addChild("div", ATTR_CLASS, CLASS_INFOBOX);
    drawNodeVersionBox(versionInfobox);

    HTMLNode jvmStatsInfobox = leftColumn.addChild("div", ATTR_CLASS, CLASS_INFOBOX);
    drawJVMStatsBox(jvmStatsInfobox, advancedMode);

    HTMLNode statGatheringContent =
        ctx.getPageMaker()
            .getInfobox(
                "#", l10n("statisticGatheringTitle"), leftColumn, "statistics-generating", true);
    if (node.isUsingWrapper()) {
      HTMLNode threadDumpForm = ctx.addFormChild(statGatheringContent, "/", "threadDumpForm");
      threadDumpForm.addChild(
          "input",
          new String[] {"type", "name", "value"},
          new String[] {"submit", "getThreadDump", l10n("threadDumpButton")});
    }
    HTMLNode logsList = statGatheringContent.addChild("ul");
    if (nodeConfig.config.get("logger").getBoolean("enabled")) {
      logsList
          .addChild("li")
          .addChild(
              "a",
              new String[] {"href", "target"},
              new String[] {"/?latestlog", "_blank"},
              l10n("getLogs"));
    }
    logsList
        .addChild("li")
        .addChild("a", "href", TranslationToadlet.TOADLET_URL + "?getOverrideTranslationFile")
        .addChild("#", NodeL10n.getBase().getString("TranslationToadlet.downloadTranslationsFile"));
    logsList
        .addChild("li")
        .addChild("a", "href", DiagnosticToadlet.TOADLET_URL)
        .addChild("#", NodeL10n.getBase().getString("FProxyToadlet.diagnostic"));

    if (!advancedMode) {
      return;
    }

    HTMLNode storeSizeInfobox = contentNode.addChild("div", ATTR_CLASS, CLASS_INFOBOX);
    drawStoreSizeBox(storeSizeInfobox, nodeUptimeSeconds);

    if (!peerStatusSummary.hasConnectedOrBackedOffPeers()) {
      return;
    }

    HTMLNode loadStatsInfobox = leftColumn.addChild("div", ATTR_CLASS, CLASS_INFOBOX);
    drawLoadBalancingBox(loadStatsInfobox, false);

    loadStatsInfobox = leftColumn.addChild("div", ATTR_CLASS, CLASS_INFOBOX);
    drawLoadBalancingBox(loadStatsInfobox, true);

    if (stats.enableNewLoadManagement(true) || stats.enableNewLoadManagement(false)) {
      HTMLNode newLoadManagementBox = leftColumn.addChild("div", ATTR_CLASS, CLASS_INFOBOX);
      drawNewLoadManagementBox(newLoadManagementBox);
    }

    HTMLNode successRateBox = leftColumn.addChild("div", ATTR_CLASS, CLASS_INFOBOX);
    successRateBox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_HEADER, l10n("successRate"));
    HTMLNode successRateContent = successRateBox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT);
    NodeStatsHtmlRenderer.fillSuccessRateBox(stats, successRateContent);

    HTMLNode timeDetailBox = leftColumn.addChild("div", ATTR_CLASS, CLASS_INFOBOX);
    timeDetailBox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_HEADER, l10n("chkDetailTiming"));
    HTMLNode timingsContent = timeDetailBox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT);
    NodeStatsHtmlRenderer.fillDetailedTimingsBox(stats, timingsContent);

    HTMLNode byHTLBox = leftColumn.addChild("div", ATTR_CLASS, CLASS_INFOBOX);
    byHTLBox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_HEADER, l10n("successByHTLBulk"));
    HTMLNode byHTLContent = byHTLBox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT);
    NodeStatsHtmlRenderer.fillRemoteRequestHTLsBox(stats, byHTLContent, false);

    byHTLBox = leftColumn.addChild("div", ATTR_CLASS, CLASS_INFOBOX);
    byHTLBox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_HEADER, l10n("successByHTLRT"));
    byHTLContent = byHTLBox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT);
    NodeStatsHtmlRenderer.fillRemoteRequestHTLsBox(stats, byHTLContent, true);
  }

  private void addActivityAndPeerBoxes(
      HTMLNode rightColumn,
      boolean advancedMode,
      long nodeUptimeSeconds,
      PeerStatusSummary peerStatusSummary,
      double swaps,
      double noSwaps,
      long now) {
    HTMLNode activityInfobox = rightColumn.addChild("div", ATTR_CLASS, CLASS_INFOBOX);
    drawActivityBox(activityInfobox, advancedMode);

    if (advancedMode) {
      HTMLNode overviewInfobox = rightColumn.addChild("div", ATTR_CLASS, CLASS_INFOBOX);
      drawOverviewBox(
          overviewInfobox,
          nodeUptimeSeconds,
          node.services()
              .clientCore()
              .getClientLayerPersister()
              .getBandwidthStatsPutter()
              .getLatestUptimeData()
              .getTotalUptime(),
          now,
          swaps,
          noSwaps);
    }

    HTMLNode peerStatsInfobox = rightColumn.addChild("div", ATTR_CLASS, CLASS_INFOBOX);

    drawPeerStatsBox(peerStatsInfobox, advancedMode, peerStatusSummary.counts, node);

    HTMLNode bandwidthInfobox = rightColumn.addChild("div", ATTR_CLASS, CLASS_INFOBOX);
    drawBandwidthBox(bandwidthInfobox, nodeUptimeSeconds, advancedMode);
  }

  private void addAdvancedOnlyBoxes(
      HTMLNode rightColumn,
      long nodeUptimeSeconds,
      double swaps,
      double noSwaps,
      double myLocation) {
    HTMLNode backoffReasonInfobox = rightColumn.addChild("div", ATTR_CLASS, CLASS_INFOBOX);
    backoffReasonInfobox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_HEADER, "Peer Backoff");
    HTMLNode backoffReasonContent =
        backoffReasonInfobox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT);

    addBackoffReasonList(
        backoffReasonContent,
        peers.getPeerNodeRoutingBackoffReasons(false),
        "Current backoff reasons" + BULK_LABEL_SUFFIX,
        false);

    addBackoffReasonList(
        backoffReasonContent,
        peers.getPeerNodeRoutingBackoffReasons(true),
        "Current backoff reasons" + REALTIME_SUFFIX,
        true);

    addBackoffStatisticsTables(backoffReasonInfobox);

    addSystemStatsBoxes(rightColumn, nodeUptimeSeconds, swaps, noSwaps, myLocation);
  }

  private void addBackoffReasonList(
      HTMLNode backoffReasonContent,
      String[] routingBackoffReasons,
      String title,
      boolean realtime) {
    HTMLNode reasonBox = backoffReasonContent.addChild("div", ATTR_CLASS, CLASS_INFOBOX);
    reasonBox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_HEADER, title);
    HTMLNode reasonContent = reasonBox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT);
    if (routingBackoffReasons.length == 0) {
      reasonContent.addChild("#", l10n("notBackedOff"));
      return;
    }
    HTMLNode reasonList = reasonContent.addChild("ul");
    for (String routingBackoffReason : routingBackoffReasons) {
      int reasonCount = peers.getPeerNodeRoutingBackoffReasonSize(routingBackoffReason, realtime);
      if (reasonCount > 0) {
        reasonList.addChild("li", routingBackoffReason + NBSP + reasonCount);
      }
    }
  }

  private void addBackoffStatisticsTables(HTMLNode backoffReasonInfobox) {
    addBackoffTable(
        backoffReasonInfobox,
        l10n("mandatoryBackoffReason") + BULK_LABEL_SUFFIX,
        stats.getMandatoryBackoffStatistics(false));
    addBackoffTable(
        backoffReasonInfobox,
        l10n("mandatoryBackoffReason") + REALTIME_SUFFIX,
        stats.getMandatoryBackoffStatistics(true));
    addBackoffTable(
        backoffReasonInfobox,
        l10n("routingBackoffReason") + BULK_LABEL_SUFFIX,
        stats.getRoutingBackoffStatistics(false));
    addBackoffTable(
        backoffReasonInfobox,
        l10n("routingBackoffReason") + REALTIME_SUFFIX,
        stats.getRoutingBackoffStatistics(true));
    addBackoffTable(
        backoffReasonInfobox,
        l10n("transferBackoffReason") + BULK_LABEL_SUFFIX,
        stats.getTransferBackoffStatistics(false));
    addBackoffTable(
        backoffReasonInfobox,
        l10n("transferBackoffReason") + REALTIME_SUFFIX,
        stats.getTransferBackoffStatistics(true));
  }

  private void addBackoffTable(HTMLNode container, String title, NodeStats.TimedStats[] entries) {
    HTMLNode table = container.addChild(TAG_TABLE, ATTR_BORDER, "0");
    HTMLNode row = table.addChild("tr");
    row.addChild("th", title);
    row.addChild("th", l10n(COUNT_LABEL));
    row.addChild("th", l10n(AVG_TIME_KEY));
    row.addChild("th", l10n(TOTAL_TIME_KEY));

    for (NodeStats.TimedStats entry : entries) {
      HTMLNode entryRow = table.addChild("tr");
      entryRow.addChild("td", entry.keyStr());
      entryRow.addChild("td", Long.toString(entry.count()));
      entryRow.addChild("td", TimeUtil.formatTime(entry.avgTime(), 2, true));
      entryRow.addChild("td", TimeUtil.formatTime(entry.totalTime(), 2, true));
    }
  }

  private void addSystemStatsBoxes(
      HTMLNode rightColumn,
      long nodeUptimeSeconds,
      double swaps,
      double noSwaps,
      double myLocation) {
    HTMLNode locationSwapInfobox = rightColumn.addChild("div", ATTR_CLASS, CLASS_INFOBOX);
    drawSwapStatsBox(locationSwapInfobox, myLocation, nodeUptimeSeconds, swaps, noSwaps);

    HTMLNode unclaimedFIFOMessageCountsInfobox =
        rightColumn.addChild("div", ATTR_CLASS, CLASS_INFOBOX);
    drawUnclaimedFIFOMessageCountsBox(unclaimedFIFOMessageCountsInfobox);

    HTMLNode threadsPriorityInfobox = rightColumn.addChild("div", ATTR_CLASS, CLASS_INFOBOX);
    drawThreadPriorityStatsBox(threadsPriorityInfobox);

    HTMLNode threadUsageInfobox = rightColumn.addChild("div", ATTR_CLASS, CLASS_INFOBOX);
    threadUsageInfobox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_HEADER, "Thread usage");
    HTMLNode threadUsageContent =
        threadUsageInfobox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT);
    HTMLNode threadUsageList = threadUsageContent.addChild("ul");
    getThreadNames(threadUsageList);

    drawRejectReasonsBox(rightColumn, false);
    drawRejectReasonsBox(rightColumn, true);

    OpennetManager om = node.network().opennet();
    if (om != null) {
      drawOpennetStatsBox(rightColumn.addChild("div", ATTR_CLASS, CLASS_INFOBOX), om);

      if (node.network().isSeednode()) {
        drawSeedStatsBox(rightColumn.addChild("div", ATTR_CLASS, CLASS_INFOBOX), om);
      }
    }
  }

  private void addDistributionBoxes(
      HTMLNode overviewTable, PeerNodeStatus[] peerNodeStatuses, double myLocation) {
    HTMLNode overviewTableRow = overviewTable.addChild("tr");
    HTMLNode nextTableCell = overviewTableRow.addChild("td", ATTR_CLASS, CLASS_FIRST);
    HTMLNode peerCircleInfobox = nextTableCell.addChild("div", ATTR_CLASS, CLASS_INFOBOX);
    peerCircleInfobox.addChild(
        "div",
        ATTR_CLASS,
        CLASS_INFOBOX_HEADER,
        "Peer" + NBSP + LABEL_LOCATION + NBSP + "Distribution (w/pReject)");
    HTMLNode peerCircleTable =
        peerCircleInfobox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT).addChild(TAG_TABLE);
    addPeerCircle(peerCircleTable, peerNodeStatuses, myLocation);
    nextTableCell = overviewTableRow.addChild("td");

    HTMLNode nodeCircleInfobox = nextTableCell.addChild("div", ATTR_CLASS, CLASS_INFOBOX);
    nodeCircleInfobox.addChild(
        "div",
        ATTR_CLASS,
        CLASS_INFOBOX_HEADER,
        "Node" + NBSP + LABEL_LOCATION + NBSP + "Distribution (w/Swap" + NBSP + "Age)");
    HTMLNode nodeCircleTable =
        nodeCircleInfobox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT).addChild(TAG_TABLE);
    addNodeCircle(nodeCircleTable, myLocation);

    overviewTableRow = overviewTable.addChild("tr");
    nextTableCell = overviewTableRow.addChild("td", ATTR_CLASS, CLASS_FIRST);
    int[] incomingRequestLocation = stats.getIncomingRequestLocation();
    int incomingRequestsCount = Arrays.stream(incomingRequestLocation).sum();

    if (incomingRequestsCount > 0) {
      HTMLNode nodeSpecialisationInfobox = nextTableCell.addChild("div", ATTR_CLASS, CLASS_INFOBOX);
      nodeSpecialisationInfobox.addChild(
          "div",
          ATTR_CLASS,
          CLASS_INFOBOX_HEADER,
          "Incoming" + NBSP + "Request" + NBSP + LABEL_DISTRIBUTION);
      HTMLNode nodeSpecialisationTable =
          nodeSpecialisationInfobox
              .addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT)
              .addChild(TAG_TABLE);
      addSpecialisation(nodeSpecialisationTable, myLocation, incomingRequestLocation);
    }

    nextTableCell = overviewTableRow.addChild("td");
    int[] outgoingLocalRequestLocation = stats.getOutgoingLocalRequestLocation();
    int outgoingLocalRequestsCount = Arrays.stream(outgoingLocalRequestLocation).sum();
    int[] outgoingRequestLocation = stats.getOutgoingRequestLocation();
    int outgoingRequestsCount = Arrays.stream(outgoingRequestLocation).sum();

    if (outgoingLocalRequestsCount > 0 && outgoingRequestsCount > 0) {
      HTMLNode nodeSpecialisationInfobox = nextTableCell.addChild("div", ATTR_CLASS, CLASS_INFOBOX);
      nodeSpecialisationInfobox.addChild(
          "div",
          ATTR_CLASS,
          CLASS_INFOBOX_HEADER,
          "Outgoing" + NBSP + "Request" + NBSP + LABEL_DISTRIBUTION);
      HTMLNode nodeSpecialisationTable =
          nodeSpecialisationInfobox
              .addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT)
              .addChild(TAG_TABLE);
      addCombinedSpecialisation(
          nodeSpecialisationTable,
          myLocation,
          outgoingLocalRequestLocation,
          outgoingRequestLocation);
    }

    overviewTableRow = overviewTable.addChild("tr");
    nextTableCell = overviewTableRow.addChild("td", ATTR_CLASS, CLASS_FIRST);

    int[] locationSuccessRatesArray = stats.getChkSuccessRatesByLocationPercentages(1000);
    HTMLNode nodeSpecialisationInfobox = nextTableCell.addChild("div", ATTR_CLASS, CLASS_INFOBOX);
    nodeSpecialisationInfobox.addChild(
        "div",
        ATTR_CLASS,
        CLASS_INFOBOX_HEADER,
        "Local"
            + NBSP
            + "CHK"
            + NBSP
            + "Success"
            + NBSP
            + "Rates"
            + NBSP
            + "By"
            + NBSP
            + LABEL_LOCATION);
    HTMLNode nodeSpecialisationTable =
        nodeSpecialisationInfobox
            .addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT)
            .addChild(TAG_TABLE);
    addSpecialisation(nodeSpecialisationTable, myLocation, locationSuccessRatesArray);
    nextTableCell = overviewTableRow.addChild("td");

    HTMLNode foafLinkInfobox = nextTableCell.addChild("div", ATTR_CLASS, CLASS_INFOBOX);
    foafLinkInfobox.addChild(
        "div",
        ATTR_CLASS,
        CLASS_INFOBOX_HEADER,
        "FOAF" + NBSP + "Link-Length" + NBSP + LABEL_DISTRIBUTION);
    HTMLNode foafLinkTable =
        foafLinkInfobox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT).addChild(TAG_TABLE);
    addFOAFLinkLengthHistogram(foafLinkTable, peerNodeStatuses);
  }

  private void showRequesters(ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    PageNode page = ctx.getPageMaker().getPageNode(l10n("fullTitle"), ctx);
    HTMLNode contentNode = page.getContentNode();

    drawClientRequestersBox(contentNode);
    writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private void drawLoadBalancingBox(HTMLNode loadStatsInfobox, boolean realTime) {
    // Load balancing box
    // Include an overall window, and RTTs for each

    loadStatsInfobox.addChild(
        "div",
        ATTR_CLASS,
        CLASS_INFOBOX_HEADER,
        "Load limiting " + (realTime ? "RealTime" : "Bulk"));
    HTMLNode loadStatsContent = loadStatsInfobox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT);
    RequestStarterGroup starters = core.getRequestStarters();
    double window = starters.getWindow(realTime);
    double realWindow = starters.getRealWindow(realTime);
    HTMLNode loadStatsList = loadStatsContent.addChild("ul");
    loadStatsList.addChild("li", l10n("globalWindow") + ": " + window);
    loadStatsList.addChild("li", l10n("realGlobalWindow") + ": " + realWindow);
    loadStatsList.addChild("li", starters.statsPageLine(false, false, realTime));
    loadStatsList.addChild("li", starters.statsPageLine(true, false, realTime));
    loadStatsList.addChild("li", starters.statsPageLine(false, true, realTime));
    loadStatsList.addChild("li", starters.statsPageLine(true, true, realTime));
    loadStatsList.addChild("li", starters.diagnosticThrottlesLine(false));
    loadStatsList.addChild("li", starters.diagnosticThrottlesLine(true));
  }

  private void drawNewLoadManagementBox(HTMLNode infobox) {
    infobox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_HEADER, l10n("newLoadManagementTitle"));
    HTMLNode content = infobox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT);
    NodeStatsHtmlRenderer.drawNewLoadManagementDelayTimes(node.network().stats(), content);
  }

  private void drawRejectReasonsBox(HTMLNode nextTableCell, boolean local) {
    HTMLNode rejectReasonsTable = new HTMLNode(TAG_TABLE);
    NodeStats nodeStats = node.network().stats();
    boolean success =
        local
            ? NodeStatsHtmlRenderer.getLocalRejectReasonsTable(nodeStats, rejectReasonsTable)
            : NodeStatsHtmlRenderer.getRejectReasonsTable(nodeStats, rejectReasonsTable);
    if (!success) return;
    HTMLNode rejectReasonsInfobox = nextTableCell.addChild("div", ATTR_CLASS, CLASS_INFOBOX);
    rejectReasonsInfobox.addChild(
        "div",
        ATTR_CLASS,
        CLASS_INFOBOX_HEADER,
        (local ? "Local " : "") + "Preemptive Rejection Reasons");
    rejectReasonsInfobox
        .addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT)
        .addChild(rejectReasonsTable);
  }

  private void drawNodeVersionBox(HTMLNode versionInfobox) {

    versionInfobox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_HEADER, l10n("versionTitle"));
    HTMLNode versionInfoboxContent =
        versionInfobox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT);
    HTMLNode versionInfoboxList = versionInfoboxContent.addChild("ul");
    versionInfoboxList.addChild(
        "li",
        NodeL10n.getBase()
            .getString(
                "WelcomeToadlet.version",
                new String[] {"fullVersion", "build", "rev"},
                new String[] {
                  Long.toString(Version.currentBuildNumber()),
                  Long.toString(Version.currentBuildNumber()),
                  Version.gitRevision()
                }));

    node.services().nodeUpdater().addChangelogLinks(Version.currentBuildNumber(), versionInfobox);
  }

  private void drawJVMStatsBox(HTMLNode jvmStatsInfobox, boolean advancedModeEnabled) {

    jvmStatsInfobox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_HEADER, l10n("jvmInfoTitle"));
    HTMLNode jvmStatsInfoboxContent =
        jvmStatsInfobox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT);
    HTMLNode jvmStatsList = jvmStatsInfoboxContent.addChild("ul");

    Runtime rt = Runtime.getRuntime();
    long freeMemory = rt.freeMemory();
    long totalMemory = rt.totalMemory();
    long maxMemory = rt.maxMemory();

    long usedJavaMem = totalMemory - freeMemory;
    int availableCpus = rt.availableProcessors();

    int threadCount = stats.getActiveThreadCount();

    jvmStatsList.addChild(
        "li", l10n("usedMemory", MEMORY_KEY, SizeUtil.formatSize(usedJavaMem, true)));
    jvmStatsList.addChild(
        "li", l10n("allocMemory", MEMORY_KEY, SizeUtil.formatSize(totalMemory, true)));
    jvmStatsList.addChild(
        "li", l10n("maxMemory", MEMORY_KEY, SizeUtil.formatSize(maxMemory, true)));
    jvmStatsList.addChild(
        "li",
        l10n(
            "threads",
            new String[] {"running", "max"},
            new String[] {
              thousandPoint.format(threadCount), Integer.toString(stats.getThreadLimit())
            }));
    jvmStatsList.addChild("li", l10n("cpus", COUNT_LABEL, Integer.toString(availableCpus)));
    jvmStatsList.addChild(
        "li", l10n("javaVersion", VERSION_KEY, System.getProperty("java.version")));
    jvmStatsList.addChild("li", l10n("jvmVendor", "vendor", System.getProperty("java.vendor")));
    jvmStatsList.addChild("li", l10n("jvmName", "name", System.getProperty("java.vm.name")));
    jvmStatsList.addChild(
        "li", l10n("jvmVersion", VERSION_KEY, System.getProperty("java.vm.version")));
    jvmStatsList.addChild("li", l10n("osName", "name", new network.crypta.fs.AppEnv().osNameRaw()));
    jvmStatsList.addChild("li", l10n("osVersion", VERSION_KEY, System.getProperty("os.version")));
    jvmStatsList.addChild("li", l10n("osArch", "arch", System.getProperty("os.arch")));
    if (advancedModeEnabled) {
      if (Rijndael.getAesCtrProvider() == null)
        jvmStatsList.addChild("li", l10n("cryptoUsingBuiltin"));
      else
        jvmStatsList.addChild("li", l10n("cryptoUsingJCA", "provider", Rijndael.getProviderName()));
    }
  }

  private void drawThreadPriorityStatsBox(HTMLNode node) {

    node.addChild("div", ATTR_CLASS, CLASS_INFOBOX_HEADER, l10n("threadsByPriority"));
    HTMLNode threadsInfoboxContent = node.addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT);
    int[] activeThreadsByPriority = stats.getActiveThreadsByPriority();
    int[] waitingThreadsByPriority = stats.getWaitingThreadsByPriority();

    HTMLNode threadsByPriorityTable = threadsInfoboxContent.addChild(TAG_TABLE, ATTR_BORDER, "0");
    HTMLNode row = threadsByPriorityTable.addChild("tr");

    row.addChild("th", l10n("priority"));
    row.addChild("th", l10n("running"));
    row.addChild("th", l10n("waiting"));

    for (int i = 0; i < activeThreadsByPriority.length; i++) {
      row = threadsByPriorityTable.addChild("tr");
      row.addChild("td", String.valueOf(i + 1));
      row.addChild("td", String.valueOf(activeThreadsByPriority[i]));
      row.addChild("td", String.valueOf(waitingThreadsByPriority[i]));
    }
  }

  private void drawOpennetStatsBox(HTMLNode box, OpennetManager om) {
    box.addChild("div", ATTR_CLASS, CLASS_INFOBOX_HEADER, l10n("opennetStats"));
    HTMLNode opennetStatsContent = box.addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT);
    HTMLNode table = opennetStatsContent.addChild(TAG_TABLE, ATTR_BORDER, "0");
    HTMLNode row = table.addChild("tr");

    row.addChild("th");
    for (OpennetManager.ConnectionType type : OpennetManager.ConnectionType.values()) {
      row.addChild("th", type.name());
    }

    row = table.addChild("tr");
    row.addChild("td", "Connection attempts");
    for (OpennetManager.ConnectionType type : OpennetManager.ConnectionType.values()) {
      row.addChild("td", Long.toString(om.getConnectionAttempts(type)));
    }

    row = table.addChild("tr");
    row.addChild("td", "Connections accepted");
    for (OpennetManager.ConnectionType type : OpennetManager.ConnectionType.values()) {
      row.addChild("td", Long.toString(om.getConnectionAttemptsAdded(type)));
    }

    row = table.addChild("tr");
    row.addChild("td", "Accepted (free slots)");
    for (OpennetManager.ConnectionType type : OpennetManager.ConnectionType.values()) {
      row.addChild("td", Long.toString(om.getConnectionAttemptsAddedPlentySpace(type)));
    }

    row = table.addChild("tr");
    row.addChild("td", "Rejected (per-type grace periods)");
    for (OpennetManager.ConnectionType type : OpennetManager.ConnectionType.values()) {
      row.addChild("td", Long.toString(om.getConnectionAttemptsRejectedByPerTypeEnforcement(type)));
    }

    row = table.addChild("tr");
    row.addChild("td", "Rejected (no droppable peers)");
    for (OpennetManager.ConnectionType type : OpennetManager.ConnectionType.values()) {
      row.addChild("td", Long.toString(om.getConnectionAttemptsRejectedNoPeersDroppable(type)));
    }
  }

  private void drawSeedStatsBox(HTMLNode box, OpennetManager om) {
    box.addChild("div", ATTR_CLASS, CLASS_INFOBOX_HEADER, l10n("seedStats"));
    HTMLNode opennetStatsContent = box.addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT);
    om.getSeedTracker().drawSeedStats(opennetStatsContent);
  }

  private void drawClientRequestersBox(HTMLNode box) {
    box.addChild("div", ATTR_CLASS, CLASS_INFOBOX_HEADER, l10n("clientRequesterObjects"));
    HTMLNode masterContent = box.addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT);
    HTMLNode table = masterContent.addChild(TAG_TABLE);
    HTMLNode row = table.addChild("tr");
    row.addChild("th", "RequestClient");
    row.addChild("th", l10n("clientRequesters.class"));
    row.addChild("th", l10n("clientRequesters.age"));
    row.addChild("th", l10n("clientRequesters.priorityClass"));
    row.addChild("th", l10n("clientRequesters.realtimeFlag"));
    row.addChild("th", l10n("clientRequesters.uri"));
    NumberFormat nf = NumberFormat.getInstance();
    nf.setMaximumFractionDigits(0);
    nf.setMinimumIntegerDigits(2);
    ClientRequester[] requests = ClientRequester.getAll();
    Arrays.sort(requests, (a, b) -> -Long.signum(a.creationTime - b.creationTime));
    long now = System.currentTimeMillis();
    for (ClientRequester request : requests) {
      if (request.isFinished() || request.isCancelled()) continue;
      row = table.addChild("tr");
      RequestClient client = request.getClient();
      row.addChild("td", client.toString());
      try {
        String s = request.toString();
        if (s.indexOf(':') > s.indexOf('@')) {
          s = s.substring(0, s.indexOf(':'));
        }
        row.addChild("td", s);
      } catch (Exception _) {
        row.addChild("td", "ERROR: " + request.getClass());
      }
      long diff = now - request.creationTime;
      row.addChild("td", TimeUtil.formatTime(diff, 2));
      row.addChild("td", Short.toString(request.getPriorityClass()));
      row.addChild("td", Boolean.toString(client.realTimeFlag()));
      FreenetURI uri = request.getURI(); // getURI() sometimes returns null, eg for ClientPutters
      row.addChild("td", uri == null ? "null" : uri.toString());
    }
  }

  private void drawStoreSizeBox(HTMLNode storeSizeInfobox, long nodeUptimeSeconds) {
    storeSizeInfobox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_HEADER, l10n("datastore"));
    HTMLNode storeSizeInfoboxContent =
        storeSizeInfobox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT);

    HTMLNode scrollDiv = storeSizeInfoboxContent.addChild("div", ATTR_STYLE, "overflow:scr");

    HTMLNode storeSizeTable = scrollDiv.addChild(TAG_TABLE, ATTR_BORDER, "0");
    HTMLNode row = storeSizeTable.addChild("tr");

    row.addChild("th", "");
    row.addChild("th", l10n("keys"));
    row.addChild("th", l10n("capacity"));
    row.addChild("th", l10n("datasize"));
    row.addChild("th", l10n("utilization"));
    row.addChild("th", l10n("readRequests"));
    row.addChild("th", l10n("successfulReads"));
    row.addChild("th", l10n("successRate"));
    row.addChild("th", l10n("writes"));
    row.addChild("th", l10n("accessRate"));
    row.addChild("th", l10n("writeRate"));
    row.addChild("th", l10n("falsePos"));
    row.addChild("th", l10n("avgLocation"));
    row.addChild("th", l10n("avgSuccessLoc"));
    row.addChild("th", l10n("furthestSuccess"));
    row.addChild("th", l10n("avgDist"));
    row.addChild("th", l10n("distanceStats"));

    Map<DataStoreInstanceType, DataStoreStats> storeStats = node.storage().getDataStoreStats();
    for (Map.Entry<DataStoreInstanceType, DataStoreStats> entry : storeStats.entrySet()) {
      addStoreStatsRow(storeSizeTable, entry.getKey(), entry.getValue(), nodeUptimeSeconds);
    }
  }

  private void addStoreStatsRow(
      HTMLNode storeSizeTable,
      DataStoreInstanceType instance,
      DataStoreStats dataStoreStats,
      long nodeUptimeSeconds) {
    StoreAccessStats sessionAccess = dataStoreStats.getSessionAccessStats();
    StoreAccessStats totalAccess = getTotalAccessStats(dataStoreStats);
    long totalUptimeSeconds = getTotalUptimeSeconds(totalAccess);

    HTMLNode row = storeSizeTable.addChild("tr");
    row.addChild("th", l10n(instance.store.name()) + "\n" + " (" + l10n(instance.key.name()) + ")");

    row.addChild("td", thousandPoint.format(dataStoreStats.keys()));
    row.addChild("td", thousandPoint.format(dataStoreStats.capacity()));
    row.addChild("td", SizeUtil.formatSize(dataStoreStats.dataSize()));
    row.addChild("td", fix3p1pct.format(dataStoreStats.utilization()));
    row.addChild(
        "td",
        thousandPoint.format(sessionAccess.readRequests())
            + formatTotalValue(totalAccess, totalAccess == null ? 0 : totalAccess.readRequests()));
    row.addChild(
        "td",
        thousandPoint.format(sessionAccess.successfulReads())
            + formatTotalValue(
                totalAccess, totalAccess == null ? 0 : totalAccess.successfulReads()));
    row.addChild("td", successRateCell(sessionAccess, totalAccess));
    row.addChild(
        "td",
        thousandPoint.format(sessionAccess.writes())
            + formatTotalValue(totalAccess, totalAccess == null ? 0 : totalAccess.writes()));
    RateSupplier totalAccessRateSupplier =
        totalAccess == null ? null : () -> totalAccess.accessRate(totalUptimeSeconds);
    RateSupplier totalWriteRateSupplier =
        totalAccess == null ? null : () -> totalAccess.writeRate(totalUptimeSeconds);
    row.addChild(
        "td",
        rateWithTotals(
            sessionAccess.accessRate(nodeUptimeSeconds), totalAccess, totalAccessRateSupplier));
    row.addChild(
        "td",
        rateWithTotals(
            sessionAccess.writeRate(nodeUptimeSeconds), totalAccess, totalWriteRateSupplier));
    row.addChild(
        "td",
        thousandPoint.format(sessionAccess.falsePos())
            + formatTotalValue(totalAccess, totalAccess == null ? 0 : totalAccess.falsePos()));
    addOptionalStat(row, () -> fix1p4.format(dataStoreStats.avgLocation()));
    addOptionalStat(row, () -> fix1p4.format(dataStoreStats.avgSuccess()));
    addOptionalStat(row, () -> fix1p4.format(dataStoreStats.furthestSuccess()));
    addOptionalStat(row, () -> fix1p4.format(dataStoreStats.avgDist()));
    addOptionalStat(row, () -> fix3p1pct.format(dataStoreStats.distanceStats()));
  }

  private StoreAccessStats getTotalAccessStats(DataStoreStats stats) {
    try {
      return stats.getTotalAccessStats();
    } catch (StatsNotAvailableException _) {
      return null;
    }
  }

  private long getTotalUptimeSeconds(StoreAccessStats totalAccess) {
    if (totalAccess == null) {
      return 0;
    }
    return node.services()
        .clientCore()
        .getClientLayerPersister()
        .getBandwidthStatsPutter()
        .getLatestUptimeData()
        .getTotalUptime();
  }

  private String formatTotalValue(StoreAccessStats totalAccess, long totalValue) {
    if (totalAccess == null) {
      return "";
    }
    return NBSP_OPEN_PAREN + thousandPoint.format(totalValue) + ")";
  }

  private String successRateCell(StoreAccessStats sessionAccess, StoreAccessStats totalAccess) {
    try {
      String rate = fix1p4.format(sessionAccess.successRate()) + "%";
      if (totalAccess != null) {
        rate += NBSP_OPEN_PAREN + fix1p4.format(totalAccess.successRate()) + "%)";
      }
      return rate;
    } catch (StatsNotAvailableException _) {
      return "N/A";
    }
  }

  private String rateWithTotals(
      double sessionRate, StoreAccessStats totalAccess, RateSupplier totalSupplier) {
    String rate = fix1p2.format(sessionRate) + " /s";
    if (totalAccess != null && totalSupplier != null) {
      try {
        rate += NBSP_OPEN_PAREN + fix1p2.format(totalSupplier.rate()) + " /s)";
      } catch (StatsNotAvailableException _) {
        return rate;
      }
    }
    return rate;
  }

  private void addOptionalStat(HTMLNode row, StatSupplier supplier) {
    try {
      row.addChild("td", supplier.value());
    } catch (StatsNotAvailableException _) {
      row.addChild("td", "N/A");
    }
  }

  @FunctionalInterface
  private interface RateSupplier {
    double rate() throws StatsNotAvailableException;
  }

  @FunctionalInterface
  private interface StatSupplier {
    String value() throws StatsNotAvailableException;
  }

  private void drawUnclaimedFIFOMessageCountsBox(HTMLNode unclaimedFIFOMessageCountsInfobox) {

    unclaimedFIFOMessageCountsInfobox.addChild(
        "div", ATTR_CLASS, CLASS_INFOBOX_HEADER, "unclaimedFIFO Message Counts");
    HTMLNode unclaimedFIFOMessageCountsInfoboxContent =
        unclaimedFIFOMessageCountsInfobox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT);
    HTMLNode unclaimedFIFOMessageCountsList =
        unclaimedFIFOMessageCountsInfoboxContent.addChild("ul");
    Map<String, Integer> unclaimedFIFOMessageCountsMap =
        node.network().usm().getUnclaimedFIFOMessageCounts();
    STMessageCount[] unclaimedFIFOMessageCountsArray =
        new STMessageCount[unclaimedFIFOMessageCountsMap.size()];
    int i = 0;
    int totalCount = 0;
    for (Map.Entry<String, Integer> e : unclaimedFIFOMessageCountsMap.entrySet()) {
      String messageName = e.getKey();
      int messageCount = e.getValue();
      totalCount = totalCount + messageCount;
      unclaimedFIFOMessageCountsArray[i++] = new STMessageCount(messageName, messageCount);
    }
    Arrays.sort(
        unclaimedFIFOMessageCountsArray,
        (firstCount, secondCount) -> secondCount.messageCount - firstCount.messageCount);
    for (STMessageCount messageCountItem : unclaimedFIFOMessageCountsArray) {
      int thisMessageCount = messageCountItem.messageCount;
      double thisMessagePercentOfTotal = ((double) thisMessageCount) / ((double) totalCount);
      unclaimedFIFOMessageCountsList.addChild(
          "li",
          messageCountItem.messageName
              + COLON_NBSP
              + thisMessageCount
              + NBSP_OPEN_PAREN
              + fix3p1pct.format(thisMessagePercentOfTotal)
              + ')');
    }
    unclaimedFIFOMessageCountsList.addChild(
        "li", "Unclaimed Messages Considered" + COLON_NBSP + totalCount);
  }

  private void drawSwapStatsBox(
      HTMLNode locationSwapInfobox,
      double location,
      long nodeUptimeSeconds,
      double swaps,
      double noSwaps) {

    locationSwapInfobox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_HEADER, "Location swaps");
    int startedSwaps = node.network().startedSwaps();
    int swapsRejectedAlreadyLocked = node.network().swapsRejectedAlreadyLocked();
    int swapsRejectedNowhereToGo = node.network().swapsRejectedNowhereToGo();
    int swapsRejectedRateLimit = node.network().swapsRejectedRateLimit();
    int swapsRejectedRecognizedID = node.network().swapsRejectedRecognizedID();
    double locChangeSession = node.network().locationChangeSession();
    int averageSwapTime = node.network().averageOutgoingSwapTime();
    long sendSwapInterval = node.network().sendSwapInterval();

    HTMLNode locationSwapInfoboxContent =
        locationSwapInfobox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT);
    HTMLNode locationSwapList = locationSwapInfoboxContent.addChild("ul");
    addSwapEntry(locationSwapList, "location", Double.toString(location));
    boolean hasSwaps = swaps > 0.0;
    boolean hasUptime = nodeUptimeSeconds >= 60;
    boolean hasSwapsAndUptime = hasSwaps && hasUptime;
    addSwapEntryIf(
        locationSwapList, hasSwaps, "locChangeSession", fix1p6sci.format(locChangeSession));
    addSwapEntryIf(
        locationSwapList, hasSwaps, "locChangePerSwap", fix1p6sci.format(locChangeSession / swaps));
    addSwapEntryIf(
        locationSwapList,
        hasSwapsAndUptime,
        "locChangePerMinute",
        fix1p6sci.format(locChangeSession / (nodeUptimeSeconds / 60.0)));
    addSwapEntryIf(
        locationSwapList,
        hasSwapsAndUptime,
        "swapsPerMinute",
        fix1p6sci.format(swaps / (nodeUptimeSeconds / 60.0)));
    addSwapEntryIf(
        locationSwapList,
        noSwaps > 0.0 && hasUptime,
        "noSwapsPerMinute",
        fix1p6sci.format(noSwaps / (nodeUptimeSeconds / 60.0)));
    addSwapEntryIf(
        locationSwapList,
        hasSwaps && noSwaps > 0.0,
        "swapsPerNoSwaps",
        fix1p6sci.format(swaps / noSwaps));
    addSwapEntryIf(locationSwapList, hasSwaps, "swaps", Integer.toString((int) swaps));
    addSwapEntryIf(locationSwapList, noSwaps > 0.0, "noSwaps", Integer.toString((int) noSwaps));
    addSwapEntryIf(
        locationSwapList, startedSwaps > 0, "startedSwaps", Integer.toString(startedSwaps));
    addSwapEntryIf(
        locationSwapList,
        swapsRejectedAlreadyLocked > 0,
        "swapsRejectedAlreadyLocked",
        Integer.toString(swapsRejectedAlreadyLocked));
    addSwapEntryIf(
        locationSwapList,
        swapsRejectedNowhereToGo > 0,
        "swapsRejectedNowhereToGo",
        Integer.toString(swapsRejectedNowhereToGo));
    addSwapEntryIf(
        locationSwapList,
        swapsRejectedRateLimit > 0,
        "swapsRejectedRateLimit",
        Integer.toString(swapsRejectedRateLimit));
    addSwapEntryIf(
        locationSwapList,
        swapsRejectedRecognizedID > 0,
        "swapsRejectedRecognizedID",
        Integer.toString(swapsRejectedRecognizedID));
    addSwapEntry(
        locationSwapList, "averageSwapTime", TimeUtil.formatTime(averageSwapTime, 2, true));
    addSwapEntry(
        locationSwapList, "sendSwapInterval", TimeUtil.formatTime(sendSwapInterval, 2, true));
  }

  private void addSwapEntry(HTMLNode list, String label, String value) {
    list.addChild("li", label + COLON_NBSP + value);
  }

  private void addSwapEntryIf(HTMLNode list, boolean condition, String label, String value) {
    if (condition) {
      addSwapEntry(list, label, value);
    }
  }

  /**
   * Builds the peer statistics infobox, adding a localized header and list entries for every peer
   * status bucket that currently has a non-zero count. Routing back-off wording adapts to advanced
   * mode, while the other buckets always render their short and long labels. Entries use distinct
   * CSS classes, so the statistics page can visually differentiate states such as connected,
   * disconnected, listen-only, or routing-disabled peers.
   *
   * <p>Counts of seed servers and seed clients are displayed using the listening class for visual
   * grouping. The method queries the opennet manager to append configured connection targets when
   * present, enabling operators to compare current peer counts against desired limits without
   * leaving the page.
   *
   * @param peerStatsInfobox infobox root node receiving the generated header and list entries.
   * @param advancedModeEnabled whether advanced wording is allowed for routing back-off buckets.
   * @param counts peer status bucket counts for the current node snapshot.
   * @param node node whose opennet manager supplies configured target counts for display.
   */
  protected static void drawPeerStatsBox(
      HTMLNode peerStatsInfobox, boolean advancedModeEnabled, PeerStatusCounts counts, Node node) {

    peerStatsInfobox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_HEADER, l10n("peerStatsTitle"));
    HTMLNode peerStatsContent = peerStatsInfobox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT);
    HTMLNode peerStatsList = peerStatsContent.addChild("ul");
    addPeerStat(
        peerStatsList, counts.connected(), "peer_connected", CLASS_CONNECTED, "connectedShort");
    addPeerStat(
        peerStatsList,
        counts.routingBackedOff(),
        "peer_backed_off",
        advancedModeEnabled ? "backedOff" : "busy",
        advancedModeEnabled ? "backedOffShort" : "busyShort");
    addPeerStat(peerStatsList, counts.tooNew(), "peer_too_new", "tooNew", "tooNewShort");
    addPeerStat(peerStatsList, counts.tooOld(), "peer_too_old", "tooOld", "tooOldShort");
    addPeerStat(
        peerStatsList,
        counts.disconnected(),
        "peer_disconnected",
        "notConnected",
        "notConnectedShort");
    addPeerStat(
        peerStatsList,
        counts.neverConnected(),
        "peer_never_connected",
        "neverConnected",
        "neverConnectedShort");
    addPeerStat(peerStatsList, counts.disabled(), "peer_disabled", "disabled", "disabledShort");
    addPeerStat(peerStatsList, counts.bursting(), "peer_bursting", "bursting", "burstingShort");
    addPeerStat(
        peerStatsList, counts.listening(), PEER_LISTENING_CLASS, "listening", "listeningShort");
    addPeerStat(
        peerStatsList,
        counts.listenOnly(),
        PEER_LISTEN_ONLY_CLASS,
        "listenOnly",
        "listenOnlyShort");
    addPeerStat(
        peerStatsList,
        counts.seedServers(),
        PEER_LISTENING_CLASS,
        "seedServers",
        "seedServersShort");
    addPeerStat(
        peerStatsList,
        counts.seedClients(),
        PEER_LISTENING_CLASS,
        "seedClients",
        "seedClientsShort");
    addPeerStat(
        peerStatsList,
        counts.routingDisabled(),
        "peer_routing_disabled",
        "routingDisabled",
        "routingDisabledShort");
    addPeerStat(
        peerStatsList,
        counts.clockProblem(),
        "peer_clock_problem",
        "clockProblem",
        "clockProblemShort");
    addPeerStat(
        peerStatsList, counts.connError(), "peer_conn_error", "connError", "connErrorShort");
    addPeerStat(
        peerStatsList,
        counts.disconnecting(),
        "peer_disconnecting",
        "disconnecting",
        "disconnectingShort");
    addPeerStat(
        peerStatsList,
        counts.noLoadStats(),
        "peer_no_load_stats",
        "noLoadStats",
        "noLoadStatsShort");
    OpennetManager om = node.network().opennet();
    if (om != null) {
      peerStatsList.addChild(
          "li", l10n("maxTotalPeers") + ": " + om.getNumberOfConnectedPeersToAimIncludingDarknet());
      peerStatsList.addChild(
          "li", l10n("maxOpennetPeers") + ": " + om.getNumberOfConnectedPeersToAim());
    }
  }

  private static void addPeerStat(
      HTMLNode list, int count, String cssClass, String titleKey, String labelKey) {
    if (count <= 0) {
      return;
    }
    HTMLNode item = list.addChild("li").addChild("span");
    item.addChild(
        "span",
        new String[] {ATTR_CLASS, TITLE_ATTR, ATTR_STYLE},
        new String[] {cssClass, l10nDark(titleKey), HOVER_STYLE},
        l10nDark(labelKey));
    item.addChild("span", COLON_NBSP + count);
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString(STATS_PREFIX + key);
  }

  private static String l10nDark(String key) {
    return NodeL10n.getBase().getString("DarknetConnectionsToadlet." + key);
  }

  private static String l10n(String key, String pattern, String value) {
    return NodeL10n.getBase()
        .getString(STATS_PREFIX + key, new String[] {pattern}, new String[] {value});
  }

  private static String l10n(String key, String[] patterns, String[] values) {
    return NodeL10n.getBase().getString(STATS_PREFIX + key, patterns, values);
  }

  private void drawActivityBox(HTMLNode activityInfobox, boolean advancedModeEnabled) {

    activityInfobox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_HEADER, l10nDark("activityTitle"));
    HTMLNode activityInfoboxContent =
        activityInfobox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT);

    HTMLNode activityList = drawActivity(activityInfoboxContent, node);

    int numARKFetchers = node.network().numArkFetchers();

    if (advancedModeEnabled && activityList != null) {
      if (numARKFetchers > 0)
        activityList.addChild("li", "ARK\u00a0Fetch\u00a0Requests:\u00a0" + numARKFetchers);
      activityList.addChild(
          "li",
          "BackgroundFetcherByUSKSize:\u00a0"
              + node.services().clientCore().getUskManager().getBackgroundFetcherByUSKSize());
      activityList.addChild(
          "li",
          "temporaryBackgroundFetchersLRUSize:\u00a0"
              + node.services().clientCore().getUskManager().getTemporaryBackgroundFetchersLRU());
      activityList.addChild(
          "li",
          "outputBandwidthLiabilityUsage:\u00a0"
              + this.fix3p1pct.format(node.network().stats().getBandwidthLiabilityUsage()));
    }
  }

  static void drawBandwidth(
      HTMLNode activityList, Node node, long nodeUptimeSeconds, boolean isAdvancedModeEnabled) {
    long[] total = node.network().collector().getTotalIO();
    if (total[0] == 0 || total[1] == 0) return;
    long totalOutputRate = total[0] / nodeUptimeSeconds;
    long totalInputRate = total[1] / nodeUptimeSeconds;
    long totalPayload = node.getTotalPayloadSent();
    long totalPayloadRate = totalPayload / nodeUptimeSeconds;
    if (node.services().clientCore() == null) throw new NullPointerException();
    BandwidthStatsContainer stats =
        node.services()
            .clientCore()
            .getClientLayerPersister()
            .getBandwidthStatsPutter()
            .getLatestBWData();
    if (stats == null) throw new NullPointerException();
    long overallTotalOut = stats.getTotalBytesOut();
    long overallTotalIn = stats.getTotalBytesIn();
    int percent = (int) (100 * totalPayload / total[0]);
    long[] rate = node.network().stats().getNodeIOStats();
    long delta = (rate[5] - rate[2]) / 1000;
    if (delta > 0) {
      long outputRate = (rate[3] - rate[0]) / delta;
      long inputRate = (rate[4] - rate[1]) / delta;
      SubConfig nodeConfig = node.getConfig().get("node");
      int outputBandwidthLimit = nodeConfig.getInt("outputBandwidthLimit");
      int inputBandwidthLimit = nodeConfig.getInt("inputBandwidthLimit");
      if (inputBandwidthLimit == -1) {
        inputBandwidthLimit = outputBandwidthLimit * 4;
      }
      activityList.addChild(
          "li",
          l10n(
              "inputRate",
              new String[] {"rate", "max"},
              new String[] {
                SizeUtil.formatSize(inputRate, true), SizeUtil.formatSize(inputBandwidthLimit, true)
              }));
      activityList.addChild(
          "li",
          l10n(
              "outputRate",
              new String[] {"rate", "max"},
              new String[] {
                SizeUtil.formatSize(outputRate, true),
                SizeUtil.formatSize(outputBandwidthLimit, true)
              }));
    }
    activityList.addChild(
        "li",
        l10n(
            "totalInputSession",
            new String[] {TOTAL_KEY, "rate"},
            new String[] {
              SizeUtil.formatSize(total[1], true), SizeUtil.formatSize(totalInputRate, true)
            }));
    activityList.addChild(
        "li",
        l10n(
            "totalOutputSession",
            new String[] {TOTAL_KEY, "rate"},
            new String[] {
              SizeUtil.formatSize(total[0], true), SizeUtil.formatSize(totalOutputRate, true)
            }));
    activityList.addChild(
        "li",
        l10n(
            "payloadOutput",
            new String[] {TOTAL_KEY, "rate", PERCENT_KEY},
            new String[] {
              SizeUtil.formatSize(totalPayload, true),
              SizeUtil.formatSize(totalPayloadRate, true),
              Integer.toString(percent)
            }));
    activityList.addChild(
        "li",
        l10n(
            "totalInput",
            new String[] {TOTAL_KEY},
            new String[] {SizeUtil.formatSize(overallTotalIn, true)}));
    activityList.addChild(
        "li",
        l10n(
            "totalOutput",
            new String[] {TOTAL_KEY},
            new String[] {SizeUtil.formatSize(overallTotalOut, true)}));
    if (isAdvancedModeEnabled) {
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
      activityList.addChild(
          "li",
          l10n(
              "requestOutput",
              new String[] {"chk", "ssk"},
              new String[] {
                SizeUtil.formatSize(totalBytesSentCHKRequests, true),
                SizeUtil.formatSize(totalBytesSentSSKRequests, true)
              }));
      activityList.addChild(
          "li",
          l10n(
              "insertOutput",
              new String[] {"chk", "ssk"},
              new String[] {
                SizeUtil.formatSize(totalBytesSentCHKInserts, true),
                SizeUtil.formatSize(totalBytesSentSSKInserts, true)
              }));
      activityList.addChild(
          "li",
          l10n(
              "offeredKeyOutput",
              new String[] {TOTAL_KEY, "offered"},
              new String[] {
                SizeUtil.formatSize(totalBytesSentOfferedKeys, true),
                SizeUtil.formatSize(totalBytesSendOffers, true)
              }));
      activityList.addChild(
          "li", l10n("swapOutput", TOTAL_KEY, SizeUtil.formatSize(totalBytesSentSwapOutput, true)));
      activityList.addChild(
          "li", l10n("authBytes", TOTAL_KEY, SizeUtil.formatSize(totalBytesSentAuth, true)));
      activityList.addChild(
          "li", l10n("ackOnlyBytes", TOTAL_KEY, SizeUtil.formatSize(totalBytesSentAckOnly, true)));
      activityList.addChild(
          "li",
          l10n(
              "resendBytes",
              new String[] {TOTAL_KEY, PERCENT_KEY},
              new String[] {
                SizeUtil.formatSize(totalBytesSentResends, true),
                Long.toString((100 * totalBytesSentResends) / Math.max(1, total[0]))
              }));
      activityList.addChild(
          "li", l10n("uomBytes", TOTAL_KEY, SizeUtil.formatSize(totalBytesSentUOM, true)));
      activityList.addChild(
          "li",
          l10n(
              "announceBytes",
              new String[] {TOTAL_KEY, "payload"},
              new String[] {
                SizeUtil.formatSize(totalBytesSentAnnounce, true),
                SizeUtil.formatSize(totalBytesSentAnnouncePayload, true)
              }));
      activityList.addChild(
          "li",
          l10n(
              "adminBytes",
              new String[] {"routingStatus", "disconn", "initial", "changedIP"},
              new String[] {
                SizeUtil.formatSize(totalBytesSentRoutingStatus, true),
                SizeUtil.formatSize(totalBytesSentDisconn, true),
                SizeUtil.formatSize(totalBytesSentInitial, true),
                SizeUtil.formatSize(totalBytesSentChangedIP, true)
              }));
      activityList.addChild(
          "li",
          l10n(
              "debuggingBytes",
              new String[] {"netColoring", "ping", "probe", "routed"},
              new String[] {
                SizeUtil.formatSize(totalBytesSentNetworkColoring, true),
                SizeUtil.formatSize(totalBytesSentPing, true),
                SizeUtil.formatSize(totalBytesSentProbeRequest, true),
                SizeUtil.formatSize(totalBytesSentRouted, true)
              }));
      activityList.addChild(
          "li",
          l10n("nodeToNodeBytes", TOTAL_KEY, SizeUtil.formatSize(totalBytesSentNodeToNode, true)));
      activityList.addChild(
          "li",
          l10n(
              "loadAllocationNoticesBytes",
              TOTAL_KEY,
              SizeUtil.formatSize(totalBytesSentAllocationNotices, true)));
      activityList.addChild(
          "li", l10n("foafBytes", TOTAL_KEY, SizeUtil.formatSize(totalBytesSentFOAF, true)));
      activityList.addChild(
          "li",
          l10n(
              "unaccountedBytes",
              new String[] {TOTAL_KEY, PERCENT_KEY},
              new String[] {
                SizeUtil.formatSize(totalBytesSentRemaining, true),
                Integer.toString((int) (totalBytesSentRemaining * 100 / total[0]))
              }));
      double sentOverheadPerSecond = node.network().stats().getSentOverheadPerSecond();
      activityList.addChild(
          "li",
          l10n(
              "totalOverhead",
              new String[] {"rate", PERCENT_KEY},
              new String[] {
                SizeUtil.formatSize((long) sentOverheadPerSecond),
                Integer.toString((int) ((100 * sentOverheadPerSecond) / totalOutputRate))
              }));
    }
  }

  static HTMLNode drawActivity(HTMLNode activityInfoboxContent, Node node) {
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
    int numCHKOfferReplys = tracker.getNumCHKOfferReplies();
    int numSSKOfferReplys = tracker.getNumSSKOfferReplies();
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
        && (numCHKOfferReplys == 0)
        && (numSSKOfferReplys == 0)) {
      activityInfoboxContent.addChild("#", l10n("noRequests"));

      return null;
    } else {
      HTMLNode activityList = activityInfoboxContent.addChild("ul");
      if (numCHKInserts > 0 || numSSKInserts > 0) {
        activityList.addChild(
            "li",
            NodeL10n.getBase()
                .getString(
                    "StatisticsToadlet.activityInserts",
                    new String[] {"CHKhandlers", "SSKhandlers", "local"},
                    new String[] {
                      Integer.toString(numCHKInserts),
                      Integer.toString(numSSKInserts),
                      numLocalCHKInserts + "/" + numLocalSSKInserts
                    }));
      }
      if (numCHKRequests > 0 || numSSKRequests > 0) {
        activityList.addChild(
            "li",
            NodeL10n.getBase()
                .getString(
                    "StatisticsToadlet.activityRequests",
                    new String[] {"CHKhandlers", "SSKhandlers", "local"},
                    new String[] {
                      Integer.toString(numCHKRequests),
                      Integer.toString(numSSKRequests),
                      numLocalCHKRequests + "/" + numLocalSSKRequests
                    }));
      }
      if (numTransferringRequests > 0 || numTransferringRequestHandlers > 0) {
        activityList.addChild(
            "li",
            NodeL10n.getBase()
                .getString(
                    "StatisticsToadlet.transferringRequests",
                    new String[] {"senders", "receivers", "turtles"},
                    new String[] {
                      Integer.toString(numTransferringRequests),
                      Integer.toString(numTransferringRequestHandlers),
                      "0"
                    }));
      }
      if (numCHKOfferReplys > 0 || numSSKOfferReplys > 0) {
        activityList.addChild(
            "li",
            NodeL10n.getBase()
                .getString(
                    "StatisticsToadlet.offerReplys",
                    new String[] {"chk", "ssk"},
                    new String[] {
                      Integer.toString(numCHKOfferReplys), Integer.toString(numSSKOfferReplys)
                    }));
      }
      activityList.addChild(
          "li",
          NodeL10n.getBase()
              .getString(
                  "StatisticsToadlet.runningBlockTransfers",
                  new String[] {"sends", "receives"},
                  new String[] {
                    Integer.toString(BlockTransmitter.getRunningSends()),
                    Integer.toString(BlockReceiver.getRunningReceives())
                  }));
      return activityList;
    }
  }

  private void drawOverviewBox(
      HTMLNode overviewInfobox,
      long nodeUptimeSeconds,
      long nodeUptimeTotal,
      long now,
      double swaps,
      double noSwaps) {

    overviewInfobox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_HEADER, "Node status overview");
    HTMLNode overviewInfoboxContent =
        overviewInfobox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT);
    HTMLNode overviewList = overviewInfoboxContent.addChild("ul");
    /* node status values */
    int bwlimitDelayTime = (int) stats.getBwlimitDelayTime();
    int bwlimitDelayTimeBulk = (int) stats.getBwlimitDelayTimeBulk();
    int bwlimitDelayTimeRT = (int) stats.getBwlimitDelayTimeRT();
    int nodeAveragePingTime = (int) stats.getNodeAveragePingTime();
    double numberOfRemotePeerLocationsSeenInSwaps =
        node.network().numberOfRemotePeerLocationsSeenInSwaps();

    // Darknet
    int darknetSizeEstimateSession = stats.getDarknetSizeEstimate(-1);
    int darknetSizeEstimate24h = 0;
    int darknetSizeEstimate48h = 0;
    if (nodeUptimeSeconds > HOURS.toSeconds(24)) {
      darknetSizeEstimate24h = stats.getDarknetSizeEstimate(now - HOURS.toMillis(24));
    }
    if (nodeUptimeSeconds > HOURS.toSeconds(48)) {
      darknetSizeEstimate48h = stats.getDarknetSizeEstimate(now - HOURS.toMillis(48));
    }
    // Opennet
    int opennetSizeEstimateSession = stats.getOpennetSizeEstimate(-1);
    int opennetSizeEstimate24h = 0;
    int opennetSizeEstimate48h = 0;
    if (nodeUptimeSeconds > HOURS.toSeconds(24)) {
      opennetSizeEstimate24h = stats.getOpennetSizeEstimate(now - HOURS.toMillis(24));
    }
    if (nodeUptimeSeconds > HOURS.toSeconds(48)) {
      opennetSizeEstimate48h = stats.getOpennetSizeEstimate(now - HOURS.toMillis(48));
    }

    double routingMissDistanceLocal = stats.routingMissDistanceLocal.currentValue();
    double routingMissDistanceRemote = stats.routingMissDistanceRemote.currentValue();
    double routingMissDistanceOverall = stats.routingMissDistanceOverall.currentValue();
    double routingMissDistanceBulk = stats.routingMissDistanceBulk.currentValue();
    double routingMissDistanceRT = stats.routingMissDistanceRT.currentValue();
    double backedOffPercent = stats.backedOffPercent.currentValue();
    overviewList.addChild("li", "bwlimitDelayTime:\u00a0" + bwlimitDelayTime + "ms");
    overviewList.addChild("li", "bwlimitDelayTimeBulk:\u00a0" + bwlimitDelayTimeBulk + "ms");
    overviewList.addChild("li", "bwlimitDelayTimeRT:\u00a0" + bwlimitDelayTimeRT + "ms");
    overviewList.addChild("li", "nodeAveragePingTime:\u00a0" + nodeAveragePingTime + "ms");
    overviewList.addChild(
        "li", "darknetSizeEstimateSession:\u00a0" + darknetSizeEstimateSession + NBSP_NODES);
    if (nodeUptimeSeconds > DAYS.toSeconds(1)) {
      overviewList.addChild(
          "li", "darknetSizeEstimate24h:\u00a0" + darknetSizeEstimate24h + NBSP_NODES);
    }
    if (nodeUptimeSeconds > DAYS.toSeconds(2)) {
      overviewList.addChild(
          "li", "darknetSizeEstimate48h:\u00a0" + darknetSizeEstimate48h + NBSP_NODES);
    }
    overviewList.addChild(
        "li", "opennetSizeEstimateSession:\u00a0" + opennetSizeEstimateSession + NBSP_NODES);
    if (nodeUptimeSeconds > DAYS.toSeconds(1)) {
      overviewList.addChild(
          "li", "opennetSizeEstimate24h:\u00a0" + opennetSizeEstimate24h + NBSP_NODES);
    }
    if (nodeUptimeSeconds > DAYS.toSeconds(2)) {
      overviewList.addChild(
          "li", "opennetSizeEstimate48h:\u00a0" + opennetSizeEstimate48h + NBSP_NODES);
    }
    if ((numberOfRemotePeerLocationsSeenInSwaps > 0.0) && ((swaps > 0.0) || (noSwaps > 0.0))) {
      overviewList.addChild(
          "li",
          "avrConnPeersPerNode:\u00a0"
              + fix6p6.format(numberOfRemotePeerLocationsSeenInSwaps / (swaps + noSwaps))
              + "\u00a0peers");
    }
    overviewList.addChild(
        "li",
        "nodeUptimeSession:\u00a0"
            + TimeUtil.formatTime(MILLISECONDS.convert(nodeUptimeSeconds, SECONDS)));
    overviewList.addChild("li", "nodeUptimeTotal:\u00a0" + TimeUtil.formatTime(nodeUptimeTotal));
    overviewList.addChild(
        "li", "routingMissDistanceLocal:\u00a0" + fix1p4.format(routingMissDistanceLocal));
    overviewList.addChild(
        "li", "routingMissDistanceRemote:\u00a0" + fix1p4.format(routingMissDistanceRemote));
    overviewList.addChild(
        "li", "routingMissDistanceOverall:\u00a0" + fix1p4.format(routingMissDistanceOverall));
    overviewList.addChild(
        "li", "routingMissDistanceBulk:\u00a0" + fix1p4.format(routingMissDistanceBulk));
    overviewList.addChild(
        "li", "routingMissDistanceRT:\u00a0" + fix1p4.format(routingMissDistanceRT));
    overviewList.addChild("li", "backedOffPercent:\u00a0" + fix3p1pct.format(backedOffPercent));
    overviewList.addChild(
        "li", "pInstantReject:\u00a0" + fix3p1pct.format(stats.pRejectIncomingInstantly()));
    overviewList.addChild(
        "li",
        "pInstantRejectRequestBulk:\u00a0"
            + fix3p1pct.format(stats.pRejectIncomingInstantlyCHKRequestBulk())
            + CHK_SUFFIX
            + fix3p1pct.format(stats.pRejectIncomingInstantlySSKRequestBulk())
            + SSK_SUFFIX);
    overviewList.addChild(
        "li",
        "pInstantRejectInsertBulk:\u00a0"
            + fix3p1pct.format(stats.pRejectIncomingInstantlyCHKInsertBulk())
            + CHK_SUFFIX
            + fix3p1pct.format(stats.pRejectIncomingInstantlySSKInsertBulk())
            + SSK_SUFFIX);
    overviewList.addChild(
        "li",
        "pInstantRejectRequestRT:\u00a0"
            + fix3p1pct.format(stats.pRejectIncomingInstantlyCHKRequestRT())
            + CHK_SUFFIX
            + fix3p1pct.format(stats.pRejectIncomingInstantlySSKRequestRT())
            + SSK_SUFFIX);
    overviewList.addChild(
        "li",
        "pInstantRejectInsertRT:\u00a0"
            + fix3p1pct.format(stats.pRejectIncomingInstantlyCHKInsertRT())
            + CHK_SUFFIX
            + fix3p1pct.format(stats.pRejectIncomingInstantlySSKInsertRT())
            + SSK_SUFFIX);
    overviewList.addChild("li", "unclaimedFIFOSize:\u00a0" + node.network().unclaimedFifoSize());
    overviewList.addChild(
        "li",
        "RAMBucketPoolSize:\u00a0"
            + SizeUtil.formatSize(core.getTempBucketFactory().getRamUsed())
            + " / "
            + SizeUtil.formatSize(core.getTempBucketFactory().getMaxRamUsed()));
    overviewList.addChild(
        "li",
        "uptimeAverage:\u00a0" + fix3p1pct.format(node.network().uptimeEstimator().getUptime()));

    long[] decoded = IncomingPacketFilterImpl.getDecodedPackets();
    if (decoded != null) {
      overviewList.addChild(
          "li",
          "packetsDecoded:\u00a0"
              + fix3p1pct.format(((double) decoded[0]) / ((double) decoded[1]))
              + NBSP_OPEN_PAREN
              + decoded[1]
              + ")");
    }
  }

  private void drawBandwidthBox(
      HTMLNode bandwidthInfobox, long nodeUptimeSeconds, boolean isAdvancedModeEnabled) {

    bandwidthInfobox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_HEADER, l10n("bandwidthTitle"));
    HTMLNode bandwidthInfoboxContent =
        bandwidthInfobox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT);
    HTMLNode bandwidthList = bandwidthInfoboxContent.addChild("ul");
    drawBandwidth(bandwidthList, node, nodeUptimeSeconds, isAdvancedModeEnabled);
  }

  private void getThreadNames(HTMLNode threadUsageList) {
    Thread[] threads = stats.getThreads();

    Map<String, Integer> counts = new LinkedHashMap<>();
    int totalCount = 0;
    for (Thread thread : threads) {
      if (thread == null) break;
      String name = NativeThread.normalizeName(thread.getName());
      counts.put(name, counts.getOrDefault(name, 0) + 1);
      totalCount++;
    }
    ThreadBunch[] bunches =
        counts.entrySet().stream()
            .map(entry -> new ThreadBunch(entry.getKey(), entry.getValue()))
            .toArray(ThreadBunch[]::new);
    Arrays.sort(
        bunches,
        (b0, b1) -> {
          if (b0.count() > b1.count()) {
            return -1;
          }
          if (b0.count() < b1.count()) {
            return 1;
          }
          return b0.name().compareTo(b1.name());
        });
    double thisThreadPercentOfTotal;
    for (ThreadBunch bunch : bunches) {
      thisThreadPercentOfTotal = ((double) bunch.count()) / ((double) totalCount);
      threadUsageList.addChild(
          "li",
          bunch.name()
              + COLON_NBSP
              + bunch.count()
              + NBSP_OPEN_PAREN
              + fix3p1pct.format(thisThreadPercentOfTotal)
              + ')');
    }
  }

  private record ThreadBunch(String name, int count) {}

  private static final int PEER_CIRCLE_RADIUS = 100;
  private static final int PEER_CIRCLE_INNER_RADIUS = 60;
  private static final int PEER_CIRCLE_ADDITIONAL_FREE_SPACE = 10;
  private static final long MAX_CIRCLE_AGE_THRESHOLD = HOURS.toMillis(24);
  private static final int HISTOGRAM_LENGTH = 10;

  private void addHistogramLegendCell(HTMLNode legendRow, String label, boolean highlight) {
    HTMLNode legendCell = legendRow.addChild("td");
    HTMLNode labelNode = legendCell.addChild("div", ATTR_CLASS, HISTOGRAM_LABEL_CLASS);
    if (highlight) {
      labelNode = labelNode.addChild("span", ATTR_CLASS, "me");
    }
    labelNode.addChild("#", label);
  }

  private HTMLNode createHistogramGraphCell(HTMLNode graphRow) {
    return graphRow.addChild("td", ATTR_STYLE, HEIGHT_100PX);
  }

  private void addHistogramBar(HTMLNode graphCell, String cssClass, double fraction) {
    graphCell.addChild(
        "div",
        new String[] {ATTR_CLASS, ATTR_STYLE},
        new String[] {cssClass, heightStyle(fraction)},
        NBSP);
  }

  private String heightStyle(double fraction) {
    return HEIGHT_PREFIX + fix3pctUS.format(fraction) + WIDTH_100;
  }

  private static final class HistogramComputationResult {
    private final int[] histogram;
    private final int totalCount;

    private HistogramComputationResult(int[] histogram, int totalCount) {
      this.histogram = histogram;
      this.totalCount = totalCount;
    }

    int[] histogram() {
      return histogram;
    }

    int totalCount() {
      return totalCount;
    }

    @Override
    public boolean equals(Object o) {
      if (!(o instanceof HistogramComputationResult other)) {
        return false;
      }
      return totalCount == other.totalCount && Arrays.equals(histogram, other.histogram);
    }

    @Override
    public int hashCode() {
      int result = Integer.hashCode(totalCount);
      result = 31 * result + Arrays.hashCode(histogram);
      return result;
    }

    @Override
    public @NotNull String toString() {
      return "HistogramComputationResult[histogram="
          + Arrays.toString(histogram)
          + ", totalCount="
          + totalCount
          + "]";
    }
  }

  private int simpleHistogramDivisor(int[] a) {
    int max = 1;
    for (int j : a) {
      if (j > max) max = j;
    }
    return max;
  }

  private int combinedHistogramDivisor(int[] a, int[] b) {
    int max = 1;
    for (int i = 0; i < a.length; i++) {
      if (a[i] + b[i] > max) max = a[i] + b[i];
    }
    return max;
  }

  private void addNodeCircle(HTMLNode circleTable, double myLocation) {
    int[] histogram = new int[HISTOGRAM_LENGTH];
    HTMLNode nodeCircleTableRow = circleTable.addChild("tr");
    HTMLNode nodeHistogramLegendTableRow = circleTable.addChild("tr");
    HTMLNode nodeHistogramGraphTableRow = circleTable.addChild("tr");
    HTMLNode nodeCircleTableCell =
        nodeCircleTableRow.addChild(
            "td", new String[] {ATTR_CLASS, "colspan"}, new String[] {CLASS_FIRST, "10"});
    HTMLNode nodeHistogramGraphCell;
    HTMLNode nodeCircleInfoboxContent =
        nodeCircleTableCell.addChild(
            "div",
            new String[] {ATTR_STYLE, ATTR_CLASS},
            new String[] {
              "position: relative; height: "
                  + ((PEER_CIRCLE_RADIUS + PEER_CIRCLE_ADDITIONAL_FREE_SPACE) * 2)
                  + "px; width: "
                  + ((PEER_CIRCLE_RADIUS + PEER_CIRCLE_ADDITIONAL_FREE_SPACE) * 2)
                  + "px",
              "peercircle"
            });
    nodeCircleInfoboxContent.addChild(
        "span",
        new String[] {ATTR_STYLE, ATTR_CLASS},
        new String[] {generatePeerCircleStyleString(0, false, 1.0), "mark"},
        "|");
    nodeCircleInfoboxContent.addChild(
        "span",
        new String[] {ATTR_STYLE, ATTR_CLASS},
        new String[] {generatePeerCircleStyleString(0.125, false, 1.0), "mark"},
        "+");
    nodeCircleInfoboxContent.addChild(
        "span",
        new String[] {ATTR_STYLE, ATTR_CLASS},
        new String[] {generatePeerCircleStyleString(0.25, false, 1.0), "mark"},
        "--");
    nodeCircleInfoboxContent.addChild(
        "span",
        new String[] {ATTR_STYLE, ATTR_CLASS},
        new String[] {generatePeerCircleStyleString(0.375, false, 1.0), "mark"},
        "+");
    nodeCircleInfoboxContent.addChild(
        "span",
        new String[] {ATTR_STYLE, ATTR_CLASS},
        new String[] {generatePeerCircleStyleString(0.5, false, 1.0), "mark"},
        "|");
    nodeCircleInfoboxContent.addChild(
        "span",
        new String[] {ATTR_STYLE, ATTR_CLASS},
        new String[] {generatePeerCircleStyleString(0.625, false, 1.0), "mark"},
        "+");
    nodeCircleInfoboxContent.addChild(
        "span",
        new String[] {ATTR_STYLE, ATTR_CLASS},
        new String[] {generatePeerCircleStyleString(0.75, false, 1.0), "mark"},
        "--");
    nodeCircleInfoboxContent.addChild(
        "span",
        new String[] {ATTR_STYLE, ATTR_CLASS},
        new String[] {generatePeerCircleStyleString(0.875, false, 1.0), "mark"},
        "+");
    nodeCircleInfoboxContent.addChild(
        "span",
        new String[] {ATTR_STYLE, ATTR_CLASS},
        new String[] {
          POSITION_TOP
              + PEER_CIRCLE_RADIUS
              + PX_LEFT
              + (PEER_CIRCLE_RADIUS + PEER_CIRCLE_ADDITIONAL_FREE_SPACE)
              + "px",
          "mark"
        },
        "+");
    final Object[] knownLocsCopy = stats.getKnownLocations(-1);
    final Double[] locations = (Double[]) knownLocsCopy[0];
    final Long[] timestamps = (Long[]) knownLocsCopy[1];
    Double location;
    Long locationTime;
    long now = System.currentTimeMillis();
    long age;
    int histogramIndex;
    for (int i = 0; i < locations.length; i++) {
      location = locations[i];
      locationTime = timestamps[i];
      age = now - locationTime;
      if (age > MAX_CIRCLE_AGE_THRESHOLD) {
        age = MAX_CIRCLE_AGE_THRESHOLD;
      }
      double strength = 1 - ((double) age / MAX_CIRCLE_AGE_THRESHOLD);
      histogramIndex = (int) Math.floor(location * HISTOGRAM_LENGTH);
      histogram[histogramIndex]++;

      nodeCircleInfoboxContent.addChild(
          "span",
          new String[] {ATTR_STYLE, ATTR_CLASS},
          new String[] {generatePeerCircleStyleString(location, false, strength), CLASS_CONNECTED},
          "x");
    }
    nodeCircleInfoboxContent.addChild(
        "span",
        new String[] {ATTR_STYLE, ATTR_CLASS},
        new String[] {generatePeerCircleStyleString(myLocation, true, 1.0), "me"},
        "x");
    //
    int histogramDiv =
        simpleHistogramDivisor(histogram); // Prevent division by 0 on empty histograms.
    double histogramPercent;
    for (int i = 0; i < HISTOGRAM_LENGTH; i++) {
      addHistogramLegendCell(
          nodeHistogramLegendTableRow, fix1p1.format(((double) i) / HISTOGRAM_LENGTH), false);
      nodeHistogramGraphCell = createHistogramGraphCell(nodeHistogramGraphTableRow);
      histogramPercent = (double) histogram[i] / histogramDiv;

      addHistogramBar(nodeHistogramGraphCell, HISTOGRAM_CONNECTED_CLASS, histogramPercent);
    }
  }

  private void addSpecialisation(
      HTMLNode table, double peerLocation, int[] incomingRequestLocation) {
    HTMLNode nodeHistogramLegendTableRow = table.addChild("tr");
    HTMLNode nodeHistogramGraphTableRow = table.addChild("tr");
    int myIndex = (int) (peerLocation * incomingRequestLocation.length);
    int histogramDiv = simpleHistogramDivisor(incomingRequestLocation);
    for (int i = 0; i < incomingRequestLocation.length; i++) {
      addHistogramLegendCell(
          nodeHistogramLegendTableRow,
          fix1p1.format(((double) i) / incomingRequestLocation.length),
          i == myIndex);
      HTMLNode nodeHistogramGraphCell = createHistogramGraphCell(nodeHistogramGraphTableRow);
      addHistogramBar(
          nodeHistogramGraphCell,
          HISTOGRAM_CONNECTED_CLASS,
          ((double) incomingRequestLocation[i]) / histogramDiv);
    }
  }

  private void addCombinedSpecialisation(
      HTMLNode table,
      double peerLocation,
      int[] locallyOriginatingRequests,
      int[] remotelyOriginatingRequests) {
    assert (locallyOriginatingRequests.length == remotelyOriginatingRequests.length);
    HTMLNode nodeHistogramLegendTableRow = table.addChild("tr");
    HTMLNode nodeHistogramGraphTableRow = table.addChild("tr");
    int myIndex = (int) (peerLocation * locallyOriginatingRequests.length);
    int histogramDiv =
        combinedHistogramDivisor(locallyOriginatingRequests, remotelyOriginatingRequests);
    for (int i = 0; i < locallyOriginatingRequests.length; i++) {
      addHistogramLegendCell(
          nodeHistogramLegendTableRow,
          fix1p1.format(((double) i) / locallyOriginatingRequests.length),
          i == myIndex);
      HTMLNode nodeHistogramGraphCell = createHistogramGraphCell(nodeHistogramGraphTableRow);
      addHistogramBar(
          nodeHistogramGraphCell,
          HISTOGRAM_CONNECTED_CLASS,
          ((double) locallyOriginatingRequests[i]) / histogramDiv);
      addHistogramBar(
          nodeHistogramGraphCell,
          HISTOGRAM_DISCONNECTED,
          ((double) remotelyOriginatingRequests[i]) / histogramDiv);
    }
  }

  private HistogramComputationResult computeFoafHistogram(PeerNodeStatus[] peerNodeStatuses) {
    int[] peersLinkHistogram = new int[HISTOGRAM_LENGTH];
    int peersLinkCount = 0;

    for (PeerNodeStatus peerNodeStatus : peerNodeStatuses) {
      if (!peerNodeStatus.isSearchable() || !peerNodeStatus.isRoutable()) {
        continue;
      }

      double peerLoc = peerNodeStatus.getLocation();
      double[] foafLocs = peerNodeStatus.getPeersLocation();
      if (Location.isValid(peerLoc) && foafLocs != null) {
        for (double foafLoc : foafLocs) {
          if (!Location.isValid(foafLoc)) {
            continue;
          }

          int idx = (int) Math.floor(Location.distance(peerLoc, foafLoc) * HISTOGRAM_LENGTH / 0.5);
          peersLinkHistogram[idx]++;
          peersLinkCount++;
        }
      }
    }

    return new HistogramComputationResult(peersLinkHistogram, peersLinkCount);
  }

  private void addFOAFLinkLengthHistogram(HTMLNode circleTable, PeerNodeStatus[] peerNodeStatuses) {
    HistogramComputationResult foafHistogram = computeFoafHistogram(peerNodeStatuses);
    int[] peersLinkHistogram = foafHistogram.histogram;
    int peersLinkCount = foafHistogram.totalCount;

    HTMLNode peerHistogramLegendTableRow = circleTable.addChild("tr");
    HTMLNode peerHistogramGraphTableRow = circleTable.addChild("tr");

    double cumulativeFraction = 0;
    for (int i = 0; i < HISTOGRAM_LENGTH; i++) {
      addHistogramLegendCell(
          peerHistogramLegendTableRow, fix1p2.format(((double) i) / HISTOGRAM_LENGTH * 0.5), false);
      HTMLNode peerHistogramGraphCell = createHistogramGraphCell(peerHistogramGraphTableRow);
      if (peersLinkCount == 0) continue;

      double histogramFraction = ((double) peersLinkHistogram[i]) / peersLinkCount;
      addHistogramBar(peerHistogramGraphCell, HISTOGRAM_CONNECTED_CLASS, histogramFraction);
      addHistogramBar(peerHistogramGraphCell, HISTOGRAM_DISCONNECTED, cumulativeFraction);
      cumulativeFraction += histogramFraction;
    }
  }

  private void populatePeerCircleData(
      PeerNodeStatus[] peerNodeStatuses,
      HTMLNode peerCircleInfoboxContent,
      int[] histogramConnected,
      int[] histogramDisconnected) {
    for (PeerNodeStatus peerNodeStatus : peerNodeStatuses) {
      double peerLocation = peerNodeStatus.getLocation();
      if (!peerNodeStatus.isSearchable() || !Location.isValid(peerLocation)) {
        continue;
      }
      addFoafLocations(peerCircleInfoboxContent, peerNodeStatus);
      int histogramIndex = (int) (peerLocation * HISTOGRAM_LENGTH);
      histogramIndex %= HISTOGRAM_LENGTH; // Map (unlikely) location 1.0 to 0.0
      if (peerNodeStatus.isConnected()) {
        histogramConnected[histogramIndex]++;
      } else {
        histogramDisconnected[histogramIndex]++;
      }
      addPeerMarker(peerCircleInfoboxContent, peerNodeStatus, peerLocation);
    }
  }

  private void addFoafLocations(HTMLNode peerCircleInfoboxContent, PeerNodeStatus peerNodeStatus) {
    double[] foafLocations = peerNodeStatus.getPeersLocation();
    if (foafLocations == null || !peerNodeStatus.isRoutable()) {
      return;
    }
    for (double foafLocation : foafLocations) {
      if (!Location.isValid(foafLocation)) {
        continue;
      }
      peerCircleInfoboxContent.addChild(
          "span",
          new String[] {ATTR_STYLE, ATTR_CLASS},
          new String[] {
            generatePeerCircleStyleString(foafLocation, false, 0.9), CLASS_DISCONNECTED
          },
          ".");
    }
  }

  private void addPeerMarker(
      HTMLNode peerCircleInfoboxContent, PeerNodeStatus peerNodeStatus, double peerLocation) {
    peerCircleInfoboxContent.addChild(
        "span",
        new String[] {ATTR_STYLE, ATTR_CLASS},
        new String[] {
          generatePeerCircleStyleString(peerLocation, false, (1.0 - peerNodeStatus.getPReject())),
          (peerNodeStatus.isConnected() ? CLASS_CONNECTED : CLASS_DISCONNECTED)
        },
        (peerNodeStatus.isOpennet() ? "o" : "x"));
  }

  private void addPeerCircle(
      HTMLNode circleTable, PeerNodeStatus[] peerNodeStatuses, double myLocation) {
    int[] histogramConnected = new int[HISTOGRAM_LENGTH];
    int[] histogramDisconnected = new int[HISTOGRAM_LENGTH];
    Arrays.fill(histogramConnected, 0);
    Arrays.fill(histogramDisconnected, 0);
    HTMLNode peerCircleTableRow = circleTable.addChild("tr");
    HTMLNode peerHistogramLegendTableRow = circleTable.addChild("tr");
    HTMLNode peerHistogramGraphTableRow = circleTable.addChild("tr");
    HTMLNode peerCircleTableCell =
        peerCircleTableRow.addChild(
            "td", new String[] {ATTR_CLASS, "colspan"}, new String[] {CLASS_FIRST, "10"});
    HTMLNode peerCircleInfoboxContent =
        peerCircleTableCell.addChild(
            "div",
            new String[] {ATTR_STYLE, ATTR_CLASS},
            new String[] {
              "position: relative; height: "
                  + ((PEER_CIRCLE_RADIUS + PEER_CIRCLE_ADDITIONAL_FREE_SPACE) * 2)
                  + "px; width: "
                  + ((PEER_CIRCLE_RADIUS + PEER_CIRCLE_ADDITIONAL_FREE_SPACE) * 2)
                  + "px",
              "peercircle"
            });
    peerCircleInfoboxContent.addChild(
        "span",
        new String[] {ATTR_STYLE, ATTR_CLASS},
        new String[] {generatePeerCircleStyleString(0, false, 1.0), "mark"},
        "|");
    peerCircleInfoboxContent.addChild(
        "span",
        new String[] {ATTR_STYLE, ATTR_CLASS},
        new String[] {generatePeerCircleStyleString(0.125, false, 1.0), "mark"},
        "+");
    peerCircleInfoboxContent.addChild(
        "span",
        new String[] {ATTR_STYLE, ATTR_CLASS},
        new String[] {generatePeerCircleStyleString(0.25, false, 1.0), "mark"},
        "--");
    peerCircleInfoboxContent.addChild(
        "span",
        new String[] {ATTR_STYLE, ATTR_CLASS},
        new String[] {generatePeerCircleStyleString(0.375, false, 1.0), "mark"},
        "+");
    peerCircleInfoboxContent.addChild(
        "span",
        new String[] {ATTR_STYLE, ATTR_CLASS},
        new String[] {generatePeerCircleStyleString(0.5, false, 1.0), "mark"},
        "|");
    peerCircleInfoboxContent.addChild(
        "span",
        new String[] {ATTR_STYLE, ATTR_CLASS},
        new String[] {generatePeerCircleStyleString(0.625, false, 1.0), "mark"},
        "+");
    peerCircleInfoboxContent.addChild(
        "span",
        new String[] {ATTR_STYLE, ATTR_CLASS},
        new String[] {generatePeerCircleStyleString(0.75, false, 1.0), "mark"},
        "--");
    peerCircleInfoboxContent.addChild(
        "span",
        new String[] {ATTR_STYLE, ATTR_CLASS},
        new String[] {generatePeerCircleStyleString(0.875, false, 1.0), "mark"},
        "+");
    peerCircleInfoboxContent.addChild(
        "span",
        new String[] {ATTR_STYLE, ATTR_CLASS},
        new String[] {
          POSITION_TOP
              + PEER_CIRCLE_RADIUS
              + PX_LEFT
              + (PEER_CIRCLE_RADIUS + PEER_CIRCLE_ADDITIONAL_FREE_SPACE)
              + "px",
          "mark"
        },
        "+");

    populatePeerCircleData(
        peerNodeStatuses, peerCircleInfoboxContent, histogramConnected, histogramDisconnected);
    peerCircleInfoboxContent.addChild(
        "span",
        new String[] {ATTR_STYLE, ATTR_CLASS},
        new String[] {generatePeerCircleStyleString(myLocation, true, 1.0), "me"},
        "x");
    //
    int histogramDiv = combinedHistogramDivisor(histogramConnected, histogramDisconnected);
    double histogramPercent;
    for (int i = 0; i < HISTOGRAM_LENGTH; i++) {
      addHistogramLegendCell(
          peerHistogramLegendTableRow, fix1p1.format(((double) i) / HISTOGRAM_LENGTH), false);
      HTMLNode peerHistogramGraphCell = createHistogramGraphCell(peerHistogramGraphTableRow);
      histogramPercent = ((double) histogramConnected[i]) / histogramDiv;
      addHistogramBar(peerHistogramGraphCell, HISTOGRAM_CONNECTED_CLASS, histogramPercent);
      histogramPercent = ((double) histogramDisconnected[i]) / histogramDiv;
      addHistogramBar(peerHistogramGraphCell, HISTOGRAM_DISCONNECTED, histogramPercent);
    }
  }

  private String generatePeerCircleStyleString(
      double peerLocation, boolean offsetMe, double strength) {
    peerLocation *= Math.PI * 2;
    //
    int offset;
    if (offsetMe) {
      // Make our own peer stand out from the crowd better so we can see it easier
      offset = -10;
    } else {
      offset = (int) (PEER_CIRCLE_INNER_RADIUS * (1.0 - strength));
    }
    double x =
        PEER_CIRCLE_ADDITIONAL_FREE_SPACE
            + PEER_CIRCLE_RADIUS
            + Math.sin(peerLocation) * (PEER_CIRCLE_RADIUS - offset);
    double y =
        PEER_CIRCLE_RADIUS
            - Math.cos(peerLocation)
                * (PEER_CIRCLE_RADIUS
                    - offset); // no PEER_CIRCLE_ADDITIONAL_FREE_SPACE for y-disposition
    //
    return POSITION_TOP + fix3p1US.format(y) + PX_LEFT + fix3p1US.format(x) + "px";
  }

  /**
   * Returns the mount point under which this toadlet is served to HTTP clients. The value is used
   * by the hosting framework when routing incoming requests and when generating links within other
   * administrative pages that reference the statistics view. The path is static and does not vary
   * with configuration or localization.
   *
   * @return immutable URL path segment {@code "/stats/"} that identifies the statistics toadlet.
   */
  @Override
  public String path() {
    return "/stats/";
  }
}

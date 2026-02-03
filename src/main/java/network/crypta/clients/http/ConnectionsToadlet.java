package network.crypta.clients.http;

import static java.util.concurrent.TimeUnit.HOURS;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.StringTokenizer;
import network.crypta.client.FetchException;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.fcp.AddPeer;
import network.crypta.clients.http.complexhtmlnodes.PeerTrustInputForAddPeerBoxNode;
import network.crypta.clients.http.complexhtmlnodes.PeerVisibilityInputForAddPeerBoxNode;
import network.crypta.clients.http.geoip.IPConverter;
import network.crypta.clients.http.geoip.IPConverter.Country;
import network.crypta.config.ConfigException;
import network.crypta.io.comm.PeerParseException;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.io.xfer.PacketThrottle;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.DarknetPeerNode.FRIEND_TRUST;
import network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY;
import network.crypta.node.FSParseException;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.NodeFile;
import network.crypta.node.NodeStats;
import network.crypta.node.PeerManager;
import network.crypta.node.PeerNode;
import network.crypta.node.PeerNodeLoadTracker.IncomingLoadSummaryStats;
import network.crypta.node.PeerNodeStatus;
import network.crypta.node.PeerStatusCounts;
import network.crypta.node.Version;
import network.crypta.support.Fields;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.SizeUtil;
import network.crypta.support.TimeUtil;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.io.FileUtil;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base HTTP toadlet used by both darknet and opennet connection pages.
 *
 * <p>This class renders peer connection state, accepts noderef submissions, and provides helpers
 * for subclasses that tailor per-network presentation. It centralizes sorting, pagination,
 * validation, and noderef ingestion so downstream pages can focus on the specifics of each
 * topology. Instances are long-lived and reused across requests; state comes from the injected
 * {@link Node} and {@link NodeClientCore} rather than per-request mutability.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Rendering peer summaries, trust/visibility columns, and message-type breakdowns.
 *   <li>Parsing noderefs from form uploads, pasted text, or URLs, then delegating to {@link Node}
 *       for peer creation.
 *   <li>Handling redirects and guidance when no peers exist or when access checks fail.
 * </ul>
 *
 * <p>Thread-safety: instances rely on externally synchronized {@link Node}/{@link PeerManager}
 * methods. The toadlet itself holds no mutable request-scoped state except transient flags on the
 * stack, so it can service concurrent requests when the surrounding HTTP server invokes it in
 * parallel. Subclasses should preserve this behavior when adding fields or caching.
 */
public abstract class ConnectionsToadlet extends Toadlet {
  private static final Logger LOG = LoggerFactory.getLogger(ConnectionsToadlet.class);
  private static final String ATTR_CLASS = "class";
  private static final String ELEMENT_TABLE = "table";
  private static final String INFOBOX_CLASS = "infobox";
  private static final String INFOBOX_NORMAL_CLASS = "infobox infobox-normal";
  private static final String INFOBOX_HEADER_CLASS = "infobox-header";
  private static final String INFOBOX_CONTENT_CLASS = "infobox-content";
  private static final String DISPLAY_MESSAGE_TYPES = "displaymessagetypes.html";
  private static final String DARKNET_CONNECTIONS = "darknet_connections";
  private static final String ATTR_TITLE = "title";
  private static final String ATTR_STYLE = "style";
  private static final String HELP_STYLE = "border-bottom: 1px dotted; cursor: help;";
  private static final String ELEMENT_INPUT = "input";
  private static final String TRUST = "trust";
  private static final String COUNT = "count";
  private static final String REF_FILE = "reffile";
  private static final String PEER_PRIVATE_NOTE = "peerPrivateNote";
  private static final String REPORT_OF_NODE_ADDITION = "reportOfNodeAddition";
  private static final String PEER_IDLE_CLASS = "peer-idle";

  /**
   * Comparator that orders {@link PeerNodeStatus} instances for table rendering.
   *
   * <p>Sorting honors a user-selected column when present and otherwise falls back to status code
   * and peer hash for deterministic ordering. The {@code reversed} flag inverts the final result so
   * callers can reuse one comparator for ascending and descending views without allocating extra
   * helpers.
   */
  protected class ComparatorByStatus implements Comparator<PeerNodeStatus> {
    /** Column key requested by the client, may be {@code null} for default ordering. */
    protected final String sortBy;

    /** Whether the comparator should invert its result for the descending presentation. */
    protected final boolean reversed;

    /**
     * Creates a comparator configured for a column and direction.
     *
     * @param sortBy column key requested by the HTTP client; may be {@code null} to use defaults.
     * @param reversed whether the ordering should be inverted for descending presentation.
     */
    ComparatorByStatus(String sortBy, boolean reversed) {
      this.sortBy = sortBy;
      this.reversed = reversed;
    }

    /**
     * Orders two peer rows using configured sort behavior.
     *
     * @param firstNode the first peer candidate; never mutated by this comparator.
     * @param secondNode the second peer candidate; never mutated by this comparator.
     * @return negative when the first precedes the second, positive when after, or zero when ties.
     */
    @Override
    public int compare(PeerNodeStatus firstNode, PeerNodeStatus secondNode) {
      isReversed = reversed;
      int result = compareWithSort(firstNode, secondNode);
      if (result == 0) {
        result = compareByStatus(firstNode, secondNode);
      }
      return reversed ? -Integer.signum(result) : Integer.signum(result);
    }

    private int compareByStatus(PeerNodeStatus firstNode, PeerNodeStatus secondNode) {
      int statusDifference =
          Integer.compare(firstNode.getStatusValue(), secondNode.getStatusValue());
      if (statusDifference != 0) {
        return statusDifference;
      }
      return lastResortCompare(firstNode, secondNode);
    }

    private int compareWithSort(PeerNodeStatus firstNode, PeerNodeStatus secondNode) {
      if (sortBy == null) {
        return 0;
      }
      return customCompare(firstNode, secondNode);
    }

    // xor: check why we do not just return the result of (long1-long2)
    // j16sdiz: (Long.MAX_VALUE - (-1)) would overflow and become negative
    private int compareLongs(long long1, long long2) {
      int diff = Long.compare(long1, long2);
      if (diff == 0) return 0;
      else return (diff > 0 ? 1 : -1);
    }

    private int compareInts(int int1, int int2) {
      int diff = Integer.compare(int1, int2);
      if (diff == 0) return 0;
      else return (diff > 0 ? 1 : -1);
    }

    /**
     * Applies column-specific ordering chosen by the requester.
     *
     * <p>Each branch matches a sortable column and compares the corresponding values using
     * type-appropriate ordering. When the column key is unrecognised the method returns {@code 0}
     * so callers can rely on default or tie-breaker ordering.
     *
     * @param firstNode first peer candidate considered in the comparison.
     * @param secondNode second peer candidate considered in the comparison.
     * @return a negative number when the first node should precede the second, positive when it
     *     should follow, or zero when the column is not supported.
     */
    protected int customCompare(PeerNodeStatus firstNode, PeerNodeStatus secondNode) {
      return switch (sortBy) {
        case "address" ->
            firstNode.getPeerAddress().compareToIgnoreCase(secondNode.getPeerAddress());
        case "location" -> compareLocations(firstNode, secondNode);
        case "version" ->
            Version.compareBuildNumbers(
                Version.parseNodeNameFromVersionStr(firstNode.getVersion()),
                Version.parseBuildNumberFromVersionStr(firstNode.getVersion(), -1),
                Version.parseNodeNameFromVersionStr(secondNode.getVersion()),
                Version.parseBuildNumberFromVersionStr(secondNode.getVersion(), -1));
        case "backoffRT" ->
            Double.compare(
                firstNode.getBackedOffPercent(true), secondNode.getBackedOffPercent(true));
        case "backoffBulk" ->
            Double.compare(
                firstNode.getBackedOffPercent(false), secondNode.getBackedOffPercent(false));
        case "overload_p" -> Double.compare(firstNode.getPReject(), secondNode.getPReject());
        case "idle" ->
            compareLongs(
                firstNode.getTimeLastConnectionCompleted(),
                secondNode.getTimeLastConnectionCompleted());
        case "time_routable" ->
            Double.compare(
                firstNode.getPercentTimeRoutableConnection(),
                secondNode.getPercentTimeRoutableConnection());
        case "total_traffic" -> {
          long total1 = firstNode.getTotalInputBytes() + firstNode.getTotalOutputBytes();
          long total2 = secondNode.getTotalInputBytes() + secondNode.getTotalOutputBytes();
          yield compareLongs(total1, total2);
        }
        case "total_traffic_since_startup" -> {
          long total1 =
              firstNode.getTotalInputSinceStartup() + firstNode.getTotalOutputSinceStartup();
          long total2 =
              secondNode.getTotalInputSinceStartup() + secondNode.getTotalOutputSinceStartup();
          yield compareLongs(total1, total2);
        }
        case "selection_percentage" ->
            Double.compare(firstNode.getSelectionRate(), secondNode.getSelectionRate());
        case "time_delta" -> compareLongs(firstNode.getClockDelta(), secondNode.getClockDelta());
        case "uptime" ->
            compareInts(
                firstNode.getReportedUptimePercentage(), secondNode.getReportedUptimePercentage());
        default -> 0;
      };
    }

    private int compareLocations(PeerNodeStatus firstNode, PeerNodeStatus secondNode) {
      double diff =
          firstNode.getLocation()
              - secondNode
                  .getLocation(); // Can occasionally be the same, and we must have a consistent
      // sort order
      if (Double.MIN_VALUE * 2 > Math.abs(diff)) return 0;
      return diff > 0 ? 1 : -1;
    }

    /**
     * Provides deterministic ordering after higher-priority comparisons tie.
     *
     * <p>This implementation compares the peer locations to ensure stable presentation across
     * renders. Subclasses can override by altering location calculation in {@link PeerNodeStatus}.
     *
     * @param firstNode first peer candidate to order.
     * @param secondNode second peer candidate to order.
     * @return negative when the first node is earlier, positive when later, zero when equal.
     */
    protected int lastResortCompare(PeerNodeStatus firstNode, PeerNodeStatus secondNode) {
      return compareLocations(firstNode, secondNode);
    }
  }

  /** Reference to the running node that backs all connection states and operations. */
  protected final Node node;

  /** Core services used for filesystem paths, configuration, and network integration. */
  protected final NodeClientCore core;

  /** Node statistics helper used to populate dashboard sections. */
  protected final NodeStats stats;

  /** Peer manager providing live peer state and addition helpers. */
  protected final PeerManager peers;

  /** Tracks whether the user requested the current comparator reversed flag. */
  protected boolean isReversed = false;

  /** Whether trivial FOAF connections should be displayed alongside non-trivial groups. */
  protected boolean showTrivialFoafConnections = false;

  /**
   * Outcomes returned when attempting to add a peer from a supplied noderef.
   *
   * <p>Values map directly to user-visible result codes in the add-peer report table. They
   * distinguish validation failures, parsing errors, identity clashes, and success.
   */
  public enum PeerAdditionReturnCodes {
    /** Peer was added successfully without warnings. */
    OK,
    /** Noderef contained malformed encoding or incorrect end marker. */
    WRONG_ENCODING,
    /** Parsing of the noderef failed before verification could run. */
    CANT_PARSE,
    /** Unexpected internal problem occurred during peer creation. */
    INTERNAL_ERROR,
    /** Noderef signature could not be validated against provided keys. */
    INVALID_SIGNATURE,
    /** Submitted noderef belongs to this node; self-adding is blocked. */
    TRY_TO_ADD_SELF,
    /** Peer already exists in the local peer set. */
    ALREADY_IN_REFERENCE
  }

  /**
   * Creates a toadlet bound to shared node infrastructure used by connection pages.
   *
   * @param n live {@link Node} supplying peer state and creation helpers; must not be {@code null}.
   * @param core {@link NodeClientCore} providing filesystem access and runtime paths used for
   *     noderef files.
   * @param client high-level client used to retrieve noderefs via Freenet or HTTP when users submit
   *     URLs instead of pasted references.
   */
  protected ConnectionsToadlet(Node n, NodeClientCore core, HighLevelSimpleClient client) {
    super(client);
    this.node = n;
    this.core = core;
    this.stats = n.network().stats();
    this.peers = n.network().peers();
    refLink = HTMLNode.link(path() + "myref.fref").setReadOnly();
    reftextLink = HTMLNode.link(path() + "myref.txt").setReadOnly();
  }

  abstract SimpleColumn[] endColumnHeaders(boolean advancedModeEnabled);

  abstract static class SimpleColumn {
    protected abstract void drawColumn(HTMLNode peerRow, PeerNodeStatus peerNodeStatus);

    public abstract String getSortString();

    public abstract String getTitleKey();

    public abstract String getExplanationKey();
  }

  /**
   * Renders the connections page and optional message-type breakdowns.
   *
   * <p>The handler validates access, resolves download endpoints for the current node reference,
   * builds sorted peer tables, and writes the resulting HTML response. When no peers exist, it
   * still renders guidance and, depending on mode, may redirect to friend-adding flows. Download
   * requests for {@code myref.fref} or {@code myref.txt} are served directly with appropriate
   * headers.
   *
   * @param uri request target URI, used to detect message-type view and download paths.
   * @param request HTTP request wrapper supplying parameters such as {@code sortBy} and {@code
   *     reversed}.
   * @param ctx toadlet context providing authorization checks and HTML generation utilities.
   * @throws ToadletContextClosedException when the client connection is already closed while
   *     writing output.
   * @throws IOException when generating the page or serving downloads fails due to I/O errors.
   * @throws RedirectException when control flow chooses to redirect instead of rendering.
   */
  @Override
  public void handleMethodGET(URI uri, final HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    if (!ctx.checkFullAccess(this)) return;

    String path = uri.getPath();
    if (serveReferenceDownload(path, ctx)) {
      return;
    }

    DecimalFormat percentageFormat = new DecimalFormat("##0.0%");
    boolean drawMessageTypes = path.endsWith(DISPLAY_MESSAGE_TYPES);

    PeerNodeStatus[] peerNodeStatuses = getPeerNodeStatuses(!drawMessageTypes);
    Arrays.sort(
        peerNodeStatuses,
        comparator(request.getParam("sortBy", null), request.isParameterSet("reversed")));

    PeerStatusCounts counts = computePeerStatusCounts(peerNodeStatuses);
    String titleCountString = buildTitleCountString(counts);

    PageNode page = ctx.getPageMaker().getPageNode(getPageTitle(titleCountString), ctx);
    boolean advancedMode = ctx.isAdvancedModeEnabled();
    HTMLNode contentNode = page.getContentNode();
    long now = System.currentTimeMillis();

    if (ctx.isAllowedFullAccess()) {
      contentNode.addChild(ctx.getAlertManager().createSummary());
    }

    RenderMode renderMode = new RenderMode(advancedMode, drawMessageTypes);
    RenderTiming renderTiming = new RenderTiming(now, percentageFormat);
    RenderContext renderContext =
        new RenderContext(
            new RenderPageContext(ctx, path, contentNode),
            new RenderPeerSnapshot(peerNodeStatuses, counts),
            renderMode,
            renderTiming);
    renderContent(renderContext);

    if (peerNodeStatuses.length == 0) {
      handleMissingPeers();
    }

    if (shouldDrawNoderefBox(advancedMode)) {
      drawAddPeerBox(contentNode, ctx);
      drawNoderefBox(contentNode, getNoderef());
    }

    this.writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private boolean serveReferenceDownload(String path, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (path.endsWith("myref.fref")) {
      SimpleFieldSet fs = getNoderef();
      String noderefString = fs.toOrderedStringWithBase64();
      MultiValueTable<String, String> extraHeaders =
          MultiValueTable.from("Content-Disposition", "attachment; filename=myref.fref");
      writeReply(
          ctx,
          ReplyHeaders.of(200, "OK", "application/x-freenet-reference", extraHeaders),
          noderefString);
      return true;
    }

    if (path.endsWith("myref.txt")) {
      SimpleFieldSet fs = getNoderef();
      String noderefString = fs.toOrderedStringWithBase64();
      writeTextReply(ctx, 200, "OK", noderefString);
      return true;
    }
    return false;
  }

  private PeerStatusCounts computePeerStatusCounts(PeerNodeStatus[] peerNodeStatuses) {
    int connected =
        PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_CONNECTED);
    int routingBackedOff =
        PeerNodeStatus.getPeerStatusCount(
            peerNodeStatuses, PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF);
    int tooNew =
        PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_TOO_NEW);
    int tooOld =
        PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_TOO_OLD);
    int disconnected =
        PeerNodeStatus.getPeerStatusCount(
            peerNodeStatuses, PeerManager.PEER_NODE_STATUS_DISCONNECTED);
    int neverConnected =
        PeerNodeStatus.getPeerStatusCount(
            peerNodeStatuses, PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED);
    int disabled =
        PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_DISABLED);
    int bursting =
        PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_BURSTING);
    int listening =
        PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_LISTENING);
    int listenOnly =
        PeerNodeStatus.getPeerStatusCount(
            peerNodeStatuses, PeerManager.PEER_NODE_STATUS_LISTEN_ONLY);
    int routingDisabled =
        PeerNodeStatus.getPeerStatusCount(
            peerNodeStatuses, PeerManager.PEER_NODE_STATUS_ROUTING_DISABLED);
    int clockProblem =
        PeerNodeStatus.getPeerStatusCount(
            peerNodeStatuses, PeerManager.PEER_NODE_STATUS_CLOCK_PROBLEM);
    int connError =
        PeerNodeStatus.getPeerStatusCount(
            peerNodeStatuses, PeerManager.PEER_NODE_STATUS_CONN_ERROR);
    int disconnecting =
        PeerNodeStatus.getPeerStatusCount(
            peerNodeStatuses, PeerManager.PEER_NODE_STATUS_DISCONNECTING);
    int noLoadStats =
        PeerNodeStatus.getPeerStatusCount(
            peerNodeStatuses, PeerManager.PEER_NODE_STATUS_NO_LOAD_STATS);

    return new PeerStatusCounts(
        connected,
        routingBackedOff,
        tooNew,
        tooOld,
        disconnected,
        neverConnected,
        disabled,
        bursting,
        listening,
        listenOnly,
        0,
        0,
        routingDisabled,
        clockProblem,
        connError,
        disconnecting,
        noLoadStats);
  }

  private String buildTitleCountString(PeerStatusCounts counts) {
    if (!node.isAdvancedModeEnabled()) {
      int numberOfSimpleConnected = counts.connected() + counts.routingBackedOff();
      int numberOfNotConnected = counts.notConnected();
      return (numberOfNotConnected + numberOfSimpleConnected) > 0
          ? String.valueOf(numberOfSimpleConnected)
          : "";
    }

    return "("
        + counts.connected()
        + '/'
        + counts.routingBackedOff()
        + '/'
        + counts.tooNew()
        + '/'
        + counts.tooOld()
        + '/'
        + counts.noLoadStats()
        + '/'
        + counts.routingDisabled()
        + '/'
        + counts.notConnected()
        + ')';
  }

  private void renderContent(RenderContext renderContext) {
    if (renderContext.advancedMode()) {
      addOverviewSection(
          renderContext.contentNode(),
          renderContext.percentageFormat(),
          renderContext.now(),
          renderContext.counts());
    }

    addPeerTableSection(renderContext);

    if (renderContext.advancedMode()) {
      addFoafTable(renderContext.contentNode(), renderContext.peerNodeStatuses());
    }
  }

  private void addOverviewSection(
      HTMLNode contentNode, DecimalFormat percentageFormat, long now, PeerStatusCounts counts) {
    long nodeUptimeSeconds = SECONDS.convert(now - node.getStartupTime(), MILLISECONDS);
    int bwlimitDelayTime = (int) stats.getBwlimitDelayTime();
    int nodeAveragePingTime = (int) stats.getNodeAveragePingTime();
    int networkSizeEstimateSession = stats.getDarknetSizeEstimate(-1);
    int networkSizeEstimateRecent = 0;
    if (nodeUptimeSeconds > HOURS.toSeconds(48)) {
      networkSizeEstimateRecent = stats.getDarknetSizeEstimate(now - HOURS.toMillis(48));
    }
    DecimalFormat routingFormat = new DecimalFormat("0.0000");
    double routingMissDistanceLocal = stats.routingMissDistanceLocal.currentValue();
    double routingMissDistanceRemote = stats.routingMissDistanceRemote.currentValue();
    double routingMissDistanceOverall = stats.routingMissDistanceOverall.currentValue();
    double routingMissDistanceBulk = stats.routingMissDistanceBulk.currentValue();
    double routingMissDistanceRT = stats.routingMissDistanceRT.currentValue();
    double backedOffPercent = stats.backedOffPercent.currentValue();
    String nodeUptimeString = TimeUtil.formatTime(MILLISECONDS.convert(nodeUptimeSeconds, SECONDS));

    HTMLNode overviewTable = contentNode.addChild(ELEMENT_TABLE, ATTR_CLASS, "column");
    HTMLNode overviewTableRow = overviewTable.addChild("tr");
    HTMLNode nextTableCell = overviewTableRow.addChild("td", ATTR_CLASS, "first");

    HTMLNode overviewInfobox = nextTableCell.addChild("div", ATTR_CLASS, INFOBOX_CLASS);
    overviewInfobox.addChild("div", ATTR_CLASS, INFOBOX_HEADER_CLASS, "Node status overview");
    HTMLNode overviewInfoboxContent =
        overviewInfobox.addChild("div", ATTR_CLASS, INFOBOX_CONTENT_CLASS);
    HTMLNode overviewList = overviewInfoboxContent.addChild("ul");
    overviewList.addChild("li", "bwlimitDelayTime:\u00a0" + bwlimitDelayTime + "ms");
    overviewList.addChild("li", "nodeAveragePingTime:\u00a0" + nodeAveragePingTime + "ms");
    overviewList.addChild(
        "li", "darknetSizeEstimateSession:\u00a0" + networkSizeEstimateSession + "\u00a0nodes");
    if (nodeUptimeSeconds > HOURS.toSeconds(48)) {
      overviewList.addChild(
          "li", "darknetSizeEstimateRecent:\u00a0" + networkSizeEstimateRecent + "\u00a0nodes");
    }
    overviewList.addChild("li", "nodeUptime:\u00a0" + nodeUptimeString);
    overviewList.addChild(
        "li", "routingMissDistanceLocal:\u00a0" + routingFormat.format(routingMissDistanceLocal));
    overviewList.addChild(
        "li", "routingMissDistanceRemote:\u00a0" + routingFormat.format(routingMissDistanceRemote));
    overviewList.addChild(
        "li",
        "routingMissDistanceOverall:\u00a0" + routingFormat.format(routingMissDistanceOverall));
    overviewList.addChild(
        "li", "routingMissDistanceBulk:\u00a0" + routingFormat.format(routingMissDistanceBulk));
    overviewList.addChild(
        "li", "routingMissDistanceRT:\u00a0" + routingFormat.format(routingMissDistanceRT));
    overviewList.addChild(
        "li", "backedOffPercent:\u00a0" + percentageFormat.format(backedOffPercent));
    overviewList.addChild(
        "li", "pInstantReject:\u00a0" + percentageFormat.format(stats.pRejectIncomingInstantly()));
    nextTableCell = overviewTableRow.addChild("td");

    addActivitySection(nextTableCell, nodeUptimeSeconds);
    addPeerStatsSection(nextTableCell, counts);
  }

  private void addActivitySection(HTMLNode tableCell, long nodeUptimeSeconds) {
    int numARKFetchers = node.network().numArkFetchers();

    HTMLNode activityInfobox = tableCell.addChild("div", ATTR_CLASS, INFOBOX_CLASS);
    activityInfobox.addChild("div", ATTR_CLASS, INFOBOX_HEADER_CLASS, l10n("activityTitle"));
    HTMLNode activityInfoboxContent =
        activityInfobox.addChild("div", ATTR_CLASS, INFOBOX_CONTENT_CLASS);
    HTMLNode activityList = StatisticsToadlet.drawActivity(activityInfoboxContent, node);
    if (activityList != null) {
      if (numARKFetchers > 0) {
        activityList.addChild("li", "ARK\u00a0Fetch\u00a0Requests:\u00a0" + numARKFetchers);
      }
      StatisticsToadlet.drawBandwidth(activityList, node, nodeUptimeSeconds, true);
    }
  }

  private void addPeerStatsSection(HTMLNode tableCell, PeerStatusCounts counts) {
    HTMLNode peerStatsInfobox = tableCell.addChild("div", ATTR_CLASS, INFOBOX_CLASS);
    StatisticsToadlet.drawPeerStatsBox(peerStatsInfobox, true, counts, node);

    addBackoffReasonBoxes(tableCell);
  }

  private void addBackoffReasonBoxes(HTMLNode tableCell) {
    addBackoffReasonBox(tableCell, true, "Peer backoff reasons (realtime)");
    addBackoffReasonBox(tableCell, false, "Peer backoff reasons (bulk)");
  }

  private void addBackoffReasonBox(HTMLNode tableCell, boolean realtime, String headerText) {
    HTMLNode backoffReasonInfobox = tableCell.addChild("div", ATTR_CLASS, INFOBOX_CLASS);
    HTMLNode title =
        backoffReasonInfobox.addChild("div", ATTR_CLASS, INFOBOX_HEADER_CLASS, headerText);
    HTMLNode backoffReasonContent =
        backoffReasonInfobox.addChild("div", ATTR_CLASS, INFOBOX_CONTENT_CLASS);
    String[] routingBackoffReasons = peers.getPeerNodeRoutingBackoffReasons(realtime);
    int total = 0;
    if (routingBackoffReasons.length == 0) {
      backoffReasonContent.addChild(
          "#", NodeL10n.getBase().getString("StatisticsToadlet.notBackedOff"));
    } else {
      HTMLNode reasonList = backoffReasonContent.addChild("ul");
      for (String routingBackoffReason : routingBackoffReasons) {
        int reasonCount = peers.getPeerNodeRoutingBackoffReasonSize(routingBackoffReason, realtime);
        if (reasonCount > 0) {
          total += reasonCount;
          reasonList.addChild("li", routingBackoffReason + '\u00a0' + reasonCount);
        }
      }
    }
    if (total > 0) {
      title.addChild("#", ": " + total);
    }
  }

  private void addPeerTableSection(RenderContext renderContext) {
    boolean enablePeerActions = showPeerActionsBox();
    boolean fProxyJavascriptEnabled = node.isFProxyJavascriptEnabled();

    if (fProxyJavascriptEnabled) {
      injectJavascript(renderContext.contentNode());
    }

    HTMLNode peerTableInfobox =
        renderContext.contentNode().addChild("div", ATTR_CLASS, INFOBOX_NORMAL_CLASS);
    HTMLNode peerTableInfoboxHeader =
        peerTableInfobox.addChild("div", ATTR_CLASS, INFOBOX_HEADER_CLASS);
    peerTableInfoboxHeader.addChild("#", getPeerListTitle());
    if (renderContext.advancedMode() && !renderContext.path().endsWith(DISPLAY_MESSAGE_TYPES)) {
      peerTableInfoboxHeader.addChild("#", " ");
      peerTableInfoboxHeader.addChild(
          "a", "href", DISPLAY_MESSAGE_TYPES, l10n("bracketedMoreDetailed"));
    }
    HTMLNode peerTableInfoboxContent =
        peerTableInfobox.addChild("div", ATTR_CLASS, INFOBOX_CONTENT_CLASS);

    if (!isOpennet()) {
      addNameSection(peerTableInfoboxContent);
    }

    if (renderContext.peerNodeStatuses().length == 0) {
      addNoPeersMessage(peerTableInfoboxContent);
      return;
    }

    PeerTableContext peerTableContext =
        buildPeerTable(
            renderContext.ctx(),
            peerTableInfoboxContent,
            enablePeerActions,
            fProxyJavascriptEnabled,
            renderContext.advancedMode());

    fillPeerTable(
        peerTableContext,
        renderContext.peerNodeStatuses(),
        renderContext.drawMessageTypes(),
        renderContext.percentageFormat(),
        renderContext.advancedMode(),
        renderContext.now());
  }

  private void injectJavascript(HTMLNode contentNode) {
    String js =
        """
          function peerNoteChange() {
            document.getElementById("action").value = "update_notes";            document.getElementById("peersForm").doAction.click();
          }
        """;
    contentNode.addChild("script", "type", "text/javascript").addChild("%", js);
    contentNode.addChild(
        "script",
        new String[] {"type", "src"},
        new String[] {"text/javascript", "/static/js/checkall.js"});
  }

  private void addNameSection(HTMLNode peerTableInfoboxContent) {
    HTMLNode myName = peerTableInfoboxContent.addChild("p");
    myName.addChild(
        "span",
        NodeL10n.getBase().getString("DarknetConnectionsToadlet.myName", "name", node.getMyName()));
    myName.addChild("span", " [");
    myName
        .addChild("span")
        .addChild(
            "a",
            "href",
            "/config/node#name",
            NodeL10n.getBase().getString("DarknetConnectionsToadlet.changeMyName"));
    myName.addChild("span", "]");
  }

  private void addNoPeersMessage(HTMLNode peerTableInfoboxContent) {
    NodeL10n.getBase()
        .addL10nSubstitution(
            peerTableInfoboxContent,
            "DarknetConnectionsToadlet.noPeersWithHomepageLink",
            new String[] {"link"},
            new HTMLNode[] {HTMLNode.link("/")});
  }

  private PeerTableContext buildPeerTable(
      ToadletContext ctx,
      HTMLNode peerTableInfoboxContent,
      boolean enablePeerActions,
      boolean fProxyJavascriptEnabled,
      boolean advancedMode) {
    HTMLNode peerForm = null;
    HTMLNode peerTable;
    if (enablePeerActions) {
      peerForm = ctx.addFormChild(peerTableInfoboxContent, ".", "peersForm");
      peerTable = peerForm.addChild(ELEMENT_TABLE, ATTR_CLASS, DARKNET_CONNECTIONS);
    } else {
      peerTable = peerTableInfoboxContent.addChild(ELEMENT_TABLE, ATTR_CLASS, DARKNET_CONNECTIONS);
    }
    HTMLNode peerTableHeaderRow = peerTable.addChild("tr");
    addPeerTableHeader(
        enablePeerActions, fProxyJavascriptEnabled, peerTableHeaderRow, advancedMode);

    SimpleColumn[] endCols = endColumnHeaders(advancedMode);
    if (endCols != null) {
      for (SimpleColumn col : endCols) {
        HTMLNode header = peerTableHeaderRow.addChild("th");
        String sortString = col.getSortString();
        if (sortString != null) {
          header = header.addChild("a", "href", sortString(isReversed, sortString));
        }
        header.addChild(
            "span",
            new String[] {ATTR_TITLE, ATTR_STYLE},
            new String[] {NodeL10n.getBase().getString(col.getExplanationKey()), HELP_STYLE},
            NodeL10n.getBase().getString(col.getTitleKey()));
      }
    }

    List<SimpleColumn> endColsList = endCols == null ? List.of() : List.of(endCols);
    return new PeerTableContext(peerForm, peerTable, endColsList);
  }

  private void addPeerTableHeader(
      boolean enablePeerActions,
      boolean fProxyJavascriptEnabled,
      HTMLNode peerTableHeaderRow,
      boolean advancedMode) {
    if (enablePeerActions) {
      if (fProxyJavascriptEnabled) {
        peerTableHeaderRow
            .addChild("th")
            .addChild(
                ELEMENT_INPUT,
                new String[] {"type", "onclick"},
                new String[] {"checkbox", "checkAll(this, 'darknet_connections')"});
      } else {
        peerTableHeaderRow.addChild("th");
      }
    }
    peerTableHeaderRow
        .addChild("th")
        .addChild("a", "href", sortString(isReversed, "status"))
        .addChild("#", l10n("statusTitle"));
    if (hasNameColumn()) {
      peerTableHeaderRow
          .addChild("th")
          .addChild("a", "href", sortString(isReversed, "name"))
          .addChild(
              "span",
              new String[] {ATTR_TITLE, ATTR_STYLE},
              new String[] {l10n("nameClickToMessage"), HELP_STYLE},
              l10n("nameTitle"));
    }
    if (hasTrustColumn()) {
      peerTableHeaderRow
          .addChild("th")
          .addChild("a", "href", sortString(isReversed, TRUST))
          .addChild(
              "span",
              new String[] {ATTR_TITLE, ATTR_STYLE},
              new String[] {l10n("trustMessage"), HELP_STYLE},
              l10n("trustTitle"));
    }
    if (hasVisibilityColumn()) {
      peerTableHeaderRow
          .addChild("th")
          .addChild("a", "href", sortString(isReversed, TRUST))
          .addChild(
              "span",
              new String[] {ATTR_TITLE, ATTR_STYLE},
              new String[] {
                l10n("visibilityMessage" + (advancedMode ? "Advanced" : "Simple")), HELP_STYLE
              },
              l10n("visibilityTitle"));
    }
    peerTableHeaderRow
        .addChild("th")
        .addChild("a", "href", sortString(isReversed, "address"))
        .addChild(
            "span",
            new String[] {ATTR_TITLE, ATTR_STYLE},
            new String[] {l10n("ipAddress"), HELP_STYLE},
            l10n("ipAddressTitle"));
    peerTableHeaderRow
        .addChild("th")
        .addChild("a", "href", sortString(isReversed, "version"))
        .addChild("#", l10n("versionTitle"));
    if (advancedMode) {
      addAdvancedPeerTableHeaders(peerTableHeaderRow);
    }
    peerTableHeaderRow
        .addChild("th")
        .addChild("a", "href", sortString(isReversed, "idle"))
        .addChild(
            "span",
            new String[] {ATTR_TITLE, ATTR_STYLE},
            new String[] {l10n("idleTime"), HELP_STYLE},
            l10n("idleTimeTitle"));
    if (hasPrivateNoteColumn()) {
      peerTableHeaderRow
          .addChild("th")
          .addChild("a", "href", sortString(isReversed, "privnote"))
          .addChild(
              "span",
              new String[] {ATTR_TITLE, ATTR_STYLE},
              new String[] {l10n("privateNote"), HELP_STYLE},
              l10n("privateNoteTitle"));
    }

    if (advancedMode) {
      peerTableHeaderRow
          .addChild("th")
          .addChild("a", "href", sortString(isReversed, "time_routable"))
          .addChild("#", "%\u00a0Time Routable");
      peerTableHeaderRow
          .addChild("th")
          .addChild("a", "href", sortString(isReversed, "selection_percentage"))
          .addChild("#", "%\u00a0Selection");
      peerTableHeaderRow
          .addChild("th")
          .addChild("a", "href", sortString(isReversed, "total_traffic"))
          .addChild("#", "Total\u00a0Traffic\u00a0(in/out/resent)");
      peerTableHeaderRow
          .addChild("th")
          .addChild("a", "href", sortString(isReversed, "total_traffic_since_startup"))
          .addChild("#", "Total\u00a0Traffic\u00a0(in/out) since startup");
      peerTableHeaderRow.addChild("th", "Congestion\u00a0Control");
      peerTableHeaderRow
          .addChild("th")
          .addChild("a", "href", sortString(isReversed, "time_delta"))
          .addChild("#", "Time\u00a0Delta");
      peerTableHeaderRow
          .addChild("th")
          .addChild("a", "href", sortString(isReversed, "uptime"))
          .addChild("#", "Reported\u00a0Uptime");
      peerTableHeaderRow.addChild("th", "Transmit\u00a0Queue");
      peerTableHeaderRow.addChild("th", "Peer\u00a0Capacity\u00a0Bulk");
      peerTableHeaderRow.addChild("th", "Peer\u00a0Capacity\u00a0Realtime");
    }
  }

  private void addAdvancedPeerTableHeaders(HTMLNode peerTableHeaderRow) {
    peerTableHeaderRow
        .addChild("th")
        .addChild("a", "href", sortString(isReversed, "location"))
        .addChild("#", l10n("locationTitle"));
    peerTableHeaderRow
        .addChild("th")
        .addChild("a", "href", sortString(isReversed, "backoffRT"))
        .addChild(
            "span",
            new String[] {ATTR_TITLE, ATTR_STYLE},
            new String[] {
              "Other node busy (realtime)? Display: Percentage of time the node is"
                  + " overloaded, Current wait time remaining (0=not overloaded)/total/last"
                  + " overload reason",
              HELP_STYLE
            },
            "Backoff (realtime)");
    peerTableHeaderRow
        .addChild("th")
        .addChild("a", "href", sortString(isReversed, "backoffBulk"))
        .addChild(
            "span",
            new String[] {ATTR_TITLE, ATTR_STYLE},
            new String[] {
              "Other node busy (bulk)? Display: Percentage of time the node is overloaded,"
                  + " Current wait time remaining (0=not overloaded)/total/last overload"
                  + " reason",
              HELP_STYLE
            },
            "Backoff (bulk)");

    peerTableHeaderRow
        .addChild("th")
        .addChild("a", "href", sortString(isReversed, "overload_p"))
        .addChild(
            "span",
            new String[] {ATTR_TITLE, ATTR_STYLE},
            new String[] {
              "Probability of the node rejecting a request due to overload or causing a timeout.",
              HELP_STYLE
            },
            "Overload Probability");
  }

  private void fillPeerTable(
      PeerTableContext peerTableContext,
      PeerNodeStatus[] peerNodeStatuses,
      boolean drawMessageTypes,
      DecimalFormat percentageFormat,
      boolean advancedMode,
      long now) {
    double totalSelectionRate = 0.0;
    RenderMode renderMode = new RenderMode(advancedMode, drawMessageTypes);
    RenderTiming renderTiming = new RenderTiming(now, percentageFormat);
    PeerNodeStatus[] allPeerNodeStatuses =
        node.network().peers().statusBook().getPeerNodeStatuses(true);
    for (PeerNodeStatus status : allPeerNodeStatuses) {
      totalSelectionRate += status.getSelectionRate();
    }
    for (PeerNodeStatus peerNodeStatus : peerNodeStatuses) {
      RowContext rowContext =
          new RowContext(
              new PeerRowContext(
                  peerTableContext.peerTable(), peerNodeStatus, peerTableContext.endCols()),
              renderMode,
              new PeerRowFlags(
                  node.isFProxyJavascriptEnabled(), peerTableContext.peerForm() != null),
              renderTiming,
              new PeerSelectionStats(totalSelectionRate));
      drawRow(rowContext);
    }

    if (peerTableContext.peerForm() != null) {
      drawPeerActionSelectBox(peerTableContext.peerForm(), advancedMode);
    }
  }

  private void addFoafTable(HTMLNode peerTableInfoboxContent, PeerNodeStatus[] peerNodeStatuses) {
    FoafGrouping grouping = buildFoafGrouping(peerNodeStatuses);
    addFoafSummary(peerTableInfoboxContent, grouping);
    addFoafRows(peerTableInfoboxContent, peerNodeStatuses, grouping);
  }

  private void addFoafSummary(HTMLNode peerTableInfoboxContent, FoafGrouping grouping) {
    peerTableInfoboxContent.addChild(
        "b",
        l10nCount(
            "secondDegreeConnectionsCountTitle", Integer.toString(grouping.locations().size())));
    peerTableInfoboxContent.addChild("br");
    if (!showTrivialFoafConnections) {
      peerTableInfoboxContent.addChild(
          "i",
          l10nCount("secondDegreeTrivialHiddenCount", Integer.toString(grouping.trivialCount())));
    } else {
      peerTableInfoboxContent.addChild(
          "i",
          l10nCount("secondDegreeNonTrivialCount", Integer.toString(grouping.nonTrivialCount())));
    }
  }

  private void addFoafRows(
      HTMLNode peerTableInfoboxContent, PeerNodeStatus[] peerNodeStatuses, FoafGrouping grouping) {
    HTMLNode foafTable =
        peerTableInfoboxContent.addChild(ELEMENT_TABLE, ATTR_CLASS, DARKNET_CONNECTIONS);
    HTMLNode foafRow = foafTable.addChild("tr");
    foafRow.addChild("th", l10n("locationTitle"));
    foafRow.addChild("th", l10n("countTitle"));
    foafRow.addChild("th", l10n("foafReachableThroughTitle"));
    int max = grouping.locations().size();
    int transitiveCount = 0;
    for (int i = 0; i < max; i++) {
      double location = grouping.locations().get(i);
      List<PeerNodeStatus> peersWithFriend = grouping.peerGroups().get(i);
      boolean isTransitivePeer = isTransitivePeer(peerNodeStatuses, location);
      if (peersWithFriend.size() == 1 && !showTrivialFoafConnections && !isTransitivePeer) {
        continue;
      }
      foafRow = foafTable.addChild("tr");
      if (isTransitivePeer) {
        foafRow.addChild("td").addChild("b", String.valueOf(location));
      } else {
        foafRow.addChild("td", String.valueOf(location));
      }
      foafRow.addChild("td", String.valueOf(peersWithFriend.size()));
      HTMLNode locationCell = foafRow.addChild("td", ATTR_CLASS, "peer-location");
      for (PeerNodeStatus peerNodeStatus : peersWithFriend) {
        String address =
            (peerNodeStatus.getPeerAddress() != null)
                ? peerNodeStatus.getPeerAddressAndPort()
                : l10n("unknownAddress");
        locationCell.addChild("i", address);
        locationCell.addChild("br");
      }
      if (isTransitivePeer) {
        transitiveCount++;
      }
    }
    if (transitiveCount > 0) {
      peerTableInfoboxContent.addChild(
          "i", l10nCount("secondDegreeAlsoOurs", Integer.toString(transitiveCount)));
    }
  }

  private FoafGrouping buildFoafGrouping(PeerNodeStatus[] peerNodeStatuses) {
    List<Double> locations = new ArrayList<>();
    List<List<PeerNodeStatus>> peerGroups = new ArrayList<>();
    for (PeerNodeStatus peerNodeStatus : peerNodeStatuses) {
      double[] peersLoc = peerNodeStatus.getPeersLocation();
      if (peersLoc == null) {
        continue;
      }
      for (double location : peersLoc) {
        int i = 0;
        int max = locations.size();
        while (i < max && locations.get(i) < location) {
          i++;
        }
        List<PeerNodeStatus> peerGroup;
        if (i < max && locations.get(i) == location) {
          peerGroup = peerGroups.get(i);
        } else {
          peerGroup = new ArrayList<>();
          locations.add(i, location);
          peerGroups.add(i, peerGroup);
        }
        peerGroup.add(peerNodeStatus);
      }
    }
    return new FoafGrouping(locations, peerGroups);
  }

  private boolean isTransitivePeer(PeerNodeStatus[] peerNodeStatuses, double location) {
    for (PeerNodeStatus peerNodeStatus : peerNodeStatuses) {
      if (location == peerNodeStatus.getLocation()) {
        return true;
      }
    }
    return false;
  }

  private void handleMissingPeers() throws RedirectException {
    if (isOpennet()) {
      return;
    }
    throw new RedirectException(URI.create("/addfriend/"));
  }

  private record PeerTableContext(
      HTMLNode peerForm, HTMLNode peerTable, List<SimpleColumn> endCols) {}

  private record FoafGrouping(List<Double> locations, List<List<PeerNodeStatus>> peerGroups) {
    int trivialCount() {
      return (int) peerGroups.stream().filter(list -> list.size() == 1).count();
    }

    int nonTrivialCount() {
      return (int) peerGroups.stream().filter(list -> list.size() > 1).count();
    }
  }

  private record AddPeerRequestData(
      String urltext,
      String reftext,
      String privateComment,
      FRIEND_TRUST trust,
      FRIEND_VISIBILITY visibility) {}

  private record RenderPageContext(ToadletContext ctx, String path, HTMLNode contentNode) {}

  @SuppressWarnings({"java:S6206", "ClassCanBeRecord"})
  private static final class RenderPeerSnapshot {
    private final PeerNodeStatus[] peerNodeStatuses;
    private final PeerStatusCounts counts;

    private RenderPeerSnapshot(PeerNodeStatus[] peerNodeStatuses, PeerStatusCounts counts) {
      this.peerNodeStatuses = peerNodeStatuses;
      this.counts = counts;
    }

    PeerNodeStatus[] peerNodeStatuses() {
      return peerNodeStatuses;
    }

    PeerStatusCounts counts() {
      return counts;
    }
  }

  private record RenderMode(boolean advancedModeEnabled, boolean drawMessageTypes) {}

  private record RenderTiming(long now, DecimalFormat percentageFormat) {}

  @SuppressWarnings({"java:S6206", "ClassCanBeRecord"})
  private static final class RenderContext {
    private final RenderPageContext pageContext;
    private final RenderPeerSnapshot peerSnapshot;
    private final RenderMode renderMode;
    private final RenderTiming renderTiming;

    private RenderContext(
        RenderPageContext pageContext,
        RenderPeerSnapshot peerSnapshot,
        RenderMode renderMode,
        RenderTiming renderTiming) {
      this.pageContext = pageContext;
      this.peerSnapshot = peerSnapshot;
      this.renderMode = renderMode;
      this.renderTiming = renderTiming;
    }

    ToadletContext ctx() {
      return pageContext.ctx();
    }

    String path() {
      return pageContext.path();
    }

    PeerNodeStatus[] peerNodeStatuses() {
      return peerSnapshot.peerNodeStatuses();
    }

    boolean drawMessageTypes() {
      return renderMode.drawMessageTypes();
    }

    DecimalFormat percentageFormat() {
      return renderTiming.percentageFormat();
    }

    boolean advancedMode() {
      return renderMode.advancedModeEnabled();
    }

    HTMLNode contentNode() {
      return pageContext.contentNode();
    }

    long now() {
      return renderTiming.now();
    }

    PeerStatusCounts counts() {
      return peerSnapshot.counts();
    }

    @Override
    public boolean equals(Object o) {
      if (!(o instanceof RenderContext that)) return false;
      return Objects.equals(pageContext, that.pageContext)
          && Objects.equals(renderMode, that.renderMode)
          && Objects.equals(renderTiming, that.renderTiming)
          && Objects.equals(peerSnapshot.counts(), that.peerSnapshot.counts())
          && Arrays.equals(peerSnapshot.peerNodeStatuses(), that.peerSnapshot.peerNodeStatuses());
    }

    @Override
    public int hashCode() {
      int result = Objects.hash(pageContext, renderMode, renderTiming, peerSnapshot.counts());
      result = 31 * result + Arrays.hashCode(peerSnapshot.peerNodeStatuses());
      return result;
    }

    @Override
    public @NotNull String toString() {
      return "RenderContext{"
          + "ctx="
          + pageContext.ctx()
          + ", path='"
          + pageContext.path()
          + '\''
          + ", peerNodeStatuses="
          + Arrays.toString(peerSnapshot.peerNodeStatuses())
          + ", drawMessageTypes="
          + renderMode.drawMessageTypes()
          + ", percentageFormat="
          + renderTiming.percentageFormat()
          + ", advancedMode="
          + renderMode.advancedModeEnabled()
          + ", contentNode="
          + pageContext.contentNode()
          + ", now="
          + renderTiming.now()
          + ", counts="
          + peerSnapshot.counts()
          + '}';
    }
  }

  private record PeerRowContext(
      HTMLNode peerTable, PeerNodeStatus peerNodeStatus, List<SimpleColumn> endCols) {}

  private record PeerRowFlags(boolean fProxyJavascriptEnabled, boolean enablePeerActions) {}

  private record PeerSelectionStats(double totalSelectionRate) {}

  private record RowContext(
      PeerRowContext peerRowContext,
      RenderMode renderMode,
      PeerRowFlags peerRowFlags,
      RenderTiming renderTiming,
      PeerSelectionStats selectionStats) {}

  /**
   * Indicates whether noderef POST submissions are accepted for this toadlet.
   *
   * <p>Subclasses can deny uploads based on network mode or feature flags, in which case POST
   * requests are answered with an unauthorized page.
   *
   * @return {@code true} when reference uploads are allowed; {@code false} when they should be
   *     rejected.
   */
  protected abstract boolean acceptRefPosts();

  /**
   * Provides the destination used when POST processing opts to redirect instead of rendering.
   *
   * @return a relative or absolute path that receives the user after recoverable errors.
   */
  @SuppressWarnings("unused")
  protected abstract String defaultRedirectLocation();

  /**
   * Handles connection-related POST requests, including noderef uploads.
   *
   * <p>The handler verifies permissions, checks whether uploads are permitted, and dispatches to
   * add-peer logic or alternate actions based on submitted form parts. It logs debug detail only
   * when enabled and leaves the state unchanged if validation fails.
   *
   * @param uri target URI, used to route auxiliary POST actions.
   * @param request HTTP request containing multipart fields such as {@code add}, {@code ref}, or
   *     {@code reffile}.
   * @param ctx toadlet context supplying authorization checks and response builders.
   * @throws ToadletContextClosedException if the client connection is already closed.
   * @throws IOException on I/O failures while reading parts or writing responses.
   * @throws ConfigException when submitted, trust or visibility values violate constraints.
   * @throws RedirectException when processing elects to redirect instead of generating a page.
   */
  public void handleMethodPOST(URI uri, final HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, ConfigException, RedirectException {
    boolean logMINOR = LOG.isDebugEnabled();

    if (!acceptRefPosts()) {
      sendUnauthorizedPage(ctx);
      return;
    }

    if (!ctx.checkFullAccess(this)) return;

    if (request.isPartSet("add")) {
      handleAddPeer(request, ctx);
    } else {
      handleAltPost(uri, request, ctx, logMINOR);
    }
  }

  private void handleAddPeer(HTTPRequest request, ToadletContext ctx)
      throws IOException, ToadletContextClosedException, ConfigException {
    AddPeerRequestData data = extractAddPeerRequestData(request);
    if (!validateTrustAndVisibility(ctx, data)) {
      return;
    }

    StringBuilder ref = fetchReference(data, ctx);
    if (ref == null) {
      return;
    }

    request.freeParts();
    processReferences(data, ref, ctx);
  }

  private AddPeerRequestData extractAddPeerRequestData(HTTPRequest request)
      throws IOException, ConfigException {
    String urltext = request.getPartAsStringFailsafe("url", 200).trim();
    String reftext = request.getPartAsStringFailsafe("ref", Integer.MAX_VALUE).trim();
    if (reftext.length() < 200) {
      reftext = request.getPartAsStringFailsafe(REF_FILE, Integer.MAX_VALUE).trim();
    }
    String privateComment = null;
    if (!isOpennet()) {
      privateComment = request.getPartAsStringFailsafe(PEER_PRIVATE_NOTE, 250).trim();
    }

    if (Boolean.parseBoolean(request.getPartAsStringFailsafe("peers-offers-files", 5))) {
      String peersOffersRefs = readPeersOffersFiles();
      if (!peersOffersRefs.isBlank()) {
        reftext = peersOffersRefs;
      }
      node.getConfig().get("node").set("peersOffersDismissed", true);
    }

    FRIEND_TRUST trust = parseTrust(request);
    FRIEND_VISIBILITY visibility = parseVisibility(request);

    return new AddPeerRequestData(urltext, reftext, privateComment, trust, visibility);
  }

  private String readPeersOffersFiles() throws IOException {
    File[] files = core.getNode().runDir().file("peers-offers").listFiles();
    if (files == null || files.length == 0) {
      return "";
    }
    StringBuilder peersOffersFilesContent = new StringBuilder();
    for (final File file : files) {
      if (file.isFile() && file.getName().endsWith(".fref")) {
        peersOffersFilesContent.append(FileUtil.readUTF(file));
      }
    }
    return peersOffersFilesContent.toString();
  }

  private FRIEND_TRUST parseTrust(HTTPRequest request) {
    String trustS = request.getPartAsStringFailsafe(TRUST, 10);
    if (trustS == null || trustS.isEmpty()) {
      return null;
    }
    return FRIEND_TRUST.valueOf(trustS);
  }

  private FRIEND_VISIBILITY parseVisibility(HTTPRequest request) {
    String visibilityS = request.getPartAsStringFailsafe("visibility", 10);
    if (visibilityS == null || visibilityS.isEmpty()) {
      return null;
    }
    return FRIEND_VISIBILITY.valueOf(visibilityS);
  }

  private boolean validateTrustAndVisibility(ToadletContext ctx, AddPeerRequestData data)
      throws ToadletContextClosedException, IOException {
    if (isOpennet()) {
      return true;
    }
    if (data.trust() == null) {
      this.sendErrorPage(
          ctx, 200, l10n("noTrustLevelAddingFriendTitle"), l10n("noTrustLevelAddingFriend"), true);
      return false;
    }
    if (data.visibility() == null) {
      this.sendErrorPage(
          ctx,
          200,
          l10n("noVisibilityLevelAddingFriendTitle"),
          l10n("noVisibilityLevelAddingFriend"),
          true);
      return false;
    }
    return true;
  }

  private StringBuilder fetchReference(AddPeerRequestData data, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (!data.urltext().isEmpty()) {
      return fetchReferenceFromUrl(data.urltext(), ctx);
    }
    if (!data.reftext().isEmpty()) {
      return new StringBuilder(cleanReferenceText(data.reftext()));
    }
    this.sendErrorPage(ctx, 200, l10n("failedToAddNodeTitle"), l10n("noRefOrURL"), !isOpennet());
    return null;
  }

  private StringBuilder fetchReferenceFromUrl(String urltext, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    try {
      return fetchReferenceViaUrl(urltext);
    } catch (IOException _) {
      this.sendErrorPage(
          ctx,
          200,
          l10n("failedToAddNodeTitle"),
          NodeL10n.getBase()
              .getString(
                  "DarknetConnectionsToadlet.cantFetchNoderefURL",
                  new String[] {"url"},
                  new String[] {urltext}),
          !isOpennet());
      return null;
    }
  }

  private StringBuilder fetchReferenceViaUrl(String urltext) throws IOException {
    try {
      FreenetURI refUri = new FreenetURI(urltext);
      return AddPeer.getReferenceFromFreenetURI(refUri, client);
    } catch (MalformedURLException | FetchException _) {
      LOG.warn("Url cannot be used as Crypta URI, trying to fetch as URL: {}", urltext);
      URL url = buildUrl(urltext);
      return AddPeer.getReferenceFromURL(url);
    }
  }

  private URL buildUrl(String urltext) throws MalformedURLException {
    try {
      return URI.create(urltext).toURL();
    } catch (IllegalArgumentException uriException) {
      throw new MalformedURLException(uriException.getMessage());
    }
  }

  private void processReferences(AddPeerRequestData data, StringBuilder ref, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    String[] nodesToAdd = splitReferences(new StringBuilder(ref.toString().trim()));
    Map<PeerAdditionReturnCodes, Integer> results = new EnumMap<>(PeerAdditionReturnCodes.class);
    for (String nodeToAdd : nodesToAdd) {
      if (nodeToAdd.isBlank()) {
        continue;
      }
      PeerAdditionReturnCodes result =
          addNewNode(
              nodeToAdd.trim().concat("\nEnd"),
              data.privateComment(),
              data.trust(),
              data.visibility());
      Integer prev = results.get(result);
      if (prev == null) prev = 0;
      results.put(result, prev + 1);
    }
    renderAddPeerResult(ctx, results);
  }

  private String[] splitReferences(StringBuilder ref) {
    replaceCarriageReturns(ref);
    String[] nodesToAdd = ref.toString().split("\nEnd\n");
    for (int i = 0; i < nodesToAdd.length; i++) {
      StringBuilder sb = new StringBuilder(nodesToAdd[i].length());
      boolean first = true;
      StringTokenizer tokenizer = new StringTokenizer(nodesToAdd[i], "\n");
      while (tokenizer.hasMoreTokens()) {
        String s = tokenizer.nextToken();
        if (s.equals("End")) {
          break;
        }
        if (s.indexOf('=') > -1 && !first) {
          sb.append('\n');
        }
        sb.append(s);
        first = false;
      }
      nodesToAdd[i] = sb.toString();
    }
    return nodesToAdd;
  }

  private void replaceCarriageReturns(StringBuilder ref) {
    int idx;
    while ((idx = ref.indexOf("\r\n")) > -1) {
      ref.deleteCharAt(idx);
    }
    while ((idx = ref.indexOf("\r")) > -1) {
      ref.setCharAt(idx, '\n');
    }
  }

  private void renderAddPeerResult(
      ToadletContext ctx, Map<PeerAdditionReturnCodes, Integer> results)
      throws ToadletContextClosedException, IOException {
    PageNode page = ctx.getPageMaker().getPageNode(l10n(REPORT_OF_NODE_ADDITION), ctx);
    HTMLNode contentNode = page.getContentNode();

    HTMLNode detailedStatusBox = new HTMLNode(ELEMENT_TABLE);
    detailedStatusBox
        .addChild(new HTMLNode("tr"))
        .addChildren(
            new HTMLNode[] {
              new HTMLNode("th", l10n("resultName")), new HTMLNode("th", l10n("numOfResults"))
            });
    HTMLNode statusBoxTable = detailedStatusBox.addChild(new HTMLNode("tbody"));
    for (PeerAdditionReturnCodes returnCode : PeerAdditionReturnCodes.values()) {
      if (results.containsKey(returnCode)) {
        statusBoxTable
            .addChild(
                new HTMLNode(
                    "tr",
                    ATTR_STYLE,
                    "color:" + (returnCode == PeerAdditionReturnCodes.OK ? "green" : "red")))
            .addChildren(
                new HTMLNode[] {
                  new HTMLNode("td", l10n("peerAdditionCode." + returnCode.toString())),
                  new HTMLNode("td", results.get(returnCode).toString())
                });
      }
    }

    HTMLNode infoboxContent =
        ctx.getPageMaker()
            .getInfobox(
                INFOBOX_CLASS, l10n(REPORT_OF_NODE_ADDITION), contentNode, "node-added", true);
    infoboxContent.addChild(detailedStatusBox);
    if (!isOpennet())
      infoboxContent.addChild("p").addChild("a", "href", "/addfriend/", l10n("addAnotherFriend"));
    infoboxContent.addChild("p").addChild("a", "href", path(), l10n("goFriendConnectionStatus"));
    addHomepageLink(infoboxContent.addChild("p"));

    writeHTMLReply(ctx, 500, l10n(REPORT_OF_NODE_ADDITION), page.generate());
  }

  private PeerAdditionReturnCodes addNewNode(
      String nodeReference,
      String privateComment,
      FRIEND_TRUST trust,
      FRIEND_VISIBILITY visibility) {
    SimpleFieldSet fs;

    try {
      fs = parseNoderefLiberally(nodeReference);
      if (!fs.getEndMarker().endsWith("End")) {
        LOG.error("Trying to add noderef with end marker \"{}\"", fs.getEndMarker());
        return PeerAdditionReturnCodes.WRONG_ENCODING;
      }
      fs.setEndMarker("End");
    } catch (IOException e) {
      LOG.error("IOException adding reference :{}", e.getMessage(), e);
      return PeerAdditionReturnCodes.CANT_PARSE;
    } catch (Exception e) {
      LOG.error("Internal error adding reference :{}", e.getMessage(), e);
      return PeerAdditionReturnCodes.INTERNAL_ERROR;
    }
    PeerNode pn;
    try {
      if (isOpennet()) {
        pn = node.network().createNewOpennetNode(fs);
      } else {
        pn = node.network().createNewDarknetNode(fs, trust, visibility);
        ((DarknetPeerNode) pn).setPrivateDarknetCommentNote(privateComment);
      }
    } catch (FSParseException | PeerParseException _) {
      return PeerAdditionReturnCodes.CANT_PARSE;
    } catch (ReferenceSignatureVerificationException _) {
      return PeerAdditionReturnCodes.INVALID_SIGNATURE;
    } catch (Exception e) {
      LOG.error("Internal error adding reference :{}", e.getMessage(), e);
      return PeerAdditionReturnCodes.INTERNAL_ERROR;
    }
    if (Arrays.equals(pn.peerECDSAPubKeyHash, node.network().darknetPubKeyHash())) {
      return PeerAdditionReturnCodes.TRY_TO_ADD_SELF;
    }
    if (!this.node.network().addPeerConnection(pn)) {
      return PeerAdditionReturnCodes.ALREADY_IN_REFERENCE;
    }
    return PeerAdditionReturnCodes.OK;
  }

  private String cleanReferenceText(String reftext) {
    StringBuilder builder = new StringBuilder(reftext.length());
    StringTokenizer tokenizer = new StringTokenizer(reftext.replace('\r', '\n'), "\n");
    while (tokenizer.hasMoreTokens()) {
      String line = tokenizer.nextToken();
      String trimmed = line.trim();
      int equalsAt = trimmed.indexOf('=');
      boolean isFieldLine = equalsAt >= 0 || trimmed.equals("End");
      if (!trimmed.isEmpty() && isFieldLine) {
        builder.append(trimmed).append('\n');
      }
    }
    return builder.toString();
  }

  private static SimpleFieldSet parseNoderefLiberally(String nodeReference) throws IOException {
    nodeReference = Fields.trimLines(nodeReference);
    SimpleFieldSet fs = new SimpleFieldSet(nodeReference, false, true, true);
    if (fs.directKeys().contains("lastGoodVersion")) {
      return fs;
    } else {
      LOG.warn(
          "Cannot parse noderef: does not contain lastGoodVersion, trying to replace all spaces"
              + " with newlines and parsing again.");
      return new SimpleFieldSet(nodeReference.replace(" ", "\n"), false, true, true);
    }
  }

  /**
   * Indicates whether this toadlet represents the opennet view rather than the darknet view.
   *
   * <p>Opennet pages skip darknet-only controls (names, trust sliders) and relax some redirects.
   * Implementations should return a consistent value per instance; callers rely on it to decide UI
   * branches and validation rules.
   *
   * @return {@code true} when rendering the opennet connections page; {@code false} for darknet.
   */
  protected abstract boolean isOpennet();

  /**
   * Delegates POST actions not handled by {@link #handleMethodPOST} to subclass-specific logic.
   *
   * <p>Default behavior proxies the POST to the GET handler, so subclasses only implementing GET
   * still behave correctly. Override to support extra form actions such as bulk operations.
   *
   * @param uri original request URI that determines routing of alternative actions.
   * @param request HTTP request wrapper containing posted fields beyond add-peer.
   * @param ctx toadlet context used to render responses or perform redirects.
   * @param logMINOR whether debug/trace logging is enabled for the current request.
   * @throws IOException when rendering fails or forwarding to GET encounters I/O errors.
   * @throws ToadletContextClosedException if the client disconnects while responses are written.
   * @throws RedirectException when subclass logic chooses to redirect instead of rendering.
   */
  protected void handleAltPost(URI uri, HTTPRequest request, ToadletContext ctx, boolean logMINOR)
      throws ToadletContextClosedException, IOException, RedirectException {
    if (logMINOR && LOG.isDebugEnabled()) {
      LOG.debug("Delegating POST to GET for {}", uri);
    }
    if (logMINOR && LOG.isTraceEnabled()) {
      LOG.trace("Original request snapshot: {}", request);
    }
    // Do nothing - we only support adding nodes
    handleMethodGET(uri, new HTTPRequestImpl(uri, "GET"), ctx);
  }

  /**
   * Supplies the primary heading displayed above the peers table.
   *
   * <p>Implementations return a localization key or literal that signals whether the view targets
   * darknet or opennet users. The value is combined with counts in {@link #buildTitleCountString}
   * to form the browser-visible page title and the on-page heading.
   *
   * @return title text or localization key describing the current connection view.
   */
  protected abstract String getPeerListTitle();

  /**
   * Indicates whether bulk peer actions should be presented to the user.
   *
   * <p>When {@code true}, the renderer adds checkboxes next to each peer row and invokes {@link
   * #drawPeerActionSelectBox(HTMLNode, boolean)} to render action controls. Subclasses typically
   * enable this in advanced mode or when authenticated users manage darknet peers.
   *
   * @return {@code true} when bulk actions and selection controls should be displayed.
   */
  protected abstract boolean showPeerActionsBox();

  /**
   * Renders additional peer actions when {@link #showPeerActionsBox()} is enabled.
   *
   * <p>A form and per-peer checkboxes are already present. Implementations should add controls and
   * submit buttons appropriate for their network mode.
   *
   * @param peerForm form a node that already wraps the peer table and checkboxes; implementations
   *     add controls directly to this element.
   * @param advancedModeEnabled whether the UI is in advanced mode, enabling additional actions or
   *     diagnostics.
   */
  protected abstract void drawPeerActionSelectBox(HTMLNode peerForm, boolean advancedModeEnabled);

  /**
   * Determines whether the noderef textarea/download box should be displayed.
   *
   * <p>Darknet pages often show noderef exchange controls even for new users, whereas opennet pages
   * may hide them unless the advanced mode is active. Implementations should keep behavior stable
   * within a session so users are not surprised by disappearing controls.
   *
   * @param advancedModeEnabled whether the user requested advanced UI features.
   * @return {@code true} to render the noderef box; {@code false} to omit it for simpler layouts.
   */
  protected abstract boolean shouldDrawNoderefBox(boolean advancedModeEnabled);

  final HTMLNode refLink;
  final HTMLNode reftextLink;

  /**
   * @param contentNode Node to add noderef box to.
   * @param fs Noderef to render as text if requested.
   */
  void drawNoderefBox(HTMLNode contentNode, SimpleFieldSet fs) {
    HTMLNode referenceInfobox = contentNode.addChild("div", ATTR_CLASS, INFOBOX_NORMAL_CLASS);
    HTMLNode headerReferenceInfobox =
        referenceInfobox.addChild("div", ATTR_CLASS, INFOBOX_HEADER_CLASS);
    // Better way to deal with this sort of thing???
    NodeL10n.getBase()
        .addL10nSubstitution(
            headerReferenceInfobox,
            "DarknetConnectionsToadlet.myReferenceHeader",
            new String[] {"linkref", "linktext"},
            new HTMLNode[] {refLink, reftextLink});
    HTMLNode referenceInfoboxContent =
        referenceInfobox.addChild("div", ATTR_CLASS, INFOBOX_CONTENT_CLASS);

    if (!isOpennet()) {
      HTMLNode myName = referenceInfoboxContent.addChild("p");
      myName.addChild(
          "span",
          NodeL10n.getBase()
              .getString("DarknetConnectionsToadlet.myName", "name", fs.get("myName")));
      myName.addChild("span", " [");
      myName
          .addChild("span")
          .addChild(
              "a",
              "href",
              "/config/node#name",
              NodeL10n.getBase().getString("DarknetConnectionsToadlet.changeMyName"));
      myName.addChild("span", "]");
    }

    HTMLNode warningSentence = referenceInfoboxContent.addChild("p");
    NodeL10n.getBase()
        .addL10nSubstitution(
            warningSentence,
            "DarknetConnectionsToadlet.referenceCopyWarning",
            new String[] {"bold"},
            new HTMLNode[] {HTMLNode.STRONG});
    referenceInfoboxContent.addChild(
        "pre", "id", "reference", fs.toOrderedStringWithBase64() + '\n');

    if (!isOpennet()) {
      HTMLNode myIps = referenceInfoboxContent.addChild("p");
      myIps.addChild(
          "span",
          NodeL10n.getBase()
              .getString("DarknetConnectionsToadlet.myIps", "ips", fs.get("physical.udp")));
    }
  }

  /**
   * Computes the full page title, optionally including connection counts.
   *
   * <p>The title appears in the browser chrome and at the top of the page. Implementations may
   * append the supplied count string or replace it entirely to match opennet/darknet conventions.
   * The method should remain deterministic for a given count input to aid testing.
   *
   * @param titleCountString preformatted count string built from {@link PeerStatusCounts}.
   * @return complete title text to render for the current request.
   */
  protected abstract String getPageTitle(String titleCountString);

  /**
   * Draws the add-a-peer box that follows the main peers table.
   *
   * <p>The box includes textarea input, file upload control, and an optional private note field.
   * Subclasses may override to hide or extend the UI but should avoid altering form names to keep
   * POST handling compatible.
   *
   * @param contentNode container to which the infobox and form are appended.
   * @param ctx toadlet context providing form helpers and localization strings.
   */
  protected void drawAddPeerBox(HTMLNode contentNode, ToadletContext ctx) {
    drawAddPeerBox(contentNode, ctx, isOpennet(), path());
  }

  /**
   * Static helper that renders the add-peer form with configurable target and mode.
   *
   * <p>Used by both opennet and darknet views to avoid code duplication. The contents include
   * textarea paste input, file chooser, optional private note, and a Submit button. The form posts
   * to {@code formTarget} using multipart encoding.
   *
   * @param contentNode HTML container receiving the generated infobox and form.
   * @param ctx toadlet context used to build forms and resolve localization keys.
   * @param isOpennet whether the UI should hide darknet-only controls like private notes.
   * @param formTarget path that receives the POST submission for adding peers.
   */
  protected static void drawAddPeerBox(
      HTMLNode contentNode, ToadletContext ctx, boolean isOpennet, String formTarget) {
    // BEGIN PEER ADDITION BOX
    HTMLNode peerAdditionInfobox = contentNode.addChild("div", ATTR_CLASS, INFOBOX_NORMAL_CLASS);
    peerAdditionInfobox.addChild(
        "div",
        ATTR_CLASS,
        INFOBOX_HEADER_CLASS,
        l10n(isOpennet ? "addOpennetPeerTitle" : "addPeerTitle"));
    HTMLNode peerAdditionContent =
        peerAdditionInfobox.addChild("div", ATTR_CLASS, INFOBOX_CONTENT_CLASS);
    HTMLNode peerAdditionForm = ctx.addFormChild(peerAdditionContent, formTarget, "addPeerForm");
    peerAdditionForm.addChild("#", l10n("pasteReference"));
    peerAdditionForm.addChild("br");
    peerAdditionForm.addChild(
        "textarea",
        new String[] {"id", "name", "rows", "cols"},
        new String[] {"reftext", "ref", "8", "74"});
    peerAdditionForm.addChild("br");
    peerAdditionForm.addChild("#", (l10n("urlReference") + ' '));
    peerAdditionForm.addChild(
        ELEMENT_INPUT, new String[] {"id", "type", "name"}, new String[] {"refurl", "text", "url"});
    peerAdditionForm.addChild("br");
    peerAdditionForm.addChild("#", (l10n("fileReference") + ' '));
    peerAdditionForm.addChild(
        ELEMENT_INPUT,
        new String[] {"id", "type", "name"},
        new String[] {REF_FILE, "file", REF_FILE});
    peerAdditionForm.addChild("br");
    if (!isOpennet) {
      peerAdditionForm.addChild(new PeerTrustInputForAddPeerBoxNode());
      peerAdditionForm.addChild(new PeerVisibilityInputForAddPeerBoxNode());
    }

    if (!isOpennet) {
      peerAdditionForm.addChild("#", (l10n("enterDescription") + ' '));
      peerAdditionForm.addChild(
          ELEMENT_INPUT,
          new String[] {"id", "type", "name", "size", "maxlength", "value"},
          new String[] {PEER_PRIVATE_NOTE, "text", PEER_PRIVATE_NOTE, "16", "250", ""});
      peerAdditionForm.addChild("br");
    }
    peerAdditionForm.addChild(
        ELEMENT_INPUT,
        new String[] {"type", "name", "value"},
        new String[] {"submit", "add", l10n("add")});
  }

  /**
   * Creates a comparator for peer listings using the requested column and direction.
   *
   * @param sortBy column key requested via HTTP parameter; may be {@code null} for default order.
   * @param reversed whether the comparator should invert the natural ordering to sort descending.
   * @return comparator suitable for {@link Arrays#sort(Object[])} on peer status arrays.
   */
  protected Comparator<PeerNodeStatus> comparator(String sortBy, boolean reversed) {
    return new ComparatorByStatus(sortBy, reversed);
  }

  /**
   * Retrieves peer statuses to render, optionally omitting heavy computations.
   *
   * @param noHeavy when {@code true}, callers request a lightweight snapshot without expensive
   *     statistics; used for message-type drill-downs.
   * @return array of peer statuses; never {@code null}, may be empty when no peers exist.
   */
  protected abstract PeerNodeStatus[] getPeerNodeStatuses(boolean noHeavy);

  /**
   * Returns the node's own reference for download or display.
   *
   * @return immutable {@link SimpleFieldSet} representing this node's noderef.
   */
  protected abstract SimpleFieldSet getNoderef();

  private void drawRow(RowContext rowContext) {
    PeerNodeStatus peerNodeStatus = rowContext.peerRowContext().peerNodeStatus();
    double totalSelectionRate = rowContext.selectionStats().totalSelectionRate();
    DecimalFormat fix1 = rowContext.renderTiming().percentageFormat();
    HTMLNode peerTable = rowContext.peerRowContext().peerTable();
    boolean advancedModeEnabled = rowContext.renderMode().advancedModeEnabled();
    boolean enablePeerActions = rowContext.peerRowFlags().enablePeerActions();
    int peerSelectionPercentage = calculateSelectionPercentage(totalSelectionRate, peerNodeStatus);
    HTMLNode peerRow =
        peerTable.addChild(
            "tr",
            ATTR_CLASS,
            "darknet_connections_"
                + (peerSelectionPercentage > PeerNode.SELECTION_PERCENTAGE_WARNING
                    ? "warning"
                    : "normal"));

    if (enablePeerActions) {
      addSelectionCheckbox(peerRow, peerNodeStatus);
    }

    addStatusColumn(peerRow, peerNodeStatus, advancedModeEnabled);

    drawNameColumn(peerRow, peerNodeStatus, advancedModeEnabled);
    drawTrustColumn(peerRow, peerNodeStatus);
    drawVisibilityColumn(peerRow, peerNodeStatus, advancedModeEnabled);
    addAddressColumn(peerRow, peerNodeStatus);
    addVersionColumn(peerRow, peerNodeStatus);

    if (advancedModeEnabled) {
      addLocationColumn(peerRow, peerNodeStatus);
      addBackoffColumns(peerRow, peerNodeStatus, rowContext.renderTiming().now(), fix1);
      addPRejectColumn(peerRow, peerNodeStatus, fix1);
    }

    addIdleColumn(peerRow, peerNodeStatus, rowContext.renderTiming().now());

    if (hasPrivateNoteColumn()) {
      drawPrivateNoteColumn(
          peerRow, peerNodeStatus, rowContext.peerRowFlags().fProxyJavascriptEnabled());
    }

    if (advancedModeEnabled) {
      addAdvancedStatistics(
          peerRow, peerNodeStatus, fix1, peerSelectionPercentage, totalSelectionRate);
    }

    addEndColumns(peerRow, peerNodeStatus, rowContext.peerRowContext().endCols());

    if (rowContext.renderMode().drawMessageTypes()) {
      drawMessageTypes(peerTable, peerNodeStatus);
    }
  }

  private int calculateSelectionPercentage(
      double totalSelectionRate, PeerNodeStatus peerNodeStatus) {
    if (totalSelectionRate <= 0) {
      return 0;
    }
    return (int) (peerNodeStatus.getSelectionRate() * 100 / totalSelectionRate);
  }

  private void addSelectionCheckbox(HTMLNode peerRow, PeerNodeStatus peerNodeStatus) {
    peerRow
        .addChild("td", ATTR_CLASS, "peer-marker")
        .addChild(
            ELEMENT_INPUT,
            new String[] {"type", "name"},
            new String[] {"checkbox", "node_" + peerNodeStatus.hashCode()});
  }

  private void addStatusColumn(
      HTMLNode peerRow, PeerNodeStatus peerNodeStatus, boolean advancedModeEnabled) {
    String statusString = peerNodeStatus.getStatusName();
    if (!advancedModeEnabled
        && (peerNodeStatus.getStatusValue() == PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF)) {
      statusString = "BUSY";
    }
    final String key = "ConnectionsToadlet.nodeStatus." + statusString.replace(' ', '_');
    peerRow
        .addChild("td", ATTR_CLASS, "peer-status")
        .addChild(
            "span",
            ATTR_CLASS,
            peerNodeStatus.getStatusCSSName(),
            NodeL10n.getBase().getString(key) + (peerNodeStatus.isFetchingARK() ? "*" : ""));
  }

  private void addAddressColumn(HTMLNode peerRow, PeerNodeStatus peerNodeStatus) {
    String pingTime = "";
    if (peerNodeStatus.isConnected()) {
      pingTime =
          " ("
              + (int) peerNodeStatus.getAveragePingTime()
              + "ms / "
              + (int) peerNodeStatus.getAveragePingTimeCorrected()
              + "ms)";
    }
    HTMLNode addressRow = peerRow.addChild("td", ATTR_CLASS, "peer-address");
    IPConverter ipc = IPConverter.getInstance(NodeFile.IPV4_TO_COUNTRY.getFile(node));
    byte[] addr = peerNodeStatus.getPeerAddressBytes();

    Country country = ipc.locateIP(addr);
    if (country != null) {
      country.renderFlagIcon(addressRow);
    }

    String address =
        peerNodeStatus.getPeerAddress() != null
            ? peerNodeStatus.getPeerAddressAndPort()
            : l10n("unknownAddress");
    addressRow.addChild("#", address + pingTime);
  }

  private void addVersionColumn(HTMLNode peerRow, PeerNodeStatus peerNodeStatus) {
    HTMLNode versionCell = peerRow.addChild("td", ATTR_CLASS, "peer-version");
    if (peerNodeStatus.getStatusValue() != PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED
        && (peerNodeStatus.isPublicInvalidVersion()
            || peerNodeStatus.isPublicReverseInvalidVersion())) {
      versionCell.addChild(
          "span",
          ATTR_CLASS,
          "peer_version_problem",
          Integer.toString(peerNodeStatus.getSimpleVersion()));
      return;
    }
    versionCell.addChild("#", Integer.toString(peerNodeStatus.getSimpleVersion()));
  }

  private void addLocationColumn(HTMLNode peerRow, PeerNodeStatus peerNodeStatus) {
    HTMLNode locationNode = peerRow.addChild("td", ATTR_CLASS, "peer-location");
    locationNode.addChild("b", String.valueOf(peerNodeStatus.getLocation()));
    locationNode.addChild("br");
    double[] peersLoc = peerNodeStatus.getPeersLocation();
    if (peersLoc != null) {
      locationNode.addChild("i", "+" + peersLoc.length + " friends");
    }
  }

  private void addBackoffColumns(
      HTMLNode peerRow, PeerNodeStatus peerNodeStatus, long now, DecimalFormat fix1) {
    addBackoffColumn(peerRow, peerNodeStatus, now, fix1, true);
    addBackoffColumn(peerRow, peerNodeStatus, now, fix1, false);
  }

  private void addBackoffColumn(
      HTMLNode peerRow,
      PeerNodeStatus peerNodeStatus,
      long now,
      DecimalFormat fix1,
      boolean realtime) {
    HTMLNode backoffCell = peerRow.addChild("td", ATTR_CLASS, "peer-backoff");
    backoffCell.addChild("#", fix1.format(peerNodeStatus.getBackedOffPercent(realtime)));
    int backoff = (int) Math.max(peerNodeStatus.getRoutingBackedOffUntil(realtime) - now, 0);
    if ((backoff > 0) && (backoff < 1000)) {
      backoff = 1000;
    }
    backoffCell.addChild(
        "#",
        ' '
            + String.valueOf(backoff / 1000)
            + '/'
            + peerNodeStatus.getRoutingBackoffLength(realtime) / 1000);
    backoffCell.addChild(
        "#",
        (peerNodeStatus.getLastBackoffReason(realtime) == null)
            ? ""
            : '/' + peerNodeStatus.getLastBackoffReason(realtime));
  }

  private void addPRejectColumn(
      HTMLNode peerRow, PeerNodeStatus peerNodeStatus, DecimalFormat fix1) {
    HTMLNode pRejectCell = peerRow.addChild("td", ATTR_CLASS, "peer-backoff");
    pRejectCell.addChild("#", fix1.format(peerNodeStatus.getPReject()));
  }

  private void addIdleColumn(HTMLNode peerRow, PeerNodeStatus peerNodeStatus, long now) {
    long idle = peerNodeStatus.getTimeLastRoutable();
    if (peerNodeStatus.isRoutable()) {
      idle = peerNodeStatus.getTimeLastConnectionCompleted();
    } else if (peerNodeStatus.getStatusValue() == PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED) {
      idle = peerNodeStatus.getPeerAddedTime();
    }
    HTMLNode idleNode;
    if (!peerNodeStatus.isConnected() && (now - idle) > (2 * 7 * 24 * 60 * 60 * 1000L)) {
      idleNode = peerRow.addChild("td", ATTR_CLASS, PEER_IDLE_CLASS);
      idleNode.addChild("span", ATTR_CLASS, "peer_idle_old", idleToString(now, idle));
      return;
    }
    peerRow.addChild("td", ATTR_CLASS, PEER_IDLE_CLASS, idleToString(now, idle));
  }

  private void addAdvancedStatistics(
      HTMLNode peerRow,
      PeerNodeStatus peerNodeStatus,
      DecimalFormat fix1,
      int peerSelectionPercentage,
      double totalSelectionRate) {
    peerRow
        .addChild("td", ATTR_CLASS, PEER_IDLE_CLASS)
        .addChild("#", fix1.format(peerNodeStatus.getPercentTimeRoutableConnection()));
    peerRow
        .addChild("td", ATTR_CLASS, PEER_IDLE_CLASS)
        .addChild("#", (totalSelectionRate > 0 ? (peerSelectionPercentage + "%") : "N/A"));
    addTrafficColumns(peerRow, peerNodeStatus, fix1);
    addTrafficSinceStartupColumn(peerRow, peerNodeStatus);
    addCongestionControl(peerRow, peerNodeStatus);
    peerRow
        .addChild("td", ATTR_CLASS, PEER_IDLE_CLASS)
        .addChild("#", TimeUtil.formatTime(peerNodeStatus.getClockDelta()));
    peerRow
        .addChild("td", ATTR_CLASS, PEER_IDLE_CLASS)
        .addChild("#", peerNodeStatus.getReportedUptimePercentage() + "%");
    peerRow
        .addChild("td", ATTR_CLASS, PEER_IDLE_CLASS)
        .addChild(
            "#",
            SizeUtil.formatSize(peerNodeStatus.getMessageQueueLengthBytes())
                + ":"
                + TimeUtil.formatTime(peerNodeStatus.getMessageQueueLengthTime()));
    addIncomingLoad(peerRow, peerNodeStatus.incomingLoadStatsBulk);
    addIncomingLoad(peerRow, peerNodeStatus.incomingLoadStatsRealTime);
  }

  private void addTrafficColumns(
      HTMLNode peerRow, PeerNodeStatus peerNodeStatus, DecimalFormat fix1) {
    long sent = peerNodeStatus.getTotalOutputBytes();
    long resent = peerNodeStatus.getResendBytesSent();
    long received = peerNodeStatus.getTotalInputBytes();
    peerRow
        .addChild("td", ATTR_CLASS, PEER_IDLE_CLASS)
        .addChild(
            "#",
            SizeUtil.formatSize(received)
                + " / "
                + SizeUtil.formatSize(sent)
                + "/"
                + SizeUtil.formatSize(resent)
                + " ("
                + fix1.format(((double) resent) / ((double) sent))
                + ")");
  }

  private void addTrafficSinceStartupColumn(HTMLNode peerRow, PeerNodeStatus peerNodeStatus) {
    peerRow
        .addChild("td", ATTR_CLASS, PEER_IDLE_CLASS)
        .addChild(
            "#",
            SizeUtil.formatSize(peerNodeStatus.getTotalInputSinceStartup())
                + " / "
                + SizeUtil.formatSize(peerNodeStatus.getTotalOutputSinceStartup()));
  }

  private void addCongestionControl(HTMLNode peerRow, PeerNodeStatus peerNodeStatus) {
    PacketThrottle throttle = peerNodeStatus.getThrottle();
    String val;
    if (throttle == null) {
      val = "none";
    } else {
      val =
          (int) throttle.getBandwidth()
              + "B/sec delay "
              + throttle.getDelay()
              + "ms (RTT "
              + throttle.getRoundTripTime()
              + "ms window "
              + throttle.getWindowSize()
              + ')';
    }
    peerRow.addChild("td", ATTR_CLASS, PEER_IDLE_CLASS).addChild("#", val);
  }

  private void addIncomingLoad(HTMLNode peerRow, IncomingLoadSummaryStats loadStats) {
    if (loadStats == null) {
      peerRow.addChild("td", ATTR_CLASS, PEER_IDLE_CLASS);
      return;
    }
    peerRow
        .addChild("td", ATTR_CLASS, PEER_IDLE_CLASS)
        .addChild(
            "#",
            loadStats.runningRequestsTotal
                + "reqs:out:"
                + SizeUtil.formatSize(loadStats.usedCapacityOutputBytes)
                + "/"
                + SizeUtil.formatSize(loadStats.othersUsedCapacityOutputBytes)
                + "/"
                + SizeUtil.formatSize(loadStats.peerCapacityOutputBytes)
                + "/"
                + SizeUtil.formatSize(loadStats.totalCapacityOutputBytes)
                + ":in:"
                + SizeUtil.formatSize(loadStats.usedCapacityInputBytes)
                + "/"
                + SizeUtil.formatSize(loadStats.othersUsedCapacityInputBytes)
                + "/"
                + SizeUtil.formatSize(loadStats.peerCapacityInputBytes)
                + "/"
                + SizeUtil.formatSize(loadStats.totalCapacityInputBytes));
  }

  private void addEndColumns(
      HTMLNode peerRow, PeerNodeStatus peerNodeStatus, List<SimpleColumn> endCols) {
    if (endCols == null || endCols.isEmpty()) {
      return;
    }
    for (SimpleColumn col : endCols) {
      col.drawColumn(peerRow, peerNodeStatus);
    }
  }

  /**
   * Indicates whether the peer table should include a trust column.
   *
   * <p>Darknet views usually show user-configurable trust, while opennet hides it. Subclasses
   * should return a stable value so column layouts remain predictable.
   *
   * @return {@code true} when a trust column should be rendered; {@code false} otherwise.
   */
  protected boolean hasTrustColumn() {
    return false;
  }

  /**
   * Renders the trust column when enabled by {@link #hasTrustColumn()}.
   *
   * @param peerRow row node corresponding to the peer being rendered.
   * @param peerNodeStatus status snapshot containing trust information to display.
   */
  protected void drawTrustColumn(HTMLNode peerRow, PeerNodeStatus peerNodeStatus) {
    // Do nothing
  }

  /**
   * Indicates whether a visibility column should be shown for peers.
   *
   * @return {@code true} to render visibility, {@code false} to omit it from the table.
   */
  protected boolean hasVisibilityColumn() {
    return false;
  }

  /**
   * Renders the visibility column when enabled.
   *
   * @param peerRow row node receiving the visibility cell.
   * @param peerNodeStatus peer status with visibility settings.
   * @param advancedModeEnabled whether advanced UI should expose additional context.
   */
  protected void drawVisibilityColumn(
      HTMLNode peerRow, PeerNodeStatus peerNodeStatus, boolean advancedModeEnabled) {
    // Do nothing
  }

  /**
   * Indicates whether a peer name column should be displayed.
   *
   * @return {@code true} to show names; {@code false} when names are not applicable.
   */
  protected abstract boolean hasNameColumn();

  /**
   * Draws the name column immediately after the status column when enabled.
   *
   * @param peerRow row node to which the name cell should be appended.
   * @param peerNodeStatus peer status that may contain a user-defined name.
   * @param advanced flag indicating whether advanced UI elements may be shown.
   */
  protected abstract void drawNameColumn(
      HTMLNode peerRow, PeerNodeStatus peerNodeStatus, boolean advanced);

  /**
   * Indicates whether a private note column should be rendered for peers.
   *
   * @return {@code true} when private notes should appear; {@code false} otherwise.
   */
  protected abstract boolean hasPrivateNoteColumn();

  /**
   * Draws the private note column when enabled by {@link #hasPrivateNoteColumn()}.
   *
   * @param peerRow row node receiving the private note cell.
   * @param peerNodeStatus peer status containing any private notes.
   * @param fProxyJavascriptEnabled whether JavaScript helpers are available for the view.
   */
  protected abstract void drawPrivateNoteColumn(
      HTMLNode peerRow, PeerNodeStatus peerNodeStatus, boolean fProxyJavascriptEnabled);

  private void drawMessageTypes(HTMLNode peerTable, PeerNodeStatus peerNodeStatus) {
    HTMLNode messageCountRow = peerTable.addChild("tr", ATTR_CLASS, "message-status");
    messageCountRow.addChild("td", "colspan", "2");
    HTMLNode messageCountCell =
        messageCountRow.addChild(
            "td", "colspan", "9"); // = total table row width - 2 from the above colspan
    HTMLNode messageCountTable =
        messageCountCell.addChild(ELEMENT_TABLE, ATTR_CLASS, "message-count");
    HTMLNode countHeaderRow = messageCountTable.addChild("tr");
    countHeaderRow.addChild("th", "Message");
    countHeaderRow.addChild("th", "Incoming");
    countHeaderRow.addChild("th", "Outgoing");
    List<String> messageNames = new ArrayList<>();
    Map<String, Long[]> messageCounts = new HashMap<>();
    for (Map.Entry<String, Long> entry : peerNodeStatus.getLocalMessagesReceived().entrySet()) {
      String messageName = entry.getKey();
      Long messageCount = entry.getValue();
      messageNames.add(messageName);
      messageCounts.put(messageName, new Long[] {messageCount, 0L});
    }
    for (Map.Entry<String, Long> entry : peerNodeStatus.getLocalMessagesSent().entrySet()) {
      String messageName = entry.getKey();
      Long messageCount = entry.getValue();
      if (!messageNames.contains(messageName)) {
        messageNames.add(messageName);
      }
      Long[] existingCounts = messageCounts.get(messageName);
      if (existingCounts == null) {
        messageCounts.put(messageName, new Long[] {0L, messageCount});
      } else {
        existingCounts[1] = messageCount;
      }
    }
    messageNames.sort(String::compareToIgnoreCase);
    for (String messageName : messageNames) {
      Long[] messageCount = messageCounts.get(messageName);
      HTMLNode messageRow = messageCountTable.addChild("tr");
      messageRow.addChild("td", messageName);
      messageRow.addChild("td", ATTR_CLASS, "right-align", String.valueOf(messageCount[0]));
      messageRow.addChild("td", ATTR_CLASS, "right-align", String.valueOf(messageCount[1]));
    }
  }

  private String idleToString(long now, long idle) {
    if (idle <= 0) {
      return " ";
    }
    long idleMilliseconds = now - idle;
    return TimeUtil.formatTime(idleMilliseconds);
  }

  private static String l10n(String string) {
    return NodeL10n.getBase().getString("DarknetConnectionsToadlet." + string);
  }

  private static String l10nCount(String string, String value) {
    return NodeL10n.getBase().getString("DarknetConnectionsToadlet." + string, COUNT, value);
  }

  private String sortString(boolean isReversed, String type) {
    return (isReversed ? ("?sortBy=" + type) : ("?sortBy=" + type + "&reversed"));
  }

  /**
   * Sends a simple error page with optional navigation hints.
   *
   * @param ctx toadlet context used to build and send the HTML reply.
   * @param code HTTP status code to return to the client.
   * @param desc short description used as the page title and infobox heading.
   * @param message localized body text explaining the failure to the user.
   * @param returnToAddFriends whether to show a link back to the add-friend page or to the previous
   *     page.
   * @throws ToadletContextClosedException if the client connection is closed while sending output.
   * @throws IOException when writing the response fails.
   */
  protected void sendErrorPage(
      ToadletContext ctx, int code, String desc, String message, boolean returnToAddFriends)
      throws ToadletContextClosedException, IOException {
    PageNode page = ctx.getPageMaker().getPageNode(desc, ctx);
    HTMLNode contentNode = page.getContentNode();

    HTMLNode infoboxContent =
        ctx.getPageMaker().getInfobox("infobox-error", desc, contentNode, null, true);
    infoboxContent.addChild("#", message);
    if (returnToAddFriends) {
      infoboxContent.addChild("br");
      infoboxContent.addChild(
          "a", "href", DarknetAddRefToadlet.PATH, l10n("returnToAddAFriendPage"));
      infoboxContent.addChild("br");
    } else {
      infoboxContent.addChild("br");
      infoboxContent.addChild("a", "href", ".", l10n("returnToPrevPage"));
      infoboxContent.addChild("br");
    }
    addHomepageLink(infoboxContent);

    writeHTMLReply(ctx, code, desc, page.generate());
  }
}

package network.crypta.runtime.admin;

import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.config.SubConfig;
import network.crypta.io.xfer.BlockReceiver;
import network.crypta.io.xfer.BlockTransmitter;
import network.crypta.io.xfer.PacketThrottle;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.DarknetPeerNode.FRIEND_TRUST;
import network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY;
import network.crypta.node.DarknetPeerNodeStatus;
import network.crypta.node.Node;
import network.crypta.node.NodeStats;
import network.crypta.node.OpennetManager;
import network.crypta.node.OpennetPeerNodeStatus;
import network.crypta.node.PeerManager;
import network.crypta.node.PeerNode;
import network.crypta.node.PeerNodeLoadTracker.IncomingLoadSummaryStats;
import network.crypta.node.PeerNodeStatus;
import network.crypta.node.PeerStatusCounts;
import network.crypta.node.RequestTracker;
import network.crypta.node.Version;
import network.crypta.runtime.admin.geoip.GeoIpCountryInfo;
import network.crypta.runtime.admin.geoip.GeoIpCountryLookup;
import network.crypta.runtime.spi.ConnectionsPageKind;
import network.crypta.runtime.spi.ConnectionsPagePort;
import network.crypta.runtime.spi.ConnectionsPageRequest;
import network.crypta.runtime.spi.ConnectionsPageSnapshot;
import network.crypta.support.BandwidthStatsContainer;
import network.crypta.support.HTMLNode;
import network.crypta.support.SizeUtil;
import network.crypta.support.TimeUtil;

import static java.util.concurrent.TimeUnit.HOURS;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * Renders the legacy friends and strangers pages behind the runtime connections-page SPI.
 *
 * <p>This adapter keeps the heavy read-only traversal in the daemon layer while returning detached
 * {@link ConnectionsPageSnapshot} fragments to the HTTP toadlets. Each render reads the current
 * peer, routing, and bandwidth state and applies the historical sort and table rules for darknet or
 * opennet. It emits localized HTML fragments that match the legacy admin UI structure closely
 * enough for the existing toadlets to keep their outer shell and POST behavior unchanged.
 *
 * <p>The class is intentionally transitional rather than reusable outside the legacy admin UI. It
 * still depends on daemon-local node services and HTML helpers internally, but it hides those
 * details behind JDK-only SPI DTOs. Instances retain only references to live node services, so
 * callers should treat each render as a point-in-time snapshot of a mutable daemon state rather
 * than a cached or stable model.
 */
final class LegacyConnectionsPagePort implements ConnectionsPagePort {
  /** HTML attribute name for CSS classes in generated fragments. */
  private static final String ATTR_CLASS = "class";

  /** HTML attribute name for inline styles in generated fragments. */
  private static final String ATTR_STYLE = "style";

  /** HTML attribute name for localized tooltip text. */
  private static final String ATTR_TITLE = "title";

  /** HTML attribute name for form control values. */
  private static final String ATTR_VALUE = "value";

  /** HTML element name for peer and overview tables. */
  private static final String ELEMENT_TABLE = "table";

  /** HTML element name for form inputs. */
  private static final String ELEMENT_INPUT = "input";

  /** HTML element name for select boxes. */
  private static final String ELEMENT_SELECT = "select";

  /** HTML element name for select options. */
  private static final String ELEMENT_OPTION = "option";

  /** CSS class used for standard infobox containers. */
  private static final String INFOBOX_CLASS = "infobox";

  /** CSS class used for normal infobox variants. */
  private static final String INFOBOX_NORMAL_CLASS = "infobox infobox-normal";

  /** CSS class used for infobox headers. */
  private static final String INFOBOX_HEADER_CLASS = "infobox-header";

  /** CSS class used for infobox body content. */
  private static final String INFOBOX_CONTENT_CLASS = "infobox-content";

  /** Request path suffix that enables per-peer message-type output. */
  private static final String DISPLAY_MESSAGE_TYPES = "displaymessagetypes.html";

  /** CSS identifier for the detached darknet peer table. */
  private static final String DARKNET_CONNECTIONS = "darknet_connections";

  /** Inline style applied to help-text headers that expose tooltips. */
  private static final String HELP_STYLE = "border-bottom: 1px dotted; cursor: help;";

  /** Sort key for the darknet trust column. */
  private static final String TRUST = "trust";

  /** Replacement token used for count-oriented localization entries. */
  private static final String COUNT = "count";

  /** CSS class used when a peer is considered idle. */
  private static final String PEER_IDLE_CLASS = "peer-idle";

  /** Prefix used for peer checkbox and form field identifiers. */
  private static final String NODE_PREFIX = "node_";

  /** Prefix used for private-note form field identifiers. */
  private static final String PEER_PRIVATE_NOTE_PREFIX = "peerPrivateNote_";

  /** Form submit control name used by the legacy peer actions form. */
  private static final String SUBMIT = "submit";

  /** Request parameter name for peer actions. */
  private static final String ACTION = "action";

  /** Request parameter name that triggers action execution. */
  private static final String DO_ACTION = "doAction";

  /** Request parameter value for trust-level changes. */
  private static final String CHANGE_TRUST = "changeTrust";

  /** Request parameter value for visibility changes. */
  private static final String CHANGE_VISIBILITY = "changeVisibility";

  /** Request parameter value for peer removal. */
  private static final String REMOVE = "remove";

  /** Filename prefix used when exporting darknet references. */
  private static final String FRIEND_PREFIX = "friend-";

  /** Filename suffix used when exporting darknet references. */
  private static final String FREF_SUFFIX = ".fref";

  /** Path separator reused when assembling local admin paths. */
  private static final char PATH_SEPARATOR = '/';

  /** Legacy admin path for the darknet friends page. */
  private static final String FRIENDS_PATH = PATH_SEPARATOR + "friends" + PATH_SEPARATOR;

  /** Placeholder inserted before the detached peer table is spliced into the page shell. */
  private static final String PEER_TABLE_PLACEHOLDER = "<!--CRYPTA_CONNECTIONS_PEER_TABLE-->";

  /** Localization prefix shared with the legacy statistics toadlet strings. */
  private static final String STATS_PREFIX = "StatisticsToadlet.";

  /** Replacement token used for total-byte localization entries. */
  private static final String TOTAL_KEY = "total";

  /** Replacement token used for percentage-oriented localization entries. */
  private static final String PERCENT_KEY = "percent";

  /** CSS class name used for connected peers. */
  private static final String CLASS_CONNECTED = "connected";

  /** CSS class used for peers that are listening and connectable. */
  private static final String PEER_LISTENING_CLASS = "peer_listening";

  /** CSS class used for peers that can only accept inbound connections. */
  private static final String PEER_LISTEN_ONLY_CLASS = "peer_listen_only";

  /** Non-breaking space used in legacy header labels. */
  private static final String NBSP = "\u00a0";

  /** Colon followed by a non-breaking space for compact labels. */
  private static final String COLON_NBSP = ":" + NBSP;

  /** Live daemon node used as the source of page state during each render. */
  private final Node node;

  /** Shared node statistics facade used by the overview and table renderers. */
  private final NodeStats stats;

  /** Shared peer manager facade used for status lookups and routing metadata. */
  private final PeerManager peers;

  /** Runtime-owned GeoIP seam used to render optional country flags beside peer addresses. */
  private final GeoIpCountryLookup geoIpCountryLookup;

  /**
   * Creates the daemon-side adapter for the legacy connections pages.
   *
   * @param node live node that supplies peer, routing, and bandwidth state for each render
   * @param geoIpCountryLookup runtime-owned GeoIP lookup used for optional address flag rendering
   * @throws NullPointerException if either argument is {@code null}
   */
  LegacyConnectionsPagePort(Node node, GeoIpCountryLookup geoIpCountryLookup) {
    this.node = Objects.requireNonNull(node);
    this.geoIpCountryLookup = Objects.requireNonNull(geoIpCountryLookup);
    this.stats = node.network().stats();
    this.peers = node.network().peers();
  }

  @Override
  public ConnectionsPageSnapshot render(ConnectionsPageRequest request) {
    return rendererFor(request.kind()).render(request);
  }

  /**
   * Returns the per-kind renderer used for one detached page render.
   *
   * @param kind requested legacy connections page kind
   * @return fresh renderer configured for darknet or opennet output
   */
  private ConnectionsRenderer rendererFor(ConnectionsPageKind kind) {
    return switch (kind) {
      case DARKNET -> new DarknetRenderer();
      case OPENNET -> new OpennetRenderer();
    };
  }

  /** Describes one renderer-specific trailing table column and its header metadata. */
  private abstract static class SimpleColumn {
    protected abstract void drawColumn(HTMLNode peerRow, PeerNodeStatus peerNodeStatus);

    abstract String getSortString();

    abstract String getTitleKey();

    abstract String getExplanationKey();
  }

  /**
   * Implements the shared detached-render pipeline for one legacy connections page kind.
   *
   * <p>Subclasses provide the peer source, localized titles, and any renderer-specific columns or
   * row fragments. The base implementation owns the common work: sorting, overview infoboxes, peer
   * table assembly, and splitting the final content around the peer-table placeholder so the HTTP
   * layer can decide whether to wrap the table in a request-context form.
   */
  private abstract class ConnectionsRenderer {
    ConnectionsPageSnapshot render(ConnectionsPageRequest request) {
      PeerNodeStatus[] peerNodeStatuses = getPeerNodeStatuses(!request.drawMessageTypes());
      Arrays.sort(peerNodeStatuses, comparator(request.sortBy(), request.reversed()));

      PeerStatusCounts counts = computePeerStatusCounts(peerNodeStatuses);
      String pageTitle = getPageTitle(buildTitleCountString(counts));
      long now = System.currentTimeMillis();
      DecimalFormat percentageFormat = new DecimalFormat("##0.0%");

      HTMLNode contentNode = new HTMLNode("#");
      if (request.advancedMode()) {
        addOverviewSection(contentNode, percentageFormat, now, counts);
      }

      addPeerTableSectionTemplate(contentNode, request);
      if (request.advancedMode()) {
        addFoafTable(contentNode, peerNodeStatuses);
      }

      String peerTableHtml = buildPeerTableHtml(peerNodeStatuses, request, percentageFormat, now);
      String contentHtml = contentNode.generate();
      int placeholderIndex = contentHtml.indexOf(PEER_TABLE_PLACEHOLDER);
      if (placeholderIndex < 0) {
        throw new IllegalStateException("Connections page placeholder missing from detached HTML");
      }

      String contentHtmlBeforePeerTable = contentHtml.substring(0, placeholderIndex);
      String contentHtmlAfterPeerTable =
          contentHtml.substring(placeholderIndex + PEER_TABLE_PLACEHOLDER.length());

      return new ConnectionsPageSnapshot(
          pageTitle,
          peerNodeStatuses.length,
          peerActionsEnabled(),
          contentHtmlBeforePeerTable,
          peerTableHtml,
          contentHtmlAfterPeerTable);
    }

    protected abstract String getPageTitle(String titleCountString);

    protected abstract String getPeerListTitle();

    protected abstract boolean isOpennet();

    protected boolean peerActionsEnabled() {
      return false;
    }

    protected boolean hasTrustColumn() {
      return false;
    }

    protected void drawTrustColumn(HTMLNode peerRow, PeerNodeStatus peerNodeStatus) {
      // No-op by default.
    }

    protected boolean hasVisibilityColumn() {
      return false;
    }

    protected void drawVisibilityColumn(
        HTMLNode peerRow, PeerNodeStatus peerNodeStatus, boolean advancedModeEnabled) {
      // No-op by default.
    }

    protected abstract boolean hasNameColumn();

    protected abstract void drawNameColumn(
        HTMLNode peerRow, PeerNodeStatus peerNodeStatus, boolean advancedModeEnabled);

    protected abstract boolean hasPrivateNoteColumn();

    protected abstract void drawPrivateNoteColumn(
        HTMLNode peerRow, PeerNodeStatus peerNodeStatus, boolean fProxyJavascriptEnabled);

    protected abstract PeerNodeStatus[] getPeerNodeStatuses(boolean noHeavy);

    protected Comparator<PeerNodeStatus> comparator(String sortBy, boolean reversed) {
      return new ComparatorByStatus(sortBy, reversed);
    }

    /**
     * Returns any renderer-specific trailing columns for the peer table.
     *
     * @param advancedMode whether the current request is rendering the advanced table variant;
     *     subclasses may use this to expose extra columns
     */
    protected List<SimpleColumn> endColumnHeaders(boolean advancedMode) {
      return List.of();
    }

    protected void drawPeerActionSelectBox(HTMLNode peerForm, boolean advancedModeEnabled) {
      // No-op by default.
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
      String nodeUptimeString =
          TimeUtil.formatTime(MILLISECONDS.convert(nodeUptimeSeconds, SECONDS));

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
          "li",
          "routingMissDistanceRemote:\u00a0" + routingFormat.format(routingMissDistanceRemote));
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
          "li",
          "pInstantReject:\u00a0" + percentageFormat.format(stats.pRejectIncomingInstantly()));
      nextTableCell = overviewTableRow.addChild("td");

      addActivitySection(nextTableCell, nodeUptimeSeconds);
      addPeerStatsSection(nextTableCell, counts);
    }

    private void addActivitySection(HTMLNode tableCell, long nodeUptimeSeconds) {
      int numArkFetchers = node.network().numArkFetchers();

      HTMLNode activityInfobox = tableCell.addChild("div", ATTR_CLASS, INFOBOX_CLASS);
      activityInfobox.addChild(
          "div", ATTR_CLASS, INFOBOX_HEADER_CLASS, connectionsL10n("activityTitle"));
      HTMLNode activityInfoboxContent =
          activityInfobox.addChild("div", ATTR_CLASS, INFOBOX_CONTENT_CLASS);
      HTMLNode activityList = drawActivity(activityInfoboxContent);
      if (activityList != null) {
        if (numArkFetchers > 0) {
          activityList.addChild("li", "ARK\u00a0Fetch\u00a0Requests:\u00a0" + numArkFetchers);
        }
        drawBandwidth(activityList, nodeUptimeSeconds);
      }
    }

    private void addPeerStatsSection(HTMLNode tableCell, PeerStatusCounts counts) {
      HTMLNode peerStatsInfobox = tableCell.addChild("div", ATTR_CLASS, INFOBOX_CLASS);
      drawPeerStatsBox(peerStatsInfobox, counts);
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
          int reasonCount =
              peers.getPeerNodeRoutingBackoffReasonSize(routingBackoffReason, realtime);
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

    private void addPeerTableSectionTemplate(HTMLNode contentNode, ConnectionsPageRequest request) {
      if (node.isFProxyJavascriptEnabled()) {
        injectJavascript(contentNode);
      }

      HTMLNode peerTableInfobox = contentNode.addChild("div", ATTR_CLASS, INFOBOX_NORMAL_CLASS);
      HTMLNode peerTableInfoboxHeader =
          peerTableInfobox.addChild("div", ATTR_CLASS, INFOBOX_HEADER_CLASS);
      peerTableInfoboxHeader.addChild("#", getPeerListTitle());
      if (request.advancedMode() && !request.drawMessageTypes()) {
        peerTableInfoboxHeader.addChild("#", " ");
        peerTableInfoboxHeader.addChild(
            "a", "href", DISPLAY_MESSAGE_TYPES, connectionsL10n("bracketedMoreDetailed"));
      }

      HTMLNode peerTableInfoboxContent =
          peerTableInfobox.addChild("div", ATTR_CLASS, INFOBOX_CONTENT_CLASS);

      if (!isOpennet()) {
        addNameSection(peerTableInfoboxContent);
      }

      peerTableInfoboxContent.addChild("%", PEER_TABLE_PLACEHOLDER);
    }

    private String buildPeerTableHtml(
        PeerNodeStatus[] peerNodeStatuses,
        ConnectionsPageRequest request,
        DecimalFormat percentageFormat,
        long now) {
      HTMLNode peerTableContent = new HTMLNode("#");
      if (peerNodeStatuses.length == 0) {
        addNoPeersMessage(peerTableContent);
        return peerTableContent.generate();
      }

      HTMLNode peerTable =
          peerTableContent.addChild(ELEMENT_TABLE, ATTR_CLASS, DARKNET_CONNECTIONS);
      HTMLNode peerTableHeaderRow = peerTable.addChild("tr");
      boolean enablePeerActions = peerActionsEnabled();
      boolean fProxyJavascriptEnabled = node.isFProxyJavascriptEnabled();
      addPeerTableHeader(
          enablePeerActions,
          fProxyJavascriptEnabled,
          peerTableHeaderRow,
          request.advancedMode(),
          request.reversed());

      List<SimpleColumn> endCols = endColumnHeaders(request.advancedMode());
      double totalSelectionRate = 0.0;
      PeerNodeStatus[] allPeerNodeStatuses = peers.statusBook().getPeerNodeStatuses(true);
      for (PeerNodeStatus status : allPeerNodeStatuses) {
        totalSelectionRate += status.getSelectionRate();
      }
      RowRenderContext rowRenderContext =
          new RowRenderContext(
              endCols,
              request,
              fProxyJavascriptEnabled,
              enablePeerActions,
              percentageFormat,
              now,
              totalSelectionRate);

      for (PeerNodeStatus peerNodeStatus : peerNodeStatuses) {
        drawRow(peerTable, peerNodeStatus, rowRenderContext);
      }

      if (enablePeerActions) {
        drawPeerActionSelectBox(peerTableContent, request.advancedMode());
      }

      return peerTableContent.generate();
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
          NodeL10n.getBase()
              .getString("DarknetConnectionsToadlet.myName", "name", node.getMyName()));
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

    private void addPeerTableHeader(
        boolean enablePeerActions,
        boolean fProxyJavascriptEnabled,
        HTMLNode peerTableHeaderRow,
        boolean advancedMode,
        boolean reversed) {
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
          .addChild("a", "href", sortString(reversed, "status"))
          .addChild("#", connectionsL10n("statusTitle"));

      if (hasNameColumn()) {
        peerTableHeaderRow
            .addChild("th")
            .addChild("a", "href", sortString(reversed, "name"))
            .addChild(
                "span",
                new String[] {ATTR_TITLE, ATTR_STYLE},
                new String[] {connectionsL10n("nameClickToMessage"), HELP_STYLE},
                connectionsL10n("nameTitle"));
      }

      if (hasTrustColumn()) {
        peerTableHeaderRow
            .addChild("th")
            .addChild("a", "href", sortString(reversed, TRUST))
            .addChild(
                "span",
                new String[] {ATTR_TITLE, ATTR_STYLE},
                new String[] {connectionsL10n("trustMessage"), HELP_STYLE},
                connectionsL10n("trustTitle"));
      }

      if (hasVisibilityColumn()) {
        peerTableHeaderRow
            .addChild("th")
            .addChild("a", "href", sortString(reversed, TRUST))
            .addChild(
                "span",
                new String[] {ATTR_TITLE, ATTR_STYLE},
                new String[] {
                  connectionsL10n("visibilityMessage" + (advancedMode ? "Advanced" : "Simple")),
                  HELP_STYLE
                },
                connectionsL10n("visibilityTitle"));
      }

      peerTableHeaderRow
          .addChild("th")
          .addChild("a", "href", sortString(reversed, "address"))
          .addChild(
              "span",
              new String[] {ATTR_TITLE, ATTR_STYLE},
              new String[] {connectionsL10n("ipAddress"), HELP_STYLE},
              connectionsL10n("ipAddressTitle"));
      peerTableHeaderRow
          .addChild("th")
          .addChild("a", "href", sortString(reversed, "version"))
          .addChild("#", connectionsL10n("versionTitle"));

      if (advancedMode) {
        addAdvancedPeerTableHeaders(peerTableHeaderRow, reversed);
      }

      peerTableHeaderRow
          .addChild("th")
          .addChild("a", "href", sortString(reversed, "idle"))
          .addChild(
              "span",
              new String[] {ATTR_TITLE, ATTR_STYLE},
              new String[] {connectionsL10n("idleTime"), HELP_STYLE},
              connectionsL10n("idleTimeTitle"));

      if (hasPrivateNoteColumn()) {
        peerTableHeaderRow
            .addChild("th")
            .addChild("a", "href", sortString(reversed, "privnote"))
            .addChild(
                "span",
                new String[] {ATTR_TITLE, ATTR_STYLE},
                new String[] {connectionsL10n("privateNote"), HELP_STYLE},
                connectionsL10n("privateNoteTitle"));
      }

      if (advancedMode) {
        peerTableHeaderRow
            .addChild("th")
            .addChild("a", "href", sortString(reversed, "time_routable"))
            .addChild("#", "%\u00a0Time Routable");
        peerTableHeaderRow
            .addChild("th")
            .addChild("a", "href", sortString(reversed, "selection_percentage"))
            .addChild("#", "%\u00a0Selection");
        peerTableHeaderRow
            .addChild("th")
            .addChild("a", "href", sortString(reversed, "total_traffic"))
            .addChild("#", "Total\u00a0Traffic\u00a0(in/out/resent)");
        peerTableHeaderRow
            .addChild("th")
            .addChild("a", "href", sortString(reversed, "total_traffic_since_startup"))
            .addChild("#", "Total\u00a0Traffic\u00a0(in/out) since startup");
        peerTableHeaderRow.addChild("th", "Congestion\u00a0Control");
        peerTableHeaderRow
            .addChild("th")
            .addChild("a", "href", sortString(reversed, "time_delta"))
            .addChild("#", "Time\u00a0Delta");
        peerTableHeaderRow
            .addChild("th")
            .addChild("a", "href", sortString(reversed, "uptime"))
            .addChild("#", "Reported\u00a0Uptime");
        peerTableHeaderRow.addChild("th", "Transmit\u00a0Queue");
        peerTableHeaderRow.addChild("th", "Peer\u00a0Capacity\u00a0Bulk");
        peerTableHeaderRow.addChild("th", "Peer\u00a0Capacity\u00a0Realtime");
      }

      for (SimpleColumn col : endColumnHeaders(advancedMode)) {
        HTMLNode header = peerTableHeaderRow.addChild("th");
        String sortString = col.getSortString();
        if (sortString != null) {
          header = header.addChild("a", "href", sortString(reversed, sortString));
        }
        header.addChild(
            "span",
            new String[] {ATTR_TITLE, ATTR_STYLE},
            new String[] {NodeL10n.getBase().getString(col.getExplanationKey()), HELP_STYLE},
            NodeL10n.getBase().getString(col.getTitleKey()));
      }
    }

    private void addAdvancedPeerTableHeaders(HTMLNode peerTableHeaderRow, boolean reversed) {
      peerTableHeaderRow
          .addChild("th")
          .addChild("a", "href", sortString(reversed, "location"))
          .addChild("#", connectionsL10n("locationTitle"));
      peerTableHeaderRow
          .addChild("th")
          .addChild("a", "href", sortString(reversed, "backoffRT"))
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
          .addChild("a", "href", sortString(reversed, "backoffBulk"))
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
          .addChild("a", "href", sortString(reversed, "overload_p"))
          .addChild(
              "span",
              new String[] {ATTR_TITLE, ATTR_STYLE},
              new String[] {
                "Probability of the node rejecting a request due to overload or causing a timeout.",
                HELP_STYLE
              },
              "Overload Probability");
    }

    private void drawRow(
        HTMLNode peerTable, PeerNodeStatus peerNodeStatus, RowRenderContext rowRenderContext) {
      ConnectionsPageRequest request = rowRenderContext.request();
      DecimalFormat percentageFormat = rowRenderContext.percentageFormat();
      long now = rowRenderContext.now();
      double totalSelectionRate = rowRenderContext.totalSelectionRate();
      int peerSelectionPercentage =
          totalSelectionRate <= 0
              ? 0
              : (int) (peerNodeStatus.getSelectionRate() * 100 / totalSelectionRate);
      HTMLNode peerRow =
          peerTable.addChild(
              "tr",
              ATTR_CLASS,
              "darknet_connections_"
                  + (peerSelectionPercentage > PeerNode.SELECTION_PERCENTAGE_WARNING
                      ? "warning"
                      : "normal"));

      if (rowRenderContext.enablePeerActions()) {
        peerRow
            .addChild("td", ATTR_CLASS, "peer-marker")
            .addChild(
                ELEMENT_INPUT,
                new String[] {"type", "name"},
                new String[] {"checkbox", NODE_PREFIX + peerNodeStatus.hashCode()});
      }

      addStatusColumn(peerRow, peerNodeStatus, request.advancedMode());
      drawNameColumn(peerRow, peerNodeStatus, request.advancedMode());
      drawTrustColumn(peerRow, peerNodeStatus);
      drawVisibilityColumn(peerRow, peerNodeStatus, request.advancedMode());
      addAddressColumn(peerRow, peerNodeStatus);
      addVersionColumn(peerRow, peerNodeStatus);

      if (request.advancedMode()) {
        addLocationColumn(peerRow, peerNodeStatus);
        addBackoffColumns(peerRow, peerNodeStatus, now, percentageFormat);
        addPRejectColumn(peerRow, peerNodeStatus, percentageFormat);
      }

      addIdleColumn(peerRow, peerNodeStatus, now);

      if (hasPrivateNoteColumn()) {
        drawPrivateNoteColumn(peerRow, peerNodeStatus, rowRenderContext.fProxyJavascriptEnabled());
      }

      if (request.advancedMode()) {
        addAdvancedStatistics(
            peerRow, peerNodeStatus, percentageFormat, peerSelectionPercentage, totalSelectionRate);
      }

      for (SimpleColumn col : rowRenderContext.endCols()) {
        col.drawColumn(peerRow, peerNodeStatus);
      }

      if (request.drawMessageTypes()) {
        drawMessageTypes(peerTable, peerNodeStatus);
      }
    }

    private void addStatusColumn(
        HTMLNode peerRow, PeerNodeStatus peerNodeStatus, boolean advancedModeEnabled) {
      String statusString = peerNodeStatus.getStatusName();
      if (!advancedModeEnabled
          && peerNodeStatus.getStatusValue() == PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF) {
        statusString = "BUSY";
      }
      String key = "ConnectionsToadlet.nodeStatus." + statusString.replace(' ', '_');
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
      GeoIpCountryInfo country = geoIpCountryLookup.locate(peerNodeStatus.getPeerAddressBytes());
      if (country != null && country.staticFlagUrl() != null) {
        addressRow.addChild(
            "img",
            new String[] {"src", ATTR_CLASS, ATTR_TITLE},
            new String[] {country.staticFlagUrl(), "flag", country.displayName()});
      }

      String address =
          peerNodeStatus.getPeerAddress() != null
              ? peerNodeStatus.getPeerAddressAndPort()
              : connectionsL10n("unknownAddress");
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
        HTMLNode peerRow, PeerNodeStatus peerNodeStatus, long now, DecimalFormat percentageFormat) {
      addBackoffColumn(peerRow, peerNodeStatus, now, percentageFormat, true);
      addBackoffColumn(peerRow, peerNodeStatus, now, percentageFormat, false);
    }

    private void addBackoffColumn(
        HTMLNode peerRow,
        PeerNodeStatus peerNodeStatus,
        long now,
        DecimalFormat percentageFormat,
        boolean realtime) {
      HTMLNode backoffCell = peerRow.addChild("td", ATTR_CLASS, "peer-backoff");
      backoffCell.addChild(
          "#", percentageFormat.format(peerNodeStatus.getBackedOffPercent(realtime)));
      int backoff = (int) Math.max(peerNodeStatus.getRoutingBackedOffUntil(realtime) - now, 0);
      if (backoff > 0 && backoff < 1000) {
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
          peerNodeStatus.getLastBackoffReason(realtime) == null
              ? ""
              : '/' + peerNodeStatus.getLastBackoffReason(realtime));
    }

    private void addPRejectColumn(
        HTMLNode peerRow, PeerNodeStatus peerNodeStatus, DecimalFormat percentageFormat) {
      peerRow
          .addChild("td", ATTR_CLASS, "peer-backoff")
          .addChild("#", percentageFormat.format(peerNodeStatus.getPReject()));
    }

    private void addIdleColumn(HTMLNode peerRow, PeerNodeStatus peerNodeStatus, long now) {
      long idle = peerNodeStatus.getTimeLastRoutable();
      if (peerNodeStatus.isRoutable()) {
        idle = peerNodeStatus.getTimeLastConnectionCompleted();
      } else if (peerNodeStatus.getStatusValue() == PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED) {
        idle = peerNodeStatus.getPeerAddedTime();
      }

      if (!peerNodeStatus.isConnected() && (now - idle) > (2L * 7 * 24 * 60 * 60 * 1000)) {
        HTMLNode idleNode = peerRow.addChild("td", ATTR_CLASS, PEER_IDLE_CLASS);
        idleNode.addChild("span", ATTR_CLASS, "peer_idle_old", idleToString(now, idle));
        return;
      }

      peerRow.addChild("td", ATTR_CLASS, PEER_IDLE_CLASS, idleToString(now, idle));
    }

    private void addAdvancedStatistics(
        HTMLNode peerRow,
        PeerNodeStatus peerNodeStatus,
        DecimalFormat percentageFormat,
        int peerSelectionPercentage,
        double totalSelectionRate) {
      peerRow
          .addChild("td", ATTR_CLASS, PEER_IDLE_CLASS)
          .addChild(
              "#", percentageFormat.format(peerNodeStatus.getPercentTimeRoutableConnection()));
      peerRow
          .addChild("td", ATTR_CLASS, PEER_IDLE_CLASS)
          .addChild("#", totalSelectionRate > 0 ? peerSelectionPercentage + "%" : "N/A");
      addTrafficColumns(peerRow, peerNodeStatus, percentageFormat);
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
        HTMLNode peerRow, PeerNodeStatus peerNodeStatus, DecimalFormat percentageFormat) {
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
                  + percentageFormat.format(((double) resent) / ((double) sent))
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

    private void drawMessageTypes(HTMLNode peerTable, PeerNodeStatus peerNodeStatus) {
      HTMLNode messageCountRow = peerTable.addChild("tr", ATTR_CLASS, "message-status");
      messageCountRow.addChild("td", "colspan", "2");
      HTMLNode messageCountCell = messageCountRow.addChild("td", "colspan", "9");
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

    private void addFoafTable(HTMLNode contentNode, PeerNodeStatus[] peerNodeStatuses) {
      FoafGrouping grouping = buildFoafGrouping(peerNodeStatuses);
      addFoafSummary(contentNode, grouping);
      addFoafRows(contentNode, peerNodeStatuses, grouping);
    }

    private void addFoafSummary(HTMLNode contentNode, FoafGrouping grouping) {
      contentNode.addChild(
          "b",
          connectionsL10nCount(
              "secondDegreeConnectionsCountTitle", Integer.toString(grouping.locations().size())));
      contentNode.addChild("br");
      contentNode.addChild(
          "i",
          connectionsL10nCount(
              "secondDegreeTrivialHiddenCount", Integer.toString(grouping.trivialCount())));
    }

    private void addFoafRows(
        HTMLNode contentNode, PeerNodeStatus[] peerNodeStatuses, FoafGrouping grouping) {
      HTMLNode foafTable = contentNode.addChild(ELEMENT_TABLE, ATTR_CLASS, DARKNET_CONNECTIONS);
      HTMLNode foafRow = foafTable.addChild("tr");
      foafRow.addChild("th", connectionsL10n("locationTitle"));
      foafRow.addChild("th", connectionsL10n("countTitle"));
      foafRow.addChild("th", connectionsL10n("foafReachableThroughTitle"));
      int max = grouping.locations().size();
      int transitiveCount = 0;
      for (int i = 0; i < max; i++) {
        double location = grouping.locations().get(i);
        List<PeerNodeStatus> peersWithFriend = grouping.peerGroups().get(i);
        boolean isTransitivePeer = isTransitivePeer(peerNodeStatuses, location);
        if (peersWithFriend.size() == 1 && !isTransitivePeer) {
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
              peerNodeStatus.getPeerAddress() != null
                  ? peerNodeStatus.getPeerAddressAndPort()
                  : connectionsL10n("unknownAddress");
          locationCell.addChild("i", address);
          locationCell.addChild("br");
        }
        if (isTransitivePeer) {
          transitiveCount++;
        }
      }
      if (transitiveCount > 0) {
        contentNode.addChild(
            "i", connectionsL10nCount("secondDegreeAlsoOurs", Integer.toString(transitiveCount)));
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

    private PeerStatusCounts computePeerStatusCounts(PeerNodeStatus[] peerNodeStatuses) {
      return new PeerStatusCounts(
          PeerNodeStatus.getPeerStatusCount(
              peerNodeStatuses, PeerManager.PEER_NODE_STATUS_CONNECTED),
          PeerNodeStatus.getPeerStatusCount(
              peerNodeStatuses, PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF),
          PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_TOO_NEW),
          PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_TOO_OLD),
          PeerNodeStatus.getPeerStatusCount(
              peerNodeStatuses, PeerManager.PEER_NODE_STATUS_DISCONNECTED),
          PeerNodeStatus.getPeerStatusCount(
              peerNodeStatuses, PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED),
          PeerNodeStatus.getPeerStatusCount(
              peerNodeStatuses, PeerManager.PEER_NODE_STATUS_DISABLED),
          PeerNodeStatus.getPeerStatusCount(
              peerNodeStatuses, PeerManager.PEER_NODE_STATUS_BURSTING),
          PeerNodeStatus.getPeerStatusCount(
              peerNodeStatuses, PeerManager.PEER_NODE_STATUS_LISTENING),
          PeerNodeStatus.getPeerStatusCount(
              peerNodeStatuses, PeerManager.PEER_NODE_STATUS_LISTEN_ONLY),
          0,
          0,
          PeerNodeStatus.getPeerStatusCount(
              peerNodeStatuses, PeerManager.PEER_NODE_STATUS_ROUTING_DISABLED),
          PeerNodeStatus.getPeerStatusCount(
              peerNodeStatuses, PeerManager.PEER_NODE_STATUS_CLOCK_PROBLEM),
          PeerNodeStatus.getPeerStatusCount(
              peerNodeStatuses, PeerManager.PEER_NODE_STATUS_CONN_ERROR),
          PeerNodeStatus.getPeerStatusCount(
              peerNodeStatuses, PeerManager.PEER_NODE_STATUS_DISCONNECTING),
          PeerNodeStatus.getPeerStatusCount(
              peerNodeStatuses, PeerManager.PEER_NODE_STATUS_NO_LOAD_STATS));
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

    private HTMLNode drawActivity(HTMLNode activityInfoboxContent) {
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
      int numChkOfferReplys = tracker.getNumCHKOfferReplies();
      int numSskOfferReplys = tracker.getNumSSKOfferReplies();
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
          && (numChkOfferReplys == 0)
          && (numSskOfferReplys == 0)) {
        activityInfoboxContent.addChild("#", statisticsL10n("noRequests"));
        return null;
      }

      HTMLNode activityList = activityInfoboxContent.addChild("ul");
      if (numChkInserts > 0 || numSskInserts > 0) {
        activityList.addChild(
            "li",
            NodeL10n.getBase()
                .getString(
                    "StatisticsToadlet.activityInserts",
                    new String[] {"CHKhandlers", "SSKhandlers", "local"},
                    new String[] {
                      Integer.toString(numChkInserts),
                      Integer.toString(numSskInserts),
                      numLocalChkInserts + "/" + numLocalSskInserts
                    }));
      }
      if (numChkRequests > 0 || numSskRequests > 0) {
        activityList.addChild(
            "li",
            NodeL10n.getBase()
                .getString(
                    "StatisticsToadlet.activityRequests",
                    new String[] {"CHKhandlers", "SSKhandlers", "local"},
                    new String[] {
                      Integer.toString(numChkRequests),
                      Integer.toString(numSskRequests),
                      numLocalChkRequests + "/" + numLocalSskRequests
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
      if (numChkOfferReplys > 0 || numSskOfferReplys > 0) {
        activityList.addChild(
            "li",
            NodeL10n.getBase()
                .getString(
                    "StatisticsToadlet.offerReplys",
                    new String[] {"chk", "ssk"},
                    new String[] {
                      Integer.toString(numChkOfferReplys), Integer.toString(numSskOfferReplys)
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

    private void drawBandwidth(HTMLNode activityList, long nodeUptimeSeconds) {
      long[] total = node.network().collector().getTotalIO();
      if (total[0] == 0 || total[1] == 0) {
        return;
      }
      long totalOutputRate = total[0] / nodeUptimeSeconds;
      long totalInputRate = total[1] / nodeUptimeSeconds;
      long totalPayload = node.getTotalPayloadSent();
      long totalPayloadRate = totalPayload / nodeUptimeSeconds;
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
            statisticsL10n(
                "inputRate",
                new String[] {"rate", "max"},
                new String[] {
                  SizeUtil.formatSize(inputRate, true),
                  SizeUtil.formatSize(inputBandwidthLimit, true)
                }));
        activityList.addChild(
            "li",
            statisticsL10n(
                "outputRate",
                new String[] {"rate", "max"},
                new String[] {
                  SizeUtil.formatSize(outputRate, true),
                  SizeUtil.formatSize(outputBandwidthLimit, true)
                }));
      }
      activityList.addChild(
          "li",
          statisticsL10n(
              "totalInputSession",
              new String[] {TOTAL_KEY, "rate"},
              new String[] {
                SizeUtil.formatSize(total[1], true), SizeUtil.formatSize(totalInputRate, true)
              }));
      activityList.addChild(
          "li",
          statisticsL10n(
              "totalOutputSession",
              new String[] {TOTAL_KEY, "rate"},
              new String[] {
                SizeUtil.formatSize(total[0], true), SizeUtil.formatSize(totalOutputRate, true)
              }));
      activityList.addChild(
          "li",
          statisticsL10n(
              "payloadOutput",
              new String[] {TOTAL_KEY, "rate", PERCENT_KEY},
              new String[] {
                SizeUtil.formatSize(totalPayload, true),
                SizeUtil.formatSize(totalPayloadRate, true),
                Integer.toString(percent)
              }));
      activityList.addChild(
          "li", statisticsL10n("totalInput", SizeUtil.formatSize(overallTotalIn, true)));
      activityList.addChild(
          "li", statisticsL10n("totalOutput", SizeUtil.formatSize(overallTotalOut, true)));
      long totalBytesSentChkRequests = stats.getCHKRequestTotalBytesSent();
      long totalBytesSentSskRequests = stats.getSSKRequestTotalBytesSent();
      long totalBytesSentChkInserts = stats.getCHKInsertTotalBytesSent();
      long totalBytesSentSskInserts = stats.getSSKInsertTotalBytesSent();
      long totalBytesSentOfferedKeys = stats.getOfferedKeysTotalBytesSent();
      long totalBytesSentOffers = stats.getOffersSentBytesSent();
      long totalBytesSentSwapOutput = stats.getSwappingTotalBytesSent();
      long totalBytesSentAuth = stats.getTotalAuthBytesSent();
      long totalBytesSentAckOnly = stats.getNotificationOnlyPacketsSentBytes();
      long totalBytesSentResends = stats.getResendBytesSent();
      long totalBytesSentUom = stats.getUOMBytesSent();
      long totalBytesSentAnnounce = stats.getAnnounceBytesSent();
      long totalBytesSentAnnouncePayload = stats.getAnnounceBytesPayloadSent();
      long totalBytesSentRoutingStatus = stats.getRoutingStatusBytes();
      long totalBytesSentNetworkColoring = stats.getNetworkColoringSentBytes();
      long totalBytesSentPing = stats.getPingSentBytes();
      long totalBytesSentProbeRequest = stats.getProbeRequestSentBytes();
      long totalBytesSentRouted = stats.getRoutedMessageSentBytes();
      long totalBytesSentDisconn = stats.getDisconnBytesSent();
      long totalBytesSentInitial = stats.getInitialMessagesBytesSent();
      long totalBytesSentChangedIp = stats.getChangedIPBytesSent();
      long totalBytesSentNodeToNode = stats.getNodeToNodeBytesSent();
      long totalBytesSentAllocationNotices = stats.getAllocationNoticesBytesSent();
      long totalBytesSentFoaf = stats.getFOAFBytesSent();
      long totalBytesSentRemaining =
          total[0]
              - (totalPayload
                  + totalBytesSentChkRequests
                  + totalBytesSentSskRequests
                  + totalBytesSentChkInserts
                  + totalBytesSentSskInserts
                  + totalBytesSentOfferedKeys
                  + totalBytesSentOffers
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
      activityList.addChild(
          "li",
          statisticsL10n(
              "requestOutput",
              new String[] {"chk", "ssk"},
              new String[] {
                SizeUtil.formatSize(totalBytesSentChkRequests, true),
                SizeUtil.formatSize(totalBytesSentSskRequests, true)
              }));
      activityList.addChild(
          "li",
          statisticsL10n(
              "insertOutput",
              new String[] {"chk", "ssk"},
              new String[] {
                SizeUtil.formatSize(totalBytesSentChkInserts, true),
                SizeUtil.formatSize(totalBytesSentSskInserts, true)
              }));
      activityList.addChild(
          "li",
          statisticsL10n(
              "offeredKeyOutput",
              new String[] {TOTAL_KEY, "offered"},
              new String[] {
                SizeUtil.formatSize(totalBytesSentOfferedKeys, true),
                SizeUtil.formatSize(totalBytesSentOffers, true)
              }));
      activityList.addChild(
          "li", statisticsL10n("swapOutput", SizeUtil.formatSize(totalBytesSentSwapOutput, true)));
      activityList.addChild(
          "li", statisticsL10n("authBytes", SizeUtil.formatSize(totalBytesSentAuth, true)));
      activityList.addChild(
          "li", statisticsL10n("ackOnlyBytes", SizeUtil.formatSize(totalBytesSentAckOnly, true)));
      activityList.addChild(
          "li",
          statisticsL10n(
              "resendBytes",
              new String[] {TOTAL_KEY, PERCENT_KEY},
              new String[] {
                SizeUtil.formatSize(totalBytesSentResends, true),
                Long.toString((100 * totalBytesSentResends) / Math.max(1, total[0]))
              }));
      activityList.addChild(
          "li", statisticsL10n("uomBytes", SizeUtil.formatSize(totalBytesSentUom, true)));
      activityList.addChild(
          "li",
          statisticsL10n(
              "announceBytes",
              new String[] {TOTAL_KEY, "payload"},
              new String[] {
                SizeUtil.formatSize(totalBytesSentAnnounce, true),
                SizeUtil.formatSize(totalBytesSentAnnouncePayload, true)
              }));
      activityList.addChild(
          "li",
          statisticsL10n(
              "adminBytes",
              new String[] {"routingStatus", "disconn", "initial", "changedIP"},
              new String[] {
                SizeUtil.formatSize(totalBytesSentRoutingStatus, true),
                SizeUtil.formatSize(totalBytesSentDisconn, true),
                SizeUtil.formatSize(totalBytesSentInitial, true),
                SizeUtil.formatSize(totalBytesSentChangedIp, true)
              }));
      activityList.addChild(
          "li",
          statisticsL10n(
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
          statisticsL10n("nodeToNodeBytes", SizeUtil.formatSize(totalBytesSentNodeToNode, true)));
      activityList.addChild(
          "li",
          statisticsL10n(
              "loadAllocationNoticesBytes",
              SizeUtil.formatSize(totalBytesSentAllocationNotices, true)));
      activityList.addChild(
          "li", statisticsL10n("foafBytes", SizeUtil.formatSize(totalBytesSentFoaf, true)));
      activityList.addChild(
          "li",
          statisticsL10n(
              "unaccountedBytes",
              new String[] {TOTAL_KEY, PERCENT_KEY},
              new String[] {
                SizeUtil.formatSize(totalBytesSentRemaining, true),
                Integer.toString((int) (totalBytesSentRemaining * 100 / total[0]))
              }));
      double sentOverheadPerSecond = stats.getSentOverheadPerSecond();
      activityList.addChild(
          "li",
          statisticsL10n(
              "totalOverhead",
              new String[] {"rate", PERCENT_KEY},
              new String[] {
                SizeUtil.formatSize((long) sentOverheadPerSecond),
                Integer.toString((int) ((100 * sentOverheadPerSecond) / totalOutputRate))
              }));
    }

    private void drawPeerStatsBox(HTMLNode peerStatsInfobox, PeerStatusCounts counts) {
      peerStatsInfobox.addChild(
          "div", ATTR_CLASS, INFOBOX_HEADER_CLASS, statisticsL10n("peerStatsTitle"));
      HTMLNode peerStatsContent =
          peerStatsInfobox.addChild("div", ATTR_CLASS, INFOBOX_CONTENT_CLASS);
      HTMLNode peerStatsList = peerStatsContent.addChild("ul");
      addPeerStat(
          peerStatsList, counts.connected(), "peer_connected", CLASS_CONNECTED, "connectedShort");
      addPeerStat(
          peerStatsList,
          counts.routingBackedOff(),
          "peer_backed_off",
          "backedOff",
          "backedOffShort");
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
      OpennetManager opennetManager = node.network().opennet();
      if (opennetManager != null) {
        peerStatsList.addChild(
            "li",
            statisticsL10n("maxTotalPeers")
                + ": "
                + opennetManager.getNumberOfConnectedPeersToAimIncludingDarknet());
        peerStatsList.addChild(
            "li",
            statisticsL10n("maxOpennetPeers")
                + ": "
                + opennetManager.getNumberOfConnectedPeersToAim());
      }
    }

    private void addPeerStat(
        HTMLNode list, int count, String cssClass, String titleKey, String labelKey) {
      if (count <= 0) {
        return;
      }
      HTMLNode item = list.addChild("li").addChild("span");
      item.addChild(
          "span",
          new String[] {ATTR_CLASS, ATTR_TITLE, ATTR_STYLE},
          new String[] {cssClass, connectionsL10n(titleKey), HELP_STYLE},
          connectionsL10n(labelKey));
      item.addChild("span", COLON_NBSP + count);
    }

    private String idleToString(long now, long idle) {
      if (idle <= 0) {
        return " ";
      }
      return TimeUtil.formatTime(now - idle);
    }

    private String sortString(boolean reversed, String type) {
      return reversed ? ("?sortBy=" + type) : ("?sortBy=" + type + "&reversed");
    }

    protected static class ComparatorByStatus implements Comparator<PeerNodeStatus> {
      protected final String sortBy;
      protected final boolean reversed;

      ComparatorByStatus(String sortBy, boolean reversed) {
        this.sortBy = sortBy;
        this.reversed = reversed;
      }

      @Override
      public int compare(PeerNodeStatus firstNode, PeerNodeStatus secondNode) {
        int result = compareWithSort(firstNode, secondNode);
        if (result == 0) {
          result = compareByStatus(firstNode, secondNode);
        }
        return reversed ? -Integer.signum(result) : Integer.signum(result);
      }

      protected int customCompare(PeerNodeStatus firstNode, PeerNodeStatus secondNode) {
        if (sortBy == null) {
          return 0;
        }
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
                  firstNode.getReportedUptimePercentage(),
                  secondNode.getReportedUptimePercentage());
          default -> 0;
        };
      }

      protected int lastResortCompare(PeerNodeStatus firstNode, PeerNodeStatus secondNode) {
        return compareLocations(firstNode, secondNode);
      }

      private int compareWithSort(PeerNodeStatus firstNode, PeerNodeStatus secondNode) {
        if (sortBy == null) {
          return 0;
        }
        return customCompare(firstNode, secondNode);
      }

      private int compareByStatus(PeerNodeStatus firstNode, PeerNodeStatus secondNode) {
        int statusDifference =
            Integer.compare(firstNode.getStatusValue(), secondNode.getStatusValue());
        if (statusDifference != 0) {
          return statusDifference;
        }
        return lastResortCompare(firstNode, secondNode);
      }

      private int compareLocations(PeerNodeStatus firstNode, PeerNodeStatus secondNode) {
        double diff = firstNode.getLocation() - secondNode.getLocation();
        if (Double.MIN_VALUE * 2 > Math.abs(diff)) {
          return 0;
        }
        return diff > 0 ? 1 : -1;
      }

      private int compareLongs(long long1, long long2) {
        int diff = Long.compare(long1, long2);
        if (diff == 0) {
          return 0;
        }
        return diff > 0 ? 1 : -1;
      }

      private int compareInts(int int1, int int2) {
        int diff = Integer.compare(int1, int2);
        if (diff == 0) {
          return 0;
        }
        return diff > 0 ? 1 : -1;
      }
    }
  }

  /** Renders the legacy darknet friends page, including editable peer-action affordances. */
  private final class DarknetRenderer extends ConnectionsRenderer {
    @Override
    protected String getPageTitle(String titleCountString) {
      return NodeL10n.getBase()
          .getString(
              "DarknetConnectionsToadlet.fullTitle",
              new String[] {"counts"},
              new String[] {titleCountString});
    }

    @Override
    protected String getPeerListTitle() {
      return connectionsL10n("myFriends");
    }

    @Override
    protected boolean isOpennet() {
      return false;
    }

    @Override
    protected boolean peerActionsEnabled() {
      return true;
    }

    @Override
    protected boolean hasTrustColumn() {
      return true;
    }

    @Override
    protected void drawTrustColumn(HTMLNode peerRow, PeerNodeStatus peerNodeStatus) {
      peerRow
          .addChild("td", ATTR_CLASS, "peer-trust")
          .addChild("#", ((DarknetPeerNodeStatus) peerNodeStatus).getTrustLevel().name());
    }

    @Override
    protected boolean hasVisibilityColumn() {
      return true;
    }

    @Override
    protected void drawVisibilityColumn(
        HTMLNode peerRow, PeerNodeStatus peerNodeStatus, boolean advancedModeEnabled) {
      String content = ((DarknetPeerNodeStatus) peerNodeStatus).getOurVisibility().name();
      if (advancedModeEnabled) {
        content +=
            " (" + ((DarknetPeerNodeStatus) peerNodeStatus).getTheirVisibility().name() + ")";
      }
      peerRow.addChild("td", ATTR_CLASS, "peer-trust").addChild("#", content);
    }

    @Override
    protected boolean hasNameColumn() {
      return true;
    }

    @Override
    protected void drawNameColumn(
        HTMLNode peerRow, PeerNodeStatus peerNodeStatus, boolean advancedModeEnabled) {
      HTMLNode cell = peerRow.addChild("td", ATTR_CLASS, "peer-name");
      cell.addChild(
          "a",
          "href",
          "/send_n2ntm/?peernode_hashcode=" + peerNodeStatus.hashCode(),
          ((DarknetPeerNodeStatus) peerNodeStatus).getName());
      if (advancedModeEnabled && peerNodeStatus.hasFullNoderef) {
        cell.addChild("#", " (");
        cell.addChild(
            "a",
            "href",
            FRIENDS_PATH + FRIEND_PREFIX + peerNodeStatus.hashCode() + FREF_SUFFIX,
            connectionsL10n("noderefLink"));
        cell.addChild("#", ")");
      }
    }

    @Override
    protected boolean hasPrivateNoteColumn() {
      return true;
    }

    @Override
    protected void drawPrivateNoteColumn(
        HTMLNode peerRow, PeerNodeStatus peerNodeStatus, boolean fProxyJavascriptEnabled) {
      DarknetPeerNodeStatus status = (DarknetPeerNodeStatus) peerNodeStatus;
      if (fProxyJavascriptEnabled) {
        peerRow
            .addChild("td", ATTR_CLASS, "peer-private-darknet-comment-note")
            .addChild(
                ELEMENT_INPUT,
                new String[] {"type", "name", "size", "maxlength", "onChange", ATTR_VALUE},
                new String[] {
                  "text",
                  PEER_PRIVATE_NOTE_PREFIX + peerNodeStatus.hashCode(),
                  "16",
                  "250",
                  "peerNoteChange();",
                  status.getPrivateDarknetCommentNote()
                });
      } else {
        peerRow
            .addChild("td", ATTR_CLASS, "peer-private-darknet-comment-note")
            .addChild(
                ELEMENT_INPUT,
                new String[] {"type", "name", "size", "maxlength", ATTR_VALUE},
                new String[] {
                  "text",
                  PEER_PRIVATE_NOTE_PREFIX + peerNodeStatus.hashCode(),
                  "16",
                  "250",
                  status.getPrivateDarknetCommentNote()
                });
      }
    }

    @Override
    protected PeerNodeStatus[] getPeerNodeStatuses(boolean noHeavy) {
      return peers.statusBook().getDarknetPeerNodeStatuses(noHeavy);
    }

    @Override
    protected Comparator<PeerNodeStatus> comparator(String sortBy, boolean reversed) {
      return new DarknetComparator(sortBy, reversed);
    }

    @Override
    protected void drawPeerActionSelectBox(HTMLNode peerForm, boolean advancedModeEnabled) {
      peerForm.addChild(
          ELEMENT_INPUT,
          new String[] {"type", "name", ATTR_VALUE},
          new String[] {
            SUBMIT, "doSendMessageToPeers", connectionsL10n("sendConfidentialMessage")
          });
      peerForm.addChild("br");

      HTMLNode actionSelect =
          peerForm.addChild(
              ELEMENT_SELECT, new String[] {"id", "name"}, new String[] {ACTION, ACTION});
      actionSelect.addChild(ELEMENT_OPTION, ATTR_VALUE, "", connectionsL10n("selectAction"));
      actionSelect.addChild(
          ELEMENT_OPTION, ATTR_VALUE, "update_notes", connectionsL10n("updateChangedPrivnotes"));
      if (advancedModeEnabled) {
        actionSelect.addChild(ELEMENT_OPTION, ATTR_VALUE, "enable", connectionsL10n("peersEnable"));
        actionSelect.addChild(
            ELEMENT_OPTION, ATTR_VALUE, "disable", connectionsL10n("peersDisable"));
        actionSelect.addChild(
            ELEMENT_OPTION, ATTR_VALUE, "set_burst_only", connectionsL10n("peersSetBurstOnly"));
        actionSelect.addChild(
            ELEMENT_OPTION, ATTR_VALUE, "clear_burst_only", connectionsL10n("peersClearBurstOnly"));
        actionSelect.addChild(
            ELEMENT_OPTION, ATTR_VALUE, "set_listen_only", connectionsL10n("peersSetListenOnly"));
        actionSelect.addChild(
            ELEMENT_OPTION,
            ATTR_VALUE,
            "clear_listen_only",
            connectionsL10n("peersClearListenOnly"));
        actionSelect.addChild(
            ELEMENT_OPTION, ATTR_VALUE, "set_allow_local", connectionsL10n("peersSetAllowLocal"));
        actionSelect.addChild(
            ELEMENT_OPTION,
            ATTR_VALUE,
            "clear_allow_local",
            connectionsL10n("peersClearAllowLocal"));
        actionSelect.addChild(
            ELEMENT_OPTION,
            ATTR_VALUE,
            "set_ignore_source_port",
            connectionsL10n("peersSetIgnoreSourcePort"));
        actionSelect.addChild(
            ELEMENT_OPTION,
            ATTR_VALUE,
            "clear_ignore_source_port",
            connectionsL10n("peersClearIgnoreSourcePort"));
        actionSelect.addChild(
            ELEMENT_OPTION, ATTR_VALUE, "set_dont_route", connectionsL10n("peersSetDontRoute"));
        actionSelect.addChild(
            ELEMENT_OPTION, ATTR_VALUE, "clear_dont_route", connectionsL10n("peersClearDontRoute"));
      }
      actionSelect.addChild(ELEMENT_OPTION, ATTR_VALUE, "", connectionsL10n("separator"));
      actionSelect.addChild(ELEMENT_OPTION, ATTR_VALUE, REMOVE, connectionsL10n("removePeers"));
      peerForm.addChild(
          ELEMENT_INPUT,
          new String[] {"type", "name", ATTR_VALUE},
          new String[] {SUBMIT, DO_ACTION, connectionsL10n("go")});
      peerForm.addChild("br");
      peerForm.addChild(
          ELEMENT_INPUT,
          new String[] {"type", "name", ATTR_VALUE},
          new String[] {SUBMIT, "doChangeTrust", connectionsL10n("changeTrustButton")});
      HTMLNode changeTrustLevelSelect =
          peerForm.addChild(
              ELEMENT_SELECT,
              new String[] {"id", "name"},
              new String[] {CHANGE_TRUST, CHANGE_TRUST});
      for (FRIEND_TRUST trust : FRIEND_TRUST.valuesBackwards()) {
        changeTrustLevelSelect.addChild(
            ELEMENT_OPTION, ATTR_VALUE, trust.name(), connectionsL10n("peerTrust." + trust.name()));
      }
      peerForm.addChild("br");
      peerForm.addChild(
          ELEMENT_INPUT,
          new String[] {"type", "name", ATTR_VALUE},
          new String[] {SUBMIT, "doChangeVisibility", connectionsL10n("changeVisibilityButton")});
      HTMLNode changeVisibilitySelect =
          peerForm.addChild(
              ELEMENT_SELECT,
              new String[] {"id", "name"},
              new String[] {CHANGE_VISIBILITY, CHANGE_VISIBILITY});
      for (FRIEND_VISIBILITY visibility : FRIEND_VISIBILITY.values()) {
        changeVisibilitySelect.addChild(
            ELEMENT_OPTION,
            ATTR_VALUE,
            visibility.name(),
            connectionsL10n("peerVisibility." + visibility.name()));
      }
    }

    private static final class DarknetComparator extends ComparatorByStatus {
      private DarknetComparator(String sortBy, boolean reversed) {
        super(sortBy, reversed);
      }

      @Override
      protected int customCompare(PeerNodeStatus firstNode, PeerNodeStatus secondNode) {
        if (sortBy == null) {
          return 0;
        }
        return switch (sortBy) {
          case "name" ->
              ((DarknetPeerNodeStatus) firstNode)
                  .getName()
                  .compareToIgnoreCase(((DarknetPeerNodeStatus) secondNode).getName());
          case "privnote" ->
              ((DarknetPeerNodeStatus) firstNode)
                  .getPrivateDarknetCommentNote()
                  .compareToIgnoreCase(
                      ((DarknetPeerNodeStatus) secondNode).getPrivateDarknetCommentNote());
          case TRUST ->
              ((DarknetPeerNodeStatus) firstNode)
                  .getTrustLevel()
                  .compareTo(((DarknetPeerNodeStatus) secondNode).getTrustLevel());
          case "visibility" -> {
            int ret =
                ((DarknetPeerNodeStatus) firstNode)
                    .getOurVisibility()
                    .compareTo(((DarknetPeerNodeStatus) secondNode).getOurVisibility());
            if (ret != 0) {
              yield ret;
            }
            yield ((DarknetPeerNodeStatus) firstNode)
                .getTheirVisibility()
                .compareTo(((DarknetPeerNodeStatus) secondNode).getTheirVisibility());
          }
          default -> super.customCompare(firstNode, secondNode);
        };
      }

      @Override
      protected int lastResortCompare(PeerNodeStatus firstNode, PeerNodeStatus secondNode) {
        return ((DarknetPeerNodeStatus) firstNode)
            .getName()
            .compareToIgnoreCase(((DarknetPeerNodeStatus) secondNode).getName());
      }
    }
  }

  /** Renders the legacy opennet strangers page, which remains read-only in this transition step. */
  private final class OpennetRenderer extends ConnectionsRenderer {
    @Override
    protected String getPageTitle(String titleCountString) {
      return NodeL10n.getBase()
          .getString(
              "OpennetConnectionsToadlet.fullTitle",
              new String[] {"counts"},
              new String[] {titleCountString});
    }

    @Override
    protected String getPeerListTitle() {
      return NodeL10n.getBase().getString("OpennetConnectionsToadlet.peersListTitle");
    }

    @Override
    protected boolean isOpennet() {
      return true;
    }

    @Override
    protected boolean hasNameColumn() {
      return false;
    }

    @Override
    protected void drawNameColumn(
        HTMLNode peerRow, PeerNodeStatus peerNodeStatus, boolean advancedModeEnabled) {
      // No-op: opennet peers do not expose names.
    }

    @Override
    protected boolean hasPrivateNoteColumn() {
      return false;
    }

    @Override
    protected void drawPrivateNoteColumn(
        HTMLNode peerRow, PeerNodeStatus peerNodeStatus, boolean fProxyJavascriptEnabled) {
      // No-op: opennet peers do not expose private notes.
    }

    @Override
    protected PeerNodeStatus[] getPeerNodeStatuses(boolean noHeavy) {
      return peers.statusBook().getOpennetPeerNodeStatuses(noHeavy);
    }

    @Override
    protected Comparator<PeerNodeStatus> comparator(String sortBy, boolean reversed) {
      return new OpennetComparator(sortBy, reversed);
    }

    @Override
    protected List<SimpleColumn> endColumnHeaders(boolean advancedMode) {
      if (!advancedMode) {
        return List.of();
      }
      return List.of(
          new SimpleColumn() {
            @Override
            protected void drawColumn(HTMLNode peerRow, PeerNodeStatus peerNodeStatus) {
              OpennetPeerNodeStatus status = (OpennetPeerNodeStatus) peerNodeStatus;
              long timeLastSuccess = status.timeLastSuccess;
              peerRow.addChild(
                  "td",
                  ATTR_CLASS,
                  "peer-last-success",
                  timeLastSuccess > 0
                      ? TimeUtil.formatTime(System.currentTimeMillis() - timeLastSuccess)
                      : "NEVER");
            }

            @Override
            String getSortString() {
              return "successTime";
            }

            @Override
            String getTitleKey() {
              return "OpennetConnectionsToadlet.successTimeTitle";
            }

            @Override
            String getExplanationKey() {
              return "OpennetConnectionsToadlet.successTime";
            }
          });
    }

    private static final class OpennetComparator extends ComparatorByStatus {
      private OpennetComparator(String sortBy, boolean reversed) {
        super(sortBy, reversed);
      }

      @Override
      protected int customCompare(PeerNodeStatus firstNode, PeerNodeStatus secondNode) {
        if ("successTime".equals(sortBy)) {
          long t1 = ((OpennetPeerNodeStatus) firstNode).timeLastSuccess;
          long t2 = ((OpennetPeerNodeStatus) secondNode).timeLastSuccess;
          if (t1 > t2) {
            return reversed ? 1 : -1;
          } else if (t2 > t1) {
            return reversed ? -1 : 1;
          }
        }
        return super.customCompare(firstNode, secondNode);
      }
    }
  }

  /**
   * Groups friend-of-a-friend peer locations with the peer-status rows that fall into each bucket.
   */
  private record FoafGrouping(List<Double> locations, List<List<PeerNodeStatus>> peerGroups) {
    int trivialCount() {
      return (int) peerGroups.stream().filter(list -> list.size() == 1).count();
    }
  }

  /** Carries per-request row-render state so each peer row does not need a long argument list. */
  private record RowRenderContext(
      List<SimpleColumn> endCols,
      ConnectionsPageRequest request,
      boolean fProxyJavascriptEnabled,
      boolean enablePeerActions,
      DecimalFormat percentageFormat,
      long now,
      double totalSelectionRate) {}

  /**
   * Resolves one localized string from the legacy darknet-connections bundle namespace.
   *
   * @param key unqualified localization key under {@code DarknetConnectionsToadlet}
   * @return localized text for the current node locale
   */
  private static String connectionsL10n(String key) {
    return NodeL10n.getBase().getString("DarknetConnectionsToadlet." + key);
  }

  /**
   * Resolves one count-oriented localized string from the darknet-connections bundle namespace.
   *
   * @param key unqualified localization key under {@code DarknetConnectionsToadlet}
   * @param value replacement value for the {@value #COUNT} token
   * @return localized text with the count token substituted
   */
  private static String connectionsL10nCount(String key, String value) {
    return NodeL10n.getBase().getString("DarknetConnectionsToadlet." + key, COUNT, value);
  }

  /**
   * Resolves one localized string from the shared statistics bundle namespace.
   *
   * @param key unqualified localization key under {@code StatisticsToadlet}
   * @return localized text for the current node locale
   */
  private static String statisticsL10n(String key) {
    return NodeL10n.getBase().getString(STATS_PREFIX + key);
  }

  /**
   * Resolves one statistics string that expects a single {@value #TOTAL_KEY} token replacement.
   *
   * @param key unqualified localization key under {@code StatisticsToadlet}
   * @param total formatted total value to insert into the localized text
   * @return localized text with the total token substituted
   */
  private static String statisticsL10n(String key, String total) {
    return NodeL10n.getBase()
        .getString(STATS_PREFIX + key, new String[] {TOTAL_KEY}, new String[] {total});
  }

  /**
   * Resolves one statistics string with multiple token replacements.
   *
   * @param key unqualified localization key under {@code StatisticsToadlet}
   * @param patterns replacement token names expected by the bundle entry
   * @param values formatted values aligned with {@code patterns}
   * @return localized text with all provided tokens substituted
   */
  private static String statisticsL10n(String key, String[] patterns, String[] values) {
    return NodeL10n.getBase().getString(STATS_PREFIX + key, patterns, values);
  }
}
